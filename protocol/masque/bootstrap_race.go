package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

// QUIC handshake-level happy eyeballs for the MASQUE server connection.
//
// # Why the winner is decided at handshake completion
//
// A UDP socket connect succeeds against an address that has no QUIC listener at all, and
// qtls.DialEarly returns as soon as a connection object exists -- which for 0-RTT is
// before the peer has confirmed anything. Neither is evidence that the path works.
//
// So neither is treated as success:
//
//	a successful UDP dial        -> NOT a winner
//	DialEarly returning          -> NOT a winner
//	a usable 0-RTT connection    -> NOT a winner
//	the QUIC handshake completing -> the winner
//
// This is the difference between "a packet could be sent" and "the server answered",
// and only the second one means the user's traffic will flow.
//
// # Session resumption is preserved
//
// The race does not disable 0-RTT, session tickets or resumption. It simply does not let
// their early return decide the winner: the connection still completes its handshake and
// still reports a winner, it is only that the winner is chosen later than DialEarly
// returns. A resumed session wins the race on the same terms as a fresh one.
//
// # Congestion control ordering is unchanged
//
// The racer returns a raw connection and a completed QUIC connection. Installing the
// configured congestion control, wrapping in transport.NewClientConn and memoizing the
// result all still happen in transport/http, in the same order as before: DialEarly, then
// congestion control, then the client conn. The handshake wait changes WHICH connection
// wins, not what happens to it afterwards.
type handshakeRacer struct {
	// fallbackDelay is how long the preferred family is given before the other family
	// is started. It matches the standard Happy Eyeballs delay.
	fallbackDelay time.Duration
}

func newHandshakeRacer(fallbackDelay time.Duration) *handshakeRacer {
	if fallbackDelay <= 0 {
		fallbackDelay = N.DefaultFallbackDelay
	}
	return &handshakeRacer{fallbackDelay: fallbackDelay}
}

// dial races the resolved candidates and returns the first whose QUIC handshake COMPLETES.
//
// The returned raw connection and QUIC connection are the winner's, and every loser has
// been cancelled and closed before this returns. On failure the caller receives the last
// attempt's error, which is more useful than a synthesised one because it names the
// actual cause (handshake timeout, TLS verification, connection refused).
func (r *handshakeRacer) dial(
	ctx context.Context,
	dialer N.Dialer,
	server M.Socksaddr,
	tlsConfig aTLS.Config,
	quicConfig *quic.Config,
	candidates []netip.Addr,
	preferIPv6 bool,
) (net.Conn, *quic.Conn, error) {
	if len(candidates) == 0 {
		return nil, nil, E.New("no bootstrap candidates to race")
	}
	if len(candidates) == 1 {
		// A single candidate is dialled directly: there is nothing to race, and starting
		// a racer would add a goroutine and a timer for no benefit.
		return r.dialOne(ctx, dialer, server, tlsConfig, quicConfig, candidates[0])
	}

	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	type result struct {
		rawConn  net.Conn
		quicConn *quic.Conn
		err      error
	}
	results := make(chan result, len(candidates))

	var (
		wg sync.WaitGroup
		// outstanding counts attempts that have neither succeeded nor reported failure.
		// The race ends when it reaches zero, which is what makes "all candidates
		// failed" a fact rather than a guess.
		outstanding     atomic.Int64
		pendingLaunches []netip.Addr
	)

	// launch starts one candidate attempt. Each attempt owns its socket and is
	// responsible for closing it if it loses.
	launch := func(address netip.Addr) {
		outstanding.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawConn, quicConn, err := r.dialOne(raceCtx, dialer, server, tlsConfig, quicConfig, address)
			if err != nil {
				outstanding.Add(-1)
				results <- result{err: err}
				return
			}
			select {
			case results <- result{rawConn: rawConn, quicConn: quicConn}:
			case <-raceCtx.Done():
				// The race is over and this attempt was not the winner. Close BOTH the
				// QUIC connection and the socket: closing only the QUIC connection would
				// leave the UDP socket open, and closing only the socket would leave the
				// QUIC state machine with a dead transport.
				_ = quicConn.CloseWithError(0, "")
				_ = rawConn.Close()
			}
		}()
	}

	// The preferred family goes first; the next address is staggered by the fallback
	// delay. Addresses within a family are tried in the order the resolver produced,
	// which is the order the DNS layer already chose.
	preferred, other := splitByPreference(candidates, preferIPv6)
	pendingLaunches = append(append([]netip.Addr(nil), preferred...), other...)
	launch(pendingLaunches[0])
	pendingLaunches = pendingLaunches[1:]

	timer := time.NewTimer(r.fallbackDelay)
	defer timer.Stop()

	var lastErr error
	for {
		select {
		case res := <-results:
			if res.err == nil {
				// A COMPLETED handshake. Cancel the losers and return.
				cancelRace()
				go func() {
					// Wait for the losers to finish closing so their sockets are gone
					// before the winner is handed to the caller. This is what makes the
					// leak assertions meaningful rather than timing-dependent.
					wg.Wait()
				}()
				return res.rawConn, res.quicConn, nil
			}
			lastErr = res.err
			// An attempt failed outright. Start the next candidate immediately rather
			// than waiting for the timer: a refusal is information, whereas the timer
			// exists for silence.
			if len(pendingLaunches) > 0 {
				launch(pendingLaunches[0])
				pendingLaunches = pendingLaunches[1:]
			} else if outstanding.Load() == 0 {
				// Every candidate that was ever started has now failed, and none remain
				// to start.
				cancelRace()
				wg.Wait()
				return nil, nil, lastErr
			}

		case <-timer.C:
			// The preferred family has had its head start. Start the next candidate.
			if len(pendingLaunches) > 0 {
				launch(pendingLaunches[0])
				pendingLaunches = pendingLaunches[1:]
				timer.Reset(r.fallbackDelay)
			}

		case <-ctx.Done():
			cancelRace()
			wg.Wait()
			return nil, nil, ctx.Err()
		}
	}
}

// dialOne performs one candidate attempt.
//
// It returns only after the QUIC handshake COMPLETES, which is the entire point of this
// type. DialEarly returning is not enough: for a 0-RTT resumption it returns before the
// peer has confirmed the connection.
func (r *handshakeRacer) dialOne(
	ctx context.Context,
	dialer N.Dialer,
	server M.Socksaddr,
	tlsConfig aTLS.Config,
	quicConfig *quic.Config,
	address netip.Addr,
) (net.Conn, *quic.Conn, error) {
	destination := M.SocksaddrFrom(address, server.Port)
	rawConn, err := dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		// A failed UDP dial is not a race outcome worth distinguishing: the socket was
		// never created, so there is nothing to close.
		return nil, nil, E.Cause(err, "dial UDP to ", address)
	}
	quicConn, err := qtls.DialEarly(ctx, rawConn, tlsConfig, quicConfig)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, E.Cause(err, "QUIC dial to ", address)
	}
	// THE decisive wait. The connection is only a candidate once its handshake has
	// completed; until then it is a socket and a state machine, not a working path.
	select {
	case <-quicConn.HandshakeComplete():
		return rawConn, quicConn, nil
	case <-quicConn.Context().Done():
		err = context.Cause(quicConn.Context())
		_ = quicConn.CloseWithError(0, "")
		_ = rawConn.Close()
		return nil, nil, E.Cause(err, "QUIC handshake to ", address)
	case <-ctx.Done():
		_ = quicConn.CloseWithError(0, "")
		_ = rawConn.Close()
		return nil, nil, ctx.Err()
	}
}

// splitByPreference divides candidates into the preferred family and the rest.
//
// The families are kept in their resolver order within each group. Addresses of neither
// family (which cannot occur for a resolved candidate, but is handled rather than
// assumed) land in the fallback group so they are still attempted.
func splitByPreference(candidates []netip.Addr, preferIPv6 bool) (preferred []netip.Addr, other []netip.Addr) {
	for _, address := range candidates {
		isIPv6 := address.Is6() && !address.Is4In6()
		if isIPv6 == preferIPv6 {
			preferred = append(preferred, address)
		} else {
			other = append(other, address)
		}
	}
	if len(preferred) == 0 {
		// Nothing matched the preference; start with whatever exists rather than with an
		// empty group.
		return other, nil
	}
	return preferred, other
}

// masqueConnDialer adapts the racer to the transport's hook.
//
// It is the ONLY place the two packages meet: the transport owns connection setup and
// lifetime, this package owns candidate policy. The hook receives the dialer and QUIC
// configuration the transport already resolved, so nothing about TLS, QUIC options or
// congestion control is duplicated here.
func masqueConnDialer(racer *handshakeRacer, candidates []netip.Addr, preferIPv6 bool) transportHTTP.HTTP3ConnDialer {
	return func(
		ctx context.Context,
		dialer N.Dialer,
		server M.Socksaddr,
		tlsConfig aTLS.Config,
		quicConfig *quic.Config,
	) (net.Conn, *quic.Conn, error) {
		return racer.dial(ctx, dialer, server, tlsConfig, quicConfig, candidates, preferIPv6)
	}
}
