package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/quic-go"
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
// been cancelled AND CLOSED before this returns. On failure the caller receives the last
// attempt's error, which is more useful than a synthesised one because it names the
// actual cause (handshake timeout, TLS verification, connection refused).
//
// # Ownership: exactly one winner, and it is decided once
//
// Every attempt ends in exactly one of two states: it is the winner, or it is closed. There
// is deliberately no third state in which a successful attempt is published somewhere
// nobody will read.
//
// The previous implementation had exactly that third state, and it leaked. Attempts
// published their result with `results <- result{conn}` on a channel buffered to
// len(candidates). A buffered send SUCCEEDS when there is room, so the select's
// cancellation arm was never taken: a second attempt finishing its handshake after the
// winner had been returned wrote its connection into the buffer and exited its goroutine.
// Nothing read that slot, so nobody ever closed the QUIC connection or its socket. Measured
// with a socket-counting dialer, a three-candidate race against one reachable server left
// THREE sockets open where one was correct.
//
// Three changes remove the state rather than paper over it:
//
//  1. winner is a sync.Once-guarded CAS, so the race is decided exactly once and the
//     decision cannot be lost by a channel that has room;
//  2. results is UNBUFFERED, so a send only completes when the loop is actually receiving;
//  3. the success send selects on the attempt's context too, so an attempt that finishes
//     after the race is over takes the close arm instead of parking a connection.
//
// # Cleanup is synchronous
//
// Losers are closed before this function returns, not in a detached goroutine. The earlier
// version did:
//
//	cancelRace()
//	go func() { wg.Wait() }()
//	return winner
//
// which returned while losers were still closing, contradicting the comment that claimed
// their sockets were gone first. A caller that counted open descriptors at the moment of
// return would see them, so the guarantee was not real. The wait is now inline.
func (r *handshakeRacer) dial(
	ctx context.Context,
	connectCandidate connectCandidateFunc,
	candidates []netip.Addr,
	preferIPv6 bool,
) (net.Conn, *quic.Conn, error) {
	rawConn, quicConn, _, err := r.dialWithWinner(ctx, connectCandidate, candidates, preferIPv6)
	return rawConn, quicConn, err
}

// dialWithWinner is dial, additionally reporting WHICH address won.
//
// The address is what the caller needs to record as last-known-good, and it is knowable only
// here: the racer is the only component that sees which attempt completed its handshake. The
// exported transport/http hook signature is unchanged, so this extra fact stays inside the
// package rather than widening a shared API.
func (r *handshakeRacer) dialWithWinner(
	ctx context.Context,
	connectCandidate connectCandidateFunc,
	candidates []netip.Addr,
	preferIPv6 bool,
) (net.Conn, *quic.Conn, netip.Addr, error) {
	if len(candidates) == 0 {
		return nil, nil, netip.Addr{}, E.New("no bootstrap candidates to race")
	}
	if len(candidates) == 1 {
		// A single candidate is dialled directly: there is nothing to race, and starting a
		// racer would add a goroutine and a timer for no benefit.
		rawConn, quicConn, err := r.dialOne(ctx, connectCandidate, candidates[0])
		if err != nil {
			return nil, nil, netip.Addr{}, err
		}
		return rawConn, quicConn, candidates[0], nil
	}

	raceCtx, cancelRace := context.WithCancel(ctx)
	defer cancelRace()

	type result struct {
		rawConn  net.Conn
		quicConn *quic.Conn
		address  netip.Addr
		err      error
	}

	// UNBUFFERED. A buffered channel is what let a late success park where nobody would
	// read it; with no buffer, a successful send can only complete while the loop below is
	// receiving, which is exactly when the result will be consumed.
	results := make(chan result)

	var (
		wg sync.WaitGroup
		// outstanding counts attempts that have neither succeeded nor reported failure.
		// The race ends when it reaches zero, which is what makes "all candidates
		// failed" a fact rather than a guess.
		outstanding atomic.Int64
		// won makes the winner decision exactly once, so no second success can slip past
		// a loop that has already returned.
		won atomic.Bool
		// remaining is the launch queue, owned by the loop below. Attempts never touch it.
		remaining []netip.Addr
	)

	// launch starts one candidate attempt. Each attempt owns its socket and closes it
	// itself if it does not become the winner.
	//
	// attemptCtx is cancelled as soon as the race is decided, so an attempt still
	// handshaking is aborted rather than left to finish into a closed race.
	launch := func(attemptCtx context.Context, address netip.Addr) {
		attemptAddress := address
		outstanding.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawConn, quicConn, err := r.dialOne(attemptCtx, connectCandidate, address)
			if err != nil {
				outstanding.Add(-1)
				// A failed attempt cannot deliver while nobody is receiving, which is
				// fine: failures are only interesting while the race is still running,
				// and the loop is receiving for exactly that long.
				select {
				case results <- result{err: err}:
				case <-attemptCtx.Done():
				}
				return
			}
			if won.Load() {
				// The race is already decided. Do not publish: close both halves of this
				// attempt, which is the ONLY way a successful loser may end.
				closeAttempt(quicConn, rawConn)
				return
			}
			select {
			case results <- result{rawConn: rawConn, quicConn: quicConn, address: attemptAddress}:
				// Delivered; the loop owns it now.
			case <-attemptCtx.Done():
				// The race ended between the check above and this send. Close BOTH:
				// closing only the QUIC connection would leave the UDP socket open, and
				// closing only the socket would leave a QUIC state machine on a dead
				// transport.
				closeAttempt(quicConn, rawConn)
			}
		}()
	}

	// Candidates are ordered by alternating families, so the second attempt is the OTHER
	// family. Trying every address of the preferred family first is not Happy Eyeballs:
	// on a broken IPv6 network it would wait out N fallback delays before IPv4 was ever
	// attempted, which is the case the mechanism exists to fix.
	remaining = interleaveCandidates(candidates, preferIPv6)

	// The preferred family goes first; the next candidate is staggered by the fallback
	// delay so silence has a chance to be detected before the fallback is tried.
	launch(raceCtx, remaining[0])
	remaining = remaining[1:]

	timer := time.NewTimer(r.fallbackDelay)
	defer timer.Stop()

	var lastErr error
	for {
		select {
		case res := <-results:
			if res.err == nil {
				if !won.CompareAndSwap(false, true) {
					// Another attempt won first. This one must not be dropped: close it.
					closeAttempt(res.quicConn, res.rawConn)
					continue
				}
				// Stop the losers, then WAIT for them, so the caller receives a winner
				// with nothing else still holding a socket.
				cancelRace()
				wg.Wait()
				return res.rawConn, res.quicConn, res.address, nil
			}
			lastErr = res.err
			// An attempt failed outright. Start the next candidate immediately rather
			// than waiting for the timer: a refusal is information, whereas the timer
			// exists for silence.
			//
			// The timer is deliberately NOT reset here. A hard failure cascading through the
			// remaining candidates is the intended behaviour -- with every candidate refusing,
			// they are all tried at once rather than at fallback-delay intervals -- and the
			// timer is left for the case it exists for. There is no stale-timer hazard to
			// guard against: the loop is single-threaded, so a failure handled here cannot be
			// followed in the same iteration by the timer also firing. An earlier version of
			// this comment claimed otherwise and a Reset was added for it; the Reset changed
			// nothing, and the test written to justify it passed with and without it, which is
			// how the claim was caught.
			if len(remaining) > 0 {
				launch(raceCtx, remaining[0])
				remaining = remaining[1:]
			} else if outstanding.Load() == 0 {
				// Every candidate that was ever started has now failed, and none remain
				// to start.
				cancelRace()
				wg.Wait()
				return nil, nil, netip.Addr{}, lastErr
			}

		case <-timer.C:
			// The preferred family has had its head start. Start the next candidate.
			if len(remaining) > 0 {
				launch(raceCtx, remaining[0])
				remaining = remaining[1:]
				timer.Reset(r.fallbackDelay)
			}

		case <-ctx.Done():
			cancelRace()
			wg.Wait()
			return nil, nil, netip.Addr{}, ctx.Err()
		}
	}
}

// closeAttempt releases an attempt that did not become the winner.
//
// Both halves must be released, and the QUIC connection must be closed before the socket so
// the transport has a chance to send its CONNECTION_CLOSE rather than having its socket
// pulled out from under it. A nil half is tolerated because a failed attempt may have only
// ever created one of them.
func closeAttempt(quicConn *quic.Conn, rawConn net.Conn) {
	if quicConn != nil {
		_ = quicConn.CloseWithError(0, "")
	}
	if rawConn != nil {
		_ = rawConn.Close()
	}
}

// dialOne performs one candidate attempt.
//
// It returns only after the QUIC handshake COMPLETES, which is the entire point of this type.
// DialEarly returning is not enough: for a 0-RTT resumption it returns before the peer has
// confirmed the connection.
func (r *handshakeRacer) dialOne(ctx context.Context, connectCandidate connectCandidateFunc, address netip.Addr) (net.Conn, *quic.Conn, error) {
	// The CANDIDATE IS BUILT BY THE TRANSPORT, through the closure it supplied.
	//
	// That closure performs the UDP dial, the QUIC handshake start and the congestion-control
	// installation, in the transport's own order. This package never sees a TLS config, a QUIC
	// config or a dialer, so it cannot duplicate connection setup or get the ordering wrong --
	// which an earlier version did, by calling DialEarly itself and leaving congestion control
	// to be installed after the handshake had already exchanged packets.
	//
	// A nil closure means no transport supplied one, which happens only when a caller drives the
	// racer directly (tests). It is reported rather than worked around, because there is no
	// correct way to build a candidate here.
	if connectCandidate == nil {
		return nil, nil, E.New("no HTTP/3 candidate connector was supplied")
	}
	rawConn, quicConn, err := connectCandidate(ctx, address)
	if err != nil {
		return nil, nil, err
	}
	return r.awaitHandshake(ctx, rawConn, quicConn, address)
}

// connectCandidateFunc establishes ONE candidate, fully configured.
//
// It is declared as a plain function type rather than an interface so the transport can hand one
// over without this package depending on any of its types, and so a test can supply a closure.
type connectCandidateFunc func(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error)

// awaitHandshake waits for a candidate's handshake to COMPLETE, which is the whole point of
// this type: DialEarly returning is not enough, because for a 0-RTT resumption it returns
// before the peer has confirmed anything.
func (r *handshakeRacer) awaitHandshake(ctx context.Context, rawConn net.Conn, quicConn *quic.Conn, address netip.Addr) (net.Conn, *quic.Conn, error) {
	// THE decisive wait. The connection is only a candidate once its handshake has
	// completed; until then it is a socket and a state machine, not a working path.
	select {
	case <-quicConn.HandshakeComplete():
		return rawConn, quicConn, nil
	case <-quicConn.Context().Done():
		handshakeErr := context.Cause(quicConn.Context())
		_ = quicConn.CloseWithError(0, "")
		_ = rawConn.Close()
		return nil, nil, E.Cause(handshakeErr, "QUIC handshake to ", address)
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

// interleaveCandidates orders candidates by ALTERNATING address families, starting with the
// preferred one.
//
// # Why alternating rather than grouping
//
// The obvious ordering -- every preferred address, then every other address -- is not Happy
// Eyeballs. With two IPv6 addresses and a broken IPv6 path, it produces:
//
//	IPv6#1 -> fallback delay -> IPv6#2 -> fallback delay -> IPv4
//
// so the user waits two fallback delays before the family that actually works is tried.
// RFC 8305 section 4 exists precisely to avoid that: the address list is interleaved so the
// first address of the other family follows the first address of the preferred family.
//
//	IPv6#1 -> fallback delay -> IPv4#1 -> fallback delay -> IPv6#2
//
// # Why this reorders rather than filters
//
// Every input address appears exactly once in the output. Silently dropping the preferred
// family's later addresses would trade a latency bug for a connectivity one: a host whose
// only working address is the second IPv6 one would stop connecting at all.
//
// With a single family there is nothing to alternate with, so the resolver's order is
// preserved untouched.
func interleaveCandidates(candidates []netip.Addr, preferIPv6 bool) []netip.Addr {
	preferred, other := splitByPreference(candidates, preferIPv6)
	if len(other) == 0 {
		// Single family: no interleaving is possible or wanted.
		return append([]netip.Addr(nil), preferred...)
	}
	if len(preferred) == 0 {
		return append([]netip.Addr(nil), other...)
	}
	ordered := make([]netip.Addr, 0, len(preferred)+len(other))
	for index := 0; index < len(preferred) || index < len(other); index++ {
		if index < len(preferred) {
			ordered = append(ordered, preferred[index])
		}
		if index < len(other) {
			ordered = append(ordered, other[index])
		}
	}
	return ordered
}

// masqueConnDialer adapts the racer to the transport's hook.
//
// It is the ONLY place the two packages meet: the transport owns connection setup and
// lifetime, this package owns candidate policy. The hook receives the dialer and QUIC
// configuration the transport already resolved, so nothing about TLS, QUIC options or
// congestion control is duplicated here.
//
// # Every attempt resolves FRESH, and the cache is only a fallback
//
// This used to reuse `bootstrapCandidates()` whenever any were published, so after the first
// successful connection every later reconnect raced the SAME list and never consulted DNS
// again. That breaks rotation (the server moves and we keep dialling the old address),
// failover, and network changes -- and it fails silently, because a stale address that still
// answers looks like success.
//
// So a fresh, bounded lookup happens on EVERY new connection attempt. A successful answer
// replaces the snapshot and leads; only a failed, timed-out or empty answer falls back to the
// recovery cache. That is also what makes a reconnect after a network change correct: the
// previous winner was an address on the OLD network.
//
// # The winner is recorded
//
// The racer knows which address actually completed its handshake. Reporting it here is what
// lets the recovery ordering prefer the address that demonstrably worked, rather than
// whichever one DNS happened to list first. Without this the promotion mechanism existed but
// nothing on the QUIC path ever fed it.
func masqueConnDialer(racer *handshakeRacer, dialer *bootstrapDialer, strategy C.DomainStrategy) transportHTTP.HTTP3ConnDialer {
	return func(
		ctx context.Context,
		server M.Socksaddr,
		connectCandidate transportHTTP.HTTP3CandidateConnector,
	) (net.Conn, *quic.Conn, error) {
		if server.Fqdn == "" {
			return nil, nil, E.New("bootstrap candidates require a hostname server address")
		}
		if connectCandidate == nil {
			return nil, nil, E.New("the transport supplied no HTTP/3 candidate connector")
		}
		candidateAddresses, err := dialer.resolveCandidates(ctx, server.Fqdn)
		if err != nil {
			return nil, nil, E.Cause(err, "bootstrap resolve for QUIC race")
		}
		// The strategy decides which family leads, and the racer interleaves the rest so the
		// other family is attempted second rather than after every preferred address.
		preferIPv6 := preferIPv6FromStrategy(strategy, candidateAddresses)
		rawConn, quicConn, winner, err := racer.dialWithWinner(ctx, connectCandidateFunc(connectCandidate), candidateAddresses, preferIPv6)
		if err != nil {
			return nil, nil, err
		}
		// Record the address that actually completed a handshake: the only fact here that the
		// DNS layer cannot know.
		dialer.cache.promote(winner)
		return rawConn, quicConn, nil
	}
}

// preferIPv6FromStrategy decides which family leads the race.
//
// The configured strategy wins, because the operator has already expressed a preference and
// overriding it would make the option quietly ineffective for the server connection. With
// no preference the family of the FIRST resolved address leads, which respects the ordering
// the DNS layer already chose rather than hardcoding one.
func preferIPv6FromStrategy(strategy C.DomainStrategy, candidates []netip.Addr) bool {
	switch strategy {
	case C.DomainStrategyPreferIPv6:
		return true
	case C.DomainStrategyPreferIPv4:
		return false
	}
	for _, address := range candidates {
		if address.Is4() || address.Is4In6() {
			return false
		}
		if address.Is6() {
			return true
		}
	}
	return false
}
