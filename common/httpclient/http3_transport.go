//go:build with_quic

package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type http3Transport struct {
	h3Transport *http3.Transport
}

type http3BrokenEntry struct {
	until   time.Time
	backoff time.Duration
}

type http3FallbackTransport struct {
	h3Transport   *http3.Transport
	h2Fallback    innerTransport
	fallbackDelay time.Duration
	brokenAccess  sync.Mutex
	broken        map[string]http3BrokenEntry
}

func newHTTP3RoundTripper(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) *http3.Transport {
	var handshakeTimeout time.Duration
	if baseTLSConfig != nil {
		handshakeTimeout = baseTLSConfig.HandshakeTimeout()
	}
	quicConfig := NewQUICConfig(options)
	if handshakeTimeout > 0 {
		quicConfig.HandshakeIdleTimeout = handshakeTimeout
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: &stdTLS.Config{},
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsConfig *stdTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			if handshakeTimeout > 0 && quicConfig.HandshakeIdleTimeout == 0 {
				quicConfig = quicConfig.Clone()
				quicConfig.HandshakeIdleTimeout = handshakeTimeout
			}
			if baseTLSConfig != nil {
				var err error
				tlsConfig, err = buildSTDTLSConfig(baseTLSConfig, M.ParseSocksaddr(addr), []string{http3.NextProtoH3})
				if err != nil {
					return nil, err
				}
			} else {
				tlsConfig = tlsConfig.Clone()
				tlsConfig.NextProtos = []string{http3.NextProtoH3}
			}
			conn, err := rawDialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
			if err != nil {
				return nil, err
			}
			quicConn, err := quic.DialEarlyConn(ctx, conn, tlsConfig, quicConfig)
			if err != nil {
				conn.Close()
				return nil, err
			}
			go func() {
				<-quicConn.Context().Done()
				conn.Close()
			}()
			return quicConn, nil
		},
	}
	return h3Transport
}

func newHTTP3Transport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) (innerTransport, error) {
	return &http3Transport{
		h3Transport: newHTTP3RoundTripper(rawDialer, baseTLSConfig, options),
	}, nil
}

func newHTTP3FallbackTransport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	h2Fallback innerTransport,
	options option.QUICOptions,
	fallbackDelay time.Duration,
) (innerTransport, error) {
	return &http3FallbackTransport{
		h3Transport:   newHTTP3RoundTripper(rawDialer, baseTLSConfig, options),
		h2Fallback:    h2Fallback,
		fallbackDelay: fallbackDelay,
		broken:        make(map[string]http3BrokenEntry),
	}, nil
}

func (t *http3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.h3Transport.RoundTrip(request)
}

func (t *http3Transport) CloseIdleConnections() {
	t.h3Transport.CloseIdleConnections()
}

func (t *http3Transport) Close() error {
	t.CloseIdleConnections()
	return t.h3Transport.Close()
}

func (t *http3FallbackTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || requestRequiresHTTP1(request) {
		return t.h2Fallback.RoundTrip(request)
	}
	return t.roundTripHTTP3(request)
}

func (t *http3FallbackTransport) roundTripHTTP3(request *http.Request) (*http.Response, error) {
	authority := requestAuthority(request)
	if t.h3Broken(authority) {
		return t.h2FallbackRoundTrip(request)
	}
	response, err := t.h3Transport.RoundTripOpt(request, http3.RoundTripOpt{OnlyCachedConn: true})
	if err == nil {
		t.clearH3Broken(authority)
		return response, nil
	}
	if !errors.Is(err, http3.ErrNoCachedConn) {
		t.recordH3AttemptFailure(request, authority, err)
		return t.h2FallbackRoundTrip(cloneRequestForRetry(request))
	}
	if !requestReplayable(request) {
		response, err = t.h3Transport.RoundTrip(request)
		if err == nil {
			t.clearH3Broken(authority)
			return response, nil
		}
		t.recordH3AttemptFailure(request, authority, err)
		return nil, err
	}
	return t.roundTripHTTP3Race(request, authority)
}

func (t *http3FallbackTransport) roundTripHTTP3Race(request *http.Request, authority string) (*http.Response, error) {
	type result struct {
		response *http.Response
		err      error
		h3       bool
	}
	var (
		results  = make(chan result, 2)
		cancels  []context.CancelFunc
		received int
	)
	startRoundTrip := func(useH3 bool) {
		ctx, cancel := context.WithCancel(request.Context())
		cancels = append(cancels, cancel)
		raceRequest := cloneRequestForRetry(request).WithContext(ctx)
		go func() {
			var (
				response *http.Response
				err      error
			)
			if useH3 {
				response, err = t.h3Transport.RoundTrip(raceRequest)
			} else {
				response, err = t.h2FallbackRoundTrip(raceRequest)
			}
			results <- result{response: response, err: err, h3: useH3}
		}()
	}
	finish := func(winner int) {
		for index, cancel := range cancels {
			if index != winner {
				cancel()
			}
		}
		for range len(cancels) - received {
			go func() {
				loser := <-results
				if loser.response != nil {
					loser.response.Body.Close()
				}
			}()
		}
	}
	startRoundTrip(true)
	timer := time.NewTimer(t.fallbackDelay)
	defer timer.Stop()
	var (
		h3Err       error
		fallbackErr error
	)
	for {
		select {
		case <-timer.C:
			if len(cancels) == 1 {
				startRoundTrip(false)
			}
		case raceResult := <-results:
			received++
			if raceResult.err == nil {
				winner := 1
				if raceResult.h3 {
					winner = 0
					t.clearH3Broken(authority)
				}
				finish(winner)
				raceResult.response.Body = &cancelOnCloseBody{ReadCloser: raceResult.response.Body, cancel: cancels[winner]}
				return raceResult.response, nil
			}
			if raceResult.h3 {
				t.recordH3AttemptFailure(request, authority, raceResult.err)
				h3Err = raceResult.err
				if len(cancels) == 1 {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					startRoundTrip(false)
				}
			} else {
				fallbackErr = raceResult.err
			}
			if received < len(cancels) {
				continue
			}
			finish(-1)
			switch {
			case h3Err != nil && fallbackErr != nil:
				return nil, E.Errors(h3Err, fallbackErr)
			case fallbackErr != nil:
				return nil, fallbackErr
			default:
				return nil, h3Err
			}
		}
	}
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

func (t *http3FallbackTransport) h2FallbackRoundTrip(request *http.Request) (*http.Response, error) {
	if fallback, isFallback := t.h2Fallback.(*http2FallbackTransport); isFallback {
		return fallback.roundTrip(request, true)
	}
	return t.h2Fallback.RoundTrip(request)
}

func (t *http3FallbackTransport) CloseIdleConnections() {
	t.h3Transport.CloseIdleConnections()
	t.h2Fallback.CloseIdleConnections()
}

func (t *http3FallbackTransport) Close() error {
	t.CloseIdleConnections()
	return t.h3Transport.Close()
}

func (t *http3FallbackTransport) h3Broken(authority string) bool {
	if authority == "" {
		return false
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	entry, found := t.broken[authority]
	if !found {
		return false
	}
	if entry.until.IsZero() || !time.Now().Before(entry.until) {
		delete(t.broken, authority)
		return false
	}
	return true
}

func (t *http3FallbackTransport) clearH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	delete(t.broken, authority)
	t.brokenAccess.Unlock()
}

// recordH3AttemptFailure arms the per-authority verdict for an attempt that failed, and does
// nothing for an attempt that was never allowed to conclude.
//
// # Why a failed attempt is not automatically evidence
//
// The verdict this arms is long-lived and expensive to be wrong about: while it is live every later
// request for the authority goes straight to the H2 fallback, so a wrong entry costs an H3-capable
// server its H3 for the length of the window. That makes "what does this attempt prove?" the whole
// question, and the answer for a request the CALLER ended is: nothing. The caller's context is
// cancelled by a closed client, an abandoned DNS query, a refresh that lost its consumer, a
// shutdown or a caller-side deadline - none of which is a fact about the server, and all of which
// used to reach `markH3Broken` and move the authority onto HTTP/2.
//
// # Why the rule is the request's context and not only the error
//
// Reading the error alone would miss the shapes where the cancellation is laundered: a transport
// whose dial is aborted can report the underlying transport error rather than
// `context.Canceled`, and in the race path the two legs can finish in either order. The caller's
// own context is the fact that cannot be laundered - if it is done, the attempt was cut short by
// the caller, whatever error surfaced. `context.Canceled` is checked as well for the case where a
// cancellation reaches the transport without the request context being the parent that stopped.
//
// # What is deliberately still evidence
//
// Everything else, including a caller-side deadline that has NOT yet expired and any error the
// transport produced on its own - a QUIC handshake timeout, a stateless reset, a version
// negotiation failure. Those are the half-dead peers this fallback exists for, and the sibling
// implementation (`transport/v2rayxhttp`, SPEC 094) takes the same position while keeping
// `context.DeadlineExceeded` a failure on purpose.
func (t *http3FallbackTransport) recordH3AttemptFailure(request *http.Request, authority string, err error) {
	if err == nil {
		return
	}
	if request != nil && request.Context().Err() != nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	t.markH3Broken(authority)
}

func (t *http3FallbackTransport) markH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	entry := t.broken[authority]
	if entry.backoff == 0 {
		entry.backoff = 5 * time.Minute
	} else {
		entry.backoff *= 2
		if entry.backoff > 48*time.Hour {
			entry.backoff = 48 * time.Hour
		}
	}
	entry.until = time.Now().Add(entry.backoff)
	t.broken[authority] = entry
}

func NewQUICConfig(options option.QUICOptions) *quic.Config {
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     options.StreamReceiveWindow.Value(),
		MaxStreamReceiveWindow:         options.StreamReceiveWindow.Value(),
		InitialConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
		MaxConnectionReceiveWindow:     options.ConnectionReceiveWindow.Value(),
		KeepAlivePeriod:                time.Duration(options.KeepAlivePeriod),
		MaxIdleTimeout:                 time.Duration(options.IdleTimeout),
		DisablePathMTUDiscovery:        options.DisablePathMTUDiscovery,
	}
	if options.InitialPacketSize > 0 {
		quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	}
	if options.MaxConcurrentStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	return quicConfig
}

// NewClientCongestionControl resolves `quic_congestion_control` to a sender
// factory for a CLIENT HTTP/3 connection.
//
// It returns (nil, nil) for an unset or explicitly "default" value, which means
// "leave quic-go's own sender in place". That is the important case: the upstream
// default is CUBIC, and this fork must not silently select a different algorithm,
// because a congestion control choice changes wire behaviour and would not be
// visible in the configuration.
//
// It is a separate function from the option parsing so the VALUE VALIDATION can be
// tested without opening a QUIC connection: a test that wanted to check "bogus is
// refused" through a dial would need a live server.
//
// Matching is exact, with no trimming and no case folding: an unrecognised value is
// a configuration error the operator should see, and silently accepting "BBR" or
// " bbr" would make a typo look like it worked.
func NewClientCongestionControl(name string) (func(conn *quic.Conn) congestion.CongestionControl, error) {
	switch name {
	case "", "default":
		// nil leaves quic-go's own sender, which is CUBIC.
		return nil, nil
	case "bbr":
		// The congestion_meta2 BBR profile, the same implementation the HTTP/3
		// server selects through bbr_profile, so a client and server that both
		// name BBR get the same sender rather than two different BBRs.
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard)
		}, nil
	case "cubic":
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{},
				conn.InitialPacketSize(),
				false,
			)
		}, nil
	case "reno":
		// congestion_meta1's CubicSender with `reno=true` IS the Reno
		// implementation; there is no separate constructor, and this mirrors how
		// protocol/naive/quic resolves the same option name.
		return func(conn *quic.Conn) congestion.CongestionControl {
			return congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{},
				conn.InitialPacketSize(),
				true,
			)
		}, nil
	default:
		return nil, E.New("unknown quic congestion control: ", name)
	}
}

// ApplyClientCongestionControl installs the configured congestion control on a
// freshly dialled client QUIC connection.
//
// A nil factory is the "leave the library default" case and is deliberately NOT an
// error: that is what an unset option resolves to, and it is the upstream
// behaviour.
func ApplyClientCongestionControl(conn *quic.Conn, factory func(conn *quic.Conn) congestion.CongestionControl) {
	if factory == nil {
		return
	}
	conn.SetCongestionControl(factory(conn))
}
