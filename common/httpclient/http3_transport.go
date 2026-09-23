//go:build with_quic

package httpclient

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// http3Transport holds one or more independent HTTP/3 transports. With a pool
// size of 1 it is the upstream single-transport transport; larger sizes let
// concurrent requests spread over genuinely separate QUIC connections.
type http3Transport struct {
	transports []*http3.Transport
	next       atomic.Uint64
}

// pick returns the transport for the given request. Rotation only happens for
// replayable requests: a request with a one-shot body must keep using a stable
// member so that a failing attempt can never be retried onto another
// connection with an already-consumed body.
func (t *http3Transport) pick(request *http.Request) *http3.Transport {
	if len(t.transports) == 1 {
		return t.transports[0]
	}
	if !requestReplayable(request) {
		return t.transports[0]
	}
	index := t.next.Add(1) - 1
	return t.transports[index%uint64(len(t.transports))]
}

func (t *http3Transport) roundTripOpt(request *http.Request, opt http3.RoundTripOpt) (*http.Response, error) {
	return t.pick(request).RoundTripOpt(request, opt)
}

func (t *http3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.pick(request).RoundTrip(request)
}

type http3BrokenEntry struct {
	until   time.Time
	backoff time.Duration
}

type http3FallbackTransport struct {
	h3Pool        *http3Transport
	h2Fallback    innerTransport
	fallbackDelay time.Duration
	schedule      option.HTTP3FallbackSchedule
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

// newHTTP3RoundTrippers builds `size` fully independent HTTP/3 transports.
// Each one owns its own QUIC connection pool, so they really are separate
// connections rather than streams within one connection.
func newHTTP3RoundTrippers(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) ([]*http3.Transport, error) {
	size, err := options.HTTP3ConnectionPool.Build()
	if err != nil {
		return nil, err
	}
	transports := make([]*http3.Transport, 0, size)
	for range size {
		transports = append(transports, newHTTP3RoundTripper(rawDialer, baseTLSConfig, options))
	}
	return transports, nil
}

func newHTTP3Transport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	options option.QUICOptions,
) (innerTransport, error) {
	transports, err := newHTTP3RoundTrippers(rawDialer, baseTLSConfig, options)
	if err != nil {
		return nil, err
	}
	return &http3Transport{transports: transports}, nil
}

func newHTTP3FallbackTransport(
	rawDialer N.Dialer,
	baseTLSConfig tls.Config,
	h2Fallback innerTransport,
	options option.QUICOptions,
	fallbackDelay time.Duration,
) (innerTransport, error) {
	transports, err := newHTTP3RoundTrippers(rawDialer, baseTLSConfig, options)
	if err != nil {
		return nil, err
	}
	return &http3FallbackTransport{
		h3Pool:        &http3Transport{transports: transports},
		h2Fallback:    h2Fallback,
		fallbackDelay: fallbackDelay,
		schedule:      options.HTTP3Fallback.Build(),
		broken:        make(map[string]http3BrokenEntry),
	}, nil
}

func (t *http3Transport) CloseIdleConnections() {
	for _, transport := range t.transports {
		transport.CloseIdleConnections()
	}
}

func (t *http3Transport) Close() error {
	var err error
	for _, transport := range t.transports {
		transport.CloseIdleConnections()
		err = E.Append(err, transport.Close(), func(err error) error {
			return E.Cause(err, "close http3 transport")
		})
	}
	return err
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
	// Probe for an already-established QUIC connection on the member this
	// request would use. The probe and any follow-up share the same member so
	// that the cached-connection check is meaningful.
	member := t.h3Pool.pick(request)
	response, err := member.RoundTripOpt(request, http3.RoundTripOpt{OnlyCachedConn: true})
	if err == nil {
		t.clearH3Broken(authority)
		return response, nil
	}
	if !errors.Is(err, http3.ErrNoCachedConn) {
		t.markH3Broken(authority)
		return t.h2FallbackRoundTrip(cloneRequestForRetry(request))
	}
	if !requestReplayable(request) {
		response, err = member.RoundTrip(request)
		if err == nil {
			t.clearH3Broken(authority)
			return response, nil
		}
		t.markH3Broken(authority)
		return nil, err
	}
	return t.roundTripHTTP3Race(request, authority, member)
}

func (t *http3FallbackTransport) roundTripHTTP3Race(request *http.Request, authority string, member *http3.Transport) (*http.Response, error) {
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
				response, err = member.RoundTrip(raceRequest)
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
				t.markH3Broken(authority)
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
	t.h3Pool.CloseIdleConnections()
	t.h2Fallback.CloseIdleConnections()
}

func (t *http3FallbackTransport) Close() error {
	t.CloseIdleConnections()
	return E.Errors(t.h3Pool.Close(), t.h2Fallback.Close())
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

// clearH3Broken drops the recorded failure for an authority after a successful
// HTTP/3 round trip. When reset_on_success is disabled the backoff counter is
// preserved so the next failure continues the previous escalation.
func (t *http3FallbackTransport) clearH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	if !t.schedule.ResetOnSuccess {
		return
	}
	delete(t.broken, authority)
}

func (t *http3FallbackTransport) markH3Broken(authority string) {
	if authority == "" {
		return
	}
	t.brokenAccess.Lock()
	defer t.brokenAccess.Unlock()
	entry := t.broken[authority]
	entry.backoff = t.schedule.Next(entry.backoff)
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
