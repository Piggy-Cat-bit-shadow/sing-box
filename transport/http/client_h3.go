//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func init() {
	NewHTTP3Client = newHTTP3Client
}

type http3ClientImpl struct {
	dialer N.Dialer
	// connDialer, when set, replaces candidate SELECTION. See HTTP3ConnDialer. nil means
	// connect one candidate and use it, which is the previous behaviour.
	connDialer HTTP3ConnDialer
	// connectCandidate builds one candidate at a chosen address, and is the ONLY place the
	// UDP dial, the QUIC start and the congestion-control installation happen. It is handed
	// to the hook so a caller racing candidates cannot get that ordering wrong.
	connectCandidate HTTP3CandidateConnector
	tlsConfig        aTLS.Config
	server           M.Socksaddr
	authority        string
	// http3Authority is the authority this connection is authenticated for. It is what
	// the generic request path validates against; see Client.validateSameOrigin.
	http3Authority string
	headers        http.Header
	authorization  string
	quicConfig     *quic.Config
	// congestionControl is resolved once in newHTTP3Client. nil means "keep
	// quic-go's default sender", which is what an unset option selects.
	congestionControl func(conn *quic.Conn) congestion.CongestionControl
	transport         *http3.Transport
	access            sync.Mutex
	conn              *http3.ClientConn
	rawConn           net.Conn
}

func newHTTP3Client(options ClientOptions, authorization string) (http3Client, error) {
	if options.TLSConfig == nil {
		return nil, E.New("HTTP/3 requires TLS")
	}
	dialer := options.RawDialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	quicConfig := httpclient.NewQUICConfig(options.HTTP3Options)
	quicConfig.EnableDatagrams = true
	// Resolve the client congestion control ONCE, at construction, so an
	// unrecognised value is a configuration error reported at load rather than a
	// failure on the first packet. A nil result is the "leave quic-go's default"
	// case and is not an error: that is what an unset option means.
	congestionControl, err := httpclient.NewClientCongestionControl(options.HTTP3Options.CongestionControl)
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Clone()
	authority := options.Server.String()
	if options.Authority != "" {
		authority = options.Authority
	}
	if headers != nil {
		if host := headers.Get("Host"); host != "" {
			authority = host
		}
		headers.Del("Host")
	}
	impl := &http3ClientImpl{
		dialer:            dialer,
		tlsConfig:         options.TLSConfig,
		server:            options.Server,
		authority:         authority,
		headers:           headers,
		authorization:     authorization,
		quicConfig:        quicConfig,
		congestionControl: congestionControl,
		connDialer:        options.HTTP3ConnDialer,
		transport:         &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	// Bound after construction so it closes over the fully built value.
	impl.connectCandidate = impl.connectCandidateAt
	return impl, nil
}

// existingConn returns the live, memoized ClientConn WITHOUT dialing.
//
// It shares the liveness test with acquire() -- the connection must exist and its context must
// not be done -- so the two agree about what "usable" means. The difference is only what
// happens when there is none: acquire() dials, this reports failure.
func (c *http3ClientImpl) existingConn() (*http3.ClientConn, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn, true
	}
	return nil, false
}

// HTTP3ConnectionAuthority implements http3ExistingConnectionRoundTripper.
func (c *http3ClientImpl) HTTP3ConnectionAuthority() (string, bool) {
	if _, live := c.existingConn(); !live {
		return "", false
	}
	return c.authority, true
}

func (c *http3ClientImpl) acquire(ctx context.Context) (*http3.ClientConn, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn, nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}

	// One connector, used by BOTH paths, so a raced candidate and a plain one are built the
	// same way. That is what keeps the congestion-control ordering identical whether or not a
	// hook is installed: the connector is the only place it happens.
	//
	// The UDP dial happens INSIDE the connector rather than before the branch, because dialing
	// first would create a socket that a hook choosing its own candidate never uses -- it would
	// be overwritten and leak. An earlier version did exactly that, and the regression test
	// caught it by asserting this client's dialer is not called when a hook is set.
	var (
		rawConn  net.Conn
		quicConn *quic.Conn
		err      error
	)
	if c.connDialer != nil {
		// The caller owns candidate SELECTION and returns only a connection whose QUIC
		// handshake has COMPLETED, so this path's winner is the racer's winner. Everything
		// after this point is unchanged, which keeps the memoization and the wrapping
		// identical to the default path.
		rawConn, quicConn, err = c.connDialer(ctx, c.server, c.candidateConnector())
	} else {
		rawConn, quicConn, err = c.candidateConnector()(ctx, c.server.Addr)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	c.conn = c.transport.NewClientConn(quicConn)
	c.rawConn = rawConn
	return c.conn, nil
}

// candidateConnector returns the connector, binding it on first use if construction did not.
//
// Binding in the constructor is the normal path. The lazy fallback exists because a zero-value
// http3ClientImpl is constructible (tests do it), and a nil connector would otherwise panic
// inside acquire rather than dialing. That was a real crash, not a hypothetical one.
func (c *http3ClientImpl) candidateConnector() HTTP3CandidateConnector {
	if c.connectCandidate != nil {
		return c.connectCandidate
	}
	return c.connectCandidateAt
}

// connectCandidateAt establishes ONE HTTP/3 candidate at the given address.
//
// It is the single definition of how a candidate is built, and it performs the three steps in
// the order that matters:
//
//	UDP dial -> qtls.DialEarly -> ApplyClientCongestionControl
//
// The congestion control is installed here, BEFORE the handshake has been waited for, because it
// is not a post-connection option: the first flight sets the initial window and the pacing
// behaviour. A racer that built candidates itself could only apply it after HandshakeComplete,
// which is the defect this closure exists to make impossible.
//
// A per-address connector is used rather than a fixed destination so a caller can race several
// addresses, each getting its own socket and its own QUIC connection.
func (c *http3ClientImpl) connectCandidateAt(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error) {
	destination := c.server
	if address.IsValid() {
		destination = M.SocksaddrFrom(address, c.server.Port)
	}
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, nil, E.Cause(err, "dial UDP to ", destination)
	}
	quicConn, err := qtls.DialEarly(ctx, rawConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, E.Cause(err, "QUIC dial to ", destination)
	}
	httpclient.ApplyClientCongestionControl(quicConn, c.congestionControl)
	return rawConn, quicConn, nil
}

// openStream establishes a CONNECT tunnel: one HTTP/3 stream carrying payload in both directions
// for as long as the tunnel lives.
//
// # This is not a request, and must not be treated as one
//
// Every step here -- acquire a connection, open a stream, send a CONNECT header, read the response
// -- looks like the start of an ordinary request, and that resemblance is the hazard. For an
// ordinary request the response is the END: the write side is finished once the request has been
// sent and closing it is correct cleanup. For a CONNECT the 200 is the BEGINNING, and closing the
// write side there leaves a stream that can be read but never written, so the first proxy write
// fails with "write on closed stream".
//
// The two therefore do not share an implementation. openConnectStream owns the CONNECT lifecycle
// and returns the stream LIVE; ordinary requests go through ClientConn.RoundTrip, which manages its
// own. What they DO share is the connection, how it is acquired, and the same-origin policy.
func (c *http3ClientImpl) openStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, error) {
	stream, clientConn, err := c.openConnectStream(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	return stream, clientConn, nil
}

func (c *http3ClientImpl) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	stream, _, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination.String()},
		Host:   destination.String(),
		Header: buildRequestHeader(c.headers, c.authorization, false),
	})
	if err != nil {
		return nil, err
	}
	return &http3StreamConn{stream: stream, remoteAddr: destination}, nil
}

func (c *http3ClientImpl) OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error) {
	requestURL := *request.url
	requestURL.Scheme = "https"
	requestURL.Host = c.authority
	header := buildRequestHeader(c.headers, c.authorization, request.originAuthorization)
	header.Set("Capsule-Protocol", "?1")
	stream, clientConn, err := c.openStream(ctx, &http.Request{
		Method: http.MethodConnect,
		Proto:  request.protocol,
		URL:    &requestURL,
		Host:   c.authority,
		Header: header,
	})
	if err != nil {
		return nil, err
	}
	return &http3RequestDatagramStream{stream: stream, datagramsEnabled: clientConn.Settings().EnableDatagrams}, nil
}

func (c *http3ClientImpl) ResetConnection() {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil {
		c.conn.CloseWithError(0, "")
		c.conn = nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
}

func (c *http3ClientImpl) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil {
		c.conn.CloseWithError(0, "")
		c.conn = nil
	}
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
	return c.transport.Close()
}

type http3StreamConn struct {
	stream      *http3.RequestStream
	remoteAddr  net.Addr
	writeAccess sync.Mutex
	closed      atomic.Bool
}

func (c *http3StreamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	n, err := c.stream.Write(p)
	return n, c.wrapError(err)
}

func (c *http3StreamConn) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	return qtls.WrapError(err)
}

func (c *http3StreamConn) CloseWrite() error {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.stream.Close()
}

func (c *http3StreamConn) Close() error {
	c.closed.Store(true)
	c.stream.SetWriteDeadline(time.Now())
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.stream.CancelRead(0)
	return c.stream.Close()
}

func (c *http3StreamConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *http3StreamConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3StreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *http3StreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *http3StreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *http3StreamConn) NeedAdditionalReadDeadline() bool {
	return true
}

type http3RequestDatagramStream struct {
	stream           *http3.RequestStream
	datagramsEnabled bool
}

func (s *http3RequestDatagramStream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *http3RequestDatagramStream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *http3RequestDatagramStream) Close() error {
	s.stream.SetWriteDeadline(time.Now())
	s.stream.CancelRead(0)
	return s.stream.Close()
}

// DatagramsEnabled reports whether the peer negotiated HTTP Datagrams.
func (s *http3RequestDatagramStream) DatagramsEnabled() bool {
	return s.datagramsEnabled
}

func (s *http3RequestDatagramStream) SendDatagram(payload []byte) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.stream.SendDatagram(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.stream.StreamID()/4))}
	}
	return err
}

// SendDatagramOwned is the ownership-transferring counterpart of SendDatagram.
//
// # The error translation must stay identical
//
// The MTU a caller learns from a too-large error is used to build an ICMP Packet Too Big, and the
// subtraction below accounts for the framing the QUIC layer measured but the caller did not send
// (the quarter stream ID, and the context ID the caller prepended). Reporting a different ceiling
// here than SendDatagram reports would make the same packet produce two different PTBs depending on
// which path happened to be used.
//
// # Ownership on each branch
//
//	unsupported  -> payload untouched, still the caller's
//	too large    -> payload rolled back by the HTTP/3 layer, still the caller's
//	success      -> payload owned by the transport, released exactly once after serialization
//
// The rollback is what makes the first two branches useful: the caller trims the buffer and builds
// the PTB, or hands it to the capsule fallback, from the very payload that failed.
func (s *http3RequestDatagramStream) SendDatagramOwned(payload http3.OwnedDatagramPayload) error {
	if !s.datagramsEnabled {
		return ErrDatagramUnsupported
	}
	err := s.stream.SendDatagramOwned(payload)
	if err == nil {
		return nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &DatagramTooLargeError{MaxPayloadSize: int(tooLarge.MaxDatagramPayloadSize) - VarintLen(uint64(s.stream.StreamID()/4))}
	}
	return err
}

func (s *http3RequestDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

var (
	_ net.Conn       = (*http3StreamConn)(nil)
	_ N.WriteCloser  = (*http3StreamConn)(nil)
	_ DatagramStream = (*http3RequestDatagramStream)(nil)
)

// DialHTTP3Candidate establishes ONE HTTP/3 candidate and installs congestion control on it
// before waiting for the handshake to complete.
//
// # Why this exists
//
// The default path in acquire() is, in order:
//
//	UDP dial -> DialEarly -> ApplyClientCongestionControl -> wait -> NewClientConn
//
// A racer that calls DialEarly itself and only returns after HandshakeComplete leaves the
// congestion control to be installed later, by acquire(), which means the handshake exchanged
// packets under the DEFAULT controller. Congestion control is not a post-connection option:
// the first flight sets the initial window and the pacing behaviour, so installing it after the
// handshake is a real behavioural difference, not a bookkeeping one.
//
// This primitive gives the racer the middle three steps without duplicating any of them.
// protocol/masque supplies only candidate ordering, the stagger and the winner decision; the
// UDP dial, the TLS/QUIC construction and the congestion-control choice all stay here, where
// the transport already owns them.
//
// It does NOT touch the memoized connection: the caller (the racer) owns the returned pair
// until it hands the winner back through the hook, at which point acquire() wraps it exactly as
// before. So the memoization, the ordering and the default path are all unchanged.
func (c *http3ClientImpl) DialHTTP3Candidate(ctx context.Context, server M.Socksaddr, address netip.Addr) (net.Conn, *quic.Conn, error) {
	destination := M.SocksaddrFrom(address, server.Port)
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, nil, E.Cause(err, "dial UDP to ", address)
	}
	quicConn, err := qtls.DialEarly(ctx, rawConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, E.Cause(err, "QUIC dial to ", address)
	}
	// THE point of this function: the configured congestion control is installed on the
	// connection BEFORE it has completed its handshake, so the handshake itself runs under it --
	// exactly as on the default path.
	httpclient.ApplyClientCongestionControl(quicConn, c.congestionControl)
	return rawConn, quicConn, nil
}
