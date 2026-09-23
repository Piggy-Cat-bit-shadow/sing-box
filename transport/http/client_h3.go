//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
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

// http3PoolSlot owns one complete, independent HTTP/3 stack: its own UDP socket,
// its own QUIC connection and its own http3.ClientConn. Slots share nothing, so
// two slots are two QUIC connections rather than two streams on one.
type http3PoolSlot struct {
	transport *http3.Transport
	access    sync.Mutex
	conn      *http3.ClientConn
	// quicConn is retained so a new tunnel can wait for the handshake to complete
	// before sending its CONNECT header. See awaitHandshake.
	quicConn *quic.Conn
	rawConn  net.Conn

	// quicAccess guards quicConfig, which is created lazily per slot.
	quicAccess sync.Mutex
	quicConfig *quic.Config
}

// http3ClientImpl is the MASQUE tunnel client.
//
// The pool exists because every CONNECT and CONNECT-UDP tunnel previously shared
// one QUIC connection, putting them all under a single congestion controller. A
// pool of N gives N independent congestion controllers on the wire.
//
// A NEW tunnel picks a slot once, round-robin, and stays on it for its lifetime.
// A tunnel is never migrated to another slot and its payload is never replayed,
// which is the property that matters for CONNECT: a half-written tunnel body
// cannot be rewound, so "do not replay" is about one tunnel, not about pinning
// every tunnel to slot 0.
type http3ClientImpl struct {
	dialer        N.Dialer
	tlsConfig     aTLS.Config
	server        M.Socksaddr
	authority     string
	headers       http.Header
	authorization string
	// baseQUICConfig is cloned per slot, because sing-quic mutates the config it
	// is handed.
	baseQUICConfig *quic.Config

	slots []*http3PoolSlot
	next  atomic.Uint64

	// beforeOpenStream is a test hook invoked immediately before a tunnel opens
	// its request stream. It is nil in production and exists so the ordering
	// between the handshake gate and the CONNECT header can be asserted directly
	// rather than inferred from timing.
	beforeOpenStream func(slot *http3PoolSlot)
}

func newHTTP3Client(options ClientOptions, authorization string) (http3Client, error) {
	if options.TLSConfig == nil {
		return nil, E.New("HTTP/3 requires TLS")
	}
	dialer := options.RawDialer
	if dialer == nil {
		dialer = N.SystemDialer
	}
	baseQUICConfig := httpclient.NewQUICConfig(options.HTTP3Options)
	baseQUICConfig.EnableDatagrams = true
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
	// A size of 1 is the upstream behaviour: exactly one transport, one lazily
	// established connection.
	poolSize, err := options.HTTP3Options.HTTP3ConnectionPool.Build()
	if err != nil {
		return nil, err
	}
	slots := make([]*http3PoolSlot, 0, poolSize)
	for range poolSize {
		slots = append(slots, &http3PoolSlot{
			transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		})
	}

	return &http3ClientImpl{
		dialer:         dialer,
		tlsConfig:      options.TLSConfig,
		server:         options.Server,
		authority:      authority,
		headers:        headers,
		authorization:  authorization,
		baseQUICConfig: baseQUICConfig,
		slots:          slots,
	}, nil
}

// quicConfigFor returns a per-slot QUIC config.
//
// sing-quic's DialEarly mutates the config it is given (it assigns
// HandshakeIdleTimeout when unset), so a config shared between slots is a data
// race once two slots dial concurrently. Each slot therefore gets its own copy.
func (c *http3ClientImpl) quicConfigFor(slot *http3PoolSlot) *quic.Config {
	slot.quicAccess.Lock()
	defer slot.quicAccess.Unlock()
	if slot.quicConfig == nil {
		slot.quicConfig = c.baseQUICConfig.Clone()
	}
	return slot.quicConfig
}

// pickSlot chooses the slot a NEW tunnel will use.
func (c *http3ClientImpl) pickSlot() *http3PoolSlot {
	if len(c.slots) == 1 {
		return c.slots[0]
	}
	index := c.next.Add(1) - 1
	return c.slots[index%uint64(len(c.slots))]
}

// slotCount reports how many independent QUIC connections this client can hold.
func (c *http3ClientImpl) slotCount() int {
	return len(c.slots)
}

func (c *http3ClientImpl) acquire(slot *http3PoolSlot, ctx context.Context) (*http3.ClientConn, error) {
	slot.access.Lock()
	defer slot.access.Unlock()
	if slot.conn != nil && slot.conn.Context().Err() == nil {
		return slot.conn, nil
	}
	if slot.rawConn != nil {
		slot.rawConn.Close()
		slot.rawConn = nil
	}
	rawConn, err := c.dialer.DialContext(ctx, N.NetworkUDP, c.server)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A slot-level failure is NOT proof that the authority lacks HTTP/3: this
		// particular pooled connection could not be established (transient UDP
		// loss, a NAT rebinding, a closed socket). Reporting it as
		// ErrHTTP3Unavailable would make the caller mark the whole authority
		// broken and drop to HTTP/2 even though other slots are healthy. The
		// error is therefore returned as a plain failure so the caller retries
		// without poisoning the authority.
		return nil, E.Cause(err, "establish HTTP/3 connection")
	}
	// qtls.DialEarly returns once the connection object exists, but it DOES honor
	// ctx: with a peer that stalls its TLS handshake it returns the context error
	// at the deadline (verified against the pinned sing-quic). No extra timeout
	// wrapper is therefore needed here.
	quicConn, err := qtls.DialEarly(ctx, rawConn, c.tlsConfig, c.quicConfigFor(slot))
	if err != nil {
		rawConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Same reasoning as above, except for a genuine protocol negotiation
		// failure: if the server rejects the h3 ALPN then the authority really
		// does not speak HTTP/3 and falling back is correct.
		if isHTTP3NegotiationFailure(err) {
			return nil, E.Cause1(ErrHTTP3Unavailable, err)
		}
		return nil, E.Cause(err, "establish HTTP/3 connection")
	}
	slot.conn = slot.transport.NewClientConn(quicConn)
	slot.quicConn = quicConn
	slot.rawConn = rawConn
	return slot.conn, nil
}

// awaitHandshake blocks until the QUIC handshake for this slot has completed.
//
// Why this is required: sing-quic's DialEarly returns as soon as the connection
// object exists, and OpenStreamSync only waits for stream limits, not for the
// handshake. Our MASQUE client writes the CONNECT header with
// OpenRequestStream + SendRequestHeader, which bypasses the protection the
// standard http3.ClientConn.roundTrip applies. That method waits for
// HandshakeComplete() for every request except GET_0RTT and HEAD_0RTT, and it is
// what keeps ordinary requests out of 0-RTT.
//
// A proxy tunnel must not be created as 0-RTT application data: 0-RTT data is
// replayable by design, so a captured CONNECT could be replayed by an attacker.
// Session resumption itself is left enabled; only the sending of the CONNECT
// header is gated.
func (c *http3ClientImpl) awaitHandshake(slot *http3PoolSlot, ctx context.Context) error {
	slot.access.Lock()
	quicConn := slot.quicConn
	slot.access.Unlock()
	if quicConn == nil {
		return nil
	}
	select {
	case <-quicConn.HandshakeComplete():
		return nil
	case <-quicConn.Context().Done():
		return context.Cause(quicConn.Context())
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *http3ClientImpl) openStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, error) {
	// The slot is chosen exactly once per tunnel, before any bytes are written,
	// so a failure can never cause this tunnel's payload to be replayed on
	// another connection.
	slot := c.pickSlot()
	clientConn, err := c.acquire(slot, ctx)
	if err != nil {
		return nil, nil, err
	}
	// Never send a CONNECT before the handshake completes; otherwise it could be
	// transmitted as replayable 0-RTT data.
	if err = c.awaitHandshake(slot, ctx); err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause(err, "await HTTP/3 handshake")
	}
	if c.beforeOpenStream != nil {
		c.beforeOpenStream(slot)
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		// The connection exists but could not open a stream. That is a failure on
		// this slot, not evidence about the authority, so it does not trigger the
		// authority-level fallback.
		return nil, nil, E.Cause(err, "open HTTP/3 stream")
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	var response *http.Response
	err = stream.SendRequestHeader(request)
	if err == nil {
		response, err = stream.ReadResponse()
	}
	if err == nil {
		select {
		case <-clientConn.ReceivedSettings():
		case <-clientConn.Context().Done():
			err = context.Cause(clientConn.Context())
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if !stop() {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelRead(0)
		stream.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause(err, "HTTP/3 CONNECT")
	}
	if response.StatusCode != http.StatusOK {
		stream.CancelRead(0)
		stream.Close()
		return nil, nil, statusError(response)
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

// ResetConnection tears down every pooled connection so later tunnels dial
// fresh. All slots are reset because a shared authority failure affects them all.
func (c *http3ClientImpl) ResetConnection() {
	for _, slot := range c.slots {
		slot.access.Lock()
		if slot.conn != nil {
			slot.conn.CloseWithError(0, "")
			slot.conn = nil
		}
		slot.quicConn = nil
		if slot.rawConn != nil {
			slot.rawConn.Close()
			slot.rawConn = nil
		}
		slot.access.Unlock()
	}
}

// Close releases every slot's connection, UDP socket and transport. A failure on
// one slot does not prevent the others from being closed.
func (c *http3ClientImpl) Close() error {
	var closeErr error
	for _, slot := range c.slots {
		slot.access.Lock()
		if slot.conn != nil {
			slot.conn.CloseWithError(0, "")
			slot.conn = nil
		}
		slot.quicConn = nil
		if slot.rawConn != nil {
			slot.rawConn.Close()
			slot.rawConn = nil
		}
		slot.access.Unlock()
		closeErr = E.Append(closeErr, slot.transport.Close(), func(err error) error {
			return E.Cause(err, "close http3 transport")
		})
	}
	return closeErr
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

func (s *http3RequestDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.stream.ReceiveDatagram(ctx)
}

var (
	_ net.Conn       = (*http3StreamConn)(nil)
	_ N.WriteCloser  = (*http3StreamConn)(nil)
	_ DatagramStream = (*http3RequestDatagramStream)(nil)
)

// isHTTP3NegotiationFailure reports whether a QUIC handshake failed because the
// peer does not speak HTTP/3.
//
// This is the only handshake outcome that justifies an authority-level fallback:
// it means the server itself declined the h3 protocol. A timeout, an unreachable
// address or a closed socket says nothing about the authority and must not
// disable HTTP/3 for it, because other pooled connections may still be healthy.
func isHTTP3NegotiationFailure(err error) bool {
	if err == nil {
		return false
	}
	// A TLS alert about ALPN surfaces as a CRYPTO_ERROR carrying
	// "no application protocol"; quic-go wraps it in a TransportError with a
	// crypto error code (0x100 + alert). Code 0x178 is alert 120,
	// no_application_protocol.
	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		const noApplicationProtocol = 0x100 + 120
		if uint64(transportErr.ErrorCode) == noApplicationProtocol {
			return true
		}
	}
	return false
}
