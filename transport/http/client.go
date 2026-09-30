package http

import (
	std_bufio "bufio"
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
)

type tlsDialer interface {
	DialTLSContext(ctx context.Context, destination M.Socksaddr) (aTLS.Conn, error)
}

// HTTP3CandidateConnector establishes ONE HTTP/3 candidate.
//
// It performs the whole of connection setup -- the UDP dial, the QUIC handshake start, and the
// congestion-control installation -- in this package's own order, and returns the connected
// QUIC connection plus the socket underneath it.
//
// # Why this is a closure rather than exposed configuration
//
// A caller that wants to choose among several addresses needs to build candidates itself, but it
// must not need to know HOW a candidate is built. An earlier seam handed out the dialer, the TLS
// config and the QUIC config instead, and the consequence was real: the caller called
// DialEarly itself and could only return after the handshake completed, so congestion control
// was installed AFTER the handshake had already exchanged packets under the default controller.
//
// With a closure, the ordering lives here, once, and a caller cannot get it wrong.
type HTTP3CandidateConnector func(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error)

// HTTP3ConnDialer is an optional seam that replaces candidate SELECTION.
//
// # What this package still owns
//
// Everything that happens around a connection: the congestion-control installation ordering, the
// transport.NewClientConn wrapping, the single-connection memoization, and the lifetime and
// cleanup of both the QUIC connection and its UDP socket.
//
// # What the hook owns
//
// Which candidate to use, and when to give up on one. It receives the server address and a
// connector, and returns the winning connection. It is responsible for closing any candidate it
// creates and does not choose.
//
// nil -- the default, and every non-MASQUE caller -- preserves the existing path verbatim:
// connect one candidate and use it.
type HTTP3ConnDialer func(ctx context.Context, server M.Socksaddr, connectCandidate HTTP3CandidateConnector) (net.Conn, *quic.Conn, error)

type ClientOptions struct {
	Dialer                 N.Dialer
	HTTP1Dialer            N.Dialer
	RawDialer              N.Dialer
	TLSConfig              aTLS.Config
	Server                 M.Socksaddr
	Authority              string
	Username               string
	Password               string
	Path                   string
	Headers                http.Header
	Version                int
	DisableVersionFallback bool
	HTTP2Options           option.HTTP2Options
	HTTP3Options           option.QUICOptions
	// HTTP3ConnDialer optionally replaces the UDP-dial + QUIC-handshake step of the
	// HTTP/3 client. See HTTP3ConnDialer in client_h3.go for what it is for and why it
	// is deliberately narrow. nil keeps the existing behaviour, which is every caller
	// except the MASQUE client.
	HTTP3ConnDialer HTTP3ConnDialer
	// lifecycleLogger is carried through to the HTTP/3 client for TRACE-level connection
	// lifecycle tracing. It is unexported because it is an internal wiring detail: callers
	// pass their logger to NewClientWithTLS, and that is the only entry point that sets it.
	lifecycleLogger logger.ContextLogger
}

// http3Authority is set when this client is configured for HTTP/3, and is the authority
// that generic HTTP/3 requests are validated against. See Client.validateSameOrigin.

type http3Client interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	OpenTunnel(ctx context.Context, request tunnelRequest) (DatagramStream, error)
	ResetConnection()
	Close() error
}

var NewHTTP3Client func(options ClientOptions, authorization string) (http3Client, error)

type Client struct {
	dialer                          N.Dialer
	http1Dialer                     N.Dialer
	tlsDialer                       tlsDialer
	server                          M.Socksaddr
	authorityOverride               string
	authorization                   string
	host                            string
	path                            string
	headers                         http.Header
	version                         int
	disableVersionFallback          bool
	http2Transport                  *http2.Transport
	http2Access                     sync.Mutex
	http2Conns                      []*http2ClientConn
	http2Unsupported                atomic.Bool
	http2ExtendedConnectUnsupported atomic.Bool
	http3                           http3Client
	http3Broken                     atomic.Int64
	http3Backoff                    atomic.Int64
	// lifecycleLogger is used ONLY for connection-lifecycle tracing. Every call site must
	// stay at TRACE/DEBUG: the success path must be silent at INFO and above, and nothing
	// sensitive (Authorization, Proxy-Authorization, credentials, destination query strings)
	// may be passed.
	lifecycleLogger logger.ContextLogger
	// http3Authority is the authority this client's HTTP/3 connection is authenticated
	// for. Generic HTTP/3 requests are validated against it so an authenticated
	// connection cannot be turned into a cross-origin tunnel.
	http3Authority string
}

func NewClientWithTLS(ctx context.Context, logger logger.ContextLogger, outboundDialer N.Dialer, serverOptions option.ServerOptions, tlsOptions option.OutboundTLSOptions, options ClientOptions) (*Client, error) {
	if options.Version == 3 && !tlsOptions.Enabled {
		return nil, C.ErrTLSRequired
	}
	alpnIsDefault := tlsOptions.Enabled && len(tlsOptions.ALPN) == 0
	if alpnIsDefault {
		if options.Version == 1 {
			tlsOptions.ALPN = []string{"http/1.1"}
		} else {
			tlsOptions.ALPN = []string{http2.NextProtoTLS, "http/1.1"}
		}
	}
	var err error
	options.Dialer, err = tls.NewDialerFromOptions(ctx, logger, outboundDialer, serverOptions.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	if options.Version >= 2 && (alpnIsDefault || slices.Contains(tlsOptions.ALPN, "http/1.1")) {
		http1TLSOptions := tlsOptions
		http1TLSOptions.ALPN = []string{"http/1.1"}
		options.HTTP1Dialer, err = tls.NewDialerFromOptions(ctx, logger, outboundDialer, serverOptions.Server, http1TLSOptions)
		if err != nil {
			return nil, err
		}
	}
	if options.Version == 3 {
		if alpnIsDefault {
			tlsOptions.ALPN = []string{"h3"}
		}
		options.TLSConfig, err = tls.NewClient(ctx, logger, serverOptions.Server, tlsOptions)
		if err != nil {
			return nil, err
		}
	}
	options.RawDialer = outboundDialer
	options.Server = serverOptions.Build()
	options.lifecycleLogger = logger
	return NewClient(options)
}

func NewClient(options ClientOptions) (*Client, error) {
	client := &Client{
		lifecycleLogger:        options.lifecycleLogger,
		dialer:                 options.Dialer,
		http1Dialer:            options.HTTP1Dialer,
		server:                 options.Server,
		authorityOverride:      options.Authority,
		path:                   options.Path,
		headers:                options.Headers.Clone(),
		version:                options.Version,
		disableVersionFallback: options.DisableVersionFallback,
	}
	if client.headers != nil {
		client.host = client.headers.Get("Host")
		client.headers.Del("Host")
	}
	if client.host != "" && client.path != "" {
		return nil, E.New("Host header and path are not allowed at the same time")
	}
	client.version = ResolveVersion(client.version, client.path, client.host)
	if client.version >= 2 && (client.path != "" || client.host != "") {
		return nil, E.New("path and Host header are only supported by HTTP/1")
	}
	if client.dialer == nil {
		client.dialer = N.SystemDialer
	}
	if client.http1Dialer == nil {
		client.http1Dialer = client.dialer
	}
	if dialer, isTLSDialer := options.Dialer.(tlsDialer); isTLSDialer && client.version >= 2 {
		client.tlsDialer = dialer
		http2Transport, err := httpclient.ConfigureHTTP2Transport(options.HTTP2Options)
		if err != nil {
			return nil, err
		}
		http2Transport.DisableCompression = true
		client.http2Transport = http2Transport
	} else if client.version == 2 && options.DisableVersionFallback {
		return nil, E.New("HTTP/2 requires TLS")
	}
	if client.version == 3 && NewHTTP3Client == nil {
		return nil, C.ErrQUICNotIncluded
	}
	if options.Username != "" {
		client.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(options.Username+":"+options.Password))
	}
	if client.version == 3 {
		http3, err := NewHTTP3Client(options, client.authorization)
		if err != nil {
			return nil, err
		}
		client.http3 = http3
		// Give the HTTP/3 client the same logger for lifecycle tracing only. It is optional:
		// an implementation that does not accept one simply does not trace.
		if tracer, isTracer := http3.(http3LifecycleTracer); isTracer {
			tracer.SetLifecycleLogger(options.lifecycleLogger)
		}
		// Record the authority this connection is authenticated for. The generic request
		// path validates against it, so an authenticated connection cannot be used to
		// reach an origin its certificate does not cover.
		client.http3Authority = client.authorityOverride
		if client.http3Authority == "" {
			client.http3Authority = options.Server.String()
		}
	}
	return client, nil
}

func ResolveVersion(version int, path string, host string) int {
	if version != 0 {
		return version
	}
	if path != "" || host != "" {
		return 1
	}
	return 2
}

func (c *Client) http3Available() bool {
	if c.http3 == nil {
		return false
	}
	brokenUntil := c.http3Broken.Load()
	return brokenUntil == 0 || time.Now().UnixNano() >= brokenUntil
}

func (c *Client) markHTTP3Broken() {
	backoff := time.Duration(c.http3Backoff.Load())
	if backoff == 0 {
		backoff = http3BrokenBackoffInitial
	} else {
		backoff = min(backoff*2, http3BrokenBackoffMax)
	}
	c.http3Backoff.Store(int64(backoff))
	c.http3Broken.Store(time.Now().Add(backoff).UnixNano())
}

func (c *Client) clearHTTP3Broken() {
	c.http3Broken.Store(0)
	c.http3Backoff.Store(0)
}

func (c *Client) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
	case N.NetworkUDP:
		return nil, os.ErrInvalid
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if c.http3Available() {
		conn, err := c.http3.DialContext(ctx, destination)
		if err == nil {
			c.clearHTTP3Broken()
			return conn, nil
		}
		if c.disableVersionFallback || !errors.Is(err, ErrHTTP3Unavailable) {
			return nil, err
		}
		c.markHTTP3Broken()
	}
	if c.tlsDialer != nil && !c.http2Unsupported.Load() {
		clientConn, conn, err := c.acquireHTTP2(ctx)
		if err != nil {
			return nil, err
		}
		if clientConn != nil {
			return c.connectHTTP2(ctx, clientConn, destination)
		}
		if c.disableVersionFallback {
			conn.Close()
			return nil, ErrHTTP2Unsupported
		}
		return c.connectAndClose(ctx, conn, destination)
	}
	conn, err := c.http1Dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	return c.connectAndClose(ctx, conn, destination)
}

func (c *Client) closeHTTP2Locked() {
	for _, clientConn := range c.http2Conns {
		clientConn.Close()
	}
	c.http2Conns = nil
}

func (c *Client) ResetConnections() {
	c.http2Access.Lock()
	c.closeHTTP2Locked()
	c.http2Access.Unlock()
	c.http2Unsupported.Store(false)
	c.http2ExtendedConnectUnsupported.Store(false)
	if c.http3 != nil {
		c.http3.ResetConnection()
		c.clearHTTP3Broken()
	}
}

func (c *Client) connect(ctx context.Context, conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
	})
	defer stop()
	request := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if c.host != "" && c.host != destination.Fqdn {
		request.Host = c.host
		request.URL = &url.URL{Opaque: destination.String()}
	} else {
		request.URL = &url.URL{Host: destination.String()}
	}
	if c.path != "" {
		err := badhttp.URLSetPath(request.URL, c.path)
		if err != nil {
			return nil, err
		}
	}
	maps.Copy(request.Header, buildRequestHeader(c.headers, c.authorization, false))
	err := request.Write(conn)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, statusError(response)
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if reader.Buffered() > 0 {
		buffer := buf.NewSize(reader.Buffered())
		_, err = buffer.ReadFullFrom(reader, buffer.FreeLen())
		if err != nil {
			buffer.Release()
			return nil, err
		}
		return bufio.NewCachedConn(conn, buffer), nil
	}
	return conn, nil
}

func buildRequestHeader(headers http.Header, authorization string, originAuthorization bool) http.Header {
	header := headers.Clone()
	if header == nil {
		header = make(http.Header)
	}
	if _, loaded := header["User-Agent"]; !loaded {
		header["User-Agent"] = nil
	}
	if authorization != "" {
		if originAuthorization {
			header.Set("Authorization", authorization)
		} else {
			header.Set("Proxy-Authorization", authorization)
		}
	}
	return header
}

func (c *Client) Close() error {
	c.http2Access.Lock()
	defer c.http2Access.Unlock()
	c.closeHTTP2Locked()
	if c.http3 != nil {
		c.http3.Close()
	}
	return nil
}

const (
	http3BrokenBackoffInitial = 5 * time.Second
	http3BrokenBackoffMax     = 5 * time.Minute
)

var (
	ErrHTTP2Unsupported           = E.New("server does not support HTTP/2")
	ErrHTTP3Unavailable           = E.New("HTTP/3 unavailable")
	errExtendedConnectUnsupported = E.New("server does not support HTTP/2 extended CONNECT")
	errExtendedConnectUnavailable = E.New("HTTP/2 extended CONNECT is unavailable in this build: Go 1.27+ requires the badlinkname build tag")
)

func statusError(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusProxyAuthRequired:
		return E.New("authentication required")
	case http.StatusMethodNotAllowed:
		return E.New("method not allowed")
	default:
		return E.New("unexpected status: ", response.Status)
	}
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, err := c.listenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return deadline.NewPacketConn(bufio.NewNetPacketConn(&boundPacketConn{PacketConn: packetConn, destination: destination.Unwrap()})), nil
}

func (c *Client) listenPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	// The transport kind is not needed here: this path only needs the stream. It is discarded
	// deliberately rather than plumbed through a caller that has no use for it.
	conn, stream, _, err := c.openTunnel(ctx, tunnelRequest{
		protocol:    connectUDPProtocol,
		url:         connectUDPURL(destination),
		destination: destination,
	})
	if err != nil {
		return nil, err
	}
	if stream != nil {
		return newHTTP3PacketConn(stream, destination, M.Socksaddr{}), nil
	}
	return newCapsuleConn(std_bufio.NewReader(conn), conn, destination), nil
}

var _ N.Dialer = (*Client)(nil)

type boundPacketConn struct {
	N.PacketConn
	destination M.Socksaddr
}

func (c *boundPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if destination.Unwrap() != c.destination {
		buffer.Release()
		return E.New("connect-udp: destination mismatch: ", destination)
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

func (c *boundPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *boundPacketConn) Upstream() any {
	return c.PacketConn
}
