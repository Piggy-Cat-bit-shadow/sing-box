package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	// maxHeaderBytes is the upstream request header limit. It stays the
	// default so that an inbound which does not configure a limit behaves
	// exactly as upstream.
	maxHeaderBytes      = 1 << 20
	idleTimeout         = 60 * time.Second
	maxDiscardBodyBytes = 256 << 10
	// maxUnauthenticatedBodyBytes bounds the request body an unauthenticated
	// (failed-authentication) request may push at the masquerade backend. Normal
	// web requests are far smaller; this exists so a failed-auth probe cannot
	// stream an unbounded body through the reverse proxy.
	maxUnauthenticatedBodyBytes = 256 << 10
	discardBodyTimeout          = 5 * time.Second
	realm                       = "sing-box"
)

// ConfigureHTTP3ListenerFunc builds the HTTP/3 listener. maxHeaderBytes is the
// effective request header limit resolved from server_profile and
// max_header_bytes; the HTTP/3 server needs it explicitly because it does not
// share the HTTP/2 server's configuration.
var ConfigureHTTP3ListenerFunc func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.QUICOptions, maxHeaderBytes int) (io.Closer, error)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type ServerOptions struct {
	Authenticator *auth.Authenticator
	Logger        logger.ContextLogger
	HTTP1         bool
	HTTP2         bool
	HTTP2Options  option.HTTP2Options
	UDP           bool
	Tunnels       map[string]TunnelHandler
	Masquerade    http.Handler
	// MaxHeaderBytes overrides the request header limit. Zero keeps the
	// upstream default.
	MaxHeaderBytes int
	// UnauthenticatedLimits bounds pre-authentication traffic. A nil or
	// disabled value installs no limiter at all.
	UnauthenticatedLimits *option.UnauthenticatedLimitsOptions
}

type Server struct {
	authenticator *auth.Authenticator
	logger        logger.ContextLogger
	http1         bool
	http2Server   *http2.Server
	udp           bool
	tunnels       map[string]TunnelHandler
	masquerade    http.Handler
	// overLimitDecoy answers a request that both failed authentication and
	// exceeded the unauthenticated budget. It never touches the masquerade
	// backend, so an over-limit peer cannot keep driving it.
	overLimitDecoy http.Handler
	maxHeaderBytes int

	unauthenticatedLimiter *unauthenticatedLimiter
}

func NewServer(options ServerOptions) *Server {
	server := &Server{
		authenticator:  options.Authenticator,
		logger:         options.Logger,
		http1:          options.HTTP1,
		udp:            options.UDP,
		tunnels:        options.Tunnels,
		masquerade:     options.Masquerade,
		maxHeaderBytes: options.MaxHeaderBytes,
	}
	server.unauthenticatedLimiter = newUnauthenticatedLimiter(options.UnauthenticatedLimits.Build())
	if server.unauthenticatedLimiter != nil {
		// Only install the decoy when a limiter exists, so an unconfigured server
		// keeps the upstream response shape exactly.
		server.overLimitDecoy = NewOverLimitDecoy()
	}
	if server.maxHeaderBytes <= 0 {
		server.maxHeaderBytes = maxHeaderBytes
	}
	if options.HTTP2 {
		// The casts below are safe because the option values were range-checked
		// in option.validateHTTPResourceBounds before reaching the server:
		// MaxConcurrentStreams is within MaxUint32 and both windows are within
		// MaxInt32. The previous min/max clamps silently repaired out-of-range
		// values, which meant a nonsensical configuration produced a working
		// server with a limit nobody chose.
		server.http2Server = &http2.Server{
			IdleTimeout:                  idleTimeout,
			ReadIdleTimeout:              time.Duration(options.HTTP2Options.KeepAlivePeriod),
			PingTimeout:                  time.Duration(options.HTTP2Options.IdleTimeout),
			MaxConcurrentStreams:         uint32(options.HTTP2Options.MaxConcurrentStreams),
			MaxUploadBufferPerConnection: int32(options.HTTP2Options.ConnectionReceiveWindow.Value()),
			MaxUploadBufferPerStream:     int32(options.HTTP2Options.StreamReceiveWindow.Value()),
		}
		if options.HTTP2Options.IdleTimeout > 0 {
			server.http2Server.IdleTimeout = time.Duration(options.HTTP2Options.IdleTimeout)
		}
	}
	return server
}

func (s *Server) ServeConnection(ctx context.Context, conn net.Conn, reader *Reader, handler Handler, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	if s.http2Server != nil {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
		isHTTP2, err := reader.isHTTP2Preface()
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			s.finishConnection(ctx, conn, source, onClose, E.Cause(err, "peek request"))
			return
		}
		if isHTTP2 {
			s.serveHTTP2(ctx, conn, reader, handler, source, onClose)
			return
		}
	}
	if !s.http1 {
		_, err := conn.Write([]byte("HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		s.finishConnection(ctx, conn, source, onClose, err)
		return
	}
	connection := &serverConn{
		server:  s,
		ctx:     ctx,
		conn:    conn,
		reader:  reader,
		handler: handler,
		source:  source,
		onClose: onClose,
	}
	connection.serve()
}

// ConfigureTLS resolves the ALPN list this server's TCP listener may negotiate.
//
// It used to write h2/http1.1 into the SHARED config, and ListenHTTP3 then
// prepended h3 to that same object. Both listeners therefore negotiated from one
// union, which was measured to leak in both directions: a TCP client offering h3
// was told to speak h3, a QUIC-only protocol, and a QUIC client offering h2 was
// told to speak h2. Native Naive had the identical defect and it is fixed the same
// way here - by giving each transport its OWN view of the shared config rather
// than mutating it.
//
// The list is returned rather than applied so the caller can wrap the config in a
// transport-scoped view; see tls.TransportALPNView. Operators who configured ALPN
// explicitly keep it, because their value is used verbatim.
func (s *Server) ConfigureTLS(tlsConfig tls.ServerConfig) []string {
	if configured := tlsConfig.NextProtos(); len(configured) > 0 {
		return configured
	}
	var nextProtos []string
	if s.http2Server != nil {
		nextProtos = append(nextProtos, http2.NextProtoTLS)
	}
	if s.http1 {
		nextProtos = append(nextProtos, "http/1.1")
	}
	return nextProtos
}

// HTTP3NextProtos returns the ALPN list for this server's HTTP/3 listener.
//
// h3 and nothing else: the QUIC transport speaks HTTP/3, and offering a
// TCP-oriented protocol there is what let a QUIC client negotiate h2.
//
// An operator-configured list is still honoured for any protocol the server does
// not own, but h3 is always present, because without it the QUIC listener could
// not complete a handshake at all.
func (s *Server) HTTP3NextProtos(tlsConfig tls.ServerConfig) []string {
	protos := []string{"h3"}
	for _, configured := range tlsConfig.NextProtos() {
		if configured == "h3" || configured == http2.NextProtoTLS || configured == "http/1.1" {
			continue
		}
		protos = append(protos, configured)
	}
	return protos
}

func (s *Server) ListenHTTP3(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler Handler, tlsConfig tls.ServerConfig, options option.QUICOptions) (io.Closer, error) {
	if ConfigureHTTP3ListenerFunc == nil {
		return nil, C.ErrQUICNotIncluded
	}
	// The QUIC listener gets its OWN ALPN view, so the shared config is never
	// mutated and the TCP listener cannot inherit h3.
	quicTLSConfig := tls.TransportALPNView(tlsConfig, s.HTTP3NextProtos(tlsConfig))
	return ConfigureHTTP3ListenerFunc(ctx, logger, listener, &httpHandler{
		server:  s,
		handler: handler,
	}, quicTLSConfig, options, s.maxHeaderBytes)
}

func (s *Server) finishConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc, err error) {
	conn.Close()
	if err != nil {
		if E.IsClosedOrCanceled(err) || E.IsTimeout(err) {
			s.logger.DebugContext(ctx, "connection closed: ", err)
			err = nil
		} else {
			s.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", source))
		}
	}
	if onClose != nil {
		onClose(err)
	}
}
