package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transportHttp "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

var (
	ConfigureHTTP3ListenerFunc func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error)
	WrapError                  func(error) error
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	options          option.NaiveInboundOptions
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
	h3Server         io.Closer
	// masquerade serves ordinary web traffic on the proxy port. It is nil when
	// no masquerade is configured, in which case the upstream reject behaviour
	// is kept. It is shared with the HTTP/MASQUE inbounds and has no access to
	// the proxy data path, so it can never open a tunnel.
	masquerade http.Handler
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
		authenticator:    auth.NewAuthenticator(options.Users),
	}
	if common.Contains(inbound.network, N.NetworkUDP) {
		if options.TLS == nil || !options.TLS.Enabled {
			return nil, E.New("TLS is required for QUIC server")
		}
	}
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	masqueradeHandler, err := transportHttp.NewMasqueradeHandler(ctx, options.Masquerade)
	if err != nil {
		return nil, err
	}
	inbound.masquerade = masqueradeHandler
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if common.Contains(n.network, N.NetworkTCP) {
		tcpListener, err := n.listener.ListenTCP()
		if err != nil {
			return err
		}
		n.httpServer = &http.Server{
			//nolint:staticcheck
			Handler: h2c.NewHandler(n, &http2.Server{}),
			BaseContext: func(listener net.Listener) context.Context {
				return n.ctx
			},
		}
		listener := net.Listener(tcpListener)
		if n.tlsConfig != nil {
			if len(n.tlsConfig.NextProtos()) == 0 {
				n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
			} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
				n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
			}
			listener = aTLS.NewListener(tcpListener, n.tlsConfig)
		}
		go func() {
			sErr := n.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				n.logger.Error("http server serve error: ", sErr)
			}
		}()
	}

	if common.Contains(n.network, N.NetworkUDP) {
		http3Server, err := ConfigureHTTP3ListenerFunc(n.ctx, n.logger, n.listener, n, n.tlsConfig, n.options)
		if err == nil {
			n.h3Server = http3Server
		} else if len(n.network) > 1 {
			n.logger.Warn(E.Cause(err, "naive http3 disabled"))
		} else {
			return err
		}
	}

	return nil
}

func (n *Inbound) Close() error {
	return common.Close(
		n.listener,
		common.PtrOrNil(n.httpServer),
		n.h3Server,
		n.tlsConfig,
	)
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())

	// A Naive proxy request is, by definition, an authenticated HTTP CONNECT.
	// Everything else is "not a proxy request" and is handled by the masquerade
	// when one is configured.
	//
	// This shape deliberately mirrors klzgrad/forwardproxy: the request is
	// parsed FIRST, authentication is checked SECOND, and only a request that is
	// both a CONNECT and correctly authenticated ever reaches the tunnel. A
	// missing Padding header is NOT a reason to reject a CONNECT -- see below.
	if request.Method != http.MethodConnect {
		n.serveWebOrReject(ctx, writer, request, http.StatusBadRequest, E.New("not CONNECT request"))
		return
	}

	userName, password, authOk := badhttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	if authOk {
		authOk = n.authenticator.Verify(userName, password)
	}
	if !authOk {
		// An unauthenticated CONNECT must never open a tunnel. With a
		// masquerade configured it is answered as ordinary web traffic so the
		// endpoint does not advertise a proxy authentication surface; without
		// one it keeps the upstream 407 challenge.
		n.serveWebOrReject(ctx, writer, request, http.StatusProxyAuthRequired, E.New("authorization failed"))
		return
	}

	// A CONNECT that carries no Padding header is NOT invalid. The Padding
	// header is a Naive EXTENSION: klzgrad/forwardproxy only enables padding
	// frames when the client actually sent the header, and treats a CONNECT
	// without it as a standard HTTP proxy request. Rejecting it here broke
	// plain HTTP CONNECT clients and every Naive client that does not pad.
	//
	// The response Padding header is still emitted for a padding client so the
	// negotiation completes, and padding frames are then read/written on the
	// tunnel exactly as before.
	usePadding := request.Header.Get("Padding") != ""

	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	destination := M.ParseSocksaddr(hostPort).Unwrap()
	if !destination.IsValid() {
		n.serveWebOrReject(ctx, writer, request, http.StatusBadRequest, E.New("invalid CONNECT target: ", hostPort))
		return
	}

	if usePadding {
		writer.Header().Set("Padding", generatePaddingHeader())
	}
	writer.WriteHeader(http.StatusOK)
	flusher, isFlusher := writer.(http.Flusher)
	if !isFlusher {
		n.badRequest(ctx, request, E.New("response writer is not a flusher"))
		return
	}
	flusher.Flush()

	source := badhttp.SourceAddress(request)

	if hijacker, isHijacker := writer.(http.Hijacker); isHijacker {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			n.badRequest(ctx, request, E.New("hijack failed"))
			return
		}
		n.newConnection(ctx, false, &naiveConn{Conn: conn, paddingConn: paddingConn{enabled: usePadding}}, userName, source, destination)
	} else {
		n.newConnection(ctx, true, &naiveH2Conn{
			reader:        request.Body,
			writer:        writer,
			flusher:       flusher,
			remoteAddress: source,
			paddingConn:   paddingConn{enabled: usePadding},
		}, userName, source, destination)
	}
}

// serveWebOrReject answers a request that is not an authenticated Naive CONNECT.
//
// With a masquerade configured the request is served the masquerade handler,
// which is a normal web response and reveals nothing about the proxy. Without
// one, the request is rejected with the given status exactly as before.
//
// The masquerade path is deliberately WEB-ONLY: it is only reached before any
// tunnel exists, and it never receives the tunnel connection. That ordering is
// what makes "an unauthenticated CONNECT can never become a tunnel" true by
// construction rather than by a later check.
func (n *Inbound) serveWebOrReject(ctx context.Context, writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	if n.masquerade != nil {
		// Logged at debug: a probe or a browser hitting the port is the
		// intended design path for the masquerade and must not flood the error
		// log. Real faults on the tunnel path are still logged as errors.
		n.logger.DebugContext(ctx, E.Cause(err, "masquerade request from ", request.RemoteAddr))
		n.serveMasquerade(ctx, writer, request)
		return
	}
	rejectHTTP(writer, statusCode)
	n.badRequest(ctx, request, err)
}

// serveMasquerade serves the decoy web response, with the request sanitised so
// that the proxy credential can never leak to the web backend.
func (n *Inbound) serveMasquerade(ctx context.Context, writer http.ResponseWriter, request *http.Request) {
	// Proxy-Authorization carries a proxy credential in the clear. It must never
	// be forwarded to the masquerade backend, whatever the backend is.
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	n.masquerade.ServeHTTP(writer, request)
}

func (n *Inbound) newConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound connection from ", source)
		n.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		n.router.RouteConnectionEx(ctx, conn, metadata, nil)
	} else {
		done := make(chan struct{})
		wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
		n.router.RouteConnectionEx(ctx, wrapper, metadata, N.OnceClose(func(it error) {
			close(done)
		}))
		<-done
		wrapper.CloseWrapper()
	}
}

func (n *Inbound) badRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func rejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)
		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}
