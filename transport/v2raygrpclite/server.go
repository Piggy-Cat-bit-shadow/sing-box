package v2raygrpclite

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

type Server struct {
	tlsConfig  tls.ServerConfig
	logger     logger.ContextLogger
	handler    adapter.V2RayServerTransportHandler
	httpServer *http.Server
	h2Server   *http2.Server
	h2cHandler http.Handler
	path       string
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayGRPCOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	server := &Server{
		tlsConfig: tlsConfig,
		logger:    logger,
		handler:   handler,
		// The service name is a PATH, not a path segment; service_name.go has the reference's rule.
		path: servicePath(options.ServiceName),
		h2Server: &http2.Server{
			IdleTimeout: time.Duration(options.IdleTimeout),
		},
	}
	server.httpServer = &http.Server{
		Handler: server,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
	}
	//nolint:staticcheck
	server.h2cHandler = h2c.NewHandler(server, server.h2Server)
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "PRI" && len(request.Header) == 0 && request.URL.Path == "*" && request.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(writer, request)
		return
	}
	// EscapedPath, not Path: net/http DECODES the request target into Path, so a service name that
	// is itself an escape (`a%2Fb`) could never match its own literal comparison - and a name with a
	// literal `/` would match a path the reference would not have sent. EscapedPath() is the raw
	// path the reference server dispatches on; see service_name.go.
	if request.URL.EscapedPath() != s.path {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad path: ", request.URL.EscapedPath()))
		return
	}
	if request.Method != http.MethodPost {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad method: ", request.Method))
		return
	}
	if ct := request.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/grpc") {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad content type: ", ct))
		return
	}
	writer.Header().Set("Content-Type", "application/grpc")
	writer.Header().Set("TE", "trailers")
	writer.WriteHeader(http.StatusOK)
	done := make(chan struct{})
	conn := v2rayhttp.NewHTTP2Wrapper(newGunConn(request.Body, writer, writer.(http.Flusher)))
	s.handler.NewConnectionEx(request.Context(), conn, badhttp.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	conn.CloseWrapper()
}

func (s *Server) invalidRequest(writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	if statusCode > 0 {
		writer.WriteHeader(statusCode)
	}
	s.logger.ErrorContext(request.Context(), E.Cause(err, "process connection from ", request.RemoteAddr))
}

func (s *Server) Network() []string {
	return []string{N.NetworkTCP}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{"h2"}, s.tlsConfig.NextProtos()...))
		}
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	return s.httpServer.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return os.ErrInvalid
}

func (s *Server) Close() error {
	return common.Close(common.PtrOrNil(s.httpServer))
}
