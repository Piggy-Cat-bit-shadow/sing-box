package http

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"

	"golang.org/x/net/http2"
)

const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (r *Reader) isHTTP2Preface() (bool, error) {
	head, err := r.Peek(3)
	if err != nil {
		return false, err
	}
	if string(head) != http2Preface[:3] {
		return false, nil
	}
	preface, err := r.Peek(len(http2Preface))
	if err != nil {
		return false, err
	}
	return string(preface) == http2Preface, nil
}

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

type statedConn struct {
	net.Conn
	stater connectionStater
}

func (c *statedConn) ConnectionState() tls.ConnectionState {
	return c.stater.ConnectionState()
}

func (s *Server) serveHTTP2(ctx context.Context, conn net.Conn, reader *Reader, handler Handler, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	serveConn := reader.cachedConn(conn)
	stater, isStater := conn.(connectionStater)
	if isStater && serveConn != conn {
		serveConn = &statedConn{Conn: serveConn, stater: stater}
	}
	s.http2Server.ServeConn(serveConn, &http2.ServeConnOpts{
		Context: ctx,
		BaseConfig: &http.Server{
			MaxHeaderBytes: s.maxHeaderBytes,
		},
		Handler: &httpHandler{
			server:    s,
			handler:   handler,
			source:    source,
			plaintext: !isStater,
		},
	})
	if onClose != nil {
		onClose(nil)
	}
}

type httpHandler struct {
	server    *Server
	handler   Handler
	source    M.Socksaddr
	plaintext bool
}

func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	connectionSource := h.source
	if !connectionSource.IsValid() {
		connectionSource = h.resolveSource(request)
	}
	var protocol string
	if request.Method == http.MethodConnect {
		protocol = request.Header.Get(":protocol")
		if protocol == "" && request.ProtoMajor == 3 && !strings.HasPrefix(request.Proto, "HTTP/") {
			protocol = request.Proto
		}
	}
	tunnelHandler := h.server.tunnels[protocol]
	if tunnelHandler != nil {
		// Authenticate FIRST. A successful authentication must not touch the
		// limiter at all: no token is consumed, no concurrent slot is taken and
		// the limiter map is not consulted. Acquiring before authenticating made
		// authenticated traffic pay for the limiter and could delay it under
		// abuse.
		authCtx, authErr := h.server.authenticate(ctx, request, "Authorization")
		if authErr == nil {
			h.serveTunnel(authCtx, writer, request, badhttp.ForwardedSource(request, connectionSource), tunnelHandler)
			return
		}
		h.serveUnauthenticatedFailure(ctx, writer, request, connectionSource, authErr, false)
		return
	}
	// Authenticate FIRST, for the same reason as the tunnel path above.
	proxyCtx, authErr := h.server.authenticate(ctx, request, "Proxy-Authorization")
	if authErr != nil {
		h.serveUnauthenticatedFailure(ctx, writer, request, connectionSource, authErr, true)
		return
	}
	// Only a request that has already AUTHENTICATED may learn that no proxy
	// handler is installed. Answering 404 before authenticating made a
	// configured-but-absent proxy handler externally distinguishable from a
	// normal web server and let an unauthenticated prober bypass the limiter
	// entirely, since the limiter is only consulted on an authentication
	// failure.
	if h.handler == nil {
		h.server.logger.ErrorContext(ctx, "process connection from ", connectionSource, ": unexpected request: ", request.Method, " ", request.URL)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	ctx = proxyCtx
	source := badhttp.ForwardedSource(request, connectionSource)
	if request.Method == http.MethodConnect {
		switch {
		case protocol == "":
			h.serveConnect(ctx, writer, request, source)
		case protocol == connectUDPProtocol && h.server.udp:
			h.serveConnectUDP(ctx, writer, request, source)
		default:
			h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unsupported CONNECT protocol: ", protocol)
			writer.WriteHeader(http.StatusNotImplemented)
		}
		return
	}
	h.serveForward(ctx, writer, request, source)
}

// rejectUnauthenticated answers a request that both failed authentication and
// exceeded the unauthenticated budget.
//
// It deliberately does NOT call the masquerade handler. For a `proxy` masquerade
// that handler issues a real HTTP request to the configured backend, so using it
// here would mean an over-limit attacker still drives one backend request per
// probe — the opposite of a resource bound. The locally generated decoy costs no
// outbound connection and is shaped like an ordinary web server response, so the
// limiter remains invisible to a prober: no 401, no 407 and no auth headers.
func (h *httpHandler) rejectUnauthenticated(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	h.server.logger.DebugContext(ctx, "unauthenticated request from ", source, " over the unauthenticated budget")
	decoy := h.server.overLimitDecoy
	if decoy == nil {
		decoy = NewOverLimitDecoy()
	}
	decoy.ServeHTTP(writer, request)
}

// serveUnauthenticatedFailure handles a request that has already FAILED
// authentication. It is only reached on that path, so authenticated proxy
// traffic never touches the limiter.
//
// Order of operations:
//
//  1. acquire the limiter slot (token + per-IP concurrency);
//  2. if allowed, serve the masquerade handler while HOLDING the slot, so the
//     concurrency bound covers the entire backend request, not just admission;
//  3. if over limit, answer with the local decoy and never reach the backend.
func (h *httpHandler) serveUnauthenticatedFailure(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr, authErr error, proxyAuth bool) {
	release, overLimit := h.admitUnauthenticated(source)
	if overLimit {
		release()
		h.rejectUnauthenticated(ctx, writer, request, source)
		return
	}
	if h.server.masquerade != nil {
		// The slot is released only after the masquerade handler returns, which is
		// what makes the per-IP concurrency bound cover the backend request.
		defer release()
		// Bound the body an unauthenticated peer can push at the decoy backend.
		// Without this a failed-auth request could stream an arbitrarily large
		// body through the reverse proxy.
		if request.Body != nil && request.Body != http.NoBody {
			request.Body = http.MaxBytesReader(writer, request.Body, maxUnauthenticatedBodyBytes)
		}
		h.serveAuthFailure(ctx, writer, request, source, authErr, proxyAuth)
		return
	}
	release()
	h.serveAuthFailure(ctx, writer, request, source, authErr, proxyAuth)
}

// admitUnauthenticated accounts a FAILED authentication attempt against the
// limiter.
//
// It is called only after authentication has failed, so it never consumes budget
// for legitimate proxy traffic.
func (h *httpHandler) admitUnauthenticated(source M.Socksaddr) (release func(), overLimit bool) {
	limiter := h.server.unauthenticatedLimiter
	if limiter == nil {
		return func() {}, false
	}
	release, allowed := limiter.acquire(source.AddrString(), time.Now())
	return release, !allowed
}

// serveAuthFailure handles a failed authentication attempt. With a masquerade
// handler the request is served a normal web response, which is the intended
// design path and therefore logged at debug level; the previous code logged
// these at error level even though the client received a 200. Without a
// masquerade handler a real 401/407 challenge is returned and logged as an
// error, which stays an error.
func (h *httpHandler) serveAuthFailure(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr, authErr error, proxyAuth bool) {
	if h.server.masquerade != nil {
		h.server.logger.DebugContext(ctx, E.Cause(authErr, "masquerade unauthenticated request from ", source))
		h.server.masquerade.ServeHTTP(writer, request)
		return
	}
	h.server.logger.ErrorContext(ctx, E.Cause(authErr, "process connection from ", source))
	if proxyAuth {
		writer.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	writer.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	writer.WriteHeader(http.StatusUnauthorized)
}

func (h *httpHandler) serveConnect(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination := connectDestination(request)
	if !destination.IsValid() {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid CONNECT target: ", request.Host)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	wrapped := v2rayhttp.NewHTTP2Wrapper(&v2rayhttp.ServerHTTPConn{
		HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer),
		Flusher:   writer.(http.Flusher),
	})
	// Normalize stream-level errors at the OUTERMOST boundary, which is what the
	// routing layer actually reads and writes.
	//
	// Wrapping only request.Body is not enough: NewHTTP2Wrapper layers a
	// bufio.ExtendedConn on top, and its buffered write path bypasses the inner
	// wrapper entirely, so an orderly HTTP/3 close still surfaced as an
	// unrecognised "H3 error (0x0)" and route/conn.go logged it at ERROR.
	conn := &normalizingConn{inner: wrapped}
	done := make(chan struct{})
	h.handler.NewConnectionEx(ctx, conn, source, destination, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	wrapped.CloseWrapper()
}

func (h *httpHandler) serveForward(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	// golang.org/x/net/http2 builds the request URL from :path only (internal/httpcommon.NewServerRequest);
	// :scheme survives only as request.TLS, which it sets when :scheme is https and the served conn
	// exposes ConnectionState, so on a plaintext conn the scheme is unknowable. quic-go/http3 sets URL.Scheme.
	if request.URL.Scheme == "" {
		if h.plaintext {
			h.server.logger.ErrorContext(ctx, "process connection from ", source, ": forward request over cleartext HTTP/2")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.TLS != nil {
			request.URL.Scheme = "https"
		} else {
			request.URL.Scheme = "http"
		}
	}
	request.URL.Host = request.Host
	destination, valid := forwardDestination(request)
	if !valid {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid forward target: ", request.URL.Scheme, "://", request.Host)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	removeHopByHopHeaders(request.Header)
	if _, loaded := request.Header["User-Agent"]; !loaded {
		request.Header["User-Agent"] = nil
	}
	if request.ContentLength == 0 {
		request.Body = http.NoBody
	}
	request.Close = false

	upstream := newUpstreamConn(ctx, h.handler, source, destination)
	stop := context.AfterFunc(request.Context(), func() {
		upstream.Close()
	})
	defer stop()
	writeDone := make(chan error, 1)
	go func() {
		err := request.Write(upstream)
		if err != nil {
			upstream.Close()
		}
		writeDone <- err
	}()
	defer func() {
		upstream.Close()
		request.Body.Close()
		<-writeDone
	}()

	var response *http.Response
	for {
		var err error
		response, err = upstream.readResponse(request)
		if err != nil {
			upstream.Close()
			h.server.logger.ErrorContext(ctx, E.Cause(E.Errors(upstream.closeErr(), err), "process connection from ", source, ": read upstream response"))
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		if response.StatusCode >= 200 {
			break
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			upstream.Close()
			h.server.logger.ErrorContext(ctx, "process connection from ", source, ": unexpected 101 response")
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		removeHopByHopHeaders(response.Header)
		maps.Copy(writer.Header(), response.Header)
		writer.WriteHeader(response.StatusCode)
		clear(writer.Header())
	}
	removeHopByHopHeaders(response.Header)
	maps.Copy(writer.Header(), response.Header)
	if !responseHasBody(request, response) && request.Method != http.MethodHead {
		writer.Header().Del("Content-Length")
	}
	for name := range response.Trailer {
		writer.Header().Add("Trailer", name)
	}
	writer.WriteHeader(response.StatusCode)
	if !responseHasBody(request, response) {
		response.Body.Close()
		return
	}
	writer.(http.Flusher).Flush()
	_, err := bufio.Copy(flushWriter{writer}, response.Body)
	if err != nil {
		upstream.Close()
		response.Body.Close()
		h.server.logger.DebugContext(ctx, "process connection from ", source, ": relay response: ", err)
		panic(http.ErrAbortHandler)
	}
	response.Body.Close()
	maps.Copy(writer.Header(), response.Trailer)
}

func newUpstreamConn(ctx context.Context, handler Handler, source M.Socksaddr, destination M.Socksaddr) *upstreamConn {
	serverSide, clientSide := pipe.Pipe()
	limiter := &readLimiter{reader: clientSide, remaining: -1}
	upstream := &upstreamConn{
		Conn:        clientSide,
		reader:      std_bufio.NewReader(limiter),
		limiter:     limiter,
		source:      source,
		destination: destination,
		done:        make(chan struct{}),
	}
	go handler.NewConnectionEx(ctx, serverSide, source, destination, N.OnceClose(func(it error) {
		upstream.err = it
		close(upstream.done)
	}))
	return upstream
}

type flushWriter struct {
	http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, err
	}
	w.ResponseWriter.(http.Flusher).Flush()
	return n, nil
}

// resolveSource determines the peer address for a request. It prefers the
// address captured when the connection was accepted, then quic-go's HTTP/3
// context value, and finally http.Request.RemoteAddr.
func (h *httpHandler) resolveSource(request *http.Request) M.Socksaddr {
	if request == nil {
		return M.Socksaddr{}
	}
	if source, loaded := http3RemoteAddr(request); loaded {
		return source.Unwrap()
	}
	return M.ParseSocksaddr(request.RemoteAddr).Unwrap()
}
