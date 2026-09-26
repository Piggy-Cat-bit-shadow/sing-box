package http

import (
	std_bufio "bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/transport/v2rayhttp"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	connectUDPProtocol   = "connect-udp"
	connectUDPPathPrefix = "/.well-known/masque/udp/"
)

func parseConnectUDPTarget(path string) (M.Socksaddr, bool) {
	rest, found := strings.CutPrefix(path, connectUDPPathPrefix)
	if !found {
		return M.Socksaddr{}, false
	}
	segments := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(segments) != 2 {
		return M.Socksaddr{}, false
	}
	host, err := url.PathUnescape(segments[0])
	if err != nil || host == "" {
		return M.Socksaddr{}, false
	}
	port, err := strconv.ParseUint(segments[1], 10, 16)
	if err != nil || port == 0 {
		return M.Socksaddr{}, false
	}
	destination := M.ParseSocksaddrHostPort(host, uint16(port)).Unwrap()
	if !destination.IsValid() {
		return M.Socksaddr{}, false
	}
	return destination, true
}

func connectUDPURL(destination M.Socksaddr) *url.URL {
	host := destination.AddrString()
	port := "/" + strconv.Itoa(int(destination.Port)) + "/"
	return &url.URL{
		Path:    connectUDPPathPrefix + host + port,
		RawPath: connectUDPPathPrefix + strings.ReplaceAll(url.PathEscape(host), ":", "%3A") + port,
	}
}

func requestIsConnectUDP(request *http.Request) bool {
	return request.Method == http.MethodGet && requestIsUpgrade(request) && strings.EqualFold(request.Header.Get("Upgrade"), connectUDPProtocol)
}

func (c *serverConn) serveConnectUDP(ctx context.Context, request *http.Request, source M.Socksaddr) (requestResult, error) {
	destination, valid := parseConnectUDPTarget(request.URL.EscapedPath())
	if !valid || !request.ProtoAtLeast(1, 1) {
		return c.reject(request, c.rejectionKeepAlive(request), http.StatusBadRequest, nil, E.New("invalid connect-udp request: ", request.URL.Path))
	}
	_, err := c.conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"))
	if err != nil {
		return requestClose, E.Cause(err, "write response")
	}
	c.handler.NewPacketConnectionEx(ctx, newCapsuleConn(c.reader.Reader, c.conn, destination), source, destination, c.onClose)
	return requestHandedOff, nil
}

func (h *httpHandler) serveConnectUDP(ctx context.Context, writer http.ResponseWriter, request *http.Request, source M.Socksaddr) {
	destination, valid := parseConnectUDPTarget(request.URL.EscapedPath())
	if !valid {
		h.server.logger.ErrorContext(ctx, "process connection from ", source, ": invalid connect-udp target: ", request.URL.Path)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if request.ProtoMajor == 3 && HTTP3StreamFunc != nil {
		stream, isDatagramStream := HTTP3StreamFunc(request.Context(), writer)
		if isDatagramStream {
			localAddr, _ := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
			conn := newHTTP3PacketConn(stream, destination, localAddr)
			// Hold the response until the target is actually reachable.
			//
			// Without this the sequence was: 200 OK, flush, and only THEN dial the
			// target. A DNS or dial failure therefore arrived after the client had
			// already been told the tunnel was up, and the only signal left was a
			// silent dead tunnel - the client could not distinguish "target
			// unreachable" from "target is quiet".
			//
			// The router signals the outcome through the handshake hooks, and this
			// goroutine is the only one that touches the ResponseWriter. So the
			// router never writes here; it only reports, and the handler decides.
			conn.deferUntilTargetReady()
			h.handler.NewPacketConnectionEx(ctx, conn, source, destination, nil)

			if err := conn.AwaitReady(request.Context()); err != nil {
				// The target could not be set up and the headers are still unset, so a
				// real HTTP error can be returned instead of a 200.
				h.server.logger.ErrorContext(ctx, "process connection from ", source,
					": connect-udp target setup failed: ", err)
				conn.Close()
				rejectConnectUDPSetup(writer, err)
				return
			}

			writer.Header().Set("Capsule-Protocol", "?1")
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			conn.wait(request.Context())
			return
		}
	}
	writer.Header().Set("Capsule-Protocol", "?1")
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
	// Normalize stream-level errors before they reach the routing layer, for the
	// same reason as serveConnect: route/conn.go logs a copy failure at ERROR
	// unless it recognises the error as a normal closure, and an http3.Error
	// carrying ErrCodeNoError is not recognised on its own.
	rawConn := v2rayhttp.NewHTTP2Wrapper(&v2rayhttp.ServerHTTPConn{
		HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer),
		Flusher:   writer.(http.Flusher),
	})
	conn := &normalizingConn{inner: rawConn}
	done := make(chan struct{})
	h.handler.NewPacketConnectionEx(ctx, newCapsuleConn(std_bufio.NewReader(conn), conn, destination), source, destination, N.OnceClose(func(it error) {
		close(done)
	}))
	<-done
	rawConn.CloseWrapper()
}

// rejectConnectUDPSetup maps a target-setup failure to an HTTP status, and adds a
// Proxy-Status only where RFC 9209 has a token that matches the meaning EXACTLY.
//
// The mapping is deliberately conservative, and the reasoning mirrors the masque-server
// endpoint audit:
//
//	deadline / timeout        -> 504, no Proxy-Status. RFC 9209 has no timeout token, and
//	                             connection_timeout describes the client's connection, not
//	                             the proxy's upstream dial.
//	DNS resolution failure    -> 502 with error=dns_error, which IS an exact match:
//	                             RFC 9209 section 2.3.4 defines it as "the proxy failed to
//	                             resolve the requested hostname".
//	any other dial/route fail -> 502, no Proxy-Status. There is no token for "could not
//	                             reach the target", and http_protocol_error /
//	                             proxy_internal_error would both be wrong: the HTTP layer
//	                             was fine and nothing internal failed.
//
// Nothing internal is ever echoed: the client sees a status and, at most, the standard
// error token. The detailed cause stays in the server log.
func rejectConnectUDPSetup(writer http.ResponseWriter, err error) {
	switch {
	case E.IsTimeout(err) || errors.Is(err, context.DeadlineExceeded):
		writer.WriteHeader(http.StatusGatewayTimeout)
	case isDNSError(err):
		writer.Header().Set("Proxy-Status", "sing-box; error=dns_error")
		writer.WriteHeader(http.StatusBadGateway)
	default:
		writer.WriteHeader(http.StatusBadGateway)
	}
}

// isDNSError reports whether the failure came from name resolution.
//
// It walks the wrapped chain for a *net.DNSError rather than matching on message text,
// so a renamed error keeps working and an unrelated failure that merely mentions "dns"
// is not misreported as a DNS error with a Proxy-Status token attached.
func isDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
