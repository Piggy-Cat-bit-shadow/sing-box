package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/common/badhttp"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type requestResult uint8

const (
	requestContinue requestResult = iota
	requestClose
	requestHandedOff
)

type serverConn struct {
	server   *Server
	ctx      context.Context
	conn     net.Conn
	reader   *Reader
	handler  Handler
	source   M.Socksaddr
	onClose  N.CloseHandlerFunc
	upstream *upstreamConn
}

func (c *serverConn) serve() {
	for {
		result, err := c.serveRequest()
		switch result {
		case requestContinue:
			continue
		case requestHandedOff:
			c.closeUpstream()
			return
		case requestClose:
			c.closeUpstream()
			c.server.finishConnection(c.ctx, c.conn, c.source, c.onClose, err)
			return
		}
	}
}

func (c *serverConn) serveRequest() (requestResult, error) {
	c.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	// Use the resolved per-server limit, not the package constant, so
	// max_header_bytes applies to HTTP/1.1 as well as HTTP/2 and HTTP/3.
	c.reader.setLimit(int64(c.server.maxHeaderBytes))
	request, err := badhttp.ReadRequest(c.reader.Reader)
	c.reader.setLimit(-1)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		switch {
		case errors.Is(err, io.EOF), E.IsTimeout(err), E.IsClosed(err):
			return requestClose, err
		case errors.Is(err, errHeaderTooLarge):
			return c.rejectAndClose(nil, http.StatusRequestHeaderFieldsTooLarge, err)
		default:
			return c.rejectAndClose(nil, http.StatusBadRequest, E.Cause(err, "read request"))
		}
	}
	tunnelProtocol, tunnelHandler := c.server.upgradeTunnelHandler(request)
	if tunnelHandler != nil {
		tunnelCtx, tunnelAuthErr := c.server.authenticate(c.ctx, request, "Authorization")
		if tunnelAuthErr != nil {
			c.server.logger.ErrorContext(c.ctx, E.Cause(tunnelAuthErr, "process connection from ", c.source))
			return c.reject(request, requestKeepAlive(request), http.StatusUnauthorized, nil, tunnelAuthErr)
		}
		// c.source is the transport peer. X-Forwarded-For is deliberately not
		// consulted: it is client-controlled and must not decide metadata.Source.
		return c.serveTunnel(tunnelCtx, request, c.source, tunnelProtocol, tunnelHandler)
	}
	if c.handler == nil {
		return c.reject(request, requestKeepAlive(request), http.StatusNotFound, nil, E.New("unexpected request: ", request.Method, " ", request.URL))
	}
	ctx, authErr := c.server.authenticate(c.ctx, request, "Proxy-Authorization")
	if authErr != nil {
		c.server.logger.ErrorContext(c.ctx, E.Cause(authErr, "process connection from ", c.source))
		return c.reject(request, c.rejectionKeepAlive(request), http.StatusProxyAuthRequired, nil, authErr)
	}
	// The transport peer, not a client-supplied header.
	source := c.source
	switch {
	case request.Method == http.MethodConnect:
		return c.serveConnect(ctx, request, source)
	case c.server.udp && requestIsConnectUDP(request):
		return c.serveConnectUDP(ctx, request, source)
	case requestIsUpgrade(request):
		return c.serveForward(ctx, request, source, true)
	default:
		return c.serveForward(ctx, request, source, false)
	}
}

func (c *serverConn) serveConnect(ctx context.Context, request *http.Request, source M.Socksaddr) (requestResult, error) {
	destination := connectDestination(request)
	if !destination.IsValid() {
		return c.reject(request, c.rejectionKeepAlive(request), http.StatusBadRequest, nil, E.New("invalid CONNECT target: ", request.URL.Host))
	}
	_, err := c.conn.Write([]byte(F.ToString("HTTP/", request.ProtoMajor, ".", request.ProtoMinor, " 200 Connection established\r\n\r\n")))
	if err != nil {
		return requestClose, E.Cause(err, "write response")
	}
	c.handler.NewConnectionEx(ctx, c.reader.cachedConn(c.conn), source, destination, c.onClose)
	return requestHandedOff, nil
}

// rejectionKeepAlive decides whether a REJECTED request may leave the HTTP/1.1
// connection open.
//
// RFC 9931 section 8 ("Requirements for HTTP CONNECT") makes this a MUST, not a
// preference:
//
//	"As a mitigation, proxy servers MUST close the underlying connection when
//	 rejecting a CONNECT request without processing any further requests on
//	 that connection.  This requirement applies whether or not the request
//	 includes a 'close' connection option."
//
// The attack it closes: a proxy CLIENT that forwards untrusted TCP payload
// optimistically, before it has seen the 2xx, cannot know whether the server
// accepted the tunnel. If the server REJECTS the CONNECT it returns to reading
// HTTP/1.1 on the same connection, so the optimistically forwarded bytes are
// parsed as a further request -- a request the client is then deemed to have
// made. Answering it is a request-smuggling primitive.
//
// The RFC also updates CONNECT-UDP (section 6.3) for the same reason: an
// HTTP/1.x CONNECT-UDP upgrade "is likely to be rejected in certain
// circumstances, such as when the UDP destination address (which is
// attacker-controlled) is invalid", and the tunnel content can be untrusted
// material from other applications on the client device. So an HTTP/1.1
// CONNECT-UDP rejected before the 101 must close too.
//
// This applies only to HTTP/1.1. HTTP/2 and HTTP/3 give every request an
// explicit stream, so a rejected request cannot leave a second one half-read on
// a shared byte stream; the RFC says so and recommends them as the way to avoid
// the cost below.
//
// The cost is real and is accepted deliberately: the RFC notes the mitigation
// "will frequently cause slower connection establishment ... especially when
// returning a 407", because a compliant client must reconnect and renegotiate
// TLS. That is the price of not being a smuggling vector, and it is paid only
// on the rejection path -- an accepted CONNECT still hands the connection to the
// tunnel and is unaffected.
//
// Note the deliberate asymmetry with requestKeepAlive: an ordinary rejected
// request (a bad GET, say) still honours keep-alive, because no protocol
// transition was requested and the smuggling shape does not arise. Only the
// CONNECT and CONNECT-UDP rejection paths use this.
func (c *serverConn) rejectionKeepAlive(request *http.Request) bool {
	// Always false. It is a function rather than a constant so each rejection
	// site reads as a deliberate decision, and so the HTTP-version condition the
	// RFC scopes this to can be expressed if a future HTTP/1.x version ever
	// makes a difference here.
	if request.ProtoAtLeast(2, 0) {
		// Not reachable from the HTTP/1.1 server connection, which is the only
		// caller. If that ever changes, an HTTP/2 or HTTP/3 request has an
		// explicit stream and must NOT be closed for this reason.
		return true
	}
	return false
}

func (c *serverConn) reject(request *http.Request, keepAlive bool, statusCode int, header http.Header, cause error) (requestResult, error) {
	if keepAlive && request.Body != nil && request.Body != http.NoBody {
		keepAlive = c.discardBody(request.Body)
	}
	err := c.writeReject(request, statusCode, header, keepAlive)
	if err != nil {
		return requestClose, E.Errors(cause, err)
	}
	if keepAlive {
		return requestContinue, nil
	}
	return requestClose, cause
}

func (c *serverConn) rejectAndClose(request *http.Request, statusCode int, cause error) (requestResult, error) {
	err := c.writeReject(request, statusCode, nil, false)
	if err != nil {
		return requestClose, E.Errors(cause, err)
	}
	return requestClose, cause
}

func (c *serverConn) writeReject(request *http.Request, statusCode int, header http.Header, keepAlive bool) error {
	response := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header.Clone(),
		Request:    request,
		Close:      !keepAlive,
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	if request != nil {
		response.ProtoMajor = request.ProtoMajor
		response.ProtoMinor = request.ProtoMinor
	}
	switch statusCode {
	case http.StatusProxyAuthRequired:
		response.Header.Set("Proxy-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	case http.StatusUnauthorized:
		response.Header.Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	}
	if keepAlive && request.ProtoMajor == 1 && request.ProtoMinor == 0 {
		response.Header.Set("Connection", "keep-alive")
		response.Header.Set("Proxy-Connection", "keep-alive")
	}
	err := response.Write(c.conn)
	if err != nil {
		return E.Cause(err, "write response")
	}
	return nil
}

func (c *serverConn) discardBody(body io.Reader) bool {
	c.conn.SetReadDeadline(time.Now().Add(discardBodyTimeout))
	_, err := io.CopyN(io.Discard, body, maxDiscardBodyBytes)
	c.conn.SetReadDeadline(time.Time{})
	return errors.Is(err, io.EOF)
}

func (c *serverConn) closeUpstream() {
	if c.upstream != nil {
		c.upstream.Close()
		c.upstream = nil
	}
}
