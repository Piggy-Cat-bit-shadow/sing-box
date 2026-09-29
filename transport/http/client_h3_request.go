//go:build with_quic

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Generic HTTP/3 request support on the SAME connection the CONNECT-IP tunnel uses.
//
// # Why this exists
//
// draft-ietf-masque-connect-ip-dns-06 §3.5 says that when the proxy is authoritative for
// a DoH origin, "the client SHOULD send its DNS queries to that nameserver directly as
// independent HTTPS requests. When possible, those requests SHOULD be coalesced over the
// same HTTPS connection."
//
// That is a normative SHOULD for connection reuse, and it only means anything if the DoH
// requests really do travel on the CONNECT-IP connection. So this type's whole purpose is
// to open additional request streams on the connection `acquire()` already memoizes --
// never to create a second QUIC connection, and never to carry DoH inside the CONNECT-IP
// capsule stream.
//
// # Layering
//
// The CONNECT path and the generic path share a small primitive (openRequestStream) and
// then diverge, rather than one function growing a mode flag:
//
//	openRequestStream   acquire the ClientConn, open a stream, send the request, read the
//	                    response, wire up cancellation and cleanup
//	        |
//	        +-- openStream      CONNECT-specific: requires StatusOK, returns the stream for
//	        |                   tunnel use
//	        +-- RoundTripHTTP3  normal HTTP semantics: any status is a valid response, the
//	                            body is handed to the caller
//
// Both call the SAME acquire(), so they share one ClientConn by construction rather than
// by convention.

// http3RequestRoundTripper is an OPTIONAL capability of an HTTP/3 client.
//
// It exists as a separate interface so that the existing http3Client interface is not
// widened: every current implementer, including test doubles, keeps compiling untouched.
// Only http3ClientImpl satisfies it, which is the only type that owns a ClientConn.
type http3RequestRoundTripper interface {
	RoundTripHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
}

// http3ExistingConnectionRoundTripper is the narrower capability for callers that must use an
// ALREADY ESTABLISHED HTTP/3 connection and must never cause one to be created.
//
// # Why this is separate from RoundTripHTTP3
//
// RoundTripHTTP3 calls acquire(), which dials when no live connection exists. That is right
// for a caller that owns the connection's lifecycle, but wrong for MASQUE's assigned-DNS
// path: draft-ietf-masque-connect-ip-dns-06 §3.5 asks for DoH to be COALESCED over the
// connection the CONNECT-IP tunnel already uses, and dialing a second connection purely to
// carry DNS would defeat the purpose while creating an extra, observable connection.
//
// So the requirement is expressed in the type system rather than left to the caller's
// discipline: this method reports whether a live connection exists and refuses to create one.
type http3ExistingConnectionRoundTripper interface {
	// RoundTripExistingHTTP3 issues a request only if an HTTP/3 connection is already
	// established and alive. It must not dial.
	RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
	// HTTP3ConnectionAuthority reports the authority of the live HTTP/3 connection, or
	// false when there is none.
	HTTP3ConnectionAuthority() (string, bool)
}

// http3CandidateDialer is the capability the MASQUE racer needs: establish ONE candidate with
// the transport's own TLS, QUIC and congestion-control configuration.
//
// Supplying this from transport/http is what lets the racer own candidate policy while the
// transport keeps ownership of connection construction. The alternative -- the racer calling
// DialEarly itself -- would mean protocol/masque duplicating the TLS config resolution, the
// QUIC options and the congestion-control choice, and would put congestion control on the
// WRONG side of the handshake, which is the defect this seam exists to fix.
type http3CandidateDialer interface {
	DialHTTP3Candidate(ctx context.Context, server M.Socksaddr, address netip.Addr) (net.Conn, *quic.Conn, error)
}

var (
	_ http3RequestRoundTripper            = (*http3ClientImpl)(nil)
	_ http3ExistingConnectionRoundTripper = (*http3ClientImpl)(nil)
	_ http3CandidateDialer                = (*http3ClientImpl)(nil)
)

// HTTP3CandidateDialer exposes the single-candidate primitive to a caller that supplies its own
// candidate ordering. It returns nil when this client has no HTTP/3 support, so a caller falls
// back to its own dialing rather than failing.
func (c *Client) HTTP3CandidateDialer() any {
	if c.http3 == nil {
		return nil
	}
	dialer, isDialer := c.http3.(http3CandidateDialer)
	if !isDialer {
		return nil
	}
	return dialer
}

// HTTP3ConnectionState reports whether the tunnel is currently running over HTTP/3, and the
// authority that connection is authenticated for.
//
// # Why the caller needs this
//
// "This client can do HTTP/3" and "this tunnel IS HTTP/3" are different facts. transport/http
// falls back from HTTP/3 to HTTP/2, so an endpoint configured for version 3 can end up with an
// HTTP/2 tunnel while the HTTP/3 code path still exists. A caller that conflated the two would
// ask for a same-connection DoH request on an HTTP/2 tunnel and silently get a NEW HTTP/3
// connection instead -- a second connection that the CONNECT-IP traffic does not share.
//
// The authority is returned alongside because same-origin reuse is only meaningful against the
// origin the connection was actually verified for.
func (c *Client) HTTP3ConnectionState() (string, bool) {
	if c.http3 == nil {
		return "", false
	}
	provider, isProvider := c.http3.(http3ExistingConnectionRoundTripper)
	if !isProvider {
		return "", false
	}
	authority, live := provider.HTTP3ConnectionAuthority()
	if !live {
		return "", false
	}
	// The connection's own authority is what matters, falling back to the configured one when
	// the implementation does not track it separately.
	if authority == "" {
		authority = c.http3Authority
	}
	if authority == "" {
		return "", false
	}
	return authority, true
}

// RoundTripExistingHTTP3 issues a request only on an already-established HTTP/3 connection.
//
// It is the same-connection DoH entry point: see http3ExistingConnectionRoundTripper for why
// it must not dial.
func (c *Client) RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	if c.http3 == nil {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("this client is not using HTTP/3"))
	}
	roundTripper, isRoundTripper := c.http3.(http3ExistingConnectionRoundTripper)
	if !isRoundTripper {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("this HTTP/3 client does not support existing-connection requests"))
	}
	if _, live := c.HTTP3ConnectionState(); !live {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("no live HTTP/3 connection"))
	}
	if err := c.validateSameOrigin(request); err != nil {
		return nil, err
	}
	return roundTripper.RoundTripExistingHTTP3(ctx, request)
}

// RoundTripHTTP3 issues a request over HTTP/3 on this client's existing connection.
//
// # No fallback, deliberately
//
// If this client has no HTTP/3 support, the error is returned. Falling back to HTTP/2 or
// HTTP/1 would defeat the purpose of the API, which is to prove and preserve reuse of one
// HTTP/3 connection: a silent downgrade would appear to work while establishing a
// different connection, making the reuse claim untestable and the privacy property false.
func (c *Client) RoundTripHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	if c.http3 == nil {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("this client is not using HTTP/3"))
	}
	roundTripper, isRoundTripper := c.http3.(http3RequestRoundTripper)
	if !isRoundTripper {
		// A client implementation that predates this capability. Reported as unavailable
		// rather than attempted, so callers fall back to their own resolver rather than
		// receiving a confusing transport error.
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("this HTTP/3 client does not support generic requests"))
	}
	if err := c.validateSameOrigin(request); err != nil {
		return nil, err
	}
	return roundTripper.RoundTripHTTP3(ctx, request)
}

// validateSameOrigin restricts generic HTTP/3 requests to the connection's own authority.
//
// # Why this is not merely cautious
//
// The connection is established to the MASQUE server and authenticated with that server's
// TLS certificate. Allowing it to carry requests for an arbitrary authority would turn it
// into a cross-origin tunnel riding on credentials that were only ever presented for the
// configured origin -- the client would be asking the server to forward traffic it never
// agreed to carry, and any response would arrive over a connection whose identity does not
// match the request's authority.
//
// So a request must name the same authority the client was configured with. The check is
// on the request's HOST, which is what the server would route on, and it is compared
// case-insensitively because host names are.
//
// A future cross-origin path would need HTTP/3 coalescing rules plus independent
// certificate verification for the second origin. Neither is implemented here, and nothing
// in this API should be relaxed to make DNS_ASSIGN easier: an assigned resolver from a
// different origin uses the tunnel-carried path instead.
func (c *Client) validateSameOrigin(request *http.Request) error {
	authority := request.URL.Host
	if authority == "" {
		authority = request.Host
	}
	if authority == "" {
		return E.New("generic HTTP/3 request must name an authority")
	}
	expected := c.http3Authority
	if expected == "" {
		return E.New("generic HTTP/3 request requires a configured authority")
	}
	if !equalAuthority(authority, expected) {
		return E.New("refusing cross-origin generic HTTP/3 request: request authority ",
			authority, " does not match the connection authority ", expected)
	}
	return nil
}

// equalAuthority compares two authorities, ignoring case and an implicit default port.
func equalAuthority(first string, second string) bool {
	if equalFoldASCII(first, second) {
		return true
	}
	// "example.com" and "example.com:443" are the same authority for HTTPS.
	return equalFoldASCII(normalizeAuthority(first), normalizeAuthority(second))
}

// normalizeAuthority rewrites an authority into host:port form, supplying the HTTPS default
// port when none is present and the port is not an explicit default.
//
// Splitting on the LAST colon would be wrong twice over: it would read the colons inside an
// IPv6 literal as a port separator, and it would append a port to an authority that already
// carries one. So the host is located the way RFC 3986 defines it -- everything up to the
// final colon, but only when that colon is outside any brackets -- and the port, when
// present, is returned as written.
func normalizeAuthority(authority string) string {
	host, port, found := splitAuthority(authority)
	if !found {
		return authority + ":443"
	}
	return host + ":" + port
}

// splitAuthority separates an authority into host and port.
//
// The port separator is only a separator when it is not inside an IPv6 literal's brackets:
// in "[::1]:443" the last colon is the separator, while in "[::1]" the final colon is part
// of the address and there is no port at all.
func splitAuthority(authority string) (host string, port string, found bool) {
	separator := -1
	for i := len(authority) - 1; i >= 0; i-- {
		switch authority[i] {
		case ']':
			// Past this point everything belongs to the address literal, so any colon
			// already skipped is not a separator.
			i = strings.LastIndexByte(authority[:i], '[')
			if i < 0 {
				return authority, "", false
			}
			continue
		case ':':
			separator = i
		}
		if separator >= 0 {
			break
		}
	}
	if separator < 0 {
		return authority, "", false
	}
	return authority[:separator], authority[separator+1:], true
}

// equalFoldASCII compares ASCII strings case-insensitively.
//
// It is written out rather than using strings.EqualFold so that the comparison cannot be
// affected by Unicode case folding, which is not how host names are compared.
func equalFoldASCII(first string, second string) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range len(first) {
		a, b := first[i], second[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// requestStreamPrimitive is the shared lower-level machinery both the CONNECT path and the
// generic request path build on.
//
// It deliberately stops short of interpreting the response: what counts as a usable
// response differs between a tunnel (StatusOK is required) and an ordinary request (any
// status is a response). Keeping the interpretation out of the primitive is what stops it
// from becoming a function with a mode flag.
func (c *http3ClientImpl) openRequestStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, *http.Response, error) {
	clientConn, err := c.acquire(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.openRequestStreamOn(ctx, clientConn, request)
}

// openRequestStreamOn issues a request on a connection the caller already holds.
//
// Splitting this out is what lets the same-connection path share the entire request mechanism
// while differing in exactly one respect: where the connection comes from. acquire() dials
// when there is none; existingConn() reports failure. Everything after that -- stream
// opening, cancellation scoping, body handling, response wiring -- is identical, which is
// what keeps the two paths from drifting apart.
func (c *http3ClientImpl) openRequestStreamOn(ctx context.Context, clientConn *http3.ClientConn, request *http.Request) (*http3.RequestStream, *http3.ClientConn, *http.Response, error) {
	if request.Body != nil && request.Body != http.NoBody {
		// See roundTripWithBody: a body-bearing request cannot go through
		// RequestStream, because its header must be written by quic-go's own request
		// writer. ClientConn.RoundTrip does exactly that, and -- crucially -- it opens
		// its request stream on THIS clientConn, so the reuse property this whole API
		// exists for is preserved.
		response, err := roundTripWithBody(ctx, clientConn, request)
		if err != nil {
			return nil, nil, nil, err
		}
		return nil, clientConn, response, nil
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	// Cancelling the context cancels THIS stream only. The shared ClientConn is untouched,
	// so one cancelled DoH query cannot take down the CONNECT-IP tunnel or any other
	// in-flight request.
	//
	// The stream reset is what unblocks the response read below: ReadResponse does not
	// observe a context itself, so the AfterFunc is what makes cancellation return
	// promptly instead of waiting for a response that will never arrive.
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(h3StreamErrorCodeRequestCanceled)
		stream.CancelWrite(h3StreamErrorCodeRequestCanceled)
	})
	response, err := readRequestResponse(ctx, clientConn, stream, request)
	if err == nil && !stop() {
		err = ctx.Err()
	}
	if err != nil {
		stream.CancelRead(h3StreamErrorCodeRequestCanceled)
		stream.Close()
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		return nil, nil, nil, err
	}
	return stream, clientConn, response, nil
}

// h3StreamErrorCodeRequestCanceled mirrors quic-go's own ErrCodeRequestCanceled, which is
// unexported.
//
// The value is fixed by RFC 9114 section 8.1: H3_REQUEST_CANCELLED is 0x010c. It is only
// used to abort a stream this client owns, so a wrong code would be a protocol nicety, not
// a correctness problem -- but there is no reason to guess when the registry pins it.
const h3StreamErrorCodeRequestCanceled = 0x010c

// roundTripWithBody issues a request that carries a body on an existing HTTP/3 connection.
//
// # Why this does not use RequestStream
//
// RequestStream is the natural way to issue a request, and it is what the CONNECT-IP path
// uses. But it cannot carry a body:
//
//	func (s *RequestStream) SendRequestHeader(req *http.Request) error {
//	    if req.Body != nil && req.Body != http.NoBody {
//	        return errors.New("http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body")
//	    }
//	    return s.sendRequestHeader(req)
//	}
//
// The guard is on the request, not on who writes the bytes, so no amount of replacing or
// detaching the body satisfies it: the framing written into the header block is derived from
// the body, and the exported entry point refuses to derive body-bearing framing at all. Only
// the unexported sendRequestHeader does, and it is unreachable from here.
//
// The failure mode of trying to defeat the guard is worth recording, because it is silent
// until it is not: framing a body-bearing request with Body == nil makes the writer emit a
// zero length, which permits NO DATA frames. The body bytes then arrive as an unexpected
// frame and the server kills the stream with H3_FRAME_UNEXPECTED (0x010a = 270) -- observed
// while implementing this, reported as "stream 0 canceled by remote with error code 270".
//
// So body-bearing requests go through ClientConn.RoundTrip instead. That is not a compromise:
// RoundTrip opens its request stream on the SAME ClientConn it is called on (it calls
// this.openRequestStream, not a new connection), so the one-connection property this API
// exists to guarantee is preserved by construction. The connection is acquired first, once,
// through acquire(), so the CONNECT-IP tunnel and every DoH query still share it, and
// RoundTrip never dials.
//
// # Why the request is copied
//
// RoundTrip consumes and closes the request body as part of its contract, and it records the
// request on the response. The caller handed us a request it may still reference, so the body
// is swapped on a shallow copy and the original is left as the caller wrote it.
// # Cancellation
//
// quic-go cancels the request stream when the request's context ends, including while the
// body is still being written, so a cancelled request returns promptly without this function
// wrapping it. That was verified rather than assumed: the leak tests cancel in-flight
// requests and assert they return well before their own deadline, and the assertion holds
// with this function calling RoundTrip directly.
//
// An earlier version of this function ran RoundTrip on a goroutine and selected on the
// context as well. It was reverted once measured, because it added a goroutine to every
// request while changing nothing observable -- the failure it was written to prevent turned
// out to be a bug in the TEST, which cancelled its context only after the call had already
// returned. Keeping the wrapper would have meant carrying a goroutine per DoH query to guard
// against a problem that does not exist.
func roundTripWithBody(ctx context.Context, clientConn *http3.ClientConn, request *http.Request) (*http.Response, error) {
	bodyRequest := *request
	if bodyRequest.ContentLength == 0 {
		// net/http documents that a zero ContentLength with a non-nil body means "unknown",
		// and quic-go's writer treats 0 as literally zero: it would then enforce a
		// content-length of 0 against a body that has bytes, failing the request. Making
		// "unknown" explicit preserves the caller's intent.
		bodyRequest.ContentLength = -1
	}
	response, err := clientConn.RoundTrip(&bodyRequest)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.Cause(err, "HTTP/3 request")
	}
	return response, nil
}

// Settings must be received before a stream is usable, and the CONNECT-IP path relies on
// that same wait: sending a request before SETTINGS is a protocol error, and the server's
// settings are what advertise datagram and Extended CONNECT support.
//
// For the RequestStream path the wait is done explicitly below; for the RoundTrip path
// quic-go performs it internally, which is why only one of the two call sites shows it.

// readRequestResponse sends a BODYLESS request on an already-open stream and reads its
// response.
//
// Only bodyless requests reach here. A request with a body is framed by quic-go's own writer
// instead, for the reasons documented on roundTripWithBody -- the guard in SendRequestHeader
// makes this path unusable for a body, and a body written after a zero-length header is a
// protocol violation rather than a working request.
//
// The send direction is closed immediately, so the server sees end-of-stream on the request
// and can answer without waiting for a body that will never arrive.
func readRequestResponse(ctx context.Context, clientConn *http3.ClientConn, stream *http3.RequestStream, request *http.Request) (*http.Response, error) {
	select {
	case <-clientConn.ReceivedSettings():
	case <-clientConn.Context().Done():
		return nil, context.Cause(clientConn.Context())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := stream.SendRequestHeader(request); err != nil {
		return nil, E.Cause(err, "send HTTP/3 request header")
	}
	if err := stream.Close(); err != nil {
		return nil, E.Cause(err, "close HTTP/3 request stream")
	}
	return stream.ReadResponse()
}

// RoundTripExistingHTTP3 issues a request on the connection this client ALREADY holds.
//
// It is the same-connection DoH entry point. Unlike RoundTripHTTP3 it never dials: if no live
// connection exists it reports HTTP/3 unavailable, because creating one here would produce a
// second connection that the CONNECT-IP tunnel does not share, which is precisely what
// draft-ietf-masque-connect-ip-dns-06 §3.5's coalescing requirement exists to avoid.
func (c *http3ClientImpl) RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	clientConn, live := c.existingConn()
	if !live {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("no live HTTP/3 connection to reuse"))
	}
	stream, _, response, err := c.openRequestStreamOn(ctx, clientConn, request)
	if err != nil {
		return nil, E.Cause(err, "HTTP/3 request on existing connection")
	}
	if response == nil {
		releaseStream(stream, nil)
		return nil, E.New("HTTP/3 request returned no response")
	}
	originalBody := response.Body
	response.Body = &streamBoundBody{
		Reader: originalBody,
		closer: func() {
			releaseStream(stream, originalBody)
		},
	}
	return response, nil
}

// RoundTripHTTP3 performs a generic request on this client's existing HTTP/3 connection.
//
// It returns the response for ANY status code: the generic layer does not decide what a
// usable response is, and a non-2xx is a legitimate answer that the caller interprets.
// The caller owns response.Body and must close it.
//
// The stream is held open for the lifetime of the response body: closing the body releases
// the stream, which is what lets the caller stream a large response instead of buffering.
func (c *http3ClientImpl) RoundTripHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, E.New("nil HTTP/3 request")
	}
	stream, clientConn, response, err := c.openRequestStream(ctx, request)
	if err != nil {
		return nil, E.Cause(err, "HTTP/3 request")
	}
	if response == nil {
		releaseStream(stream, nil)
		return nil, E.New("HTTP/3 request returned no response")
	}
	// The body is replaced with one that also releases the stream exactly once, so a
	// caller that closes the body (as it must) finishes the stream, and a caller that
	// forgets does not leak it silently forever.
	//
	// This runs for BOTH paths even though only the RequestStream path has a stream to
	// release: the body-bearing path goes through ClientConn.RoundTrip, which owns its
	// stream internally and whose response body already releases it. Replacing the body
	// there is still worthwhile, because it makes "close the body exactly once" a property
	// the caller can rely on regardless of which path was taken.
	originalBody := response.Body
	response.Body = &streamBoundBody{
		Reader: originalBody,
		closer: func() {
			releaseStream(stream, originalBody)
		},
	}
	// The connection is referenced so its lifetime is tied to the response by the caller
	// holding the body; nothing extra is retained here, which keeps a long-lived connection
	// from being pinned by a finished response.
	_ = clientConn
	return response, nil
}

// releaseStream finishes a request stream precisely once, tolerating the body-bearing path
// where quic-go owns the stream and hands back no handle to it.
//
// The originalBody argument is the body quic-go returned, NOT the wrapper this package
// installed around it. Closing the wrapper here would recurse into this same function
// forever: the wrapper's closer is the caller of releaseStream.
//
// When a stream is present, cancelling the read direction before closing releases
// flow-control credit the peer might otherwise keep spending against the SHARED connection.
// The reset code is H3_REQUEST_CANCELLED because the caller is done with the response; by
// the time the body is closed it has been read, so this releases credit rather than
// truncating anything still wanted.
func releaseStream(stream *http3.RequestStream, originalBody io.Closer) {
	if stream == nil {
		if originalBody != nil {
			// The stream belongs to quic-go here, and its body is the only handle that
			// can finish it.
			_ = originalBody.Close()
		}
		return
	}
	stream.CancelRead(h3StreamErrorCodeRequestCanceled)
	stream.Close()
}

// streamBoundBody ties an HTTP/3 response body to its stream.
//
// Closing it closes the stream exactly once. This is what makes "the caller owns the body
// and must close it" a real contract rather than a comment: an unclosed stream would hold
// HTTP/3 flow-control credit on the SHARED connection, which would eventually stall the
// CONNECT-IP tunnel as well.
type streamBoundBody struct {
	io.Reader
	once   sync.Once
	closer func()
}

func (b *streamBoundBody) Close() error {
	b.once.Do(b.closer)
	return nil
}
