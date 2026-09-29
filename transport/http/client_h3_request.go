//go:build with_quic

package http

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Generic HTTP/3 request support on the SAME connection the CONNECT-IP tunnel uses.
//
// # Why this exists
//
// draft-ietf-masque-connect-ip-dns-06 §3.5 says that when the proxy is authoritative for a DoH
// origin, "the client SHOULD send its DNS queries to that nameserver directly as independent
// HTTPS requests. When possible, those requests SHOULD be coalesced over the same HTTPS
// connection."
//
// That is a normative SHOULD for connection reuse, and it only means anything if the DoH requests
// really travel on the CONNECT-IP connection. So this exists to issue requests on the connection
// acquire() already memoizes -- never to create a second QUIC connection, and never to carry DoH
// inside the CONNECT-IP capsule stream.
//
// # The two lifecycles, and why they are NOT shared
//
//	A. CONNECT (a tunnel)
//	    The 200 response MARKS THE BEGINNING. The stream then carries payload in both
//	    directions for as long as the tunnel lives, and the write side must stay open.
//
//	B. Ordinary HTTP (a request)
//	    The response MARKS THE END of the request. The write side is finished once the
//	    request has been sent, and the response body is the whole remaining lifecycle.
//
// An earlier version of this file factored the two into one shared primitive that always closed
// the write side before reading the response. That is correct for B and catastrophic for A: it
// half-closed every tunnel immediately after its 200, so the first payload byte failed with
// "write on closed stream". This was not a missing branch -- it was two different protocols
// forced through one shape.
//
// So they are separated by shape rather than by a flag:
//
//	CONNECT          -> RequestStream, owned by the tunnel, write side left OPEN
//	ordinary HTTP/3  -> ClientConn.RoundTrip, which is quic-go's own request lifecycle
//
// They share exactly two things: the ClientConn, and the connection acquisition. Nothing about
// stream completion, response bodies, request bodies or cancellation is shared, because none of
// those mean the same thing in the two cases.

// http3ExistingConnectionRoundTripper is the narrow capability for callers that must use an
// ALREADY ESTABLISHED HTTP/3 connection and must never cause one to be created.
//
// It is separate from any auto-acquiring variant so the requirement is expressed in the type
// system rather than left to a caller's discipline: the only method available cannot dial.
type http3ExistingConnectionRoundTripper interface {
	// RoundTripExistingHTTP3 issues a request only if an HTTP/3 connection is already
	// established and alive. It must not dial.
	RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error)
	// HTTP3ConnectionAuthority reports the authority of the live HTTP/3 connection, or false
	// when there is none.
	HTTP3ConnectionAuthority() (string, bool)
}

var _ http3ExistingConnectionRoundTripper = (*http3ClientImpl)(nil)

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

// HTTP3ConnectionState reports whether this client currently HOLDS a live, usable HTTP/3
// connection, and the authority that connection is authenticated for.
//
// # What this does NOT say
//
// It does not say the tunnel is running over HTTP/3. That is a separate fact which this package
// cannot observe: transport/http falls back from HTTP/3 to HTTP/2, so after a fallback the client
// still holds the connection it opened while trying, while the tunnel is carried over HTTP/2. Only
// the code that opened the tunnel knows which branch won, and transport/http reports it separately
// through the tunnel-transport hook.
//
// The distinction matters because a caller that read this as "the tunnel is HTTP/3" would issue a
// same-connection DoH request during an HTTP/2 session and get a query on a connection the tunnel
// traffic does not share -- a second connection, silently, which is what the coalescing requirement
// exists to avoid. Callers must therefore combine this resource fact with the session fact.
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

// http3StreamErrorCodeRequestCanceled mirrors quic-go's own ErrCodeRequestCanceled, which is
// unexported.
//
// The value is fixed by RFC 9114 §8.1: H3_REQUEST_CANCELLED is 0x010c. It is only used to abort a
// stream this client owns, so a wrong code would be a protocol nicety rather than a correctness
// problem -- but there is no reason to guess when the registry pins it.
const h3StreamErrorCodeRequestCanceled = 0x010c

// RoundTripExistingHTTP3 issues an ordinary HTTP request on the connection this client ALREADY
// holds.
//
// # It never dials
//
// The whole point is connection reuse: draft-06 §3.5 asks for DoH to be coalesced over the
// connection the CONNECT-IP tunnel already uses, and a request that opened its own connection
// would defeat that while appearing to work. If no live connection exists this reports HTTP/3
// unavailable, and the caller falls back rather than causing a second connection to appear.
//
// # It uses quic-go's own request lifecycle
//
// ClientConn.RoundTrip creates a request stream on THIS ClientConn, sends the request, streams a
// request body if there is one, applies the request context, and returns a response whose body
// closes the stream. Reimplementing that here is what produced the shared-primitive defect this
// file now avoids: a hand-rolled version has to get bodies, cancellation, trailers, and 1xx
// responses right, and any of it being subtly wrong is invisible until it is not.
func (c *http3ClientImpl) RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	clientConn, live := c.existingConn()
	if !live {
		return nil, E.Cause1(ErrHTTP3Unavailable, E.New("no live HTTP/3 connection to reuse"))
	}
	// The request is cloned so RoundTrip can attach its own bookkeeping without disturbing a
	// caller-owned value.
	requestCopy := request.Clone(ctx)
	response, err := clientConn.RoundTrip(requestCopy)
	if err != nil {
		return nil, E.Cause(err, "HTTP/3 request on the existing connection")
	}
	return response, nil
}

// openConnectStream opens a CONNECT stream and returns it LIVE, which is what makes it a tunnel.
//
// # The single most important line in this file is the one that is NOT here
//
// There is no stream.Close() on the success path, and there must never be one. For an ordinary
// request the write side is finished once the request has been sent; for a CONNECT the 200 is
// where the tunnel STARTS, and closing the write side there leaves a stream that can be read but
// never written. The failure is immediate and total: the first payload byte is rejected with
// "write on closed stream", which is exactly the production symptom this function exists to fix.
//
// The write side is closed only on the paths where the stream will not become a tunnel:
//
//	the request failed            -> close, since there is nothing to carry
//	the response was not 200      -> close, since the tunnel was refused
//
// # Setup cancellation stops when setup succeeds
//
// The context passed here bounds SETUP: acquiring the connection, opening the stream, sending the
// headers, and reading the response. Once the stream is handed to the caller the setup context has
// no further authority over it -- the caller's DialContext typically cancels its own setup
// context on return, and if that cancellation were still wired to the stream it would tear down a
// perfectly healthy tunnel. So the hook is stopped before returning, and lifetime passes to the
// stream's owner.
func (c *http3ClientImpl) openConnectStream(ctx context.Context, request *http.Request) (*http3.RequestStream, *http3.ClientConn, error) {
	clientConn, err := c.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, E.Cause1(ErrHTTP3Unavailable, err)
	}
	stopSetupCancel := context.AfterFunc(ctx, func() {
		stream.CancelRead(quic.StreamErrorCode(h3StreamErrorCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(h3StreamErrorCodeRequestCanceled))
	})
	// From here on the stream must be released on every failure path.
	fail := func(cause error) (*http3.RequestStream, *http3.ClientConn, error) {
		stopSetupCancel()
		stream.CancelRead(quic.StreamErrorCode(h3StreamErrorCodeRequestCanceled))
		_ = stream.Close()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, cause
	}
	// The settings must have arrived before the stream is usable: sending a request before
	// SETTINGS is a protocol error, and the server's settings are what advertise the extended
	// CONNECT support this request depends on.
	select {
	case <-clientConn.ReceivedSettings():
	case <-clientConn.Context().Done():
		return fail(context.Cause(clientConn.Context()))
	case <-ctx.Done():
		return fail(ctx.Err())
	}
	if err = stream.SendRequestHeader(request); err != nil {
		return fail(E.Cause(err, "send CONNECT request header"))
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return fail(E.Cause(err, "read CONNECT response"))
	}
	if response.StatusCode != http.StatusOK {
		// The tunnel was refused. The response body is not a tunnel and is not read: the caller
		// receives the status error, and the stream is released.
		return fail(statusError(response))
	}
	if !stopSetupCancel() && ctx.Err() != nil {
		// Setup "succeeded" only after the caller gave up. Returning the stream would hand over a
		// tunnel nobody is waiting for.
		stream.CancelRead(quic.StreamErrorCode(h3StreamErrorCodeRequestCanceled))
		_ = stream.Close()
		return nil, nil, ctx.Err()
	}
	// LIVE. The write side is open and stays open.
	return stream, clientConn, nil
}

// RoundTripExistingHTTP3 is the public entry point for same-connection requests.
//
// It validates same-origin before delegating: the connection is authenticated for one authority,
// and a request naming another would ride on credentials never presented for that origin.
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
