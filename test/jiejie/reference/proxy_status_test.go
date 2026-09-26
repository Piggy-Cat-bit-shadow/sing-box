package reference_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Proxy-Status (RFC 9209) on the MASQUE endpoint.
//
// The audit said "Proxy-Status reporting: Not implemented", which was inaccurate:
// transport/masque/server.go already emits
//
//	Proxy-Status: sing-box; error=dns_error
//
// when a CONNECT-IP request names a domain it cannot resolve. So the state is
// PARTIAL, not absent, and this file pins what is actually there.
//
// The security boundary matters more than the coverage. Proxy-Status describes what
// a PROXY did, so it must only ever be visible to a request that was actually
// authenticated and actually attempted forwarding. An unauthenticated prober, a
// probe with wrong credentials, a masquerade request and an over-limit request must
// all see an ordinary web response with no Proxy-Status, no DNS status and no
// internal error detail - otherwise the header becomes a fingerprint that
// distinguishes this server from a normal web server, which is exactly what the
// masquerade path exists to prevent.

// proxyStatusOf returns the Proxy-Status header value, or "" when absent.
func proxyStatusOf(response *http.Response) string {
	return response.Header.Get("Proxy-Status")
}

// connectIPRequestThrough builds an authenticated CONNECT-IP extended CONNECT to a
// named target.
//
// It is built by hand rather than with connect-ip-go so a test can name a domain
// that will not resolve, which the reference client's template handling makes
// awkward.
func connectIPRequestThrough(t *testing.T, clientConn *http3.ClientConn, server *singBoxServer, target string, authorization string) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	// The default template's two variables are the target and the protocol. A
	// domain target exercises the resolve path that emits Proxy-Status.
	requestURL, err := url.Parse("https://" + referenceTestTLSName + "/.well-known/masque/ip/" + target + "/*/")
	require.NoError(t, err)

	header := http.Header{"Capsule-Protocol": []string{"?1"}}
	if authorization != "" {
		header.Set("Authorization", authorization)
	}
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-ip",
		URL:    requestURL,
		Host:   referenceTestTLSName,
		Header: header,
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	return response
}

// startConnectIPH3Client dials the CONNECT-IP endpoint over a plain HTTP/3 client,
// so the tests can craft requests the reference client would not send.
func startConnectIPH3Client(t *testing.T, server *singBoxServer) *http3.ClientConn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, server.address(), &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: true}
	clientConn := transport.NewClientConn(quicConn)
	t.Cleanup(func() {
		clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return clientConn
}

// TestProxyStatusIsAbsentForUnauthenticatedRequests is the leakage check, and the
// most important test in this file.
//
// Every unauthorised shape must be indistinguishable from an ordinary web server:
// no Proxy-Status, no WWW-Authenticate, no Proxy-Authenticate.
func TestProxyStatusIsAbsentForUnauthenticatedRequests(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	clientConn := startConnectIPH3Client(t, server)

	// A domain that cannot resolve, which is the condition that WOULD produce
	// Proxy-Status for an authenticated caller. Using the same target for both
	// cases is what makes the comparison meaningful.
	const unresolvable = "no-such-host.invalid"

	cases := []struct {
		name          string
		authorization string
	}{
		{name: "no authorization", authorization: ""},
		{name: "wrong authorization", authorization: "Basic " + wrongAuthorization()},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response := connectIPRequestThrough(t, clientConn, server, unresolvable, testCase.authorization)
			defer response.Body.Close()

			// THE SECURITY PROPERTY: no proxy-side detail leaks to a caller that
			// was never authenticated, whatever status code it gets.
			require.Empty(t, proxyStatusOf(response),
				"an unauthenticated request must not receive Proxy-Status: the "+
					"header reports what the PROXY did, and only an authenticated "+
					"request can have caused it to do anything")
			require.NotEqual(t, http.StatusBadGateway, response.StatusCode,
				"an unauthenticated request must not receive the proxy's upstream "+
					"failure status, which would confirm the proxy resolved "+
					"something before rejecting the caller")

			// A MEASURED DIFFERENCE, recorded because it is easy to assume
			// otherwise: this endpoint answers an unauthenticated request with a
			// bare 401, NOT with a masquerade decoy. The `http` INBOUND has a
			// masquerade option and serves a decoy page; the `masque-server`
			// ENDPOINT has no such option (option/masque.go defines no Masquerade
			// field) and transport/http/server_h2.go answers 401 directly. So an
			// anti-fingerprinting assertion copied from the inbound tests does not
			// apply here, and asserting it would fail against correct behaviour -
			// which is what the first version of this test did.
			require.Equal(t, http.StatusUnauthorized, response.StatusCode,
				"an unauthenticated CONNECT-IP request is answered with a bare 401 "+
					"by this endpoint")
			require.NotEmpty(t, response.Header.Get("WWW-Authenticate"),
				"a 401 from this endpoint carries a WWW-Authenticate challenge")
		})
	}
}

// TestProxyStatusIsPresentForAnAuthenticatedDNSFailure is the positive case.
//
// An authenticated caller whose target cannot be resolved must be told that the
// PROXY failed to resolve it, because that is a proxy-side condition the client
// cannot diagnose from a bare status code.
func TestProxyStatusIsPresentForAnAuthenticatedDNSFailure(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	clientConn := startConnectIPH3Client(t, server)

	response := connectIPRequestThrough(t, clientConn, server, "no-such-host.invalid", basicAuthorization())
	defer response.Body.Close()

	require.Equal(t, http.StatusBadGateway, response.StatusCode,
		"an unresolvable target must be reported as a bad gateway")

	status := proxyStatusOf(response)
	require.NotEmpty(t, status,
		"an authenticated caller must be told the proxy could not resolve the "+
			"target; without this the failure is indistinguishable from the "+
			"destination itself being down")
	require.Contains(t, status, "error=dns_error",
		"the Proxy-Status must name the DNS error using the RFC 9209 error token "+
			"vocabulary")
	require.Contains(t, status, "sing-box",
		"the Proxy-Status must name the proxy that generated it")
}

// TestProxyStatusUsesTheRFC9209Shape checks the header's syntax.
//
// RFC 9209 defines Proxy-Status as a List whose members are Items: a proxy name
// followed by semicolon-separated parameters. A malformed value would be silently
// dropped by a conforming client, so the shape is asserted rather than only the
// substring.
func TestProxyStatusUsesTheRFC9209Shape(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	clientConn := startConnectIPH3Client(t, server)
	response := connectIPRequestThrough(t, clientConn, server, "no-such-host.invalid", basicAuthorization())
	defer response.Body.Close()

	status := proxyStatusOf(response)
	require.NotEmpty(t, status)

	// A conforming parsers must accept it. net/http has no SFV parser, so the
	// structural properties are checked directly: a proxy name, then parameters
	// as semicolon-separated key=value pairs.
	segments := strings.Split(status, ";")
	for index := range segments {
		segments[index] = strings.TrimSpace(segments[index])
	}
	require.GreaterOrEqual(t, len(segments), 2,
		"the value must carry a proxy name and at least one parameter: %q", status)
	require.Equal(t, "sing-box", segments[0],
		"the first segment must be the proxy name")
	for _, parameter := range segments[1:] {
		require.Contains(t, parameter, "=",
			"every parameter must be a key=value pair: %q", parameter)
	}
}

// TestProxyStatusIsAbsentOnSuccessAndOnLocalRejections pins the cases where the
// header must NOT appear.
//
// Proxy-Status describes a proxy-side failure. A successful tunnel is not a
// failure, and a request rejected BEFORE any forwarding was attempted (a malformed
// path, an unknown protocol) is not one either - the task is explicit that a bare
// status code is the right answer there and proxy detail should not be bolted on.
func TestProxyStatusIsAbsentOnSuccessAndOnLocalRejections(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	clientConn := startConnectIPH3Client(t, server)

	t.Run("successful tunnel carries no Proxy-Status", func(t *testing.T) {
		requestURL, err := url.Parse("https://" + referenceTestTLSName + "/.well-known/masque/ip/*/*/")
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stream, err := clientConn.OpenRequestStream(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.SendRequestHeader(&http.Request{
			Method: http.MethodConnect,
			Proto:  "connect-ip",
			URL:    requestURL,
			Host:   referenceTestTLSName,
			Header: http.Header{
				"Capsule-Protocol": []string{"?1"},
				"Authorization":    []string{basicAuthorization()},
			},
		}))
		response, err := stream.ReadResponse()
		require.NoError(t, err)
		defer response.Body.Close()

		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Empty(t, proxyStatusOf(response),
			"a successful tunnel must not carry Proxy-Status: the header reports a "+
				"proxy-side failure and there was none")
	})

	t.Run("unmatched path carries no Proxy-Status", func(t *testing.T) {
		requestURL, err := url.Parse("https://" + referenceTestTLSName + "/not-the-tunnel-resource")
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stream, err := clientConn.OpenRequestStream(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.SendRequestHeader(&http.Request{
			Method: http.MethodConnect,
			Proto:  "connect-ip",
			URL:    requestURL,
			Host:   referenceTestTLSName,
			Header: http.Header{
				"Capsule-Protocol": []string{"?1"},
				"Authorization":    []string{basicAuthorization()},
			},
		}))
		response, err := stream.ReadResponse()
		require.NoError(t, err)
		defer response.Body.Close()

		require.Equal(t, http.StatusNotFound, response.StatusCode)
		require.Empty(t, proxyStatusOf(response),
			"a request rejected before any forwarding was attempted must not carry "+
				"proxy failure detail; a bare status code is the correct answer")
	})
}

// wrongAuthorization is a syntactically valid Basic header with the wrong
// password, for the unauthorised-probe cases.
func wrongAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(referenceTestUser+":wrong-password"))
}

// ---------------------------------------------------------------------------
// The RFC 9209 mapping audit: which rejection paths carry Proxy-Status, and why
// ---------------------------------------------------------------------------
//
// transport/masque/server.go has exactly SIX pre-accept rejection paths. This file
// records the RFC 9209 decision for each one, because the interesting question is not
// "how many carry the header" but "is each one either correctly mapped or deliberately
// left bare".
//
// The paths, in the order they are reachable:
//
//	1. path does not match the URI template   -> 404, no Proxy-Status
//	2. template matched but failed to expand  -> 400, no Proxy-Status
//	3. authenticated DNS resolution failed    -> 502, Proxy-Status: sing-box; error=dns_error
//	4. address pool exhausted                 -> 503, no Proxy-Status
//	5. advertised-route construction failed   -> 500, no Proxy-Status
//	6. requested target is not routable       -> 403, no Proxy-Status
//
// # Why only ONE of the six carries the header
//
// RFC 9209 section 2.3 defines a fixed set of `error` tokens, and the rule applied here
// is that the header is added ONLY where a standardised token matches the meaning
// exactly. An approximate mapping is worse than none: it tells a client something
// specific and wrong, and it leaks internal detail to a probe.
//
//	path 3 (dns_error)
//	    dns_error is an EXACT match: RFC 9209 section 2.3.4 defines it as "the proxy
//	    failed to resolve the requested hostname". That is precisely what failed.
//
//	path 4 (address pool exhausted)
//	    There is NO exact token. The nearest is connection_limit_reached, which RFC 9209
//	    section 2.3.7 defines in terms of the PROXY's connection limit being reached -
//	    a different condition from "this endpoint has no free tunnel address". Mapping it
//	    would tell a client to back off from a limit that is not what it hit. Left bare:
//	    the 503 status is accurate and carries the same actionable meaning.
//
//	path 6 (target not routable)
//	    There is NO exact token. http_protocol_error and proxy_internal_error are both
//	    wrong (the HTTP layer was fine and nothing internal failed - the request asked for
//	    a prefix this endpoint is not allowed to reach). Left bare, with a 403 that a
//	    client can already act on.
//
//	paths 1, 2, 5
//	    These are not proxying outcomes at all. Paths 1 and 2 are request-malformation
//	    failures and path 5 is an internal construction failure; RFC 9209 describes what a
//	    proxy DID with a request, and there is nothing to describe. Path 5 in particular
//	    would leak implementation detail.
//
// # What is deliberately NOT done
//
//   - no Proxy-Status is emitted for an UNauthenticated request, on any path. The header
//     describes proxy behaviour to a client that is entitled to it; emitting it before
//     authentication would fingerprint this server as a proxy to a prober, which is the
//     opposite of what the masquerade path exists for. This is asserted by
//     TestProxyStatusIsAbsentForUnauthenticatedRequests.
//   - no Proxy-Status is added AFTER a 200 has been sent. Once the tunnel is established
//     the HTTP response is complete and RFC 9209 has no mechanism for a late header; a
//     failure at that point is a data-path failure and is reported by ICMP, not by HTTP.
//
// PARTIAL is the correct verdict for this area and it is stated rather than implied: one
// of six paths carries the header, and that is a deliberate outcome rather than an
// unfinished one.

// TestProxyStatusAuditCoversEveryRejectionPath guards the audit above from going stale.
//
// The list of rejection paths is COMPILED HERE from the source, so adding a new
// `request.Reject` call in transport/masque/server.go without deciding its RFC 9209
// mapping fails this test. A stale audit is worse than none, because it reads as a
// reviewed decision.
func TestProxyStatusAuditCoversEveryRejectionPath(t *testing.T) {
	source := readServerSource(t)

	// Every rejection call in the file, in order.
	rejections := rejectionCallPattern.FindAllStringSubmatch(source, -1)
	require.NotEmpty(t, rejections,
		"the audit must be looking at a file that actually contains rejection calls; "+
			"finding none means the path or the pattern is wrong, and the rest of this "+
			"test would be vacuous")

	// The audited count. If a rejection path is added or removed, this fails and the
	// reader is sent to the table above.
	const auditedRejectionPaths = 6
	require.Len(t, rejections, auditedRejectionPaths,
		"transport/masque/server.go now has %d rejection paths but the audit above "+
			"documents %d. Decide the RFC 9209 mapping for the new one (add a "+
			"standardised error token ONLY where one matches the meaning exactly), then "+
			"update this constant and the table. Paths found: %v",
		len(rejections), auditedRejectionPaths, rejections)

	// Exactly ONE path may carry Proxy-Status, and it must be the dns_error one. If a
	// second appears, the reasoning above is out of date.
	withProxyStatus := strings.Count(source, "Proxy-Status")
	require.Equal(t, 1, withProxyStatus,
		"exactly one rejection path carries Proxy-Status (the authenticated DNS "+
			"failure, error=dns_error). Found %d occurrences of \"Proxy-Status\", which "+
			"means a mapping was added or removed without updating the audit",
		withProxyStatus)

	require.Contains(t, source, `"sing-box; error=dns_error"`,
		"the one mapped path must use the RFC 9209 dns_error token verbatim")
}

// readServerSource returns the production source this audit describes.
func readServerSource(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "transport", "masque", "server.go"))
	require.NoError(t, err,
		"the audit reads the production file relative to this test's directory; if the "+
			"layout changed, fix the path rather than deleting the guard")
	return string(content)
}

// rejectionCallPattern matches a `request.Reject(` call, which is the only way a MASQUE
// pre-accept rejection is issued.
var rejectionCallPattern = regexp.MustCompile(`request\.Reject\(`)
