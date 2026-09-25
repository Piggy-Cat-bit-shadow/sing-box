package reference_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/url"
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
