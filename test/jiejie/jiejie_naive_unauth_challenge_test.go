package jiejie_test

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// The unauthenticated proxy challenge, on the no-masquerade path.
//
// This is the parity surface that was previously wrong. The reference
// (klzgrad/forwardproxy@d62c80d3, forwardproxy.go) answers an unauthorised
// request with a normal HTTP response:
//
//	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
//	return caddyhttp.Error(http.StatusProxyAuthRequired, authErr)
//
// Measured against the built reference, that is exactly:
//
//	HTTP/1.1 407 Proxy Authentication Required
//	Proxy-Authenticate: Basic realm="Caddy Secure Web Proxy"
//	Content-Length: 0
//
// and it is produced for an unauthenticated CONNECT, a wrong-credential CONNECT
// and even a plain GET.
//
// This inbound previously hijacked the connection, set SO_LINGER to 0 and closed
// it, so the client observed a reset with no status line and no challenge. That
// made a bad-credential refusal indistinguishable from the proxy dying, and it
// diverged from the reference on the one behaviour a proxy client is most likely
// to act on.
//
// Scope, stated so this is not over-read: this is the NO-MASQUERADE path. When a
// masquerade is configured the request must instead be served as ordinary web
// traffic and must NOT advertise a proxy authentication surface - that is the
// probe-resistance behaviour, and it is covered by the masquerade tests, which
// assert the absence of this very header.

// bareProxyRealm is the realm the reference advertises, reproduced verbatim.
const bareProxyRealm = "Caddy Secure Web Proxy"

// readRawHTTPResponse writes a raw request and parses the reply, so the test sees
// what an ordinary client receives rather than what a CONNECT helper normalises.
func readRawHTTPResponse(t *testing.T, conn net.Conn, raw string) *http.Response {
	t.Helper()
	_, err := io.WriteString(conn, raw)
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err, "the server must answer with a parseable HTTP response")
	return response
}

// TestJiejieNaiveUnauthenticatedConnectKeepsTheProxyChallenge asserts the
// reference behaviour for an unauthenticated CONNECT with no masquerade.
func TestJiejieNaiveUnauthenticatedConnectKeepsTheProxyChallenge(t *testing.T) {
	env := startNaiveInbound(t, false)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	response, err := naiveWriteConnect(t, conn, "example.com:443", nil)
	require.NoError(t, err,
		"an unauthenticated CONNECT must receive an HTTP response, not a reset: "+
			"the reference answers it with a 407 challenge")
	defer response.Body.Close()
	defer conn.Close()

	require.Equal(t, http.StatusProxyAuthRequired, response.StatusCode,
		"the reference answers an unauthorised CONNECT with 407")
	require.Equal(t, "Basic realm=\""+bareProxyRealm+"\"",
		response.Header.Get("Proxy-Authenticate"),
		"the challenge realm is part of the wire behaviour a proxy client may "+
			"act on, so it must match the reference verbatim")
}

// TestJiejieNaiveWrongCredentialsKeepTheProxyChallenge covers the wrong-credential
// case, which the reference treats identically to the missing-credential case.
func TestJiejieNaiveWrongCredentialsKeepTheProxyChallenge(t *testing.T) {
	env := startNaiveInbound(t, false)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	response, err := naiveWriteConnect(t, conn, "example.com:443", map[string]string{
		"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":definitely-the-wrong-password")),
	})
	require.NoError(t, err, "wrong credentials must still produce a response")
	defer response.Body.Close()
	defer conn.Close()

	require.Equal(t, http.StatusProxyAuthRequired, response.StatusCode)
	require.Equal(t, "Basic realm=\""+bareProxyRealm+"\"",
		response.Header.Get("Proxy-Authenticate"))
}

// TestJiejieNaiveUnauthenticatedConnectOpensNoTunnel is the security control for
// the two tests above.
//
// Returning a proper challenge must not have turned the refusal into an
// acceptance: the decisive property is still that no tunnel exists, which is
// asserted by the origin never being dialled.
func TestJiejieNaiveUnauthenticatedConnectOpensNoTunnel(t *testing.T) {
	env := startNaiveInbound(t, false)
	origin := startCountingTCPOrigin(t)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	response, err := naiveWriteConnect(t, conn, origin.addr, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusProxyAuthRequired, response.StatusCode)
	defer response.Body.Close()
	defer conn.Close()

	require.EqualValues(t, 0, origin.conns.Load(),
		"an unauthenticated CONNECT must never reach the target, whatever status "+
			"it is answered with")
}

// TestJiejieNaiveUnauthenticatedNonConnectIsRejected covers the non-CONNECT case
// routed through the same path.
//
// The reference sets Proxy-Authenticate only on its auth-failure path, so a
// non-CONNECT request keeps 400 without a challenge header. Asserting the
// absence here pins that the challenge was not smeared across every status.
func TestJiejieNaiveUnauthenticatedNonConnectIsRejected(t *testing.T) {
	env := startNaiveInbound(t, false)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	defer conn.Close()

	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	response := readRawHTTPResponse(t, conn, raw)
	defer response.Body.Close()

	require.Equal(t, http.StatusBadRequest, response.StatusCode,
		"a non-CONNECT request on the proxy port is rejected")
	require.Empty(t, response.Header.Get("Proxy-Authenticate"),
		"only the 407 path carries the proxy challenge, matching the reference")
}
