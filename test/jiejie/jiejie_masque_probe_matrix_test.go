package jiejie_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/stretchr/testify/require"
)

// This file completes the unauthorised-probe matrix for the MASQUE inbounds.
//
// Existing coverage already asserted GET and CONNECT with no auth and with wrong
// auth. What was missing, and is added here, is:
//
//   - no-auth CONNECT (there was a wrong-auth CONNECT test but no no-auth one);
//   - no-auth and wrong-auth CONNECT-UDP (RFC 9298 extended CONNECT with UDP
//     proxying), which is a distinct code path from plain CONNECT and therefore
//     a distinct fingerprinting risk;
//   - the same cells over HTTP/3 rather than only HTTP/2.
//
// Every cell must land on the masquerade web decoy and must never expose a proxy
// authentication surface. The decoy is a local backend, so these tests do not
// depend on the public internet.

// probeCredential is the one axis of variation in the matrix.
type probeCredential struct {
	label   string
	headers http.Header
}

// probeCredentials returns the two unauthorised variants: absent and wrong.
func probeCredentials() []probeCredential {
	return []probeCredential{
		{label: "no auth", headers: http.Header{}},
		{
			label:   "wrong auth",
			headers: http.Header{"Proxy-Authorization": []string{jiejieWrongAuthorization()}},
		},
	}
}

// assertDecoyServed asserts an unauthorised probe landed on the masquerade decoy
// and was not shown any proxy authentication surface.
func assertDecoyServed(t *testing.T, response *http.Response, body string, what string) {
	t.Helper()
	assertNotAProxyChallenge(t, response)
	require.Contains(t, body, "jiejie decoy site",
		"an unauthorised %s must reach the masquerade backend", what)
}

// TestJiejieMASQUEH2ProbeMatrix runs the full unauthorised matrix against the
// HTTP/2 MASQUE inbound.
func TestJiejieMASQUEH2ProbeMatrix(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH2(t, decoyAddr)
	clientConn := dialJiejieH2(t, port)
	udpTarget := startMinimalUDPEchoAddr(t)

	for _, credential := range probeCredentials() {
		t.Run("GET "+credential.label, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "https://example.org/", nil)
			require.NoError(t, err)
			for name, values := range credential.headers {
				request.Header[name] = values
			}
			response, err := clientConn.RoundTrip(request)
			require.NoError(t, err)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, response.StatusCode)
			assertDecoyServed(t, response, string(body), "GET "+credential.label)
		})

		t.Run("CONNECT "+credential.label, func(t *testing.T) {
			response := probeConnectH2(t, clientConn, targetAddr, credential.headers)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assertDecoyServed(t, response, string(body), "CONNECT "+credential.label)
		})

		t.Run("CONNECT-UDP "+credential.label, func(t *testing.T) {
			requireH2ExtendedConnectUsable(t)
			response := probeConnectUDPH2(t, clientConn, udpTarget, credential.headers)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)

			// An unauthorised extended CONNECT is still routed to the masquerade
			// handler, but the decoy ORIGIN is a plain HTTP site and refuses a
			// CONNECT request, so the reverse proxy reports a bare 502. That is
			// the decoy backend's answer, not a proxy error surface: what matters
			// for probe resistance is that no authentication challenge is exposed
			// and the response is an ordinary HTTP error any web server could
			// produce for an unsupported method.
			//
			// This case is recorded explicitly rather than asserted to contain the
			// decoy body, because pretending it returns HTML would hide the real
			// behaviour from anyone reading this test.
			assertNotAProxyChallenge(t, response)
			require.Equal(t, http.StatusBadGateway, response.StatusCode,
				"an unauthorised CONNECT-UDP reaches the masquerade backend, whose plain "+
					"HTTP origin rejects the CONNECT method")
			require.Empty(t, string(body),
				"the 502 must be an empty body with no proxy detail")
		})
	}
}

// TestJiejieMASQUEH3ProbeMatrix runs the same matrix against the HTTP/3 inbound.
func TestJiejieMASQUEH3ProbeMatrix(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH3(t, decoyAddr, nil)
	client := dialJiejieH3(t, port)

	for _, credential := range probeCredentials() {
		t.Run("GET "+credential.label, func(t *testing.T) {
			var headers http.Header
			if len(credential.headers) > 0 {
				headers = credential.headers
			}
			response, err := client.get(t, "/", headers)
			require.NoError(t, err)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, response.StatusCode)
			assertDecoyServed(t, response, string(body), "GET "+credential.label)
		})

		t.Run("CONNECT "+credential.label, func(t *testing.T) {
			var headers http.Header
			if len(credential.headers) > 0 {
				headers = credential.headers
			}
			// No payload: an unauthenticated CONNECT is answered with the decoy
			// response, so nothing should be written into the stream. Passing a
			// payload here would race the server's rejection and produce a
			// spurious "stream canceled" error rather than the decoy.
			response, _, err := client.connect(t, targetAddr, headers, "")
			require.NoError(t, err)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assertDecoyServed(t, response, string(body), "CONNECT "+credential.label)
		})

		if credential.label != "no auth" {
			continue
		}
		t.Run("CONNECT-UDP "+credential.label, func(t *testing.T) {
			udpTarget := startMinimalUDPEchoAddr(t)
			response := probeConnectUDPH3(t, client.clientConn, udpTarget, credential.headers)
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assertDecoyServed(t, response, string(body), "CONNECT-UDP "+credential.label)
		})
	}
}

// probeConnectH2 issues a plain CONNECT over HTTP/2 with the given credentials.
func probeConnectH2(t *testing.T, clientConn *http2.ClientConn, targetAddr string, headers http.Header) *http.Response {
	t.Helper()
	requestHeader := http.Header{}
	for name, values := range headers {
		requestHeader[name] = values
	}
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: targetAddr},
		Host:   targetAddr,
		Header: requestHeader,
	})
	require.NoError(t, err)
	return response
}

// probeConnectUDPH2 issues an RFC 9298 extended CONNECT over HTTP/2.
func probeConnectUDPH2(t *testing.T, clientConn *http2.ClientConn, udpTarget string, headers http.Header) *http.Response {
	t.Helper()
	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() { _ = pipeWriter.Close() })

	requestHeader := http.Header{
		"Capsule-Protocol": []string{"?1"},
	}
	for name, values := range headers {
		requestHeader[name] = values
	}
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.org",
			Path:   minimalConnectUDPPath(udpTarget),
		},
		Host:   "example.org",
		Header: h2ExtendedConnectHeader(requestHeader),
		Body:   pipeReader,
	})
	require.NoError(t, err)
	return response
}

// h3StreamOpener is the small surface the extended CONNECT probe needs. Both
// HTTP/3 test clients in this package satisfy it.
type h3StreamOpener interface {
	OpenRequestStream(ctx context.Context) (*http3.RequestStream, error)
}

// probeConnectUDPH3 is the HTTP/3 form of the extended CONNECT probe.
func probeConnectUDPH3(t *testing.T, client h3StreamOpener, udpTarget string, headers http.Header) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := client.OpenRequestStream(ctx)
	require.NoError(t, err)

	requestHeader := http.Header{
		"Capsule-Protocol": []string{"?1"},
	}
	for name, values := range headers {
		requestHeader[name] = values
	}
	// The extended CONNECT :protocol pseudo-header is supplied through the Proto
	// field; putting it in the header map is rejected as an invalid header name.
	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(udpTarget),
		},
		Host:   minimalTestTLSName,
		Header: requestHeader,
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	return response
}
