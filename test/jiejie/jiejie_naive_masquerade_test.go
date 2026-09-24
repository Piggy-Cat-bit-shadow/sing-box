package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/stretchr/testify/require"
)

// These tests cover the Naive inbound's Web masquerade.
//
// The security property under test is asymmetric and easy to get backwards:
//
//   - a NON-proxy request (browser GET/HEAD, probe, bad credentials) must be
//     served a normal website, so the endpoint does not advertise itself; but
//   - an UNAUTHENTICATED or MALFORMED CONNECT must NEVER open a tunnel.
//
// Returning HTTP 200 is therefore NOT the success criterion. A 200 to a browser
// is correct; a 200 to an unauthenticated CONNECT would be a security failure.
// Every test below asserts which of the two happened.

// startNaiveMasqueradeEnv starts a Naive inbound whose masquerade points at a
// decoy website, and returns the port plus a hit counter for the backend.
func startNaiveMasqueradeEnv(t *testing.T) (uint16, *int32) {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	hits := new(int32)
	decoyAddr := startNaiveCountingDecoy(t, hits)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       option.NetworkList("tcp"),
				Users: []auth.User{{
					Username: naiveTestUser,
					Password: naiveTestPassword,
				}},
				Masquerade: &option.Hysteria2Masquerade{
					Type: C.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         "http://" + decoyAddr,
						RewriteHost: true,
					},
				},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return port, hits
}

// startNaiveCountingDecoy starts the fake website, counting requests and
// reporting which proxy headers it saw.
func startNaiveCountingDecoy(t *testing.T, hits *int32) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			*hits++
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("X-Decoy-Site", "naive-decoy")
			// Report the proxy headers so the test can prove they were stripped
			// BEFORE reaching the backend.
			if value := request.Header.Get("Proxy-Authorization"); value != "" {
				writer.Header().Set("X-Saw-Proxy-Authorization", "yes")
			}
			if value := request.Header.Get("Proxy-Connection"); value != "" {
				writer.Header().Set("X-Saw-Proxy-Connection", "yes")
			}
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "<html><body>naive decoy page</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// naivePlainRequest performs an ordinary HTTP request over TLS to the proxy port,
// the way a browser would, optionally with proxy credentials attached.
func naivePlainRequest(t *testing.T, port uint16, method string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s / HTTP/1.1\r\n", method)
	builder.WriteString("Host: naive.test\r\n")
	for name, value := range headers {
		fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
	}
	builder.WriteString("Connection: close\r\n\r\n")
	_, err = io.WriteString(tlsConn, builder.String())
	require.NoError(t, err)

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: method})
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	response.Body.Close()
	return response, string(body)
}

// TestJiejieNaiveMasqueradeServesBrowserTraffic is the baseline: a plain GET and
// a plain HEAD must receive the decoy site.
func TestJiejieNaiveMasqueradeServesBrowserTraffic(t *testing.T) {
	port, hits := startNaiveMasqueradeEnv(t)

	t.Run("GET", func(t *testing.T) {
		response, body := naivePlainRequest(t, port, http.MethodGet, nil)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, body, "naive decoy page",
			"a browser GET must be served the masquerade site")
		require.Equal(t, "naive-decoy", response.Header.Get("X-Decoy-Site"))
	})

	t.Run("HEAD", func(t *testing.T) {
		response, _ := naivePlainRequest(t, port, http.MethodHead, nil)
		require.Equal(t, http.StatusOK, response.StatusCode,
			"a browser HEAD must be served the masquerade site")
	})

	require.Positive(t, *hits, "the masquerade backend must have been reached")
}

// TestJiejieNaiveMasqueradeHandlesWrongCredential proves a request with bad proxy
// credentials is answered as ordinary web traffic rather than with a challenge,
// so the endpoint does not reveal a proxy authentication surface.
func TestJiejieNaiveMasqueradeHandlesWrongCredential(t *testing.T) {
	port, _ := startNaiveMasqueradeEnv(t)

	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong"))
	response, body := naivePlainRequest(t, port, http.MethodGet, map[string]string{
		"Proxy-Authorization": wrongAuth,
	})
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a wrong credential must be served the decoy, not a challenge")
	require.Contains(t, body, "naive decoy page")
	require.Empty(t, response.Header.Get("Proxy-Authenticate"),
		"the masquerade must not emit a proxy authentication challenge")
}

// TestJiejieNaiveMasqueradeDoesNotLeakProxyCredential is the credential-leak
// guard: the web backend must never see Proxy-Authorization.
func TestJiejieNaiveMasqueradeDoesNotLeakProxyCredential(t *testing.T) {
	port, _ := startNaiveMasqueradeEnv(t)

	correctAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":"+naiveTestPassword))
	// A GET (not a CONNECT) carrying proxy credentials: this is the shape that
	// reaches the masquerade path with a credential attached.
	response, body := naivePlainRequest(t, port, http.MethodGet, map[string]string{
		"Proxy-Authorization": correctAuth,
		"Proxy-Connection":    "keep-alive",
	})
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, body, "naive decoy page")

	require.NotEqual(t, "yes", response.Header.Get("X-Saw-Proxy-Authorization"),
		"the masquerade backend must NEVER receive Proxy-Authorization: it carries "+
			"the proxy credential in the clear")
	require.NotEqual(t, "yes", response.Header.Get("X-Saw-Proxy-Connection"),
		"hop-by-hop proxy headers must not be forwarded to the web backend")
}

// TestJiejieNaiveMasqueradeUnauthorisedConnectIsNotATunnel is the security half.
//
// Status code alone is NOT the security property here, and asserting "not 200"
// would be wrong: when a masquerade is configured the unauthorised CONNECT is
// relayed to the Web backend, and a Web backend legitimately answers 200 with its
// own page. What matters is WHICH response comes back:
//
//	the proxy tunnel -> the origin's content ("origin-ok")   = SECURITY FAILURE
//	the decoy website -> the Web backend's page              = correct
//
// So each case asserts that the bytes belong to the website and never to the
// origin. That distinction is the whole point: an endpoint that hides behind a
// real website while still refusing unauthenticated tunnelling.
func TestJiejieNaiveMasqueradeUnauthorisedConnectIsNotATunnel(t *testing.T) {
	port, _ := startNaiveMasqueradeEnv(t)
	originAddr := startOriginBackend(t)

	for _, testCase := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "no credentials", headers: map[string]string{"Padding": "~~~~~~~~"}},
		{
			name: "wrong credentials",
			headers: map[string]string{
				"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("naive-user:nope")),
				"Padding":             "~~~~~~~~",
			},
		},
		{
			name: "malformed credentials",
			headers: map[string]string{
				"Proxy-Authorization": "Basic !!!not-base64!!!",
				"Padding":             "~~~~~~~~",
			},
		},
		{name: "wrong credentials, no padding", headers: map[string]string{
			"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("naive-user:nope")),
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := naiveTLSConn(t, port)
			response, err := naiveWriteConnect(t, conn, originAddr, testCase.headers)
			if err != nil {
				// The connection was closed instead of answered. Acceptable.
				return
			}
			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			text := string(body)

			// Whatever the status, the ORIGIN must not be reachable.
			require.NotContains(t, text, "origin-ok",
				"an unauthorised CONNECT must never reach the CONNECT target: that would "+
					"be a proxy tunnel opened without authentication")

			// The response must be the masquerade website, which is what makes
			// the refusal indistinguishable from ordinary web traffic.
			require.Contains(t, text, "naive decoy page",
				"an unauthorised CONNECT must be answered by the masquerade website")
			require.Empty(t, response.Header.Get("Proxy-Authenticate"),
				"the masquerade must not emit a proxy authentication challenge")
		})
	}
}

// TestJiejieNaiveMasqueradeAuthenticatedConnectStillWorks proves adding a
// masquerade did not break the proxy path.
func TestJiejieNaiveMasqueradeAuthenticatedConnectStillWorks(t *testing.T) {
	port, _ := startNaiveMasqueradeEnv(t)
	originAddr := startOriginBackend(t)

	conn := naiveTLSConn(t, port)
	response := naiveWriteConnectOK(t, conn, originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated CONNECT must still open a tunnel when a masquerade is configured")

	_, err := conn.Write(naivePaddingFrame(
		[]byte("GET / HTTP/1.1\r\nHost: "+originAddr+"\r\nConnection: close\r\n\r\n"), 0))
	require.NoError(t, err)
	body := naiveReadPaddingFrame(t, bufio.NewReader(conn))
	require.Contains(t, string(body), "origin-ok",
		"the authenticated tunnel must still reach the origin")
}

// TestJiejieNaiveMasqueradeBackendUnavailableFailsClosed proves a broken web
// backend cannot turn an unauthorised request into a tunnel.
func TestJiejieNaiveMasqueradeBackendUnavailableFailsClosed(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	originAddr := startOriginBackend(t)

	// Point the masquerade at a port that nothing is listening on.
	deadPort := reserveTCPPort(t)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       option.NetworkList("tcp"),
				Users:         []auth.User{{Username: naiveTestUser, Password: naiveTestPassword}},
				Masquerade: &option.Hysteria2Masquerade{
					Type: C.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         "http://127.0.0.1:" + strconv.Itoa(int(deadPort)),
						RewriteHost: true,
					},
				},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})

	conn := naiveTLSConn(t, port)
	response, err := naiveWriteConnect(t, conn, originAddr, map[string]string{
		"Padding": "~~~~~~~~",
	})
	if err != nil {
		return // refused outright, which is correct
	}
	defer response.Body.Close()
	require.NotEqual(t, http.StatusOK, response.StatusCode,
		"a dead masquerade backend must not cause an unauthenticated CONNECT to be "+
			"accepted as a tunnel")
}

// TestJiejieNaiveMasqueradeCannotBeUsedAsOpenProxy proves the masquerade reverse
// proxy target is fixed by configuration: a client cannot redirect it with the
// Host header or the request target.
func TestJiejieNaiveMasqueradeCannotBeUsedAsOpenProxy(t *testing.T) {
	port, _ := startNaiveMasqueradeEnv(t)
	// A second origin that the masquerade is NOT configured to reach.
	attackerTarget := startOriginBackend(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	// Absolute-form request target plus a spoofed Host, both pointing elsewhere.
	request := "GET http://" + attackerTarget + "/ HTTP/1.1\r\n" +
		"Host: " + attackerTarget + "\r\n" +
		"Connection: close\r\n\r\n"
	_, err = io.WriteString(tlsConn, request)
	require.NoError(t, err)

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return // refused: also acceptable
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.NotContains(t, string(body), "origin-ok",
		"the masquerade must always proxy to its CONFIGURED backend; a client must not "+
			"be able to redirect it with the Host header or an absolute request target")
}
