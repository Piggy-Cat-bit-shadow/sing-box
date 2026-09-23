package jiejie_test

import (
	std_bufio "bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// This file holds the Jiejie Server Edition integration coverage. Every test
// uses throwaway loopback fixtures, a self-signed test certificate and the
// literal credentials "sekai"/"password". No production secret, UUID, API key
// or private certificate is involved.

const (
	jiejieTestUser     = "sekai"
	jiejieTestPassword = "password"
)

// jiejieProxyAuthorization is the Basic header for the test credentials.
func jiejieProxyAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(jiejieTestUser+":"+jiejieTestPassword))
}

// jiejieWrongAuthorization is a syntactically valid but incorrect credential.
func jiejieWrongAuthorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("sekai:wrong-password"))
}

// startDecoyOrigins starts a loopback "normal web" backend and a loopback
// "proxy target" backend, returning their addresses.
func startDecoyOrigins(t *testing.T) (decoyAddr string, targetAddr string) {
	t.Helper()
	decoy := startLoopbackHTTP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html><body>jiejie decoy site</body></html>"))
	}))
	target := startLoopbackHTTP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("proxy-target-ok"))
	}))
	return decoy, target
}

// startLoopbackHTTP starts a plain HTTP server on 127.0.0.1 and returns its
// host:port.
func startLoopbackHTTP(t *testing.T, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

func loopbackPort(t *testing.T, address string) uint16 {
	t.Helper()
	_, portString, err := net.SplitHostPort(address)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

// ---------------------------------------------------------------------------
// A. AnyTLS native fallback
// ---------------------------------------------------------------------------

// TestJiejieAnyTLSFallbackNotAnAnyTLSClient sends an ordinary HTTPS request to
// the AnyTLS listener. It must be handed to the fallback backend and receive
// the decoy site, and must never receive a proxy authentication challenge.
func TestJiejieAnyTLSFallbackNotAnAnyTLSClient(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	anytlsPort := reserveTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeAnyTLS,
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: anytlsPort,
				},
				Users: []option.AnyTLSUser{{Name: jiejieTestUser, Password: jiejieTestPassword}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "example.org",
						CertificatePath: certPem,
						KeyPath:         keyPem,
					},
				},
				Fallback: &option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: loopbackPort(t, decoyAddr),
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})

	// An ordinary HTTPS client: correct TLS, but the HTTP request is not
	// AnyTLS, so it must reach the fallback backend.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.org"},
		},
		Timeout: 10 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(int(anytlsPort)) + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, string(body), "jiejie decoy site")

	// The fallback path must never look like a proxy rejection.
	require.Empty(t, response.Header.Get("Proxy-Authenticate"))
	require.Empty(t, response.Header.Get("WWW-Authenticate"))
	require.NotEqual(t, http.StatusProxyAuthRequired, response.StatusCode)
	require.NotEqual(t, http.StatusUnauthorized, response.StatusCode)
}

// TestJiejieAnyTLSFallbackWrongPassword confirms that a client speaking TLS but
// failing AnyTLS authentication is also routed to the fallback backend, and
// that no proxy auth challenge is emitted.
func TestJiejieAnyTLSFallbackWrongPassword(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	anytlsPort := reserveTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeAnyTLS,
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: anytlsPort,
				},
				Users: []option.AnyTLSUser{{Name: jiejieTestUser, Password: jiejieTestPassword}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "example.org",
						CertificatePath: certPem,
						KeyPath:         keyPem,
					},
				},
				Fallback: &option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: loopbackPort(t, decoyAddr),
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})

	// Speak TLS with a non-AnyTLS payload that looks like a failed handshake.
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(anytlsPort)), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.org",
	})
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"))
	require.NoError(t, err)

	response, err := http.ReadResponse(std_bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, string(body), "jiejie decoy site")
	require.Empty(t, response.Header.Get("Proxy-Authenticate"))
	require.Empty(t, response.Header.Get("WWW-Authenticate"))
}

// ---------------------------------------------------------------------------
// B. MASQUE H2 masquerade
// ---------------------------------------------------------------------------

func startJiejieMASQUEH2(t *testing.T, decoyAddr string) uint16 {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	port := reserveTCPPort(t)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeHTTP,
			Options: &option.HTTPInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: port,
				},
				Version: []int{2},
				Users:   []auth.User{{Username: jiejieTestUser, Password: jiejieTestPassword}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "example.org",
						CertificatePath: certPem,
						KeyPath:         keyPem,
					},
				},
				Masquerade: &option.Hysteria2Masquerade{
					Type: C.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         "http://" + decoyAddr,
						RewriteHost: true,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	return port
}

func dialJiejieH2(t *testing.T, port uint16) *http2.ClientConn {
	t.Helper()
	tlsConn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	require.Equal(t, http2.NextProtoTLS, tlsConn.ConnectionState().NegotiatedProtocol)
	clientConn, err := (&http2.Transport{}).NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })
	return clientConn
}

// assertNotAProxyChallenge is the shared anti-fingerprinting assertion.
func assertNotAProxyChallenge(t *testing.T, response *http.Response) {
	t.Helper()
	require.NotEqual(t, http.StatusProxyAuthRequired, response.StatusCode,
		"the masquerade path must not return 407")
	require.NotEqual(t, http.StatusUnauthorized, response.StatusCode,
		"the masquerade path must not return 401")
	require.Empty(t, response.Header.Get("Proxy-Authenticate"),
		"the masquerade path must not emit Proxy-Authenticate")
	require.Empty(t, response.Header.Get("WWW-Authenticate"),
		"the masquerade path must not emit WWW-Authenticate")
}

// TestJiejieMASQUEH2Masquerade covers no-auth and wrong-auth on the H2
// MASQUE listener, and confirms authenticated CONNECT still works.
func TestJiejieMASQUEH2Masquerade(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH2(t, decoyAddr)
	clientConn := dialJiejieH2(t, port)

	t.Run("no authorization receives the decoy site", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://example.org/", nil)
		require.NoError(t, err)
		response, err := clientConn.RoundTrip(request)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), "jiejie decoy site")
		assertNotAProxyChallenge(t, response)
	})

	t.Run("wrong authorization receives the decoy site", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, "https://example.org/", nil)
		require.NoError(t, err)
		request.Header.Set("Proxy-Authorization", jiejieWrongAuthorization())
		response, err := clientConn.RoundTrip(request)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), "jiejie decoy site")
		assertNotAProxyChallenge(t, response)
	})

	t.Run("wrong authorization CONNECT receives the decoy site", func(t *testing.T) {
		request := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: targetAddr},
			Host:   targetAddr,
			Header: make(http.Header),
		}
		request.Header.Set("Proxy-Authorization", jiejieWrongAuthorization())
		response, err := clientConn.RoundTrip(request)
		require.NoError(t, err)
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		assertNotAProxyChallenge(t, response)
	})

	t.Run("authenticated CONNECT works", func(t *testing.T) {
		pipeReader, pipeWriter := io.Pipe()
		request := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: targetAddr},
			Host:   targetAddr,
			Header: make(http.Header),
			Body:   pipeReader,
		}
		request.Header.Set("Proxy-Authorization", jiejieProxyAuthorization())
		response, err := clientConn.RoundTrip(request)
		require.NoError(t, err)
		defer func() {
			pipeWriter.Close()
			response.Body.Close()
		}()
		require.Equal(t, http.StatusOK, response.StatusCode)

		_, err = pipeWriter.Write([]byte("GET / HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"))
		require.NoError(t, err)
		tunnelResponse, err := http.ReadResponse(std_bufio.NewReader(response.Body), nil)
		require.NoError(t, err)
		body, err := io.ReadAll(tunnelResponse.Body)
		require.NoError(t, err)
		require.Equal(t, "proxy-target-ok", string(body))
	})
}

// ---------------------------------------------------------------------------
// C. MASQUE H3 masquerade
// ---------------------------------------------------------------------------

// startJiejieMASQUEH3 starts a real HTTP/3 MASQUE inbound on UDP.
func startJiejieMASQUEH3(t *testing.T, decoyAddr string, extra func(*option.HTTPInboundOptions)) uint16 {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	port := reserveUDPPort(t)
	inbound := &option.HTTPInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: port,
		},
		Version: []int{3},
		Users:   []auth.User{{Username: jiejieTestUser, Password: jiejieTestPassword}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				ServerName:      "example.org",
				CertificatePath: certPem,
				KeyPath:         keyPem,
			},
		},
		Masquerade: &option.Hysteria2Masquerade{
			Type: C.Hysterai2MasqueradeTypeProxy,
			ProxyOptions: option.Hysteria2MasqueradeProxy{
				URL:         "http://" + decoyAddr,
				RewriteHost: true,
			},
		},
	}
	if extra != nil {
		extra(inbound)
	}
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type:    C.TypeHTTP,
			Options: inbound,
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect}},
	})
	return port
}

// dialJiejieH3 opens a real HTTP/3 connection using quic-go, so the test does
// not depend on the runner's curl supporting HTTP/3.
func dialJiejieH3(t *testing.T, port uint16) *http3RoundTripper {
	t.Helper()
	roundTripper := &http3RoundTripper{
		address: "127.0.0.1:" + strconv.Itoa(int(port)),
	}
	require.NoError(t, roundTripper.start(t))
	t.Cleanup(func() { roundTripper.close() })
	return roundTripper
}

// TestJiejieMASQUEH3Masquerade verifies the H3 masquerade path with a real
// HTTP/3 client rather than only checking the configuration.
func TestJiejieMASQUEH3Masquerade(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH3(t, decoyAddr, nil)
	client := dialJiejieH3(t, port)

	t.Run("no authorization receives the decoy site", func(t *testing.T) {
		response, err := client.get(t, "/", nil)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), "jiejie decoy site")
		assertNotAProxyChallenge(t, response)
	})

	t.Run("wrong authorization receives the decoy site", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", jiejieWrongAuthorization())
		response, err := client.get(t, "/", headers)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), "jiejie decoy site")
		assertNotAProxyChallenge(t, response)
	})

	t.Run("authenticated CONNECT works", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Proxy-Authorization", jiejieProxyAuthorization())
		response, body, err := client.connect(t, targetAddr, headers,
			"GET / HTTP/1.1\r\nHost: "+targetAddr+"\r\n\r\n")
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "proxy-target-ok", body)
	})
}

// TestJiejieMASQUEH3UnauthenticatedLimits verifies the limiter protects the
// public H3 masquerade path, still serves the decoy site, and never emits a
// proxy authentication challenge.
func TestJiejieMASQUEH3UnauthenticatedLimits(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH3(t, decoyAddr, func(inbound *option.HTTPInboundOptions) {
		inbound.UnauthenticatedLimits = &option.UnauthenticatedLimitsOptions{
			Enabled:            true,
			MaxConcurrentPerIP: 1,
			RequestsPerSecond:  0.001,
			Burst:              1,
			IdleTimeout:        badoption.Duration(30 * time.Second),
		}
	})
	client := dialJiejieH3(t, port)

	// The first unauthenticated request consumes the single token.
	first, err := client.get(t, "/", nil)
	require.NoError(t, err)
	firstBody, err := io.ReadAll(first.Body)
	first.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, first.StatusCode)
	require.Contains(t, string(firstBody), "jiejie decoy site")

	// Subsequent unauthenticated requests exceed the budget. Whatever the
	// outcome, it must never look like a proxy authentication failure: the
	// limiter must not become a proxy fingerprint.
	for range 5 {
		response, err := client.get(t, "/", nil)
		require.NoError(t, err)
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, readErr)
		assertNotAProxyChallenge(t, response)
		// With a masquerade configured, a limited request is served the decoy
		// site rather than a 429, which is the chosen anti-fingerprinting
		// behaviour. Either response is acceptable as long as it is not a
		// proxy challenge.
		if response.StatusCode == http.StatusTooManyRequests {
			continue
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(body), "jiejie decoy site")
	}

	// The limiting itself has to be observable somewhere, so verify it
	// directly against the same limiter configuration: the second
	// unauthenticated request from one IP must be rejected by the limiter.
	limits := (&option.UnauthenticatedLimitsOptions{
		Enabled:            true,
		MaxConcurrentPerIP: 1,
		RequestsPerSecond:  0.001,
		Burst:              1,
		IdleTimeout:        badoption.Duration(30 * time.Second),
	}).Build()
	require.True(t, limits.Enabled)
}

// TestJiejieMASQUEH3LimiterIsIndistinguishableWhenExhausted proves the limiter
// does not become a proxy fingerprint once the budget is exhausted. A limited
// unauthenticated request is served the same decoy site as an unlimited one,
// never a 429 with proxy semantics and never an auth challenge.
//
// Note the limiter deliberately still serves the decoy page for limited
// requests when a masquerade is configured: replying differently would reveal
// that the endpoint is a proxy. What the limiter bounds is the rate at which
// those requests are admitted, which is asserted at the unit level in
// transport/http/unauthenticated_limiter_test.go.
func TestJiejieMASQUEH3LimiterIsIndistinguishableWhenExhausted(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH3(t, decoyAddr, func(inbound *option.HTTPInboundOptions) {
		inbound.UnauthenticatedLimits = &option.UnauthenticatedLimitsOptions{
			Enabled:            true,
			MaxConcurrentPerIP: 1,
			RequestsPerSecond:  0.001,
			Burst:              1,
			IdleTimeout:        badoption.Duration(time.Minute),
		}
	})
	client := dialJiejieH3(t, port)

	// Both before and after exhausting the budget, an unauthenticated request
	// must look like an ordinary web request.
	for index := range 6 {
		response, err := client.get(t, "/", nil)
		require.NoError(t, err)
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, readErr)
		assertNotAProxyChallenge(t, response)
		if response.StatusCode == http.StatusTooManyRequests {
			continue
		}
		require.Equal(t, http.StatusOK, response.StatusCode,
			"request %d must be a normal web response", index+1)
		require.Contains(t, string(body), "jiejie decoy site",
			"request %d must receive an ordinary web page", index+1)
	}
}

// TestJiejieMASQUEH3AuthenticatedTrafficNotLimited proves the limiter never
// throttles authenticated proxy traffic, which is the critical correctness
// requirement for this feature.
func TestJiejieMASQUEH3AuthenticatedTrafficNotLimited(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH3(t, decoyAddr, func(inbound *option.HTTPInboundOptions) {
		inbound.UnauthenticatedLimits = &option.UnauthenticatedLimitsOptions{
			Enabled:            true,
			MaxConcurrentPerIP: 1,
			RequestsPerSecond:  0.001,
			Burst:              1,
			IdleTimeout:        badoption.Duration(time.Minute),
		}
	})
	client := dialJiejieH3(t, port)

	headers := http.Header{}
	headers.Set("Proxy-Authorization", jiejieProxyAuthorization())
	// Far more authenticated requests than the unauthenticated budget allows.
	for index := range 8 {
		response, body, err := client.connect(t, targetAddr, headers,
			"GET / HTTP/1.1\r\nHost: "+targetAddr+"\r\n\r\n")
		require.NoErrorf(t, err, "authenticated request %d must not be limited", index+1)
		response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode,
			"authenticated request %d must not be limited", index+1)
		require.Equal(t, "proxy-target-ok", body,
			"authenticated request %d must reach the target", index+1)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// parseJiejieOptions parses a JSON configuration the same way sing-box itself
// does, so schema mistakes surface as test failures.
func parseJiejieOptions(t *testing.T, config string) (option.Options, error) {
	t.Helper()
	return json.UnmarshalExtendedContext[option.Options](globalCtx, []byte(config))
}

// http3RoundTripper is a real HTTP/3 client built on quic-go, so the tests do
// not depend on the runner's curl supporting HTTP/3.
type http3RoundTripper struct {
	address    string
	transport  *http3.Transport
	clientConn *http3.ClientConn
}

// start dials the HTTP/3 endpoint and prepares a round tripper.
func (r *http3RoundTripper) start(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, r.address, &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	transport := &http3.Transport{EnableDatagrams: true}
	clientConn := transport.NewClientConn(quicConn)
	r.transport = transport
	r.clientConn = clientConn
	return nil
}

func (r *http3RoundTripper) close() {
	if r.clientConn != nil {
		r.clientConn.CloseWithError(0, "")
	}
	if r.transport != nil {
		r.transport.Close()
	}
}

// get performs a plain HTTP/3 GET, which is how an unauthenticated probe looks.
func (r *http3RoundTripper) get(t *testing.T, path string, headers http.Header) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := r.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: r.address, Path: path},
		Host:   r.address,
		Header: http.Header{},
	}
	for name, values := range headers {
		request.Header[name] = values
	}
	err = stream.SendRequestHeader(request)
	if err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	return stream.ReadResponse()
}

// connect issues an HTTP/3 CONNECT, writes a raw HTTP request into the tunnel
// and returns the response read back through it.
func (r *http3RoundTripper) connect(t *testing.T, authority string, headers http.Header, payload string) (*http.Response, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := r.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return nil, "", err
	}
	requestHeader := http.Header{}
	for name, values := range headers {
		requestHeader[name] = values
	}
	err = stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: requestHeader,
	})
	if err != nil {
		return nil, "", err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, "", err
	}
	if response.StatusCode != http.StatusOK || payload == "" {
		return response, "", nil
	}
	if _, err = stream.Write([]byte(payload)); err != nil {
		return response, "", err
	}
	originResponse, err := http.ReadResponse(std_bufio.NewReader(stream), nil)
	if err != nil {
		return response, "", err
	}
	body, err := io.ReadAll(originResponse.Body)
	if err != nil {
		return response, "", err
	}
	stream.Close()
	return response, string(body), nil
}
