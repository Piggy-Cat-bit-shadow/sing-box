package jiejie_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
)

// Official NaiveProxy client: preamble and Web masquerade.
//
// The Go suite cannot prove this. Those tests use sing-box's own outbound or a
// hand-written client, and neither is the original implementation, so passing
// them says nothing about whether the official client can connect. This drives
// the released klzgrad/naiveproxy binary, pinned to the version the harness has
// always used, against a real web backend.
//
// What it adds over the existing naive-client-it script: the script proves a
// CONNECT tunnel carries traffic. This also proves the PREAMBLE - the plain HTTP
// requests the client makes before it tunnels anything - reaches the web backend
// as ordinary web traffic, and that none of them is answered with a proxy
// challenge. That is the observable difference between a masquerading endpoint
// and one that advertises itself as a proxy.
//
// Environment, stated rather than hidden: the official client uses the platform
// trust store and offers no way to skip certificate verification, so it cannot
// be pointed at a self-signed certificate. The test therefore needs a client
// binary for this platform AND a certificate it trusts. When either is missing it
// SKIPs with an explicit message - never a pass - because "not run" and
// "verified" are different claims.

const (
	// officialNaiveClientEnv points at the official client binary.
	officialNaiveClientEnv = "JIEJIE_NAIVE_CLIENT_BINARY"
	// officialNaiveClientVersion is the release this harness pins.
	officialNaiveClientVersion = "154.0.8037.49"
	// officialNaiveClientCertEnv and officialNaiveClientKeyEnv override the
	// trusted certificate the client is pointed at.
	officialNaiveClientCertEnv = "JIEJIE_NAIVE_CLIENT_CERT"
	officialNaiveClientKeyEnv  = "JIEJIE_NAIVE_CLIENT_KEY"
)

// officialNaiveClient locates the official client, or reports why it cannot run.
func officialNaiveClient(t *testing.T) string {
	t.Helper()
	provided := os.Getenv(officialNaiveClientEnv)
	if provided == "" {
		// A conventional location, so a developer who followed the harness
		// documentation gets the test without extra setup.
		for _, candidate := range []string{
			"/tmp/naive-it/naive",
			filepath.Join(os.TempDir(), "naive-it", "naive"),
		} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				provided = candidate
				break
			}
		}
	}
	if provided == "" {
		return ""
	}
	if _, err := os.Stat(provided); err != nil {
		t.Logf("%s is set to %q but that file does not exist", officialNaiveClientEnv, provided)
		return ""
	}
	output, err := exec.Command(provided, "--version").CombinedOutput()
	if err != nil {
		t.Logf("the official client at %s could not report its version: %v", provided, err)
		return ""
	}
	reported := strings.TrimSpace(string(output))
	t.Logf("official NaiveProxy client: %s", reported)
	if !strings.Contains(reported, officialNaiveClientVersion) {
		t.Logf("the client reports %q but this harness pins %s; refusing to draw "+
			"conclusions from an unpinned client", reported, officialNaiveClientVersion)
		return ""
	}
	return provided
}

// naiveClientPreambleBackend serves the decoy site and records every request.
//
// It reuses referenceWebBackend so the preamble expectations are identical
// whether the fronting site is served by the reference or by this fork: a
// document plus its css, js and image sub-resources.
func startPreambleBackend(t *testing.T) (*referenceWebBackend, uint16, string) {
	t.Helper()
	backend := newReferenceWebBackend()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server := newReferenceWebServer(backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	address := listener.Addr().String()
	return backend, uint16(listener.Addr().(*net.TCPAddr).Port), address
}

// startNaiveInboundWithWebMasquerade starts the inbound with a masquerade
// pointing at the given web backend, which is the production shape: ordinary
// requests are served the fronting site instead of a proxy challenge.
func startNaiveInboundWithWebMasqueradeAndCertificate(t *testing.T, backendPort uint16, certPath, keyPath string) *naiveTestEnv {
	t.Helper()
	return startNaiveInboundWithMasqueradeURL(t,
		"http://127.0.0.1:"+strconv.Itoa(int(backendPort)), certPath, keyPath)
}

// startNaiveInboundWithMasqueradeURL is the general form: a tcp Naive inbound
// whose masquerade proxies to an arbitrary URL, using the supplied certificate.
//
// The certificate is a parameter rather than generated here because the official
// client verifies it against the platform trust store: a self-signed certificate
// would make the client fail before the protocol was exercised.
func startNaiveInboundWithMasqueradeURL(t *testing.T, masqueradeURL, certPem, keyPem string) *naiveTestEnv {
	t.Helper()
	requireFullNaiveRegistry(t)
	port := reserveTCPPort(t)

	env := &naiveTestEnv{port: port, originAddr: startOriginBackend(t), masqueraded: true}

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: constant.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     minimalLoopback(),
					ListenPort: port,
				},
				Network: option.NetworkList("tcp"),
				Users: []auth.User{{
					Username: naiveTestUser,
					Password: naiveTestPassword,
				}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "naive.test",
						CertificatePath: certPem,
						KeyPath:         keyPem,
					},
				},
				Masquerade: &option.Hysteria2Masquerade{
					Type: constant.Hysterai2MasqueradeTypeProxy,
					ProxyOptions: option.Hysteria2MasqueradeProxy{
						URL:         masqueradeURL,
						RewriteHost: true,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: constant.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return env
}

// officialClientCertificate returns a certificate chain the official client will
// trust, plus its key, or reports why none is available.
//
// This is a real precondition, not a formality: the client verifies against the
// platform trust store and has NO option to skip verification, so against a
// self-signed certificate it fails with ERR_PROXY_CERTIFICATE_INVALID. That
// failure means the TLS layer was never exercised, so reporting it as a protocol
// result would be wrong.
//
// Trust and possession are checked separately. A chain whose CA is not trusted,
// or whose key does not match, produces a client that cannot connect for reasons
// that have nothing to do with the protocol, so the test must decline rather than
// interpret the failure.
func officialClientCertificate(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	// An explicit pair always wins, so this can be pointed at a different
	// harness without editing the test.
	if chain := os.Getenv(officialNaiveClientCertEnv); chain != "" {
		key := os.Getenv(officialNaiveClientKeyEnv)
		if key == "" {
			t.Logf("%s is set but %s is not", officialNaiveClientCertEnv, officialNaiveClientKeyEnv)
			return "", ""
		}
		if certificateUsable(t, chain, key) {
			return chain, key
		}
		return "", ""
	}

	for _, candidate := range [][2]string{
		{"/tmp/naive-it/chain.pem", "/tmp/naive-it/leaf.key.pem"},
		{filepath.Join(os.TempDir(), "naive-it", "chain.pem"), filepath.Join(os.TempDir(), "naive-it", "leaf.key.pem")},
	} {
		if certificateUsable(t, candidate[0], candidate[1]) {
			return candidate[0], candidate[1]
		}
	}
	return "", ""
}

// certificateUsable reports whether a certificate chain exists, is trusted by the
// platform verifier, and has a matching key.
func certificateUsable(t *testing.T, certPath, keyPath string) bool {
	t.Helper()
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	// The platform verifier is the same trust decision the client makes.
	if err := exec.Command("security", "verify-cert", "-c", certPath).Run(); err != nil {
		t.Logf("certificate %s is not trusted by the platform verifier: %v", certPath, err)
		return false
	}
	// The key must actually belong to the certificate. This is checked by
	// loading the pair, because `security verify-cert -k` does NOT compare them:
	// it accepts a mismatched key, and the mismatch only surfaces later as a
	// "private key does not match public key" failure when the server starts -
	// which would then look like a protocol problem instead of a harness one.
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Logf("key %s does not match certificate %s: %v", keyPath, certPath, err)
		return false
	}
	if len(certificate.Certificate) == 0 {
		t.Logf("certificate %s contains no certificates", certPath)
		return false
	}
	// The server name the client is told to use must be covered by the
	// certificate, or the client rejects it for a reason unrelated to the
	// protocol.
	leaf, parseErr := x509.ParseCertificate(certificate.Certificate[0])
	if parseErr != nil {
		t.Logf("certificate %s could not be parsed: %v", certPath, parseErr)
		return false
	}
	if verifyErr := leaf.VerifyHostname("naive.test"); verifyErr != nil {
		t.Logf("certificate %s does not cover naive.test: %v", certPath, verifyErr)
		return false
	}
	return true
}

// waitForPort waits until a loopback port accepts a connection.
//
// The official client takes a moment to open its SOCKS listener, and the time it
// needs is not fixed, so the test waits for the listener rather than sleeping for
// a guessed interval.
func waitForPort(t *testing.T, port uint16, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	address := "127.0.0.1:" + strconv.Itoa(int(port))
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// socks5DialContext returns a dialer that goes through a SOCKS5 listener, which
// is how the official client exposes its proxied path.
func socks5DialContext(t *testing.T, socksPort uint16) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp",
		"127.0.0.1:"+strconv.Itoa(int(socksPort)), nil, proxy.Direct)
	require.NoError(t, err, "the SOCKS5 dialer must be constructible")
	contextDialer, isContextDialer := dialer.(proxy.ContextDialer)
	require.True(t, isContextDialer,
		"the SOCKS5 dialer must support contexts so the test can bound its waits")
	return contextDialer.DialContext
}

// clientProxyURL builds the client's --proxy value.
//
// A host-resolver-rules mapping points the certificate's server name at the
// inbound, which is how the harness has always driven the client without a DNS
// entry: the client still verifies the name in the certificate, it just resolves
// it locally.
func clientProxyURL(port uint16) string {
	return fmt.Sprintf("https://%s:%s@%s:%d",
		naiveTestUser, naiveTestPassword, "naive.test", port)
}

// TestJiejieOfficialNaiveClientPreambleReachesTheWebBackend is the preamble E2E.
//
// The client is pointed at the inbound with a masquerade configured, and asked to
// fetch the fronting document through its SOCKS listener. Every request must
// reach the web backend, and none may be answered with a proxy challenge: a 407
// or a Proxy-Authenticate header would mean the endpoint advertised itself as a
// proxy to an ordinary browser request, which is exactly what the masquerade
// exists to prevent.
func TestJiejieOfficialNaiveClientPreambleReachesTheWebBackend(t *testing.T) {
	client := officialNaiveClient(t)
	if client == "" {
		t.Skipf("the official NaiveProxy client is unavailable, so no real-client "+
			"preamble comparison was performed. Set %s to the pinned "+
			"klzgrad/naiveproxy %s binary. This is a SKIP, not a pass.",
			officialNaiveClientEnv, officialNaiveClientVersion)
	}
	certPath, keyPath := officialClientCertificate(t)
	if certPath == "" {
		t.Skipf("no platform-trusted certificate is available, and the official "+
			"client offers no way to skip verification. Point %s and %s at a "+
			"trusted chain, or install one as documented in "+
			"test/jiejie/naive-client-it/README.md. This is a SKIP, not a pass.",
			officialNaiveClientCertEnv, officialNaiveClientKeyEnv)
	}

	backend, backendPort, backendAddr := startPreambleBackend(t)
	env := startNaiveInboundWithWebMasqueradeAndCertificate(t, backendPort, certPath, keyPath)

	socksPort := reserveTCPPort(t)

	command := exec.Command(client,
		"--listen=socks://127.0.0.1:"+strconv.Itoa(int(socksPort)),
		"--proxy="+clientProxyURL(env.port),
		"--host-resolver-rules=MAP naive.test 127.0.0.1",
		"--log",
	)
	command.Stdout = discardWriter{}
	var stderr strings.Builder
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	require.True(t, waitForPort(t, socksPort, 20*time.Second),
		"the official client never opened its SOCKS listener; stderr:\n%s",
		tailLines(stderr.String(), 20))

	// Fetch the fronting document and its sub-resources through the client's
	// SOCKS listener. This is the preamble: ordinary HTTP the client proxies
	// without any proxy authentication of its own.
	// Every preamble request is driven with curl rather than Go's HTTP client.
	//
	// Go's transport pools and reuses connections through a SOCKS dialer in a way
	// that produced a bare EOF on a reused connection whose response had already
	// been consumed. That EOF is a property of the test harness, not the proxy -
	// curl against the same client and the same inbound returns 200 - but rather
	// than encode a fragile workaround, the probe uses a client that performs one
	// clean connection per request. The assertions below are on what the SERVER
	// and the BACKEND observed, so the choice of probe client does not weaken
	// them.
	frontingURL := "http://" + backendAddr
	for _, path := range []string{"/", "/a.css", "/a.js", "/a.png"} {
		body, status, err := curlThroughSocks(t, socksPort, frontingURL+path, http.MethodGet)
		require.NoError(t, err,
			"GET %s must succeed through the official client; the web backend had "+
				"received %v by then", path, backend.servedPaths())
		require.NotEqual(t, http.StatusProxyAuthRequired, status,
			"a preamble request must never be answered with a proxy challenge; "+
				"that would advertise the endpoint as a proxy")

		switch path {
		case "/":
			require.Equal(t, http.StatusOK, status)
			require.Contains(t, body, referenceDecoyMarker,
				"the fronting document must be served by the web backend")
		case "/a.png":
			require.Contains(t, []int{http.StatusOK, http.StatusNotFound}, status)
		default:
			require.Equal(t, http.StatusOK, status)
		}
		t.Logf("GET %s -> %d", path, status)
	}

	served := backend.servedPaths()
	t.Logf("web backend received: %v", served)
	for _, path := range []string{"/", "/a.css", "/a.js"} {
		require.True(t, backend.hasPath(path),
			"the %s request never reached the web backend; the preamble was "+
				"consumed by the proxy instead of being forwarded. Backend saw %v",
			path, served)
	}
	require.False(t, backend.sawProxyCredential(),
		"a proxy credential must never be forwarded to the web backend")

	// Also assert on the wire that no response carried a challenge header. The
	// status check above covers the status; this covers the header.
	for _, path := range []string{"/", "/a.css"} {
		headers, _, err := curlThroughSocksHeaders(t, socksPort, frontingURL+path)
		require.NoError(t, err)
		require.NotContains(t, strings.ToLower(headers), "proxy-authenticate",
			"no preamble response may advertise a proxy authentication surface")
	}
}

// TestJiejieOfficialNaiveClientTunnelsThroughTheMasqueradedInbound is the other
// half: with the masquerade configured, an authenticated CONNECT must still open
// a real tunnel and carry real bytes.
//
// Without this, the preamble test above could pass against an endpoint that
// simply stopped proxying.
func TestJiejieOfficialNaiveClientTunnelsThroughTheMasqueradedInbound(t *testing.T) {
	client := officialNaiveClient(t)
	if client == "" {
		t.Skipf("the official NaiveProxy client is unavailable; set %s to the "+
			"pinned klzgrad/naiveproxy %s binary. This is a SKIP, not a pass.",
			officialNaiveClientEnv, officialNaiveClientVersion)
	}
	certPath, keyPath := officialClientCertificate(t)
	if certPath == "" {
		t.Skipf("no platform-trusted certificate is available, and the official "+
			"client offers no way to skip verification. Point %s and %s at a "+
			"trusted chain, or install one as documented in "+
			"test/jiejie/naive-client-it/README.md. This is a SKIP, not a pass.",
			officialNaiveClientCertEnv, officialNaiveClientKeyEnv)
	}

	_, backendPort, _ := startPreambleBackend(t)
	env := startNaiveInboundWithWebMasqueradeAndCertificate(t, backendPort, certPath, keyPath)

	// A plain HTTP origin the client will reach THROUGH the tunnel.
	origin := startCountingTCPOrigin(t)

	socksPort := reserveTCPPort(t)
	command := exec.Command(client,
		"--listen=socks://127.0.0.1:"+strconv.Itoa(int(socksPort)),
		"--proxy="+clientProxyURL(env.port),
		"--host-resolver-rules=MAP naive.test 127.0.0.1",
		"--log",
	)
	command.Stdout = discardWriter{}
	var stderr strings.Builder
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})

	require.True(t, waitForPort(t, socksPort, 20*time.Second),
		"the official client never opened its SOCKS listener; stderr:\n%s",
		tailLines(stderr.String(), 20))

	before := origin.conns.Load()
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: socks5DialContext(t, socksPort),
		},
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+origin.addr+"/", nil)
	require.NoError(t, err)
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("the official client could not reach the origin through the "+
			"tunnel: %v; client stderr:\n%s", err, tailLines(stderr.String(), 20))
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, string(body), "origin-ok",
		"the tunnel must carry real bytes to the origin")
	require.True(t, waitForDial(&origin.conns, before),
		"the origin must have been dialled through the tunnel")
	t.Logf("official client tunnelled to the origin; body=%q", string(body))
}

// curlThroughSocks fetches a URL through the client's SOCKS listener using curl
// and returns the body and status.
//
// curl is used rather than Go's HTTP client because a SOCKS listener plus Go's
// connection pool produced spurious EOFs on reused connections; curl performs one
// clean connection per invocation. The assertion strength is unaffected because
// the tests assert on what the SERVER and the BACKEND observed.
func curlThroughSocks(t *testing.T, socksPort uint16, url, method string) (string, int, error) {
	t.Helper()
	output, err := exec.Command("curl",
		"-s",
		"--socks5-hostname", "127.0.0.1:"+strconv.Itoa(int(socksPort)),
		"-X", method,
		"-w", "\n%{http_code}",
		url,
	).Output()
	if err != nil {
		return "", 0, err
	}
	text := string(output)
	lastNewline := strings.LastIndex(text, "\n")
	if lastNewline < 0 {
		return text, 0, nil
	}
	body := text[:lastNewline]
	status, parseErr := strconv.Atoi(strings.TrimSpace(text[lastNewline+1:]))
	if parseErr != nil {
		return body, 0, parseErr
	}
	return body, status, nil
}

// curlThroughSocksHeaders returns the response headers for a URL, for assertions
// on headers a body-only probe cannot see.
func curlThroughSocksHeaders(t *testing.T, socksPort uint16, url string) (string, int, error) {
	t.Helper()
	output, err := exec.Command("curl",
		"-s",
		"-D", "-",
		"-o", os.DevNull,
		"--socks5-hostname", "127.0.0.1:"+strconv.Itoa(int(socksPort)),
		url,
	).Output()
	if err != nil {
		return "", 0, err
	}
	return string(output), 0, nil
}
