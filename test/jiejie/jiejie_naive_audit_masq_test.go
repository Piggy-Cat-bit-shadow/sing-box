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
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// AUDIT: exactly which headers reach the masquerade backend.
//
// The task lists specific headers that must not be forwarded or must not be
// trusted. Rather than reason about httputil.ReverseProxy's documented behaviour,
// this records what the backend ACTUALLY saw.

// headerRecorder captures the last request the backend received.
type headerRecorder struct {
	mu      sync.Mutex
	headers http.Header
	host    string
	url     string
	method  string
	hits    int
}

func (r *headerRecorder) record(request *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headers = request.Header.Clone()
	r.host = request.Host
	r.url = request.URL.String()
	r.method = request.Method
	r.hits++
}

func (r *headerRecorder) snapshot() (http.Header, string, string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headers, r.host, r.url, r.method
}

// startNaiveWithRecordingDecoy starts a Naive inbound whose masquerade points at
// a recording backend, and returns the port plus the recorder.
func startNaiveWithRecordingDecoy(t *testing.T) (uint16, *headerRecorder) {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	recorder := &headerRecorder{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	backend := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			recorder.record(request)
			writer.Header().Set("Content-Type", "text/html")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "<html><body>DECOY</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = backend.Serve(listener) }()
	t.Cleanup(func() { _ = backend.Close() })

	startInstanceWithMasquerade(t, port, certPem, keyPem, "http://"+listener.Addr().String())
	return port, recorder
}

// startInstanceWithMasquerade starts a Naive inbound pointing at a decoy URL.
func startInstanceWithMasquerade(t *testing.T, port uint16, certPem, keyPem, decoyURL string) {
	t.Helper()
	config := fmt.Sprintf(`{
		"inbounds": [{
			"type": "naive", "tag": "naive-in",
			"listen": "127.0.0.1", "listen_port": %d,
			"network": "tcp",
			"users": [{"username": %q, "password": %q}],
			"masquerade": {"type": "proxy", "url": %q, "rewrite_host": true},
			"tls": {"enabled": true, "server_name": "naive.test",
			        "certificate_path": %q, "key_path": %q}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"final": "direct"}
	}`, port, naiveTestUser, naiveTestPassword, decoyURL, certPem, keyPem)
	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)
}

// TestAuditMasqueradeHeaderForwarding records what the backend receives for a
// browser-shaped request carrying a hostile set of headers.
func TestAuditMasqueradeHeaderForwarding(t *testing.T) {
	port, recorder := startNaiveWithRecordingDecoy(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	credential := base64.StdEncoding.EncodeToString([]byte(naiveTestUser + ":" + naiveTestPassword))
	request := strings.Join([]string{
		"GET /probe HTTP/1.1",
		"Host: attacker.example",
		"Proxy-Authorization: Basic " + credential,
		"Proxy-Connection: keep-alive",
		"Connection: keep-alive, X-Injected",
		"X-Injected: should-not-be-hop-by-hop",
		"TE: trailers",
		"Trailer: X-Trailer",
		"X-Forwarded-For: 1.2.3.4",
		"X-Forwarded-Host: evil.example",
		"X-Forwarded-Proto: https",
		"Forwarded: for=9.9.9.9",
		"",
		"",
	}, "\r\n")
	_, err = io.WriteString(tlsConn, request)
	require.NoError(t, err)

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	require.Contains(t, string(body), "DECOY")

	require.Equal(t, 1, recorder.hits, "the backend must have been reached exactly once")
	headers, host, _, method := recorder.snapshot()
	t.Logf("backend saw method=%s host=%q", method, host)
	for name, values := range headers {
		t.Logf("  %s: %v", name, values)
	}

	// The proxy credential must never reach the backend.
	require.Empty(t, headers.Get("Proxy-Authorization"),
		"Proxy-Authorization carries the proxy credential and must never be forwarded")

	// Hop-by-hop headers must not be forwarded.
	require.Empty(t, headers.Get("Proxy-Connection"))
	require.Empty(t, headers.Get("Trailer"))

	// TE is the documented exception, and this is CORRECT rather than a leak.
	// Go's ReverseProxy strips the hop-by-hop list but then deliberately re-adds
	// `Te: trailers` when the client sent it (net/http/httputil/reverseproxy.go),
	// because RFC 7230 4.3 makes that the one TE value that is legal end to end.
	// Only "trailers" is acceptable here; any other TE value would be a real leak.
	require.Equal(t, "trailers", headers.Get("Te"),
		"the only TE value that may be forwarded is 'trailers' (RFC 7230 4.3)")

	// The rewritten Host must be the CONFIGURED backend, not the client's.
	require.NotEqual(t, "attacker.example", host,
		"rewrite_host must replace the client-supplied Host with the configured target")
}

// TestAuditMasqueradeCannotBeRedirectedByHost proves a client cannot use the Host
// header to turn the masquerade into an open proxy.
func TestAuditMasqueradeCannotBeRedirectedByHost(t *testing.T) {
	port, recorder := startNaiveWithRecordingDecoy(t)
	// A second backend the masquerade is NOT configured to use.
	otherBackend := startRecordingTCPTarget(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: "+otherBackend.address+
		"\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	_, _ = io.ReadAll(tlsConn)

	time.Sleep(200 * time.Millisecond)
	require.Zero(t, otherBackend.connections.Load(),
		"the masquerade target is fixed by configuration and must not be "+
			"redirectable via the Host header")
	require.Equal(t, 1, recorder.hits, "the CONFIGURED backend must still serve the request")
}

// TestAuditMasqueradeDoesNotForwardProxyCredentialsForConnect repeats the
// credential check on the CONNECT path, which reaches the masquerade only when
// unauthenticated.
func TestAuditMasqueradeDoesNotForwardProxyCredentialsForConnect(t *testing.T) {
	port, recorder := startNaiveWithRecordingDecoy(t)

	wrongCredential := base64.StdEncoding.EncodeToString([]byte(naiveTestUser + ":wrong"))

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = io.WriteString(tlsConn, "CONNECT example.test:443 HTTP/1.1\r\n"+
		"Host: example.test:443\r\nProxy-Authorization: Basic "+wrongCredential+"\r\n"+
		"Padding: ~~~~~~~~\r\n\r\n")
	require.NoError(t, err)
	_, _ = io.ReadAll(tlsConn)

	time.Sleep(200 * time.Millisecond)
	if recorder.hits == 0 {
		t.Log("the CONNECT was refused without reaching the backend (also acceptable)")
		return
	}
	headers, _, _, _ := recorder.snapshot()
	require.Empty(t, headers.Get("Proxy-Authorization"),
		"a rejected CONNECT's credential must not be forwarded to the backend")
}
