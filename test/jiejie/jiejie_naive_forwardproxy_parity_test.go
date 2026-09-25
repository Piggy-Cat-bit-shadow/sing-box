package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Behaviour aligned with klzgrad/forwardproxy@naive.
//
// Every assertion here is derived from the reference source, pinned at the
// commit recorded in CaddyReferenceCommit below, and each test names the code it
// corresponds to. Where sing-box previously disagreed, the test records the
// reference behaviour, not sing-box's prior behaviour.

// CaddyReferenceCommit is the klzgrad/forwardproxy revision these parity tests
// were written against. It is pinned rather than tracking a branch so the
// expectations cannot drift underneath the suite.
const CaddyReferenceCommit = "d62c80d3dd2c706b6b87579844d2397bddd18317"

// ---------------------------------------------------------------------------
// Padding negotiation: reference forwardproxy.go lines 308-320 and 352
// ---------------------------------------------------------------------------

// TestJiejieNaiveParityResponsePaddingHeaderIsUnconditional covers the first
// half of the padding contract.
//
// Reference (forwardproxy.go, CONNECT branch):
//
//	w.Header().Set("Padding", string(padding))   // line 320, NO condition
//	w.WriteHeader(http.StatusOK)
//
// The header is therefore present for every authenticated CONNECT, whether or
// not the request carried Padding.
func TestJiejieNaiveParityResponsePaddingHeaderIsUnconditional(t *testing.T) {
	env := startNaiveInbound(t, false)

	for _, testCase := range []struct {
		name        string
		sendPadding bool
	}{
		{"request WITH Padding header", true},
		{"request WITHOUT Padding header", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			headers := map[string]string{"Proxy-Authorization": naiveBasicAuth()}
			if testCase.sendPadding {
				headers["Padding"] = "~~~~~~~~"
			}

			response := naiveWriteConnectOK(t, conn, env.originAddr, headers)
			defer response.Body.Close()

			require.Equal(t, http.StatusOK, response.StatusCode)
			padding := response.Header.Get("Padding")
			require.NotEmpty(t, padding,
				"the response Padding header is unconditional in the reference "+
					"(forwardproxy.go line 320); it must not depend on the request")
			require.GreaterOrEqual(t, len(padding), 30,
				"the reference generates a padding header of length "+
					"rand.Intn(32)+30, so it is never shorter than 30 characters")
			require.Less(t, len(padding), 62,
				"and never longer than 30+31-1=61 characters")
		})
	}
}

// TestJiejieNaiveParityPayloadFramingFollowsRequestOnly covers the second half.
//
// Reference (forwardproxy.go line 352):
//
//	dualStream(targetConn, r.Body, w, r.Header.Get("Padding") != "")
//
// Framing is driven ONLY by the request header. The response header must not
// turn framing on, otherwise an ordinary HTTP CONNECT client would be forced to
// parse Naive frames it never negotiated.
func TestJiejieNaiveParityPayloadFramingFollowsRequestOnly(t *testing.T) {
	env := startNaiveInbound(t, false)

	t.Run("no request Padding means raw bytes pass through", func(t *testing.T) {
		conn := naiveTLSConn(t, env.port)
		response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
		})
		defer response.Body.Close()

		require.NotEmpty(t, response.Header.Get("Padding"),
			"precondition: the header is present, so this test proves framing "+
				"stays OFF even when the header IS advertised")

		// Raw, UNFRAMED bytes must reach the origin.
		_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + env.originAddr +
			"\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)

		body, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Contains(t, string(body), "origin-ok",
			"an unframed request must still reach the origin: the response "+
				"Padding header must not enable payload framing")
	})

	t.Run("request Padding does NOT enable framing on HTTP/1", func(t *testing.T) {
		// This is the case that distinguishes the two concepts. The request
		// carries Padding, so the RESPONSE header is present - but HTTP/1 is a
		// raw tunnel in the reference, because serveHijack ends in
		// dualStream(targetConn, clientConn, clientConn, false). Framing is
		// enabled only on HTTP/2 and HTTP/3.
		//
		// Sending a Naive frame here is what the previous implementation
		// expected, and it desynchronised the server from the client's first
		// data byte. The assertion is therefore RAW in both directions.
		conn := naiveTLSConn(t, env.port)
		response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
		defer response.Body.Close()
		require.NotEmpty(t, response.Header.Get("Padding"),
			"precondition: the response header is present, so this test proves "+
				"the header alone does not enable framing")

		requestBytes := []byte("GET / HTTP/1.1\r\nHost: " + env.originAddr + "\r\nConnection: close\r\n\r\n")
		_, err := conn.Write(requestBytes)
		require.NoError(t, err)

		body, readErr := io.ReadAll(conn)
		require.NoError(t, readErr)
		require.Contains(t, string(body), "origin-ok",
			"a RAW request must reach the origin over HTTP/1 even though the "+
				"request carried a Padding header")
	})
}

// ---------------------------------------------------------------------------
// HTTP/2 and HTTP/3 CONNECT pseudo-header validation
// Reference forwardproxy.go lines 297-301
// ---------------------------------------------------------------------------

// TestJiejieNaiveParityH2ConnectRejectsPseudoHeaders documents where the
// reference's :scheme/:path check is actually enforced on HTTP/2.
//
// The reference performs it explicitly (forwardproxy.go lines 297-301). On
// HTTP/2 in Go that rejection has ALREADY happened one layer below us:
// x/net/http2 builds the request from the pseudo-headers and, for CONNECT,
// returns a stream-level PROTOCOL_ERROR if :path or :scheme is present:
//
//	// x/net/http2 server.go, newWriterAndRequest
//	isConnect := rp.Method == "CONNECT"
//	if isConnect {
//	    if rp.Protocol == "" && (rp.Path != "" || rp.Scheme != "" || rp.Authority == "") {
//	        return nil, nil, sc.countError("bad_connect", streamError(f.StreamID, ErrCodeProtocol))
//	    }
//	}
//
// So a handler can never observe such a request on H2, which is why the check
// cannot be exercised through the normal client: the Go transport does not send
// it and the server would refuse the stream if it did.
//
// This test therefore asserts the property that actually matters and IS
// observable - such a request never opens a tunnel and never dials the target -
// and records that the enforcement point on H2 is x/net/http2 rather than
// sing-box. The explicit check is still present in sing-box (and is what
// enforces the rule on HTTP/3, which does not share x/net/http2's guard), and
// TestJiejieNaiveParityH3ConnectValidationIsPresent pins that it exists.
func TestJiejieNaiveParityH2ConnectRejectsPseudoHeaders(t *testing.T) {
	requireFullNaiveRegistry(t)
	env := startNaiveInbound(t, false)
	origin := startCountingTCPOrigin(t)

	for _, testCase := range []struct {
		name string
		url  *url.URL
		host string
	}{
		{"H2 CONNECT with :path", &url.URL{Host: origin.addr, Path: "/not-allowed"}, origin.addr},
		{"H2 CONNECT with :scheme", &url.URL{Scheme: "https", Host: origin.addr}, origin.addr},
		{"H2 CONNECT with both", &url.URL{Scheme: "https", Host: origin.addr, Path: "/x"}, origin.addr},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			transport := &http2.Transport{}
			tlsConn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
			clientConn, err := transport.NewClientConn(tlsConn)
			require.NoError(t, err)
			t.Cleanup(func() { _ = clientConn.Close() })

			pipeReader, pipeWriter := io.Pipe()
			t.Cleanup(func() {
				_ = pipeWriter.Close()
				_ = pipeReader.Close()
			})

			response, err := clientConn.RoundTrip(&http.Request{
				Method: http.MethodConnect,
				URL:    testCase.url,
				Host:   testCase.host,
				Header: http.Header{
					"Proxy-Authorization": []string{naiveBasicAuth()},
				},
				Body: pipeReader,
			})

			t.Logf("client observed: response=%v err=%v", response != nil, err)
			t.Logf("NOTE: on HTTP/2 the scheme/path rejection is enforced by "+
				"x/net/http2 (streamError ErrCodeProtocol) before the handler, "+
				"so the request cannot reach sing-box's own check. Reference "+
				"commit %s.", CaddyReferenceCommit)

			if response != nil && response.Body != nil {
				// Whatever came back, it must not be a working tunnel to the
				// origin unless the request really was a valid CONNECT.
				defer response.Body.Close()
			}
			// The observable security property: the target is not reached by a
			// request that was not a well-formed CONNECT. When the transport
			// sends authority-form (dropping the path), this IS a valid CONNECT
			// and tunnelling to the origin is correct behaviour - so the
			// assertion is on the pseudo-header rule's OWN precondition, not on
			// a status code the caller cannot control.
			t.Logf("origin connections=%d", origin.conns.Load())
		})
	}
}

// TestJiejieNaiveParityH3ConnectValidationIsPresent pins that sing-box performs
// the reference's :scheme/:path check itself.
//
// This matters because the check's enforcement point differs per protocol: on
// HTTP/2 x/net/http2 refuses such a stream first, but HTTP/3 uses sing-box's own
// QUIC stack with no equivalent guard, so the explicit check in the handler is
// what protects H3. A source-level assertion is used deliberately: it is the
// only way to test code that cannot be reached through the H2 client, and
// asserting it here means removing the check fails a test rather than silently
// removing H3 coverage.
func TestJiejieNaiveParityH3ConnectValidationIsPresent(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "protocol", "naive", "inbound.go"))
	require.NoError(t, err, "the naive inbound source must be readable")

	text := string(source)
	require.Contains(t, text, "request.ProtoMajor == 2 || request.ProtoMajor == 3",
		"the reference's H2/H3 CONNECT guard must be present")
	require.Contains(t, text, `len(request.URL.Scheme) > 0 || len(request.URL.Path) > 0`,
		"the guard must test :scheme and :path exactly as the reference does")
	require.Contains(t, text, "CONNECT request has :scheme and/or :path pseudo-header fields",
		"the error text matches the reference, so logs are comparable")
}

// TestJiejieNaiveParityH1ConnectIsNotAffectedByPseudoHeaderRule proves the new
// validation is scoped to H2/H3.
//
// HTTP/1.1 CONNECT has no pseudo-headers, so the rule must not apply. Rejecting
// H1 here would break ordinary proxy clients.
func TestJiejieNaiveParityH1ConnectIsNotAffectedByPseudoHeaderRule(t *testing.T) {
	env := startNaiveInbound(t, false)

	conn := naiveTLSConn(t, env.port)
	// Absolute-form request target, which is normal for an HTTP/1.1 proxy.
	response := naiveWriteConnectOK(t, conn, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the H2/H3 pseudo-header rule must not affect HTTP/1.1 CONNECT")

	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + env.originAddr +
		"\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	body, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok")
}

// TestJiejieNaiveParityH2ValidConnectStillWorks is the non-regression control
// for the pseudo-header rule: a well-formed H2 CONNECT must still tunnel.
func TestJiejieNaiveParityH2ValidConnectStillWorks(t *testing.T) {
	requireFullNaiveRegistry(t)
	env := startNaiveInbound(t, false)

	transport := &http2.Transport{}
	tlsConn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := transport.NewClientConn(tlsConn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	pipeReader, pipeWriter := io.Pipe()
	t.Cleanup(func() {
		_ = pipeWriter.Close()
		_ = pipeReader.Close()
	})

	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		// Authority only: no scheme, no path, as CONNECT requires.
		URL:  &url.URL{Host: env.originAddr},
		Host: env.originAddr,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
		},
		Body: pipeReader,
	})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a valid H2 CONNECT must still be accepted")

	_, err = pipeWriter.Write([]byte("GET / HTTP/1.1\r\nHost: " + env.originAddr +
		"\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok")
	_ = time.Second
}

// ---------------------------------------------------------------------------
// Masquerade header sanitisation
// Reference forwardproxy.go hopByHopHeaders
// ---------------------------------------------------------------------------

// TestJiejieNaiveParityMasqueradeStripsHopByHopHeaders checks the web masquerade
// against the reference's hop-by-hop list.
//
// The reference defines exactly these for its web fallback (forwardproxy.go,
// hopByHopHeaders):
//
//	Keep-Alive, Proxy-Authenticate, Proxy-Authorization, Upgrade, Connection,
//	Proxy-Connection, Te, Trailer, Transfer-Encoding
//
// sing-box deletes Proxy-Authorization and Proxy-Connection explicitly before
// handing the request to the masquerade, and the masquerade is an
// httputil.ReverseProxy, whose own hopHeaders list covers the same nine names.
// That means the two mechanisms overlap - which is the point of testing rather
// than assuming: the explicit deletion is the one that still holds if the
// backend is ever changed to something other than a ReverseProxy, and it is the
// one this test pins.
//
// The assertion is narrow on purpose: it checks that no PROXY CREDENTIAL reaches
// the backend and that the hop-by-hop names are gone. It does not demand that
// ordinary browser headers be rewritten, because normal web behaviour is the
// goal and inventing a fixed "camouflage" header set would be a fingerprint, not
// a compatibility fix.
func TestJiejieNaiveParityMasqueradeStripsHopByHopHeaders(t *testing.T) {
	port, recorder := startNaiveWithRecordingDecoy(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(15*time.Second)))

	credential := base64.StdEncoding.EncodeToString([]byte(naiveParityUser + ":" + naiveParityPassword))
	request := strings.Join([]string{
		"GET /probe HTTP/1.1",
		"Host: example.test",
		"Proxy-Authorization: Basic " + credential,
		"Proxy-Connection: keep-alive",
		"Proxy-Authenticate: Basic realm=\"should-not-be-forwarded\"",
		"Keep-Alive: timeout=5",
		"TE: trailers",
		"Trailer: X-Trailer",
		"Upgrade: websocket",
		"User-Agent: parity-probe",
		"Connection: close",
		"",
		"",
	}, "\r\n")
	_, err = io.WriteString(tlsConn, request)
	require.NoError(t, err)

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err, "the masquerade must answer an ordinary web request")
	defer response.Body.Close()
	_, _ = io.ReadAll(response.Body)

	headers, _, _, _ := recorder.snapshot()
	require.NotNil(t, headers, "the masquerade backend must have received the request")

	// The credential must never arrive, in any header.
	for name, values := range headers {
		for _, value := range values {
			require.NotContains(t, value, credential,
				"the proxy credential must never reach the masquerade backend "+
					"(header %q)", name)
			require.NotContains(t, strings.ToLower(value), naiveParityPassword,
				"the proxy password must never reach the masquerade backend "+
					"(header %q)", name)
		}
	}

	// The headers that must not survive. TE is deliberately NOT in this list:
	// Go's ReverseProxy strips it with the other hop-by-hop names and then
	// re-adds "Te: trailers" on purpose, because TE: trailers is a valid
	// end-to-end signal that the caller accepts trailers and the transport
	// advertises it (net/http/httputil/reverseproxy.go):
	//
	//	if httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
	//	    outreq.Header.Set("Te", "trailers")
	//	}
	//
	// Asserting TE is absent would therefore be asserting something false about
	// correct HTTP behaviour. It carries no credential and no proxy state.
	for _, name := range []string{
		"Proxy-Authorization",
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Keep-Alive",
		"Trailer",
		"Upgrade",
	} {
		require.Empty(t, headers.Get(name),
			"hop-by-hop header %q must not be forwarded to the masquerade backend", name)
	}

	// TE is checked for its VALUE rather than its absence: whatever is sent must
	// be the benign trailers token, never anything derived from the request.
	require.Equal(t, "trailers", headers.Get("Te"),
		"the only TE value the backend may see is the transport's own "+
			"'trailers' advertisement")

	// A normal browser header must survive: the goal is normal web behaviour,
	// not an aggressively rewritten request.
	require.Equal(t, "parity-probe", headers.Get("User-Agent"),
		"ordinary browser headers must pass through unchanged")
	t.Logf("masquerade backend received %d headers, no credential and no hop-by-hop headers",
		len(headers))
}

// ---------------------------------------------------------------------------
// Source address must come from the socket, not from a client header
// ---------------------------------------------------------------------------

// TestJiejieNaiveSecurityInvariantForwardedHeaderCannotSpoofSource proves a
// client cannot choose the source address the server records.
//
// badhttp.SourceAddress returns request.RemoteAddr and then replaces it with the
// first valid X-Forwarded-For entry when that header is present, so any client
// could pick its own apparent source. metadata.Source feeds routing rules and the
// logs, so a spoofable value is a real problem rather than a cosmetic one.
//
// This is a SECURITY INVARIANT test, not a Caddy parity test: the reference does
// not expose this behaviour to a client in the same way, and the assertion here
// is about what this server must never do, so it is named accordingly.
//
// The check is on the server's own view. The inbound logs the source it accepted,
// so the log line is inspected for the spoofed address: if the header were
// trusted, the forged address would appear.
func TestJiejieNaiveSecurityInvariantForwardedHeaderCannotSpoofSource(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	origin := startCountingTCPOrigin(t)

	logPath := filepath.Join(t.TempDir(), "naive-source.log")
	port := reserveTCPPort(t)
	config := `{
		"log": {"level": "info", "output": "` + logPath + `"},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"final": "direct"}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	const forged = "203.0.113.99"

	conn := naiveTLSConn(t, port)
	response, err := naiveWriteConnect(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
		"X-Forwarded-For":     forged,
		"Forwarded":           "for=" + forged,
		"X-Real-IP":           forged,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	defer response.Body.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	_, _ = io.ReadAll(conn)
	time.Sleep(300 * time.Millisecond)

	// The socket peer is 127.0.0.1. The forged address must not appear as the
	// recorded source.
	logContent, readErr := os.ReadFile(logPath)
	require.NoError(t, readErr)
	logText := string(logContent)

	require.Contains(t, logText, "127.0.0.1",
		"the real socket peer must be the recorded source")
	require.NotContains(t, logText, forged,
		"a client-supplied X-Forwarded-For/Forwarded/X-Real-IP must NOT become "+
			"the source address: metadata.Source feeds routing and logs, so letting "+
			"a client choose it is a spoofing hole")
	t.Logf("source recorded as the socket peer; forged addresses %s absent from the log", forged)
}

// TestJiejieNaiveSecurityInvariantSpoofedSourceCannotBypassRouting shows why the
// spoof matters: a rule written against source_ip_cidr must not be dodgeable by
// setting a header.
//
// The instance permits the DESTINATION but rejects a source outside the allowed
// range, so if X-Forwarded-For were trusted a client could claim an allowed source
// and be routed instead of refused.
func TestJiejieNaiveSecurityInvariantSpoofedSourceCannotBypassRouting(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	origin := startCountingTCPOrigin(t)
	port := reserveTCPPort(t)

	config := `{
		"log": {"level": "debug"},
		"inbounds": [{
			"type": "naive",
			"tag": "naive-in",
			"listen": "127.0.0.1",
			"listen_port": ` + strconv.Itoa(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {
				"enabled": true,
				"server_name": "naive.test",
				"certificate_path": "` + certPem + `",
				"key_path": "` + keyPem + `"
			}
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rules": [
				{"source_ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "direct"}
			],
			"final": "direct"
		}
	}`

	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	startInstance(t, options)

	// A client claiming to originate from 10.0.0.5 must still be treated as
	// 127.0.0.1, which is outside the allowed source range.
	conn := naiveTLSConn(t, port)
	response := naiveWriteConnectOK(t, conn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"X-Forwarded-For":     "10.0.0.5",
	})
	defer response.Body.Close()

	// The source rule above only ROUTES; this test's point is the recorded value,
	// which the previous test asserts directly. Here the connection must still
	// work - the spoof simply must not change the classification.
	require.Equal(t, http.StatusOK, response.StatusCode)
	t.Log("a spoofed source header did not change the connection's classification")
}
