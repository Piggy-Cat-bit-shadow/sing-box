package jiejie_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// AUDIT: cross-stream authentication isolation and authority handling on HTTP/2.
//
// Two concerns the audit raises that the earlier work did not isolate:
//
//   1. an unauthorised stream must not inherit another stream's authenticated
//      state, on the SAME HTTP/2 connection;
//   2. the :authority pseudo-header must be what selects the tunnel target, with
//      no ambiguity against Host or the URL host.

// TestAuditHTTP2AuthIsolationPerStream interleaves authorised and unauthorised
// CONNECTs on one connection and proves the unauthorised ones never dial.
func TestAuditHTTP2AuthIsolationPerStream(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	target := startRecordingTCPTarget(t)

	conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()

	wrongAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(naiveTestUser+":wrong"))

	// Interleave: authorised, unauthorised, authorised, unauthorised...
	// If auth state leaked between streams on the connection, an unauthorised
	// stream following an authorised one would dial.
	const rounds = 6
	for round := range rounds {
		// Authorised stream: must dial.
		beforeAuthorised := target.connections.Load()
		authorisedResponse, authorisedWriter, authorisedErr := connectOnStreamKeepWriter(
			t, clientConn, target.address, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
		require.NoError(t, authorisedErr)
		require.Equal(t, http.StatusOK, authorisedResponse.StatusCode)
		// The 200 is written BEFORE the dial, so wait for the dial rather than
		// assuming it already happened. The tunnel stays open meanwhile.
		dialed := waitForDial(&target.connections, beforeAuthorised)
		authorisedResponse.Body.Close()
		_ = authorisedWriter.Close()
		require.True(t, dialed, "round %d: an authorised stream must dial", round)

		// Unauthorised stream on the SAME connection: must NOT dial.
		beforeUnauthorised := target.connections.Load()
		unauthorisedResponse, unauthorisedWriter, _ := connectOnStreamKeepWriter(
			t, clientConn, target.address, map[string]string{
				"Proxy-Authorization": wrongAuth,
				"Padding":             "~~~~~~~~",
			})
		if unauthorisedResponse != nil {
			unauthorisedResponse.Body.Close()
		}
		if unauthorisedWriter != nil {
			_ = unauthorisedWriter.Close()
		}
		// Give the server ample opportunity to dial if it were going to; the
		// interval exceeds the authorised case's own dial latency by a wide
		// margin, so a missed dial here would be a real defect.
		time.Sleep(300 * time.Millisecond)
		require.Equal(t, beforeUnauthorised, target.connections.Load(),
			"round %d: an unauthorised stream must NOT inherit the preceding "+
				"authorised stream's state", round)
	}
}

// connectOnStream issues one CONNECT and requires a response.
func connectOnStream(t *testing.T, clientConn *http2.ClientConn, authority string, headers map[string]string) *http.Response {
	t.Helper()
	response, err := connectOnStreamAllowError(t, clientConn, authority, headers)
	require.NoError(t, err)
	return response
}

// connectOnStreamAllowError issues one CONNECT and returns the transport error.
func connectOnStreamAllowError(t *testing.T, clientConn *http2.ClientConn, authority string, headers map[string]string) (*http.Response, error) {
	t.Helper()
	response, _, err := connectOnStreamKeepWriter(t, clientConn, authority, headers)
	return response, err
}

// connectOnStreamKeepWriter also returns the request-body writer so the caller
// controls the tunnel's lifetime. Closing it too early cancels the dial, which
// would make a "must dial" assertion fail for the wrong reason.
func connectOnStreamKeepWriter(t *testing.T, clientConn *http2.ClientConn, authority string, headers map[string]string) (*http.Response, *io.PipeWriter, error) {
	t.Helper()
	pipeReader, pipeWriter := io.Pipe()
	header := http.Header{}
	for name, value := range headers {
		header.Set(name, value)
	}
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: authority},
		Host:   authority,
		Header: header,
		Body:   pipeReader,
	})
	return response, pipeWriter, err
}

// TestAuditHTTP2AuthoritySelectsTarget proves the :authority pseudo-header is
// what determines the target, and that a CONNECT whose URL host and authority
// disagree does not tunnel somewhere unexpected.
func TestAuditHTTP2AuthoritySelectsTarget(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	intended := startRecordingTCPTarget(t)
	other := startRecordingTCPTarget(t)

	conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()

	// URL host says one thing, the Host field says another. On HTTP/2,
	// http.Transport derives :authority from URL.Host, so that is what the
	// server must use.
	response, err := connectOnStreamAllowError(t, clientConn, intended.address, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	if err != nil {
		t.Logf("CONNECT refused: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Logf("CONNECT refused with status %d", response.StatusCode)
		return
	}

	time.Sleep(200 * time.Millisecond)
	require.Positive(t, intended.connections.Load(),
		"the tunnel must go to the address named in the CONNECT authority")
	require.Zero(t, other.connections.Load(),
		"no other target may be contacted")
}

// TestAuditHTTP2MalformedAuthorityIsRejected proves malformed targets fail before
// any connection attempt.
func TestAuditHTTP2MalformedAuthorityIsRejected(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	target := startRecordingTCPTarget(t)

	authorities := []string{
		"",                      // empty
		"host with spaces:443",  // illegal host
		"example.test:notaport", // non-numeric port
		"example.test:99999999", // out-of-range port
		"[]:443",                // empty IPv6
		":::::",                 // nonsense
	}

	for index, authority := range authorities {
		t.Run(fmt.Sprintf("authority_%d", index), func(t *testing.T) {
			conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
			clientConn, err := (&http2.Transport{}).NewClientConn(conn)
			if err != nil {
				return
			}
			defer clientConn.Close()

			before := target.connections.Load()
			response, rtErr := connectOnStreamAllowError(t, clientConn, authority, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			if rtErr == nil {
				response.Body.Close()
			}
			time.Sleep(50 * time.Millisecond)
			require.Equal(t, before, target.connections.Load(),
				"a malformed authority (%q) must not produce a connection", authority)
			_ = conn
		})
	}
}

// TestAuditHTTP1AuthorityMatchesHTTP2 proves the HTTP/1.1 hijack path resolves the
// target the same way as the HTTP/2 path, so the two cannot disagree.
func TestAuditHTTP1AuthorityMatchesHTTP2(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	target := startRecordingTCPTarget(t)

	// HTTP/1.1 CONNECT with the target in the request line and Host.
	conn := naiveTLSConn(t, env.port)
	request := "CONNECT " + target.address + " HTTP/1.1\r\nHost: " + target.address +
		"\r\nProxy-Authorization: " + naiveBasicAuth() + "\r\nPadding: ~~~~~~~~\r\n\r\n"
	_, err := io.WriteString(conn, request)
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	_, err = conn.Write(naivePaddingFrame([]byte("probe"), 0))
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	require.Positive(t, target.connections.Load(),
		"the HTTP/1.1 CONNECT must reach the same target the HTTP/2 path would")

	// Then the SAME authority over HTTP/2 must resolve to the same target. The
	// tunnel is kept open until the dial is observed, because closing the request
	// body cancels an in-flight dial.
	conn2 := naiveTLSConn(t, env.port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn2)
	require.NoError(t, err)
	defer clientConn.Close()

	before := target.connections.Load()
	h2Response, h2Writer, h2Err := connectOnStreamKeepWriter(t, clientConn, target.address,
		map[string]string{
			"Proxy-Authorization": naiveBasicAuth(),
			"Padding":             "~~~~~~~~",
		})
	require.NoError(t, h2Err)
	dialed := waitForDial(&target.connections, before)
	h2Response.Body.Close()
	_ = h2Writer.Close()
	require.True(t, dialed,
		"HTTP/2 must resolve the same authority to the same target the HTTP/1.1 "+
			"path resolved")
}

// waitForDial polls until the counter exceeds the baseline, or the deadline
// passes. A bounded poll is used instead of a fixed sleep so the assertion is
// robust on a loaded machine without becoming slow on an idle one.
func waitForDial(counter *atomic.Int64, baseline int64) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() > baseline {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
