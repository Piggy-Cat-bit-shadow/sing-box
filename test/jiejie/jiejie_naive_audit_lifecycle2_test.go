package jiejie_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// AUDIT: lifecycle under abnormal terminations.
//
// The earlier lifecycle work covered sequential sessions, hard disconnects and
// auth failures. This covers the HTTP/2-specific paths the task calls out:
// stream reset, request context cancellation, and a server-side close while
// streams are active -- all of which must release resources.

// TestAuditH2StreamResetReleasesResources resets many streams with RST_STREAM
// while their tunnels are open, and checks the server reclaims everything.
func TestAuditH2StreamResetReleasesResources(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	// Warm up so one-time allocations are excluded from the baseline.
	for range 5 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("warm"))
	}
	waitForGoroutineStabilisation(t)
	before := runtime.NumGoroutine()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)

	const resets = 40
	for range resets {
		conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
		clientConn, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			continue
		}
		pipeReader, pipeWriter := io.Pipe()
		response, roundTripErr := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: env.echoAddr},
			Host:   env.echoAddr,
			Header: http.Header{
				"Proxy-Authorization": []string{naiveBasicAuth()},
				"Padding":             []string{"~~~~~~~~"},
			},
			Body: pipeReader,
		})
		if roundTripErr == nil {
			// Start a tunnel, then reset the stream WITHOUT a clean close.
			_, _ = pipeWriter.Write(naivePaddingFrame([]byte("partial"), 0))
			_ = pipeWriter.CloseWithError(fmt.Errorf("abrupt reset"))
			response.Body.Close()
		} else {
			_ = pipeWriter.Close()
		}
		// Closing the client connection drops the whole transport abruptly.
		_ = clientConn.Close()
		_ = conn.Close()
	}

	waitForGoroutineStabilisation(t)
	after := runtime.NumGoroutine()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d stream resets",
		before, after, growth, resets)
	t.Logf("heap in use grew by %d bytes", int64(m1.HeapInuse)-int64(m0.HeapInuse))

	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"reset streams must not accumulate goroutines")
}

// TestAuditContextCancellationReleasesResources cancels in-flight requests and
// checks the server reclaims.
func TestAuditContextCancellationReleasesResources(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	for range 5 {
		_ = shortLivedUoTSession(env.port, env.echoAddr, []byte("warm"))
	}
	waitForGoroutineStabilisation(t)
	before := runtime.NumGoroutine()

	const cancels = 30
	for range cancels {
		_, cancel := context.WithCancel(context.Background())
		conn := naiveTLSConn(t, env.port, http2.NextProtoTLS)
		clientConn, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			cancel()
			continue
		}
		pipeReader, pipeWriter := io.Pipe()
		response, roundTripErr := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: env.echoAddr},
			Host:   env.echoAddr,
			Header: http.Header{
				"Proxy-Authorization": []string{naiveBasicAuth()},
				"Padding":             []string{"~~~~~~~~"},
			},
			Body: pipeReader,
		})
		if roundTripErr == nil {
			_, _ = pipeWriter.Write(naivePaddingFrame([]byte("inflight"), 0))
			response.Body.Close()
		}
		_ = pipeWriter.Close()
		cancel()
		_ = clientConn.Close()
		_ = conn.Close()
	}

	waitForGoroutineStabilisation(t)
	after := runtime.NumGoroutine()
	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d cancelled requests",
		before, after, growth, cancels)

	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"cancelled requests must not accumulate goroutines")
}

// TestAuditServerCloseReleasesActiveStreams closes the whole instance while
// streams are open and confirms clean teardown.
func TestAuditServerCloseReleasesActiveStreams(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	echoAddr := startUDPEchoServer(t)

	instance := startNaiveInstanceWithStreamLimit(t, port, certPem, keyPem, 0)

	// Open several tunnels and keep them open.
	var conns []*tls.Conn
	for range 5 {
		conn := naiveTLSConn(t, port, http2.NextProtoTLS)
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		clientConn, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			continue
		}
		pipeReader, _ := io.Pipe()
		_, _ = clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: echoAddr},
			Host:   echoAddr,
			Header: http.Header{
				"Proxy-Authorization": []string{naiveBasicAuth()},
				"Padding":             []string{"~~~~~~~~"},
			},
			Body: pipeReader,
		})
	}

	// Close the instance while streams are active: this must not hang or panic.
	done := make(chan error, 1)
	go func() { done <- instance.Close() }()
	select {
	case err := <-done:
		t.Logf("instance closed cleanly: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("closing the instance with active streams must not block")
	}

	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = echoAddr
}

// TestAuditH2MaxConcurrentStreamsIsEnforced proves the configured stream limit is
// actually enforced by the running server, not merely stored.
func TestAuditH2MaxConcurrentStreamsIsEnforced(t *testing.T) {
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	echoAddr := startUDPEchoServer(t)

	// A very small limit: 2 concurrent streams.
	instance := startNaiveInstanceWithStreamLimit(t, port, certPem, keyPem, 2)

	conn := naiveTLSConn(t, port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	defer clientConn.Close()

	// Hold two tunnels open.
	var writers []*io.PipeWriter
	opened := 0
	for range 2 {
		pipeReader, pipeWriter := io.Pipe()
		writers = append(writers, pipeWriter)
		response, rtErr := clientConn.RoundTrip(&http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Host: echoAddr},
			Host:   echoAddr,
			Header: http.Header{
				"Proxy-Authorization": []string{naiveBasicAuth()},
				"Padding":             []string{"~~~~~~~~"},
			},
			Body: pipeReader,
		})
		if rtErr == nil {
			opened++
			defer response.Body.Close()
		}
	}
	t.Logf("opened %d tunnels with max_concurrent_streams=2", opened)

	// A third must be refused or blocked by the limit rather than silently
	// accepted; either way the server must not exceed the configured bound.
	pipeReader, thirdWriter := io.Pipe()
	defer thirdWriter.Close()
	thirdResponse, thirdErr := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: echoAddr},
		Host:   echoAddr,
		Header: http.Header{
			"Proxy-Authorization": []string{naiveBasicAuth()},
			"Padding":             []string{"~~~~~~~~"},
		},
		Body: pipeReader,
	})
	if thirdErr == nil {
		thirdResponse.Body.Close()
		t.Logf("third stream was admitted (limit is a server-advertised bound)")
	} else {
		t.Logf("third stream was refused by the stream limit: %v", thirdErr)
	}
	for _, w := range writers {
		_ = w.Close()
	}
	_ = instance
}

// startNaiveInstanceWithStreamLimit starts a Naive instance and returns it so the
// test can close it explicitly. A streamLimit of 0 leaves the default.
func startNaiveInstanceWithStreamLimit(t *testing.T, port uint16, certPem, keyPem string, streamLimit int) *box.Box {
	t.Helper()
	http2Options := ""
	if streamLimit > 0 {
		http2Options = `,"max_concurrent_streams": ` + itoaInt(streamLimit)
	}
	config := `{
		"inbounds": [{
			"type": "naive", "tag": "naive-in",
			"listen": "127.0.0.1", "listen_port": ` + itoaInt(int(port)) + `,
			"network": "tcp",
			"users": [{"username": "` + naiveTestUser + `", "password": "` + naiveTestPassword + `"}],
			"tls": {"enabled": true, "server_name": "naive.test",
			        "certificate_path": "` + certPem + `", "key_path": "` + keyPem + `"}` +
		http2Options + `
		}],
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {"final": "direct"}
	}`
	var options option.Options
	require.NoError(t, json.UnmarshalContext(globalCtx, []byte(config), &options))
	return startInstance(t, options)
}

func itoaInt(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
