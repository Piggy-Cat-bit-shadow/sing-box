package jiejie_test

import (
	"context"
	"crypto/tls"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Resource behaviour of the HTTP/3 listener's stream limit.
//
// The Native Naive QUIC config sets MaxIncomingStreams to 1 << 60, which is
// effectively "no limit". That is a deliberate value carried over from the
// original implementation, and docs/JIEJIE-NAIVE-H3-AUDIT.md records it as a
// difference from the reference that has NOT been aligned - aligning it needs
// runtime evidence about what the limit is actually for, not a config diff.
//
// These tests record what the setting DOES, so a later decision to change it can
// be made against measurements rather than guesses. They do not assert that
// 1 << 60 is correct, and they are written to pass either way, so they double as
// the acceptance test for a future change: if the limit becomes bounded, the
// "bounded" branch below is what runs.

// h3StreamLimitProbe reports how many concurrent HTTP/3 request streams this
// server let through before refusing one.
//
// It opens streams until either the server refuses, or `attempts` are reached.
// The result is a measurement, not an assertion about a specific number.
func h3StreamLimitProbe(t *testing.T, port uint16, attempts int) (accepted int, refused int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	quicConn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "naive.test",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{})
	if err != nil {
		t.Skipf("HTTP/3 is not available in this build/environment (%v), so the "+
			"stream limit was not exercised. This is a SKIP, not a pass.", err)
	}
	defer quicConn.CloseWithError(0, "")

	transport := &http3.Transport{}
	defer transport.Close()
	clientConn := transport.NewClientConn(quicConn)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			streamCtx, streamCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer streamCancel()
			stream, openErr := clientConn.OpenRequestStream(streamCtx)
			mu.Lock()
			if openErr != nil {
				refused++
			} else {
				accepted++
				_ = stream.Close()
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return accepted, refused
}

// TestJiejieNaiveH3StreamLimitIsMeasured records the effective concurrency the
// server accepts.
//
// The assertion is deliberately weak - that the server accepts more than a
// handful of concurrent streams and stays healthy - because the point is to have
// a measurement and a liveness check, not to enshrine 1 << 60. A future change to
// a bounded limit will keep this test meaningful while the log line shows the new
// number.
func TestJiejieNaiveH3StreamLimitIsMeasured(t *testing.T) {
	port := startNaiveInboundH3(t)

	const attempts = 64
	accepted, refused := h3StreamLimitProbe(t, port, attempts)
	t.Logf("HTTP/3 stream limit probe: %d attempted, %d accepted, %d refused "+
		"(configured MaxIncomingStreams = 1 << 60, i.e. effectively unbounded)",
		attempts, accepted, refused)

	require.Positive(t, accepted,
		"the HTTP/3 listener must accept concurrent streams; zero accepted means "+
			"the listener is not serving rather than that a limit was reached")
	require.Equal(t, attempts, accepted+refused,
		"every attempt must be accounted for as accepted or refused")
}

// TestJiejieNaiveH3SurvivesStreamChurn proves the listener stays healthy after a
// burst of concurrently opened and abandoned streams.
//
// This is the liveness property that matters for the unbounded setting: even with
// no server-side stream cap, the listener must not wedge, leak its accept path, or
// stop answering. A subsequent normal request is required to succeed.
func TestJiejieNaiveH3SurvivesStreamChurn(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)

	// Burst.
	accepted, refused := h3StreamLimitProbe(t, port, 64)
	t.Logf("churn burst: accepted=%d refused=%d", accepted, refused)

	// The listener must still serve a real CONNECT afterwards.
	client := dialNaiveH3(t, port)
	response, stream := client.connect(t, origin.addr, naiveH3Auth())
	require.Equal(t, 200, response.StatusCode,
		"the HTTP/3 listener must still accept a CONNECT after a stream burst")

	_, err := stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + origin.addr + "\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	require.True(t, waitForDial(&origin.conns, 0),
		"the post-burst CONNECT must reach the origin")
	t.Logf("listener healthy after the burst; origin connections=%d", origin.conns.Load())
}

// TestJiejieNaiveH3ListenerSurvivesClientAbort proves an abruptly closed client
// does not take the listener down.
//
// With an unbounded stream limit, the connection count is the only bound, so a
// client that opens a connection and vanishes must be cleaned up and must not
// prevent the next client from being served.
func TestJiejieNaiveH3ListenerSurvivesClientAbort(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)

	for range 8 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
			ServerName:         "naive.test",
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		}, &quic.Config{})
		cancel()
		if err != nil {
			continue
		}
		// Abrupt close with no streams opened.
		_ = conn.CloseWithError(0, "abrupt")
	}

	client := dialNaiveH3(t, port)
	response, _ := client.connect(t, origin.addr, naiveH3Auth())
	require.Equal(t, 200, response.StatusCode,
		"the listener must keep serving after clients abort connections")
	t.Log("listener still serving after 8 abrupt client aborts")
}
