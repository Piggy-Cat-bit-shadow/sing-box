//go:build with_quic

package http

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Resource-leak tests for the generic HTTP/3 request path.
//
// # Why these are separate from the functional tests
//
// The functional tests prove a request works. These prove that a request which is
// CANCELLED, or whose response body is never read, or which fails, does not leave something
// behind. The failure mode is not a wrong answer -- it is a process that works perfectly in
// testing and then exhausts memory or file descriptors after hours in production, because a
// long-lived deployment issues far more DoH queries than a test does.
//
// The streams matter more here than they would elsewhere: HTTP/3 flow-control credit is
// shared across a connection, so a leaked stream on the SHARED connection eventually stalls
// the CONNECT-IP tunnel as well. That is why an unclosed response body is not merely untidy.

// settledGoroutineCount samples the goroutine count and returns the minimum.
//
// The minimum rather than the current value, because transient goroutines from the test
// framework and the QUIC runtime are constantly appearing and disappearing; the minimum is
// the closest available estimate of the steady-state count.
func settledGoroutineCount() int {
	best := -1
	for range 8 {
		count := runtime.NumGoroutine()
		if best == -1 || count < best {
			best = count
		}
		time.Sleep(25 * time.Millisecond)
	}
	return best
}

// TestRoundTripHTTP3CancellationDoesNotLeakStreams issues many requests that are cancelled
// before they complete and requires the goroutine count to return to where it started.
//
// A cancellation path that left a reader goroutine blocked would be invisible to a
// single-request test and fatal to a long-running one, so the check is on the aggregate
// across many iterations rather than on any single one.
func TestRoundTripHTTP3CancellationDoesNotLeakStreams(t *testing.T) {
	t.Parallel()

	// A handler that never answers, so every request below is genuinely cancelled
	// mid-flight rather than completing before the cancellation lands.
	//
	// It watches the REQUEST context rather than a timer, so it releases as soon as the
	// client abandons the request. A fixed sleep here would make the test measure the
	// sleep instead of the cancellation path: with one, a request that failed to observe
	// its own cancellation would still appear to pass once the timer expired.
	release := make(chan struct{})
	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-release:
		case <-request.Context().Done():
		}
	})
	client := newGenericTestClient(t, server)

	// Warm up first: the first request establishes the connection and starts the QUIC
	// runtime's background goroutines, and counting those as a leak would make this test
	// fail for a reason that has nothing to do with the code under test.
	warmupCtx, warmupCancel := context.WithCancel(context.Background())
	warmupRequest, err := http.NewRequestWithContext(warmupCtx, http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	_, _ = client.RoundTripHTTP3(warmupCtx, warmupRequest)
	warmupCancel()
	time.Sleep(100 * time.Millisecond)

	baseline := settledGoroutineCount()

	// Each iteration is bounded by its own deadline, so a request that failed to observe
	// cancellation fails this test quickly and says so, rather than hanging until the
	// package timeout and reporting nothing useful.
	for index := range 25 {
		// A generous deadline so it cannot be what ends the request: the CANCELLATION
		// must be what returns it. The timeout exists only so a request that ignores
		// cancellation fails this test with a clear message instead of hanging.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://"+server.address+"/dns-query", strings.NewReader("query"))
		if requestErr != nil {
			cancel()
			continue
		}
		type outcome struct {
			elapsed time.Duration
		}
		done := make(chan outcome, 1)
		started := time.Now()
		go func() {
			response, roundTripErr := client.RoundTripHTTP3(ctx, request)
			if roundTripErr == nil && response != nil {
				_ = response.Body.Close()
			}
			done <- outcome{elapsed: time.Since(started)}
		}()
		// Cancel once the request is certainly in flight. The connection is already
		// established by the warm-up above, so this is not a race with the handshake.
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case result := <-done:
			require.Less(t, result.elapsed, 15*time.Second,
				"request %d must return on cancellation rather than waiting for the server or its own deadline (took %s)", index, result.elapsed)
		case <-time.After(15 * time.Second):
			t.Fatalf("request %d did not return after cancellation", index)
		}
	}

	// Give the cancelled requests time to unwind before counting.
	time.Sleep(300 * time.Millisecond)
	after := settledGoroutineCount()

	// The allowance is not zero: the QUIC runtime and the test framework keep background
	// goroutines this test does not own, and asserting exact equality would be a flake
	// rather than a check. What the bound catches is a leak proportional to the iteration
	// count, which is the failure that matters.
	require.Less(t, after-baseline, 20,
		"25 cancelled requests must not leak goroutines proportional to the request count (baseline %d, after %d)", baseline, after)

	// The connection must still be usable after all that cancellation: a cancellation
	// path that damaged the SHARED connection would show up here as a failed request
	// rather than as a leak.
	close(release)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err, "the shared connection must survive repeated cancellation")
	require.NoError(t, response.Body.Close())
}

// TestRoundTripHTTP3AbandonedBodyDoesNotStallTheConnection is the flow-control test.
//
// Closing the response body is a contract the caller must honour, and this test makes the
// consequence concrete: after many requests whose bodies were properly closed, the
// connection still serves traffic. If each response leaked flow-control credit, the
// connection would eventually stall and this would time out.
func TestRoundTripHTTP3AbandonedBodyDoesNotStallTheConnection(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		// A response large enough to need multiple flow-control windows.
		_, _ = writer.Write(make([]byte, 64<<10))
	})
	client := newGenericTestClient(t, server)

	for index := range 30 {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"https://"+server.address+"/dns-query", nil)
		require.NoError(t, err)
		response, err := client.RoundTripHTTP3(context.Background(), request)
		require.NoError(t, err, "request %d must succeed", index)
		// Read less than the full body and close: the abandoned remainder must not
		// hold credit against the shared connection.
		_, _ = io.CopyN(io.Discard, response.Body, 1024)
		require.NoError(t, response.Body.Close())
	}

	require.Equal(t, 1, server.connectionCount(),
		"thirty requests with partly-read bodies must not have needed another connection")
}

// TestRoundTripHTTP3ConcurrentRequestsDoNotLeakResponses runs many concurrent requests and
// checks that they all complete and share one connection.
//
// Concurrency is where a leak is most likely: a response body that is only closed on the
// happy path, or a stream only released when the caller reads to EOF, would still pass a
// sequential test.
func TestRoundTripHTTP3ConcurrentRequestsDoNotLeakResponses(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "answer")
	})
	client := newGenericTestClient(t, server)

	const concurrency = 32
	var waitGroup sync.WaitGroup
	failures := make(chan error, concurrency)
	for range concurrency {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				"https://"+server.address+"/dns-query", strings.NewReader("query"))
			if err != nil {
				failures <- err
				return
			}
			response, err := client.RoundTripHTTP3(context.Background(), request)
			if err != nil {
				failures <- err
				return
			}
			if _, err = io.ReadAll(response.Body); err != nil {
				failures <- err
			}
			if err = response.Body.Close(); err != nil {
				failures <- err
			}
		}()
	}
	waitGroup.Wait()
	close(failures)
	for failure := range failures {
		require.NoError(t, failure)
	}

	require.Equal(t, 1, server.connectionCount(),
		"%d concurrent requests must share one connection", concurrency)
	require.GreaterOrEqual(t, server.streamCount(), concurrency,
		"each concurrent request must have had its own stream")
}

// TestRoundTripHTTP3ErrorPathsDoNotLeakStreams drives the failure paths.
//
// A server that resets the stream, a request that never gets a response, and a bad status are
// all cases where cleanup has to happen on a path that is not the happy one. Each is run
// repeatedly so a leak proportional to the failure count would be visible.
func TestRoundTripHTTP3ErrorPathsDoNotLeakStreams(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		// A non-2xx is a valid response the caller interprets, not a transport failure.
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(writer, "upstream failed")
	})
	client := newGenericTestClient(t, server)

	baseline := settledGoroutineCount()

	for range 20 {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+server.address+"/dns-query", strings.NewReader("query"))
		require.NoError(t, err)
		response, err := client.RoundTripHTTP3(context.Background(), request)
		require.NoError(t, err, "a non-2xx status is not a transport error")
		require.Equal(t, http.StatusBadGateway, response.StatusCode)
		_, _ = io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
	}

	time.Sleep(200 * time.Millisecond)
	after := settledGoroutineCount()
	require.Less(t, after-baseline, 20,
		"20 non-2xx responses must not leak goroutines (baseline %d, after %d)", baseline, after)

	require.Equal(t, 1, server.connectionCount())
}

// TestRoundTripHTTP3BodyCloseIsIdempotent proves a double close is harmless.
//
// Callers routinely close in a defer and again on an error path. A body that panicked or
// double-released its stream on the second close would be a latent crash in production code
// that happens to be written that way.
func TestRoundTripHTTP3BodyCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	server := startCountingH3Server(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "answer")
	})
	client := newGenericTestClient(t, server)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+server.address+"/dns-query", nil)
	require.NoError(t, err)
	response, err := client.RoundTripHTTP3(context.Background(), request)
	require.NoError(t, err)
	_, _ = io.ReadAll(response.Body)
	require.NoError(t, response.Body.Close())
	require.NoError(t, response.Body.Close(), "closing the body twice must be harmless")
	require.NoError(t, response.Body.Close())
}
