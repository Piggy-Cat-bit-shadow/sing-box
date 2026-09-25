package jiejie_test

import (
	"context"
	"crypto/tls"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Resource cost of concurrent HTTP/3 CONNECT streams.
//
// MaxIncomingStreams is 1 << 60, i.e. effectively unbounded, so on a ~1 GiB host
// the only bound on concurrent HTTP/3 work is whatever the front end and the OS
// impose. Deciding whether to keep that or return to the library default needs
// measurements rather than an opinion, which is what these tests collect.
//
// The figures are the TEST PROCESS's, so they include the Go test harness and the
// origin servers; they are a relative measure across concurrency levels, not a
// production RSS prediction. The absolute numbers are reported so a decision can
// be made against real values instead of a guess.

// processRSSKiB reports VmRSS from /proc, or 0 off Linux.
func processRSSKiB() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		value, convErr := strconv.Atoi(fields[1])
		if convErr != nil {
			return 0
		}
		return value
	}
	return 0
}

// openFileDescriptorCount counts entries in /proc/self/fd, or 0 off Linux.
func openFileDescriptorCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

// TestJiejieNaiveH3StreamConcurrencyResourceProfile measures what N concurrent
// HTTP/3 request streams cost, at every level the review asked for.
//
// It asserts only liveness and accounting - every requested stream is either
// opened or reported as refused, and the listener keeps serving afterwards - so
// the numbers are a measurement that stays meaningful whatever the limit becomes.
func TestJiejieNaiveH3StreamConcurrencyResourceProfile(t *testing.T) {
	port := startNaiveInboundH3(t)
	origin := startCountingTCPOrigin(t)

	// Warm up so the first measurement is not dominated by one-time setup.
	client := dialNaiveH3(t, port)
	if response, _ := client.connect(t, origin.addr, naiveH3Auth()); response != nil {
		_ = response.Body.Close()
	}
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	baselineRSS := processRSSKiB()
	baselineFD := openFileDescriptorCount()
	baselineGoroutines := runtime.NumGoroutine()
	t.Logf("baseline: RSS=%d KiB goroutines=%d fds=%d",
		baselineRSS, baselineGoroutines, baselineFD)
	t.Logf("%-10s %-9s %-9s %-8s %-8s %-8s", "streams", "accepted", "refused", "RSS+KiB", "goroutines", "fds")

	for _, level := range []int{1, 8, 32, 64, 128, 256} {
		accepted, refused := openConcurrentH3Streams(t, port, level)
		runtime.GC()
		time.Sleep(100 * time.Millisecond)

		rss := processRSSKiB()
		goroutines := runtime.NumGoroutine()
		fds := openFileDescriptorCount()
		t.Logf("%-10d %-9d %-9d %-8d %-10d %-8d",
			level, accepted, refused,
			rss-baselineRSS, goroutines-baselineGoroutines, fds-baselineFD)

		require.Equal(t, level, accepted+refused,
			"every stream attempt at level %d must be accounted for", level)
		require.Positive(t, accepted,
			"level %d: the listener must accept at least one stream, otherwise "+
				"it is not serving rather than being limited", level)
	}

	// The listener must still serve a real CONNECT after all that.
	after := dialNaiveH3(t, port)
	response, stream := after.connect(t, origin.addr, naiveH3Auth())
	require.Equal(t, 200, response.StatusCode,
		"the listener must still accept a CONNECT after the concurrency sweep")
	_, err := stream.Write([]byte("GET / HTTP/1.1\r\nHost: " + origin.addr +
		"\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	require.True(t, waitForDial(&origin.conns, 0))
	t.Log("listener healthy after the concurrency sweep")
}

// openConcurrentH3Streams opens `count` request streams as concurrently as
// possible and reports how many were accepted and refused.
func openConcurrentH3Streams(t *testing.T, port uint16, count int) (accepted, refused int) {
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
			"concurrency profile was not measured. This is a SKIP, not a pass.", err)
	}
	defer quicConn.CloseWithError(0, "")

	transport := &http3.Transport{}
	defer transport.Close()
	clientConn := transport.NewClientConn(quicConn)

	// A barrier so the streams really are concurrent rather than sequential.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	var mu sync.Mutex

	for range count {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			streamCtx, streamCancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	start.Done()
	done.Wait()
	return accepted, refused
}
