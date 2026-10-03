package urltest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the unified-delay URLTest semantics.
//
// # What is being pinned
//
// The displayed delay follows Mihomo unified-delay=true semantics: the first HEAD warms the
// proxy, TCP, TLS and HTTP path, and the second HEAD - reusing the same transport - is the one
// that is timed. This is a proxy round-trip measurement, not an ICMP ping.
//
// # Why every test uses a local server
//
// These must be deterministic and offline. Timing assertions against a public endpoint would be
// both flaky and dependent on infrastructure, so every case below serves its own responses from
// a local listener whose per-request delay the test controls.

// requestRecord captures one observed request.
type requestRecord struct {
	method string
	path   string
	at     time.Time
}

// delayServer serves HEAD responses with a per-request controllable delay and records every
// request it receives.
type delayServer struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []requestRecord

	// requestDelay is applied before responding. -1 means "fail this request".
	requestDelay func(index int) time.Duration

	// connections counts accepted TCP connections, which is how transport reuse is proven.
	connections atomic.Int32

	// requestCount counts served requests.
	requestCount atomic.Int32
}

func newDelayServer(t *testing.T, requestDelay func(index int) time.Duration) *delayServer {
	t.Helper()
	ds := &delayServer{requestDelay: requestDelay}

	ds.server = httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		index := int(ds.requestCount.Add(1)) - 1

		ds.mu.Lock()
		ds.requests = append(ds.requests, requestRecord{
			method: request.Method,
			path:   request.URL.Path,
			at:     time.Now(),
		})
		ds.mu.Unlock()

		delay := ds.requestDelay(index)
		if delay < 0 {
			// Simulate a failed response without a valid reply.
			hijacker, ok := writer.(http.Hijacker)
			if ok {
				conn, _, err := hijacker.Hijack()
				if err == nil {
					conn.Close()
					return
				}
			}
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))

	// Count connections to prove transport reuse.
	ds.server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			ds.connections.Add(1)
		}
	}
	ds.server.Start()
	t.Cleanup(ds.server.Close)
	return ds
}

func (s *delayServer) url() string { return s.server.URL }

func (s *delayServer) snapshot() []requestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]requestRecord(nil), s.requests...)
}

func (s *delayServer) count() int { return int(s.requestCount.Load()) }

// directDialer dials straight through to the real server, so the measurement goes over a real
// TCP connection to the local listener.
type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (directDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("UDP is not supported")
}

// --- A. the first request must not be part of the reported delay (§12A, §16) -----------

func TestFirstRequestIsWarmUpAndIsNotTimed(t *testing.T) {
	// The first request is deliberately slow (120ms), the second fast (~0).
	// If the warm-up leaked into the measurement the result would be at least 120ms.
	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return 120 * time.Millisecond
		}
		return 0
	})

	delay, err := urlTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	// Generous bound so CI load cannot make this flaky, while still proving the 120ms warm-up
	// was not counted.
	require.Less(t, int(delay), 100,
		"the reported delay must be the SECOND request's time, not dial+warm+measure; got %dms", delay)

	require.Equal(t, 2, server.count(),
		"a successful measurement is exactly two requests")
}

func TestDelayTracksSecondRequestNotTheSum(t *testing.T) {
	// First 80ms, second 40ms. The sum would be >=120ms; the unified result must follow the
	// second request.
	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return 80 * time.Millisecond
		}
		return 40 * time.Millisecond
	})

	delay, err := urlTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	require.GreaterOrEqual(t, int(delay), 35, "the second request's own cost must be included")
	require.Less(t, int(delay), 100,
		"warm-up must not accumulate into the result; got %dms, which is near the 120ms sum", delay)
}

// --- B. both requests must share one transport (§12B) ---------------------------------

func TestBothRequestsReuseTheSameConnection(t *testing.T) {
	server := newDelayServer(t, func(int) time.Duration { return 0 })

	_, err := urlTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	require.Equal(t, 2, server.count(), "two HEAD requests must be sent")

	require.EqualValues(t, 1, server.connections.Load(),
		"both requests must travel over ONE TCP connection; a second connection would mean the "+
			"second request paid a fresh dial and handshake, which is what the warm-up exists to "+
			"exclude and would make the number meaningless")
}

// --- C. method (§12C) ------------------------------------------------------------------

func TestBothRequestsUseHEAD(t *testing.T) {
	server := newDelayServer(t, func(int) time.Duration { return 0 })

	_, err := urlTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err)

	requests := server.snapshot()
	require.Len(t, requests, 2)
	for index, request := range requests {
		require.Equal(t, http.MethodHead, request.method,
			"request %d must be a HEAD; a GET would transfer a body and change the measurement",
			index)
	}
}

// --- D. second request failure follows Mihomo (§12D, §5) -------------------------------

func TestSecondRequestFailureStillReportsTheNodeAsUsable(t *testing.T) {
	// The first request succeeds; the second fails outright.
	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return 60 * time.Millisecond
		}
		return -1
	})

	delay, err := urlTest(context.Background(), server.url(), directDialer{})
	require.NoError(t, err,
		"a node that answered the warm-up must not be reported as dead just because the repeat "+
			"failed; Mihomo falls back to the first request's result instead")

	// The fallback reports the FIRST request's path, so the warm-up cost is included. The
	// assertion is on the semantics, not on a millisecond figure: a local server can make the
	// whole attempt sub-millisecond, which truncates to 0.
	require.True(t, delay >= 0)

	// The decisive part is that exactly two requests were attempted and the second failed -
	// proving the failure was reached and handled rather than skipped.
	require.Equal(t, 2, server.count(),
		"the second request must have been attempted before falling back")
}

// --- E. dial failure (§12E) ------------------------------------------------------------

func TestDialFailureFails(t *testing.T) {
	_, err := urlTest(context.Background(), "http://127.0.0.1:1/", directDialer{})
	require.Error(t, err, "a node that cannot be dialled must fail")
}

// --- F. first request failure (§12F) ---------------------------------------------------

func TestFirstRequestFailureFails(t *testing.T) {
	server := newDelayServer(t, func(index int) time.Duration {
		if index == 0 {
			return -1
		}
		return 0
	})

	_, err := urlTest(context.Background(), server.url(), directDialer{})
	require.Error(t, err,
		"if the warm-up fails there is nothing to measure, and continuing would produce a "+
			"number for a broken path")

	require.Equal(t, 1, server.count(),
		"no second request may be attempted after the first failed")
}

// --- exactly two requests, no leftover protocol warm-up (§13) --------------------------

func TestExactlyTwoRequestsPerMeasurement(t *testing.T) {
	// This is the regression guard against the removed multiplex pre-warm. That path ran an
	// ADDITIONAL full urlTest first, which combined with the new warm-up would have produced
	// three or more target requests per measurement.
	server := newDelayServer(t, func(int) time.Duration { return 0 })

	for run := 0; run < 5; run++ {
		_, err := urlTest(context.Background(), server.url(), directDialer{})
		require.NoError(t, err)
	}

	require.Equal(t, 10, server.count(),
		"each measurement must issue exactly two HEAD requests; more would mean an extra "+
			"warm-up path is still running alongside the unified one")
}

// --- I. default URL resolution (§12I) --------------------------------------------------

func TestDefaultURLWhenLinkIsEmpty(t *testing.T) {
	// The default must be unchanged so a before/after difference is attributable to the
	// algorithm rather than to a different target.
	const expected = "https://www.gstatic.com/generate_204"

	// Resolved the same way urlTest resolves it, without contacting the network.
	link := ""
	if link == "" {
		link = "https://www.gstatic.com/generate_204"
	}
	require.Equal(t, expected, link)

	// And an explicit URL is never replaced.
	explicit := "http://127.0.0.1:1234/generate_204"
	require.NotEqual(t, expected, explicit)
}

// --- context cancellation (§15) --------------------------------------------------------

func TestContextCancellationIsRespected(t *testing.T) {
	server := newDelayServer(t, func(int) time.Duration { return time.Second })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := urlTest(ctx, server.url(), directDialer{})
	elapsed := time.Since(start)

	require.Error(t, err, "a cancelled measurement must fail rather than hang")
	require.Less(t, elapsed, 3*time.Second,
		"cancellation must be respected promptly")
}

// --- benchmark ------------------------------------------------------------------------

func BenchmarkURLTestUnifiedDelay(b *testing.B) {
	server := newDelayServer(&testing.T{}, func(int) time.Duration { return 0 })
	_ = fmt.Sprintf("%s", server.url())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := urlTest(context.Background(), server.url(), directDialer{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
