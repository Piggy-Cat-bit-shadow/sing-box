package urltest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Measurement contract tests: status validation, timeout/cancel classification, the delay floor,
// and the lazy-handshake warm-up guarantee.

// --- status validation (§11, §42) ------------------------------------------------------

func TestExpectedStatusAppliesToTheMeasuredResponse(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)

	strict, err := ParseExpectedStatus("204")
	require.NoError(t, err)

	result, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204", ExpectedStatus: strict}, directDialer{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, result.StatusCode)
	require.GreaterOrEqual(t, result.Delay, uint16(0))
}

func TestExpectedStatusMismatchIsAnError(t *testing.T) {
	// A captive portal answering 302 must not look like a fast healthy node: the delay for a
	// redirect is meaningless and would beat a genuine 204 node.
	server := newStatusServer(t, http.StatusFound)

	strict, err := ParseExpectedStatus("204")
	require.NoError(t, err)

	_, err = Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204", ExpectedStatus: strict}, directDialer{})
	require.Error(t, err, "a status outside the expected set must fail the measurement")
	require.Contains(t, err.Error(), "302")
}

func TestUnconstrainedExpectedAcceptsAnyStatus(t *testing.T) {
	// expected="*" means "reachable", and a 500 still proves the node answered.
	server := newStatusServer(t, http.StatusInternalServerError)

	result, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204"}, directDialer{})
	require.NoError(t, err, "an unconstrained measurement accepts any HTTP status")
	require.Equal(t, http.StatusInternalServerError, result.StatusCode)
}

func TestExpectedStatusRangeAndList(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)

	for _, expression := range []string{"204", "200-299", "200/204", "200,204", "200,204,301-399"} {
		t.Run(expression, func(t *testing.T) {
			expected, err := ParseExpectedStatus(expression)
			require.NoError(t, err)

			_, err = Measure(context.Background(),
				MeasureOptions{Link: server.URL + "/generate_204", ExpectedStatus: expected}, directDialer{})
			require.NoError(t, err, "204 satisfies %s", expression)
		})
	}
}

// --- second-request failure classification (§8, §9, §10) -------------------------------

func TestSecondRequestTimeoutIsAnError(t *testing.T) {
	// The first request succeeds immediately; the second blocks until the context expires.
	//
	// This is the defect being fixed: the old code treated ANY second failure as the Mihomo
	// fallback, so an expired measurement returned success - which the Clash layer reported as a
	// timeout while the history recorded a healthy node.
	server := newBlockingSecondServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	result, err := Measure(ctx, MeasureOptions{Link: server.URL + "/generate_204"}, directDialer{})
	elapsed := time.Since(start)

	require.Error(t, err, "an expired measurement must fail, not fall back to a success")
	require.Zero(t, result.Delay)
	require.True(t,
		errors.Is(err, context.DeadlineExceeded) || isTimeout(err),
		"the error must be recognisable as a timeout, got %v", err)
	require.Less(t, elapsed, 3*time.Second)
}

func TestSecondRequestCancellationIsAnError(t *testing.T) {
	server := newBlockingSecondServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()

	result, err := Measure(ctx, MeasureOptions{Link: server.URL + "/generate_204"}, directDialer{})
	require.Error(t, err, "a cancelled measurement must fail")
	require.Zero(t, result.Delay,
		"a cancelled measurement must not report a delay")
}

func TestSecondQuickFailureKeepsTheMihomoFallback(t *testing.T) {
	// The second request fails immediately with a non-timeout error while the context is healthy.
	// Mihomo keeps the node usable in this case, and so must we.
	server := newFailingSecondServer(t)

	result, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204"}, directDialer{})
	require.NoError(t, err,
		"a node that answered the warm-up must not be reported dead because a repeat failed")
	require.Greater(t, result.Delay, uint16(0),
		"the fallback reports the whole attempt's cost, which is not zero")
	require.Equal(t, http.StatusNoContent, result.StatusCode,
		"the fallback reports the FIRST response's status")
}

func TestShouldFallbackSecondRequestClassification(t *testing.T) {
	// The predicate is the whole distinction, so it is tested directly as well as through the
	// measurement.
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, shouldFallbackSecondRequest(expired, errors.New("boom")),
		"a dead context is never a fallback, whatever the error says")

	require.False(t, shouldFallbackSecondRequest(context.Background(), context.Canceled))
	require.False(t, shouldFallbackSecondRequest(context.Background(), context.DeadlineExceeded))
	require.False(t, shouldFallbackSecondRequest(context.Background(), &net.DNSError{IsTimeout: true}),
		"a network timeout is a timeout")

	require.True(t, shouldFallbackSecondRequest(context.Background(), errors.New("connection reset")),
		"a repeat-request failure is exactly what the fallback is for")
	require.True(t, shouldFallbackSecondRequest(context.Background(), errors.New("EOF")))
}

// --- delay floor (§34) -----------------------------------------------------------------

func TestDurationToDelay(t *testing.T) {
	require.EqualValues(t, 0, durationToDelay(0))
	require.EqualValues(t, 0, durationToDelay(-time.Second))
	require.EqualValues(t, 1, durationToDelay(time.Nanosecond),
		"a sub-millisecond success must not report 0, which means 'no result' everywhere else")
	require.EqualValues(t, 1, durationToDelay(999*time.Microsecond))
	require.EqualValues(t, 1, durationToDelay(time.Millisecond))
	require.EqualValues(t, 250, durationToDelay(250*time.Millisecond))
	require.EqualValues(t, 0xFFFF, durationToDelay(time.Hour))
}

func TestFastFixtureReportsOneNotZero(t *testing.T) {
	server := newStatusServer(t, http.StatusNoContent)

	result, err := Measure(context.Background(),
		MeasureOptions{Link: server.URL + "/generate_204"}, directDialer{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, result.Delay, uint16(1),
		"a successful measurement is never 0, so 0 keeps meaning 'no result'")
}

// --- lazy handshake warm-up (§37) ------------------------------------------------------

func TestLazyHandshakeDelayStaysInTheWarmUp(t *testing.T) {
	// The first write is deliberately slow, modelling a protocol whose handshake is deferred until
	// bytes are sent. That cost belongs to the warm-up request; the unified delay must exclude it.
	//
	// This is the property the removed `N.NeedHandshakeForWrite` clock reset used to approximate,
	// and it must hold without any protocol-specific branch.
	server := newStatusServer(t, http.StatusNoContent)

	conn := newDelayedFirstWriteDialer(150 * time.Millisecond)
	delay, err := URLTest(context.Background(), server.URL+"/generate_204", conn)
	require.NoError(t, err)

	require.Less(t, int(delay), 120,
		"the %v first-write delay must be absorbed by the warm-up; reported %dms",
		150*time.Millisecond, delay)
	require.GreaterOrEqual(t, delay, uint16(1))
}

// --- fixtures --------------------------------------------------------------------------

func newStatusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server
}

// newBlockingSecondServer answers the first HEAD and blocks the second until its context ends.
func newBlockingSecondServer(t *testing.T) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if count.Add(1) == 1 {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		// Wait for the client to give up, then return - the client's error is what matters.
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)
	return server
}

// newFailingSecondServer resets the connection on the second request.
func newFailingSecondServer(t *testing.T) *httptest.Server {
	t.Helper()
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if count.Add(1) == 1 {
			time.Sleep(40 * time.Millisecond)
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		// Abrupt close: no response, so the client sees EOF or a reset. This is not a timeout.
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		conn, _, err := hijacker.Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// delayedFirstWriteConn delays the first Write only.
type delayedFirstWriteConn struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *delayedFirstWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.delay) })
	return c.Conn.Write(p)
}

// delayedFirstWriteDialer hands out connections whose first write is slow.
type delayedFirstWriteDialer struct {
	delay time.Duration
}

func newDelayedFirstWriteDialer(delay time.Duration) *delayedFirstWriteDialer {
	return &delayedFirstWriteDialer{delay: delay}
}

func (d *delayedFirstWriteDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	return &delayedFirstWriteConn{Conn: conn, delay: d.delay}, nil
}

func (d *delayedFirstWriteDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not supported")
}

// isTimeout reports whether an error is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
