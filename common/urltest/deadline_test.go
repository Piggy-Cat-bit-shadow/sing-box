package urltest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for the measurement's total deadline.
//
// # The contract
//
// A measurement is bounded by the EARLIER of the caller's deadline and C.TCPTimeout. The previous
// implementation applied C.TCPTimeout only when the caller had no deadline at all, so a caller with
// a 60s deadline got 60s - the measurement was bounded by something other than what it intended.

// constantDialer blocks until its context is done, then reports how it ended.
type constantDialer struct {
	dials  atomic.Int32
	closed atomic.Int32
}

func (d *constantDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *constantDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, http.ErrNotSupported
}

// TestMeasurementDeadlineAddedWithoutParent is §42.
func TestMeasurementDeadlineAddedWithoutParent(t *testing.T) {
	const timeout = 200 * time.Millisecond

	ctx, cancel := withMeasurementTimeout(context.Background(), timeout)
	defer cancel()

	deadline, hasDeadline := ctx.Deadline()
	require.True(t, hasDeadline, "a context with no deadline must gain one")
	require.WithinDuration(t, time.Now().Add(timeout), deadline, 100*time.Millisecond)
}

// TestEarlierParentDeadlineWins is §42.
//
// The measurement must never extend a caller's own limit.
func TestEarlierParentDeadlineWins(t *testing.T) {
	const parentTimeout = 100 * time.Millisecond
	const measurementTimeout = 5 * time.Second

	parent, cancelParent := context.WithTimeout(context.Background(), parentTimeout)
	defer cancelParent()

	ctx, cancel := withMeasurementTimeout(parent, measurementTimeout)
	defer cancel()

	deadline, hasDeadline := ctx.Deadline()
	require.True(t, hasDeadline)

	parentDeadline, _ := parent.Deadline()
	require.Equal(t, parentDeadline, deadline,
		"a caller's earlier deadline must be kept exactly; a measurement must not widen it")
}

// TestTCPTimeoutWinsOverLaterParentDeadline is the defect being fixed.
//
// A caller with a LATER deadline must still be bounded by the measurement timeout.
func TestTCPTimeoutWinsOverLaterParentDeadline(t *testing.T) {
	const parentTimeout = 30 * time.Second
	const measurementTimeout = 100 * time.Millisecond

	parent, cancelParent := context.WithTimeout(context.Background(), parentTimeout)
	defer cancelParent()

	ctx, cancel := withMeasurementTimeout(parent, measurementTimeout)
	defer cancel()

	deadline, hasDeadline := ctx.Deadline()
	require.True(t, hasDeadline)

	parentDeadline, _ := parent.Deadline()
	require.True(t, deadline.Before(parentDeadline),
		"the measurement timeout (%v) must tighten a later parent deadline (%v); previously it was "+
			"ignored entirely whenever the caller had any deadline at all, so the measurement ran "+
			"for as long as the caller allowed", measurementTimeout, parentTimeout)
	require.WithinDuration(t, time.Now().Add(measurementTimeout), deadline, 80*time.Millisecond)
}

// TestBlockedDialIsBoundedByTheMeasurementDeadline checks the deadline actually reaches the dial.
//
// The measurement deadline is applied to the ctx the dial receives, so a dial that never completes
// must end with the context's error rather than hanging.
func TestBlockedDialIsBoundedByTheMeasurementDeadline(t *testing.T) {
	dialer := &constantDialer{}

	// A parent with a much later deadline, so only the measurement timeout can end this.
	parent, cancelParent := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelParent()

	measurementCtx, cancel := withMeasurementTimeout(parent, 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Measure(measurementCtx, MeasureOptions{Link: "https://example.com/generate_204"}, dialer)
	elapsed := time.Since(start)

	require.Error(t, err, "the blocked dial must end in an error")
	require.Less(t, elapsed, 5*time.Second,
		"the dial ran for %v, so the measurement deadline did not reach it", elapsed)
	require.EqualValues(t, 1, dialer.dials.Load(), "and exactly one dial was attempted")
}

// TestBlockedWarmupRequestIsBounded checks the deadline covers a stalled first request.
func TestBlockedWarmupRequestIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}

	parent, cancelParent := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelParent()

	measurementCtx, cancel := withMeasurementTimeout(parent, 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Measure(measurementCtx, MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	elapsed := time.Since(start)

	require.Error(t, err, "a stalled warm-up must fail")
	require.Less(t, elapsed, 5*time.Second,
		"the warm-up ran for %v, so it was not under the measurement deadline", elapsed)
}
