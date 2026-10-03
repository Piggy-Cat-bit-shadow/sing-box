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

// Tests for the boundary between waiting for a measurement slot and probing.
//
// # The defect these pin
//
// Measure established its active-probe deadline BEFORE asking the coordinator for a slot, so time
// spent queued was charged against the probe budget. Under saturation - several groups checking at
// once against one Box budget - a member could exhaust its budget while waiting, never dial, and
// still be reported as a measurement failure.
//
// The consequence is not a slow measurement. The group treats a measurement failure as health
// evidence and DELETES that node's scope, so a node that was never tested is recorded as unhealthy:
// evidence changed without a measurement.
//
// The two budgets are distinct and must stay distinct:
//
//	caller deadline   -> bounds the whole operation, queue included
//	C.TCPTimeout      -> bounds dial + warm-up + timed request, once a slot is held

// queueTestDialer records dials and can hold a connection open.
type queueTestDialer struct {
	dials   atomic.Int32
	release chan struct{}
}

func (d *queueTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	if d.release == nil {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, destination.String())
	}
	select {
	case <-d.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *queueTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, http.ErrNotSupported
}

// TestCoordinatorWaitDoesNotConsumeProbeTimeout is the release blocker (§8.2 / §8.3).
//
// A measurement queued behind a held slot must not fail merely because it waited. Once admitted it
// gets its full probe budget.
func TestCoordinatorWaitDoesNotConsumeProbeTimeout(t *testing.T) {
	coordinator := NewCoordinator(1)
	ctx := ContextWithCoordinator(context.Background(), coordinator)

	// Occupy the only slot.
	releaseSlot, err := coordinator.Acquire(ctx)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dialer := &queueTestDialer{}

	// The probe budget this measurement will be given once admitted. It is short so the test is
	// fast, and it must be entirely available AFTER admission.
	const probeBudget = 120 * time.Millisecond

	start := time.Now()
	result := make(chan error, 1)
	go func() {
		_, measureErr := measureWithTimeout(ctx,
			MeasureOptions{Link: server.URL + "/generate_204"}, dialer, probeBudget)
		result <- measureErr
	}()

	// Hold the slot well past the probe budget, so the queued measurement has spent far more than
	// its budget while waiting.
	time.Sleep(3 * probeBudget)

	select {
	case err := <-result:
		t.Fatalf("the queued measurement returned %v while the only slot was still held; a "+
			"measurement that never got a slot must still be WAITING, not failed", err)
	default:
	}

	// Admit it. It must now get its FULL probe budget and succeed.
	releaseSlot()

	select {
	case err := <-result:
		require.NoError(t, err,
			"after waiting %v for a slot the measurement failed with %v. The queue wait was "+
				"charged against the probe budget, so the node was reported as unhealthy without "+
				"ever being dialled - and the group deletes health evidence on a measurement "+
				"failure", time.Since(start), err)
	case <-time.After(5 * time.Second):
		t.Fatal("the measurement never completed after being admitted")
	}

	require.GreaterOrEqual(t, dialer.dials.Load(), int32(1),
		"and it must actually have dialled")
}

// TestCallerDeadlineStillBoundsCoordinatorWait is the other half of the contract (§8.1).
//
// The caller's deadline bounds the WHOLE operation, queue included, so a caller that gives up while
// queued still stops.
func TestCallerDeadlineStillBoundsCoordinatorWait(t *testing.T) {
	coordinator := NewCoordinator(1)

	slotCtx := ContextWithCoordinator(context.Background(), coordinator)
	releaseSlot, err := coordinator.Acquire(slotCtx)
	require.NoError(t, err)
	defer releaseSlot()

	// The caller gives up quickly, while still queued.
	callerCtx, cancelCaller := context.WithTimeout(slotCtx, 100*time.Millisecond)
	defer cancelCaller()

	dialer := &queueTestDialer{}
	start := time.Now()

	_, err = measureWithTimeout(callerCtx,
		MeasureOptions{Link: "https://example.com/generate_204"}, dialer, 5*time.Second)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded,
		"a caller that gives up while queued must see its own deadline, not a probe timeout")
	require.Less(t, elapsed, 3*time.Second,
		"caller deadline must bound the queue wait")
	require.EqualValues(t, 0, dialer.dials.Load(),
		"and nothing may be dialled")
}

// TestInvalidTargetDoesNotConsumeASlot covers the ordering of parsing.
func TestInvalidTargetDoesNotConsumeASlot(t *testing.T) {
	coordinator := NewCoordinator(1)
	ctx := ContextWithCoordinator(context.Background(), coordinator)

	dialer := &queueTestDialer{}
	_, err := Measure(ctx, MeasureOptions{Link: "https://example.com:0/x"}, dialer)
	require.Error(t, err)

	require.Equal(t, 0, coordinator.InFlight(),
		"an unusable target must fail before taking a slot, so a malformed configuration cannot "+
			"occupy the Box's measurement budget")

	// The slot is still available.
	release, err := coordinator.Acquire(ctx)
	require.NoError(t, err)
	release()
}
