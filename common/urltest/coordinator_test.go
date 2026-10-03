package urltest

import (
	"context"
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

// Tests for the per-Box measurement coordinator.

// gatedDialer dials a real target and holds the connection until released, so a test can observe
// how many measurements are simultaneously in flight.
type gatedDialer struct {
	active      atomic.Int32
	peak        atomic.Int32
	release     chan struct{}
	releaseOnce sync.Once
}

func (d *gatedDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	current := d.active.Add(1)
	for {
		observed := d.peak.Load()
		if current <= observed || d.peak.CompareAndSwap(observed, current) {
			break
		}
	}

	select {
	case <-d.release:
	case <-ctx.Done():
		d.active.Add(-1)
		return nil, ctx.Err()
	}
	d.active.Add(-1)

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (d *gatedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, http.ErrNotSupported
}

func (d *gatedDialer) releaseAll() { d.releaseOnce.Do(func() { close(d.release) }) }

// TestCoordinatorCapsConcurrentMeasurementsPerBox is §41, §25.
//
// Far more measurements are started than the limit allows; the coordinator must hold the peak at
// the limit rather than at the number of callers.
func TestCoordinatorCapsConcurrentMeasurementsPerBox(t *testing.T) {
	const limit = 10
	const callers = 40

	coordinator := NewCoordinator(limit)
	dialer := &gatedDialer{release: make(chan struct{})}
	defer dialer.releaseAll()

	ctx := ContextWithCoordinator(context.Background(), coordinator)

	var waitGroup sync.WaitGroup
	for index := 0; index < callers; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			// Each measurement blocks in the dial, so every acquired slot stays held.
			_, _ = Measure(ctx, MeasureOptions{Link: "https://example.com/generate_204"}, dialer)
		}()
	}

	// Wait until the slots are saturated, then observe.
	require.Eventually(t, func() bool { return coordinator.InFlight() == limit },
		5*time.Second, 5*time.Millisecond,
		"the coordinator must admit measurements up to its limit")

	// Give any excess caller a chance to wrongly proceed.
	time.Sleep(200 * time.Millisecond)

	require.LessOrEqual(t, dialer.peak.Load(), int32(limit),
		"%d concurrent callers must be capped at %d simultaneous measurements by one Box; the "+
			"per-batch limit alone would allow %d", callers, limit, callers)

	dialer.releaseAll()
	waitGroup.Wait()

	require.Eventually(t, func() bool { return coordinator.InFlight() == 0 },
		5*time.Second, 5*time.Millisecond,
		"every slot must be returned once the measurements finish")
}

// TestCoordinatorAcquireHonorsCancellation is §24, §41.
//
// A measurement waiting for a slot must give up when its own context ends, rather than holding a
// goroutine until a slot happens to free.
func TestCoordinatorAcquireHonorsCancellation(t *testing.T) {
	coordinator := NewCoordinator(1)

	// Occupy the only slot.
	release, err := coordinator.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, coordinator.InFlight())

	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, acquireErr := coordinator.Acquire(ctx)
		waiting <- acquireErr
	}()

	// Let it start waiting, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case acquireErr := <-waiting:
		require.ErrorIs(t, acquireErr, context.Canceled,
			"a cancelled waiter must return the context error")
	case <-time.After(3 * time.Second):
		t.Fatal("Acquire ignored cancellation and kept waiting; a measurement that can never run " +
			"would hold a goroutine and, once admitted, a slot it does not need")
	}

	require.Equal(t, 1, coordinator.InFlight(),
		"the cancelled waiter must not have taken a slot")

	release()
	require.Equal(t, 0, coordinator.InFlight())
}

// TestCoordinatorAcquireHonorsDeadline is the same contract for a deadline.
func TestCoordinatorAcquireHonorsDeadline(t *testing.T) {
	coordinator := NewCoordinator(1)
	release, err := coordinator.Acquire(context.Background())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = coordinator.Acquire(ctx)
	elapsed := time.Since(start)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, elapsed, 3*time.Second,
		"a waiter with an expired deadline must not linger")
}

// TestCoordinatorsAreIndependentAcrossBoxes is §26, §41.
//
// One Box exhausting its budget must not stall another. This is the whole reason the limiter is not
// a package global.
func TestCoordinatorsAreIndependentAcrossBoxes(t *testing.T) {
	boxA := NewCoordinator(1)
	boxB := NewCoordinator(1)

	// Box A's only slot is taken and held.
	releaseA, err := boxA.Acquire(context.Background())
	require.NoError(t, err)
	defer releaseA()

	// Box B must still be able to measure.
	ctxB, cancelB := context.WithTimeout(ContextWithCoordinator(context.Background(), boxB), 2*time.Second)
	defer cancelB()

	releaseB, err := boxB.Acquire(ctxB)
	require.NoError(t, err,
		"Box B must not be blocked by Box A: a shared limiter would let a temporary "+
			"configuration-check Box exhaust the running Box's budget")
	releaseB()

	require.Equal(t, 1, boxA.InFlight())
	require.Equal(t, 0, boxB.InFlight())
}

// TestMeasurementWithoutCoordinatorIsUnbounded keeps the isolated-caller contract.
//
// A test or library caller that never built a Box must still be able to measure, and must NOT fall
// back to a process-wide limiter.
func TestMeasurementWithoutCoordinatorIsUnbounded(t *testing.T) {
	require.Nil(t, CoordinatorFromContext(context.Background()),
		"a plain context carries no coordinator")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	dialer := &countingDialer{}
	_, err := Measure(context.Background(), MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
	require.NoError(t, err, "a measurement with no coordinator must still run")
}

// TestSlotIsReleasedOnEveryOutcome checks the release is deferred, not conditional.
func TestSlotIsReleasedOnEveryOutcome(t *testing.T) {
	coordinator := NewCoordinator(2)
	ctx := ContextWithCoordinator(context.Background(), coordinator)

	// A link that cannot be parsed, so every measurement fails before dialling.
	failing := &countingDialer{}
	for index := 0; index < 5; index++ {
		_, _ = Measure(ctx, MeasureOptions{Link: "not a url"}, failing)
		require.Equal(t, 0, coordinator.InFlight(),
			"a failed measurement must return its slot; otherwise the budget is consumed by "+
				"measurements that never ran")
	}
}

// TestDisabledCoordinatorBlocksNothing covers the non-positive limit.
func TestDisabledCoordinatorBlocksNothing(t *testing.T) {
	coordinator := NewCoordinator(0)
	require.Equal(t, 0, coordinator.Limit())

	release, err := coordinator.Acquire(context.Background())
	require.NoError(t, err)
	release()
}

// TestMultipleGroupsShareOneBoxBudget is §25.
//
// Three URLTest batches, each with its own concurrency of ten, are started together. The per-batch
// limit alone would allow thirty simultaneous measurements; the Box budget must hold the peak at
// ten.
func TestMultipleGroupsShareOneBoxBudget(t *testing.T) {
	const groups = 3
	const membersPerGroup = 12
	const limit = 10

	coordinator := NewCoordinator(limit)
	dialer := &gatedDialer{release: make(chan struct{})}
	defer dialer.releaseAll()

	ctx := ContextWithCoordinator(context.Background(), coordinator)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	// Each batch runs its members concurrently, exactly as a group health check does.
	var waitGroup sync.WaitGroup
	for groupIndex := 0; groupIndex < groups; groupIndex++ {
		for memberIndex := 0; memberIndex < membersPerGroup; memberIndex++ {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				_, _ = Measure(ctx, MeasureOptions{Link: server.URL + "/generate_204"}, dialer)
			}()
		}
	}

	// Every measurement blocks in the dial, so the peak is the number admitted at once.
	require.Eventually(t, func() bool { return coordinator.InFlight() == limit },
		5*time.Second, 5*time.Millisecond,
		"the Box budget must be saturated by the concurrent groups")

	time.Sleep(250 * time.Millisecond)

	require.LessOrEqual(t, dialer.peak.Load(), int32(limit),
		"%d groups x %d members must share ONE Box budget of %d; the per-batch limit alone would "+
			"allow %d simultaneous measurements, which on a phone inside a NetworkExtension is a "+
			"memory and socket spike", groups, membersPerGroup, limit, groups*membersPerGroup)

	dialer.releaseAll()
	waitGroup.Wait()
}
