//go:build darwin && cgo

package oomkiller

import (
	"sync/atomic"
	"testing"
	"time"

	tun "github.com/sagernet/sing-tun"
)

// Tests for late memory-pressure callbacks (§5).
//
// # The failure being fixed
//
// notifyPressure used to call releaseMemory() BEFORE checking whether the timer was still
// running:
//
//	releaseMemory()          <- Flush, Store(Critical), badCleanup, FreeOSMemory
//	if t.timer == nil { return }
//
// The registry hands each service a snapshot of the registered services, so a callback can be
// in flight while that service is being closed - the snapshot predates the Close, the callback
// runs after it. Such a callback performed the entire destructive sequence on a shut-down
// service and only then discovered the timer was nil.
//
// The observable consequences, both asserted below:
//
//   - pressure was rewritten from None back to Critical, re-arming a report for a service the
//     user had stopped and that other components read;
//   - FreeOSMemory and the cache flush ran for a service nobody owns any more.

// TestLatePressureCallbackDoesNotRunCleanupAfterClose is the §5 regression.
//
// The timer is stopped first, then a callback that was already in flight is delivered. It must
// perform NO destructive work: pressure stays None rather than flipping back to Critical.
func TestLatePressureCallbackDoesNotRunCleanupAfterClose(t *testing.T) {
	pressure := &atomic.Uint32{}
	pressure.Store(uint32(tun.MemoryPressureNone))
	timer := newPressureTestTimer(pressure)

	// A live timer, then Close.
	timer.start(nil)
	timer.stop()

	if pressure.Load() != uint32(tun.MemoryPressureNone) {
		t.Fatalf("precondition: pressure should be None after stop, got %d", pressure.Load())
	}

	// The late callback.
	timer.notifyPressure()

	if got := pressure.Load(); got != uint32(tun.MemoryPressureNone) {
		t.Fatalf("a late pressure callback rewrote pressure to %d after Close; "+
			"destructive cleanup must not run against a stopped timer", got)
	}
}

// TestLatePressureCallbackDoesNotReArmTheTimer checks the callback cannot resurrect a stopped
// timer, which would leave the service polling after it was closed.
func TestLatePressureCallbackDoesNotReArmTheTimer(t *testing.T) {
	pressure := &atomic.Uint32{}
	timer := newPressureTestTimer(pressure)

	timer.start(nil)
	timer.stop()

	timer.notifyPressure()

	timer.access.Lock()
	running := timer.timer != nil
	forced := timer.forceMinInterval
	timer.access.Unlock()

	if running {
		t.Fatal("a late pressure callback restarted the timer after Close")
	}
	if forced {
		t.Fatal("a late pressure callback set forceMinInterval on a stopped timer")
	}
}

// TestPressureCallbackOnALiveTimerStillWorks is the other direction.
//
// Guarding the cleanup must not disable the feature: an active service receiving real pressure
// must still act on it.
//
// The assertion targets the pressure BASELINE rather than the pressure value. notifyPressure
// calls poll() right after releaseMemory(), and poll() recomputes pressure from a fresh sample -
// so with a low simulated usage the value returns to None immediately, and poll() also consumes
// the pendingPressureBaseline flag.
//
// What survives the poll is pressureBaselineTime, which records that a pressure event was
// observed and makes subsequent polls measure growth from that moment. Asserting the pressure
// value would be asserting a transient the very next line overwrites; asserting the flag would
// be asserting something poll() deliberately consumes.
func TestPressureCallbackOnALiveTimerStillWorks(t *testing.T) {
	pressure := &atomic.Uint32{}
	pressure.Store(uint32(tun.MemoryPressureNone))
	timer := newPressureTestTimer(pressure)

	timer.start(nil)
	defer timer.stop()

	timer.notifyPressure()

	timer.access.Lock()
	baselineTime := timer.pressureBaselineTime
	timer.access.Unlock()

	if baselineTime.IsZero() {
		t.Fatal("a pressure callback on a LIVE timer must record a pressure baseline")
	}
}

// TestLatePressureCallbackRacingClose is the deterministic concurrency form.
//
// notifyPressure and stop() are mutually exclusive through the lifecycle lock, so the outcome
// is one of exactly two acceptable states - never "cleanup ran against a stopped timer":
//
//   - stop() wins: the callback returns without doing anything, and pressure stays None.
//   - notifyPressure wins: it completes legitimately while the service was still live, and the
//     subsequent stop() leaves the timer stopped.
//
// Either way the timer must end stopped. The test runs many iterations because the interesting
// interleaving is timing-dependent, while the ASSERTION is not: a stopped timer must never be
// the target of destructive work.
func TestLatePressureCallbackRacingClose(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		pressure := &atomic.Uint32{}
		pressure.Store(uint32(tun.MemoryPressureNone))
		timer := newPressureTestTimer(pressure)
		timer.start(nil)

		callbackDone := make(chan struct{})
		closeDone := make(chan struct{})

		go func() {
			defer close(callbackDone)
			timer.notifyPressure()
		}()
		go func() {
			defer close(closeDone)
			timer.stop()
		}()

		<-callbackDone
		<-closeDone

		timer.access.Lock()
		stillRunning := timer.timer != nil
		timer.access.Unlock()
		if stillRunning {
			t.Fatalf("iteration %d: the timer is still running after stop returned", iteration)
		}

		// Whatever the interleaving, the timer is stopped at the end. A callback delivered
		// definitively after stop must do nothing at all: the durable evidence is that it did
		// not set the pressure baseline or force the minimum interval, which it would have
		// done had it believed the timer was live.
		timer.access.Lock()
		timer.pendingPressureBaseline = false
		timer.forceMinInterval = false
		timer.access.Unlock()

		timer.notifyPressure() // a definitively late callback

		timer.access.Lock()
		baselineSet := timer.pendingPressureBaseline
		forced := timer.forceMinInterval
		timer.timer = nil
		timer.access.Unlock()

		if baselineSet || forced {
			t.Fatalf("iteration %d: a callback delivered after stop acted on a stopped timer", iteration)
		}
	}
}

// TestCloseWaitsForInFlightPressureCallback is the §1 regression.
//
// # The interleaving it forces
//
//	notifyPressure: active check passes, Add(1), unlock
//	callback:       enters cleanup, BLOCKS on the hook
//	stopTimer:      stop() sets timer = nil, then must WAIT
//	...
//	hook released:  callback finishes
//	stopTimer:      returns
//
// The assertion is that stopTimer/Close has NOT returned while the callback is inside its
// cleanup. An earlier implementation released the lock and returned immediately, so Close
// completed while releaseMemory was still going to store MemoryPressureCritical - leaving a
// closed service reporting critical pressure, with cache flush and FreeOSMemory still to run.
//
// The hook makes this deterministic. The previous test raced goroutines and asserted the
// outcome, which could pass by luck on a machine where the callback never won the race.
func TestCloseWaitsForInFlightPressureCallback(t *testing.T) {
	pressure := &atomic.Uint32{}
	pressure.Store(uint32(tun.MemoryPressureNone))
	timer := newPressureTestTimer(pressure)

	callbackEntered := make(chan struct{})
	callbackRelease := make(chan struct{})
	timer.cleanupHook = func() {
		close(callbackEntered)
		<-callbackRelease
	}

	timer.start(nil)

	// Run the callback on its own goroutine: it is about to block inside the barrier.
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		timer.notifyPressure()
	}()

	// Wait until the callback is provably inside the cleanup.
	select {
	case <-callbackEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the callback never entered its cleanup")
	}

	// Close concurrently. It must WAIT, not return.
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		timer.stop()
	}()

	select {
	case <-closeDone:
		t.Fatal("stop returned while a pressure callback was still inside its cleanup; " +
			"the destructive work can still rewrite pressure to Critical after Close")
	case <-time.After(150 * time.Millisecond):
		// Correct: stop is blocked on the in-flight barrier.
	}

	// Release the callback and let everything settle.
	close(callbackRelease)

	select {
	case <-callbackDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the callback did not finish after being released")
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return after the callback finished")
	}

	// Final state: timer stopped, in-flight count zero.
	timer.access.Lock()
	running := timer.timer != nil
	timer.access.Unlock()
	if running {
		t.Fatal("the timer must be stopped")
	}

	// The callback ran legitimately - it was active when the pressure arrived - so pressure is
	// Critical at this instant. What matters is that it can no longer CHANGE after Close.
	pressureAfterClose := pressure.Load()
	time.Sleep(50 * time.Millisecond)
	if got := pressure.Load(); got != pressureAfterClose {
		t.Fatalf("pressure changed from %d to %d after Close returned", pressureAfterClose, got)
	}
}

// TestLateCallbackAfterCloseHasNoEffect is the other half: a callback delivered AFTER Close
// must do nothing at all.
//
// It must not set the pressure baseline, must not force the minimum interval, and must not
// touch the reported pressure.
func TestLateCallbackAfterCloseHasNoEffect(t *testing.T) {
	pressure := &atomic.Uint32{}

	var hookCalls atomic.Int32
	timer := newPressureTestTimer(pressure)
	timer.cleanupHook = func() { hookCalls.Add(1) }

	timer.start(nil)
	timer.stop()

	// Normalise the state so any change is visible.
	pressure.Store(uint32(tun.MemoryPressureNone))
	timer.access.Lock()
	timer.forceMinInterval = false
	timer.pendingPressureBaseline = false
	timer.pressureBaselineTime = time.Time{}
	timer.access.Unlock()

	// A definitively late callback.
	timer.notifyPressure()

	if got := pressure.Load(); got != uint32(tun.MemoryPressureNone) {
		t.Fatalf("a callback after Close rewrote pressure to %d", got)
	}
	if calls := hookCalls.Load(); calls != 0 {
		t.Fatalf("a callback after Close executed the cleanup %d time(s)", calls)
	}

	timer.access.Lock()
	forced := timer.forceMinInterval
	baseline := timer.pendingPressureBaseline
	baselineTime := timer.pressureBaselineTime
	timer.access.Unlock()

	if forced || baseline || !baselineTime.IsZero() {
		t.Fatalf("a callback after Close modified timer state: forced=%v baseline=%v at=%v",
			forced, baseline, baselineTime)
	}
}

// TestStopIsNotBlockedWhenNoCallbackIsInFlight guards against the barrier turning into a
// permanent stall: with nothing in flight, stop must return promptly.
func TestStopIsNotBlockedWhenNoCallbackIsInFlight(t *testing.T) {
	pressure := &atomic.Uint32{}
	timer := newPressureTestTimer(pressure)
	timer.start(nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		timer.stop()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop blocked with no callback in flight")
	}
}
