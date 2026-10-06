package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
)

// newGovernor returns a governor with a window open and test-sized parameters.
func newGovernor(t *testing.T, limit int) *dialGovernor {
	t.Helper()
	governor := &dialGovernor{limit: limit, budget: 40 * time.Millisecond}
	governor.open(time.Now())
	return governor
}

// TestDialGovernorNeverDelaysInteractive is the constraint that decides the design: a person waiting
// on a flow must not be queued behind a bulk one, whatever the governor is doing.
func TestDialGovernorNeverDelaysInteractive(t *testing.T) {
	governor := newGovernor(t, 1)
	// Fill the single slot with a bounded dial.
	release := governor.enter(context.Background(), trafficclass.ClassBulk)
	defer release()

	for _, class := range []trafficclass.Class{trafficclass.ClassInteractive, trafficclass.ClassRealtime} {
		start := time.Now()
		leave := governor.enter(context.Background(), class)
		elapsed := time.Since(start)
		leave()
		if elapsed > 5*time.Millisecond {
			t.Fatalf("%s was delayed by %s; it must never be queued", class, elapsed)
		}
	}
}

// TestDialGovernorIsInertOutsideTheWindow: a steady stream of dials on a working network is not a
// herd, and must not pay for one.
func TestDialGovernorIsInertOutsideTheWindow(t *testing.T) {
	governor := &dialGovernor{limit: 1, budget: 10 * time.Millisecond}
	// No window has ever been opened.

	first := governor.enter(context.Background(), trafficclass.ClassBulk)
	start := time.Now()
	second := governor.enter(context.Background(), trafficclass.ClassBulk)
	elapsed := time.Since(start)
	second()
	first()
	if elapsed > 2*time.Millisecond {
		t.Fatalf("a dial outside the window waited %s", elapsed)
	}
	if governor.activeCount() != 0 {
		t.Fatal("a dial outside the window took a slot")
	}
}

// TestDialGovernorSoftBoundGivesUp pins the trade the governor is allowed to make: it may delay the
// start of a burst, it may never queue behind it indefinitely.
func TestDialGovernorSoftBoundGivesUp(t *testing.T) {
	governor := newGovernor(t, 1)
	release := governor.enter(context.Background(), trafficclass.ClassBulk)
	defer release()

	start := time.Now()
	leave := governor.enter(context.Background(), trafficclass.ClassDefault)
	elapsed := time.Since(start)
	leave()

	if elapsed < 20*time.Millisecond {
		t.Fatalf("the second dial was not held at all (%s); the bound is not applying", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("the second dial waited %s; the bound must give up rather than serialise", elapsed)
	}
}

// TestDialGovernorReleasesItsSlot matters because a leaked slot would shrink the bound permanently
// until the window closed.
func TestDialGovernorReleasesItsSlot(t *testing.T) {
	governor := newGovernor(t, 1)
	release := governor.enter(context.Background(), trafficclass.ClassBulk)
	if governor.activeCount() != 1 {
		t.Fatalf("active = %d, want 1", governor.activeCount())
	}
	release()
	if governor.activeCount() != 0 {
		t.Fatalf("active = %d after release, want 0", governor.activeCount())
	}
	// A double release must not drive the count negative and hand out a phantom slot.
	release()
	if governor.activeCount() != 0 {
		t.Fatalf("active = %d after a double release, want 0", governor.activeCount())
	}
}

// TestTransitionOpensTheGovernorWindow ties the governor to the event it exists for.
func TestTransitionOpensTheGovernorWindow(t *testing.T) {
	h := newDrainHarness(t)
	if h.manager.DialGovernorOpen() {
		t.Fatal("the governor window was open before any transition")
	}
	h.manager.Reclaim(ReclaimNetworkTransition)
	if !h.manager.DialGovernorOpen() {
		t.Fatal("a network transition did not open the governor window")
	}
}

// TestShutdownDoesNotOpenTheGovernorWindow keeps the reasons distinct: teardown is not a herd, and
// opening a window during it would gate dials that are on their way out anyway.
func TestShutdownDoesNotOpenTheGovernorWindow(t *testing.T) {
	h := newDrainHarness(t)
	h.manager.Reclaim(ReclaimShutdown)
	if h.manager.DialGovernorOpen() {
		t.Fatal("shutdown opened the reconnect governor window")
	}
}

// TestGovernorWakesAWaiterOnRelease is the §7 property.
//
// The wait used to retry every 6-18ms until its budget expired. With several dials waiting after a
// transition that is a stream of timer wakeups, scheduler wakeups and mutex contention for the whole
// 500ms - the opposite of what this fork is for. A waiter must now be woken BY the release, not by
// its own polling.
//
// The assertion that separates the two is timing: event-driven wakeup happens in microseconds, and
// the old jitter floor alone was 6ms, so a bound of 2ms cannot be met by polling.
func TestGovernorWakesAWaiterOnRelease(t *testing.T) {
	governor := &dialGovernor{limit: 1, budget: 5 * time.Second}
	governor.open(time.Now())

	holder := governor.enter(context.Background(), trafficclass.ClassBulk)

	wokeAt := make(chan time.Time, 1)
	go func() {
		leave := governor.enter(context.Background(), trafficclass.ClassDefault)
		// Stamped the instant the gate opens, before the deferred release, so the measurement is of
		// the wakeup itself and not of anything the holder did afterwards.
		wokeAt <- time.Now()
		leave()
	}()

	// Let the waiter actually reach its wait, and take the reference time at the release - measuring
	// from the goroutine's start would just measure this sleep.
	time.Sleep(20 * time.Millisecond)
	releasedAt := time.Now()
	holder()

	select {
	case got := <-wokeAt:
		if elapsed := got.Sub(releasedAt); elapsed > 2*time.Millisecond {
			t.Fatalf("the waiter took %s to notice a released slot; it is polling rather than waiting "+
				"to be woken", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiter was never woken by the release")
	}
}

// TestGovernorCancelsAWaiter keeps the context path honest: a caller that has gone away must not be
// left holding a place in the queue.
func TestGovernorCancelsAWaiter(t *testing.T) {
	governor := &dialGovernor{limit: 1, budget: 5 * time.Second}
	governor.open(time.Now())
	holder := governor.enter(context.Background(), trafficclass.ClassBulk)
	defer holder()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		leave := governor.enter(ctx, trafficclass.ClassDefault)
		leave()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter was not released")
	}
}
