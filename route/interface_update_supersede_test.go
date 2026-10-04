package route

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

// A superseding interface notification must not have its pending reset consumed by the update it
// replaced.
//
// # The interleaving
//
// updateInterface decides whether to consume networkResetPending in two steps that are not one
// decision:
//
//	if ctx.Err() == nil {                 // (1) checked OUTSIDE the lock
//	    r.interfaceUpdateAccess.Lock()
//	    if r.networkResetPending {        // (2) consumed INSIDE the lock
//	        r.networkResetPending = false
//	        ...
//
// notifyInterfaceUpdate does its work under that same lock: it arms the flag and cancels the
// in-flight update's context. So the two can interleave as
//
//	old update:   ctx.Err() == nil                  <- passed, still looks current
//	new notify:   lock; networkResetPending = true; cancel(oldCtx); unlock
//	old update:   lock; sees the NEW pending; clears it; unlock
//
// and the new event's reset is gone: its own update finds nothing pending. The window is a single
// instruction wide, which is precisely why it cannot be found by running the old arrangement and
// hoping - it is found by holding the update at (1) and letting the notification land.
//
// # What these tests do
//
// They park the update between (1) and (2) with a barrier, deliver the superseding notification, and
// then release. No sleep orders anything; every step is signalled.

// parkUpdate installs the decision hook so the update signals on the way in and waits to be let go.
//
// It returns the two channels the test drives, and restores the hook on cleanup so no other test in
// the package sees it.
func parkUpdate(t *testing.T, h *transitionWindowHarness) (atDecision chan struct{}, release chan struct{}) {
	t.Helper()
	atDecision = make(chan struct{})
	release = make(chan struct{})
	// The hook parks exactly ONE update - the first to reach the window - and is a no-op for every
	// later one, so the superseding update performed at the end of the test runs normally instead of
	// parking as well.
	var parked atomic.Bool
	h.manager.interfaceUpdateDecision = func() {
		if parked.CompareAndSwap(false, true) {
			close(atDecision)
			<-release
		}
	}
	t.Cleanup(func() { h.manager.interfaceUpdateDecision = nil })
	return atDecision, release
}

// testDefaultInterface is the interface every update in these tests reports.
func testDefaultInterface() *control.Interface {
	return &control.Interface{Index: 1, Name: "en0"}
}

// TestSupersededUpdateDoesNotConsumeTheNewPendingReset is the reproduction.
//
// The hook parks the update BETWEEN its context check and its pending consumption - the window the
// defect lives in. Because the hook runs inside interfaceUpdateAccess, the notification that
// supersedes it must be delivered by the update's own cancellation path rather than by the test
// taking the lock, so the sequence is:
//
//  1. the update passes its context check and parks in the window
//  2. a superseding notification arrives (a second notifyInterfaceUpdate)
//  3. it arms the flag for its own update and cancels this one
//  4. the parked update is released and must NOT consume that flag
func TestSupersededUpdateDoesNotConsumeTheNewPendingReset(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	// The OLD update's own reason, so there is something for it to wrongly consume and so the two
	// updates' resets can be told apart.
	h.manager.interfaceUpdateAccess.Lock()
	h.manager.networkResetPending = true
	h.manager.interfaceUpdateAccess.Unlock()

	oldCtx, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()

	atDecision, release := parkUpdate(t, h)

	oldDone := make(chan struct{})
	go func() {
		defer close(oldDone)
		h.manager.updateInterface(oldCtx, testDefaultInterface())
	}()

	// 1. The old update has passed its context check and is parked in the window.
	select {
	case <-atDecision:
	case <-time.After(10 * time.Second):
		t.Fatal("the update never reached its decision point")
	}

	// 2/3. The superseding notification: arm the flag for the NEW update and cancel the old context.
	// This is what notifyInterfaceUpdate does, in the order it does it.
	//
	// It cannot take interfaceUpdateAccess here - the parked update holds it - so the flag is armed
	// through the same field the notifier writes, and the cancellation is what the parked update will
	// observe. That is the interleaving under test: the cancellation happens AFTER the update's
	// context check has already passed.
	h.manager.networkResetPending = true
	cancelOld()

	// 4. Release the parked update.
	close(release)
	select {
	case <-oldDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the old update did not finish")
	}

	h.manager.interfaceUpdateAccess.Lock()
	stillPending := h.manager.networkResetPending
	h.manager.interfaceUpdateAccess.Unlock()

	require.True(t, stillPending,
		"the superseded update consumed the pending reset belonging to the notification that "+
			"cancelled it. That notification's own update now finds nothing to do, so the interface "+
			"change it announced is silently dropped")

	// The new update performs it.
	h.manager.updateInterface(h.manager.startedCtx, testDefaultInterface())
	require.Equal(t, int(base+1), dnsResetCount(h.router),
		"the superseding notification's reset must still be performed exactly once")
}

// TestUpdateThatIsNotSupersededStillConsumes covers the other side: an update that owns its event
// must consume and reset, or the flag would be left armed for an update that never comes.
func TestUpdateThatIsNotSupersededStillConsumes(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	h.manager.interfaceUpdateAccess.Lock()
	h.manager.networkResetPending = true
	h.manager.interfaceUpdateAccess.Unlock()

	h.manager.updateInterface(h.manager.startedCtx, testDefaultInterface())

	require.Equal(t, int(base+1), dnsResetCount(h.router), "an un-superseded update performs its reset")
	h.manager.interfaceUpdateAccess.Lock()
	pending := h.manager.networkResetPending
	h.manager.interfaceUpdateAccess.Unlock()
	require.False(t, pending, "the consumed flag must be cleared, not left armed")
}

// TestSupersededUpdateDoesNotResetForItsOwnStaleEnvironment covers the environment half.
//
// An update that has been superseded must not run a reset on behalf of the state it recomputed: the
// superseding event owns that work, and running both would be two resets for one transition.
func TestSupersededUpdateDoesNotResetForItsOwnStaleEnvironment(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	// A superseded update, cancelled before it acts, with a changed environment of its own.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	h.setSSID("B")

	h.manager.updateInterface(cancelledCtx, testDefaultInterface())

	require.Equal(t, int(base), dnsResetCount(h.router),
		"a cancelled update ran a reset for an environment it no longer owns; the superseding event "+
			"will establish the boundary, so this one is a stale reset with no event behind it")
}

// TestSupersedeUsesRealNotifyInterfaceUpdate is the regression for the notifier's own lock discipline.
//
// # Why the synthetic version is not enough
//
// The older test parked the update inside interfaceUpdateAccess and then wrote networkResetPending
// directly, because a real notifyInterfaceUpdate could not be delivered while that lock was held. That
// reproduces the CONSUMPTION ordering but not the notifier's protocol: it never exercised
// notifyInterfaceUpdate taking the lock, arming the flag and cancelling the in-flight update.
//
// # How the update is started
//
// Through the production dispatch, so its context really is the one registered in
// interfaceUpdateCancel. A hand-built context would not be cancellable by the notifier at all, and the
// test would then be asserting something the code cannot do.
//
// # The interleaving
//
//	1  dispatch starts update A and registers its cancel
//	2  A reaches the pre-lock gate and parks, past its context check, not yet holding the lock
//	3  a REAL notifyInterfaceUpdate runs: arms the flag, cancels A, dispatches B
//	4  A is released and must neither consume the flag nor reset
func TestSupersedeUsesRealNotifyInterfaceUpdate(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()
	baseResets := dnsResetCount(h.router)

	atGate := make(chan struct{})
	release := make(chan struct{})
	var parked atomic.Bool
	// The hook parks only the first update and leaves the field alone afterwards: writing it from the
	// parked goroutine would race the cleanup that clears it. Later updates - the successor the
	// notifier dispatches - see a hook that is still installed and simply do not park.
	h.manager.interfaceUpdateBeforeLock = func() {
		if parked.CompareAndSwap(false, true) {
			close(atGate)
			<-release
		}
	}
	t.Cleanup(func() { h.manager.interfaceUpdateBeforeLock = nil })

	// 1. Start update A through the production dispatch, which registers its cancel.
	h.manager.interfaceUpdateAccess.Lock()
	h.manager.dispatchInterfaceUpdateLocked()
	h.manager.interfaceUpdateAccess.Unlock()

	// 2. A parks at the gate.
	select {
	case <-atGate:
	case <-time.After(10 * time.Second):
		t.Fatal("the dispatched update never reached the pre-lock gate")
	}

	// 3. A real notification.
	notifierDone := make(chan struct{})
	go func() {
		defer close(notifierDone)
		h.manager.notifyInterfaceUpdate(testDefaultInterface(), 0)
	}()
	select {
	case <-notifierDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the real notification did not complete")
	}

	// 4. Release A. Its cancellation was already observed by the notifier, so it must now finish
	// WITHOUT consuming the flag.
	close(release)

	// Wait for the reset that the notification's own dispatched update performs. Joining on the
	// router's own signal is what keeps this test from leaving a goroutine behind: the successor is
	// started by notifyInterfaceUpdate and would otherwise still be running when the test ends,
	// touching a manager the next test owns.
	// The successor was dispatched by notifyInterfaceUpdate and reads the hook as it enters. Join on
	// its reset before the cleanup clears the hook, or the write races the read.
	// The harness already performed one reset while settling on A, so the threshold is that count
	// plus one, not a bare 1.
	require.True(t, h.router.waitForCount(baseResets+1, 10*time.Second),
		"the notification's own update must establish the boundary exactly once. It is the update "+
			"that owns the event; if the superseded one consumed the flag, nothing would reset at all")

	require.Equal(t, baseResets+1, dnsResetCount(h.router),
		"exactly one reset for one notification")
	require.EqualValues(t, base+1, h.manager.NetworkResetGeneration(),
		"and exactly one epoch for one logical transition")
}
