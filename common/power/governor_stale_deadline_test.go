package power

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStaleIdleCallbackCannotActOnANewerDeadline is the deterministic version of a race that sleeping
// cannot reliably produce.
//
// time.Timer.Stop() does not recall a callback that has already begun, so this interleaving is
// reachable:
//
//	the old deadline arrives and its callback starts, but has not yet taken the lock
//	ObserveTraffic takes the lock, resets the deadline, and arms a NEW timer
//	the old callback finally takes the lock
//
// At that point the old callback belongs to a deadline that no longer exists. It must not put the
// governor into DEEP_IDLE - the traffic that just arrived bought another DeepIdleAfter - and it must
// not clear the reference to the new timer, which would leave a live timer nobody can stop.
//
// The hook blocks the callback before it takes the lock, so the ordering is forced rather than
// hoped for.
func TestStaleIdleCallbackCannotActOnANewerDeadline(t *testing.T) {
	const after = 80 * time.Millisecond
	governor := NewGovernor(deepIdlePolicy(after))
	t.Cleanup(governor.Close)

	entered := make(chan struct{})
	release := make(chan struct{})
	// The hook runs for EVERY idle deadline, including the replacement, so the signal has to be
	// one-shot: the test only needs to catch the first callback.
	var once sync.Once
	governor.idleCallbackEntered = func() {
		once.Do(func() { close(entered) })
		<-release
	}

	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())

	// The old deadline arrives and its callback is now committed to running, parked before the lock.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the idle callback never started; the test cannot force the interleaving")
	}

	// Real traffic arrives while that callback is still parked. This resets the deadline.
	governor.ObserveTraffic()

	// Now let the obsolete callback proceed.
	close(release)

	// It must not have forced deep idle: the deadline moved to now + after.
	time.Sleep(40 * time.Millisecond)
	require.Equal(t, StateQuiescent, governor.State(),
		"a callback from an obsolete deadline put the governor into DEEP_IDLE before the new deadline elapsed")

	// And the NEW deadline must still be live and still fire - which it cannot be if the obsolete
	// callback cleared the reference to it.
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond,
		"the new deadline never fired: an obsolete callback cleared the reference to a live timer")
}

// TestStaleIdleCallbackCannotClearANewerTimer states the same invariant directly on the reference, so
// a regression is reported as what it is rather than as a state that arrived early.
func TestStaleIdleCallbackCannotClearANewerTimer(t *testing.T) {
	const after = 80 * time.Millisecond
	governor := NewGovernor(deepIdlePolicy(after))
	t.Cleanup(governor.Close)

	entered := make(chan struct{})
	release := make(chan struct{})
	// The hook runs for EVERY idle deadline, including the replacement, so the signal has to be
	// one-shot: the test only needs to catch the first callback.
	var once sync.Once
	governor.idleCallbackEntered = func() {
		once.Do(func() { close(entered) })
		<-release
	}

	governor.DevicePaused()
	<-entered
	governor.ObserveTraffic()

	// A new deadline was armed by the reset.
	require.NotNil(t, governor.idleTimer, "the reset did not arm a new deadline")

	close(release)
	time.Sleep(40 * time.Millisecond)

	require.NotNil(t, governor.idleTimer,
		"an obsolete callback cleared the reference to the live timer, leaving it unstoppable")
}
