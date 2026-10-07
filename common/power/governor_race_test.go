package power

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The tests in this file are adversarial. Each one tries to reproduce a failure the brief names in
// its concurrency section, and they exist because "it holds a mutex" is not evidence: every one of
// these is a case where a correct-looking implementation with the same lock still goes wrong.

// TestRapidPauseWakeIsIdempotent is §16.1. The platform delivers these in bursts, and the machine
// must end up where the LAST signal put it rather than where a racing timer did.
func TestRapidPauseWakeIsIdempotent(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{HealthCheck: 20 * time.Millisecond})

	for i := 0; i < 200; i++ {
		governor.DevicePaused()
		governor.DeviceWake()
	}
	// Last signal was a wake.
	require.NotEqual(t, StateQuiescent, governor.State(),
		"a burst ending in a wake left the governor suppressed")
	require.NotEqual(t, StateDeepIdle, governor.State())

	for i := 0; i < 200; i++ {
		governor.DeviceWake()
		governor.DevicePaused()
	}
	require.Equal(t, StateQuiescent, governor.State(),
		"a burst ending in a pause left the governor running speculative work")
}

// TestStaleIdleTimerCannotOutliveItsWake is §16.2 and §16.3 together.
//
// This is the dangerous shape the brief describes: the pause arms a timer, the wake arrives, and the
// OLD timer fires afterwards. Without a check on the era it belongs to, it promotes a device that is
// awake into deep idle - and the user's next request is handled by a governor that has stopped
// everything.
func TestStaleIdleTimerCannotOutliveItsWake(t *testing.T) {
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 60 * time.Millisecond
	policy.WakeStagger = WakeStagger{}
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)

	governor.DevicePaused()
	// Well past DeepIdleAfter, but the wake lands first.
	governor.DeviceWake()
	require.Equal(t, StateActive, governor.State())

	// The stale idle timer fires somewhere in here.
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, StateActive, governor.State(),
		"the idle timer from a pause that already ended promoted an awake device to deep idle")
}

// TestStaleWakeTimerCannotOutliveItsPause is the mirror image: the stagger's timer belongs to a wake
// that a new pause has already superseded, and it must not release work onto a sleeping device.
func TestStaleWakeTimerCannotOutliveItsPause(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{HealthCheck: 60 * time.Millisecond})

	governor.DevicePaused()
	governor.DeviceWake()
	require.Equal(t, StateWaking, governor.State())

	// Pause again while the stagger is still outstanding.
	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())

	// The wake timer fires somewhere in here.
	//
	// What must not happen is the superseded wake releasing work onto a sleeping device. That the
	// device has since gone DEEP IDLE is the machine working, not failing - a paused device with no
	// traffic is supposed to get there - so the assertion is on the release, not on the exact state.
	// Asserting QUIESCENT here would have been asserting that deep idle is broken.
	time.Sleep(200 * time.Millisecond)
	require.NotEqual(t, StateActive, governor.State(),
		"a wake timer from a superseded wake made a sleeping device active")
	require.NotEqual(t, StateWaking, governor.State(),
		"a wake timer from a superseded wake left a sleeping device mid-stagger")
	require.Equal(t, Allow{}, governor.Allow(),
		"a wake timer from a superseded wake released speculative work")
}

// TestCloseDuringPendingTimersIsSafe is the third failure §16.2 names: a timer callback running after
// the object it belongs to has been torn down.
//
// The tunnel is stopped on every disconnect and the governor is closed with it, so this runs in the
// field whenever a user turns the VPN off while the phone is asleep.
func TestCloseDuringPendingTimersIsSafe(t *testing.T) {
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 30 * time.Millisecond
	policy.WakeStagger = WakeStagger{HealthCheck: 30 * time.Millisecond}
	governor := NewGovernor(policy)

	governor.DevicePaused()
	governor.DeviceWake()   // arms the wake timer
	governor.DevicePaused() // arms the idle timer
	governor.Close()
	governor.Close()

	require.NotPanics(t, func() {
		time.Sleep(150 * time.Millisecond)
	})
	require.False(t, governor.Active(), "a closed governor must not report itself usable")
}

// TestAClosedGovernorDoesNotPolluteTheNextOne is §16.4. A service reload builds a new governor, and a
// tunnel stopped while asleep must not leave the next one believing the device is still paused.
func TestAClosedGovernorDoesNotPolluteTheNextOne(t *testing.T) {
	first := NewGovernor(DefaultPolicy())
	first.DevicePaused()
	require.Equal(t, StateQuiescent, first.State())
	first.Close()

	second := NewGovernor(DefaultPolicy())
	t.Cleanup(second.Close)
	require.Equal(t, StateActive, second.State(),
		"a governor built after a paused one inherited the pause")
	require.Equal(t, allowAll, second.Allow())
}

// TestPauseAndWakeAreNotRefcounted is §16.5, and it pins a decision rather than a behaviour.
//
// The brief asks whether a refcount is really needed and notes that asymmetric counting is a failure
// mode in itself. It is not needed here: pause and wake are EDGES from a platform that reports state,
// not borrowed resources, so the machine holds a boolean and the last signal wins. A refcount would
// additionally mean a missed wake leaves the device permanently suppressed, which is the failure this
// whole package exists to avoid.
func TestPauseAndWakeAreNotRefcounted(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{})

	governor.DevicePaused()
	governor.DevicePaused()
	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())

	// One wake must clear an arbitrary number of pauses, because the platform is reporting a state and
	// not acquiring a lock.
	governor.DeviceWake()
	require.Equal(t, StateActive, governor.State(),
		"wake did not clear every pause: the signals are being counted as if they were borrowed")
}

// TestSignalStormIsRaceFree drives every entry point concurrently. It is a race-detector test first
// and a correctness test second: the assertions are deliberately weak because the ORDER is genuinely
// undefined, and the point is that no interleaving corrupts the machine or trips the detector.
func TestSignalStormIsRaceFree(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{HealthCheck: 5 * time.Millisecond})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				governor.DevicePaused()
				governor.DeviceWake()
				governor.NetworkPaused()
				governor.NetworkWake()
				governor.ObserveTraffic()
				_ = governor.Allow()
				_ = governor.State()
				_ = governor.Active()
			}
		}()
	}
	wg.Wait()

	// Whatever the interleaving, it must still be a state the machine defines.
	require.Contains(t, []State{StateActive, StateWaking, StateQuiescent, StateDeepIdle},
		governor.State())
}
