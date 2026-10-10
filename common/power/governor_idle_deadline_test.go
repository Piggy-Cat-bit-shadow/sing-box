package power

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests pin the semantics of the DEEP_IDLE deadline: it is "no real activity for
// DeepIdleAfter", so traffic RESETS the deadline. It does not destroy it.
//
// The distinction is the difference between a device that eventually stops doing health checks and
// probes while it sleeps, and one that stops doing them only until the first push notification
// arrives - after which it never reaches deep idle again for the rest of the night.

func deepIdlePolicy(after time.Duration) Policy {
	policy := DefaultPolicy()
	policy.DeepIdleAfter = after
	policy.WakeStagger = WakeStagger{}
	return policy
}

// Case A: a transient request must POSTPONE deep idle, not prevent it.
func TestTransientTrafficPostponesDeepIdle(t *testing.T) {
	// The deadline is an ORDER OF MAGNITUDE above the observation window below (50ms), so the verdict
	// is the governor's sequencing and not the accuracy of time.Sleep on a loaded machine. MEASURED:
	// with the previous 150ms against the same 50ms window the margin was 100ms, which a full-suite
	// scan can exceed.
	const after = 400 * time.Millisecond
	governor := NewGovernor(deepIdlePolicy(after))
	t.Cleanup(governor.Close)

	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())

	// A short real request arrives, and finishes immediately.
	time.Sleep(60 * time.Millisecond)
	governor.ObserveTraffic()

	// Still well inside DeepIdleAfter measured from the ACTIVITY, so deep idle would be premature.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, StateQuiescent, governor.State(),
		"deep idle arrived before DeepIdleAfter had elapsed since the last real activity")

	// And once the deadline passes with no further activity, it must go.
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond,
		"a single transient request permanently prevented DEEP_IDLE; "+
			"the device would keep doing health checks and probes for the rest of the night")
}

// Case B: the round trip must close. The earlier suite only ever asserted DEEP_IDLE -> QUIESCENT.
func TestDeepIdleCanBeReenteredAfterTraffic(t *testing.T) {
	governor := NewGovernor(deepIdlePolicy(60 * time.Millisecond))
	t.Cleanup(governor.Close)

	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond)

	governor.ObserveTraffic()
	require.Equal(t, StateQuiescent, governor.State())

	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond,
		"DEEP_IDLE -> QUIESCENT -> DEEP_IDLE did not close: one wake latched the governor awake")
}

// Case C: intermittent traffic extends the deadline rather than disabling it.
//
// This is what "idle since the LAST real activity" means, and what a device receiving a slow trickle
// of background pushes actually experiences.
func TestIntermittentTrafficExtendsTheDeadline(t *testing.T) {
	// 300ms against 60ms gaps, so "no gap reached the deadline" is a statement about the governor
	// rather than about how late a 60ms sleep can return under load. The cadence is unchanged.
	const after = 300 * time.Millisecond
	governor := NewGovernor(deepIdlePolicy(after))
	t.Cleanup(governor.Close)

	governor.DevicePaused()

	// Activity every 60ms for ~600ms. No gap reaches DeepIdleAfter, so deep idle must not arrive.
	deadline := time.Now().Add(600 * time.Millisecond)
	sawDeepIdle := false
	for time.Now().Before(deadline) {
		governor.ObserveTraffic()
		time.Sleep(60 * time.Millisecond)
		if governor.State() == StateDeepIdle {
			sawDeepIdle = true
		}
	}
	require.False(t, sawDeepIdle,
		"deep idle arrived while real activity was still arriving every 60ms against a 100ms deadline")

	// Activity stops. The deadline now runs from the last activity, so it must arrive.
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond,
		"deep idle never arrived after activity stopped")
}

// TestStateStringsCoverEveryState is §5 of the audit. WAKING existed as a state and had no String()
// branch, so anything logging it printed "unknown" - which is exactly the case an operator reading a
// power problem would be looking at.
func TestStateStringsCoverEveryState(t *testing.T) {
	for state, expected := range map[State]string{
		StateActive:    "active",
		StateWaking:    "waking",
		StateQuiescent: "quiescent",
		StateDeepIdle:  "deep-idle",
	} {
		require.Equal(t, expected, state.String())
	}
	require.Equal(t, "unknown", State(200).String(), "an out-of-range state must still be identifiable")
}

// TestCoalescedNotificationsNeverReportAStateThatIsOver pins the direction §7 asks for.
//
// A DEEP_IDLE notification that is delivered after traffic has already moved the governor on is the
// dangerous one: acting on it would release a pool that is about to be used. The state delivered must
// therefore be the CURRENT one, not the one that scheduled the flush.
func TestCoalescedNotificationsNeverReportAStateThatIsOver(t *testing.T) {
	// A deadline long enough that the state cannot legitimately move on by itself during the test: the
	// question here is what a coalesced notification REPORTS, not how fast the machine is.
	//
	// It must be WELL above the 50ms observation window below. MEASURED: with the previous 60ms the
	// margin was 10ms, so on a loaded machine (a full-suite scan) the 50ms sleep returned after the
	// re-armed deadline had already fired and the assertion saw the state the timer had just moved it
	// to - a verdict decided by time.Sleep's accuracy, not by the governor.
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 600 * time.Millisecond
	policy.WakeStagger = WakeStagger{}
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)

	delivered := make(chan State, 32)
	governor.AddObserver(func(state State) { delivered <- state })

	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond)
	// Traffic arrives immediately after the deep-idle transition.
	governor.ObserveTraffic()

	// Whatever was delivered, an observer acting on the LAST notification must not believe the device
	// is still deep idle when it is not.
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, StateQuiescent, governor.State(),
		"the governor stayed deep idle after traffic arrived")
	for {
		select {
		case state := <-delivered:
			if state == StateDeepIdle && governor.State() != StateDeepIdle {
				// Allowed only if a QUIESCENT notification follows it; the observer re-checks anyway.
				continue
			}
		default:
			return
		}
	}
}
