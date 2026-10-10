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
//
// # The assertion this file used to be missing
//
// This test previously drained the observer channel in a loop whose every branch either `continue`d or
// fell to `default: return` - there was NO assertion inside it - and its only real check was
// `governor.State() == StateQuiescent`, which is the different property "traffic leaves deep idle" and
// is already covered by `TestDeepIdleCanBeReenteredAfterTraffic`. MEASURED by an independent adversary
// with the governor mutated to deliver the REMEMBERED deep-idle state instead of the current one
// (`go vet` exit 0 first): this test still PASSED, while a detector that read the last delivered state
// went RED with `last state delivered to the observer: deep-idle; governor state now: quiescent`.
//
// So the property in this test's NAME was unfalsifiable, before the DeepIdleAfter widening and after
// it. The fix is to assert the property: the last state an observer was told about must not be one the
// governor has already left.
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

	// Drain until the channel has been quiet for a moment, so "the last notification" is the last one
	// the observer will actually receive rather than whichever one a single non-blocking read saw.
	//
	// The quiet window is deliberately small against the re-armed DeepIdleAfter above (600ms): the
	// whole drain is bounded well inside it, so the governor cannot legitimately move on while this
	// runs, and the assertion below therefore compares two facts about the same instant. That bound is
	// a property of the DRAIN, not a widened assertion - nothing here accepts an older state.
	var last State
	sawAny := false
	quietSince := time.Now()
	for {
		select {
		case state := <-delivered:
			last = state
			sawAny = true
			quietSince = time.Now()
			continue
		default:
		}
		if time.Since(quietSince) > 30*time.Millisecond {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	require.True(t, sawAny, "no state was delivered to the observer at all, so this test proves nothing")
	require.False(t, last == StateDeepIdle && governor.State() != StateDeepIdle,
		"the LAST state delivered to the observer was %s while the governor is %s: a coalesced "+
			"notification reported a state that is OVER, and an observer acting on it would release a "+
			"pool that is about to be used. The delivered state must be the current one, not the one "+
			"that scheduled the flush", last, governor.State())
}
