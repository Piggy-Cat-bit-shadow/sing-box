package power

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Agent F, round 2: the detector that TestCoalescedNotificationsNeverReportAStateThatIsOver does not
// contain.
//
// # The claim, and the hole in its detector
//
// governor_idle_deadline_test.go:117-121 states the property precisely: "A DEEP_IDLE notification that
// is delivered after traffic has already moved the governor on is the dangerous one: acting on it
// would release a pool that is about to be used. The state delivered must therefore be the CURRENT
// one, not the one that scheduled the flush."
//
// The test that carries that name asserts it with a drain loop at :150-159 whose every branch either
// `continue`s or falls to `default: return`. There is no assertion inside it, so no product behaviour
// can make it fail. Its only real assertion is :148 (`governor.State() == StateQuiescent`), which is
// the DIFFERENT property "traffic leaves deep idle" - a property already covered by Case B,
// TestDeepIdleCanBeReenteredAfterTraffic at :63.
//
// MEASURED: with the governor mutated so that every notification after the first DEEP_IDLE transition
// reports the STALE DEEP_IDLE while State() is QUIESCENT - exactly the "state that scheduled the
// flush" - TestCoalescedNotificationsNeverReportAStateThatIsOver still PASSES.
//
// # What this file asserts instead
//
// The property as the comment states it, expressed so that it can fail: once the transitions have
// settled, the last state the OBSERVER was told must be the state the governor is actually in. An
// observer acting on the last notification is the hazard named above, so the last notification is the
// thing to check.
//
// Both directions are asserted, because a drain that finds nothing would otherwise pass vacuously:
// the observer must have been told something, AND what it was last told must be current.

func TestAgentFLastCoalescedNotificationMustBeTheCurrentState(t *testing.T) {
	// The same window the production test uses, widened from 60ms to 600ms by the round that fixed a
	// full-suite flake. A deadline this far above the observation window is what makes the
	// measurement a statement about the governor rather than about time.Sleep.
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 600 * time.Millisecond
	policy.WakeStagger = WakeStagger{}
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)

	delivered := make(chan State, 64)
	governor.AddObserver(func(state State) { delivered <- state })

	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		2*time.Second, 5*time.Millisecond, "precondition: the governor must reach deep idle")

	// Traffic arrives while the observer may still be holding a DEEP_IDLE notification.
	governor.ObserveTraffic()
	require.Eventually(t, func() bool { return governor.State() == StateQuiescent },
		2*time.Second, 5*time.Millisecond, "precondition: traffic must move the governor off deep idle")

	// Let any in-flight flush land, then read what the observer was last told.
	time.Sleep(50 * time.Millisecond)

	var (
		last     State
		observed bool
	)
	for {
		select {
		case state := <-delivered:
			last = state
			observed = true
			continue
		default:
		}
		break
	}

	// Direction 1: the instrument must be armed, or direction 2 proves nothing.
	require.True(t, observed,
		"no state was ever delivered to the observer, so this test would pass vacuously")

	// Direction 2: the property the production test names, in a form that can fail.
	current := governor.State()
	t.Logf("MEASURED last state delivered to the observer: %s; governor state now: %s", last, current)
	require.Equal(t, current, last,
		"the last notification an observer received was %s while the governor is %s: acting on it "+
			"would release a pool that is about to be used, which is the hazard this property exists "+
			"to name", last, current)
}
