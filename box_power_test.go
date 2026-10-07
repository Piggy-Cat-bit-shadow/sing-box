package box

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// TestApplyPauseEventMapsThePlatformVocabulary is the whole bridge, and the only place the
// platform's event names meet the governor's.
//
// A mis-mapped event here would not look like a failure: it would look like a device that never
// sleeps on one platform, or one that never wakes.
func TestApplyPauseEventMapsThePlatformVocabulary(t *testing.T) {
	policy := power.DefaultPolicy()
	policy.DeepIdleAfter = 50 * time.Millisecond
	// This test pins the MAPPING between the two vocabularies, so the wake stagger is off here: with it
	// on, a wake legitimately lands on WAKING, and a mapping failure would be indistinguishable from a
	// stagger doing its job. The stagger has its own tests in common/power.
	policy.WakeStagger = power.WakeStagger{}
	governor := power.NewGovernor(policy)
	t.Cleanup(governor.Close)

	require.Equal(t, power.StateActive, governor.State())

	applyPauseEvent(governor, pause.EventDevicePaused)
	require.Equal(t, power.StateQuiescent, governor.State(), "a device pause must reach the governor")

	applyPauseEvent(governor, pause.EventDeviceWake)
	require.Equal(t, power.StateActive, governor.State(), "a device wake must reach the governor")

	applyPauseEvent(governor, pause.EventNetworkPause)
	require.Equal(t, power.StateQuiescent, governor.State(), "a network pause must reach the governor")

	applyPauseEvent(governor, pause.EventNetworkWake)
	require.Equal(t, power.StateActive, governor.State(), "a network wake must reach the governor")

	// An event this fork does not map must be ignored rather than treated as a wake: the vocabularies
	// are separate, and a new constant upstream must not silently disable the policy.
	applyPauseEvent(governor, pause.EventNetworkPause)
	applyPauseEvent(governor, 999)
	require.Equal(t, power.StateQuiescent, governor.State(), "an unknown event changed the state")

	// And with the SHIPPING policy a wake must land on WAKING, not ACTIVE: the mapping still has to
	// carry the event, and the governor has to stagger what follows it. Without this, zeroing the
	// stagger above would quietly stop this test from covering wakes at all.
	shipping := power.NewGovernor(power.DefaultPolicy())
	t.Cleanup(shipping.Close)
	applyPauseEvent(shipping, pause.EventDevicePaused)
	applyPauseEvent(shipping, pause.EventDeviceWake)
	require.Equal(t, power.StateWaking, shipping.State(),
		"a wake released every speculative subsystem at once")

	// And a nil governor, which is what a Box without the wiring has, must not panic.
	applyPauseEvent(nil, pause.EventDevicePaused)
}
