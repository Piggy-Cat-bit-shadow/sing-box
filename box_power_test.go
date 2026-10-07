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

	// And a nil governor, which is what a Box without the wiring has, must not panic.
	applyPauseEvent(nil, pause.EventDevicePaused)
}
