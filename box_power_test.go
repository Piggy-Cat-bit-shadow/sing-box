package box

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing/service"
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

// TestFailedConstructionDoesNotLeakThePauseCallback is the lifecycle half of the power wiring.
//
// The governor and its callback are registered early in NewBox, and there are many ways to fail
// afterwards. The manager is not necessarily ours: WithDefaultManager returns an EXISTING manager
// unchanged, and the libbox path supplies one, so a callback left behind would keep calling into a
// governor whose Box was never returned - for every device pause and wake, for the life of the
// process.
//
// The assertions are on observable behaviour rather than on the list internals: a callback that is
// still registered is one that still runs.
func TestFailedConstructionDoesNotLeakThePauseCallback(t *testing.T) {
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)

	var calls atomic.Int32
	governor := power.NewGovernor(power.DefaultPolicy())
	callback := manager.RegisterCallback(func(int) { calls.Add(1) })

	// Registered: a pause reaches the callback.
	manager.DevicePause()
	require.Equal(t, int32(1), calls.Load(), "a registered callback did not receive the pause")
	manager.DeviceWake()
	require.Equal(t, int32(2), calls.Load())

	// The construction fails, so the registration is undone.
	releasePowerGovernor(governor, manager, callback)

	manager.DevicePause()
	manager.DeviceWake()
	require.Equal(t, int32(2), calls.Load(),
		"a callback survived a failed construction: it would keep signalling a governor whose Box was never returned")

	// And the governor it belonged to is closed, so it cannot authorise work either.
	require.False(t, governor.Active())
}

// TestReleasePowerGovernorToleratesNils keeps the teardown safe on the paths where only part of the
// wiring was reached.
func TestReleasePowerGovernorToleratesNils(t *testing.T) {
	require.NotPanics(t, func() {
		releasePowerGovernor(nil, nil, nil)
	})
	require.NotPanics(t, func() {
		releasePowerGovernor(power.NewGovernor(power.DefaultPolicy()), nil, nil)
	})
}

// TestApplyPauseEventPublishesTheReuseEdges is the mapping's second half, and the half that was
// missing: the platform vocabulary must reach the reuse epoch as well as the state machine.
//
// A mis-mapping here is invisible from the outside - the tunnel still pauses and still wakes - and
// it is exactly the shape of the shipped defect: the device axis moves, the reusable state is never
// distrusted, and the first request after an unlock is handed a socket that the sleep killed.
//
// The shipping thresholds are moved rather than the clock, because the governor's clock is its own
// and this package must not reach into it: what is under test is the mapping, and the tuning has its
// own tests in common/power.
func TestApplyPauseEventPublishesTheReuseEdges(t *testing.T) {
	policy := power.DefaultPolicy()
	policy.WakeStagger = power.WakeStagger{}
	policy.ReuseFreshness = power.ReuseFreshness{
		SuspectAfter: 5 * time.Second,
		RetireAfter:  15 * time.Second,
	}
	// An injected clock, so the boundary is measured exactly rather than waited for: the sleep this
	// test asserts is 30 seconds, and no test should take thirty seconds to say so.
	now := time.Unix(1700000000, 0)
	var elapsed time.Duration
	clock := func() time.Time { return now.Add(elapsed) }
	governor := power.NewGovernorWithClock(policy, clock)
	t.Cleanup(governor.Close)

	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	applyPauseEvent(governor, pause.EventDevicePaused)
	require.Equal(t, power.StateQuiescent, governor.State())
	require.Zero(t, governor.ReuseEpoch(), "a pause is not a boundary")

	// A sleep long enough for the policy to act on.
	elapsed = 30 * time.Second
	applyPauseEvent(governor, pause.EventDeviceWake)

	require.Len(t, boundaries, 1, "the device wake did not publish a reuse boundary")
	require.Equal(t, power.ReuseRetire, boundaries[0].Action)
	require.Equal(t, uint64(1), governor.ReuseEpoch())
	require.Equal(t, power.StateActive, governor.State(), "the wake no longer moves the device axis")

	// A network wake is neither an edge nor a level for the reuse epoch: it must not publish one, and
	// it must not consume the next device boundary either.
	applyPauseEvent(governor, pause.EventDevicePaused)
	applyPauseEvent(governor, pause.EventNetworkPause)
	applyPauseEvent(governor, pause.EventNetworkWake)
	require.Len(t, boundaries, 1, "a network wake published a reuse boundary")
	elapsed += 30 * time.Second
	applyPauseEvent(governor, pause.EventDeviceWake)
	require.Len(t, boundaries, 2, "the device boundary after the network transition was lost")
	require.Equal(t, uint64(2), governor.ReuseEpoch())
}
