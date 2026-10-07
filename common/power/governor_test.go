package power

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestGovernor builds a governor whose deep-idle threshold is short enough to reach in a test.
func newTestGovernor(t *testing.T) *Governor {
	t.Helper()
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 40 * time.Millisecond
	// These tests pin the pause/wake machine itself, so the wake stagger is switched off here; it has
	// its own tests below, which would otherwise be indistinguishable from a wake that never completes.
	policy.WakeStagger = WakeStagger{}
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)
	return governor
}

// TestActiveAllowsEverything is the compatibility guarantee: a build where nothing ever pauses must
// behave exactly as it did before this package existed.
func TestActiveAllowsEverything(t *testing.T) {
	governor := newTestGovernor(t)
	require.Equal(t, StateActive, governor.State())
	require.Equal(t, allowAll, governor.Allow())
	require.True(t, governor.Active())
}

// TestDevicePauseSuppressesOnlySpeculativeWork is the QUIESCENT contract.
//
// Speculative maintenance stops, because it costs radio to learn nothing while the device is asleep.
// Health checking and probing stay on, because a tunnel whose liveness nobody checks is one that
// fails silently the moment the user picks the phone up.
func TestDevicePauseSuppressesOnlySpeculativeWork(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()

	require.Equal(t, StateQuiescent, governor.State())
	allow := governor.Allow()
	require.True(t, allow.HealthCheck, "health checks must survive a device pause")
	require.True(t, allow.NetworkProbe, "probing must survive a device pause")
	require.False(t, allow.ProviderRefresh, "provider refresh is speculative")
	require.False(t, allow.Statistics, "UI statistics are speculative")
	require.False(t, governor.Active())
}

// TestDeepIdleAfterSilenceStopsEverything is the other end of the machine.
func TestDeepIdleAfterSilenceStopsEverything(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()

	require.Eventually(t, func() bool {
		return governor.State() == StateDeepIdle
	}, 3*time.Second, 5*time.Millisecond, "a paused device with no traffic must reach deep idle")

	require.Equal(t, Allow{}, governor.Allow(), "deep idle permits no speculative work")
}

// TestTrafficDoesNotReEnableMaintenance is the §5 requirement, and the one most easily got wrong.
//
// A push notification arriving while the phone is in a pocket makes the phone forward one request.
// Returning the whole governor to ACTIVE for that would re-enable provider refresh, probing and
// statistics for every subsystem at once - the wake storm the brief names. The traffic gets its link;
// the maintenance stays asleep.
func TestTrafficDoesNotReEnableMaintenance(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())

	governor.ObserveTraffic()

	require.Equal(t, StateQuiescent, governor.State(),
		"traffic returned the governor to ACTIVE, which re-enables every speculative subsystem")
	require.False(t, governor.Allow().ProviderRefresh)
	require.False(t, governor.Allow().Statistics)
}

// TestTrafficPreventsDeepIdle is what "traffic-driven" buys: the countdown is disarmed by real use,
// so a device that is being used is never treated as idle however long the screen has been off.
func TestTrafficPreventsDeepIdle(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		governor.ObserveTraffic()
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, StateQuiescent, governor.State(),
		"a paused device that keeps carrying traffic was treated as idle")
}

// TestTrafficLiftsDeepIdleToQuiescent keeps the machine from latching: once traffic arrives, the link
// carrying it gets the maintenance QUIESCENT permits, without going all the way to ACTIVE.
func TestTrafficLiftsDeepIdleToQuiescent(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		3*time.Second, 5*time.Millisecond)

	governor.ObserveTraffic()
	require.Equal(t, StateQuiescent, governor.State())
}

// TestDeviceWakeRestoresEverything is the recovery path.
func TestDeviceWakeRestoresEverything(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		3*time.Second, 5*time.Millisecond)

	governor.DeviceWake()
	require.Equal(t, StateActive, governor.State())
	require.Equal(t, allowAll, governor.Allow())
}

// TestNetworkPauseSuppressesWhileTheDeviceIsAwake covers the other signal.
//
// With no path, a health check or a probe cannot succeed; running one spends radio to learn nothing.
func TestNetworkPauseSuppressesWhileTheDeviceIsAwake(t *testing.T) {
	governor := newTestGovernor(t)

	governor.NetworkPaused()
	require.Equal(t, StateQuiescent, governor.State(), "a device with no path is not active")

	governor.NetworkWake()
	require.Equal(t, StateActive, governor.State())
}

// TestWaitActiveWakesOnATransition is the alternative to polling: a subsystem waits for the device
// instead of running a ticker that discovers it is asleep.
func TestWaitActiveWakesOnATransition(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()

	done := make(chan bool, 1)
	go func() {
		done <- governor.WaitActive(context.Background())
	}()

	time.Sleep(20 * time.Millisecond)
	governor.DeviceWake()

	select {
	case active := <-done:
		require.True(t, active, "WaitActive must report active once the device wakes")
	case <-time.After(2 * time.Second):
		t.Fatal("WaitActive did not return after the device woke; a waiter would have to poll")
	}
}

// TestWaitActiveHonoursContext keeps a waiter from outliving its caller.
func TestWaitActiveHonoursContext(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, governor.WaitActive(ctx))
}

// TestObserversSeeEveryTransition is how a subsystem reacts without polling the state.
func TestObserversSeeEveryTransition(t *testing.T) {
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 30 * time.Millisecond
	policy.WakeStagger = WakeStagger{}
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)

	var seen atomic.Int32
	var last atomic.Value
	governor.AddObserver(func(state State) {
		seen.Add(1)
		last.Store(state)
	})

	governor.DevicePaused()
	require.Eventually(t, func() bool { return governor.State() == StateDeepIdle },
		3*time.Second, 5*time.Millisecond)
	governor.DeviceWake()

	require.GreaterOrEqual(t, seen.Load(), int32(3), "quiescent, deep idle and active were all transitions")
	require.Equal(t, StateActive, last.Load())
}

// TestRepeatedSignalsAreIdempotent guards the transitions against a chatty platform: Apple delivers
// pause and wake more than once, and each repeat must not restart the countdown or re-notify.
func TestRepeatedSignalsAreIdempotent(t *testing.T) {
	governor := newTestGovernor(t)

	var transitions atomic.Int32
	governor.AddObserver(func(State) { transitions.Add(1) })

	governor.DevicePaused()
	governor.DevicePaused()
	governor.DevicePaused()
	require.Equal(t, int32(1), transitions.Load(), "repeated pauses produced more than one transition")

	governor.DeviceWake()
	governor.DeviceWake()
	require.Equal(t, int32(2), transitions.Load())
}

// TestCloseIsIdempotentAndQuiet keeps teardown safe: the tunnel is closed on every stop, and a
// signal arriving afterwards must not panic or notify.
func TestCloseIsIdempotentAndQuiet(t *testing.T) {
	governor := NewGovernor(DefaultPolicy())
	governor.Close()
	governor.Close()
	governor.DevicePaused()
	governor.ObserveTraffic()
	governor.NetworkPaused()
	require.False(t, governor.WaitActive(context.Background()))
}

// newStaggeredGovernor builds one with the wake stagger ON, which is the shipping default.
func newStaggeredGovernor(t *testing.T, stagger WakeStagger) *Governor {
	t.Helper()
	policy := DefaultPolicy()
	policy.DeepIdleAfter = 20 * time.Millisecond
	policy.WakeStagger = stagger
	governor := NewGovernor(policy)
	t.Cleanup(governor.Close)
	return governor
}

// TestWakeReleasesCategoriesInStages is §15: a wake must not be a storm.
//
// Every subsystem is told to come back at the same moment, and the ones that are cheap to delay cost
// the most radio - a health check starting in the same instant as the request that woke the phone is
// competing with the thing the user actually asked for.
func TestWakeReleasesCategoriesInStages(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{
		HealthCheck:     30 * time.Millisecond,
		ProviderRefresh: 120 * time.Millisecond,
		NetworkProbe:    30 * time.Millisecond,
		Statistics:      60 * time.Millisecond,
	})

	governor.DevicePaused()
	governor.DeviceWake()
	require.Equal(t, StateWaking, governor.State(), "a wake must not release everything at once")
	require.Equal(t, Allow{}, governor.Allow(), "nothing speculative may run in the first instant")

	// The business path is already usable - that is what WAKING means - so a subsystem waiting for the
	// device is not held for the stagger's sake.
	require.True(t, governor.WaitActive(context.Background()))

	require.Eventually(t, func() bool { return governor.Allow().HealthCheck },
		3*time.Second, 5*time.Millisecond, "the health check was never released")
	require.False(t, governor.Allow().ProviderRefresh, "provider refresh came back too early")

	require.Eventually(t, func() bool { return governor.Allow().Statistics },
		3*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return governor.Allow().ProviderRefresh },
		3*time.Second, 5*time.Millisecond)
}

// TestWakeSettlesToActive keeps WAKING from being a terminal state.
func TestWakeSettlesToActive(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{HealthCheck: 30 * time.Millisecond})
	governor.DevicePaused()
	governor.DeviceWake()
	require.Equal(t, StateWaking, governor.State())

	require.Eventually(t, func() bool { return governor.State() == StateActive },
		3*time.Second, 5*time.Millisecond, "WAKING never became ACTIVE")
	require.Equal(t, allowAll, governor.Allow())
}

// TestNoStaggerMeansNoWakingStage is the compatibility guarantee: a policy with no stagger behaves
// exactly as the machine did before WAKING existed.
func TestNoStaggerMeansNoWakingStage(t *testing.T) {
	governor := newTestGovernor(t)
	governor.DevicePaused()
	governor.DeviceWake()
	require.Equal(t, StateActive, governor.State())
}

// TestTrafficDuringWakingDoesNotReEnableSpeculation closes the loop with the traffic rule: the phone
// is awake, a request is in flight, and the staggered categories still wait their turn.
func TestTrafficDuringWakingDoesNotReEnableSpeculation(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{ProviderRefresh: 200 * time.Millisecond})
	governor.DevicePaused()
	governor.DeviceWake()

	governor.ObserveTraffic()
	require.Equal(t, StateWaking, governor.State(), "traffic short-circuited the stagger")
	require.False(t, governor.Allow().ProviderRefresh)
}

// TestWakeWithNoPathWaitsForThePath keeps the order: the stagger is measured from the moment the
// device is actually usable, not from the wake signal.
func TestWakeWithNoPathWaitsForThePath(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{HealthCheck: 200 * time.Millisecond})
	governor.NetworkPaused()
	governor.DevicePaused()
	governor.DeviceWake()

	require.NotEqual(t, StateWaking, governor.State(),
		"the stagger began before there was a path to stagger onto")

	governor.NetworkWake()
	require.Equal(t, StateWaking, governor.State())
}

// TestWaitProviderRefreshWaitsForTheDevice is the alternative to a 3am fetch.
//
// A remote rule-set refresh is periodic AND deferrable: it does not need to happen at a particular
// moment, only before the rules go stale, so it can wait for the device rather than waking it. This
// is the difference between a schedule that costs a radio wakeup while the phone is in a pocket and
// one that costs nothing until somebody picks it up.
func TestWaitProviderRefreshWaitsForTheDevice(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{})

	// A paused device does not permit it, and must not be woken by the wait.
	governor.DevicePaused()
	done := make(chan bool, 1)
	go func() { done <- governor.WaitProviderRefresh(context.Background()) }()

	select {
	case <-done:
		t.Fatal("a provider refresh ran while the device was asleep")
	case <-time.After(50 * time.Millisecond):
	}

	governor.DeviceWake()
	select {
	case permitted := <-done:
		require.True(t, permitted, "the refresh was not released by the wake")
	case <-time.After(2 * time.Second):
		t.Fatal("the refresh was never released; the rules would go stale indefinitely")
	}
}

// TestWaitProviderRefreshHonoursContext keeps a deferred refresh from outliving its tunnel.
func TestWaitProviderRefreshHonoursContext(t *testing.T) {
	governor := newStaggeredGovernor(t, WakeStagger{})
	governor.DevicePaused()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	require.False(t, governor.WaitProviderRefresh(ctx),
		"a cancelled wait must report that it did not get permission")

	closed := newStaggeredGovernor(t, WakeStagger{})
	closed.DevicePaused()
	closed.Close()
	require.False(t, closed.WaitProviderRefresh(context.Background()),
		"a closed governor must not authorise work")
}
