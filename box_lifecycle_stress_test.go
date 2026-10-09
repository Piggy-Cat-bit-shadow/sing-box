package box

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// This file is the stress half of the Apple device-axis work: the sequences §3.3 requires, run enough
// times that a leak, a resurrected pool or a boundary that fires twice shows up as a number rather
// than as a hunch.
//
// What is deliberately NOT asserted here: wall-clock durations. The bands are the policy's and the
// clock is injected, so "how long did this sleep take" is decided by the test and not by the machine
// it runs on. Two things ARE asserted that a shorter test cannot see:
//
//   - the goroutine count returns to its baseline, which is what catches a bridge that starts a
//     goroutine per fact (the tempting way to make a callback "not block"), and
//   - nothing is published after Close, however many facts arrive afterwards, which is the
//     resurrection a reload creates.

// TestOneHundredSleepWakeCyclesLeakNothingAndLeaveNoBoundaryUnpaired is §3.3's hundred-cycle
// sequence, with the two lifecycle assertions a cycle count alone does not make.
func TestOneHundredSleepWakeCyclesLeakNothingAndLeaveNoBoundaryUnpaired(t *testing.T) {
	clock := newTestClock()
	policy := bridgePolicy()
	policy.WakeStagger = power.WakeStagger{}
	governor, bridge, manager, transitions := newAppleBridge(t, policy, clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	baseline := runtime.NumGoroutine()

	const cycles = 100
	for cycle := 0; cycle < cycles; cycle++ {
		// A screen-off reported the way the platform reports it: the tunnel is going to sleep, the
		// display goes off, the device locks. One sleep, three facts.
		bridge.slept()
		bridge.screenState(false)
		bridge.lockState(true)
		require.True(t, manager.IsDevicePaused(), "cycle %d: the device level was not entered", cycle)

		clock.Advance(20 * time.Second)

		// And the unlock: a resume, a display coming back, and the unlock itself.
		bridge.resumed()
		bridge.screenState(true)
		bridge.lockState(false)
		require.False(t, manager.IsDevicePaused(), "cycle %d: the device level latched", cycle)
		require.Equal(t, power.StateActive, governor.State(), "cycle %d: the wake did not release", cycle)
	}

	require.Len(t, boundaries, cycles,
		"one hundred paired sleep/wake cycles must produce one hundred boundaries, not %d", len(boundaries))
	require.Equal(t, uint64(cycles), governor.ReuseEpoch())
	for index, boundary := range boundaries {
		require.Equal(t, uint64(index+1), boundary.Epoch)
		require.Equal(t, power.ReuseRetire, boundary.Action)
		require.Equal(t, 20*time.Second, boundary.Sleep)
	}
	// One level transition per direction per cycle: the three facts of each transition coalesced.
	pauses, wakes := transitions.counts()
	require.Equal(t, cycles, pauses)
	require.Equal(t, cycles, wakes)

	requireGoroutinesReturnTo(t, baseline, "the sleep/wake cycles")
}

// TestOneHundredNetworkTransitionsDoNotConsumeOrPublishADeviceBoundary is §3.3's network half.
//
// The two epochs are separate on purpose: a network transition is a HARD change - every transport and
// every ownership epoch is reset, because the resource belongs to the network being left - and a
// sleep boundary is a soft one that distrusts IDLE resources and dials nothing. If a transition
// published a reuse boundary, sleeping would become indistinguishable from a handover; if it consumed
// one, the first flow after an unlock would be handed a socket that predates the sleep.
func TestOneHundredNetworkTransitionsDoNotConsumeOrPublishADeviceBoundary(t *testing.T) {
	clock := newTestClock()
	policy := bridgePolicy()
	policy.WakeStagger = power.WakeStagger{}
	governor, bridge, _, _ := newAppleBridge(t, policy, clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	baseline := runtime.NumGoroutine()
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)

	const transitions = 100
	for transition := 0; transition < transitions; transition++ {
		// A sleep is being measured while the path changes: the boundary belongs to the sleep and must
		// survive the transition.
		bridge.slept()
		manager.NetworkPause()
		require.Equal(t, power.StateQuiescent, governor.State())
		clock.Advance(2 * time.Second)
		manager.NetworkWake()
		clock.Advance(30 * time.Second)
		bridge.lockState(false)
	}

	require.Len(t, boundaries, transitions,
		"a network transition published a reuse boundary, or consumed one: %d boundaries for %d transitions",
		len(boundaries), transitions)
	require.Equal(t, uint64(transitions), governor.ReuseEpoch())
	require.Equal(t, power.StateActive, governor.State())
	require.False(t, manager.IsDevicePaused())

	requireGoroutinesReturnTo(t, baseline, "the network transitions")
}

// TestNoResurrectionAfterClose is the teardown rule under load: the governor is closed before the
// scope that owns the pools, so a platform callback already in flight arrives after Close. It must be
// a counted no-op - no state change, no boundary, no goroutine, and above all no reach into a pool
// that is being torn down.
func TestNoResurrectionAfterClose(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, _ := newAppleBridge(t, bridgePolicy(), clock)
	var (
		access     sync.Mutex
		boundaries int
	)
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		access.Lock()
		defer access.Unlock()
		boundaries++
	})

	bridge.slept()
	clock.Advance(30 * time.Second)
	require.Equal(t, power.StateQuiescent, governor.State())

	epochBefore := governor.ReuseEpoch()
	governor.Close()
	baseline := runtime.NumGoroutine()

	// Every fact the platform can deliver, delivered after the lifecycle ended. The loop ends on an
	// unlock, because the pause LEVEL is deliberately not this test's subject: the manager outlives
	// the governor (a reload replaces the Box inside the same service), so a post-Close fact still
	// moves the level for whoever is wired next - and what must NOT happen is that moving it reaches a
	// governor whose pools are gone. That is what the assertions below are.
	for round := 0; round < 100; round++ {
		bridge.resumed()
		bridge.screenState(true)
		bridge.screenState(false)
		bridge.lockState(true)
		bridge.lockState(false)
		bridge.woke()
		bridge.slept()
	}
	bridge.lockState(false)

	access.Lock()
	published := boundaries
	access.Unlock()
	require.Zero(t, published, "a reuse boundary was published after Close")
	require.Equal(t, epochBefore, governor.ReuseEpoch(), "the reuse epoch moved after Close")
	require.False(t, governor.Active(), "a closed governor authorised work")
	require.False(t, manager.IsDevicePaused(),
		"the level was left stranded paused: a reload would inherit a pause with no publisher")
	requireGoroutinesReturnTo(t, baseline, "the post-Close facts")
}

// TestTheBridgeUnderConcurrentLifecyclesAndTeardown is the race-detector target for the whole file:
// facts from several platform threads while a Close is in flight, which is what a tunnel restart
// under a device-sleep callback actually looks like.
func TestTheBridgeUnderConcurrentLifecyclesAndTeardown(t *testing.T) {
	clock := newTestClock()
	governor, bridge, _, _ := newAppleBridge(t, bridgePolicy(), clock)
	baseline := runtime.NumGoroutine()

	const workers = 8
	const rounds = 100
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for round := 0; round < rounds; round++ {
				bridge.slept()
				clock.Advance(2 * time.Second)
				bridge.screenState(round%2 == 0)
				bridge.resumed()
				bridge.lockState(round%3 == 0)
				_ = governor.Allow()
			}
		}(worker)
	}
	// The teardown races the facts, which is the interleaving the closed flag and the in-flight
	// discipline exist for.
	var closer sync.WaitGroup
	closer.Add(1)
	go func() {
		defer closer.Done()
		time.Sleep(5 * time.Millisecond)
		governor.Close()
	}()
	wait.Wait()
	closer.Wait()

	require.False(t, governor.Active())
	requireGoroutinesReturnTo(t, baseline, "concurrent facts and a teardown")
}

// requireGoroutinesReturnTo is the leak assertion, and it is a helper because every phase of this file
// needs the same one: the bridge must not own a goroutine per fact, and the governor's timers are
// runtime timers rather than per-deadline goroutines.
//
// It is an Eventually rather than an immediate comparison because the runtime itself schedules
// transient goroutines (GC workers, the timer goroutine) whose lifetime is not this code's to decide.
func requireGoroutinesReturnTo(t *testing.T, baseline int, phase string) {
	t.Helper()
	require.Eventually(t, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseline+2
	}, 10*time.Second, 25*time.Millisecond,
		"%s left goroutines behind: %d before, %d after", phase, baseline, runtime.NumGoroutine())
}
