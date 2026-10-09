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

// The tests in this file pin the Apple device axis, and they are written against the REAL pause
// manager and the REAL applyPauseEvent bridge rather than a mock of either.
//
// That is not thoroughness for its own sake. The defect these tests exist for was not in the
// governor - the governor's own tests already covered the state machine - it was that the Apple
// vocabulary reached the level and not the epoch, and then that nothing lifted the level at all. A
// mock of the level would have agreed with whatever the bridge did. The manager is the object whose
// `IsDevicePaused` is the level every subsystem reads, so it is the object the assertions are on.
//
// The clock is injected, so the reuse bands are exercised by moving time rather than by waiting for
// it: a test that waits fifteen seconds still cannot say which side of a fifteen-second boundary it
// observed, and under load it fails for reasons that have nothing to do with the policy.

// testClock is a movable wall clock for the governor.
//
// It is a wall clock on purpose, matching production: the governor measures a sleep with
// `Round(0).Sub`, because Go's darwin monotonic reading stops while the device is asleep. A test
// clock with no monotonic reading is therefore the faithful one.
type testClock struct {
	access sync.Mutex
	now    time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Unix(1700000000, 0)}
}

func (c *testClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.access.Lock()
	defer c.access.Unlock()
	c.now = c.now.Add(d)
}

// newAppleBridge builds the production wiring: a governor, the real pause manager, and the bridge
// between them that NewBox installs.
//
// The returned manager is what the lifecycle publishes to, so `manager.IsDevicePaused()` is the
// level fact the whole core reads - the same one route/reference.go mirrors into its own state.
func newAppleBridge(t *testing.T, policy power.Policy, clock *testClock) (*power.Governor, lifecycle, pause.Manager, *levelTransitions) {
	t.Helper()
	ctx := pause.WithDefaultManager(context.Background())
	manager := service.FromContext[pause.Manager](ctx)
	governor := power.NewGovernorWithClock(policy, clock.Now)
	t.Cleanup(governor.Close)
	transitions := &levelTransitions{}
	manager.RegisterCallback(func(event int) {
		transitions.record(event)
		applyPauseEvent(governor, event)
	})
	return governor, lifecycle{governor: governor, device: manager}, manager, transitions
}

// levelTransitions counts the two device-axis events the pause manager emits. It counts EMISSIONS,
// not calls: the manager is a level, and a level that is already held does not emit again.
type levelTransitions struct {
	access sync.Mutex
	pauses int
	wakes  int
}

func (c *levelTransitions) record(event int) {
	c.access.Lock()
	defer c.access.Unlock()
	switch event {
	case pause.EventDevicePaused:
		c.pauses++
	case pause.EventDeviceWake:
		c.wakes++
	}
}

func (c *levelTransitions) counts() (int, int) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.pauses, c.wakes
}

// bridgePolicy is the shipping policy with the state machine's deep-idle deadline pushed out of the
// way, so a test that is about the reuse epoch is not also racing the deep-idle timer.
func bridgePolicy() power.Policy {
	policy := power.DefaultPolicy()
	policy.DeepIdleAfter = time.Hour
	return policy
}

// TestASleepAndResumePairIsOneBoundaryAndTheLevelIsHeld is §3.3's "a sleep/resume pair produces a
// reuse boundary", and the same sequence's other half: a resume is not a wake.
//
// Both halves are asserted because either one alone is a shipped defect. Without the boundary, the
// first flow after the unlock is handed a socket the sleep killed. With the level released on a
// resume, a phone in a pocket runs its speculative work - and on iOS a push notification lights the
// lock screen, so the resume that arrives is very often a push.
func TestASleepAndResumePairIsOneBoundaryAndTheLevelIsHeld(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, transitions := newAppleBridge(t, bridgePolicy(), clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	require.Equal(t, power.StateActive, governor.State())
	require.False(t, manager.IsDevicePaused())

	bridge.slept()
	require.Equal(t, power.StateQuiescent, governor.State(), "a sleep must pause the device axis")
	require.True(t, manager.IsDevicePaused(), "a sleep must enter the device level")
	require.Zero(t, governor.ReuseEpoch(), "a sleep is not a boundary")

	clock.Advance(30 * time.Second)
	bridge.resumed()

	require.Len(t, boundaries, 1, "a sleep/resume pair must publish exactly one boundary")
	require.Equal(t, power.ReuseRetire, boundaries[0].Action)
	require.Equal(t, 30*time.Second, boundaries[0].Sleep, "the sleep must be measured on the wall clock")
	require.Equal(t, uint64(1), governor.ReuseEpoch())
	require.True(t, manager.IsDevicePaused(), "a resume is not a device wake")
	require.Equal(t, power.StateQuiescent, governor.State())
	require.False(t, governor.Allow().ProviderRefresh, "a locked background resume released speculation")

	pauses, wakes := transitions.counts()
	require.Equal(t, 1, pauses)
	require.Zero(t, wakes, "a resume moved the device level")
}

// TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn is §3.3's "a real unlock recovers the
// device axis", and the discrimination the whole change turns on.
//
// A display turning on is not an unlock: iOS lights the lock screen for a push notification, for
// raise-to-wake, and for a notification the user dismissed without unlocking. An unlock
// (`lockstate == 0`) is the platform saying a person is using the device, and it is the only fact
// that lifts the pause. The release that follows is staggered, so an unlock is a ramp and not a
// burst.
func TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, transitions := newAppleBridge(t, bridgePolicy(), clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	bridge.screenState(false)
	require.True(t, manager.IsDevicePaused(), "a display going off must pause the device axis")

	// A push arrives while the phone is locked and lights the lock screen.
	clock.Advance(60 * time.Second)
	bridge.screenState(true)
	require.Len(t, boundaries, 1, "a display-on must publish the reuse boundary")
	require.True(t, manager.IsDevicePaused(),
		"a display turning on released the device pause; a push notification lights the lock screen")
	require.Equal(t, power.StateQuiescent, governor.State(),
		"a display turning on moved the device axis out of the paused state")
	// QUIESCENT deliberately keeps health checks and probes - a tunnel whose liveness nobody checks
	// fails silently the moment the user picks it up - so the categories that say "speculation was
	// released" are the two QUIESCENT suppresses.
	require.False(t, governor.Allow().ProviderRefresh,
		"a lock-screen notification released provider refresh")
	require.False(t, governor.Allow().Statistics,
		"a lock-screen notification released statistics")

	// And the unlock, which is the fact that means somebody is using the device.
	bridge.lockState(false)
	require.False(t, manager.IsDevicePaused(), "an unlock must lift the device pause: the axis was latched")
	require.Equal(t, power.StateWaking, governor.State(), "a wake must be staggered, not immediate")
	require.Len(t, boundaries, 1, "the unlock published a second boundary for one sleep")

	// The stagger is per category, measured from the wake.
	require.False(t, governor.Allow().HealthCheck, "a health check ran at the instant of the unlock")
	clock.Advance(5 * time.Second)
	require.True(t, governor.Allow().HealthCheck)
	require.True(t, governor.Allow().NetworkProbe)
	require.False(t, governor.Allow().Statistics, "statistics are staggered further than a health check")
	clock.Advance(5 * time.Second)
	require.True(t, governor.Allow().Statistics)
	require.False(t, governor.Allow().ProviderRefresh, "provider refresh carries the longest stagger")
	clock.Advance(5 * time.Second)
	require.True(t, governor.Allow().ProviderRefresh, "provider refresh must be released after its stagger")

	pauses, wakes := transitions.counts()
	require.Equal(t, 1, pauses, "one sleep produced more than one level pause")
	require.Equal(t, 1, wakes, "one unlock produced more than one level wake")
}

// TestOneSleepProducesOneLevelTransitionHoweverManyFactsReportIt is the dedup contract.
//
// The shipped client reports the display fact and the lock fact, and the NetworkExtension reports
// sleep() and wake() as well. Four facts describe one screen-off, and if each one were a transition
// the phone would retire its pool four times per unlock and emit four level events into every
// subsystem that watches them. The coalescing belongs to the governor and the manager, and this test
// is what says so.
func TestOneSleepProducesOneLevelTransitionHoweverManyFactsReportIt(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, transitions := newAppleBridge(t, bridgePolicy(), clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	// One screen-off, reported the way the platform reports it: the tunnel is put to sleep, the
	// display goes off, and the device locks. The order is not fixed by the platform.
	bridge.slept()
	clock.Advance(2 * time.Second)
	bridge.lockState(true)
	clock.Advance(2 * time.Second)
	bridge.screenState(false)

	pauses, wakes := transitions.counts()
	require.Equal(t, 1, pauses, "one screen-off produced more than one level pause")
	require.Zero(t, wakes)

	// And one unlock, reported as a resume, a display-on and an unlock.
	clock.Advance(60 * time.Second)
	bridge.resumed()
	clock.Advance(time.Second)
	bridge.screenState(true)
	clock.Advance(time.Second)
	bridge.lockState(false)

	require.Len(t, boundaries, 1, "one sleep produced more than one reuse boundary")
	require.Equal(t, 64*time.Second, boundaries[0].Sleep,
		"the sleep was re-measured by a later fact of the same sleep")
	pauses, wakes = transitions.counts()
	require.Equal(t, 1, pauses)
	require.Equal(t, 1, wakes, "one unlock produced more than one level wake")
	require.False(t, manager.IsDevicePaused())
}

// TestEverySleepCycleIsPairedAcrossOneHundredCycles is §3.3's hundred-cycle sequence.
//
// The latch this replaces was invisible in a single cycle: the first sleep was measured, the first
// unlock worked, and every cycle after it silently reused the first measurement - or, with the level
// latched, never resumed speculation at all. A hundred cycles is what makes "each one is paired"
// observable, and it is also where a boundary that fired twice per cycle would show up as a churn
// that a two-cycle test cannot see.
func TestEverySleepCycleIsPairedAcrossOneHundredCycles(t *testing.T) {
	policy := bridgePolicy()
	// The stagger is not what is under test here and the levels are: with it off, each cycle's state
	// is unambiguous, and the stagger has its own test above.
	policy.WakeStagger = power.WakeStagger{}
	clock := newTestClock()
	governor, bridge, manager, transitions := newAppleBridge(t, policy, clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	const cycles = 100
	for i := 0; i < cycles; i++ {
		bridge.slept()
		require.Equal(t, power.StateQuiescent, governor.State(), "cycle %d: the sleep did not pause", i)
		require.True(t, manager.IsDevicePaused(), "cycle %d: the device level was not entered", i)
		clock.Advance(60 * time.Second)
		bridge.resumed()
		bridge.lockState(false)
		require.False(t, manager.IsDevicePaused(), "cycle %d: the device level latched", i)
		require.Equal(t, power.StateActive, governor.State(), "cycle %d: the wake did not release", i)
	}

	require.Len(t, boundaries, cycles, "every cycle must publish exactly one boundary")
	for i, boundary := range boundaries {
		require.Equal(t, uint64(i+1), boundary.Epoch, "the epoch is not the cycle number")
		require.Equal(t, power.ReuseRetire, boundary.Action)
		require.Equal(t, 60*time.Second, boundary.Sleep)
	}
	require.Equal(t, uint64(cycles), governor.ReuseEpoch())
	pauses, wakes := transitions.counts()
	require.Equal(t, cycles, pauses)
	require.Equal(t, cycles, wakes)
}

// TestTheBridgeUsesThePolicyBandsAndNothingElse is §3.3's threshold sequence, asserted at the bridge
// rather than only in the governor: the bands are the policy's, the short one costs nothing, and a
// clock that went backwards is not evidence of a short sleep.
func TestTheBridgeUsesThePolicyBandsAndNothingElse(t *testing.T) {
	clock := newTestClock()
	policy := bridgePolicy()
	policy.WakeStagger = power.WakeStagger{}
	governor, bridge, _, _ := newAppleBridge(t, policy, clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	// A glance at the lock screen: under SuspectAfter, nothing happens at all. This is the whole
	// reason the boundary is a policy and not "close on every resume".
	bridge.slept()
	clock.Advance(2 * time.Second)
	bridge.resumed()
	require.Empty(t, boundaries, "a two-second pause retired something")
	require.Zero(t, governor.ReuseEpoch())

	// The suspect band: the epoch advances so the distrust is visible and monotonic, and the pools are
	// kept by policy.
	bridge.slept()
	clock.Advance(7 * time.Second)
	bridge.resumed()
	require.Len(t, boundaries, 1)
	require.Equal(t, power.ReuseSuspect, boundaries[0].Action)
	require.Equal(t, uint64(1), governor.ReuseEpoch())

	// The retire band.
	bridge.slept()
	clock.Advance(20 * time.Second)
	bridge.resumed()
	require.Len(t, boundaries, 2)
	require.Equal(t, power.ReuseRetire, boundaries[1].Action)
	require.Equal(t, uint64(2), governor.ReuseEpoch())

	// A wall clock that moved backwards is reported as unknown, and unknown is the strict verdict: a
	// resource whose age cannot be established must not be republished as current.
	bridge.slept()
	clock.Advance(-time.Hour)
	bridge.resumed()
	require.Len(t, boundaries, 3)
	require.Equal(t, power.ReuseRetire, boundaries[2].Action)
	require.False(t, boundaries[2].Known)
}

// TestAFactWithoutASleepPublishesNothing is the other direction of the same rule.
//
// A platform resumes the extension for reasons that have nothing to do with a sleep this process saw:
// a background task after a cold start, a push delivered while the tunnel was being set up, an unlock
// notification replayed on a fresh process. None of those is a boundary, because there is no sleep to
// measure - and inventing one would retire a pool that was never asleep, which is a handshake storm
// with no correctness gain.
func TestAFactWithoutASleepPublishesNothing(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, transitions := newAppleBridge(t, bridgePolicy(), clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	bridge.resumed()
	bridge.screenState(true)
	bridge.lockState(false)
	bridge.woke()

	require.Empty(t, boundaries, "a fact with no sleep on record published a boundary")
	require.Zero(t, governor.ReuseEpoch())
	require.False(t, manager.IsDevicePaused())
	require.Equal(t, power.StateActive, governor.State())
	pauses, wakes := transitions.counts()
	require.Zero(t, pauses)
	require.Zero(t, wakes, "an unlock lifted a pause that was never entered")
}

// TestCloseWinsOverALateAppleFact is §3.3's "Close takes priority over any pending operation".
//
// The platform's callback arrives on its own thread and a teardown can be in flight when it does, so
// a fact that arrives after Close must be a no-op that neither publishes a boundary nor panics. The
// governor is closed by the Box's scope; the pause manager outlives it, which is why this is the
// shape a late callback actually takes.
func TestCloseWinsOverALateAppleFact(t *testing.T) {
	clock := newTestClock()
	governor, bridge, manager, _ := newAppleBridge(t, bridgePolicy(), clock)
	var boundaries []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	bridge.slept()
	clock.Advance(30 * time.Second)
	governor.Close()

	require.NotPanics(t, func() {
		bridge.resumed()
		bridge.screenState(true)
		bridge.lockState(false)
		bridge.woke()
		bridge.slept()
	})
	require.Empty(t, boundaries, "a fact published a boundary after Close")
	require.Zero(t, governor.ReuseEpoch())
	require.False(t, governor.Active())
	// The level is not this test's subject and is deliberately left as the manager has it: the pause
	// manager outlives the governor, so a late fact still moves the level for whoever is left, and the
	// thing that must not happen - reaching a torn-down pool through a boundary - is what is asserted.
	_ = manager
}

// TestTheBridgeIsSafeUnderConcurrentFacts is the race-detector half: the platform delivers these
// facts from its own threads, and a tunnel can be paused while a resume is already in flight.
//
// What is asserted is the invariants the design actually guarantees, and the reason is worth stating
// because the first version of this test got it wrong. The measured sleep of a concurrent pair is NOT
// guaranteed to be long: every slept() fact re-arms the measurement once the previous one has been
// resumed, so eight goroutines interleaving sleep and resume facts legitimately coalesce into many
// short measurements and few boundaries. Asserting a boundary count from that would be asserting a
// scheduler's behaviour. What IS guaranteed is that the epoch never moves backwards, that concurrent
// facts never panic or race, and that nothing is left running afterwards.
func TestTheBridgeIsSafeUnderConcurrentFacts(t *testing.T) {
	clock := newTestClock()
	policy := bridgePolicy()
	policy.WakeStagger = power.WakeStagger{}
	governor, bridge, manager, _ := newAppleBridge(t, policy, clock)

	// A known floor first: five sequential cycles, each one a thirty-second sleep, which is five
	// boundaries that no interleaving can take away.
	const sequential = 5
	for i := 0; i < sequential; i++ {
		bridge.slept()
		clock.Advance(30 * time.Second)
		bridge.resumed()
		bridge.lockState(false)
	}
	floor := governor.ReuseEpoch()
	require.Equal(t, uint64(sequential), floor)

	// A watcher turns "monotonic" into an observation rather than an assumption.
	stop := make(chan struct{})
	watchFailed := make(chan uint64, 1)
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		last := floor
		for {
			select {
			case <-stop:
				return
			default:
			}
			current := governor.ReuseEpoch()
			if current < last {
				select {
				case watchFailed <- current:
				default:
				}
				return
			}
			last = current
		}
	}()

	before := runtime.NumGoroutine()
	const workers = 8
	const rounds = 50
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for round := 0; round < rounds; round++ {
				bridge.slept()
				clock.Advance(time.Second)
				bridge.resumed()
				bridge.screenState(worker%2 == 0)
				bridge.lockState(round%3 == 0)
				_ = governor.Allow()
				_ = governor.Active()
			}
		}(worker)
	}
	wait.Wait()
	close(stop)
	watcher.Wait()
	select {
	case regressed := <-watchFailed:
		t.Fatalf("the reuse epoch moved backwards, to %d", regressed)
	default:
	}
	require.GreaterOrEqual(t, governor.ReuseEpoch(), floor,
		"the concurrent phase lost a boundary that had already been published")

	// Every fact is a short, non-blocking call on the core's own objects, so the bridge itself owns no
	// goroutine: the ones the governor arms are timers, and they are bounded by the policy. The
	// assertion is a leak check, so it allows for the runtime's own transient goroutines.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= before+2
	}, 5*time.Second, 20*time.Millisecond,
		"the bridge left goroutines behind: %d before, %d after", before, runtime.NumGoroutine())
	_ = manager
}
