package power

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// reuseTestClock is a wall clock a test can move.
//
// It is wall-only on purpose: time.Unix carries no monotonic reading, which is what the device's own
// clock looks like across a sleep. The offset is atomic because the concurrency tests move it from
// several goroutines.
type reuseTestClock struct {
	base   time.Time
	offset atomic.Int64
}

func newReuseTestClock() *reuseTestClock {
	return &reuseTestClock{base: time.Unix(1700000000, 0)}
}

func (c *reuseTestClock) Now() time.Time {
	return c.base.Add(time.Duration(c.offset.Load()))
}

func (c *reuseTestClock) Advance(d time.Duration) {
	c.offset.Add(int64(d))
}

// reuseTestGovernor builds a governor with an injected clock, so a test can move the device through
// a five hour sleep without waiting for one.
//
// The clock is the whole reason these tests can be deterministic: the reuse bands are durations, and
// the alternative to injecting a clock is a test that sleeps for the threshold and still cannot say
// which side of the boundary it observed.
func reuseTestGovernor(t *testing.T, freshness ReuseFreshness) (*Governor, *reuseTestClock) {
	t.Helper()
	policy := DefaultPolicy()
	policy.DeepIdleAfter = time.Hour
	policy.WakeStagger = WakeStagger{}
	policy.ReuseFreshness = freshness
	clock := newReuseTestClock()
	governor := NewGovernorWithClock(policy, clock.Now)
	t.Cleanup(governor.Close)
	return governor, clock
}

// TestReuseKeepsEveryResourceForAShortSleep is the power half of the policy, and the one that must
// not regress: a glance at the lock screen must not cost a handshake.
func TestReuseKeepsEveryResourceForAShortSleep(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) {
		boundaries = append(boundaries, boundary)
	})

	governor.SleepStarted()
	governor.DevicePaused()
	clock.Advance(2 * time.Second)
	governor.Resumed()
	governor.DeviceWake()

	require.Zero(t, governor.ReuseEpoch(), "a two second sleep advanced the reuse epoch")
	require.Empty(t, boundaries, "a two second sleep published a boundary")
	_, ok := governor.LastReuseBoundary()
	require.False(t, ok)

	// And the device axis did move: the level is a different question with a different answer, and it
	// is the one the stagger is measured against.
	require.Equal(t, StateActive, governor.State())
}

// TestReuseBandsAreThePolicy is the correctness half: the two published verdicts, in order, and the
// sleep duration that produced them.
func TestReuseBandsAreThePolicy(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	type observation struct {
		boundary ReuseBoundary
		at       uint64
	}
	var (
		access       sync.Mutex
		observations []observation
	)
	governor.AddReuseObserver(func(boundary ReuseBoundary) {
		access.Lock()
		defer access.Unlock()
		observations = append(observations, observation{boundary: boundary, at: governor.ReuseEpoch()})
	})

	// Band one: suspect, at eight seconds.
	governor.SleepStarted()
	clock.Advance(8 * time.Second)
	governor.Resumed()
	require.Equal(t, uint64(1), governor.ReuseEpoch(), "the suspect band did not advance the epoch")

	// Band two: retire, at forty seconds. This is a SECOND sleep: the edge API exists precisely so
	// that a platform whose pause level is latched still gets a boundary per sleep.
	governor.SleepStarted()
	clock.Advance(40 * time.Second)
	governor.Resumed()
	require.Equal(t, uint64(2), governor.ReuseEpoch(), "the retire band did not advance the epoch")

	access.Lock()
	defer access.Unlock()
	require.Len(t, observations, 2)
	require.Equal(t, ReuseSuspect, observations[0].boundary.Action)
	require.Equal(t, 8*time.Second, observations[0].boundary.Sleep)
	require.True(t, observations[0].boundary.Known)
	require.Equal(t, uint64(1), observations[0].boundary.Epoch)
	// The epoch an observer sees while it runs is the epoch of the boundary it was handed: a consumer
	// that reads the governor from inside the callback must not see a stale generation.
	require.Equal(t, observations[0].boundary.Epoch, observations[0].at)

	require.Equal(t, ReuseRetire, observations[1].boundary.Action)
	require.Equal(t, 40*time.Second, observations[1].boundary.Sleep)
	require.Equal(t, uint64(2), observations[1].boundary.Epoch)

	last, ok := governor.LastReuseBoundary()
	require.True(t, ok)
	require.Equal(t, observations[1].boundary, last)
}

// TestOneBoundaryPerSleepAndOneMeasurementPerSleep pins the two coalescing rules that keep a resume
// from becoming a reconnect storm, and a repeated sleep report from becoming a zero-length sleep.
func TestOneBoundaryPerSleepAndOneMeasurementPerSleep(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var calls atomic.Int64
	governor.AddReuseObserver(func(ReuseBoundary) { calls.Add(1) })

	governor.SleepStarted()
	// The same sleep reported again - the platform level arriving after the edge - must not restart
	// the measurement: a five minute sleep is not a five microsecond one.
	clock.Advance(10 * time.Second)
	governor.SleepStarted()
	governor.DevicePaused()
	clock.Advance(10 * time.Second)
	governor.Resumed()

	require.Equal(t, int64(1), calls.Load(), "one sleep produced more than one boundary")
	require.Equal(t, uint64(1), governor.ReuseEpoch())
	boundary, _ := governor.LastReuseBoundary()
	require.Equal(t, 20*time.Second, boundary.Sleep, "a repeated sleep report restarted the measurement")

	// A locked phone is resumed many times. The first resume publishes the boundary; the rest are
	// no-ops until the platform reports another sleep, and so is a device wake arriving after them.
	for range 5 {
		clock.Advance(time.Minute)
		governor.Resumed()
	}
	governor.DeviceWake()
	require.Equal(t, int64(1), calls.Load(), "a repeated resume published a second boundary")
	require.Equal(t, uint64(1), governor.ReuseEpoch())

	// And the NEXT sleep is measured on its own, which is the whole point of the edge form.
	governor.SleepStarted()
	clock.Advance(20 * time.Second)
	governor.Resumed()
	require.Equal(t, int64(2), calls.Load())
	require.Equal(t, uint64(2), governor.ReuseEpoch())
}

// TestResumeWithoutASleepIsNotABoundary: a platform can deliver a resume for a sleep this process
// never saw. Inventing a boundary for one would retire a pool that was never asleep.
func TestResumeWithoutASleepIsNotABoundary(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: time.Second, RetireAfter: 2 * time.Second})
	var calls atomic.Int64
	governor.AddReuseObserver(func(ReuseBoundary) { calls.Add(1) })

	governor.Resumed()
	governor.DeviceWake()
	clock.Advance(time.Hour)
	governor.Resumed()

	require.Zero(t, governor.ReuseEpoch())
	require.Zero(t, calls.Load())
}

// TestNetworkWakeIsNotAReuseBoundary keeps the three axes apart.
//
// A path that goes away and comes back is a NETWORK transition: it is handled by the network epoch,
// which resets rather than retires, and it says nothing about how long the device was asleep. The
// reuse boundary is measured from the sleep edge and is published when the sleep ends, so a network
// wake in the middle of a sleep must neither consume the sleep nor advance the epoch - and the
// boundary that follows must still carry the whole sleep duration.
func TestNetworkWakeIsNotAReuseBoundary(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) { boundaries = append(boundaries, boundary) })

	governor.SleepStarted()
	governor.DevicePaused()
	clock.Advance(20 * time.Second)
	governor.NetworkPaused()
	governor.NetworkWake()
	require.Zero(t, governor.ReuseEpoch(), "a network wake was treated as a reuse boundary")
	require.Empty(t, boundaries)

	clock.Advance(40 * time.Second)
	governor.Resumed()
	require.Equal(t, uint64(1), governor.ReuseEpoch())
	require.Len(t, boundaries, 1)
	require.Equal(t, 60*time.Second, boundaries[0].Sleep,
		"the boundary did not carry the whole sleep: a network pause in the middle reset the measurement")
	require.Equal(t, ReuseRetire, boundaries[0].Action)
}

// TestTheBridgePublishesBothAxes is the mapping between the platform's vocabulary and the governor's
// two axes, tested where that mapping lives: the pause event must mark the reusable state suspect
// AND move the state machine, and the wake event must publish the verdict BEFORE it releases work.
func TestTheBridgePublishesBothAxes(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) { boundaries = append(boundaries, boundary) })

	governor.SleepStarted()
	governor.DevicePaused()
	require.Equal(t, StateQuiescent, governor.State())
	clock.Advance(30 * time.Second)

	governor.Resumed()
	governor.DeviceWake()

	require.Len(t, boundaries, 1)
	require.Equal(t, ReuseRetire, boundaries[0].Action)
	require.Equal(t, 30*time.Second, boundaries[0].Sleep)
	require.Equal(t, StateActive, governor.State(), "the device axis did not move on a wake")
}

// TestDeviceWakeAloneIsNotABoundary is the separation the iOS lifecycle forced: a device wake is a
// LEVEL, and a level that never fires on this platform must not be the only thing that produces a
// verdict. The bridge publishes the edge; the level does not stand in for it.
func TestDeviceWakeAloneIsNotABoundary(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var calls atomic.Int64
	governor.AddReuseObserver(func(ReuseBoundary) { calls.Add(1) })

	governor.DevicePaused()
	clock.Advance(30 * time.Second)
	governor.DeviceWake()

	require.Zero(t, calls.Load(), "a device wake published a reuse verdict without a resume edge")
	require.Zero(t, governor.ReuseEpoch())
}

// TestLevelOnlyPlatformStillGetsAVerdict is the other half of the same rule: a platform that reports
// the pause LEVEL and nothing else must not be worse off than one that reports edges.
//
// Android and the Windows power event are level-driven - the pause arrives as a level transition and
// the wake as another one - so the level arms the measurement, and the edge that the bridge publishes
// alongside the wake is what turns it into a verdict. Only a wake with no pause before it is nothing.
func TestLevelOnlyPlatformStillGetsAVerdict(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) { boundaries = append(boundaries, boundary) })

	// The level pair alone.
	governor.DevicePaused()
	clock.Advance(30 * time.Second)
	governor.Resumed()
	governor.DeviceWake()

	require.Len(t, boundaries, 1)
	require.Equal(t, 30*time.Second, boundaries[0].Sleep)
	require.Equal(t, ReuseRetire, boundaries[0].Action)
	require.Equal(t, StateActive, governor.State())

	// A resume with no pause before it is still nothing, as is a wake with no resume edge.
	quiet, quietClock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var quietCalls atomic.Int64
	quiet.AddReuseObserver(func(ReuseBoundary) { quietCalls.Add(1) })
	quietClock.Advance(time.Hour)
	quiet.Resumed()
	quiet.DeviceWake()
	require.Zero(t, quietCalls.Load())
}

// TestUnknownSleepIsRetired is the fail-safe direction. A backwards wall clock - NTP, a manual
// change, a timezone database update - must not be read as "a very short sleep", because the only
// resource whose age cannot be established would then be republished as current.
func TestUnknownSleepIsRetired(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: time.Hour, RetireAfter: 2 * time.Hour})
	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) { boundaries = append(boundaries, boundary) })

	governor.SleepStarted()
	clock.Advance(-time.Hour)
	governor.Resumed()

	require.Len(t, boundaries, 1)
	require.False(t, boundaries[0].Known)
	require.Equal(t, ReuseRetire, boundaries[0].Action)
	require.Equal(t, uint64(1), boundaries[0].Epoch)
}

// TestZeroReusePolicyKeepsEverything is the compatibility rule the rest of this package follows: a
// caller that builds a Policy without opting in gets the behaviour that existed before the reuse
// epoch did, and no boundary at all.
func TestZeroReusePolicyKeepsEverything(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{})
	var calls atomic.Int64
	governor.AddReuseObserver(func(ReuseBoundary) { calls.Add(1) })

	governor.SleepStarted()
	clock.Advance(12 * time.Hour)
	governor.Resumed()

	require.Zero(t, governor.ReuseEpoch())
	require.Zero(t, calls.Load())
}

// TestReuseEpochIsMonotonicUnderConcurrency is the generation rule: the epoch is a generation, and a
// generation that can go backwards is not one.
func TestReuseEpochIsMonotonicUnderConcurrency(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: time.Second, RetireAfter: 2 * time.Second})
	const (
		writers = 4
		rounds  = 200
	)
	var (
		regressed atomic.Int64
		waitGroup sync.WaitGroup
	)
	// Monotonicity is asserted PER OBSERVER, which is the only form of it that can be observed while
	// writers are running: a sample taken by one goroutine and compared against a value another
	// goroutine published in between is a stale sample, not a regression, and a shared high-water mark
	// would report exactly that as a failure. Within one goroutine successive reads are ordered, and
	// the epoch only ever increases, so the sequence must be non-decreasing - and that is the property
	// a consumer relies on.
	observer := func() {
		var last uint64
		for range rounds {
			governor.SleepStarted()
			clock.Advance(time.Second)
			governor.DevicePaused()
			governor.Resumed()
			governor.DeviceWake()
			governor.ObserveTraffic()
			epoch := governor.ReuseEpoch()
			if epoch < last {
				regressed.Add(1)
			}
			last = epoch
		}
	}
	for range writers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			observer()
		}()
	}
	waitGroup.Wait()
	// With every writer stopped there is nothing to race, so the last reading is the generation the
	// governor settled on, and it must be at least everything observed above.
	final := governor.ReuseEpoch()
	require.Zero(t, regressed.Load(), "the reuse epoch went backwards")
	require.NotZero(t, final)
	require.GreaterOrEqual(t, final, uint64(rounds))
}

// TestReuseObserverRunsWithTheGovernorUnlocked is the lock contract.
//
// An observer's real job is to retire connections, which takes locks of its own; calling one under
// the governor's lock makes the governor a lock-ordering hazard for every subsystem that observes
// it. The observer here does the thing that would deadlock if the lock were held - it reads the
// governor - and the test fails rather than hangs.
func TestReuseObserverRunsWithTheGovernorUnlocked(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: time.Second, RetireAfter: 2 * time.Second})
	observed := make(chan State, 1)
	governor.AddReuseObserver(func(ReuseBoundary) {
		observed <- governor.State()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		governor.SleepStarted()
		governor.DevicePaused()
		clock.Advance(10 * time.Second)
		governor.Resumed()
	}()
	select {
	case state := <-observed:
		require.Equal(t, StateQuiescent, state)
	case <-time.After(10 * time.Second):
		t.Fatal("the reuse observer was called with the governor's lock held: it deadlocked reading the state")
	}
	<-done
}

// TestCloseMakesResumeAResurrectionSafeNoOp: Close wins. A boundary that arrives after the lifecycle
// ended must not retire, nudge or wake anything, and repeated closes must stay harmless.
func TestCloseMakesResumeAResurrectionSafeNoOp(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: time.Second, RetireAfter: 2 * time.Second})
	var calls atomic.Int64
	governor.AddReuseObserver(func(ReuseBoundary) { calls.Add(1) })

	governor.SleepStarted()
	clock.Advance(10 * time.Second)
	governor.Close()

	governor.Resumed()
	governor.DeviceWake()
	governor.SleepStarted()
	governor.Resumed()
	governor.Close()

	require.Zero(t, calls.Load(), "a boundary was published after Close")
	require.Zero(t, governor.ReuseEpoch())
	require.False(t, governor.Active())
}

// TestReuseBoundaryStressCycles runs the whole sleep/wake vocabulary a hundred times and asserts the
// two things a stress test is for: the accounting stays exact, and nothing is left behind.
//
// The goroutine baseline is the leak check. Publishing a boundary must not start a worker, and the
// observers here are called synchronously for exactly that reason; a resume that spawned a goroutine
// per cycle would leave a hundred of them, which is how a lifecycle fix becomes a resource leak.
func TestReuseBoundaryStressCycles(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var (
		boundaries atomic.Int64
		retires    atomic.Int64
	)
	governor.AddReuseObserver(func(boundary ReuseBoundary) {
		boundaries.Add(1)
		if boundary.Action == ReuseRetire {
			retires.Add(1)
		}
	})

	settle()
	before := runtime.NumGoroutine()

	const cycles = 100
	for cycle := range cycles {
		switch cycle % 4 {
		case 0: // a glance: no boundary, and the pool must survive it
			governor.SleepStarted()
			governor.DevicePaused()
			clock.Advance(time.Second)
			governor.Resumed()
			governor.DeviceWake()
		case 1: // the suspect band
			governor.SleepStarted()
			governor.DevicePaused()
			clock.Advance(8 * time.Second)
			governor.Resumed()
		case 2: // the retire band, reported as a device wake
			governor.SleepStarted()
			governor.DevicePaused()
			clock.Advance(45 * time.Second)
			governor.Resumed()
			governor.DeviceWake()
		case 3: // a real network transition in the middle of a sleep
			governor.SleepStarted()
			governor.DevicePaused()
			clock.Advance(30 * time.Second)
			governor.NetworkPaused()
			governor.NetworkWake()
			governor.Resumed()
		}
		governor.ObserveTraffic()
	}

	// 25 glances publish nothing; the other 75 cycles publish one boundary each, and the retire band
	// is cycles 2 and 3 of every four.
	require.Equal(t, int64(75), boundaries.Load(), "the boundary count does not match the cycle mix")
	require.Equal(t, int64(50), retires.Load(), "the retire count does not match the cycle mix")
	require.Equal(t, uint64(75), governor.ReuseEpoch())

	settle()
	after := runtime.NumGoroutine()
	require.LessOrEqual(t, after, before+2,
		"the reuse path left goroutines behind: %d before, %d after 100 cycles", before, after)

	// And no resurrection: closing the governor stops everything and does not rewind the generation.
	governor.Close()
	require.Equal(t, uint64(75), governor.ReuseEpoch(), "Close changed the epoch")
	governor.SleepStarted()
	governor.Resumed()
	require.Equal(t, int64(75), boundaries.Load())
	require.Equal(t, uint64(75), governor.ReuseEpoch())
}

// TestReuseBoundaryUnderRaceWithCloseAndTraffic is the interleaving the race detector exists for: a
// resume, a new flow, a state transition and a close, all at once.
func TestReuseBoundaryUnderRaceWithCloseAndTraffic(t *testing.T) {
	for range 20 {
		governor := NewGovernor(Policy{
			DeepIdleAfter:  time.Millisecond,
			ReuseFreshness: ReuseFreshness{SuspectAfter: time.Millisecond, RetireAfter: 2 * time.Millisecond},
		})
		var waitGroup sync.WaitGroup
		start := make(chan struct{})
		worker := func(run func()) {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				<-start
				run()
			}()
		}
		worker(func() {
			for range 50 {
				governor.SleepStarted()
				governor.DevicePaused()
				governor.Resumed()
			}
		})
		worker(func() {
			for range 50 {
				governor.DevicePaused()
				governor.DeviceWake()
			}
		})
		worker(func() {
			for range 50 {
				governor.ObserveTraffic()
				governor.ReuseEpoch()
				governor.LastReuseBoundary()
			}
		})
		worker(func() {
			<-start
			governor.Close()
		})
		close(start)
		waitGroup.Wait()
	}
}

// settle gives the runtime a moment to retire goroutines that have already returned, so a baseline
// comparison measures the code under test rather than the scheduler.
func settle() {
	for range 50 {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
}

// TestReuseVerdictDoesNotWaitForTheStagger is the prompt's "correctness must not be staggered"
// requirement, made explicit.
//
// The stagger exists to keep speculative work - health checks, probes, provider refreshes,
// statistics - from arriving in the same instant as the request the user woke the phone to make. The
// reuse verdict is not speculative work: it decides whether the request that is about to arrive may
// be handed a socket that the sleep killed. If it waited for the longest stagger, the business path
// would be running for fifteen seconds before anything noticed the pool was stale, which is the
// failure the fix exists to remove.
//
// This test uses the SHIPPING stagger on purpose, and asserts both halves: the verdict is immediate,
// and speculative work is still held back.
func TestReuseVerdictDoesNotWaitForTheStagger(t *testing.T) {
	clock := newReuseTestClock()
	governor := NewGovernorWithClock(DefaultPolicy(), clock.Now)
	t.Cleanup(governor.Close)

	var boundaries []ReuseBoundary
	governor.AddReuseObserver(func(boundary ReuseBoundary) { boundaries = append(boundaries, boundary) })

	governor.SleepStarted()
	governor.DevicePaused()
	clock.Advance(time.Minute)
	governor.Resumed()
	governor.DeviceWake()

	require.Len(t, boundaries, 1, "the verdict waited for the stagger")
	require.Equal(t, ReuseRetire, boundaries[0].Action)
	require.Equal(t, uint64(1), governor.ReuseEpoch())
	require.Equal(t, StateWaking, governor.State(), "the shipping stagger no longer exists")
	require.False(t, governor.Allow().ProviderRefresh,
		"the stagger was collapsed: a provider refresh is running while the user waits")
	require.False(t, governor.Allow().Statistics)
	// The business path, though, is up: WAKING means the request the user just made may proceed.
	require.True(t, governor.WaitActive(context.Background()))
}

// TestTransitionStressCycles runs a hundred REAL path transitions, each one inside a sleep, and
// asserts the accounting, the goroutine baseline and the absence of a resurrection.
//
// A transition is not a sleep boundary and a sleep boundary is not a transition: the network epoch
// resets, the reuse epoch distrusts, and a hundred of them in a row must not blur the two - the
// reuse epoch must advance exactly once per sleep and never on the transition itself.
func TestTransitionStressCycles(t *testing.T) {
	governor, clock := reuseTestGovernor(t, ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second})
	var (
		boundaries atomic.Int64
		retires    atomic.Int64
	)
	governor.AddReuseObserver(func(boundary ReuseBoundary) {
		boundaries.Add(1)
		if boundary.Action == ReuseRetire {
			retires.Add(1)
		}
	})

	settle()
	before := runtime.NumGoroutine()

	const cycles = 100
	var expected uint64
	for range cycles {
		governor.SleepStarted()
		governor.DevicePaused()
		clock.Advance(30 * time.Second)
		// The path changes while the device is asleep, and comes back before the device does.
		governor.NetworkPaused()
		governor.NetworkWake()
		require.Equal(t, expected, governor.ReuseEpoch(),
			"a network transition advanced the reuse epoch")
		governor.Resumed()
		governor.DeviceWake()
		governor.ObserveTraffic()
		expected++
	}

	require.Equal(t, int64(cycles), boundaries.Load())
	require.Equal(t, int64(cycles), retires.Load())
	require.Equal(t, uint64(cycles), governor.ReuseEpoch())

	settle()
	after := runtime.NumGoroutine()
	require.LessOrEqual(t, after, before+2,
		"the transition path left goroutines behind: %d before, %d after %d cycles", before, after, cycles)

	// Close wins, and the generation does not rewind: a boundary after Close is a counted no-op, not
	// a resurrection of the lifecycle.
	governor.Close()
	governor.SleepStarted()
	governor.Resumed()
	require.Equal(t, int64(cycles), boundaries.Load(), "a boundary was published after Close")
	require.Equal(t, uint64(cycles), governor.ReuseEpoch())
}
