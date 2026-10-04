package trafficsched

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"

	"github.com/stretchr/testify/require"
)

// awaitResult waits for a flow operation to settle, failing the test rather than hanging it.
func awaitResult(t *testing.T, result <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not settle within the deadline", what)
		return nil
	}
}

// TestUncontendedNormalFlowIsPassThrough is the property that makes it safe to leave the scheduler
// installed. A configuration that never produces interactive traffic must never reach the
// scheduler body: no queue, no lock, no allocation, no disarm goroutine.
func TestUncontendedNormalFlowIsPassThrough(t *testing.T) {
	scheduler := NewScheduler(Options{})
	flow := scheduler.NewFlow(trafficclass.ClassDefault)

	require.NoError(t, flow.wait(4096))
	require.Zero(t, flow.grants.Load(),
		"an uncontended NORMAL write must not reach the scheduler body")
	require.EqualValues(t, 4096, flow.admitted.Load(),
		"but it is still accounted, which is how a scheduler that quietly left the path is "+
			"distinguishable from a working one")
	// done() must be a safe no-op when wait() took the fast path.
	flow.done()
	require.NoError(t, flow.wait(1))
	flow.done()

	require.False(t, scheduler.Armed())
}

// TestHighPriorityWriteArmsTheScheduler pins that interactive traffic, and only interactive
// traffic, turns scheduling on.
func TestHighPriorityWriteArmsTheScheduler(t *testing.T) {
	scheduler := NewScheduler(Options{HighIdleWindow: time.Minute})
	normal := scheduler.NewFlow(trafficclass.ClassDefault)
	require.False(t, scheduler.Armed())

	require.NoError(t, normal.wait(1))
	normal.done()
	require.False(t, scheduler.Armed(), "NORMAL traffic must not arm the scheduler itself")

	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	require.NoError(t, high.wait(1))
	require.True(t, scheduler.Armed(),
		"a high-priority write must arm the scheduler, or NORMAL traffic would never yield")

	// The high-priority write completes, then the same NORMAL flow takes the scheduled path.
	high.done()
	require.NoError(t, normal.wait(1))
	require.Positive(t, normal.grants.Load(),
		"once armed, NORMAL writes must go through the scheduler")
	normal.done()
}

// TestNormalYieldsToAnInFlightHighPriorityWrite is ModeAdmission's whole mechanism: a NORMAL write
// is not admitted while a high-priority write is in progress, so NORMAL does not add itself to the
// queue ahead of work that has already started.
func TestNormalYieldsToAnInFlightHighPriorityWrite(t *testing.T) {
	scheduler := NewScheduler(Options{HighIdleWindow: time.Minute})
	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	normal := scheduler.NewFlow(trafficclass.ClassDefault)

	require.NoError(t, high.wait(64), "the high-priority write starts immediately")

	result := make(chan error, 1)
	go func() { result <- normal.wait(64) }()

	select {
	case <-result:
		t.Fatal("NORMAL must not be admitted while a high-priority write is in flight")
	case <-time.After(75 * time.Millisecond):
	}

	high.done()
	require.NoError(t, awaitResult(t, result, "the NORMAL write"))
	normal.done()

	// A second high-priority write must still be admitted immediately - the yield is one-way.
	require.NoError(t, high.wait(64))
	high.done()
}

// TestHighPriorityFlowIsNeverDelayedByAnotherHighPriorityFlow pins that the yield is one-way: two
// interactive flows must not serialise each other in the cheap mode.
func TestHighPriorityFlowIsNeverDelayedByAnotherHighPriorityFlow(t *testing.T) {
	scheduler := NewScheduler(Options{HighIdleWindow: time.Minute})
	first := scheduler.NewFlow(trafficclass.ClassInteractive)
	second := scheduler.NewFlow(trafficclass.ClassInteractive)

	require.NoError(t, first.wait(64))
	result := make(chan error, 1)
	go func() { result <- second.wait(64) }()

	require.NoError(t, awaitResult(t, result, "the second high-priority write"),
		"a high-priority write must never wait for another high-priority write")

	first.done()
	second.done()
}

// TestPickLockedServesHighFirstWithANormalFloor is the priority policy, tested directly so the
// ratio is exact rather than dependent on goroutine timing.
func TestPickLockedServesHighFirstWithANormalFloor(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModeService, HighPerNormal: 4})
	high := &Flow{sched: scheduler, high: true, lane: laneHigh}
	normal := &Flow{sched: scheduler, lane: laneNormal}

	var picks []int
	for index := 0; index < 10; index++ {
		scheduler.lanes[laneHigh].push(high)
		scheduler.lanes[laneNormal].push(normal)
		scheduler.inflightService = 0
		chosen := scheduler.pickLocked()
		require.GreaterOrEqual(t, chosen, 0, "a lane must be servable when both have waiters")
		picks = append(picks, chosen)
		scheduler.lanes[lane(chosen)].pop()
	}

	require.Equal(t, []int{0, 0, 0, 0, 1, 0, 0, 0, 0, 1}, picks,
		"four high-priority grants, then one NORMAL: high-priority first with a floor that stops "+
			"a saturated high-priority lane from starving NORMAL")
}

// TestPickLockedServesTheOnlyLaneThatHasWorkers keeps the floor from starving high-priority
// traffic in the other direction.
func TestPickLockedServesTheOnlyLaneThatHasWorkers(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModeService, HighPerNormal: 4})
	high := &Flow{sched: scheduler, high: true, lane: laneHigh}
	normal := &Flow{sched: scheduler, lane: laneNormal}

	scheduler.inflightService = 0
	scheduler.lanes[laneNormal].push(normal)
	require.Equal(t, int(laneNormal), scheduler.pickLocked())
	scheduler.lanes[laneNormal].pop()

	scheduler.inflightService = 0
	scheduler.lanes[laneHigh].push(high)
	require.Equal(t, int(laneHigh), scheduler.pickLocked())
	scheduler.lanes[laneHigh].pop()
}

// TestOneLargeHighPriorityFlowCannotStarveATinyOne is the within-lane fairness requirement.
//
// The lane is FIFO, so a flow that has just been served goes to the back when it asks again. That
// is what gives a small interactive request a turn against a bulk transfer that shares its class.
func TestOneLargeHighPriorityFlowCannotStarveATinyOne(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModeService})
	huge := &Flow{sched: scheduler, high: true, lane: laneHigh}
	tiny := &Flow{sched: scheduler, high: true, lane: laneHigh}

	scheduler.lanes[laneHigh].push(huge)
	scheduler.lanes[laneHigh].push(tiny)

	first := scheduler.lanes[laneHigh].pop()
	require.Same(t, huge, first, "the queue is FIFO")
	// The huge flow wants to write again immediately, which is exactly the starvation shape.
	scheduler.lanes[laneHigh].push(first)

	second := scheduler.lanes[laneHigh].pop()
	require.Same(t, tiny, second,
		"the tiny flow must be served next; a lane that always returned to the head would starve it")
}

// TestNeitherLaneStarvesWhenBothAreBusy is the liveness requirement end to end.
//
// The exact 4:1 ratio is owned by TestPickLockedServesHighFirstWithANormalFloor, which tests the
// policy directly. A live two-goroutine run cannot pin a ratio honestly: the weight only decides
// between lanes that are waiting AT THE SAME INSTANT, so a lane that is briefly not parked does
// not collect the credit it would have had. What a live run can and must show is that neither lane
// stalls, which is the property a scheduler bug actually breaks.
func TestNeitherLaneStarvesWhenBothAreBusy(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModeService, HighIdleWindow: time.Minute})
	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	normal := scheduler.NewFlow(trafficclass.ClassDefault)

	// Arm the scheduler, then release the initial grant.
	require.NoError(t, high.wait(1))
	high.done()

	var (
		mu     sync.Mutex
		counts = map[lane]int{}
	)
	stop := make(chan struct{})
	var workers sync.WaitGroup
	worker := func(flow *Flow, which lane) {
		defer workers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := flow.wait(1); err != nil {
				return
			}
			mu.Lock()
			counts[which]++
			mu.Unlock()
			flow.done()
		}
	}
	workers.Add(2)
	go worker(high, laneHigh)
	go worker(normal, laneNormal)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return counts[laneHigh]+counts[laneNormal] >= 200
	}, 5*time.Second, time.Millisecond, "both flows must make progress")

	close(stop)
	workers.Wait()
	_ = scheduler.Close()

	mu.Lock()
	highGrants, normalGrants := counts[laneHigh], counts[laneNormal]
	mu.Unlock()

	require.Positive(t, normalGrants,
		"NORMAL must never be starved by a busy high-priority lane")
	require.Positive(t, highGrants, "and high priority must make progress too")
}

// TestShutdownReleasesParkedFlows is the liveness half of the lifecycle: a copy goroutine parked in
// the gate is not inside a write, so closing the connection does not wake it. Only the scheduler
// can.
func TestShutdownReleasesParkedFlows(t *testing.T) {
	scheduler := NewScheduler(Options{HighIdleWindow: time.Minute})
	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	normal := scheduler.NewFlow(trafficclass.ClassDefault)

	require.NoError(t, high.wait(64))

	result := make(chan error, 1)
	go func() { result <- normal.wait(64) }()
	time.Sleep(25 * time.Millisecond)

	require.NoError(t, scheduler.Close())
	require.ErrorIs(t, awaitResult(t, result, "the parked NORMAL write"), ErrClosed)
	high.done()
}

// TestClosingAFlowReleasesItAndItsSlot covers both directions of Flow.Close: waking a flow parked
// on the queue, and handing back a slot a granted flow never released because it never wrote.
func TestClosingAFlowReleasesItAndItsSlot(t *testing.T) {
	t.Run("parked flow is released", func(t *testing.T) {
		scheduler := NewScheduler(Options{HighIdleWindow: time.Minute})
		high := scheduler.NewFlow(trafficclass.ClassInteractive)
		normal := scheduler.NewFlow(trafficclass.ClassDefault)
		require.NoError(t, high.wait(64))

		result := make(chan error, 1)
		go func() { result <- normal.wait(64) }()
		time.Sleep(25 * time.Millisecond)

		require.NoError(t, normal.Close())
		require.ErrorIs(t, awaitResult(t, result, "the parked NORMAL write"), ErrClosed)
		high.done()
	})

	t.Run("granted flow hands its slot back", func(t *testing.T) {
		scheduler := NewScheduler(Options{Mode: ModeService, HighIdleWindow: time.Minute})
		first := scheduler.NewFlow(trafficclass.ClassInteractive)
		require.NoError(t, first.wait(64), "the first flow takes the single service slot")

		// A connection that dies between the grant and the write must not stall the lane.
		require.NoError(t, first.Close())

		second := scheduler.NewFlow(trafficclass.ClassInteractive)
		result := make(chan error, 1)
		go func() { result <- second.wait(64) }()
		require.NoError(t, awaitResult(t, result, "the next flow"),
			"the abandoned slot must have been returned, or this blocks forever")
		second.done()
	})

	t.Run("close is idempotent", func(t *testing.T) {
		scheduler := NewScheduler(Options{})
		flow := scheduler.NewFlow(trafficclass.ClassDefault)
		require.NoError(t, flow.Close())
		require.NoError(t, flow.Close())
	})
}

// TestDisarmRestoresPassThrough is the other half of the idle window: once interactive traffic
// stops, NORMAL traffic must go back to the immediate path rather than paying for a lane that has
// nothing to arbitrate against.
func TestDisarmRestoresPassThrough(t *testing.T) {
	scheduler := NewScheduler(Options{HighIdleWindow: 40 * time.Millisecond})
	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	normal := scheduler.NewFlow(trafficclass.ClassDefault)

	require.NoError(t, high.wait(1))
	high.done()
	require.True(t, scheduler.Armed())

	require.Eventually(t, func() bool { return !scheduler.Armed() }, 2*time.Second, 2*time.Millisecond,
		"the scheduler must disarm once high-priority activity stops")

	require.NoError(t, normal.wait(1))
	normal.done()
	require.Zero(t, normal.grants.Load(),
		"and NORMAL writes must be back on the immediate path")
}

// TestSchedulerSurvivesConcurrentFlowChurn runs the lifecycle operations against each other under
// -race: creating, waiting, completing and closing flows while the scheduler grants.
func TestSchedulerSurvivesConcurrentFlowChurn(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModeService, HighIdleWindow: time.Minute})
	arm := scheduler.NewFlow(trafficclass.ClassInteractive)
	require.NoError(t, arm.wait(1))
	arm.done()

	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		class := trafficclass.ClassDefault
		if index%2 == 0 {
			class = trafficclass.ClassInteractive
		}
		workers.Add(1)
		go func(class trafficclass.Class) {
			defer workers.Done()
			for iteration := 0; iteration < 50; iteration++ {
				flow := scheduler.NewFlow(class)
				if err := flow.wait(32); err == nil {
					flow.done()
				}
				_ = flow.Close()
			}
		}(class)
	}
	workers.Wait()
	require.NoError(t, scheduler.Close())
}

// TestTheInstalledDefaultIsInert pins the production default and the reasoning behind it.
//
// The contention experiment measured that reordering writes does not move the receiver-visible
// p99, so the configuration that ships must provably do nothing rather than do something that
// looks like scheduling. "Inert" means exactly that: no queue, no lock, no disarm goroutine, not
// even for a high-priority flow that by any other reading would have armed the scheduler.
func TestTheInstalledDefaultIsInert(t *testing.T) {
	scheduler := NewScheduler(Options{Mode: ModePaced})
	high := scheduler.NewFlow(trafficclass.ClassInteractive)
	normal := scheduler.NewFlow(trafficclass.ClassDefault)

	require.True(t, scheduler.inert())
	require.NoError(t, high.wait(1))
	require.NoError(t, normal.wait(1))
	require.False(t, scheduler.Armed(),
		"an inert scheduler must not even start the arm/disarm machinery")
	require.Zero(t, high.grants.Load())
	require.Zero(t, normal.grants.Load())
	require.EqualValues(t, 1, high.AdmittedBytes(),
		"but the gate still observes the bytes, which is what makes the choice reversible")
	require.EqualValues(t, 1, normal.AdmittedBytes())

	// Granting a rate is what turns it on, and then the same flow is really scheduled.
	active := NewScheduler(Options{Mode: ModePaced, NormalRate: 1 << 20, HighIdleWindow: time.Minute})
	activeHigh := active.NewFlow(trafficclass.ClassInteractive)
	activeNormal := active.NewFlow(trafficclass.ClassDefault)
	require.False(t, active.inert())
	require.NoError(t, activeHigh.wait(1))
	require.True(t, active.Armed())
	require.NoError(t, activeNormal.wait(64))
	require.Positive(t, activeNormal.grants.Load())
	activeNormal.done()
	activeHigh.done()
	require.NoError(t, active.Close())
}
