package trafficsched

import (
	"io"
	"math"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing/common/bufio"

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
	require.Zero(t, flow.Grants(),
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
	require.Positive(t, normal.Grants(),
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
		chosen, flow := scheduler.pickLocked()
		require.NotNil(t, flow, "a lane must be servable when both have waiters")
		picks = append(picks, int(chosen))
		scheduler.lanes[chosen].pop()
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
	chosen, flow := scheduler.pickLocked()
	require.Equal(t, laneNormal, chosen)
	require.Same(t, normal, flow)
	scheduler.lanes[laneNormal].pop()

	scheduler.inflightService = 0
	scheduler.lanes[laneHigh].push(high)
	chosen, flow = scheduler.pickLocked()
	require.Equal(t, laneHigh, chosen)
	require.Same(t, high, flow)
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
	require.Zero(t, normal.Grants(),
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
	require.Zero(t, high.Grants())
	require.Zero(t, normal.Grants())
	require.EqualValues(t, 1, high.AdmittedBytes(),
		"but the gate still observes the bytes, which is what makes the choice reversible")
	require.EqualValues(t, 1, normal.AdmittedBytes())

	// Granting a rate is what turns it on, and then the same flow is really scheduled.
	active := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(1 << 20), HighIdleWindow: time.Minute})
	activeHigh := active.NewFlow(trafficclass.ClassInteractive)
	activeNormal := active.NewFlow(trafficclass.ClassDefault)
	require.False(t, active.inert())
	require.NoError(t, activeHigh.wait(1))
	require.False(t, active.Armed(),
		"the paced modes must NOT arm: shaping that starts when interactive traffic arrives is "+
			"shaping that protects the second request, not the first")
	require.NoError(t, activeNormal.wait(64))
	require.Positive(t, activeNormal.Grants())
	activeNormal.done()
	activeHigh.done()
	require.NoError(t, active.Close())
}

// TestPacedModeShapesFromTheFirstWrite pins the change that question A forced.
//
// The ordering modes arm on high-priority activity. The paced modes must not: shaping that begins
// when an interactive request arrives cannot protect that request, because the queue it would have
// prevented is already full. This test asserts the mechanism directly - a single flow writing with
// no high-priority traffic anywhere is still shaped to the configured rate.
func TestPacedModeShapesFromTheFirstWrite(t *testing.T) {
	const (
		rate  = 100_000
		burst = 1024
	)
	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(rate), Burst: burst})
	defer scheduler.Close()
	flow := scheduler.NewFlow(trafficclass.ClassDefault)

	require.False(t, scheduler.Armed(), "the paced modes must never depend on arming")

	start := time.Now()
	const writes = 5
	for index := 0; index < writes; index++ {
		require.NoError(t, flow.wait(burst))
		flow.done()
	}
	elapsed := time.Since(start)

	// Four of the five writes have to wait a full bucket's worth of time.
	require.Greater(t, elapsed, time.Duration(writes-1)*time.Second*burst/rate*3/4,
		"a NORMAL flow must be shaped from its first write, with no interactive traffic in sight")
	require.Less(t, elapsed, time.Duration(writes)*time.Second*burst/rate*2)
	require.Zero(t, scheduler.Armed())
}

// TestOversizedWriteIsChargedNotExempted is question B, as an exact accounting property.
//
// The rule this replaced admitted any write larger than the bucket without charging it, because
// such a write can never be covered and the alternative looked like a deadlock. The consequence
// was that the largest writes were the only ones exempt from shaping.
//
// The charge is now split. The shared bucket pays what the write had to see, which is at most one
// burst and can therefore never hold another flow hostage. The flow that sent it pays the rest, in
// its own future, which is the only place that cost belongs.
func TestOversizedWriteIsChargedNotExempted(t *testing.T) {
	const (
		rate  = 2_000_000
		burst = 16 * 1024
	)
	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(rate), Burst: burst})
	defer scheduler.Close()

	offender := scheduler.NewFlow(trafficclass.ClassDefault)
	bystander := scheduler.NewFlow(trafficclass.ClassDefault)

	const oversized = 256 * 1024
	require.NoError(t, offender.wait(oversized), "the oversized write is admitted once")
	offender.done()

	scheduler.mu.Lock()
	tokensAfter := scheduler.tokens
	scheduler.mu.Unlock()
	require.GreaterOrEqual(t, tokensAfter, 0.0,
		"the shared bucket must never go negative: a negative balance is a bill every other flow "+
			"has to pay")

	// The rest of the cost lands on the flow that incurred it.
	expected := time.Duration(float64(oversized) / rate * float64(time.Second))
	start := time.Now()
	require.NoError(t, offender.wait(1024))
	offenderElapsed := time.Since(start)
	offender.done()
	require.Greater(t, offenderElapsed, expected/2,
		"an oversized write must not be free: the next write from that flow must pay for most of it")
	require.Less(t, offenderElapsed, expected*2)

	// And it must not have become everyone else's problem.
	start = time.Now()
	require.NoError(t, bystander.wait(1024))
	bystanderElapsed := time.Since(start)
	bystander.done()
	require.Less(t, bystanderElapsed, time.Duration(3)*time.Second*burst/rate,
		"a bystander must wait at most for the shared bucket, not for another flow's debt")
}

// TestOversizedWriteCannotBlockItsOwnLane pins the release valve: a flow paying off a large write
// must not stop the rest of its lane, or one large upload would stall every other interactive flow.
func TestOversizedWriteCannotBlockItsOwnLane(t *testing.T) {
	const (
		rate  = 2_000_000
		burst = 16 * 1024
	)
	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(rate), Burst: burst})
	defer scheduler.Close()

	bulk := scheduler.NewFlow(trafficclass.ClassInteractive)
	small := scheduler.NewFlow(trafficclass.ClassInteractive)

	require.NoError(t, bulk.wait(256*1024), "the bulk flow runs up a debt")
	bulk.done()

	start := time.Now()
	result := make(chan error, 1)
	go func() { result <- small.wait(256) }()
	require.NoError(t, awaitResult(t, result, "the small write"), 2*time.Second)
	elapsed := time.Since(start)
	small.done()
	require.Less(t, elapsed, 20*time.Millisecond,
		"a small write must not wait for another flow's debt; the debt is that flow's alone")
}

// TestAggregateShapingCoversTheHighPriorityLane pins the difference the HIGH-versus-HIGH
// experiment measured, at the level of the policy.
//
// Shaping only the NORMAL lane leaves a high-priority flow free to fill the acceptance windows,
// and a small high-priority write then waits behind exactly the queue the NORMAL lane was prevented
// from creating. The aggregate mode closes that by charging the same bucket for both lanes, while
// the lane policy still decides who spends it first.
func TestAggregateShapingCoversTheHighPriorityLane(t *testing.T) {
	const (
		rate  = 100_000
		burst = 1024
	)
	measure := func(mode Mode) time.Duration {
		scheduler := NewScheduler(Options{Mode: mode, RateSource: NewFixedRate(rate), Burst: burst})
		defer scheduler.Close()
		flow := scheduler.NewFlow(trafficclass.ClassInteractive)
		start := time.Now()
		const writes = 4
		for index := 0; index < writes; index++ {
			require.NoError(t, flow.wait(burst))
			flow.done()
		}
		return time.Since(start)
	}

	normalOnly := measure(ModePacedNormalOnly)
	aggregate := measure(ModePaced)

	require.Less(t, normalOnly, 10*time.Millisecond,
		"the NORMAL-lane-only shaper must leave high-priority writes entirely unshaped, which is "+
			"the hole the aggregate mode exists to close")
	require.Greater(t, aggregate, time.Duration(3)*time.Second*burst/rate/2,
		"aggregate shaping must charge the high-priority lane for what it sends")
}

// TestAdmittedRateMatchesTheConfiguredRate is the precision half of the shaping contract.
//
// # The two bounds are not the same kind of statement
//
// The UPPER bound is the safety property and it is exact: the scheduler charges the shared bucket
// min(size, burst) on every grant and refills it at the configured rate against its own clock, so
// no interval can admit more than burst + rate x interval whatever the host is doing. It has no
// tolerance and it is unchanged.
//
// The LOWER bound is a statement about the pacer's achievable period, and its derivation used to be
// missing a term. A write of `chunk` bytes is charged `chunk/rate` of future, and the parked flow is
// woken no earlier than the next pace tick, so the period the pacer actually achieves is
//
//	chunk/rate  +  paceTick  +  the host's wake-up latency
//
// Only the first term is the shaper's. The original comment derived the shortfall from `paceTick`
// alone (`about 13%` for 16 KiB), which left only two points of margin under a 0.85 bound - and the
// missing term is a property of the HOST, not a constant: measured with this rig, the excess is
// about 1.4-1.5 ms per write whether the machine is idle or carrying load 380. At load 381 the
// 16 KiB case read 1.668 MB/s against 2.097 configured (79.6%) and the test failed, while the exact
// upper bound held in the same run. The constant had already been lowered once (0.90, then 0.85) for
// the same reason, so lowering it again would have been the same non-fix a third time.
//
// # What replaces it
//
// The excess is MEASURED rather than assumed, by running the identical rig at 64 KiB. There the
// imposed period is 31.25 ms and the excess is 1.4-1.5 ms of it, so the excess is read with a few
// percent of relative error and does not depend on knowing the host. The 16 KiB bound is then the
// rate the pacer can reach with that measured excess:
//
//	chunk / (chunk/rate + measuredExcess)
//
// with the same 0.85 margin. This is not a weaker statement where a verdict is possible: a shaper
// that paced at half the configured rate still reads about 1.0 MB/s against a bound of about
// 1.5 MB/s, so halving is still caught. And the two sizes now cover two different faults - a
// regression in the pacer's wake granularity (`paceTick`) shows up as an inflated excess at 64 KiB,
// where the flat 0.85 bound is still applied, while a regression in the rate itself shows up at
// 16 KiB against the derived bound.
//
// The measurement runs through the REAL copy engine and a real socket, so it also covers the
// buffer sizes the engine chooses rather than only the scheduler's arithmetic.
func TestAdmittedRateMatchesTheConfiguredRate(t *testing.T) {
	if testing.Short() {
		t.Skip("rate precision measurement runs for several seconds")
	}
	const configured = 2 << 20
	const window = 2 * time.Second
	const coarseChunk = 64 * 1024
	const fineChunk = 16 * 1024

	// The coarse run measures the pace excess: the cost of being woken on a tick, in seconds per
	// write. Achieved period is elapsed/writes, and writes = admittedBytes/chunk, so the period is
	// chunk/rate directly - no window length enters it.
	coarseRate, coarseElapsed := measureAdmittedRate(t, coarseChunk, configured, window)
	imposedCoarsePeriod := float64(coarseChunk) / float64(configured)
	coarseExcess := float64(coarseChunk)/coarseRate - imposedCoarsePeriod

	require.LessOrEqual(t, coarseRate, float64(configured)*1.02,
		"the admitted rate must never exceed the configured one by more than the rounding of a "+
			"single write: an excess is the queue this exists to remove (measured %.3f MB/s against "+
			"%.3f configured)", coarseRate/1e6, float64(configured)/1e6)
	// The coarse size keeps the flat bound. It is the one that notices the wake granularity
	// itself getting worse, because that granularity IS the excess the fine size is excused.
	require.Greater(t, coarseRate, float64(configured)*0.85,
		"at a 31 ms period the pacer's own granularity is a few percent, so the flat bound still "+
			"applies (measured %.3f MB/s against %.3f configured over %s, achieved period %s "+
			"against an imposed %s)", coarseRate/1e6, float64(configured)/1e6, coarseElapsed,
		time.Duration(float64(coarseChunk)/coarseRate*float64(time.Second)),
		time.Duration(imposedCoarsePeriod*float64(time.Second)))

	// The measured excess is a mean over one window and the host's wake latency moves between
	// windows, so a negative reading is clamped and one pace tick is added as the allowance for
	// that movement. The allowance is the pacer's OWN declared wake granularity rather than a
	// second free constant: a write cannot be admitted before the tick that makes it eligible.
	if coarseExcess < 0 {
		coarseExcess = 0
	}
	maxExcess := coarseExcess + paceTick.Seconds()

	fineExpected := float64(fineChunk) / (float64(fineChunk)/float64(configured) + maxExcess)
	fineRate, fineElapsed := measureAdmittedRate(t, fineChunk, configured, window)
	fineExcess := float64(fineChunk)/fineRate - float64(fineChunk)/float64(configured)
	t.Logf("%d-byte writes: paced %.3f MB/s over %s, achieved period %s, excess %s; "+
		"pace excess measured at %d bytes %s, allowed %s; %d-byte pacer-achievable %.3f MB/s, "+
		"bound %.3f MB/s", coarseChunk, coarseRate/1e6, coarseElapsed.Round(time.Millisecond),
		time.Duration(float64(coarseChunk)/coarseRate*float64(time.Second)),
		time.Duration(coarseExcess*float64(time.Second)),
		fineChunk, time.Duration(coarseExcess*float64(time.Second)),
		time.Duration(maxExcess*float64(time.Second)),
		fineChunk, fineExpected/1e6, fineExpected*0.85/1e6)
	t.Logf("%d-byte writes: paced %.3f MB/s over %s, achieved period %s, excess %s",
		fineChunk, fineRate/1e6, fineElapsed.Round(time.Millisecond),
		time.Duration(float64(fineChunk)/fineRate*float64(time.Second)),
		time.Duration(fineExcess*float64(time.Second)))

	require.LessOrEqual(t, fineRate, float64(configured)*1.02,
		"the admitted rate must never exceed the configured one by more than the rounding of a "+
			"single write: an excess is the queue this exists to remove (measured %.3f MB/s against "+
			"%.3f configured)", fineRate/1e6, float64(configured)/1e6)
	require.Greater(t, fineRate, fineExpected*0.85,
		"the achieved rate must stay near what the pacer can actually reach on this host, within "+
			"the 0.85 margin (measured %.3f MB/s against %.3f MB/s reachable [configured %.3f, "+
			"achieved excess %s per write against an allowance of %s] over %s, with %d-byte writes "+
			"whose imposed period is %s)", fineRate/1e6, fineExpected/1e6, float64(configured)/1e6,
		time.Duration(fineExcess*float64(time.Second)),
		time.Duration(maxExcess*float64(time.Second)), fineElapsed, fineChunk,
		time.Duration(float64(fineChunk)/float64(configured)*float64(time.Second)))
}

// measureAdmittedRate runs one copy-engine rig for window and returns the rate the flow was
// admitted at.
//
// It is the measurement the test above is built from, factored out so the coarse run that measures
// the pace excess and the fine run that is judged against it are the same rig, byte for byte: the
// same writers, the same gate, the same socket pair and the same window. A rate of zero leaves the
// paced scheduler inert - `inert` is true whenever the rate source reports no rate - which is
// available as an unshaped control.
func measureAdmittedRate(t *testing.T, chunk int, rate int64, window time.Duration) (float64, time.Duration) {
	t.Helper()

	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(rate)})
	defer scheduler.Close()
	flow := scheduler.NewFlow(trafficclass.ClassDefault)

	sink, sinkPeer := net.Pipe()
	defer sink.Close()
	defer sinkPeer.Close()
	go func() { _, _ = io.Copy(io.Discard, sinkPeer) }()
	source, sourcePeer := net.Pipe()
	defer source.Close()
	defer sourcePeer.Close()

	gate := NewGate(sink, flow)
	var accepted atomic.Int64
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		payload := make([]byte, chunk)
		for {
			select {
			case <-stop:
				return
			default:
			}
			written, err := sourcePeer.Write(payload)
			accepted.Add(int64(written))
			if err != nil {
				return
			}
		}
	}()

	start := time.Now()
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = bufio.CopyWithIncreateBuffer(gate, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	}()

	time.Sleep(window)
	elapsed := time.Since(start)
	close(stop)
	<-writerDone

	admitted := float64(flow.AdmittedBytes()) / elapsed.Seconds()

	_ = source.Close()
	_ = sink.Close()
	<-copyDone

	return admitted, elapsed
}

// TestWritePeriodSaturatesInsteadOfWrapping covers the arithmetic at the edge of what a
// time.Duration can represent.
//
// The conversion from float64 nanoseconds to a Duration is undefined for a value outside the range,
// and both directions of that are wrong in a way that would not look like a failure: a value in the
// past admits the rate the shaper was configured to prevent, and a value in the far future stalls
// the connection. Neither is reachable from a copy loop whose buffers are bounded, and the helper
// that cannot produce either is three lines.
func TestWritePeriodSaturatesInsteadOfWrapping(t *testing.T) {
	// A generous rate with an ordinary write.
	require.Equal(t, 1*time.Second, writePeriod(1000, 1000))
	require.Equal(t, 500*time.Millisecond, writePeriod(1000, 2000))

	// Degenerate inputs have no period rather than a negative one.
	require.Zero(t, writePeriod(0, 1000))
	require.Zero(t, writePeriod(-1, 1000))
	require.Zero(t, writePeriod(1000, 0))
	require.Zero(t, writePeriod(1000, -1))

	// A period that cannot be represented saturates rather than becoming arbitrary.
	saturated := writePeriod(math.MaxInt, 1)
	require.Equal(t, time.Duration(math.MaxInt64), saturated)
	require.Positive(t, saturated)

	// And the value is only ever used to push a deadline forward, so saturation has to be a future
	// time rather than a past one.
	require.True(t, time.Now().Add(saturated).After(time.Now().Add(time.Hour)))
}

// TestPacedSchedulerLeavesNoGoroutineBehind pins the lifecycle of the wake loop and the ordering
// modes' timer.
//
// An idle scheduler holds no timer at all, and a wake loop exits when the last waiter is served.
// Both are properties that only show up as a slow leak in a process that runs for weeks, which is
// exactly the kind of thing a test has to look for on purpose.
func TestPacedSchedulerLeavesNoGoroutineBehind(t *testing.T) {
	baseline := runtime.NumGoroutine()

	for iteration := 0; iteration < 20; iteration++ {
		scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(1 << 30)})
		flow := scheduler.NewFlow(trafficclass.ClassDefault)
		for write := 0; write < 20; write++ {
			require.NoError(t, flow.wait(1024))
			flow.done()
		}
		require.NoError(t, scheduler.Close())
	}

	// The ordering modes start a disarm timer instead, and it has to stop too.
	for iteration := 0; iteration < 20; iteration++ {
		scheduler := NewScheduler(Options{Mode: ModeAdmission, HighIdleWindow: 10 * time.Millisecond})
		high := scheduler.NewFlow(trafficclass.ClassInteractive)
		require.NoError(t, high.wait(1))
		high.done()
		require.NoError(t, scheduler.Close())
	}

	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+2
	}, 5*time.Second, 20*time.Millisecond,
		"every scheduler goroutine must exit: the wake loop when its last waiter is served or the "+
			"scheduler closes, and the disarm timer when it disarms or the scheduler closes (%d "+
			"goroutines against a baseline of %d)", runtime.NumGoroutine(), baseline)
}

// TestReleaseAllDoesNotShutTheSchedulerDown pins the difference between ending the connections that
// exist and ending the scheduler: a network transition is the first, and a connection created after
// one must still be scheduled.
func TestReleaseAllDoesNotShutTheSchedulerDown(t *testing.T) {
	// A rate low enough that the first write's own period is a long wait: a flow pays for what it
	// sends in its own future, which is exactly the parking this test needs.
	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(100_000)})
	defer scheduler.Close()

	parked := scheduler.NewFlow(trafficclass.ClassDefault)
	require.NoError(t, parked.wait(1<<20))
	parked.done()

	result := make(chan error, 1)
	go func() { result <- parked.wait(1) }()
	time.Sleep(25 * time.Millisecond)

	scheduler.ReleaseAll()
	require.ErrorIs(t, awaitResult(t, result, "the parked flow"), ErrClosed)

	// The scheduler is still usable, which is the whole point of not closing it.
	fresh := scheduler.NewFlow(trafficclass.ClassBulk)
	require.NoError(t, fresh.wait(1), "a transition must not end the scheduler")
	fresh.done()
	require.False(t, fresh.HighPriority())

	// ReleaseAll is safe with nothing parked, and with a flow that was already released.
	scheduler.ReleaseAll()
	require.NoError(t, parked.Close())
	require.NoError(t, fresh.Close())
}

// TestRateSourceObservationSeam covers the seam a learning controller uses, without any timing.
//
// It always runs, including under the race detector, because the properties it checks are exactly
// the ones the detector can break: the observer is read from the same holder the rate came from, it
// is only consulted when one is installed, and replacing the source stops the old one being
// consulted. What it deliberately does NOT check is whether any particular control law is a good
// idea - see adaptive_research_test.go for that, and for why it is not shipped.
func TestRateSourceObservationSeam(t *testing.T) {
	observer := &countingRateSource{rate: 1 << 30}
	scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: observer})
	defer scheduler.Close()
	require.True(t, scheduler.observing.Load())

	flow := scheduler.NewFlow(trafficclass.ClassDefault)
	for index := 0; index < 16; index++ {
		start := flow.observeWriteStart()
		require.False(t, start.IsZero(), "an installed observer must be timed")
		flow.observeWrite(start, 4096)
	}
	require.EqualValues(t, 16, observer.count.Load())
	require.EqualValues(t, 16*4096, observer.bytes.Load())

	// Replacing the source must stop the old one from being consulted: a controller that is being
	// replaced cannot be observed and consulted as two different objects.
	plain := NewFixedRate(1 << 20)
	scheduler.SetRateSource(plain)
	require.False(t, scheduler.observing.Load())
	require.Zero(t, flow.observeWriteStart().Nanosecond(), "no observer, no clock read")
	flow.observeWrite(time.Now(), 4096)
	require.EqualValues(t, 16, observer.count.Load(), "the replaced observer must not be called")
	require.EqualValues(t, 1<<20, scheduler.Rate())

	// And with the shaping switched off altogether, a write is admitted without touching the queue.
	scheduler.SetRateSource(nil)
	require.True(t, scheduler.inert())
	require.NoError(t, flow.wait(1<<20))
	require.Zero(t, flow.Grants())
	flow.done()
}

// countingRateSource is a rate source that also observes, which is the shape a learned rate has.
type countingRateSource struct {
	rate  int64
	count atomic.Int64
	bytes atomic.Int64
}

func (c *countingRateSource) Rate() int64 { return c.rate }

func (c *countingRateSource) ObserveWrite(size int, _ time.Duration, _ bool) {
	c.count.Add(1)
	c.bytes.Add(int64(size))
}
