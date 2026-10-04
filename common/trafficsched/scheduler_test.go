package trafficsched

import (
	"fmt"
	"io"
	"net"
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
// A shaper that is approximately right is not right: a rate the path sustains is only safe to
// configure if the admitted rate does not exceed it, because the excess is exactly the queue the
// feature exists to prevent. The measurement runs through the REAL copy engine and a real socket, so
// it also covers the buffer sizes the engine chooses rather than only the scheduler's arithmetic.
func TestAdmittedRateMatchesTheConfiguredRate(t *testing.T) {
	if testing.Short() {
		t.Skip("rate precision measurement runs for several seconds")
	}
	const configured = 2 << 20
	for _, chunk := range []int{16 * 1024, 64 * 1024} {
		t.Run(fmt.Sprintf("%dKiB-writes", chunk/1024), func(t *testing.T) {
			scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(configured)})
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

			time.Sleep(2 * time.Second)
			elapsed := time.Since(start)
			close(stop)
			<-writerDone

			admitted := float64(flow.AdmittedBytes()) / elapsed.Seconds()
			require.LessOrEqual(t, admitted, float64(configured)*1.02,
				"the admitted rate must never exceed the configured one by more than the rounding of "+
					"a single write: an excess is the queue this exists to remove")
			require.Greater(t, admitted, float64(configured)*0.90,
				"and it must be within a tenth of it, or the configuration is a promise the shaper "+
					"does not keep")

			_ = source.Close()
			_ = sink.Close()
			<-copyDone
		})
	}
}
