package group

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the handoff between a traffic-triggered forced recheck and an already-running health
// check.
//
// # The defect these pin
//
// `urlTest` began with `if g.checking.Swap(true) { return }`. A forced recheck arriving while a
// PERIODIC round was running therefore returned immediately, and `recheckPending` was cleared by
// the worker that had just done nothing. The forced probe the traffic failure asked for was lost.
//
// That is not a cosmetic loss. A periodic round SKIPS any member whose measurement is still fresh
// - and a fresh measurement is exactly the state a traffic failure leaves behind. So the node that
// had just failed to carry traffic was never re-measured, and the following selection was free to
// choose it again on the strength of the measurement the failure had already contradicted.
//
// The fix queues the request behind the running round. These tests prove the probe actually
// happens, by counting probes rather than by inspecting internal flags.

// barrierOutbound probes on demand and can be held mid-probe.
type barrierOutbound struct {
	adapter.Outbound
	tag string
	// probes counts every completed probe.
	probes atomic.Int32
	// gate, when non-nil, is waited on before a probe completes.
	gate chan struct{}
	// entered is signalled when a probe has started, so a test can wait for it to be in flight.
	entered chan struct{}
	// enteredOnce guards the send on entered.
	enteredOnce sync.Once
}

func (o *barrierOutbound) Type() string      { return "stub" }
func (o *barrierOutbound) Tag() string       { return o.tag }
func (o *barrierOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *barrierOutbound) startProbe(ctx context.Context) error {
	if o.entered != nil {
		o.enteredOnce.Do(func() { close(o.entered) })
	}
	if o.gate != nil {
		select {
		case <-o.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (o *barrierOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := o.startProbe(ctx); err != nil {
		return nil, err
	}
	o.probes.Add(1)
	return &stubConn{}, nil
}

func (o *barrierOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := o.startProbe(ctx); err != nil {
		return nil, err
	}
	o.probes.Add(1)
	return &stubPacketConn{}, nil
}

// TestTrafficFailureQueuesForcedRecheckBehindRunningCheck is the release blocker (§7).
//
// A periodic round is held mid-flight. A FORCED round is requested while it runs. When the periodic
// round is released, the forced round must run and must PROBE - proven by the probe counter.
//
// # Why this drives CheckOutbounds directly
//
// The defect is in urlTest's busy branch: a forced round arriving while `checking` is held used to
// return silently, and nothing else was going to serve it. Requesting the recheck through
// requestHealthRecheck would not isolate that, because that path also starts a worker which would
// serve the debt on its own - the test would pass even with the bug present. Driving the forced
// round directly is both the exact failing path and the path the recheck worker itself takes.
func TestTrafficFailureQueuesForcedRecheckBehindRunningCheck(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{})

	node := &barrierOutbound{tag: "node-a", gate: gate, entered: entered}
	group, storage := newGroupFixture(t, "https://probe.example/generate_204", node)

	// A FRESH measurement, so a periodic round would skip this node - which is exactly why only a
	// real forced round can re-examine it.
	storage.StoreHealthHistory("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})

	group.selected.Store(&selectedState{tcp: node, udp: node})

	// --- a round starts and blocks inside its probe ---
	go group.CheckOutbounds(group.ctx, true)

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the running round never started probing")
	}

	probesWhileHeld := node.probes.Load()

	// --- a forced round is requested while it is held ---
	forcedReturned := make(chan struct{})
	go func() {
		defer close(forcedReturned)
		group.CheckOutbounds(group.ctx, true)
	}()

	select {
	case <-forcedReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("the forced round blocked instead of queueing")
	}

	// It must not have produced a probe yet: the running round still holds the guard.
	require.Equal(t, probesWhileHeld, node.probes.Load(),
		"the queued round cannot have run while the other round is still in flight")

	// --- release the held round ---
	close(gate)

	// The queued round must now run and must actually PROBE.
	require.Eventually(t, func() bool { return node.probes.Load() > probesWhileHeld },
		3*time.Second, 5*time.Millisecond,
		"the forced round was LOST: it returned because a round was already running, and nothing "+
			"re-ran it. The node that just failed to carry traffic is never re-measured, so "+
			"selection re-reads the measurement the failure already contradicted")

	// The probe is the contract, and it is asserted above. The run counter is deliberately NOT
	// asserted here: the bounded wait in the drain loop can serve the debt on a path that reaches
	// the probe before incrementing, so asserting the counter would be a timing assumption layered
	// on top of the behaviour already proven. The counter is asserted where it is meaningful - the
	// coalescing test, which waits for the worker to go idle first.
}

// TestTrafficFailureBurstCoalescesToOneQueuedForcedRound is §8.
//
// Many failures arriving while a round runs must produce ONE extra round, not one per failure and
// not zero.
func TestTrafficFailureBurstCoalescesToOneQueuedForcedRound(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{})

	node := &barrierOutbound{tag: "node-a", gate: gate, entered: entered}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	go group.CheckOutbounds(group.ctx, true)

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the periodic round never started probing")
	}

	// 100 failures while the round is held.
	const burst = 100
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < burst; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			group.requestHealthRecheck()
		}()
	}
	close(start)
	waitGroup.Wait()

	close(gate)

	// Allow the queued round to run to completion.
	require.Eventually(t, func() bool { return group.recheckRuns.Load() >= 1 },
		3*time.Second, 5*time.Millisecond,
		"a burst of failures must produce at least the one queued forced round")

	// Wait for the worker to go idle, so the count is final rather than a snapshot mid-drain.
	require.Eventually(t, func() bool {
		group.recheckAccess.Lock()
		defer group.recheckAccess.Unlock()
		return !group.recheckWorker
	}, 3*time.Second, 5*time.Millisecond, "the recheck worker must finish")

	// The bound is exact and small.
	//
	// The 100 requests all arrive while one round is held, so they coalesce into at most one extra
	// round: two in total. The number that would indicate the defect is 100 - one probe per failing
	// connection. A count is used rather than a timing window because timing cannot distinguish
	// "coalesced" from "fast".
	require.LessOrEqual(t, group.recheckRuns.Load(), int32(2),
		"%d concurrent failures must coalesce into at most ONE extra forced round (the running "+
			"round plus one), not one round per failure", burst)
	require.GreaterOrEqual(t, group.recheckRuns.Load(), int32(1),
		"and at least one forced round must actually run")
}

// TestForcedRecheckIsQueuedRatherThanDroppedWhenBusy is the direct unit-level statement.
//
// A forced round requested while the checking guard is held must leave a debt behind.
func TestForcedRecheckIsQueuedRatherThanDroppedWhenBusy(t *testing.T) {
	node := &barrierOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

	// Occupy the guard, as a running round would.
	require.False(t, group.checking.Swap(true))
	defer group.checking.Store(false)

	group.queueForcedRecheck()

	group.recheckAccess.Lock()
	queued := group.recheckQueued
	worker := group.recheckWorker
	group.recheckAccess.Unlock()

	require.True(t, queued,
		"a forced round that cannot run now must be remembered; dropping it is the defect")
	require.True(t, worker, "and a worker must be responsible for draining it")
}

// TestClosedGroupDoesNotQueueWork keeps the terminal guarantee.
func TestClosedGroupDoesNotQueueWork(t *testing.T) {
	node := &barrierOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

	require.NoError(t, group.Close())
	time.Sleep(20 * time.Millisecond)

	group.requestHealthRecheck()

	group.recheckAccess.Lock()
	queued := group.recheckQueued
	worker := group.recheckWorker
	group.recheckAccess.Unlock()

	require.False(t, queued, "a closed group must not accept a recheck")
	require.False(t, worker, "and must not start a worker")
}

// TestForcedRoundQueuesWhenGuardHeldOutsideAWorker is the precise isolation of urlTest's handoff.
//
// The end-to-end test above cannot isolate it, because the drain worker also serves the debt and
// would mask a dropped request. Here the checking guard is held WITHOUT any worker being involved,
// which is the situation a direct forced refresh is in - a native "test this URLTest group" call,
// or PostStart, both of which invoke CheckOutbounds directly.
//
// With the guard held by something that is not the drain worker, the only thing that can preserve
// the request is urlTest's own queueing branch.
func TestForcedRoundQueuesWhenGuardHeldOutsideAWorker(t *testing.T) {
	node := &barrierOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	// Hold the guard as a foreign round would, with no drain worker in existence.
	require.False(t, group.checking.Swap(true))

	group.recheckAccess.Lock()
	require.False(t, group.recheckWorker, "no worker must exist for this test to isolate the branch")
	group.recheckAccess.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		group.CheckOutbounds(group.ctx, true)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a forced round must return rather than block while the guard is held")
	}

	// Release the guard so the queued work can proceed.
	group.checking.Store(false)

	// The request must have been remembered AND a worker must now serve it.
	require.Eventually(t, func() bool { return node.probes.Load() >= 1 },
		3*time.Second, 5*time.Millisecond,
		"a forced round arriving while the guard is held by something other than a worker was "+
			"dropped: nothing re-ran it, so a direct forced refresh silently did nothing")
}
