package group

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for state recovery when a forced health round panics.
//
// # The defect these pin
//
// The drain worker released `checking` and `recheckWorker` only on the normal path. A panic inside
// the round was recovered by an outer defer that logged it and returned, leaving both flags set:
//
//	checking = true       -> every later periodic check sees a round "already running" and returns
//	recheckWorker = true  -> no later traffic failure can start a worker
//
// The group's health subsystem was then permanently dead: no probe could ever run again, so
// selection kept using whatever evidence it had when the panic happened. Recovering the panic
// without restoring the state machine turned a crash into a silent, permanent stall.
//
// The tests inject the panic through a dialer, which is the closest point to production that a test
// can control without adding a panic flag to the production code.

// panickingOutbound panics on the Nth probe and succeeds otherwise.
type panickingOutbound struct {
	adapter.Outbound
	tag string
	// panicOn is the 1-based probe number that panics. Zero disables panicking.
	panicOn atomic.Int32
	probes  atomic.Int32
}

func (o *panickingOutbound) Type() string      { return "panicking" }
func (o *panickingOutbound) Tag() string       { return o.tag }
func (o *panickingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *panickingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	attempt := o.probes.Add(1)
	if panicAt := o.panicOn.Load(); panicAt != 0 && attempt == panicAt {
		panic("injected failure inside a forced health round")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *panickingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	attempt := o.probes.Add(1)
	if panicAt := o.panicOn.Load(); panicAt != 0 && attempt == panicAt {
		panic("injected failure inside a forced health round")
	}
	return nil, net.ErrClosed
}

// waitForIdleWorker waits until no recheck worker is draining.
func waitForIdleWorker(t *testing.T, group *URLTestGroup) {
	t.Helper()
	require.Eventually(t, func() bool {
		group.recheckAccess.Lock()
		defer group.recheckAccess.Unlock()
		return !group.recheckWorker
	}, 5*time.Second, 5*time.Millisecond, "the recheck worker never became idle")
}

// TestForcedRecheckPanicDoesNotLatchChecking is problem 2.
//
// The panic is injected into the round BODY, so it happens on the worker's own goroutine - which is
// where the recovery has to work. A panic inside a member probe is a different case and is covered
// separately, because batch.Go runs members on their own goroutines and does not recover.
func TestForcedRecheckPanicDoesNotLatchChecking(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	group.forcedRoundOverride = func() {
		panic("injected failure inside the forced round body")
	}

	group.requestHealthRecheck()
	waitForIdleWorker(t, group)

	require.False(t, group.checking.Load(),
		"a panic left `checking` latched, so every later periodic check will see a round "+
			"\"already running\" and return without measuring anything. The health subsystem is "+
			"permanently stalled and selection keeps using stale evidence forever")

	// And the group can still run a round afterwards.
	group.forcedRoundOverride = nil
	require.True(t, group.checking.CompareAndSwap(false, true),
		"a later round must be able to take the checking guard")
	group.checking.Store(false)
}

// TestForcedRecheckPanicDoesNotLatchWorker is problem 2, the other flag.
func TestForcedRecheckPanicDoesNotLatchWorker(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &observingOutbound{tag: "node-a"}
	group, storage := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	group.forcedRoundOverride = func() {
		panic("injected failure inside the forced round body")
	}

	group.requestHealthRecheck()
	waitForIdleWorker(t, group)

	group.recheckAccess.Lock()
	latched := group.recheckWorker
	group.recheckAccess.Unlock()
	require.False(t, latched,
		"a panic left `recheckWorker` latched, so no later traffic failure can ever start a "+
			"worker again and the queued debt is never served")

	// A second request must actually run a round and record evidence.
	group.forcedRoundOverride = nil
	group.requestHealthRecheck()

	require.Eventually(t, func() bool {
		return storage.LoadURLTestHistoryFor("node-a", group.scope) != nil
	}, 5*time.Second, 5*time.Millisecond,
		"a recheck requested after a panicking round must actually run; if the worker flag were "+
			"latched it would be dropped forever")

	waitForIdleWorker(t, group)
}

// TestForcedRecheckRecoversAndProbesAfterPanic is the combined statement.
//
// The first round panics; the second must complete successfully and write health evidence.
func TestForcedRecheckRecoversAndProbesAfterPanic(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &panickingOutbound{tag: "node-a"}
	node.panicOn.Store(1)
	group, storage := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	group.requestHealthRecheck()
	waitForIdleWorker(t, group)

	// Nothing was stored: the round panicked before it could measure.
	require.Nil(t, storage.LoadURLTestHistoryFor("node-a", group.scope))

	// The fault is gone. A new recheck must run to completion and store evidence.
	node.panicOn.Store(0)
	group.requestHealthRecheck()

	require.Eventually(t, func() bool {
		return storage.LoadURLTestHistoryFor("node-a", group.scope) != nil
	}, 5*time.Second, 5*time.Millisecond,
		"after a panicking round the group must be able to measure and record again; a latched "+
			"state machine means it never will")

	waitForIdleWorker(t, group)
}

// TestPanicDoesNotCauseSelfRetryLoop is §13.
//
// A panicking round must not automatically re-queue itself. If it did, a reproducible panic would
// become an unbounded retry loop that pins a CPU and floods the log.
func TestPanicDoesNotCauseSelfRetryLoop(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	// EVERY round panics, on the worker's own goroutine.
	group.forcedRoundOverride = func() {
		panic("injected failure inside the forced round body")
	}

	group.requestHealthRecheck()
	waitForIdleWorker(t, group)

	// Allow any would-be retry loop time to run away.
	time.Sleep(300 * time.Millisecond)

	require.LessOrEqual(t, group.recheckRuns.Load(), int32(3),
		"a panicking round must not re-queue itself without bound; a reproducible panic would "+
			"otherwise spin forever, consuming CPU and filling the log")

	// The worker must be idle rather than still retrying.
	group.recheckAccess.Lock()
	worker := group.recheckWorker
	group.recheckAccess.Unlock()
	require.False(t, worker)
}

// TestMemberPanicDoesNotKillTheProcess is the other half of problem 2, and the more severe one.
//
// batch.Go runs each member on its own goroutine and does NOT recover, so a panic there reaches the
// runtime and terminates the whole process - one misbehaving outbound taking down sing-box. The
// round must instead record that member as unavailable and finish measuring the others.
func TestMemberPanicDoesNotKillTheProcess(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	badNode := &panickingOutbound{tag: "node-bad"}
	badNode.panicOn.Store(1)

	goodNode := &observingOutbound{tag: "node-good"}

	group, storage := newGroupFixture(t, link, badNode, goodNode)
	group.selected.Store(&selectedState{tcp: goodNode, udp: goodNode})

	// The round must complete rather than killing the process.
	done := make(chan struct{})
	go func() {
		defer close(done)
		group.CheckOutbounds(group.ctx, true)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the round never completed")
	}

	// The good member was still measured.
	require.Eventually(t, func() bool {
		return storage.LoadURLTestHistoryFor("node-good", group.scope) != nil
	}, 5*time.Second, 5*time.Millisecond,
		"one member panicking must not stop the others from being measured")

	require.Nil(t, storage.LoadURLTestHistoryFor("node-bad", group.scope),
		"the panicking member is treated as unavailable, like a failed dial")
}

// TestQueuedRecheckSurvivesConcurrentPanickingRound is the release blocker for orphaned debt.
//
// # The state that must not exist
//
// A forced round is running. Another traffic failure arrives, which records new debt but does not
// start a worker (one already exists). The running round then panics. The recovery released
// `checking` and `recheckWorker` but never considered `recheckQueued`, so it could leave:
//
//	checking = false
//	recheckWorker = false
//	recheckQueued = true
//
// That is debt with nobody to serve it. Nothing would probe again until some unrelated future
// failure happened to arrive, so a node that failed to carry traffic stays eligible on the strength
// of the very measurement the failure contradicted.
//
// The test deliberately stops requesting anything after step 7. If it did, a later request would
// start a worker by itself and the test would pass without proving anything about the recovery.

// barrierRound lets a test hold a forced round open and then decide how it ends.
type barrierRound struct {
	entered chan struct{}
	release chan struct{}
	panicIt bool
}

func (b *barrierRound) run() {
	close(b.entered)
	<-b.release
	if b.panicIt {
		panic("injected failure inside the forced round body")
	}
}

// TestQueuedRecheckSurvivesConcurrentPanickingRound is problem 1 of this round.
func TestQueuedRecheckSurvivesConcurrentPanickingRound(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &observingOutbound{tag: "node-a"}
	group, storage := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	// The FIRST round blocks and then panics; later rounds run normally.
	barrier := &barrierRound{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		panicIt: true,
	}
	var rounds atomic.Int32
	group.forcedRoundOverride = func() {
		if rounds.Add(1) == 1 {
			barrier.run()
			return
		}
		// Replacement rounds do the real work.
		URLTestOutboundsWithTarget(group.ctx, group.outbound, group.history, group.logger,
			group.outbounds, group.link, group.expected, group.interval, true, TestHistoryHealth)
		group.performUpdateCheck()
	}

	// 1-3. Start round #1 and wait until it is genuinely in flight.
	group.requestHealthRecheck()
	select {
	case <-barrier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("round #1 never started")
	}

	// 4-5. A real traffic failure arrives while that round is running.
	group.recheckAccess.Lock()
	outstandingBefore := group.recheckRequested
	group.recheckAccess.Unlock()

	group.requestHealthRecheck()

	group.recheckAccess.Lock()
	outstandingAfter := group.recheckRequested
	group.recheckAccess.Unlock()
	require.Greater(t, outstandingAfter, outstandingBefore,
		"the new request must be recorded while the round is running")

	// 6. The running round panics.
	close(barrier.release)

	// 7-8. From here on NOTHING requests a recheck. Any round that runs is the recovery working.
	require.Eventually(t, func() bool {
		return storage.LoadURLTestHistoryFor("node-a", group.scope) != nil
	}, 5*time.Second, 5*time.Millisecond,
		"the debt recorded during the panicking round was ORPHANED: recovery released checking "+
			"and the worker but left recheckQueued set, so nobody served it. The node that failed "+
			"to carry traffic is never re-measured. No further request is made by this test, so "+
			"nothing else could have woken the worker")

	// 9-11. The state machine must settle with no debt and no worker.
	waitForIdleWorker(t, group)

	require.False(t, group.checking.Load(), "checking must be released")

	group.recheckAccess.Lock()
	outstanding := group.recheckRequested > group.recheckServed
	group.recheckAccess.Unlock()
	require.False(t, outstanding,
		"the debt was served, so it must not still be outstanding; `requested > served` with no "+
			"worker is exactly the orphaned state this test rules out")

	require.GreaterOrEqual(t, rounds.Load(), int32(2),
		"the replacement round actually ran")
}

// TestPanickingRoundDoesNotRetryItsOwnDebt is the converse (§11).
//
// The panicking round's OWN debt must not be retried. Otherwise a reproducible panic becomes an
// unbounded self-retry loop.
func TestPanickingRoundDoesNotRetryItsOwnDebt(t *testing.T) {
	server := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, server.address) + "/a"

	node := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, link, node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	var rounds atomic.Int32
	group.forcedRoundOverride = func() {
		rounds.Add(1)
		panic("injected failure inside the forced round body")
	}

	group.requestHealthRecheck()
	waitForIdleWorker(t, group)

	// No new request is made. The panicking round's own debt must NOT be retried.
	time.Sleep(400 * time.Millisecond)

	require.Equal(t, int32(1), rounds.Load(),
		"the panicking round's own debt must not be retried; a reproducible panic would "+
			"otherwise become an unbounded retry loop that pins a CPU and floods the log. Got %d "+
			"rounds from a single request", rounds.Load())

	require.False(t, group.checking.Load(), "checking must be released")

	group.recheckAccess.Lock()
	worker := group.recheckWorker
	orphan := group.recheckRequested > group.recheckServed
	group.recheckAccess.Unlock()

	require.False(t, worker)
	require.False(t, orphan,
		"the panicking round's own debt is abandoned, not left outstanding: it was already the "+
			"round that failed, so re-queueing it would be the retry loop")
}
