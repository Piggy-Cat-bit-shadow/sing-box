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

// Tests for the group's terminal state against outstanding recheck debt.
//
// # The defect these pin
//
// The worker's exit path decides whether a replacement is owed purely from the debt counters:
//
//	replacement := g.recheckRequested > retired
//
// A canceled or closed group can never serve its remaining debt, so that comparison stays true
// forever. Every worker therefore exits having spawned a replacement, which starts, sees the
// canceled context, exits, and spawns another. Close does not stop the group's health work - it
// converts it into an unbounded goroutine churn that runs for the life of the process.
//
// A terminal group owes nothing: the debt is not "still to do", it is "no longer possible".

// debtTrackingOutbound counts dials, so "no new work" is a fact rather than an inference.
type debtTrackingOutbound struct {
	adapter.Outbound
	tag   string
	dials atomic.Int32
}

func (o *debtTrackingOutbound) Type() string      { return "debt-tracking" }
func (o *debtTrackingOutbound) Tag() string       { return o.tag }
func (o *debtTrackingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *debtTrackingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	return nil, net.ErrClosed
}

func (o *debtTrackingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.dials.Add(1)
	return nil, net.ErrClosed
}

// workerSpawns is a test-visible count of how many workers have started.
//
// It is read from the group's own counter rather than from runtime.NumGoroutine, because goroutine
// counts are noisy and the question is specifically "did the group spawn another worker".
func waitForQuiescence(t *testing.T, group *URLTestGroup) {
	t.Helper()
	require.Eventually(t, func() bool {
		group.recheckAccess.Lock()
		defer group.recheckAccess.Unlock()
		return !group.recheckWorker
	}, 5*time.Second, 5*time.Millisecond, "the worker never went idle")
}

// TestCloseRetiresOutstandingRecheckDebt is the release blocker.
//
// After Close, no worker may remain responsible for debt.
func TestCloseRetiresOutstandingRecheckDebt(t *testing.T) {
	node := &debtTrackingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

	// Occupy the checking guard so the requested debt cannot be served yet.
	require.False(t, group.checking.Swap(true))

	group.requestHealthRecheck()

	group.recheckAccess.Lock()
	outstandingBeforeClose := group.recheckRequested > group.recheckServed
	group.recheckAccess.Unlock()
	require.True(t, outstandingBeforeClose, "debt exists before Close")

	// Close while the debt is outstanding, then let the guard go.
	require.NoError(t, group.Close())
	group.checking.Store(false)

	waitForQuiescence(t, group)

	group.recheckAccess.Lock()
	outstanding := group.recheckRequested > group.recheckServed
	worker := group.recheckWorker
	group.recheckAccess.Unlock()

	require.False(t, worker, "a closed group must not keep a worker")
	require.False(t, outstanding,
		"a closed group owes nothing: its remaining debt can never be served, so leaving it "+
			"outstanding is what makes the exit path spawn an endless chain of replacements")
}

// TestCanceledGroupDoesNotRespawnRecheckWorker is the churn statement.
//
// The group must reach a stable state rather than respawning workers forever.
func TestCanceledGroupDoesNotRespawnRecheckWorker(t *testing.T) {
	node := &debtTrackingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

	require.False(t, group.checking.Swap(true))
	group.requestHealthRecheck()
	require.NoError(t, group.Close())
	group.checking.Store(false)

	// Let any would-be churn run.
	time.Sleep(300 * time.Millisecond)

	afterQuiescence := group.recheckRuns.Load()

	// A further window in which a respawning worker would keep running rounds.
	time.Sleep(300 * time.Millisecond)

	require.Equal(t, afterQuiescence, group.recheckRuns.Load(),
		"the forced-round counter kept growing after Close, so workers were still being "+
			"respawning against a canceled context. Close must stop the group's health work, not "+
			"convert it into unbounded goroutine churn")

	group.recheckAccess.Lock()
	worker := group.recheckWorker
	group.recheckAccess.Unlock()
	require.False(t, worker)
}

// TestRecheckRequestRacingCloseCannotCreateTerminalDebt is the §6.3 window.
//
// requestHealthRecheck reads `closed` under g.access, releases it, and only then takes
// recheckAccess to record the debt. Close sets `closed` and cancels the context under g.access
// WITHOUT taking recheckAccess, so a Close landing in that gap is admitted.
//
// The window is a few instructions wide, so the test widens it deterministically: it holds
// recheckAccess, lets the request pass the `closed` read and block on the debt lock, then closes the
// group before releasing. That is exactly the interleaving the gap permits, with the timing replaced
// by a barrier.
func TestRecheckRequestRacingCloseCannotCreateTerminalDebt(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		node := &debtTrackingOutbound{tag: "node-a"}
		group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

		// Take the debt lock FIRST. The request will read closed=false and then block here, which
		// is the position it occupies inside the window.
		group.recheckAccess.Lock()

		// Confirm the request has started so it is certain to be past the `closed` read.
		group.access.Lock()
		started := group.closed == false
		group.access.Unlock()
		require.True(t, started)

		requestStarted := make(chan struct{})
		requestDone := make(chan struct{})
		go func() {
			defer close(requestDone)
			// Signal before the call; the call itself will block on recheckAccess.
			close(requestStarted)
			group.requestHealthRecheck()
		}()
		<-requestStarted

		// Give the goroutine a chance to reach the debt lock, i.e. to pass the `closed` read.
		// This is a settle window, not a state synchronisation: the assertion below does not depend
		// on how far it got, only on the final state being consistent either way.
		time.Sleep(2 * time.Millisecond)

		// Close while the request is inside the window.
		require.NoError(t, group.Close())

		// Release it so it proceeds to record - or refuses.
		group.recheckAccess.Unlock()
		<-requestDone

		// Assert BEFORE any cleanup can mask it.
		//
		// The debt-retirement fix does eventually clear this, so asserting only the settled state
		// would pass either way. What must not happen is the request being ADMITTED at all: the
		// group was already closed when it decided to record, so the correct outcome is that it
		// recorded nothing. Admitting it works only because a later repair undoes it, which is a
		// fragile arrangement rather than a contract.
		group.recheckAccess.Lock()
		admitted := group.recheckRequested > 0
		group.recheckAccess.Unlock()

		require.False(t, admitted,
			"attempt %d admitted the request: recheckRequested reached %d on a group that was "+
				"already closed. The pre-lock `closed` read cannot close this window, so the "+
				"decision must be re-made under the lock that records the debt", attempt,
			group.recheckRequested)

		waitForQuiescence(t, group)

		group.recheckAccess.Lock()
		outstanding := group.recheckRequested > group.recheckServed
		worker := group.recheckWorker
		group.recheckAccess.Unlock()

		require.False(t, outstanding,
			"attempt %d left debt on a closed group", attempt)
		require.False(t, worker,
			"attempt %d left a worker responsible for a closed group", attempt)
	}
}

// TestClosedGroupSynchronousProbeReportsError is §29/§31.
//
// A closed group ran no measurement, so a synchronous caller must not be told the probe succeeded
// with no results. The Clash API serialises the returned map as the response body, so an empty map
// with a nil error is a 200 saying "every node is unreachable" for a group that was never measured.
func TestClosedGroupSynchronousProbeReportsError(t *testing.T) {
	node := &debtTrackingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)

	require.NoError(t, group.Close())

	result, err := group.URLTest(context.Background())

	require.Error(t, err,
		"a closed group reported success with an empty result. No measurement ran, so there is no "+
			"result to report - and a caller cannot distinguish an empty result from a failed one")
	require.Nil(t, result, "and no result may be presented as a completed measurement")

	require.EqualValues(t, 0, node.dials.Load(),
		"and nothing may be dialled for a closed group")
}

// TestClosedGroupBackgroundCheckIsStillSilent keeps the background path unchanged.
//
// CheckOutbounds discards its result, so a closed group is simply a no-op there. Only a synchronous
// caller - the one that can act on the value - is told.
func TestClosedGroupBackgroundCheckIsStillSilent(t *testing.T) {
	node := &debtTrackingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	require.NoError(t, group.Close())

	require.NotPanics(t, func() {
		group.CheckOutbounds(context.Background(), true)
	})
	require.EqualValues(t, 0, node.dials.Load())
}
