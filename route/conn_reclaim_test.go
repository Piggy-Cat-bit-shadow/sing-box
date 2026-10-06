package route

import (
	"net"
	"testing"
	"time"
)

// drainHarness drives the reclaim policies with a clock the test controls.
//
// The windows are overridden rather than slept through: a test that waited out drainIdleGrace would
// take twenty seconds to say something a field assignment says instantly, and the policies are
// written against time.Since, not against a timer.
type drainHarness struct {
	manager *ConnectionManager
	now     time.Time
}

func newDrainHarness(t *testing.T) *drainHarness {
	t.Helper()
	manager := NewConnectionManager(nil)
	manager.drainIdleGraceOverride = 10 * time.Second
	manager.drainSweepIntervalOverride = 50 * time.Millisecond
	t.Cleanup(func() { _ = manager.Close() })
	return &drainHarness{manager: manager, now: time.Now()}
}

// dial registers a connection the way the dialer does, and returns the tracked value so the test can
// drive traffic through it.
func (h *drainHarness) dial(t *testing.T) (*trackedConn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	tracked, isTracked := h.manager.TrackConn(client).(*trackedConn)
	if !isTracked {
		t.Fatal("TrackConn did not return a tracked connection")
	}
	return tracked, server
}

// idleFor rewinds a connection's last observed activity, which is what the policy reads.
func (h *drainHarness) idleFor(conn net.Conn, d time.Duration) {
	tracked, isTracked := conn.(*trackedConn)
	if !isTracked {
		panic("not a tracked connection")
	}
	tracked.lastActive.Store(h.now.Add(-d).Unix())
}

// TestTransitionDrainsAnActiveConnection is the whole point of the change: a path change must not
// terminate a stream that is still moving bytes.
func TestTransitionDrainsAnActiveConnection(t *testing.T) {
	h := newDrainHarness(t)
	tracked, peer := h.dial(t)

	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := tracked.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(tracked, time.Second)

	closed := h.manager.Reclaim(ReclaimNetworkTransition)
	if closed != 0 {
		t.Fatalf("a transition reclaimed %d active connection(s); it must drain, not kill", closed)
	}
	if h.manager.Count() != 1 {
		t.Fatal("the active connection left the manager instead of draining")
	}
	// The connection is now stale rather than closed: it belongs to a path the device has left.
	state := tracked.reclaimState()
	if state.generation >= h.manager.generation.Load() {
		t.Fatal("the drained connection was not marked as belonging to the previous path")
	}
}

// TestTransitionReclaimsAProvenIdleConnection is the other half: drain must not mean "keep
// everything", or a blackholed socket would sit in the list until shutdown.
func TestTransitionReclaimsAProvenIdleConnection(t *testing.T) {
	h := newDrainHarness(t)
	tracked, _ := h.dial(t)
	h.idleFor(tracked, time.Minute)

	closed := h.manager.Reclaim(ReclaimNetworkTransition)
	if closed != 1 {
		t.Fatalf("a transition reclaimed %d idle connection(s), want 1", closed)
	}
	if h.manager.Count() != 0 {
		t.Fatal("the idle connection is still tracked after being reclaimed")
	}
}

// TestTransitionProtectsAKernelOwnedConnection covers the conservative direction.
//
// A spliced connection moves bytes between descriptors in the kernel and never reaches Read or
// Write, so its silence is not idleness - it is the absence of an instrument. Killing a working
// connection because nothing can see it working is the failure this guards.
func TestTransitionProtectsAKernelOwnedConnection(t *testing.T) {
	h := newDrainHarness(t)
	tracked, _ := h.dial(t)
	// Created long ago, and nothing was ever observed through it, because nothing can be.
	tracked.createdAt = h.now.Add(-time.Hour)
	tracked.markKernelOwned()

	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 0 {
		t.Fatalf("a kernel-owned connection was reclaimed (%d)", closed)
	}
	if h.manager.Count() != 1 {
		t.Fatal("a kernel-owned connection was dropped")
	}
}

// TestNeverUsedObservableConnectionBecomesIdle is the other half of that split, and the reason it
// exists.
//
// "No transfer observed" used to mean "protect forever", which is right for a spliced connection and
// wrong for every ordinary one: an observable flow that never carries anything would sit in the list
// for the life of the tunnel. Its clock runs from creation, so it ages out like any other idle
// connection.
func TestNeverUsedObservableConnectionBecomesIdle(t *testing.T) {
	h := newDrainHarness(t)
	tracked, _ := h.dial(t)
	// Observable (the default), never used, and older than the grace.
	tracked.createdAt = h.now.Add(-time.Hour)

	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 1 {
		t.Fatalf("a never-used observable connection reclaimed %d, want 1; it must not be protected "+
			"for the life of the tunnel", closed)
	}
	if h.manager.Count() != 0 {
		t.Fatal("the never-used observable connection is still tracked")
	}
}

// TestFreshObservableConnectionIsStillProtected keeps the grace meaningful: a connection dialled a
// moment ago has not had time to prove itself and must not be reclaimed out from under its caller.
func TestFreshObservableConnectionIsStillProtected(t *testing.T) {
	h := newDrainHarness(t)
	h.dial(t)
	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 0 {
		t.Fatalf("a just-dialled connection was reclaimed (%d)", closed)
	}
}

// TestSweepReclaimsWhatFallsSilentAfterTheTransition is the "drain that ends" requirement.
func TestSweepReclaimsWhatFallsSilentAfterTheTransition(t *testing.T) {
	h := newDrainHarness(t)
	tracked, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := tracked.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}

	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 0 {
		t.Fatal("the active connection should have drained, not closed")
	}

	// It now goes quiet: the sweep is what reclaims it, and what keeps drain from being forever.
	h.idleFor(tracked, time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for h.manager.Count() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sweep never reclaimed a connection that fell silent after the transition")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSweepSparesConnectionsDialledAfterTheTransition guards the generation comparison.
//
// Without it the sweep would also reclaim connections on the network the device is actually using,
// which would turn a drain into the same storm it replaced - only delayed.
func TestSweepSparesConnectionsDialledAfterTheTransition(t *testing.T) {
	h := newDrainHarness(t)

	stale, _ := h.dial(t)
	h.idleFor(stale, time.Minute)
	// One stale connection survives the transition because it is active...
	h.idleFor(stale, time.Second)
	h.manager.Reclaim(ReclaimNetworkTransition)

	// ...and this one is dialled on the new path.
	fresh, _ := h.dial(t)
	h.idleFor(fresh, time.Second)
	if got := h.manager.Count(); got != 2 {
		t.Fatalf("expected both connections tracked, got %d", got)
	}

	// Force a sweep pass directly: the timer's own schedule is not what this asserts.
	if remaining := h.manager.sweepStaleConnections(); !remaining {
		t.Fatal("the stale connection should still be held")
	}
	if h.manager.Count() != 2 {
		t.Fatal("the sweep reclaimed a connection dialled after the transition")
	}
}

// TestShutdownStillClosesEverything keeps the reason-aware split honest: the transition drains, but
// teardown has nothing left to serve and must not drain.
func TestShutdownStillClosesEverything(t *testing.T) {
	h := newDrainHarness(t)
	active, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(active, time.Second)

	if closed := h.manager.Reclaim(ReclaimShutdown); closed != 1 {
		t.Fatalf("shutdown reclaimed %d connection(s), want all 1", closed)
	}
	if h.manager.Count() != 0 {
		t.Fatal("shutdown left connections behind")
	}
}

// TestIdleReclaimSparesActiveConnections pins the pause/background path, which was already correct
// before this change and must stay that way.
func TestIdleReclaimSparesActiveConnections(t *testing.T) {
	h := newDrainHarness(t)
	active, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(active, time.Second)

	idle, _ := h.dial(t)
	h.idleFor(idle, time.Minute)

	if closed := h.manager.Reclaim(ReclaimIdle); closed != 1 {
		t.Fatalf("idle reclaim closed %d connection(s), want exactly the idle one", closed)
	}
	if h.manager.Count() != 1 {
		t.Fatal("idle reclaim took the active connection as well")
	}
}

// TestDrainDiagnosticsReportTheSplit is what makes a real-device run able to prove the change.
//
// The number that matters is DrainRatio: a transition that reclaims everything looks identical in
// the log to one that drains, unless this distinguishes them.
func TestDrainDiagnosticsReportTheSplit(t *testing.T) {
	h := newDrainHarness(t)

	active, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(active, time.Second)

	idle, _ := h.dial(t)
	h.idleFor(idle, time.Minute)

	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 1 {
		t.Fatalf("expected the idle connection to be reclaimed, got %d", closed)
	}

	snapshot := h.manager.TransitionDiagnostics()
	if snapshot.Transitions != 1 {
		t.Fatalf("transitions = %d, want 1", snapshot.Transitions)
	}
	if snapshot.Drained != 1 {
		t.Fatalf("drained = %d, want 1 (the active connection)", snapshot.Drained)
	}
	if snapshot.ReclaimedAtTransition != 1 {
		t.Fatalf("reclaimedAtTransition = %d, want 1", snapshot.ReclaimedAtTransition)
	}
	if ratio := snapshot.DrainRatio(); ratio != 0.5 {
		t.Fatalf("drain ratio = %v, want 0.5", ratio)
	}
	if summary := snapshot.TransitionSummary(); summary == "" {
		t.Fatal("the summary is empty")
	}

	// Now let the drained connection fall silent: the sweep is what closes it, and the split has to
	// move with it or the numbers would describe only the first pass.
	h.idleFor(active, time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for h.manager.TransitionDiagnostics().ReclaimedBySweep == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the sweep never reclaimed the drained connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	after := h.manager.TransitionDiagnostics()
	if after.Sweeps == 0 {
		t.Fatal("a sweep reclaimed a connection but no sweep was counted")
	}
	if got := after.Reclaimed(); got != 2 {
		t.Fatalf("total reclaimed = %d, want 2", got)
	}
	if after.Drained != 1 {
		t.Fatalf("drained moved to %d; it describes the transition, not the sweep", after.Drained)
	}
}

// TestNoTransitionNoSummary keeps the shutdown line honest: a tunnel that never saw a network change
// must not print a transition report claiming zeros.
func TestNoTransitionNoSummary(t *testing.T) {
	h := newDrainHarness(t)
	h.dial(t)
	if snapshot := h.manager.TransitionDiagnostics(); snapshot.Transitions != 0 {
		t.Fatalf("transitions = %d before any transition, want 0", snapshot.Transitions)
	}
}

// TestDeadPathReclaimsWhatATransitionWouldDrain is what separates hard from medium.
//
// A medium transition keeps an active connection because the socket might still work. A hard one -
// the device has no default interface - has already answered that: nothing the connection does can
// reach anywhere, so holding it only keeps memory and file descriptors alive.
func TestDeadPathReclaimsWhatATransitionWouldDrain(t *testing.T) {
	h := newDrainHarness(t)
	active, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(active, time.Second)

	// The same connection, under the same activity, under both reasons.
	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 0 {
		t.Fatalf("a medium transition reclaimed %d active connection(s); it must drain", closed)
	}
	if closed := h.manager.Reclaim(ReclaimDeadPath); closed != 1 {
		t.Fatalf("a hard transition reclaimed %d connection(s), want all 1", closed)
	}
	if h.manager.Count() != 0 {
		t.Fatal("a hard transition left connections behind")
	}
}

// TestDeadPathIsNotDrain pins the policy table itself, so the reason cannot quietly become a drain.
func TestDeadPathIsNotDrain(t *testing.T) {
	policy := reclaimPolicyFor(ReclaimDeadPath)
	if !policy.closeAll {
		t.Fatal("a hard transition must reclaim everything")
	}
	if policy.drain {
		t.Fatal("a hard transition must not start a drain; there is nothing to drain")
	}
	if !policy.releaseFlows {
		t.Fatal("closing sockets without releasing parked flows would leave them parked")
	}
}

// TestDrainDiagnosticsCountOnlyTheOldGeneration is the §16 correctness fix.
//
// The transition used to report m.Count() as "drained", and Count() is the whole manager - so a
// connection dialled on the NEW path while the transition was running was reported as an old-path
// connection that had been spared. On a device, where reconnections begin immediately, that
// inflated the exact figure the drain is judged by.
func TestDrainDiagnosticsCountOnlyTheOldGeneration(t *testing.T) {
	h := newDrainHarness(t)

	// One old-generation connection that is working, and one that is idle.
	active, peer := h.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	h.idleFor(active, time.Second)

	idle, _ := h.dial(t)
	h.idleFor(idle, time.Minute)

	h.manager.Reclaim(ReclaimNetworkTransition)

	snapshot := h.manager.TransitionDiagnostics()
	if snapshot.OldGenerationSeen != 2 {
		t.Fatalf("oldGenerationSeen = %d, want 2", snapshot.OldGenerationSeen)
	}
	if snapshot.Drained != 1 {
		t.Fatalf("drained = %d, want 1 (the working connection)", snapshot.Drained)
	}
	if snapshot.ReclaimedAtTransition != 1 {
		t.Fatalf("reclaimedAtTransition = %d, want 1 (the idle connection)", snapshot.ReclaimedAtTransition)
	}
	// The partition has to hold, or the three numbers describe different populations.
	if got := snapshot.Drained + snapshot.ReclaimedAtTransition; got != snapshot.OldGenerationSeen {
		t.Fatalf("drained + reclaimed = %d but oldGenerationSeen = %d", got, snapshot.OldGenerationSeen)
	}

	// A connection on the NEW path is not part of that transition, however many are open.
	if _, _ = h.dial(t); h.manager.Count() != 2 {
		t.Fatalf("expected both remaining connections tracked, got %d", h.manager.Count())
	}
	after := h.manager.TransitionDiagnostics()
	if after.Drained != 1 {
		t.Fatalf("drained moved to %d when a new-generation connection was dialled; it must count "+
			"only the generation the transition scanned", after.Drained)
	}
	if after.OldGenerationSeen != 2 {
		t.Fatalf("oldGenerationSeen moved to %d on a dial", after.OldGenerationSeen)
	}
}

// TestSweepBacksOffWhenItCannotMakeProgress is §17, and it exists because of the kernel-owned split:
// a connection the sweep can never judge keeps `remaining` true forever, so the base interval would
// mean a process wakeup every fifteen seconds for the life of the tunnel. On a phone that is a
// battery bug wearing a correctness argument.
func TestSweepBacksOffWhenItCannotMakeProgress(t *testing.T) {
	h := newDrainHarness(t)
	tracked, _ := h.dial(t)

	// Belongs to the previous path and can never be proven idle.
	tracked.generation = 0
	tracked.markKernelOwned()
	h.manager.generation.Store(1)

	base := h.manager.sweepInterval()
	if base != h.manager.sweepEvery() {
		t.Fatalf("the first interval is %s, want the base %s", base, h.manager.sweepEvery())
	}

	for range 3 {
		if !h.manager.sweepStaleConnections() {
			t.Fatal("a kernel-owned connection should keep the sweep interested")
		}
	}
	backedOff := h.manager.sweepInterval()
	if backedOff <= base {
		t.Fatalf("the interval did not grow: %s after three fruitless passes, base %s", backedOff, base)
	}

	// And it must not grow without bound.
	for range 20 {
		h.manager.sweepStaleConnections()
	}
	if got := h.manager.sweepInterval(); got > drainSweepMaxInterval {
		t.Fatalf("the interval grew to %s, past the cap %s", got, drainSweepMaxInterval)
	}
}

// TestSweepBackoffResetsOnProgressAndOnANewTransition keeps the backoff from hiding work.
//
// Backing off is only safe because what it is waiting on is unjudgeable. The moment something IS
// reclaimable - or a new transition brings new information - the sweep has to be responsive again.
func TestSweepBackoffResetsOnProgressAndOnANewTransition(t *testing.T) {
	h := newDrainHarness(t)

	blocked, _ := h.dial(t)
	blocked.generation = 0
	blocked.markKernelOwned()
	h.manager.generation.Store(1)
	for range 3 {
		h.manager.sweepStaleConnections()
	}
	if h.manager.sweepInterval() == h.manager.sweepEvery() {
		t.Fatal("the fixture did not back off, so this test proves nothing")
	}

	// A reclaimable connection appears: progress resets the interval.
	h.manager.beginDrainSweep()
	if got := h.manager.sweepInterval(); got != h.manager.sweepEvery() {
		t.Fatalf("a new transition left the interval at %s, want the base %s", got, h.manager.sweepEvery())
	}
}
