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

// TestTransitionProtectsAConnectionItCannotObserve covers the conservative direction.
//
// A spliced connection moves bytes between descriptors in the kernel and never reaches Read or
// Write, so its activity is unknown. Unknown must not be read as idle: killing a working connection
// because the only available instrument cannot see it working is the failure this guards.
func TestTransitionProtectsAConnectionItCannotObserve(t *testing.T) {
	h := newDrainHarness(t)
	tracked, _ := h.dial(t)
	// Created long ago, and nothing was ever observed through it.
	tracked.createdAt = h.now.Add(-time.Hour)

	if closed := h.manager.Reclaim(ReclaimNetworkTransition); closed != 0 {
		t.Fatalf("a connection with no observable activity was reclaimed (%d)", closed)
	}
	if h.manager.Count() != 1 {
		t.Fatal("an unobservable connection was dropped")
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
