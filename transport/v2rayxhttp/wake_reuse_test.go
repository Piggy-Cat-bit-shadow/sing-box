//go:build with_xhttp

package v2rayxhttp

import (
	"testing"
)

// The wake boundary reaches this pool as one call - CloseIdleConnections - and these tests pin what
// that call must do to a pool of real connections, because it is the operation the post-wake policy
// is built on:
//
//	a stale pooled connection is not handed to the next stream,
//	a stream that is still running keeps its connection,
//	and a boundary with no demand behind it opens nothing.
//
// The idle-only half is already covered by trim_test.go (a trim and a wake retire are the same
// operation on this pool, deliberately: both release what has no user and neither may dial). What is
// added here is the freshness consequence, which is what a post-wake stall is made of.

// TestWakeRetireHandsTheNextStreamAFreshConnection is the defect this work exists for, in miniature:
// a connection that was pooled before the sleep must not carry the first stream after it.
func TestWakeRetireHandsTheNextStreamAFreshConnection(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})

	first, _ := manager.get()
	first.addOpenUsage(1)
	first.addOpenUsage(-1) // the stream ended: the connection is pooled and idle
	if got := len(conns()); got != 1 {
		t.Fatalf("opened %d connections, want 1", got)
	}

	// The boundary.
	manager.CloseIdleConnections()

	if got := conns()[0].closes(); got != 1 {
		t.Fatalf("the pooled connection survived the boundary (closes=%d)", got)
	}

	second, _ := manager.get()
	if second == first {
		t.Fatal("the stream after the boundary was handed the connection the boundary retired")
	}
	if got := len(conns()); got != 2 {
		t.Fatalf("opened %d connections, want a fresh one after the boundary", got)
	}
	if got := conns()[1].closes(); got != 0 {
		t.Fatalf("the fresh connection was closed before it was used (closes=%d)", got)
	}
}

// TestWakeRetireWithNoDemandOpensNothing is the other half of the power contract: a boundary is not a
// reason to dial. If a retire could open a connection it would be a reconnect trigger wearing a
// lifecycle name, which is exactly the shape the device matrix measures as a wake storm.
func TestWakeRetireWithNoDemandOpensNothing(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})

	// An empty pool: the boundary must be a no-op.
	manager.CloseIdleConnections()
	manager.CloseIdleConnections()
	if got := len(conns()); got != 0 {
		t.Fatalf("a boundary opened %d connections on an empty pool", got)
	}

	// A pool with one idle connection and no demand: retiring it must still open nothing.
	client, _ := manager.get()
	client.addOpenUsage(1)
	client.addOpenUsage(-1)
	if got := len(conns()); got != 1 {
		t.Fatalf("opened %d connections, want 1", got)
	}
	manager.CloseIdleConnections()
	if got := len(conns()); got != 1 {
		t.Fatalf("the boundary opened connections: %d, want 1", got)
	}
	if got := conns()[0].closes(); got != 1 {
		t.Fatalf("the idle connection was not retired (closes=%d)", got)
	}
	// And it stays retired until something actually asks for a stream.
	manager.CloseIdleConnections()
	if got := len(conns()); got != 1 {
		t.Fatalf("connections appeared with no demand: %d", got)
	}
}

// TestWakeRetireKeepsALiveStreamAndItsConnection is the constraint the policy is not allowed to
// break: a transfer in progress, a call, an upload.
func TestWakeRetireKeepsALiveStreamAndItsConnection(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.CloseIdleConnections()

	if got := conns()[0].closes(); got != 0 {
		t.Fatalf("the boundary tore down a connection with a live stream (closes=%d)", got)
	}
	if got := busy.getOpenUsage(); got != 1 {
		t.Fatalf("the boundary changed the live stream count: %d", got)
	}

	// The stream finishes on its own schedule, and the connection is then simply pooled again: the
	// boundary did not arm a teardown for it, because it was never idle. Whether the next stream may
	// use it is the residual risk pinned by the limitation test below.
	busy.addOpenUsage(-1)
	if got := busy.getOpenUsage(); got != 0 {
		t.Fatalf("openUsage = %d after the stream ended, want 0", got)
	}
	if got := conns()[0].closes(); got != 0 {
		t.Fatalf("the boundary left a teardown armed on a connection it must not touch (closes=%d)", got)
	}
}

// TestASessionWithALiveStreamStillAcceptsNewStreams_KnownLimitation pins the residual risk the fix
// cannot remove, so that it is visible rather than assumed away.
//
// A connection carrying a live stream is not idle, so the boundary leaves it pooled - it must, or the
// live stream would lose its transport. This pool has no draining or no-new-stream operation to offer
// (the module exposes CloseIdleConnections and Close, and Close is the reset-shaped one), so a new
// stream can still be placed on a connection that predates the sleep. What the fix guarantees is the
// case that was reported: a connection with nothing running on it is retired before it can carry the
// first flow after a wake. When this pool grows a draining state this test must be rewritten, and the
// boundary should use it.
func TestASessionWithALiveStreamStillAcceptsNewStreams_KnownLimitation(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.CloseIdleConnections()

	next, _ := manager.get()
	if next != busy {
		t.Fatal("the pool opened a second connection: this test documents the reuse of a live one")
	}
	if got := len(conns()); got != 1 {
		t.Fatalf("opened %d connections, want the live one to be reused", got)
	}
	// The caller counts its own stream, as the real path does.
	next.addOpenUsage(1)
	if got := busy.getOpenUsage(); got != 2 {
		t.Fatalf("openUsage = %d, want both streams counted", got)
	}
}

// TestWakeRetireIsIdempotentAndCheapForRepeatedBoundaries guards the coalescing that keeps a locked
// phone's many resumes from becoming many retirements: the second boundary on an already-empty pool
// must be a no-op, and it must not touch a connection that has since been opened.
func TestWakeRetireIsIdempotentAndCheapForRepeatedBoundaries(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	first, _ := manager.get()
	first.addOpenUsage(1)
	first.addOpenUsage(-1)

	manager.CloseIdleConnections()
	manager.CloseIdleConnections()
	if got := conns()[0].closes(); got != 1 {
		t.Fatalf("the connection was closed %d times, want 1", got)
	}

	second, _ := manager.get()
	second.addOpenUsage(1)
	if got := len(conns()); got != 2 {
		t.Fatalf("opened %d connections, want 2", got)
	}
	// A boundary during a live stream must not retire it either, which is what makes a repeat cheap.
	manager.CloseIdleConnections()
	if got := conns()[1].closes(); got != 0 {
		t.Fatalf("a repeated boundary closed a connection with a live stream (closes=%d)", got)
	}
}
