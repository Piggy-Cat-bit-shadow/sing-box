//go:build with_xhttp

package v2rayxhttp

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The reuse boundary's action on this pool is RetireSuspect, and these tests pin the three-way
// distinction the pool now has to make:
//
//	idle connection            -> closed now (it was never going to be verified again)
//	connection with a stream   -> DRAINED: no new stream, the one on it keeps its transport
//	pool with no demand        -> opens nothing
//
// The middle case is the one that was a recorded limitation before this: a session carrying a live
// stream stayed in the pool and went on accepting new streams, so a blackholed path could keep
// taking work. It cannot now. The trim contract - CloseIdleConnections, which must NOT be able to
// make the next stream dial - is unchanged and is pinned separately in trim_test.go and
// wake_reuse_test.go; this file is only about the boundary.

// TestRetireSuspectDrainsABusyConnectionAndKeepsItsStream is the core of the change.
func TestRetireSuspectDrainsABusyConnectionAndKeepsItsStream(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.RetireSuspect()

	// The stream's transport is untouched: draining is not closing, and the boundary exists to stop
	// stalls rather than to cause them.
	require.Zero(t, conns()[0].closes(), "the boundary tore down a connection with a live stream")
	require.Equal(t, 1, busy.getOpenUsage(), "the boundary changed the live stream count")
	require.True(t, busy.draining.Load(), "the connection was not marked as refusing new work")

	// And the next stream does NOT get it. This is the reported failure: a new flow multiplexed onto a
	// session whose path the sleep may have killed.
	next, _ := manager.get()
	require.NotSame(t, busy, next, "the pool handed a pre-boundary connection to a stream after the boundary")
	require.Len(t, conns(), 2, "the post-boundary stream did not dial a fresh connection")
	require.Zero(t, conns()[1].closes(), "the fresh connection was closed before it carried anything")

	// The drained connection is retired, not leaked: its teardown happens when its last stream leaves,
	// which is the deferred close every other eviction already uses.
	require.Zero(t, conns()[0].closes(), "the teardown of a busy connection must be deferred")
	busy.addOpenUsage(-1)
	require.Equal(t, 1, conns()[0].closes(),
		"the drained connection was not torn down when its last stream ended")
}

// TestRetireSuspectClosesIdleConnectionsImmediately is the other half of the same call, and the reason
// the boundary does not need a second pass over the pool.
func TestRetireSuspectClosesIdleConnectionsImmediately(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	idle, _ := manager.get()
	idle.addOpenUsage(1)
	idle.addOpenUsage(-1) // the stream ended: the connection is pooled and idle

	manager.RetireSuspect()

	require.Equal(t, 1, conns()[0].closes(), "an idle connection survived the boundary")
	require.Zero(t, idle.getOpenUsage())
}

// TestRetireSuspectWithNoDemandOpensNothing is the power contract at the new entry point: a boundary
// is not a reason to dial, so a pool that is drained and then left alone stays empty.
func TestRetireSuspectWithNoDemandOpensNothing(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})

	manager.RetireSuspect()
	manager.RetireSuspect()
	require.Empty(t, conns(), "a boundary opened connections on an empty pool")

	busy, _ := manager.get()
	busy.addOpenUsage(1)
	manager.RetireSuspect()
	require.Len(t, conns(), 1, "the boundary opened a connection with no demand behind it")
	manager.RetireSuspect()
	require.Len(t, conns(), 1, "a repeated boundary opened a connection with no demand behind it")
}

// TestRetireSuspectIsIdempotentAndCheapForRepeatedBoundaries keeps a pocketed phone's many resumes
// cheap: a repeated boundary must not re-close, re-drain or double-count anything, and the teardown it
// defers must happen exactly once.
//
// The pool is built directly rather than through get(), because this test needs one idle connection
// AND one busy connection at the same time and the pool's selection is random by design.
func TestRetireSuspectIsIdempotentAndCheapForRepeatedBoundaries(t *testing.T) {
	t.Parallel()
	idleConn := &fakeXmuxConn{}
	busyConn := &fakeXmuxConn{}
	manager := &xmuxManager{newConn: func() xmuxConn { return &fakeXmuxConn{} }}
	idle := &xmuxClient{conn: idleConn, leftUsage: -1}
	busy := &xmuxClient{conn: busyConn, leftUsage: -1}
	busy.addOpenUsage(1)
	manager.clients = []*xmuxClient{idle, busy}

	manager.RetireSuspect()
	manager.RetireSuspect()
	manager.RetireSuspect()

	require.Equal(t, 1, idleConn.closes(),
		"an idle connection was closed %d times by repeated boundaries", idleConn.closes())
	require.Zero(t, busyConn.closes(), "a repeated boundary tore down a live stream's connection")
	require.True(t, busy.draining.Load(), "the busy connection was not refused new work")
	require.Empty(t, manager.clients, "a drained connection was left in the pool")

	// The stream ends on its own schedule: the teardown the boundary deferred happens exactly once.
	busy.addOpenUsage(-1)
	require.Equal(t, 1, busyConn.closes(), "the deferred teardown did not happen exactly once")
}

// TestRetireSuspectNodesNotPoisonThePostBoundaryPool is the other side of idempotence: a connection
// opened AFTER a boundary is post-boundary state, and a boundary that retired it would turn a
// pocketed phone's many resumes into a dial per resume.
func TestRetireSuspectNodesNotPoisonThePostBoundaryPool(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.RetireSuspect()

	// The first stream after the boundary dials a fresh connection, as it must.
	next, _ := manager.get()
	require.NotSame(t, busy, next, "the pool handed a pre-boundary connection to a stream after the boundary")
	require.Len(t, conns(), 2)
	next.addOpenUsage(1)

	// Its stream ending returns it to the pool rather than arming a teardown, and the next demand gets
	// it back: the boundary did not leave a teardown armed on post-boundary state.
	next.addOpenUsage(-1)
	require.Zero(t, conns()[1].closes(),
		"a post-boundary connection was torn down instead of returning to the pool")
	reused, _ := manager.get()
	require.Same(t, next, reused, "the post-boundary connection was not returned to the pool")

	// Meanwhile the drained connection is retired exactly once, when its own last stream leaves.
	busy.addOpenUsage(-1)
	require.Equal(t, 1, conns()[0].closes(),
		"the drained connection was not torn down when its last stream ended")
}

// TestRetireSuspectDoesNotPoisonTheBreaker is the interaction worth pinning: draining is not a
// failure. A boundary must not arm the new-transport backoff, because the backoff would then delay
// the fresh dial the boundary itself requires.
func TestRetireSuspectDoesNotPoisonTheBreaker(t *testing.T) {
	t.Parallel()
	manager, _ := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.RetireSuspect()

	require.Zero(t, busy.consecFails.Load(), "the boundary counted as a stream failure")
	require.False(t, busy.failing.Load(), "the boundary tripped the breaker")
	require.False(t, manager.backoffArmed.Load(), "the boundary armed the new-transport backoff")
}

// TestATrimStillLeavesABusyConnectionPooled is the guard on the OTHER direction, and it is the reason
// RetireSuspect is a separate entry point rather than a change to CloseIdleConnections.
//
// The memory-trim pass reaches this pool through CloseIdleConnections, and a trim must not be able to
// make the next request dial: that would be a reconnect trigger wearing a memory-management name. So
// the trim keeps a busy connection pooled - and still hands it the next stream - while the boundary
// refuses it. Both behaviours are asserted here, side by side, so a future change that collapses the
// two entry points fails.
func TestATrimStillLeavesABusyConnectionPooled(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	busy, _ := manager.get()
	busy.addOpenUsage(1)

	manager.CloseIdleConnections()

	require.False(t, busy.draining.Load(), "a trim marked a connection as refusing new work")
	next, _ := manager.get()
	require.Same(t, busy, next, "a trim made the next stream dial: the trim became a reconnect trigger")
	require.Len(t, conns(), 1)

	// And the boundary, on the same pool and the same connection, refuses it.
	manager.RetireSuspect()
	after, _ := manager.get()
	require.NotSame(t, busy, after, "the boundary did not refuse the pre-boundary connection")
	require.Len(t, conns(), 2)
}

// TestTheAdapterCapabilitiesReachThePool is the wiring half: the boundary walk reaches outbounds and
// asserts adapter interfaces on them, so a capability that exists on the pool but is not forwarded by
// the transport the outbound holds would be invisible in production while every pool-level test still
// passed.
//
// It exists because the first red-check of this change did exactly that: breaking Client.RetireSuspect
// so it called the idle-only path left the whole suite green, because the pool was being driven
// directly. Both entry points are therefore pinned: the interface assertions here, and the behaviour
// they must produce.
func TestTheAdapterCapabilitiesReachThePool(t *testing.T) {
	t.Parallel()
	manager, conns := poolOf(t, xmuxConfig{maxConcurrency: intRange{4, 4}})
	client := &Client{xmux: manager}
	require.Implements(t, (*adapter.ReuseSuspect)(nil), client,
		"the transport does not expose the reuse-boundary capability the walk looks for")
	require.Implements(t, (*adapter.IdleConnectionKeeper)(nil), client)

	busy, _ := manager.get()
	busy.addOpenUsage(1)

	client.RetireSuspect()

	next, _ := manager.get()
	require.NotSame(t, busy, next,
		"Client.RetireSuspect did not reach the pool: a pre-boundary connection was handed out again")
	require.Len(t, conns(), 2)
	require.Zero(t, conns()[0].closes(), "the live stream lost its transport")
	busy.addOpenUsage(-1)
	require.Equal(t, 1, conns()[0].closes(),
		"the deferred teardown did not happen once the last stream on the drained connection ended")

	// And the trim entry point still does what the trim must: it releases idle connections without
	// refusing new work on a busy one.
	trimmed, _ := manager.get()
	trimmed.addOpenUsage(1)
	client.CloseIdleConnections()
	require.False(t, trimmed.draining.Load(), "Client.CloseIdleConnections refused new work: it is the trim")
}
