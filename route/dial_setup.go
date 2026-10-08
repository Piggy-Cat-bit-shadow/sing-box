package route

import (
	"context"
	"sync"
)

// The dial setup gate decides which context an in-flight dial runs under, and who may cancel it.
//
// # The failure it exists to prevent
//
// A blackholed dial is a dial that has already put its SYN on the wire and is waiting for a peer
// that never answers - "connected to Wi-Fi with no internet" is the everyday shape. Nothing about
// such a dial is in the connection manager's list, because the list is populated from inside the
// dial (common/dialer's TrackConn) and only once the dial has returned. So a network transition's
// Reclaim has nothing to drain and nothing to close, and the half-open dial runs until its own
// connect_timeout - or, for an outbound configured without one, until the caller cancels or the
// tunnel closes. Measured against the real Go TUN stack, the stack's own ResetNetwork does not
// close a half-open flow either (see protocol/tun/blackhole_connect_regression_test.go), so nothing
// else reaches it.
//
// The rule implemented here is the same one the fork already applies in three other places - the
// XHTTP SPEC 077 dial-context contract, the HTTP/3 CONNECT setup context, and runtimecoord's
// RebindLease:
//
//	setup context owns SETUP ONLY.
//	  caller cancel             -> cancels setup            (unchanged)
//	  network transition        -> cancels setup for a resource whose generation is stale
//	  successfully established  -> ownership TRANSFERS; the setup context has no authority left
//
// # Why a per-generation context and not a lease per dial
//
// runtimecoord.RebindLease is the same idea with an identity per resource, because a rebind has to
// be attributable to the generation that granted it. A dial needs no identity: "cancel every setup
// started before generation N" is exactly a context per generation, swapped under a lock. That is
// also the Coordinator.Advance idiom - close the previous channel, publish a new one - so a
// transition costs one context and no bookkeeping, and there is no map to leak an entry into when a
// dial is abandoned.
//
// # What this type does NOT decide
//
// It never cancels an ESTABLISHED resource. Once a dial returns, the caller calls the release
// function, which first detaches the setup from the generation and only then releases it. A
// transition arriving after that point therefore cannot touch the connection, which is what "a
// transition must never retroactively kill an established flow" has to mean: the flow's lifetime is
// the flow's, not the setup's.
//
// # Concurrency contract
//
// access guards exactly the three words below, and is owned by this gate alone - nothing outside it
// takes it, and it is taken by nothing else. The callers are:
//
//	begin    one per dial, from ConnectionManager.NewConnection / NewPacketConnection
//	         (the route layer's flow goroutine);
//	advance  from Reclaim(drain) and from CloseAll - a transition, teardown, or the
//	         CloseAllConnections control-plane call, on that caller's goroutine;
//	close    from ConnectionManager.Close, once, on the closing goroutine.
//
// No callback and no blocking I/O runs under access. begin releases the lock before registering
// context.AfterFunc; advance and close release it before invoking the cancel func, and it is the
// cancel - not the lock - that wakes a blocked dial. That matters because cancelling a context runs
// its AfterFunc callbacks, and a callback that re-entered this gate would deadlock against a lock
// its own cancellation was taken under.
//
// Close ordering: ConnectionManager.Close sets the manager's closed flag, then calls close() on this
// gate, then stops the drain sweep and only then calls CloseAll (whose own advance becomes a no-op
// once the gate is closed). So the order is: no new setup can be granted, every in-flight setup is
// cancelled, and only afterwards are the established connections torn down. A dial cannot install a
// connection after that point, and a connection cannot be closed before the dial that produced it
// has been told to stop.
type dialSetupGate struct {
	access sync.Mutex
	// current is the context every setup for the live generation derives from, or nil before the
	// first dial. swap cancels and replaces it.
	current context.Context
	swap    context.CancelFunc
	// closed is set by the owner's Close. A dial begun after it is handed an already-cancelled
	// setup, so a late caller cannot establish a connection on a manager that is going away.
	closed bool
}

// begin derives the setup context for one dial and returns the function that ends its setup.
//
// The caller's context is the parent, so cancelling the caller still cancels the dial exactly as it
// did before this gate existed. The generation's context is watched with context.AfterFunc rather
// than folded in with WithCancelCause because the watch has to be STOPPABLE at establishment: the
// release function stops it before releasing the setup, and a stopped watch cannot cancel anything
// afterwards.
func (g *dialSetupGate) begin(caller context.Context) (context.Context, func()) {
	g.access.Lock()
	if g.current == nil && !g.closed {
		g.current, g.swap = context.WithCancel(context.Background())
	}
	if g.closed {
		g.access.Unlock()
		// Closed: the dial must not be able to establish. A cancelled setup reports the same
		// context.Canceled a caller cancellation does, which the load balance classifiers already
		// treat as neutral rather than as a path failure.
		setup, cancel := context.WithCancel(caller)
		cancel()
		return setup, func() {}
	}
	generation := g.current
	g.access.Unlock()

	setup, cancelSetup := context.WithCancel(caller)
	stopGenerationWatch := context.AfterFunc(generation, cancelSetup)
	return setup, func() {
		// Order is the ownership transfer, and it is not interchangeable: the generation watch is
		// stopped BEFORE the setup is released, so a transition that arrives after establishment
		// finds nothing to cancel. Doing it the other way round would let a transition that raced
		// the dial's return cancel a connection that already exists.
		stopGenerationWatch()
		cancelSetup()
	}
}

// advance publishes a new generation: every setup begun before this call is stale and is cancelled,
// and every setup begun after it derives from the new generation.
//
// The cancels are invoked OUTSIDE the gate's lock. Cancelling a context runs context.AfterFunc
// callbacks and wakes the goroutines blocked on it; a callback that re-entered begin or advance
// would otherwise deadlock against the lock its own cancellation was taken under.
func (g *dialSetupGate) advance() {
	g.access.Lock()
	previous := g.swap
	if !g.closed {
		g.current, g.swap = context.WithCancel(context.Background())
	}
	g.access.Unlock()
	if previous != nil {
		previous()
	}
}

// close stops the gate for good. Setups already in flight are cancelled, and a later begin gets a
// dead setup rather than a live one, so nothing can be resurrected on a manager being torn down.
func (g *dialSetupGate) close() {
	g.access.Lock()
	if g.closed {
		g.access.Unlock()
		return
	}
	g.closed = true
	previous := g.swap
	g.current = nil
	g.swap = nil
	g.access.Unlock()
	if previous != nil {
		previous()
	}
}
