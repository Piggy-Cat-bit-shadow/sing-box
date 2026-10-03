package route

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// Whether two network resets can run at the same time.
//
// # Why this matters
//
// A reset performs CloseAll, walks every endpoint, inbound and outbound calling InterfaceUpdated, and
// finally resets the DNS router. Two of them interleaving do not produce the state either one would
// have produced alone: the generation advances more than once while transports and callbacks are
// reset in an order belonging to neither run, so a transport can end up serving a generation it was
// never pinned to.
//
// # Where the concurrency comes from
//
// The interface-driven path and the power paths hold resetRunAccess across a WIDER critical section
// that also decides whether to reset, so they call the inner function. The control plane does not go
// through either: experimental/clashapi and the libbox command server call ResetNetwork directly.
// Nothing serialised that against an interface event.

// emptyEndpointManager and friends satisfy the manager interfaces the reset walks, with no members.
type emptyEndpointManager struct{ adapter.EndpointManager }

func (m *emptyEndpointManager) Endpoints() []adapter.Endpoint { return nil }

type emptyInboundManager struct{ adapter.InboundManager }

func (m *emptyInboundManager) Inbounds() []adapter.Inbound { return nil }

type emptyOutboundManager struct{ adapter.OutboundManager }

func (m *emptyOutboundManager) Outbounds() []adapter.Outbound { return nil }

// countingRouter records the order in which the router's own reset is observed.
type countingRouter struct {
	adapter.Router

	access  sync.Mutex
	entered int
	// inFlight is the number of resets currently inside the router's reset. Anything above one is
	// the interleaving under test.
	inFlight atomic.Int32
	maxSeen  atomic.Int32

	// signal is closed and replaced on every reset, and waiters select on the value they read. It
	// lets a test join on the reset actually happening instead of polling the count, which is what a
	// sleep-based wait would do: a poll both slows the test down and can only ever observe the count
	// by accident of timing.
	signal atomic.Pointer[chan struct{}]
}

// noteReset publishes a new signal channel and closes the previous one, so every waiter blocked on
// the old value wakes exactly once.
func (r *countingRouter) noteReset() {
	next := make(chan struct{})
	previous := r.signal.Swap(&next)
	if previous != nil {
		close(*previous)
	}
}

// waitForCount blocks until at least n resets have been observed, or the timeout elapses.
//
// It never samples: the count is compared once, and if it is short the caller waits on the channel
// the next reset will close. There is always a channel to wait on because newCountingRouter
// publishes one at construction.
func (r *countingRouter) waitForCount(n int, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for r.count() < n {
		signal := r.signal.Load()
		if signal == nil {
			return false
		}
		select {
		case <-*signal:
		case <-deadline:
			return r.count() >= n
		}
	}
	return true
}

// newCountingRouter builds a countingRouter with its signal channel already published, so a waiter
// never has to poll for the first reset.
func newCountingRouter() *countingRouter {
	router := &countingRouter{}
	signal := make(chan struct{})
	router.signal.Store(&signal)
	return router
}

// count reports how many resets have been entered.
func (r *countingRouter) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.entered
}

func (r *countingRouter) ResetNetwork() {
	current := r.inFlight.Add(1)
	for {
		previous := r.maxSeen.Load()
		if current <= previous || r.maxSeen.CompareAndSwap(previous, current) {
			break
		}
	}

	r.access.Lock()
	r.entered++
	r.access.Unlock()
	r.noteReset()

	// Hold long enough that an unserialised second reset would certainly overlap.
	for index := 0; index < 1000; index++ {
		_ = index
	}
	r.inFlight.Add(-1)
}

// TestConcurrentResetNetworkIsSerialized is Part E.
//
// Two resets dispatched from different goroutines, as a control-plane call and an interface event
// would be, must not overlap.
func TestConcurrentResetNetworkIsSerialized(t *testing.T) {
	router := newCountingRouter()
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	const resets = 8
	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
	)

	for index := 0; index < resets; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.ResetNetwork(context.Background())
		}()
	}
	close(start)
	waitGroup.Wait()

	require.EqualValues(t, resets, router.entered,
		"every reset must have run; serialising must not drop any")

	require.EqualValues(t, 1, router.maxSeen.Load(),
		"%d resets were inside the router's reset at once. Two concurrent resets interleave "+
			"CloseAll, the InterfaceUpdated callbacks and the DNS reset, so the generation advances "+
			"more than once while transports are reset in an order belonging to neither run - and a "+
			"transport can end up serving a generation it was never pinned to", router.maxSeen.Load())
}

// TestResetNetworkIsReentrantFromTheInterfacePath is the deadlock guard.
//
// The interface path already holds resetRunAccess, so it must reach the inner function rather than
// the exported one. If it called the exported one the lock is not reentrant and the whole network
// manager would deadlock on the first interface change - a far worse outcome than the race this
// serialisation removes.
func TestResetNetworkIsReentrantFromTheInterfacePath(t *testing.T) {
	router := newCountingRouter()
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Exactly what updateInterface does: take the lock, then reset.
		manager.resetRunAccess.Lock()
		defer manager.resetRunAccess.Unlock()
		manager.resetNetworkLocked(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the interface path deadlocked. It holds resetRunAccess, so calling the exported " +
			"ResetNetwork - which takes the same non-reentrant lock - would hang every interface change")
	}

	require.EqualValues(t, 1, router.entered)
}
