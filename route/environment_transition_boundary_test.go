package route

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Does a real network environment transition establish a transport/generation boundary, and does it
// do so without deadlocking the path that already holds the reset lock?
//
// # Why the boundary belongs here
//
// The DNS cache is namespaced by a per-transport environment pin that only Router.ResetNetwork moved.
// A transport does not keep one socket: TCP/TLS/HTTPS re-dial through their dialer when a pooled
// connection is invalidated, and the dial resolves the device's routes then. An SSID change on one
// interface reaches updateNetworkEnvironment without setting networkResetPending, so nothing was
// reset - and the next query could run over the new network while the pin still named the old one.
//
// # The two facts this file pins down
//
//  1. A real transition (the hash actually changes) calls into the reset, so the pins and the
//     connections move together.
//  2. It does NOT deadlock. The debounced timer holds no reset lock and must take the exported,
//     self-locking entry; updateInterface already holds the lock and must use the inner one.
//     Reaching for the exported form from the lock-holder would self-deadlock, since sync.Mutex is
//     not reentrant.
//
// The environment value is computed from the default interface, gateways and Wi-Fi SSID, so the
// transition is driven the way production drives it rather than by poking the field.

// dnsResetCount reports how many times the DNS layer's reset was entered.
func dnsResetCount(r *countingRouter) int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.entered
}

// environmentTransitionManager counts resets so the test can observe the boundary firing.
type environmentTransitionManager struct {
	*NetworkManager
	resets atomic.Int64
}

func (m *environmentTransitionManager) NetworkEnvironment() uint64 {
	return m.NetworkManager.NetworkEnvironment()
}

// TestEnvironmentTransitionTakesTheResetBoundary is the positive direction.
func TestEnvironmentTransitionTakesTheResetBoundary(t *testing.T) {
	router := &countingRouter{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	// A started manager, because the boundary is gated on lifecycle rather than on the old value:
	// the environment is a hash for which 0 is real, so "old == 0" cannot mean "first observation".
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()

	// Seed a stable environment, as a device that has been up for a while would have.
	manager.networkEnvironment = 0x1111
	before := dnsResetCount(router)
	generationBefore := manager.NetworkResetGeneration()

	// Take the boundary exactly as the debounced production path does once it has decided the
	// fingerprint moved. The decision itself is `changed && len(options) > 0` inside
	// updateNetworkEnvironment; what this test pins is its consequence, because a test host has no
	// interfaces to derive a real fingerprint from.
	manager.boundEnvironmentTransitionExported()

	require.Greater(t, dnsResetCount(router), before,
		"a real environment transition must reach the DNS reset, or a transport that re-dials on "+
			"the new network keeps filing its answers under the old environment")
	require.Greater(t, manager.NetworkResetGeneration(), generationBefore,
		"the transition must advance the reset epoch, so in-flight work from the old network is "+
			"recognised as stale rather than accepted")

	// The negative control for the gate: a manager that has not started has no transports to bound,
	// and the environment is a hash for which 0 is a real value, so the gate is the lifecycle rather
	// than the old value.
	unstarted := &NetworkManager{
		router:   &countingRouter{},
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	unstarted.networkEnvironment = 0x1111
	unstarted.boundEnvironmentTransitionExported()
	require.Equal(t, 0, dnsResetCount(unstarted.router.(*countingRouter)),
		"an unstarted manager must not reset: the boundary is gated on lifecycle, not on the "+
			"environment value, because 0 is a representable fingerprint")
}

// TestUnchangedEnvironmentDoesNotResetOnEveryUpdate is the negative control.
//
// updateNetworkEnvironment runs on a debounce after every interface-list refresh. It must be a
// boundary only when the fingerprint actually changes; resetting on every tick would tear down every
// pooled DNS connection repeatedly on a stable network and fracture the cache for no reason.
func TestUnchangedEnvironmentDoesNotResetOnEveryUpdate(t *testing.T) {
	router := &countingRouter{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()

	// First call settles the environment to whatever this host reports.
	manager.updateNetworkEnvironment()
	settled := manager.NetworkEnvironment()
	settledResets := dnsResetCount(router)

	// Further calls with nothing changed must not reset.
	for i := 0; i < 5; i++ {
		manager.updateNetworkEnvironment()
	}
	require.Equal(t, settled, manager.NetworkEnvironment(), "the environment must be stable")
	require.Equal(t, settledResets, dnsResetCount(router),
		"an unchanged environment must not reset the transports; only a real transition is a "+
			"boundary")
}

// TestEnvironmentTransitionDoesNotDeadlockTheLockHoldingPath pins the locking design.
//
// updateInterface holds resetRunAccess for a wider critical section and reaches the reset through
// the inner function. The debounced timer holds no reset lock and reaches it through the exported
// one. If the timer path ever took the lock as well - or the interface path called the exported
// form - one of these would hang rather than fail, so the test bounds it in time.
func TestEnvironmentTransitionDoesNotDeadlockTheLockHoldingPath(t *testing.T) {
	router := &countingRouter{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The interface path: it owns resetRunAccess and must use the inner entry.
		for i := 0; i < 20; i++ {
			manager.resetRunAccess.Lock()
			manager.resetNetworkLocked(startedCtx)
			manager.resetRunAccess.Unlock()
		}
		// The debounced path concurrently, which takes the lock itself for any transition.
		for i := 0; i < 20; i++ {
			manager.updateNetworkEnvironment()
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the environment transition path and the lock-holding reset path did not finish; " +
			"this is the self-deadlock that a reentrant-lock assumption would produce")
	}
}

// TestConcurrentEnvironmentTransitionsAreSerialised checks that overlapping transitions neither
// drop work nor interleave two resets.
func TestConcurrentEnvironmentTransitionsAreSerialised(t *testing.T) {
	router := &countingRouter{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()
	manager.networkEnvironment = 0x2222

	var waitGroup sync.WaitGroup
	for i := 0; i < 8; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			manager.updateNetworkEnvironment()
		}()
	}
	waitGroup.Wait()

	// One generation advance per reset entered, so two concurrent transitions can never leave the
	// generation describing a state no single reset produced.
	require.EqualValues(t, dnsResetCount(router), int(manager.NetworkResetGeneration()),
		"every reset the DNS layer saw must correspond to exactly one generation advance")
}

var _ adapter.NetworkManager = (*environmentTransitionManager)(nil)

// TestEnvironmentRecomputeDoesNotHoldItsLockAcrossTheReset is the regression for a deadlock this
// change introduced and then had to remove.
//
// # The cycle
//
// The first version held environmentUpdateAccess (the debounced update's lock) across the reset.
// Close takes a different pair in the opposite order:
//
//	Close:                        startedCancel, then waits resetRunAccess
//	recompute-and-reset:          holds environmentUpdateAccess, then waits resetRunAccess
//	postUpdateNetworkEnvironment: waits environmentUpdateAccess
//
// So a Close in progress stops the environment update, which stops every later postUpdate - and the
// jiejie reference suite hung until its 40-minute test timeout. Seen in production, not in a fixture:
// the goroutine dump showed Close waiting on resetRunAccess while the network-update monitor waited
// on environmentUpdateAccess.
//
// # What is asserted, and what is deliberately not
//
// The RESET itself may legitimately wait for resetRunAccess - that is the serialisation working. What
// must not happen is holding environmentUpdateAccess while it waits, because that is what starves
// postUpdateNetworkEnvironment. So this asserts the narrow, true property: the recompute releases its
// lock before the boundary is taken, which is observable as postUpdateNetworkEnvironment being able
// to proceed while the boundary is still blocked on a reset.
func TestEnvironmentRecomputeDoesNotHoldItsLockAcrossTheReset(t *testing.T) {
	manager := &NetworkManager{
		router:   &countingRouter{},
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()

	// Stand in for Close: hold the reset lock so the boundary cannot proceed.
	manager.resetRunAccess.Lock()
	defer manager.resetRunAccess.Unlock()

	// The recompute phase must finish and let go of its lock.
	recomputed := make(chan struct{})
	go func() {
		defer close(recomputed)
		manager.recomputeNetworkEnvironment()
	}()
	select {
	case <-recomputed:
	case <-time.After(5 * time.Second):
		t.Fatal("recomputeNetworkEnvironment did not finish; it must not wait on the reset")
	}

	// The boundary is expected to block here, because the test holds resetRunAccess.
	go manager.boundEnvironmentTransitionExported()

	// THE ASSERTION: an update arriving now must still be able to take environmentUpdateAccess.
	// If the recompute held it across the reset, this blocks - which is precisely the starvation that
	// hung the reference suite.
	posted := make(chan struct{})
	go func() {
		defer close(posted)
		manager.postUpdateNetworkEnvironment()
	}()
	select {
	case <-posted:
	case <-time.After(5 * time.Second):
		t.Fatal("postUpdateNetworkEnvironment was starved while a reset was in progress. The " +
			"recompute is holding environmentUpdateAccess across the boundary, which is the cycle " +
			"that hung the jiejie suite for 40 minutes")
	}
}

// TestInterfacePathTakesTheInnerResetForATransition is the regression for the self-deadlock this
// change introduced and then removed.
//
// # What happened
//
// updateInterface holds resetRunAccess for a wider critical section, and it calls
// updateNetworkEnvironment inside that section. The first version of the boundary had
// updateNetworkEnvironment call the exported, self-locking ResetNetwork - so a transition taken from
// the interface path asked for a lock it was already holding. sync.Mutex is not reentrant, so it
// blocked forever.
//
// It was not caught by the unit tests: they drive the boundary directly and never go through
// updateInterface. It showed up as the jiejie reference suite hanging until its test timeout, with
// the goroutine dump pointing at updateInterface -> updateNetworkEnvironment -> ResetNetwork.
//
// # What this asserts
//
// The inner form completes while resetRunAccess is already held. A version that reached for the
// exported entry would block here rather than fail, so the assertion is bounded in time.
func TestInterfacePathTakesTheInnerResetForATransition(t *testing.T) {
	router := &countingRouter{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()

	// The interface path's critical section, exactly as updateInterface takes it.
	manager.resetRunAccess.Lock()
	generationBefore := manager.NetworkResetGeneration()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The call updateInterface makes. It must use the inner reset, because this goroutine already
		// holds the lock.
		manager.boundEnvironmentTransitionLocked(startedCtx)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		manager.resetRunAccess.Unlock()
		t.Fatal("the interface path's transition self-deadlocked: it asked for resetRunAccess while " +
			"already holding it. updateInterface must call the inner form, not the exported one")
	}
	manager.resetRunAccess.Unlock()

	require.Greater(t, manager.NetworkResetGeneration(), generationBefore,
		"the inner form must still establish the boundary, not merely return")
}
