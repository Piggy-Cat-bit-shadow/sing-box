package route

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// A network transition must have a linearization point: an instant at which the transition is
// observable to everything that could otherwise act on the half-updated state.
//
// # The window this file is about
//
// updateNetworkEnvironment publishes the new fingerprint and only then asks for the reset lock:
//
//	recomputeNetworkEnvironment()      <- NetworkEnvironment() now reports B
//	boundEnvironmentTransitionExported()
//	  ResetNetwork()
//	    resetRunAccess.Lock()          <- may WAIT
//	    networkResetGeneration.Add(1)  <- the boundary, reached only after the wait
//
// Between the publish and the epoch advance, a reader sees a transition that is half done: the
// fingerprint says B, the epoch still says A, and the DNS transport pins are still A. A query that
// completes in that state is stamped and cached under A even though it was carried by a connection
// now reaching B.
//
// # What is asserted here
//
// That the window is closed by the transition taking its epoch BEFORE it waits, so "the environment
// has moved" and "the epoch has moved" become one observation. These tests hold resetRunAccess with
// a barrier and inspect the state the instant the transition is blocked - which is exactly the
// moment the old code was unsafe.

// transitionWindowHarness holds a NetworkManager whose transition can be blocked mid-flight.
type transitionWindowHarness struct {
	manager *NetworkManager
	router  *countingRouter

	// resetHeld is closed when the test has taken resetRunAccess, so the transition is guaranteed to
	// block rather than race the test into position.
	resetHeld chan struct{}
	release   chan struct{}

	// entered is signalled by the router when a reset actually reaches it.
	entered chan struct{}
}

// blockingRouter signals when the reset body runs, so the test can wait for the transition to
// complete rather than guess.
type blockingRouter struct {
	*countingRouter
	entered chan struct{}
	once    sync.Once
}

func (r *blockingRouter) ResetNetwork() {
	r.once.Do(func() { close(r.entered) })
	r.countingRouter.ResetNetwork()
}

func newTransitionWindowHarness(t *testing.T) *transitionWindowHarness {
	t.Helper()
	entered := make(chan struct{})
	router := &blockingRouter{countingRouter: newCountingRouter(), entered: entered}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()
	manager.interfaceMonitor = &staticInterfaceMonitor{
		current: &control.Interface{Index: 1, Name: "en0"},
	}
	manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}})
	h := &transitionWindowHarness{
		manager:   manager,
		router:    router.countingRouter,
		resetHeld: make(chan struct{}),
		release:   make(chan struct{}),
		entered:   entered,
	}
	t.Cleanup(func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
	})
	return h
}

// setSSID publishes a Wi-Fi SSID without going through the event handler, so the test controls
// exactly which transition is driven.
func (h *transitionWindowHarness) setSSID(ssid string) {
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: ssid}
	h.manager.stateAccess.Unlock()
}

// holdResetLock takes resetRunAccess and returns once it is held. The caller can then be certain that
// any transition it starts will block at the lock rather than complete before the test looks.
func (h *transitionWindowHarness) holdResetLock(t *testing.T) {
	t.Helper()
	held := make(chan struct{})
	go func() {
		h.manager.resetRunAccess.Lock()
		close(held)
		<-h.release
		h.manager.resetRunAccess.Unlock()
	}()
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("could not take resetRunAccess")
	}
}

// publishWatch installs the publish hook and returns a channel closed the next time a transition
// publishes a fingerprint.
//
// The test is then ordered by the transition's own progress rather than by a poll. The returned stop
// restores the hook so no other test in the package inherits it.
func publishWatch(t *testing.T) (published chan struct{}, stop func()) {
	t.Helper()
	published = make(chan struct{})
	var once sync.Once
	environmentPublishedHook = func() {
		once.Do(func() { close(published) })
	}
	// Registered with the test as well as returned, so a test that fails before its deferred stop
	// (a require, or a t.Fatal) still cannot leave the hook installed for the next test.
	t.Cleanup(func() { environmentPublishedHook = nil })
	return published, func() { environmentPublishedHook = nil }
}

// awaitGenerationNoPoll is intentionally absent: every wait in this file is driven by the publish
// hook or by the epoch already having been observed, never by sampling on a timer.

// TestEnvironmentTransitionPublishesItsEpochBeforeWaiting is the reproduction.
//
// With the reset lock held elsewhere, a transition is started on another goroutine. The test then
// waits until the new fingerprint is VISIBLE - so the transition has definitely published - and
// asks what epoch the rest of the system sees at that moment.
func TestEnvironmentTransitionPublishesItsEpochBeforeWaiting(t *testing.T) {
	h := newTransitionWindowHarness(t)

	// Settle on network A through the normal path, so A is the epoch the transition moves away from.
	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	require.EqualValues(t, 1, h.manager.NetworkResetGeneration(), "settling on A is one boundary")

	epochA := h.manager.NetworkResetGeneration()
	fingerprintA := h.manager.NetworkEnvironment()
	h.holdResetLock(t)

	// The transition to B. It publishes the fingerprint and then blocks, either on the epoch claim or
	// on the held lock - which of the two is exactly what this test distinguishes.
	published, stopWatch := publishWatch(t)
	defer stopWatch()

	h.setSSID("B")
	transitionDone := make(chan struct{})
	go func() {
		defer close(transitionDone)
		h.manager.updateNetworkEnvironment()
	}()

	// Wait for the transition to publish, signalled by the publish itself rather than sampled.
	select {
	case <-published:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition never published a new fingerprint")
	}
	require.NotEqual(t, fingerprintA, h.manager.NetworkEnvironment(),
		"the publish signal must mean the fingerprint actually changed")

	// The transition is now blocked on the lock. It has published B; has the epoch moved with it?
	// This is the whole question: if the epoch still reads A while the fingerprint reads B, there is
	// a state a DNS operation can complete in and be accepted under the wrong namespace.
	epochDuringWait := h.manager.NetworkResetGeneration()
	fingerprintDuringWait := h.manager.NetworkEnvironment()

	require.NotZero(t, fingerprintDuringWait,
		"the transition must have published a fingerprint before we can judge the wait")

	// The transition has NOT finished (it is blocked on the lock) - assert that, so this test cannot
	// silently pass because the transition completed early.
	select {
	case <-transitionDone:
		require.Fail(t, "the transition completed while resetRunAccess was held elsewhere; the test "+
			"did not observe the waiting window it exists to inspect")
	default:
	}

	require.Equal(t, epochA+1, epochDuringWait,
		"the fingerprint is already published as the new network, but the reset epoch has not moved. "+
			"An operation that completes in this window is compared against the OLD epoch and "+
			"accepted, so it can cache the new network's answer under the old namespace. The "+
			"transition must claim its epoch BEFORE it waits for the reset lock")

	close(h.release)
	select {
	case <-transitionDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition did not complete after the lock was released")
	}
}

// TestTransitionEpochAdvancesExactlyOnceAcrossASupersedingEvent covers the other half of the same
// ownership question: the epoch must move once per logical transition, not once per reason.
//
// Claiming the epoch before the wait must not turn one transition into two epochs, and a superseding
// event must not leave the epoch describing a state no reset produced.
func TestTransitionEpochAdvancesExactlyOnceAcrossASupersedingEvent(t *testing.T) {
	h := newTransitionWindowHarness(t)

	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	h.setSSID("B")
	h.manager.updateNetworkEnvironment()
	require.Equal(t, base+1, h.manager.NetworkResetGeneration(),
		"one transition advances the epoch exactly once")

	// The same environment again: no transition, no epoch movement.
	h.manager.updateNetworkEnvironment()
	require.Equal(t, base+1, h.manager.NetworkResetGeneration(),
		"re-reporting the same environment is not a transition and must not move the epoch")

	// Two distinct transitions are two distinct boundaries.
	h.setSSID("C")
	h.manager.updateNetworkEnvironment()
	require.Equal(t, base+2, h.manager.NetworkResetGeneration(),
		"a second, genuinely different transition earns its own epoch")
}

// Consecutive transitions must each get their own boundary, and neither may reset on behalf of a
// state it no longer owns.
//
// # Why this needs its own test
//
// Claiming the epoch before waiting introduces a new question that the publish-then-wait ordering
// did not have: once a transition has claimed an epoch, is a later transition's work still correct
// when the earlier one has not finished its reset body? The answer has to be yes for both, and the
// two must not collapse into one reset or produce a stale one:
//
//	B: publish B, claim epoch, wait for the lock
//	C: publish C, claim epoch, wait for the lock
//	   -> B's body runs, then C's body runs, each for the state it published
//
// Both are genuinely different transitions, so both boundaries are meaningful. What must NOT happen
// is a boundary being skipped, or B's body running after C has already moved the world and being
// counted as C's.
func TestConsecutiveTransitionsEachGetTheirOwnBoundary(t *testing.T) {
	h := newTransitionWindowHarness(t)

	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	// B transitions, with the reset lock held so its body cannot run yet.
	h.holdResetLock(t)
	publishedB, stopB := publishWatch(t)
	defer stopB()
	h.setSSID("B")
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		h.manager.updateNetworkEnvironment()
	}()

	// B has published and claimed; its body is still blocked.
	awaitPublish(t, publishedB)

	// C transitions while B's body is still blocked. This is a second, real transition.
	publishedC, stopC := publishWatch(t)
	defer stopC()
	h.setSSID("C")
	cDone := make(chan struct{})
	go func() {
		defer close(cDone)
		h.manager.updateNetworkEnvironment()
	}()
	awaitPublish(t, publishedC)

	// Two distinct transitions, two distinct epochs, while neither body has run.
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(),
		"B and C are genuinely different transitions and each must own an epoch")
	require.Equal(t, int(base), dnsResetCount(h.router),
		"neither body can have run yet; the lock is still held")

	// Release the lock: both bodies now run, in some order, each for the state it published.
	close(h.release)
	select {
	case <-bDone:
	case <-time.After(10 * time.Second):
		t.Fatal("B's transition did not complete")
	}
	select {
	case <-cDone:
	case <-time.After(10 * time.Second):
		t.Fatal("C's transition did not complete")
	}

	require.Equal(t, int(base+2), dnsResetCount(h.router),
		"each transition must perform exactly one reset: skipping one loses a boundary, and running "+
			"one twice tears the network down for an event that happened once")
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(),
		"the epoch must describe the state the resets produced: one advance per logical transition")
}

// TestTransitionToTheSameEnvironmentWhileWaitingIsNotASecondBoundary covers the coalescing case.
//
// A repeat of the SAME environment is not a transition, so a notification that arrives while a
// transition to that same value is still waiting must not claim a second epoch. Otherwise a burst of
// identical reports would each tear the network down.
func TestTransitionToTheSameEnvironmentWhileWaitingIsNotASecondBoundary(t *testing.T) {
	h := newTransitionWindowHarness(t)

	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()

	h.holdResetLock(t)
	publishedB, stopB := publishWatch(t)
	defer stopB()
	h.setSSID("B")
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		h.manager.updateNetworkEnvironment()
	}()
	awaitPublish(t, publishedB)

	// The same environment reported again while B waits: not a transition.
	h.manager.updateNetworkEnvironment()
	require.EqualValues(t, base+1, h.manager.NetworkResetGeneration(),
		"re-reporting the environment a pending transition already published is not a new transition "+
			"and must not claim a second epoch")

	close(h.release)
	select {
	case <-bDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition did not complete")
	}
	require.Equal(t, int(base+1), dnsResetCount(h.router), "one transition, one reset")
}

// awaitPublish joins on a transition publishing its fingerprint, then reports the epoch that is
// visible. It does not sample: the publish is signalled, and the epoch is read once.
func awaitPublish(t *testing.T, published chan struct{}) {
	t.Helper()
	select {
	case <-published:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition never published")
	}
}

// BSSID does not participate in the environment fingerprint. This is a characterization test: it
// records what the code does, so that a future change to it is a deliberate decision rather than an
// accident.
//
// # What the fingerprint is built from
//
//	gateway <gateways...>        when the default interface has gateways
//	ssid <SSID>                  when the Wi-Fi state carries one
//	gateway_mac <addresses...>   when there is no SSID but there are gateways
//
// BSSID appears in none of them. It is read and published on the Wi-Fi state, and it is logged, but
// recomputeNetworkEnvironment never hashes it.
//
// # Why the distinction matters
//
// A roam between two access points that share an SSID - the normal case for a mesh or a corporate
// network - changes the BSSID but not the SSID, so it is NOT a transition under this fingerprint.
// The gateway is usually unchanged too, which means the environment hash does not move and no
// boundary is established. Whether that is correct depends on whether the new access point can serve
// the old network's DNS answers, which is a routing question this test does not answer; the point
// here is only that the behaviour is now pinned by a test rather than assumed.
func TestBSSIDDoesNotParticipateInTheEnvironmentFingerprint(t *testing.T) {
	h := newTransitionWindowHarness(t)

	// Settle on an SSID with a gateway.
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: "corp", BSSID: "00:11:22:33:44:55"}
	h.manager.stateAccess.Unlock()
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()
	fingerprint := h.manager.NetworkEnvironment()
	require.NotZero(t, fingerprint, "the fingerprint must be non-empty for this test to mean anything")

	// The SAME SSID, a DIFFERENT access point: a BSSID-only change.
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: "corp", BSSID: "66:77:88:99:AA:BB"}
	h.manager.stateAccess.Unlock()
	h.manager.updateNetworkEnvironment()

	require.EqualValues(t, fingerprint, h.manager.NetworkEnvironment(),
		"the fingerprint is unchanged by a BSSID-only move, so BSSID does not participate in it")
	require.EqualValues(t, base, h.manager.NetworkResetGeneration(),
		"a BSSID-only change is therefore not a transition and establishes no boundary")
	require.Equal(t, int(base), dnsResetCount(h.router))
}

// TestGatewayAloneIsASufficientFingerprint is the contrast to the BSSID case.
//
// With no SSID the fingerprint falls back to the gateway, so the gateway alone is enough to identify
// a network. That is the signal a roam without an SSID actually moves, and it is why the BSSID is
// not needed for the fingerprint to work.
func TestGatewayAloneIsASufficientFingerprint(t *testing.T) {
	h := newTransitionWindowHarness(t)

	// No SSID: the harness's default interface still supplies a gateway, so the fingerprint is the
	// gateway's hash rather than zero.
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: "", BSSID: "00:11:22:33:44:55"}
	h.manager.stateAccess.Unlock()
	h.manager.updateNetworkEnvironment()

	gatewayFingerprint := h.manager.NetworkEnvironment()
	require.NotZero(t, gatewayFingerprint,
		"the gateway alone identifies the network when there is no SSID")
	base := h.manager.NetworkResetGeneration()

	// The SSID appearing changes the fingerprint, which is a real transition.
	h.setSSID("corp")
	h.manager.updateNetworkEnvironment()

	require.NotEqual(t, gatewayFingerprint, h.manager.NetworkEnvironment(),
		"an SSID appearing on top of the gateway changes the fingerprint")
	require.Equal(t, int(base+1), dnsResetCount(h.router),
		"a fingerprint change is a transition and must establish exactly one boundary")
}
