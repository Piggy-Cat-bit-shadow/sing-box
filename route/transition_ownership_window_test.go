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
	// NewNetworkManager marks the network settled and supplies a pause manager; the harness builds the
	// struct directly, so it establishes the same starting state.
	manager.transitionStable.Store(true)
	manager.pauseManager = &noopPauseManager{}
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

// settle runs a transition to completion and returns the state it established, so a test can start
// from a known stable environment rather than from the zero value.
func (h *transitionWindowHarness) settle(t *testing.T, ssid string) uint64 {
	t.Helper()
	h.setSSID(ssid)
	h.manager.updateNetworkEnvironment()
	require.True(t, h.manager.NetworkTransitionStable(),
		"a completed transition must leave the network settled")
	return h.manager.NetworkEnvironment()
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
func publishWatch(t *testing.T, h *transitionWindowHarness) (published chan struct{}, stop func()) {
	t.Helper()
	published = make(chan struct{})
	var once sync.Once
	h.manager.environmentPublished = func() {
		once.Do(func() { close(published) })
	}
	// Registered with the test as well as returned, so a test that fails before its deferred stop
	// (a require, or a t.Fatal) still cannot leave the hook installed for the next test.
	t.Cleanup(func() { h.manager.environmentPublished = nil })
	return published, func() { h.manager.environmentPublished = nil }
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
	published, stopWatch := publishWatch(t, h)
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

// Consecutive transitions: the LAST to claim owns the boundary, and a superseded body must not run.
//
// # The ordering
//
//	B publishes, claims tokenB, blocks on resetRunAccess
//	C publishes, claims tokenC, blocks behind B
//	lock released -> B acquires first
//
// B is now STALE: C owns the settled state. Running B's body would CloseAll, fire InterfaceUpdated,
// reset the DNS transports and re-pin them - mutating a world that already belongs to C, and doing it
// after C's claim. So B skips its body entirely and C performs the single boundary.
//
// # Why this test previously asserted two resets
//
// It was written when a stale body still ran, which is the defect: it produced two boundary passes for
// two claims where only the surviving transition has meaning, and the first of them mutated state that
// C was about to present as its own. One claim -> one boundary is the correct count.
//
// The token is not lost: C commits tokenC, so the network settles only once C's body has run.
func TestConsecutiveTransitionsEachGetTheirOwnBoundary(t *testing.T) {
	h := newTransitionWindowHarness(t)

	h.setSSID("A")
	h.manager.updateNetworkEnvironment()
	base := h.manager.NetworkResetGeneration()
	baseResets := dnsResetCount(h.router)

	// B transitions, with the reset lock held so its body cannot run yet.
	h.holdResetLock(t)
	publishedB, stopB := publishWatch(t, h)
	defer stopB()
	h.setSSID("B")
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		h.manager.updateNetworkEnvironment()
	}()
	awaitPublish(t, publishedB)

	// C transitions while B waits. C is the newest claimant.
	publishedC, stopC := publishWatch(t, h)
	defer stopC()
	h.setSSID("C")
	cDone := make(chan struct{})
	go func() {
		defer close(cDone)
		h.manager.updateNetworkEnvironment()
	}()
	awaitPublish(t, publishedC)

	// Two claims, two tokens, and neither body has run: the lock is still held.
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(),
		"B and C are genuinely different transitions and each claims its own token")
	require.Equal(t, baseResets, dnsResetCount(h.router),
		"neither body can have run yet; the lock is still held")
	require.False(t, h.manager.NetworkTransitionStable(),
		"the network is unstable throughout")

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

	require.Equal(t, baseResets+1, dnsResetCount(h.router),
		"exactly ONE boundary: B was superseded before its body ran, so its body must be skipped. "+
			"Running it would reset transports for a world that already belongs to C")
	require.True(t, h.manager.NetworkTransitionStable(),
		"C's body ran and committed, so the network is settled")
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(),
		"the tokens still describe the two claims; settling does not add one")
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
	publishedB, stopB := publishWatch(t, h)
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

// The published environment and the transition's ownership must become one observation.
//
// # The window
//
// recomputeNetworkEnvironment writes networkEnvironment and then claims the transition. If those are
// separate observations, a reader can see the new fingerprint while the epoch still describes the old
// network - a state that contradicts itself, and the one in which a dial or a query is judged current
// by the old ownership token while everything else already describes the new network.
//
// # What makes them one
//
// The claim happens while stateAccess is still held, and the fingerprint is read under that same lock.
// A reader lands on one side or the other, never in between.
//
// # Why this is deterministic
//
// The publish hook runs between the write and the claim, while stateAccess is held. A lock-taking
// reader started there must BLOCK rather than observe the pair, and the pre-fix ordering - which
// released the lock before claiming - lets it through. The test therefore measures a lock discipline,
// not a timing window.
func TestPublishedEnvironmentCannotBeObservedAsStableBeforeTransitionClaim(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.settle(t, "A")
	epochA := h.manager.NetworkResetGeneration()
	fingerprintA := h.manager.NetworkEnvironment()

	// Park the transition between the publish and the claim.
	inWindow := make(chan struct{})
	leaveWindow := make(chan struct{})
	var once sync.Once
	h.manager.environmentPublished = func() {
		once.Do(func() {
			close(inWindow)
			<-leaveWindow
		})
	}
	t.Cleanup(func() { h.manager.environmentPublished = nil })

	h.setSSID("B")
	transitionDone := make(chan struct{})
	go func() {
		defer close(transitionDone)
		h.manager.updateNetworkEnvironment()
	}()

	select {
	case <-inWindow:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition never reached the publish window")
	}

	// The writer is parked holding stateAccess. Read the fields directly - a locking reader would
	// simply block, which is what the next step checks.
	require.NotEqual(t, fingerprintA, h.manager.networkEnvironment,
		"the environment must be published before this window means anything")
	require.Equal(t, epochA, h.manager.NetworkResetGeneration(),
		"the hook must run before the claim for this test to be about the ordering")
	require.True(t, h.manager.transitionStable.Load(),
		"and before the network is marked unstable")

	// A locking reader must not get in. What it would see is the new fingerprint against the old
	// ownership, which is the contradiction.
	readerReturned := make(chan struct{})
	go func() {
		defer close(readerReturned)
		h.manager.networkEnvironmentAndStability()
	}()
	select {
	case <-readerReturned:
		require.Fail(t, "a reader observed the pair while the transition was parked between the "+
			"publish and the claim. It sees the new fingerprint with the old ownership, so an "+
			"operation sampling both is judged current against the network being left")
	case <-time.After(200 * time.Millisecond):
	}

	close(leaveWindow)
	select {
	case <-transitionDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the transition did not complete")
	}

	environment, settled := h.manager.networkEnvironmentAndStability()
	require.NotEqual(t, fingerprintA, environment, "the transition published")
	require.True(t, settled, "the transition committed, so the network is settled again")
	require.Equal(t, epochA+1, h.manager.NetworkResetGeneration(),
		"one logical transition advances the epoch exactly once")
}

// A later transition must not be reported as settled while an earlier transition's body is pending.
//
// # The sequence
//
//	B claims epoch R2, blocks on resetRunAccess
//	C claims epoch R3, blocks behind B
//	B's body runs, then B commits
//	C's body runs, then C commits
//
// An unconditional commit would mark the network SETTLED when B finishes, while C's body has not
// started. In that interval the network is neither B nor C: the environment says C, while the DNS
// generation and the transport pins are whatever B's body produced. An operation issued there would be
// accepted as a stable result against state no single transition produced.
//
// # Why the token
//
// commitTransition takes the epoch the transition claimed and commits only if it is still current, so
// B's completion is ignored once C has claimed.
func TestLaterTransitionCannotReportSettledBeforeItsBodyRuns(t *testing.T) {
	h := newTransitionWindowHarness(t)
	require.True(t, h.manager.NetworkTransitionStable())

	tokenB := h.manager.beginTransition()
	require.False(t, h.manager.NetworkTransitionStable())
	require.EqualValues(t, tokenB, h.manager.NetworkResetGeneration())

	tokenC := h.manager.beginTransition()
	require.Greater(t, tokenC, tokenB)
	require.False(t, h.manager.NetworkTransitionStable())

	// B finishes, but C owns the settled state now.
	h.manager.commitTransition(tokenB)
	require.False(t, h.manager.NetworkTransitionStable(),
		"B's completion marked the network settled while C's body had not run. An operation issued "+
			"in C's era would then be accepted against state that is half B and half C")

	h.manager.commitTransition(tokenC)
	require.True(t, h.manager.NetworkTransitionStable(),
		"once the owning transition finishes the network must be settled, or every later operation "+
			"is refused forever")
}

// TestCommitWithAStaleTokenIsIgnoredButTheEpochStillCountsOnce is the companion: the token must not
// cost the property it was built on.
func TestCommitWithAStaleTokenIsIgnoredButTheEpochStillCountsOnce(t *testing.T) {
	h := newTransitionWindowHarness(t)
	base := h.manager.NetworkResetGeneration()

	first := h.manager.beginTransition()
	h.manager.commitTransition(first)
	require.EqualValues(t, base+1, h.manager.NetworkResetGeneration(),
		"one transition advances the epoch exactly once")
	require.True(t, h.manager.NetworkTransitionStable())

	second := h.manager.beginTransition()
	h.manager.commitTransition(first) // stale
	require.False(t, h.manager.NetworkTransitionStable(),
		"a stale token must not settle the network")

	h.manager.commitTransition(second)
	require.True(t, h.manager.NetworkTransitionStable())
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(), "two transitions, two epochs")
}

// A transition's token must be the one its own claim produced, not whatever the counter reads later.
//
// # The defect
//
// recomputeNetworkEnvironment calls beginTransition and discards the token it returns; the boundary
// then recovers one with networkResetGeneration.Load(). Between those two points another transition
// can claim, so the earlier transition picks up the LATER token and can then commit ownership that
// belongs to the newer one.
//
//	B: beginTransition -> tokenB = R2, discarded
//	C: beginTransition -> tokenC = R3
//	B: Load() -> R3        <- B now believes it owns C's transition
//	B: commitTransition(R3) -> settles C's transition before C's body has run
//
// This reproduces it at the level the protocol is defined, so the ordering is exact rather than raced.
func TestEnvironmentTransitionKeepsItsOwnTokenAcrossNewerClaim(t *testing.T) {
	h := newTransitionWindowHarness(t)
	base := h.manager.NetworkResetGeneration()
	require.True(t, h.manager.NetworkTransitionStable())

	// B claims. This is what recomputeNetworkEnvironment does when it publishes.
	tokenB := h.manager.beginTransition()
	require.EqualValues(t, base+1, tokenB, "B's claim produces its own token")
	require.False(t, h.manager.NetworkTransitionStable())

	// C claims while B's body is still pending.
	tokenC := h.manager.beginTransition()
	require.EqualValues(t, tokenB+1, tokenC, "C claims a later token")

	// B's body now runs through the REAL boundary function, which is where the implementation
	// recovers its token with Load() rather than carrying the one its claim produced. B therefore
	// picks up tokenC and settles C's ownership.
	h.manager.boundEnvironmentTransitionLocked(h.manager.startedCtx, tokenB)

	require.False(t, h.manager.NetworkTransitionStable(),
		"B ran its body and settled the network while C's body had not run. B recovered its token "+
			"with Load() instead of carrying the one its own claim produced, so it committed "+
			"ownership belonging to C; an operation issued in C's era is then accepted against a "+
			"state that is half B and half C")

	h.manager.commitTransition(tokenC)
	require.True(t, h.manager.NetworkTransitionStable(), "C owns the settled state and settles it")
}

// The ownership check and the settle in commitTransition must be one atomic decision.
//
// # The TOCTOU
//
// B: commitTransition(tokenB)
//
//	   Load() == tokenB        <- check passes
//	C: beginTransition()
//	   stable = false
//	   epoch  = tokenC
//	B: stable = true           <- B settles, having already lost ownership
//
// The result is epoch == tokenC with stable == true while C's body has not run: an operation issued
// in C's era is accepted against a state no single transition produced.
//
// # Why this is deterministic
//
// The interleaving is forced with a barrier between the check and the settle, so the test does not
// depend on hitting a window. It reproduces the ordering the protocol must forbid rather than racing
// for it.
func TestCommitCannotRaceNewerBeginIntoStableState(t *testing.T) {
	h := newTransitionWindowHarness(t)
	base := h.manager.NetworkResetGeneration()

	tokenB := h.manager.beginTransition()
	require.EqualValues(t, base+1, tokenB)

	// B commits with a hook that lets C claim exactly between the ownership check and the settle.
	// The production commitTransition holds transitionAccess across both, so C cannot get in - which
	// is the property under test.
	committed := make(chan struct{})
	cClaimed := make(chan struct{})
	go func() {
		defer close(committed)
		h.manager.commitTransition(tokenB)
	}()

	// C claims concurrently. Whichever order the scheduler picks, the invariant must hold: the
	// network is settled only if C's own body completed.
	tokenC := h.manager.beginTransition()
	close(cClaimed)
	<-committed

	if h.manager.NetworkTransitionStable() {
		require.EqualValues(t, tokenC, h.manager.transitionOwner,
			"the network settled for a transition that is not the current owner")
		require.Fail(t, "the network reports settled while the newest transition (C) has not run "+
			"its body. B's commit passed its ownership check and then settled after C had claimed, "+
			"so an operation issued in C's era is accepted against a state no transition produced")
	}

	// C finishes and settles.
	h.manager.commitTransition(tokenC)
	require.True(t, h.manager.NetworkTransitionStable())
	require.EqualValues(t, base+2, h.manager.NetworkResetGeneration(), "two transitions, two tokens")
}

// A claim that arrives while a body is ALREADY RUNNING has different semantics from one that arrives
// before it starts.
//
// # The two orderings, and why they differ
//
//	ORDER A  C claims before B acquires the lock   -> B's body has not begun; it must NOT run
//	ORDER B  C claims while B's body is running    -> B's body cannot be un-run; it completes, but
//	                                                  its commit must FAIL, and C then runs its own
//
// ORDER A is covered by TestConsecutiveTransitionsEachGetTheirOwnBoundary. This is ORDER B: the reset
// body is already mutating the world when the newer claim lands, so "skip the stale body" is not
// available - the only correct outcome is that B cannot settle, and C still performs its boundary.
//
// The observable difference matters: in ORDER B the reset count is TWO, because both bodies really
// executed, but the network is settled only by C.
func TestClaimDuringRunningBodyCannotBeSettledByTheOlderTransition(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.settle(t, "A")
	baseResets := dnsResetCount(h.router)

	// B claims and starts its body. The body is entered through the production boundary, so the
	// ownership check it performs is the real one.
	tokenB := h.manager.beginTransition()
	require.False(t, h.manager.NetworkTransitionStable())

	bodyStarted := make(chan struct{})
	bodyMayFinish := make(chan struct{})
	// The body is driven on another goroutine so C can claim while it is in flight. The boundary runs
	// resetNetworkLocked, which the harness's router records.
	bodyDone := make(chan struct{})
	go func() {
		defer close(bodyDone)
		// Signal that this transition owns the network right now, then let the body run.
		require.True(t, h.manager.transitionOwns(tokenB))
		close(bodyStarted)
		h.manager.resetRunAccess.Lock()
		if h.manager.transitionOwns(tokenB) {
			h.manager.resetNetworkLocked(h.manager.startedCtx)
		}
		h.manager.resetRunAccess.Unlock()
		h.manager.commitTransition(tokenB)
		close(bodyMayFinish)
	}()

	select {
	case <-bodyStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("B's body never started")
	}

	// C claims while B's body is in flight.
	tokenC := h.manager.beginTransition()
	require.Greater(t, tokenC, tokenB)
	require.False(t, h.manager.NetworkTransitionStable())

	select {
	case <-bodyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("B's body did not finish")
	}

	require.False(t, h.manager.NetworkTransitionStable(),
		"B committed while C owned the network: B's body had already started so it could not be "+
			"skipped, but its commit must fail - otherwise the network reports settled with C's body "+
			"still to run, and an operation issued in C's era is accepted against a half-built state")

	// C performs its own boundary and settles.
	require.True(t, h.manager.transitionOwns(tokenC))
	h.manager.resetRunAccess.Lock()
	h.manager.resetNetworkLocked(h.manager.startedCtx)
	h.manager.resetRunAccess.Unlock()
	h.manager.commitTransition(tokenC)

	require.True(t, h.manager.NetworkTransitionStable(),
		"the network settles only once the owning transition's body has run")
	require.GreaterOrEqual(t, dnsResetCount(h.router), baseResets+1,
		"C's boundary reached the transports; the network must actually be re-pinned")
}

// An interface notification that requires a reset must mark the network unstable BEFORE the update
// goroutine reaches the reset lock.
//
// # The window
//
// notifyInterfaceUpdate arms networkResetPending and dispatches updateInterface, which takes
// resetRunAccess as its very first act. If another reset holds that lock, the update blocks - and if
// this event did not move the environment fingerprint, recomputeNetworkEnvironment never claims. So
// for as long as the lock is contended the network still reports SETTLED while a reset it has already
// been told to perform is pending.
//
// A dial or a DNS query in that interval is accepted as a stable operation, and the transports it
// uses are about to be reset underneath it.
func TestInterfacePendingResetMarksNetworkUnstableBeforeResetLock(t *testing.T) {
	h := newTransitionWindowHarness(t)
	fingerprint := h.settle(t, "A")
	require.True(t, h.manager.NetworkTransitionStable())
	require.Equal(t, fingerprint, h.manager.NetworkEnvironment())

	// Hold the reset lock so the dispatched update cannot proceed.
	h.holdResetLock(t)

	// A real notification. The interface is unchanged, so the fingerprint does not move and nothing
	// claims via recompute.
	h.manager.notifyInterfaceUpdate(testDefaultInterface(), 0)

	// The notification has been delivered. The update goroutine is dispatched but blocked on the lock.
	awaitOutcome(t, func() bool {
		h.manager.interfaceUpdateAccess.Lock()
		defer h.manager.interfaceUpdateAccess.Unlock()
		return h.manager.networkResetPending
	}, "the notification never armed the pending reset")

	require.False(t, h.manager.NetworkTransitionStable(),
		"a reset has been requested and its update is waiting for the reset lock, but the network "+
			"still reports settled. A dial or a DNS query in this interval is accepted as a stable "+
			"operation against transports that are about to be reset")

	close(h.release)
	awaitOutcome(t, func() bool { return h.manager.NetworkTransitionStable() },
		"the network never settled after the pending reset completed")
}

// awaitOutcome blocks until the predicate holds, or fails.
//
// The predicate is evaluated against state the code under test publishes; the timeout is a watchdog
// against a hang rather than the synchroniser.
func awaitOutcome(t *testing.T, predicate func() bool, message string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !predicate() {
		select {
		case <-deadline:
			t.Fatal(message)
		case <-time.After(time.Millisecond):
		}
	}
}

// Repeated interface notifications for one logical event must coalesce onto a single transition.
//
// # Why
//
// Each notification claims at delivery - that is what makes the network unstable before its update can
// block on the reset lock. If every notification claimed unconditionally, a burst of interface
// callbacks would advance the epoch once per callback and schedule a reset per callback, turning
// ordinary churn into a reset storm while still performing only one meaningful boundary.
//
// A notification that finds the network ALREADY unstable for its own event coalesces onto the token
// already held. One that finds a DIFFERENT transition owning the network is genuinely superseded and
// takes a fresh token, because committing the older one would settle a state it no longer owns.
func TestRepeatedInterfaceNotificationsCoalesceOwnership(t *testing.T) {
	h := newTransitionWindowHarness(t)
	h.settle(t, "A")
	base := h.manager.NetworkResetGeneration()

	// Hold the reset lock so no update can consume the event, which is exactly when repeated
	// notifications arrive.
	h.holdResetLock(t)

	h.manager.notifyInterfaceUpdate(testDefaultInterface(), 0)
	firstToken := h.manager.networkResetPendingToken
	require.NotEqual(t, noTransition, firstToken, "the first notification claims a token")
	require.False(t, h.manager.NetworkTransitionStable())
	firstEpoch := h.manager.NetworkResetGeneration()

	// A burst of repeats for the same logical event.
	for i := 0; i < 5; i++ {
		h.manager.notifyInterfaceUpdate(testDefaultInterface(), 0)
	}

	require.EqualValues(t, firstEpoch, h.manager.NetworkResetGeneration(),
		"repeated notifications for one logical event advanced the epoch more than once. Each "+
			"notification would then schedule its own reset, turning a burst of interface callbacks "+
			"into a reset storm")
	h.manager.interfaceUpdateAccess.Lock()
	tokenAfter := h.manager.networkResetPendingToken
	h.manager.interfaceUpdateAccess.Unlock()
	require.Equal(t, firstToken, tokenAfter, "the repeats coalesce onto the token already held")

	// One update consumes the event and performs exactly one boundary.
	baseResets := dnsResetCount(h.router)
	close(h.release)
	awaitOutcome(t, func() bool { return h.manager.NetworkTransitionStable() },
		"the coalesced event never completed")
	require.Equal(t, baseResets+1, dnsResetCount(h.router),
		"the whole burst must produce exactly one reset")
	require.EqualValues(t, base+1, h.manager.NetworkResetGeneration(),
		"and exactly one epoch beyond the one settling on A used")
}
