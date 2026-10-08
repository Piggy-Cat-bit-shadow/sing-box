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

// newInitialEnvironmentManager builds a started manager whose environment derivation is
// deterministic: the interface monitor reports one interface whose gateways are supplied, so the
// fingerprint is computed from those fields instead of from this host's routing table.
//
// It is the state a manager is in between its PostStart - where the interface update is dispatched -
// and the end of Start, which is where the observation used to be left to land.
func newInitialEnvironmentManager(t *testing.T) *NetworkManager {
	t.Helper()
	manager := &NetworkManager{
		router:   newCountingRouter(),
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
		logger:   logger.NOP(),
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	// NewNetworkManager establishes both of these; a manager built as a struct literal has to.
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
	return manager
}

// TestInitialEnvironmentIsEstablishedByTheTimeStartReturns pins the fix at the layer that owns it.
//
// # The defect this is the contract for
//
// The box's first environment observation is a transition: it publishes the fingerprint, claims an
// epoch, marks the network unsettled, runs a reset body and commits. Through the ordinary update path
// it runs on a goroutine spawned during the network component's PostStart, so it can still be owed
// when Start returns - and then the first connection a caller makes is refused or cancelled by a
// transition that describes no change at all. EstablishInitialNetworkEnvironment is what the
// composition root calls at the end of Start so that this cannot happen.
//
// # What is asserted
//
// Before: nothing published, nothing claimed - a box that has not finished starting has not observed
// its network. After: the environment is published, the transition has COMMITTED (a claimed but
// uncommitted transition is the state that refuses every dial), and it was exactly one transition -
// so the epoch a caller's first dial captures is a value that has stopped moving. The reset body ran
// as well, which is what re-pins every transport to the network the box is on; without it the
// boundary would be a bookkeeping change with no effect on where queries are filed.
func TestInitialEnvironmentIsEstablishedByTheTimeStartReturns(t *testing.T) {
	manager := newInitialEnvironmentManager(t)
	router := manager.router.(*countingRouter)

	require.Zero(t, manager.NetworkEnvironment(),
		"a box that has not finished starting has not observed an environment yet")
	require.True(t, manager.NetworkTransitionStable())
	require.Zero(t, manager.NetworkResetGeneration(),
		"and nothing has claimed an epoch for it")

	manager.EstablishInitialNetworkEnvironment()

	require.NotZero(t, manager.NetworkEnvironment(),
		"the first observation must be published before Start returns: a manager that leaves it to the "+
			"background update path hands a caller a box that does not yet know which network it is on")
	epoch, settled := manager.NetworkTransitionSnapshot()
	require.True(t, settled,
		"the first observation must be complete, not merely claimed: a claimed transition that has not "+
			"committed refuses every dial until it does")
	require.EqualValues(t, 1, epoch, "the first observation is one transition")
	require.Equal(t, manager.NetworkResetGeneration(), epoch,
		"the snapshot and the reset epoch must agree, which is the pair a dial captures")
	require.Equal(t, 1, dnsResetCount(router),
		"the boundary must run: the transports are re-pinned by the reset body, not by the claim")

	// Idempotent: the composition root may call it on a manager whose background update already
	// observed the environment, and a second transition there would move the epoch under a dial that
	// has already captured it.
	environment := manager.NetworkEnvironment()
	manager.EstablishInitialNetworkEnvironment()
	require.Equal(t, environment, manager.NetworkEnvironment())
	require.Equal(t, 1, dnsResetCount(router), "a second call must not run a second reset")
	secondEpoch, secondSettled := manager.NetworkTransitionSnapshot()
	require.True(t, secondSettled)
	require.Equal(t, epoch, secondEpoch, "and must not move the epoch")
}

// TestUnstartedManagerDoesNotObserveItsEnvironment pins the other half of the lifecycle rule.
//
// The network monitor is started one stage before PostStart, so its callback can reach the
// environment path while the box is still starting. That path claims an epoch and marks the network
// unsettled, and the boundary it would run is gated on the same lifecycle - so a transition claimed
// there could never be committed, and the box would report itself unsettled for the rest of the
// process: every dial refused, on a network that never changed.
//
// Skipping the observation instead of claiming it cannot lose a real change either: the first
// observation a RUNNING box makes is the one that counts, and it is made by
// EstablishInitialNetworkEnvironment before Start returns, so whatever the monitor saw during Start
// is observed then - from the current interfaces, which is the network the box is actually on.
func TestUnstartedManagerDoesNotObserveItsEnvironment(t *testing.T) {
	manager := newInitialEnvironmentManager(t)
	router := manager.router.(*countingRouter)

	// Before PostStart: the manager has monitors and a default interface, but no lifecycle.
	manager.startedCtx = nil

	manager.postUpdateNetworkEnvironment()

	require.Zero(t, manager.NetworkEnvironment(),
		"an unstarted manager must not publish an environment: the boundary that would have to move "+
			"with it cannot run yet")
	require.Zero(t, manager.NetworkResetGeneration(),
		"and must not claim an epoch that nothing can commit - the network would stay unsettled for "+
			"the rest of the process, refusing every dial")
	require.True(t, manager.NetworkTransitionStable())
	require.Zero(t, dnsResetCount(router))

	// Started, and the observation is made for real - the deferred one is not lost.
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	manager.EstablishInitialNetworkEnvironment()
	require.NotZero(t, manager.NetworkEnvironment())
	require.True(t, manager.NetworkTransitionStable())
	require.Equal(t, 1, dnsResetCount(router))
}

// TestInitialEnvironmentEstablishmentWaitsForAnObservationInFlight pins the serialisation the
// establishment depends on.
//
// The observation and the establishment can both be in flight, because the interface update is
// dispatched during PostStart and the establishment runs later in the same Start. The interface path
// holds resetRunAccess for its whole life - recompute, claim, body, commit - so the establishment
// either gets there first (and then the update finds the fingerprint unchanged) or waits for the
// update to commit. What it must NOT do is return while the transition it is waiting for is still
// uncommitted: Start would then return with the network unsettled, which is the state that refuses
// the caller's first dial.
func TestInitialEnvironmentEstablishmentWaitsForAnObservationInFlight(t *testing.T) {
	manager := newInitialEnvironmentManager(t)
	router := manager.router.(*countingRouter)

	// Park the update between publishing the fingerprint and claiming its epoch. It holds
	// resetRunAccess here, which is exactly the interval the establishment has to respect.
	published := make(chan struct{})
	leave := make(chan struct{})
	var once sync.Once
	manager.environmentPublished = func() {
		once.Do(func() {
			close(published)
			<-leave
		})
	}
	t.Cleanup(func() { manager.environmentPublished = nil })

	updateDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		manager.updateInterface(manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	}()
	select {
	case <-published:
	case <-time.After(10 * time.Second):
		t.Fatal("the interface update never published an environment")
	}

	established := make(chan struct{})
	go func() {
		defer close(established)
		manager.EstablishInitialNetworkEnvironment()
	}()

	// The one place a bounded wait IS the assertion: the property is that the establishment does NOT
	// return while the transition is uncommitted. A signal cannot express "nothing happened".
	select {
	case <-established:
		t.Fatal("the establishment returned while the first observation was still in flight: Start " +
			"would return with the transition uncommitted, and the caller's first dial would be " +
			"refused by it")
	case <-time.After(200 * time.Millisecond):
	}

	close(leave)
	select {
	case <-established:
	case <-time.After(10 * time.Second):
		t.Fatal("the establishment did not finish after the observation it was waiting for was released")
	}
	<-updateDone

	require.True(t, manager.NetworkTransitionStable(),
		"the transition in flight committed, and the establishment left it settled")
	epoch, settled := manager.NetworkTransitionSnapshot()
	require.True(t, settled)
	require.EqualValues(t, 1, epoch,
		"one logical transition, however many entry points reach it: the establishment must join the "+
			"observation in flight rather than claim an epoch of its own")
	require.Equal(t, 1, dnsResetCount(router), "and must not run a second reset")
}

// TestInitialEnvironmentEstablishmentKeepsGenuineTransitionsRefusing is the control the fix is not
// allowed to break.
//
// The whole point of the epoch guard is that a connection dialled on one network is not handed to a
// caller who believes it is on another. The establishment makes the FIRST observation happen before
// Start returns; it must not consume the epoch, pre-commit it, or leave the network in a state where
// a later genuine transition is absorbed instead of refused.
//
// The dialer's side of this contract is pinned in common/dialer's transition stability tests, which
// drive captureEpoch's predicate directly. What is pinned here is the state those checks read: after
// a genuine transition the epoch has moved, so a dial that captured the earlier value is stale, and
// the network is settled again, so a dial that begins afterwards is not left waiting forever.
func TestInitialEnvironmentEstablishmentKeepsGenuineTransitionsRefusing(t *testing.T) {
	manager := newInitialEnvironmentManager(t)
	router := manager.router.(*countingRouter)

	manager.EstablishInitialNetworkEnvironment()
	firstEpoch, firstSettled := manager.NetworkTransitionSnapshot()
	require.True(t, firstSettled)
	firstEnvironment := manager.NetworkEnvironment()

	// A genuine change - the SSID moves, which moves the fingerprint by construction. The next dial
	// begins here, so it captures firstEpoch.
	manager.stateAccess.Lock()
	manager.wifiState = adapter.WIFIState{SSID: "somewhere-else"}
	manager.stateAccess.Unlock()
	manager.updateNetworkEnvironment()

	secondEpoch, secondSettled := manager.NetworkTransitionSnapshot()
	require.True(t, secondSettled, "a completed genuine transition settles the network again")
	require.NotEqual(t, firstEpoch, secondEpoch,
		"a dial that began before a genuine transition must still be recognised as stale: the "+
			"establishment must not have consumed the epoch or pinned it in place")
	require.NotEqual(t, firstEnvironment, manager.NetworkEnvironment(),
		"and the environment must have moved with it")
	require.Equal(t, 2, dnsResetCount(router),
		"the first observation and the genuine change are two boundaries, not one absorbed transition")

	// A dial beginning now captures (secondEpoch, settled) and the state it captured is the state that
	// holds, so it is accepted - the fix must not have made every dial wait for a transition that
	// never comes.
	settledEpoch, settledNow := manager.NetworkTransitionSnapshot()
	require.True(t, settledNow)
	require.Equal(t, secondEpoch, settledEpoch)
	require.Equal(t, manager.NetworkResetGeneration(), settledEpoch)
}
