package route

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

const (
	waitForSignal = 2 * time.Second
	waitInterval  = 2 * time.Millisecond
)

// The runtime coordinator's generation and the network manager's own epoch must describe the SAME
// transition.
//
// # Why this needs a test rather than an inspection
//
// There are now two counters that both mean "the network changed": the manager's
// networkResetGeneration, which every dial ownership check compares, and the coordinator's epoch,
// which every registered resource compares. They are advanced from different places in the reset
// path - the manager's inside beginTransition, the coordinator's at the end of it - and a later
// refactor could move one without the other. The failure that would produce is subtle: dials would
// reject stale connections while resources still considered themselves current (or the reverse), and
// both halves would look individually correct.
//
// Invariants 2 and 3 of docs/fork/runtime-lifecycle-phase1.5.md.

func newCoordinatorHarness(t *testing.T) (*NetworkManager, *runtimecoord.Coordinator) {
	t.Helper()
	coordinator := runtimecoord.New()
	t.Cleanup(func() { _ = coordinator.Close() })
	router := newCountingRouter()
	manager := &NetworkManager{
		router:             router,
		endpoint:           &emptyEndpointManager{},
		inbound:            &emptyInboundManager{},
		outbound:           &emptyOutboundManager{},
		runtimeCoordinator: coordinator,
	}
	startedCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager.startedCtx = startedCtx
	manager.logger = logger.NOP()
	manager.transitionStable.Store(true)
	manager.pauseManager = &noopPauseManager{}
	manager.interfaceMonitor = &staticInterfaceMonitor{
		current: &control.Interface{Index: 1, Name: "en0"},
	}
	return manager, coordinator
}

func TestTransitionPublishesTheCoordinatorAtTheSameEpoch(t *testing.T) {
	manager, coordinator := newCoordinatorHarness(t)
	registration, remove := coordinator.Register("resource")
	defer remove()
	require.EqualValues(t, 0, registration.Epoch())
	require.False(t, registration.Stale())

	owner := manager.beginTransition()
	epoch := uint64(owner)
	require.EqualValues(t, 1, epoch, "the manager's first transition is generation 1")

	// The publication is deliberately outside the transition lock (see beginTransition), so it runs
	// as the claim completes rather than while the lock is held.
	require.Eventually(t, func() bool { return coordinator.Epoch() == epoch },
		waitForSignal, waitInterval,
		"the coordinator must publish the transition the manager just took")
	require.EqualValues(t, epoch, manager.NetworkResetGeneration(),
		"the two counters must not drift")
	require.Eventually(t, func() bool { return registration.Epoch() == epoch },
		waitForSignal, waitInterval,
		"a registered resource must observe the transition")
	require.True(t, registration.Stale(),
		"delivery is not rebuild: the resource is stale until it acknowledges")
	registration.Acknowledge()
	require.False(t, registration.Stale())

	// A second transition is a second generation for both.
	second := uint64(manager.beginTransition())
	require.EqualValues(t, 2, second)
	require.Eventually(t, func() bool { return coordinator.Epoch() == second },
		waitForSignal, waitInterval)
	require.EqualValues(t, second, manager.NetworkResetGeneration())
}

// A manager built without a coordinator keeps its previous behaviour exactly: nothing panics and the
// epoch still advances. Every unit test that constructs a NetworkManager directly depends on this.
func TestTransitionWithoutACoordinatorStillAdvancesTheEpoch(t *testing.T) {
	manager, _ := newCoordinatorHarness(t)
	manager.runtimeCoordinator = nil
	owner := manager.beginTransition()
	require.EqualValues(t, 1, uint64(owner))
	require.EqualValues(t, 1, manager.NetworkResetGeneration())
}

// Trim must not reset the network. Conflating the two is how a memory reading turns into a round of
// handshakes the user waits on.
func TestTrimDoesNotResetTheNetwork(t *testing.T) {
	manager, _ := newCoordinatorHarness(t)
	router, isCounting := manager.router.(*countingRouter)
	require.True(t, isCounting)

	before := manager.NetworkResetGeneration()
	manager.TrimMemory(context.Background())
	require.Equal(t, before, manager.NetworkResetGeneration(),
		"a trim must not advance the network generation: nothing was rebuilt")
	require.Zero(t, router.count(),
		"a trim must not reach the router's reset")
	require.EqualValues(t, 1, router.trimCount(),
		"the trim must have gone to the router's trim path, not its reset")
}

func TestTrimReachesTheRoutersTrimPath(t *testing.T) {
	manager, _ := newCoordinatorHarness(t)
	router, isCounting := manager.router.(*countingRouter)
	require.True(t, isCounting)

	manager.TrimMemory(context.Background())
	require.EqualValues(t, 1, router.trimCount())
	require.Zero(t, router.count())
}

// ReleaseMemory is the aggressive pass: it resets, and that is why it must not be used for a soft
// threshold.
func TestReleaseMemoryResetsTheNetwork(t *testing.T) {
	manager, _ := newCoordinatorHarness(t)
	router, isCounting := manager.router.(*countingRouter)
	require.True(t, isCounting)

	before := manager.NetworkResetGeneration()
	manager.ReleaseMemory(context.Background())
	require.Greater(t, manager.NetworkResetGeneration(), before,
		"the aggressive pass advances the generation")
	require.Greater(t, router.count(), 0, "the aggressive pass reaches the router's reset")
}

var _ = netip.Addr{}
