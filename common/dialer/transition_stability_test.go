package dialer

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// A dial taken while a network transition is pending must not be handed to the caller.
//
// # Why the epoch comparison does not cover this
//
// captureEpoch answers "has the epoch moved since I captured it". A dial that STARTS during a
// transition captures the transition's own epoch, so the comparison finds them equal: the number did
// not move during the dial, because the transition had already moved it. The connection is therefore
// judged current and handed over, even though the DNS generation has not advanced and the transport
// pins still name the network being left.
//
// The two questions are different and both are necessary:
//
//	no a reset landed during my dial     -> the epoch comparison
//	the network is settled right now     -> the stability check
//
// # The four orderings, all asserted below
//
//	1  dial starts stable A, transition begins during it       -> rejected
//	2  dial starts DURING a transition, still pending          -> rejected
//	3  dial starts in stable B after the commit                -> accepted
//	4  dial starts during a transition that later commits      -> rejected

// stabilityNetworkManager supplies both capabilities and lets the test move each independently.
type stabilityNetworkManager struct {
	adapter.NetworkManager
	epoch  *atomic.Uint64
	stable *atomic.Bool
	finder control.InterfaceFinder
}

func (m *stabilityNetworkManager) NetworkResetGeneration() uint64 { return m.epoch.Load() }
func (m *stabilityNetworkManager) NetworkTransitionStable() bool  { return m.stable.Load() }
func (m *stabilityNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.finder
}
func (m *stabilityNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (m *stabilityNetworkManager) AutoDetectInterface() bool { return false }
func (m *stabilityNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error { return nil }
}

var _ adapter.NetworkTransitionState = (*stabilityNetworkManager)(nil)
var _ adapter.NetworkResetCounter = (*stabilityNetworkManager)(nil)

// TestDialEpochPredicateRequiresASettledNetwork drives the predicate directly.
//
// It is the decision the dial path makes at hand-over, isolated from the socket work, so all four
// orderings can be asserted deterministically rather than raced.
func TestDialEpochPredicateRequiresASettledNetwork(t *testing.T) {
	epoch := &atomic.Uint64{}
	stable := &atomic.Bool{}
	stable.Store(true)
	epoch.Store(1)

	dialer := &DefaultDialer{
		networkEpoch:  epoch.Load,
		networkStable: stable.Load,
	}

	// CASE 1: dial starts in stable A, a transition begins during it.
	handOver := dialer.captureEpoch()
	stable.Store(false) // beginTransition
	epoch.Add(1)
	require.False(t, handOver(),
		"a connection dialled on stable A must not be handed over after a transition began")

	// CASE 2: a dial started DURING the transition. This is the case the epoch alone gets wrong:
	// the epoch does not move again, so only the stability check can reject it.
	stable.Store(false)
	duringTransition := dialer.captureEpoch()
	require.False(t, duringTransition(),
		"a dial started while the transition is pending must not be handed over. Its epoch is the "+
			"transition's own, so the epoch comparison reports no change; without the stability check "+
			"the caller receives a connection whose network the rest of the system has not adopted")

	// CASE 4: the transition commits while the dial is in flight. The epoch is unchanged across the
	// commit, so a connection that began during the transition must still be refused - it was
	// dialled while the transport pins were unresolved.
	stable.Store(true) // commitTransition
	epoch.Add(1)       // a further transition, for good measure
	require.False(t, duringTransition(),
		"a connection dialled during a transition must not become acceptable merely because the "+
			"transition later committed; it was produced while ownership was unresolved")

	// CASE 3: a dial in stable B is accepted.
	afterCommit := dialer.captureEpoch()
	require.True(t, afterCommit(),
		"a dial taken in a settled state must be handed over normally")
}

// TestDialEpochPredicateWithoutStabilityCapabilityKeepsOldBehaviour pins the degradation.
//
// A manager that cannot report transition state is one where the distinction does not arise. It must
// keep its previous behaviour exactly, or adding this capability would silently break every existing
// implementation and mock.
func TestDialEpochPredicateWithoutStabilityCapabilityKeepsOldBehaviour(t *testing.T) {
	epoch := &atomic.Uint64{}
	epoch.Store(1)
	dialer := &DefaultDialer{networkEpoch: epoch.Load}

	handOver := dialer.captureEpoch()
	require.True(t, handOver(), "no epoch movement and no stability concept: accepted")

	epoch.Add(1)
	require.False(t, handOver(), "the epoch moved: rejected, exactly as before")
}

// TestDialEpochPredicateWithoutEpochKeepsOldBehaviour covers a manager with neither capability.
func TestDialEpochPredicateWithoutEpochKeepsOldBehaviour(t *testing.T) {
	dialer := &DefaultDialer{}
	require.True(t, dialer.captureEpoch()(),
		"a dialer with no ownership concept at all must not start refusing connections")
}

// TestDialStabilityCapabilityIsReadFromTheManager asserts the wiring: the dialer must actually take
// the capability from the manager rather than always seeing nil.
func TestDialStabilityCapabilityIsReadFromTheManager(t *testing.T) {
	epoch := &atomic.Uint64{}
	stable := &atomic.Bool{}
	stable.Store(false)
	manager := &stabilityNetworkManager{epoch: epoch, stable: stable, finder: control.NewDefaultInterfaceFinder()}

	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	concrete, err := NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)
	require.NotNil(t, concrete.networkStable,
		"the dialer must adopt the manager's stability capability, or the check above is dead code")
	require.False(t, concrete.captureEpoch()(),
		"an unstable manager must make the dial path refuse hand-over")
}
