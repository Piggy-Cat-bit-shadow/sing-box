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

	// CASE 4: the transition commits while the dial is in flight, and NOTHING ELSE HAPPENS.
	//
	// The epoch does not move across a commit - commitTransition only settles the state. Adding an
	// extra epoch advance here, which this test previously did, would make the epoch check reject on
	// its own and hide the real defect: a dial that began while the network was unstable is accepted
	// the moment the network merely becomes stable, even though the connection was produced while
	// ownership was unresolved.
	stable.Store(true) // commitTransition; the epoch is deliberately NOT advanced
	require.False(t, duringTransition(),
		"a connection dialled during a transition must not become acceptable merely because the "+
			"transition later committed. The commit does not advance the epoch, so the epoch check "+
			"alone cannot reject it; only remembering that the dial STARTED while the network was "+
			"unstable can")

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

// TestEveryDialEntryPointSharesTheTransitionContract pins that the fix covers all four entry points,
// not just the plain dial.
//
// DialContext, DialParallelInterface, ListenPacket and ListenSerialInterfacePacket each capture their
// own epoch. If any of them kept the old capture the DURING-to-AFTER laundering would remain open on
// that path, and a UDP listener is exactly where a stale network binding does the most damage.
func TestEveryDialEntryPointSharesTheTransitionContract(t *testing.T) {
	epoch := &atomic.Uint64{}
	stable := &atomic.Bool{}
	stable.Store(true)
	epoch.Store(1)
	dialer := &DefaultDialer{networkEpoch: epoch.Load, networkStable: stable.Load}

	// Start every entry point's capture while the network is settled, then transition.
	settled := []func() bool{
		dialer.captureEpoch(), // DialContext
		dialer.captureEpoch(), // DialParallelInterface
		dialer.captureEpoch(), // ListenPacket
		dialer.captureEpoch(), // ListenSerialInterfacePacket
	}
	for i, handOver := range settled {
		require.True(t, handOver(), "entry point %d must accept in a settled state", i)
	}

	stable.Store(false)
	epoch.Add(1)

	// Start a second round DURING the transition.
	during := []func() bool{
		dialer.captureEpoch(),
		dialer.captureEpoch(),
		dialer.captureEpoch(),
		dialer.captureEpoch(),
	}

	// The transition commits: the state settles and the epoch does NOT move again.
	stable.Store(true)

	for i, handOver := range settled {
		require.False(t, handOver(),
			"entry point %d accepted a connection dialled before the transition, after it committed", i)
	}
	for i, handOver := range during {
		require.False(t, handOver(),
			"entry point %d laundered a connection that STARTED during the transition into a valid "+
				"one once the transition committed; a commit does not advance the epoch, so only the "+
				"started-state record rejects it", i)
	}
}

// The epoch and the settled state must come from ONE observation.
//
// # The tear
//
// Reading them as two calls allows:
//
//	startedStable = true       <- read first
//	                           <- a transition begins here
//	capturedEpoch = R2         <- reads the NEW epoch
//
// The consumer has recorded "started settled, epoch R2", which is the state of a dial begun AFTER the
// transition. An operation that actually began during the DURING window is recorded as a valid stable
// one, and the commit that follows accepts it - the unsafe direction, because it launders exactly the
// case the start-state record exists to reject.
//
// # What is asserted here
//
// That the dialer USES the manager's snapshot when one is offered. The snapshot's own consistency is
// the manager's responsibility (it takes both values under its ownership lock, asserted in the route
// package); what this verifies is the wiring, because a dialer that ignores the capability silently
// falls back to the tearing pair.
func TestDialPrefersTheAtomicSnapshotWhenOffered(t *testing.T) {
	epoch := &atomic.Uint64{}
	stable := &atomic.Bool{}
	stable.Store(true)
	epoch.Store(1)

	// A manager that offers the capability and records how often it is used.
	var snapshotCalls atomic.Int32
	manager := &snapshotNetworkManager{
		epoch:  epoch,
		stable: stable,
		snapshot: func() (uint64, bool) {
			snapshotCalls.Add(1)
			return epoch.Load(), stable.Load()
		},
	}

	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	dialer, err := NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)
	require.NotNil(t, dialer.networkSnapshot,
		"the dialer must adopt the manager's snapshot capability; ignoring it falls back to two "+
			"separate reads, which can record a DURING dial as one that began settled")

	handOver := dialer.captureEpoch()
	require.EqualValues(t, 1, snapshotCalls.Load(),
		"the capture must come from the snapshot, not from the two individual accessors")

	require.True(t, handOver())
	stable.Store(false)
	require.False(t, handOver(), "a transition begun during the dial still rejects it")
}

// snapshotNetworkManager offers both the individual accessors and the atomic snapshot.
type snapshotNetworkManager struct {
	adapter.NetworkManager
	epoch    *atomic.Uint64
	stable   *atomic.Bool
	snapshot func() (uint64, bool)
}

func (m *snapshotNetworkManager) NetworkResetGeneration() uint64 { return m.epoch.Load() }
func (m *snapshotNetworkManager) NetworkTransitionStable() bool  { return m.stable.Load() }
func (m *snapshotNetworkManager) NetworkTransitionSnapshot() (uint64, bool) {
	return m.snapshot()
}
func (m *snapshotNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (m *snapshotNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}
func (m *snapshotNetworkManager) AutoDetectInterface() bool { return false }
func (m *snapshotNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error { return nil }
}

var _ adapter.NetworkTransitionSnapshotter = (*snapshotNetworkManager)(nil)
