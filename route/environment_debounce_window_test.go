package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

// An environment-affecting event must establish its boundary immediately, not after a debounce.
//
// # Why the delay was a correctness hole, not a latency detail
//
// The boundary resets the DNS transports, which is what re-pins each transport's cache namespace to
// the network it is actually on. A debounced boundary means that between the event and the timer
// firing, the pin still names the OLD network while the transports are free to re-dial on the NEW
// one - DNS transports acquire from a pool and dial through the dialer when a connection is
// invalidated, and that dial resolves the device's routes at that moment. So this sequence was
// reachable with no timer ever involved:
//
//	SSID moves A -> B
//	  -> the boundary is deferred by a second
//	  -> the pooled connection dies and the transport re-dials, now on B
//	  -> B's answer is filed under A's namespace
//
// # What these tests assert
//
// That the event itself takes the boundary. They observe the reset the boundary performs, so they
// fail if any of it is deferred: with a debounce the count is still zero when the assertion runs,
// and the test does not wait for a timer to make it true.

// TestWIFIStateChangeEstablishesItsBoundaryImmediately covers onWIFIStateChanged, the direct Wi-Fi
// event.
func TestWIFIStateChangeEstablishesItsBoundaryImmediately(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	before := harness.resetCount()

	// The Wi-Fi event itself.
	harness.manager.onWIFIStateChanged(adapter.WIFIState{SSID: "B"})

	// No waiting: the event must already have established the boundary. A debounced implementation
	// would still report the old count here, and would only fix it a second later - which is the
	// window this test exists to close.
	require.Equal(t, before+1, harness.resetCount(),
		"the Wi-Fi state change must establish its boundary immediately. Deferring it leaves the "+
			"DNS transports pinned to the old network while they are already free to re-dial on the "+
			"new one")
}

// TestInterfacePathWIFITransitionEstablishesItsBoundaryImmediately covers the nested path, which is
// the one that used to reach the debounce from inside the reset lock.
//
// updateInterface calls UpdateWIFIState, which calls onWIFIStateChanged. That chain must NOT reach a
// timer: updateInterface already holds resetRunAccess, and it is the synchronisation point for the
// interface event it is processing.
func TestInterfacePathWIFITransitionEstablishesItsBoundaryImmediately(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	before := harness.resetCount()

	// The Wi-Fi monitor reports a new SSID, and updateInterface reads it through UpdateWIFIState.
	harness.manager.wifiMonitor = &staticWIFIMonitor{state: adapter.WIFIState{SSID: "B"}}
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"a Wi-Fi transition observed through updateInterface must establish its boundary in that "+
			"same call. Routing it back through the debounce defers it by a second even though the "+
			"update already knows the environment moved")
}

// TestInterfaceListChangeEstablishesItsBoundaryImmediately covers the interface-list refresh path.
//
// UpdateInterfaces refreshes the host's real interface list through the system finder and then defers
// to postUpdateNetworkEnvironment, which is where the boundary is established. A unit fixture has no
// system finder - acquiring one would make the test depend on the host's live network - so this
// exercises the boundary step directly, which is the part that used to be debounced.
func TestInterfaceListChangeEstablishesItsBoundaryImmediately(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	before := harness.resetCount()

	// The interface list refresh moved the fingerprint: the default interface now reports a different
	// gateway, which is what a roam between access points looks like to this layer.
	harness.manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("198.51.100.1")},
	}})

	// This is what UpdateInterfaces defers to.
	harness.manager.postUpdateNetworkEnvironment()

	require.Equal(t, before+1, harness.resetCount(),
		"an interface list change must establish its boundary immediately; the gateways and hardware "+
			"addresses it carries are part of the environment fingerprint")
}

// TestUnchangedWIFIStateIsStillNotATransition is the negative control for the immediate path.
//
// Establishing the boundary synchronously must not turn every repeated Wi-Fi report into a reset:
// the monitor re-reports the same state, and that is exactly the noise the debounce existed for.
func TestUnchangedWIFIStateIsStillNotATransition(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	before := harness.resetCount()

	// The same state, reported repeatedly.
	for i := 0; i < 5; i++ {
		harness.manager.onWIFIStateChanged(adapter.WIFIState{SSID: "A"})
	}

	require.Equal(t, before, harness.resetCount(),
		"a repeated report of an unchanged Wi-Fi state must not reset; only a real transition is a "+
			"boundary")
}

// staticWIFIMonitor reports a fixed Wi-Fi state.
type staticWIFIMonitor struct {
	state adapter.WIFIState
}

func (m *staticWIFIMonitor) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	return m.state
}
func (m *staticWIFIMonitor) Start() error { return nil }
func (m *staticWIFIMonitor) Close() error { return nil }

// A transition to a network with no fingerprint at all still has to be a boundary.
//
// # What "no fingerprint" means, and why it is not "unknown"
//
// The hash is built from the default interface's gateways, the Wi-Fi SSID, or the gateway hardware
// addresses. It is therefore zero exactly when the device has no default interface, no gateways and
// no SSID - a disconnected network, or one whose link is down. That is a real, representable state,
// not a missing reading: the manager publishes the zero as its network environment.
//
// Publishing it without a boundary is the inconsistency this tests. After A -> disconnected the pin
// still names A, so a transport that re-dials while the device is coming back up on B files B's
// answers under A. The published environment says "not A" and the pin says "A".
func TestEnvironmentTransitionToZeroEstablishesABoundary(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	before := harness.resetCount()
	require.NotZero(t, harness.manager.NetworkEnvironment(),
		"the settled environment must be non-zero, or there is nothing to transition away from")

	// The network goes away: no default interface and no SSID, so the fingerprint is zero.
	harness.manager.stateAccess.Lock()
	harness.manager.wifiState = adapter.WIFIState{}
	harness.manager.stateAccess.Unlock()
	harness.manager.interfaceMonitor = &staticInterfaceMonitor{}

	harness.manager.postUpdateNetworkEnvironment()

	require.EqualValues(t, 0, harness.manager.NetworkEnvironment(),
		"the environment is published as zero, which is what makes the missing boundary an "+
			"inconsistency rather than an absence of information")
	require.Equal(t, before+1, harness.resetCount(),
		"a transition to a network with no fingerprint must still establish its boundary. The "+
			"environment was published as zero while the transports stayed pinned to the previous "+
			"network, so a reconnect on the next network files its answers under the old namespace")
}

// TestEnvironmentZeroToNetworkEstablishesABoundary is the reverse direction, and the one that matters
// for coming back: the device reconnects, and the transports must not still be pinned to zero.
func TestEnvironmentZeroToNetworkEstablishesABoundary(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Start from the disconnected state.
	harness.manager.interfaceMonitor = &staticInterfaceMonitor{}
	harness.manager.updateNetworkEnvironment()
	require.EqualValues(t, 0, harness.manager.NetworkEnvironment())

	before := harness.resetCount()

	// The network comes back.
	harness.manager.interfaceMonitor = &staticInterfaceMonitor{
		current: &control.Interface{Index: 1, Name: "en0"},
	}
	harness.manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}})
	harness.setSSID("A")
	harness.manager.postUpdateNetworkEnvironment()

	require.NotZero(t, harness.manager.NetworkEnvironment())
	require.Equal(t, before+1, harness.resetCount(),
		"reconnecting must establish a boundary, or the transports stay pinned to the disconnected "+
			"state and the first queries on the new network are filed under it")
}
