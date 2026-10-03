package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

// One interface update that both moves the network environment AND has a pending interface reset must
// produce exactly ONE reset.
//
// # Why both reasons fire together
//
// notifyInterfaceUpdate sets networkResetPending, and updateInterface then recomputes the environment.
// A real interface change does both at once: the default interface changed (so an interface reset is
// pending) and the gateway/SSID fingerprint moved with it (so the environment boundary fires). The
// two decisions were made independently and each called resetNetworkLocked, so a single physical
// transition tore the network down twice - and the second reset was not a response to a second event.
//
// # What the test observes
//
// It drives the production decision path rather than the inner helper: updateInterface itself, with
// the pending flag and the environment both set. Reset count is asserted with Equal, not Greater,
// because the defect is precisely that the count is one too high.

// interfaceTransitionHarness is a NetworkManager wired so updateInterface reaches a real decision.
type interfaceTransitionHarness struct {
	manager *NetworkManager
	router  *countingRouter
}

// newInterfaceTransitionHarness builds a started manager whose environment fingerprint the test
// drives through the Wi-Fi SSID.
//
// The fingerprint is a hash of the default interface's gateways, its SSID, or its gateway hardware
// addresses. An SSID is the simplest of the three to move without a host: WIFIState reads a field on
// the manager, so the test can transition A -> B by publishing a different SSID, which is also the
// exact transition onWIFIStateChanged exists for.
func newInterfaceTransitionHarness(t *testing.T) *interfaceTransitionHarness {
	t.Helper()
	router := &countingRouter{}
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
	// A default interface with one gateway, so the fingerprint is non-empty and the transition has
	// something to move. networkInterfaces is what DefaultNetworkInterface resolves against.
	// Gateways live on adapter.NetworkInterface (the control.Interface it embeds carries only index,
	// name and addresses), so the gateway the fingerprint reads is supplied there.
	manager.interfaceMonitor = &staticInterfaceMonitor{
		current: &control.Interface{Index: 1, Name: "en0"},
	}
	manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
	}})
	return &interfaceTransitionHarness{manager: manager, router: router}
}

// setSSID publishes a Wi-Fi SSID, which is the environment transition the test drives.
func (h *interfaceTransitionHarness) setSSID(ssid string) {
	h.manager.stateAccess.Lock()
	h.manager.wifiState = adapter.WIFIState{SSID: ssid}
	h.manager.stateAccess.Unlock()
}

// markInterfaceResetPending arms the other reason updateInterface resets for.
func (h *interfaceTransitionHarness) markInterfaceResetPending() {
	h.manager.interfaceUpdateAccess.Lock()
	h.manager.networkResetPending = true
	h.manager.interfaceUpdateAccess.Unlock()
}

func (h *interfaceTransitionHarness) resetCount() int { return dnsResetCount(h.router) }

// staticInterfaceMonitor is a DefaultInterfaceMonitor whose answer the test controls.
type staticInterfaceMonitor struct {
	current *control.Interface
}

func (m *staticInterfaceMonitor) Start() error                         { return nil }
func (m *staticInterfaceMonitor) Close() error                         { return nil }
func (m *staticInterfaceMonitor) DefaultInterface() *control.Interface { return m.current }
func (m *staticInterfaceMonitor) OverrideAndroidVPN() bool             { return false }
func (m *staticInterfaceMonitor) AndroidVPNEnabled() bool              { return false }
func (m *staticInterfaceMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (m *staticInterfaceMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {
}
func (m *staticInterfaceMonitor) RegisterMyInterface(string) {}
func (m *staticInterfaceMonitor) MyInterfaces() []string     { return nil }

// TestInterfaceEnvironmentTransitionCoalescesPendingReset is the reproduction.
func TestInterfaceEnvironmentTransitionCoalescesPendingReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Settle the fingerprint on SSID "A" first, so the update below is a genuine A -> B move.
	harness.setSSID("A")
	require.Equal(t, 0, harness.resetCount(), "establishing the first fingerprint is not a transition")
	harness.setSSID("B")
	harness.markInterfaceResetPending()

	generationBefore := harness.manager.NetworkResetGeneration()
	before := harness.resetCount()

	// The production entry: one interface update carrying both reasons.
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"one interface update carrying both an environment transition and a pending interface reset "+
			"must reset exactly once. Two resets means the same physical transition tore the network "+
			"down twice: once for the environment boundary and once for the pending flag, with no "+
			"second event behind either")
	require.EqualValues(t, generationBefore+1, harness.manager.NetworkResetGeneration(),
		"the reset epoch must advance exactly once per logical transition")
}

// TestInterfaceEnvironmentTransitionAloneResetsOnce is the control for the environment reason.
func TestInterfaceEnvironmentTransitionAloneResetsOnce(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")

	before := harness.resetCount()
	generationBefore := harness.manager.NetworkResetGeneration()
	harness.setSSID("B")

	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"an environment transition with no pending interface reset must still reset")
	require.EqualValues(t, generationBefore+1, harness.manager.NetworkResetGeneration())
}

// TestInterfacePendingResetAloneResetsOnce is the control for the pending reason.
func TestInterfacePendingResetAloneResetsOnce(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Settle the fingerprint, then leave it alone, so only the pending flag remains as a reason.
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	harness.markInterfaceResetPending()

	before := harness.resetCount()
	generationBefore := harness.manager.NetworkResetGeneration()

	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before+1, harness.resetCount(),
		"a pending interface reset with no environment transition must still reset")
	require.EqualValues(t, generationBefore+1, harness.manager.NetworkResetGeneration())
}

// TestInterfaceUpdateWithNoReasonDoesNotReset is the negative control.
//
// A repeated notification for an unchanged interface and an unchanged environment is exactly the
// noise the debounce exists to absorb. It must not tear down pooled connections.
func TestInterfaceUpdateWithNoReasonDoesNotReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	before := harness.resetCount()

	for i := 0; i < 5; i++ {
		harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	}

	require.Equal(t, before, harness.resetCount(),
		"an update with neither reason must not reset; repeated teardown of pooled connections on a "+
			"stable network is the failure this guards")
}

// TestCancelledInterfaceUpdateDoesNotConsumeNewPendingReset covers the concurrent notification case.
//
// A newer interface event cancels the in-flight update's context and takes over. The cancelled update
// must not consume the pending flag that belongs to the new event, or the new transition is lost.
func TestCancelledInterfaceUpdateDoesNotConsumeNewPendingReset(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")

	// The old update's context is already cancelled when it reaches the decision, as it would be
	// after a newer notification cancelled it.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// A new event arrives and arms the pending flag.
	harness.markInterfaceResetPending()

	before := harness.resetCount()
	harness.manager.updateInterface(cancelledCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, before, harness.resetCount(),
		"a cancelled update must not reset")

	// The pending flag must still be armed for the update that owns the new event.
	harness.manager.interfaceUpdateAccess.Lock()
	stillPending := harness.manager.networkResetPending
	harness.manager.interfaceUpdateAccess.Unlock()
	require.True(t, stillPending,
		"the cancelled update consumed the pending reset that belongs to the newer event; that "+
			"transition is then lost, because the newer update sees nothing to do")

	// And the newer update does perform it.
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	require.Equal(t, before+1, harness.resetCount(),
		"the newer update must still perform the pending reset")
}
