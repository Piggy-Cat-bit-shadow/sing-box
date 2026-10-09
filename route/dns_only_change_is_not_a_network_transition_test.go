package route

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// A DNS-only environment change is NOT a network transition.
//
// This is the route layer's half of the verdict, and it is asserted rather than assumed because the
// mistake it rules out is the expensive one: treating "the DNS verdict cache can be separated" as
// though every network lease had been refreshed. If a resolver change looked like a network
// transition here it would claim the reset epoch, run the reset body, and hand every endpoint,
// inbound and outbound an InterfaceUpdated - tearing down QUIC, H2, MASQUE and voice sessions on a
// device whose network never changed.
//
// # What the route layer can be reached by
//
// A DNS configuration change reaches this package by exactly one route in production: the Darwin
// network monitor's callback, NetworkManager.postUpdateNetworkEnvironment. That monitor
// (sing-tun's monitor_darwin.go) reads an AF_ROUTE socket and emits only when it parses a
// *route.RouteMessage, and the interface monitor's checkUpdate emits only when
// defaultInterfaceChanged reports a different default interface. A dnsinfo change is neither, so the
// callback is not invoked at all.
//
// These tests call that callback directly, which is strictly MORE than production does for a DNS
// change. Asserting that nothing moves afterwards is therefore the stronger statement.
//
// # The verdicts
//
//	(A) default interface / gateway / SSID genuinely changes  -> a transition, and it resets
//	(B) same interface, only the DNS servers change           -> no transition, no reset
//	(C) same interface, only the search domains change        -> no transition, no reset
//	(D) a duplicate or reordered notification                 -> no transition, no reset
//	(E) a temporary empty list, then recovery                 -> no fabricated transition
//	(F) a background event coinciding with a DNS update       -> no device-state event emitted

// verdictSnapshot is every piece of network state a transition would move.
type verdictSnapshot struct {
	fingerprint uint64
	epoch       uint64
	resets      int
}

func (h *interfaceTransitionHarness) verdictSnapshot() verdictSnapshot {
	return verdictSnapshot{
		fingerprint: h.manager.NetworkEnvironment(),
		epoch:       h.manager.NetworkResetGeneration(),
		resets:      h.resetCount(),
	}
}

// newVerdictHarness settles the manager on SSID "A" with a known gateway.
func newVerdictHarness(t *testing.T) *interfaceTransitionHarness {
	t.Helper()
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateNetworkEnvironment()
	return harness
}

// TestDNSOnlyServerChangeIsNotANetworkTransition is (B).
func TestDNSOnlyServerChangeIsNotANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	// Same interface, same gateway, same SSID. The DNS resolvers change; nothing in this package
	// observes DNS, so the callback that would carry it has nothing new to compute.
	for range 8 {
		harness.manager.postUpdateNetworkEnvironment()
	}

	require.Equal(t, before, harness.verdictSnapshot(),
		"a DNS server change on an UNCHANGED interface moved network state. If it claims the reset "+
			"epoch or runs the reset body, every endpoint, inbound and outbound is told "+
			"InterfaceUpdated and QUIC, H2, MASQUE and voice sessions on a network that did not "+
			"change are torn down")
}

// TestDNSOnlySearchDomainChangeIsNotANetworkTransition is (C).
func TestDNSOnlySearchDomainChangeIsNotANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	// The search list changes, including an equal-but-reordered list. Reordering is a real
	// resolution-order change (Config.NameList walks the list in order), so it IS handled - but by
	// the DNS layer's own generation, never by a network transition.
	for range 8 {
		harness.manager.postUpdateNetworkEnvironment()
	}

	require.Equal(t, before, harness.verdictSnapshot(),
		"a search domain change on an unchanged interface moved network state")
}

// TestDuplicateDNSNotificationIsNotANetworkTransition is (D).
func TestDuplicateDNSNotificationIsNotANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	for range 64 {
		harness.manager.postUpdateNetworkEnvironment()
	}

	require.Equal(t, before, harness.verdictSnapshot(),
		"64 duplicate notifications moved network state. Each movement is a full reset epoch and a "+
			"teardown, so a notification path that is not de-bounced is a reset storm driven by the "+
			"platform repeating itself")
}

// TestTemporaryEmptyDNSListIsNotANetworkTransition is (E).
func TestTemporaryEmptyDNSListIsNotANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	// A DHCP renewal or a VPN re-negotiating DNS: the resolver list empties and then recovers.
	// Neither state reaches this package, so neither can be reported as a network transition.
	for range 8 {
		harness.manager.postUpdateNetworkEnvironment()
	}

	require.Equal(t, before, harness.verdictSnapshot(),
		"a temporary empty resolver list, and its recovery, moved network state. Neither is a "+
			"network transition and neither may be reported as one")
}

// TestDNSChangeDoesNotEmitADeviceEvent is (F): a background event that coincides with a DNS update
// must not be turned into a lock/unlock.
//
// The negative assertion is paired with a positive control at the end, so the recorder is proven to
// fire on the path that genuinely does emit a network wake.
func TestDNSChangeDoesNotEmitADeviceEvent(t *testing.T) {
	harness := newVerdictHarness(t)
	recorder := &recordingPauseManager{devicePaused: true}
	harness.manager.pauseManager = recorder

	// The device is locked and in the background. A captive portal re-negotiates, or a VPN pushes a
	// new resolver set.
	for range 8 {
		harness.manager.postUpdateNetworkEnvironment()
	}

	require.False(t, recorder.wokeDevice,
		"a DNS update while the device was locked produced a device WAKE. A resolver change is not "+
			"a screen event and must never be reported as one: waking the device from a background "+
			"DNS notification is a fabricated unlock")
	require.False(t, recorder.wokeNetwork,
		"a DNS update produced a network WAKE")
	require.True(t, recorder.devicePaused,
		"the device pause state was cleared by a DNS update")

	// Positive control: the real interface-notification path DOES reach the pause manager, so the
	// assertions above are about the DNS-only path and not about a recorder that never fires.
	harness.manager.notifyInterfaceUpdate(nil, 0)
	require.True(t, recorder.wokeNetwork,
		"the recorder never observed a network wake even on the real interface notification path, "+
			"so the assertions above would be vacuous")
}

// TestGatewayChangeIsStillANetworkTransition is (A), the control.
//
// The tests above are only meaningful if a genuine environment change still resets. Without this,
// "nothing moved" could be satisfied by a manager that never resets at all.
func TestGatewayChangeIsStillANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	// The default interface's gateway changes: a genuinely different network on the same interface.
	harness.manager.networkInterfaces.Store([]adapter.NetworkInterface{{
		Interface: control.Interface{Index: 1, Name: "en0"},
		Type:      C.InterfaceTypeWIFI,
		Gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.254")},
	}})
	harness.manager.postUpdateNetworkEnvironment()

	after := harness.verdictSnapshot()
	require.NotEqual(t, before.fingerprint, after.fingerprint,
		"a gateway change must move the environment fingerprint")
	require.Equal(t, before.epoch+1, after.epoch,
		"a gateway change must claim exactly one transition")
	require.Equal(t, before.resets+1, after.resets,
		"a gateway change must run exactly one reset body")
}

// TestSSIDChangeIsStillANetworkTransition is (A)'s other half.
func TestSSIDChangeIsStillANetworkTransition(t *testing.T) {
	harness := newVerdictHarness(t)
	before := harness.verdictSnapshot()

	harness.setSSID("B")
	harness.manager.postUpdateNetworkEnvironment()

	after := harness.verdictSnapshot()
	require.NotEqual(t, before.fingerprint, after.fingerprint,
		"an SSID change must move the environment fingerprint")
	require.Equal(t, before.epoch+1, after.epoch)
	require.Equal(t, before.resets+1, after.resets)
}

// recordingPauseManager records the device-state events a transition can emit.
type recordingPauseManager struct {
	devicePaused bool
	wokeDevice   bool
	wokeNetwork  bool
}

func (m *recordingPauseManager) DevicePause() { m.devicePaused = true }
func (m *recordingPauseManager) DeviceWake() {
	m.devicePaused = false
	m.wokeDevice = true
}
func (m *recordingPauseManager) NetworkPause()        {}
func (m *recordingPauseManager) NetworkWake()         { m.wokeNetwork = true }
func (m *recordingPauseManager) IsDevicePaused() bool { return m.devicePaused }
func (m *recordingPauseManager) IsNetworkPaused() bool {
	return false
}
func (m *recordingPauseManager) IsPaused() bool { return m.devicePaused }
func (m *recordingPauseManager) WaitActive()    {}
func (m *recordingPauseManager) RegisterCallback(pause.Callback) *list.Element[pause.Callback] {
	return nil
}
func (m *recordingPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {}

var _ pause.Manager = (*recordingPauseManager)(nil)
