package libbox

import (
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

// # Android handover: several callbacks, one transition
//
// Android's ConnectivityManager does not promise one callback per real transition. A single
// Wi-Fi-to-cellular move can be delivered as onAvailable, onCapabilitiesChanged and
// onLinkPropertiesChanged for the same network, and a re-registration can replay a delivery for a
// network that did not change at all. The platform adapter therefore has two jobs that must not be
// confused:
//
//   - refresh the interface LIST every time, because the NetworkManager resolves the default
//     interface's index through it and a stale list would make the transition look like a
//     different network than it is;
//   - deliver the TRANSITION once, because that is what claims a network generation and runs a
//     reset. Delivering it per callback is exactly the "burst of resets is a burst of work" failure
//     runtime-lifecycle-phase1.5.md section 1.2 lists.
//
// These tests drive the real adapter with a network manager that counts the transition deliveries,
// so the property under test is the one the device sees rather than a claim about it.

// handoverNetworkManager is an adapter.NetworkManager whose only real answers are the two the
// monitor uses. Embedding the interface means every other method panics if this test ever starts
// depending on it, which is the honest failure for a test double.
type handoverNetworkManager struct {
	adapter.NetworkManager
	access  sync.Mutex
	updates int
	finder  control.InterfaceFinder
}

func (m *handoverNetworkManager) UpdateInterfaces() error {
	m.access.Lock()
	defer m.access.Unlock()
	m.updates++
	return nil
}

func (m *handoverNetworkManager) InterfaceFinder() control.InterfaceFinder { return m.finder }

func (m *handoverNetworkManager) updateCount() int {
	m.access.Lock()
	defer m.access.Unlock()
	return m.updates
}

// staticInterfaceFinder answers ByIndex from a fixed table, so the monitor resolves each interface
// deterministically rather than querying the host.
type staticInterfaceFinder struct {
	interfaces []control.Interface
}

func (f *staticInterfaceFinder) Update() error { return nil }

func (f *staticInterfaceFinder) Interfaces() []control.Interface { return f.interfaces }

func (f *staticInterfaceFinder) ByName(name string) (*control.Interface, error) {
	for index := range f.interfaces {
		if f.interfaces[index].Name == name {
			return &f.interfaces[index], nil
		}
	}
	return nil, os.ErrNotExist
}

func (f *staticInterfaceFinder) ByIndex(index int) (*control.Interface, error) {
	for i := range f.interfaces {
		if f.interfaces[i].Index == index {
			return &f.interfaces[i], nil
		}
	}
	return nil, os.ErrNotExist
}

func (f *staticInterfaceFinder) ByAddr(netip.Addr) (*control.Interface, error) {
	return nil, os.ErrNotExist
}

func (f *staticInterfaceFinder) RegisterInterfaceUpdateCallback(control.InterfaceUpdateCallback) *list.Element[control.InterfaceUpdateCallback] {
	return nil
}

func (f *staticInterfaceFinder) UnregisterInterfaceUpdateCallback(*list.Element[control.InterfaceUpdateCallback]) {
}

// handoverFixture is the adapter wired to counting doubles.
type handoverFixture struct {
	monitor *platformDefaultInterfaceMonitor
	manager *handoverNetworkManager
	access  sync.Mutex
	// delivered records every transition the monitor handed to the network manager. A nil entry is
	// the "no default interface" delivery.
	delivered []*control.Interface
}

func newHandoverFixture(t *testing.T) *handoverFixture {
	t.Helper()
	finder := &staticInterfaceFinder{interfaces: []control.Interface{
		{Index: 3, Name: "wlan0"},
		{Index: 7, Name: "rmnet0"},
	}}
	manager := &handoverNetworkManager{finder: finder}
	monitor := &platformDefaultInterfaceMonitor{
		platformInterfaceWrapper: &platformInterfaceWrapper{networkManager: manager},
		logger:                   logger.NOP(),
	}
	fixture := &handoverFixture{monitor: monitor, manager: manager}
	monitor.RegisterCallback(func(updated *control.Interface, flags int) {
		fixture.access.Lock()
		defer fixture.access.Unlock()
		fixture.delivered = append(fixture.delivered, updated)
	})
	return fixture
}

func (f *handoverFixture) deliveries() []*control.Interface {
	f.access.Lock()
	defer f.access.Unlock()
	return append([]*control.Interface(nil), f.delivered...)
}

// TestHandoverBurstDeliversOneTransitionPerRealChange is the Task 4 proof at the Android edge.
func TestHandoverBurstDeliversOneTransitionPerRealChange(t *testing.T) {
	fixture := newHandoverFixture(t)

	// One real Wi-Fi association, delivered the way ConnectivityManager delivers it: a burst of
	// callbacks for the same network. Every callback refreshes the list; only the first is a
	// transition.
	for range 8 {
		fixture.monitor.UpdateDefaultInterface("wlan0", 3, false, false)
	}
	deliveries := fixture.deliveries()
	require.Len(t, deliveries, 1,
		"a burst of callbacks for one transition must be delivered once; %d deliveries means %d network generations claimed", len(deliveries), len(deliveries))
	require.Equal(t, "wlan0", deliveries[0].Name)
	require.Equal(t, 8, fixture.manager.updateCount(),
		"the interface LIST must be refreshed for every callback even when the transition is deduplicated")

	// The real handover: a different network with a different index. It must NOT be swallowed.
	fixture.monitor.UpdateDefaultInterface("rmnet0", 7, true, true)
	deliveries = fixture.deliveries()
	require.Len(t, deliveries, 2, "a genuine change to a different interface is a new transition")
	require.Equal(t, "rmnet0", deliveries[1].Name)

	// A caller that reports the same interface again after the change is a repeat of the second
	// transition, not a third one.
	for range 5 {
		fixture.monitor.UpdateDefaultInterface("rmnet0", 7, true, true)
	}
	require.Len(t, fixture.deliveries(), 2,
		"a repeated report of the current interface is not a new transition")
}

// TestHandoverLossAndRestorationAreBothDelivered: the offline edge is deliberately NOT deduplicated,
// and this pins why.
//
// The monitor cannot tell "the same outage reported again" from "the interface came back and went
// away again" without an interface, and swallowing the report would swallow the restoration that
// follows it - the one transition that must never be lost. The deduplication that makes repeated
// offline reports cheap lives one layer down, in NetworkManager.notifyInterfaceUpdate, which
// coalesces them onto the transition token it already holds.
func TestHandoverLossAndRestorationAreBothDelivered(t *testing.T) {
	fixture := newHandoverFixture(t)
	fixture.monitor.UpdateDefaultInterface("wlan0", 3, false, false)

	// The path is lost. Android reports no default interface.
	fixture.monitor.UpdateDefaultInterface("", -1, false, false)
	fixture.monitor.UpdateDefaultInterface("", -1, false, false)
	require.Len(t, fixture.deliveries(), 3,
		"each offline report is delivered; the network layer coalesces them into one claim")
	require.Nil(t, fixture.deliveries()[1])
	require.Nil(t, fixture.deliveries()[2])

	// And the restoration is a transition, not a repeat.
	fixture.monitor.UpdateDefaultInterface("rmnet0", 7, true, false)
	require.Len(t, fixture.deliveries(), 4)
	require.Equal(t, "rmnet0", fixture.deliveries()[3].Name)
}

// TestHandoverRestorationAfterTheSameInterfaceIsNotSwallowed: "the same index came back" must still
// be a transition, because the device may have moved networks behind the same interface name.
//
// The monitor's dedup is on (index, name), and the NetworkManager's environment fingerprint - the
// gateway, the SSID, the gateway hardware address - is what decides whether the network actually
// moved. That two-level split is what lets a same-interface reconnect still claim a generation.
func TestHandoverRestorationAfterTheSameInterfaceIsNotSwallowed(t *testing.T) {
	fixture := newHandoverFixture(t)
	fixture.monitor.UpdateDefaultInterface("wlan0", 3, false, false)
	require.Len(t, fixture.deliveries(), 1)

	fixture.monitor.UpdateDefaultInterface("", -1, false, false)
	fixture.monitor.UpdateDefaultInterface("wlan0", 3, false, false)

	deliveries := fixture.deliveries()
	require.Len(t, deliveries, 3, "a loss and a restoration are two transitions even on the same interface")
	require.Nil(t, deliveries[1])
	require.Equal(t, "wlan0", deliveries[2].Name)
}

// TestNetworkInterfaceExpensiveAndConstrainedHaveAndroidSources is the Task 5 mapping.
//
// Expensive and Constrained are the two flags the existing policy reads: adapter.NetworkInterface
// carries them, route/rule_item_network_is_expensive.go and ..._constrained.go match on them, and the
// resolver logs them. Android supplies both through the platform interface:
//
//   - Expensive: NetworkCapabilities.metered (the app reports it per interface as
//     NetworkInterface.Metered, which is NET_CAPABILITY_NOT_METERED inverted), or the default
//     network's own expensive flag from UpdateDefaultInterface;
//   - Constrained: the default network's constrained flag from UpdateDefaultInterface, which is
//     Android's restricted / Data-Saver state.
//
// # Metered does not change routing on its own
//
// The flags are DATA. Nothing in the core consults them to choose an outbound: the only consumers are
// the rule items the operator writes (network_is_expensive / network_is_constrained) plus a log line.
// A metered Wi-Fi network therefore routes the user's foreground traffic exactly as an unmetered one
// does unless the configuration says otherwise, which is the requirement: metering may inform policy,
// it must not silently move traffic.
func TestNetworkInterfaceExpensiveAndConstrainedHaveAndroidSources(t *testing.T) {
	platform := &meteredPlatformInterface{interfaces: []*NetworkInterface{
		{Index: 3, Name: "wlan0", Type: InterfaceTypeWIFI, Metered: false},
		{Index: 7, Name: "rmnet0", Type: InterfaceTypeCellular, Metered: true},
	}}
	wrapper := &platformInterfaceWrapper{iif: platform, myTunName: "tun0"}
	wrapper.defaultInterface = &control.Interface{Index: 7, Name: "rmnet0"}
	// The default network is metered AND the app reports it as expensive/constrained through
	// UpdateDefaultInterface; the two sources must agree rather than one overriding the other.
	wrapper.isExpensive = true
	wrapper.isConstrained = true

	interfaces, err := wrapper.NetworkInterfaces()
	require.NoError(t, err)
	require.Len(t, interfaces, 2)

	var wifi, cellular adapter.NetworkInterface
	for _, networkInterface := range interfaces {
		switch networkInterface.Name {
		case "wlan0":
			wifi = networkInterface
		case "rmnet0":
			cellular = networkInterface
		}
	}

	require.False(t, wifi.Expensive, "an unmetered non-default interface is not expensive")
	require.False(t, wifi.Constrained,
		"constrained is a property of the DEFAULT network; a non-default interface must not inherit it")
	require.True(t, cellular.Expensive,
		"a metered interface is expensive, which is Android's NET_CAPABILITY_NOT_METERED inverted")
	require.True(t, cellular.Constrained)
	require.Equal(t, C.InterfaceTypeCellular, cellular.Type)
}

// TestMeteredDefaultDoesNotChangeTheNetworkEnvironment: the expensive flag is not part of the
// environment fingerprint, so a metered/unmetered change alone cannot claim a generation and reset
// the transports.
//
// The fingerprint is built from gateways, SSID and gateway hardware addresses - the things that
// identify the NETWORK. Metering is a property of the link, not of the path to the destination, and a
// Data Saver toggle must not tear down every pooled connection the user is using.
func TestMeteredDefaultDoesNotChangeTheNetworkEnvironment(t *testing.T) {
	fixture := newHandoverFixture(t)
	fixture.monitor.UpdateDefaultInterface("rmnet0", 7, false, false)
	require.Len(t, fixture.deliveries(), 1)

	// The same network is now reported as expensive and constrained. The index and name did not
	// change, so this is not a transition.
	fixture.monitor.UpdateDefaultInterface("rmnet0", 7, true, true)
	require.Len(t, fixture.deliveries(), 1,
		"a metering change on the same interface must not claim a generation")
}

// meteredPlatformInterface supplies the interface list and nothing else. Embedding the interface
// makes any other call a visible panic rather than a silent zero value.
type meteredPlatformInterface struct {
	PlatformInterface
	interfaces []*NetworkInterface
}

func (p *meteredPlatformInterface) GetInterfaces() (NetworkInterfaceIterator, error) {
	return newIterator(p.interfaces), nil
}

// interfaceTypeAssertion keeps the embedded-interface trick from silently changing if the platform
// interface ever gains a method this fixture needs.
var _ tun.DefaultInterfaceMonitor = (*platformDefaultInterfaceMonitor)(nil)
