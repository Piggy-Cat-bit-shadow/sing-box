package direct

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"

	"github.com/stretchr/testify/require"
)

// Network-transition tests for the bypass decision.
//
// # The invariant
//
// A bypass replaces the userspace dial with a connect performed by the platform. For that to be an
// optimisation rather than a behaviour change, the bypass decision must agree with what the userspace
// path would have done - including on the checks that depend on live state rather than on
// configuration.
//
// The self-address guard is the only such check on this outbound, and it is refreshed on every
// interface update rather than captured once. These tests pin both halves: that the two paths agree,
// and that the state they agree on is the CURRENT one rather than the one from before a transition.

// TestBypassAgreesWithTheDialPathOnSelfAddresses is the agreement invariant.
//
// If CanBypass said yes where DialContext says no, the bypass would connect to an address the
// userspace path deliberately refuses, which is how a TUN ends up routing a connection back into
// itself.
func TestBypassAgreesWithTheDialPathOnSelfAddresses(t *testing.T) {
	outbound := bypassable(option.DialerOptions{})
	tunPrefix := netip.MustParsePrefix("10.0.0.1/32")
	outbound.myAddresses.Store([]netip.Prefix{tunPrefix})

	self := netip.MustParseAddr("10.0.0.1")
	other := netip.MustParseAddr("93.184.216.34")

	_, dialErr := outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(self.String()+":443"))
	require.Error(t, dialErr, "the userspace path refuses this host's own address")
	require.False(t, outbound.CanBypass(N.NetworkTCP, self),
		"and the bypass must refuse it too, or the two paths disagree about the same connection")

	require.True(t, outbound.CanBypass(N.NetworkTCP, other),
		"an unrelated destination is unaffected")

	// The guard is exactly as fresh as the dial path's, which is the property that matters: a stale
	// or never-fetched address list makes both paths permissive together rather than one of them
	// silently stricter.
	outbound.myAddresses.Store(nil)
	require.True(t, outbound.CanBypass(N.NetworkTCP, self),
		"with no address list both paths allow it; the bypass does not invent a stricter rule than "+
			"the dial path applies")
}

// interfaceMonitorStub reports a fixed set of interfaces this host owns.
type interfaceMonitorStub struct {
	names []string
}

func (m *interfaceMonitorStub) Start() error { return nil }
func (m *interfaceMonitorStub) Close() error { return nil }
func (m *interfaceMonitorStub) DefaultInterface() *control.Interface {
	return nil
}
func (m *interfaceMonitorStub) OverrideAndroidVPN() bool { return false }
func (m *interfaceMonitorStub) AndroidVPNEnabled() bool  { return false }
func (m *interfaceMonitorStub) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (m *interfaceMonitorStub) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {
}
func (m *interfaceMonitorStub) RegisterMyInterface(string) {}
func (m *interfaceMonitorStub) MyInterfaces() []string     { return m.names }

// interfaceFinderStub serves interfaces by name. Only ByName is consulted by the code under test;
// the rest exist so the stub is a real InterfaceFinder rather than a shape that resembles one.
type interfaceFinderStub struct {
	interfaces map[string]control.Interface
}

func (f *interfaceFinderStub) Update() error { return nil }
func (f *interfaceFinderStub) Interfaces() []control.Interface {
	interfaces := make([]control.Interface, 0, len(f.interfaces))
	for _, iface := range f.interfaces {
		interfaces = append(interfaces, iface)
	}
	return interfaces
}

func (f *interfaceFinderStub) ByName(name string) (*control.Interface, error) {
	iface, loaded := f.interfaces[name]
	if !loaded {
		return nil, E.New("no such interface: ", name)
	}
	return &iface, nil
}

func (f *interfaceFinderStub) ByIndex(int) (*control.Interface, error) {
	return nil, E.New("not implemented")
}

func (f *interfaceFinderStub) ByAddr(netip.Addr) (*control.Interface, error) {
	return nil, E.New("not implemented")
}

func (f *interfaceFinderStub) RegisterInterfaceUpdateCallback(control.InterfaceUpdateCallback) *list.Element[control.InterfaceUpdateCallback] {
	return nil
}

func (f *interfaceFinderStub) UnregisterInterfaceUpdateCallback(*list.Element[control.InterfaceUpdateCallback]) {
}

// interfaceNetworkManagerStub serves an interface monitor and finder. It is named apart from the
// defaults stub in bypass_capability_test.go because the two answer different questions.
type interfaceNetworkManagerStub struct {
	adapter.NetworkManager
	monitor *interfaceMonitorStub
	finder  *interfaceFinderStub
}

func (m *interfaceNetworkManagerStub) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return m.monitor
}
func (m *interfaceNetworkManagerStub) InterfaceFinder() control.InterfaceFinder { return m.finder }

// DefaultOptions is required rather than optional: the ambient-policy check reads it on every bypass
// decision, so a manager that cannot answer it is not a manager this outbound can be given.
func (m *interfaceNetworkManagerStub) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

// TestBypassFollowsAnInterfaceUpdate is the transition half.
//
// A network change moves the host's addresses. A bypass decision made against the addresses from
// before the change would connect to somewhere the new network does not reach, and would refuse
// addresses the host now owns.
func TestBypassFollowsAnInterfaceUpdate(t *testing.T) {
	monitor := &interfaceMonitorStub{names: []string{"en0"}}
	finder := &interfaceFinderStub{interfaces: map[string]control.Interface{
		"en0": {
			Name:      "en0",
			Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")},
		},
	}}
	outbound := bypassable(option.DialerOptions{})
	outbound.network = &interfaceNetworkManagerStub{monitor: monitor, finder: finder}

	outbound.InterfaceUpdated(context.Background())
	require.Equal(t, netip.MustParseAddr("192.168.1.20"), outbound.myAddresses.Load()[0].Addr())
	require.False(t, outbound.CanBypass(N.NetworkTCP, netip.MustParseAddr("192.168.1.20")),
		"an address this host owns is refused")

	// The transition: the same interface, a different address, which is what a network change
	// produces.
	finder.interfaces["en0"] = control.Interface{
		Name:      "en0",
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.5.0.20/24")},
	}
	outbound.InterfaceUpdated(context.Background())

	require.False(t, outbound.CanBypass(N.NetworkTCP, netip.MustParseAddr("10.5.0.20")),
		"the guard must follow the update: this is the current address and a bypass to it would "+
			"loop back into the TUN")
	require.True(t, outbound.CanBypass(N.NetworkTCP, netip.MustParseAddr("192.168.1.20")),
		"and the address from before the transition must stop being treated as this host's, or the "+
			"guard would keep refusing connections the new network routes normally")
}
