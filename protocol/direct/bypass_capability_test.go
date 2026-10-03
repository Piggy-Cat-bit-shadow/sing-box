package direct

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the direct outbound's bypass capability.
//
// # Why these assert on isEmpty rather than on individual options
//
// isEmpty is the existing "this outbound carries no dial configuration" signal. The capability
// reuses it deliberately: re-listing the individual dialer options here would create a second
// copy of that judgement, and a newly added option would have to be remembered in two places.
// Forgetting one would silently convert a configured outbound into a bypassed one, which is the
// failure mode this whole feature is most exposed to.
//
// The test therefore pins the SIGNAL, so that adding a dial option which does not update isEmpty
// is caught by the isEmpty test suite rather than by a user whose configuration was ignored.

func TestCanBypassRequiresAnEmptyOutbound(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")

	plain := &Outbound{isEmpty: true}
	require.True(t, plain.CanBypass(N.NetworkTCP, address),
		"a plain direct outbound may carry a connection directly")
	require.True(t, plain.CanBypass(N.NetworkUDP, address),
		"the same holds for UDP")

	// Any dial configuration at all must disable the capability. The specific option does not
	// matter: what matters is that isEmpty reports it.
	configured := &Outbound{isEmpty: false}
	require.False(t, configured.CanBypass(N.NetworkTCP, address),
		"a direct outbound carrying dial configuration must not be bypassed, or the user's "+
			"bind address, routing mark or TFO setting would be silently discarded")
	require.False(t, configured.CanBypass(N.NetworkUDP, address))
}

func TestCanBypassRejectsNonTCPAndNonUDP(t *testing.T) {
	plain := &Outbound{isEmpty: true}
	address := netip.MustParseAddr("93.184.216.34")

	// ICMP keeps its existing Flow semantics; this optimisation does not apply to it.
	require.False(t, plain.CanBypass(N.NetworkICMP, address))
	require.False(t, plain.CanBypass("", address))
	require.False(t, plain.CanBypass("ip", address))
}

func TestCanBypassRejectsUnusableAddresses(t *testing.T) {
	plain := &Outbound{isEmpty: true}

	require.False(t, plain.CanBypass(N.NetworkTCP, netip.Addr{}),
		"an invalid address cannot be dialled by anyone")

	zoned := netip.MustParseAddr("fe80::1").WithZone("en0")
	require.False(t, plain.CanBypass(N.NetworkTCP, zoned),
		"a zoned address cannot be expressed through an interface keyed by address alone, so it "+
			"is left to the userspace path")
}

func TestCanBypassPreservesTheLoopbackGuard(t *testing.T) {
	// The direct outbound refuses to dial its own addresses, which is what prevents a TUN from
	// routing a connection back into itself. A bypass is a connect performed by the platform
	// rather than by this dialer, so this guard is the only thing standing between the fast path
	// and that loop.
	selfPrefix := netip.MustParsePrefix("10.0.0.1/32")
	plain := &Outbound{isEmpty: true}
	plain.myAddresses.Store([]netip.Prefix{selfPrefix})

	require.False(t, plain.CanBypass(N.NetworkTCP, netip.MustParseAddr("10.0.0.1")),
		"a destination matching this outbound's own address must not be bypassed")

	require.True(t, plain.CanBypass(N.NetworkTCP, netip.MustParseAddr("93.184.216.34")),
		"an unrelated destination is unaffected by the guard")
}

// --- global network policy (§16, §17, §18) ---------------------------------------------

// networkManagerStub reports a fixed set of global defaults.
//
// isEmpty describes only the outbound's own options, so this is the other half of "is this dialer
// equivalent to a plain OS connect": policy the DefaultDialer inherits from the network manager.
type networkManagerStub struct {
	adapter.NetworkManager
	options adapter.NetworkOptions
}

func (m *networkManagerStub) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *networkManagerStub) Close() error                                               { return nil }
func (m *networkManagerStub) DefaultOptions() adapter.NetworkOptions {
	return m.options
}

// TestCanBypassFailsClosedWithGlobalNetworkPolicy is §17.
//
// Each of these makes the userspace dialer do something a native connect does not: bind to an
// interface, mark packets, or select an interface by strategy. Bypassing would silently discard
// the policy.
func TestCanBypassFailsClosedWithGlobalNetworkPolicy(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")
	networkStrategy := C.NetworkStrategyDefault

	cases := map[string]adapter.NetworkOptions{
		"default_interface":        {BindInterface: "en0"},
		"default_mark":             {RoutingMark: 0x1234},
		"default_network_strategy": {NetworkStrategy: &networkStrategy},
		"default_network_type":     {NetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}},
		"default_fallback_network_type": {
			FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeCellular},
		},
		"default_fallback_delay": {FallbackDelay: 300 * time.Millisecond},
	}

	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			outbound := &Outbound{
				isEmpty: true, // the outbound itself is plain...
				network: &networkManagerStub{options: options},
			}
			require.False(t, outbound.CanBypass(N.NetworkTCP, address),
				"%s is set globally, so the userspace dialer applies policy a native bypass does "+
					"not; the connection must not take the fast path", name)
		})
	}
}

// TestCanBypassAllowedWithNoGlobalPolicy is the control.
//
// Without this, a guard that always returned false would pass the test above.
func TestCanBypassAllowedWithNoGlobalPolicy(t *testing.T) {
	address := netip.MustParseAddr("93.184.216.34")

	outbound := &Outbound{
		isEmpty: true,
		network: &networkManagerStub{options: adapter.NetworkOptions{}},
	}
	require.True(t, outbound.CanBypass(N.NetworkTCP, address),
		"a plain outbound with no global policy may carry the connection directly")

	// A nil manager means no global policy exists to lose.
	noManager := &Outbound{isEmpty: true}
	require.True(t, noManager.CanBypass(N.NetworkTCP, address))
}
