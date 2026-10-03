package direct

import (
	"net/netip"
	"testing"

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
