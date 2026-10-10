package wireguard

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// An MTU below the IPv6 minimum is refused FOR IPv6 and kept for IPv4-only tunnels.
//
// # Why the combination, and not a floor
//
// 1280 is the smallest MTU an IPv6 path may have (RFC 8200 section 5), so a tunnel configured with an
// IPv6 address and a smaller MTU cannot carry that address at all. A blanket floor at 1280 would
// reject an IPv4-only tunnel at a small MTU, which is a legitimate configuration - a narrow path is a
// real thing - so the two cases are decided separately: the address list says whether IPv6 is
// expected, and the MTU says whether it is possible.
//
// # What it replaces
//
// The failure it replaces is per flow and mislabelled: sing-tun's dispatcher refuses an IPv6 flow whose
// port reports an MTU below its IPv6 minimum, so the operator sees "flow unsupported" while IPv4
// through the same endpoint keeps working. Nothing in that message names the MTU or the address.

func TestMTUBelowTheIPv6MinimumIsRefusedForIPv6(t *testing.T) {
	for _, mtu := range []uint32{1232, 1250, 1279} {
		t.Run(mtuCase(mtu), func(t *testing.T) {
			err := validateTunnelMTU(mtu, []netip.Prefix{netip.MustParsePrefix("fd17::1/128")}, "", 0)
			require.Error(t, err,
				"an IPv6 address on a %d-byte tunnel is unreachable by construction and must be refused", mtu)
			require.ErrorContains(t, err, "mtu")
			require.ErrorContains(t, err, "1280")
		})
	}
}

func TestMTUBelowTheIPv6MinimumIsKeptForIPv4Only(t *testing.T) {
	for _, mtu := range []uint32{68, 576, 1200, 1232, 1250, 1279} {
		t.Run(mtuCase(mtu), func(t *testing.T) {
			require.NoError(t, validateTunnelMTU(mtu, []netip.Prefix{
				netip.MustParsePrefix("10.0.0.1/24"),
			}, "", 0), "an IPv4-only tunnel at %d bytes is a legal configuration and must not gain a floor", mtu)
			// No addresses at all is the same case: nothing is expected to be unreachable.
			require.NoError(t, validateTunnelMTU(mtu, nil, "", 0))
		})
	}
}

// The boundary is inclusive: 1280 is the IPv6 minimum, so it is exactly the smallest accepted value.
func TestTheIPv6MinimumItselfIsAccepted(t *testing.T) {
	require.NoError(t, validateTunnelMTU(1280, []netip.Prefix{netip.MustParsePrefix("fd17::1/128")}, "", 0))
	require.Error(t, validateTunnelMTU(1279, []netip.Prefix{netip.MustParsePrefix("fd17::1/128")}, "", 0))
	// And the fork's default is above it, so a default configuration never meets this rule.
	require.NoError(t, validateTunnelMTU(1408, []netip.Prefix{netip.MustParsePrefix("fd17::1/128")}, "", 0))
}

// A v4-MAPPED address is an IPv4 address on the wire, so it is not the IPv6 case.
//
// ::ffff:10.0.0.1 is a four-byte address expressed in sixteen bytes, and a dual-stack socket carrying
// it emits an IPv4 packet. Refusing a small MTU for it would be refusing the IPv4-only case under an
// IPv6 spelling - exactly the mistake a naive `Is6()` check makes, and the reason the validation asks
// `Is4In6()` as well.
func TestAV4MappedAddressIsNotTheIPv6Case(t *testing.T) {
	mapped := netip.AddrFrom16(netip.MustParseAddr("10.0.0.1").As16())
	require.True(t, mapped.Is4In6(), "the fixture must really be a v4-mapped address")
	require.True(t, mapped.Is6(), "and Is6() must really be true for it, or this test proves nothing")
	require.False(t, mapped.Is4(), "and Is4() must really be false, for the same reason")

	require.NoError(t, validateTunnelMTU(1232, []netip.Prefix{netip.PrefixFrom(mapped, 128)}, "", 0),
		"a v4-mapped address travels as an IPv4 packet, so a narrow MTU is legal for it")

	// The same prefix written as a plain IPv4 address agrees, which is the point.
	require.NoError(t, validateTunnelMTU(1232, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}, "", 0))

	// A real IPv6 address in the same list is still refused.
	require.Error(t, validateTunnelMTU(1232, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"),
		netip.MustParsePrefix("fd17::1/128"),
	}, "", 0), "one unreachable address is enough to refuse the configuration")
}

// The refusal happens at CONSTRUCTION, before any device exists, and it names both numbers.
func TestTheMTURefusalHappensAtConstruction(t *testing.T) {
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    t.Context(),
		Logger:     log.NewNOPFactory().Logger(),
		MTU:        1232,
		Address:    []netip.Prefix{netip.MustParsePrefix("fd17::1/128")},
		PrivateKey: testPrivateKey,
	})
	require.Error(t, err, "an unreachable address must be refused when the endpoint is built")
	require.Nil(t, endpoint)
	require.ErrorContains(t, err, "1232")
	require.ErrorContains(t, err, "fd17::1")

	// The IPv4-only counterpart of the same configuration is accepted, and it publishes the MTU the
	// operator asked for: no floor is silently applied to it either.
	ipv4Only, err := NewEndpoint(EndpointOptions{
		Context:    t.Context(),
		Logger:     log.NewNOPFactory().Logger(),
		MTU:        1232,
		Address:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		PrivateKey: testPrivateKey,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1232, ipv4Only.PortMTU(),
		"the configured MTU must be published unchanged: raising it would give the operator a tunnel "+
			"that reports capacity it was never configured with")
}

// A refusal has to name a lever the operator can actually pull.
//
// # The two cases, and why one message cannot serve both
//
// `mtu` can arrive two ways. The operator can set it, or a `detour` with a provable capacity can
// produce it. When the value is the operator's own, "raise `mtu` to at least 1280" is exactly right.
// When a detour's capacity produced it, that instruction is impossible to follow: the clamp is what
// produced the number, so EVERY larger configured value is clamped straight back to it. MEASURED with a
// detour whose own inner MTU is 1210: the nested MTU is 1130, and 1131, 1280, 1408 and 1500 all clamp to
// 1130. An operator told to "raise `mtu`" would edit the value, watch it come back as 1130, and have
// nothing naming the detour that is really responsible.
//
// So the bounded case names the detour and the value, and offers the lever that exists - the detour's
// own MTU - while the unbounded case keeps the advice that works for it. The generic message is
// asserted to still be produced, so this is a split rather than a replacement.
func TestARefusalNamesTheDetourThatBoundedTheMTU(t *testing.T) {
	const bounded = 1130
	ipv6 := []netip.Prefix{netip.MustParsePrefix("fd17::1/128")}

	derived := validateTunnelMTU(bounded, ipv6, "outer", 1360)
	require.Error(t, derived)
	derivedMessage := derived.Error()
	require.Contains(t, derivedMessage, "outer",
		"a refusal for a derived MTU must name the detour, or nothing identifies where the number came from")
	require.Contains(t, derivedMessage, "1130")
	require.Contains(t, derivedMessage, "fd17::1")
	require.Contains(t, derivedMessage, "1360",
		"and it must name the detour MTU that would work, not only describe it: 1130 needs 150 more bytes "+
			"of capacity, and the detour's own MTU is its capacity plus the difference, "+
			"1210 + 150 = 1360")
	require.NotContains(t, derivedMessage, "Raise `mtu` to at least",
		"the bounded case must not lead with the one instruction that cannot be carried out")
	require.Contains(t, derivedMessage, "Raise the detour's own `mtu`",
		"and it must offer the lever that does exist")

	own := validateTunnelMTU(bounded, ipv6, "", 0)
	require.Error(t, own, "the decision is the same either way: the address is unreachable at 1130")
	ownMessage := own.Error()
	require.Contains(t, ownMessage, "Raise `mtu` to at least",
		"an operator's own value IS theirs to raise, so the generic advice must survive")
	require.NotContains(t, ownMessage, "detour",
		"and it must not invent a detour that was never involved")

	// The construction path carries both facts through, which is what makes the split reachable rather
	// than only callable: they are set from the detour the endpoint was configured with.
	_, err := NewEndpoint(EndpointOptions{
		Context:            t.Context(),
		Logger:             log.NewNOPFactory().Logger(),
		MTU:                bounded,
		MTUBoundedBy:       "outer",
		MTUBoundedRequired: 1360,
		Address:            ipv6,
		PrivateKey:         testPrivateKey,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outer")
	require.Contains(t, err.Error(), "1360")
	require.NotContains(t, err.Error(), "Raise `mtu` to at least")
}

// The published MTU is a field, so it cannot be left stale by a lifecycle transition: it answers before
// Start, while running, and after Close with the same configured number.
//
// # Why this is asserted rather than argued
//
// The previous stale-value defect in this area was real: MASQUE's `PortMTU` read through a device that
// only existed after `StartStateInitialize`, so an upper protocol sizing itself at construction hit a
// nil interface. The equivalent property here - that the number a stacked protocol sizes against cannot
// change when the device is created, restarted or torn down - is what keeps an upper protocol's packet
// size and the tunnel's actual MTU from drifting apart.
func TestThePublishedMTUIsNotStaleAcrossTheLifecycle(t *testing.T) {
	ctx := pauseContext()
	endpoint := newListenPortEndpoint(t, 0)
	// A configured value that is not the default, so a stale default would be visible.
	endpoint.options.MTU = 1360

	beforeStart := endpoint.PortMTU()
	require.EqualValues(t, 1360, beforeStart,
		"the capability must be answerable before Start: the protocols stacked on it are constructed "+
			"first and size themselves then")

	require.NoError(t, endpoint.Initialize(nil))
	require.NoError(t, endpoint.Start(false))
	require.Equal(t, beforeStart, endpoint.PortMTU(),
		"and the value the device was built with must be the value it publishes")

	require.NoError(t, endpoint.Close())
	require.Equal(t, beforeStart, endpoint.PortMTU(),
		"and a closed endpoint still reports the configuration rather than a zero that a caller "+
			"could read as 'no capacity' (see dialer.PathCapacity for why the two are kept apart)")
	_ = ctx
}

func mtuCase(mtu uint32) string {
	switch mtu {
	case 1232:
		return "1232 the IPv6 UDP payload of a 1280-byte tunnel"
	case 1250:
		return "1250 Chrome's initial UDP payload"
	case 1279:
		return "1279 one byte below the minimum"
	case 1280:
		return "1280 the minimum"
	default:
		return "mtu " + itoaUint32(mtu)
	}
}

func itoaUint32(value uint32) string {
	if value == 0 {
		return "0"
	}
	var digits [10]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
