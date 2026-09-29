//go:build with_quic

package masque

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// Tests for the precompiled route matcher.
//
// # The property, and why it is stated against RoutesContain
//
// The matcher is an optimisation, so its only obligation is to answer exactly what the linear scan
// answers. Stating that as "agrees with RoutesContain" rather than against literal booleans keeps
// the test meaningful if the routing RULES change: the reference implementation moves with them and
// the matcher is required to follow.
//
// Equivalence over a fixed case table would be weak on its own, because the interesting inputs are
// combinations of family, containment and protocol. The table below crosses all three.

// matcherEquivalenceRouteSets covers the shapes that matter: empty, a catch-all, a mixed-protocol
// IPv4 set, an IPv6 set, and a set with both families present.
func matcherEquivalenceRouteSets() [][]AddressRange {
	return [][]AddressRange{
		nil,
		{},
		// A default route: the common single-route advertisement.
		{{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255")}},
		// Mixed protocol coverage, which is where the Protocol field earns its place.
		{
			{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.255.255"), Protocol: 0},
			{Start: netip.MustParseAddr("10.1.0.0"), End: netip.MustParseAddr("10.1.255.255"), Protocol: 6},
			{Start: netip.MustParseAddr("192.168.0.0"), End: netip.MustParseAddr("192.168.255.255"), Protocol: 17},
		},
		// IPv6 only, including a range whose end is not at a byte boundary.
		{
			{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff"), Protocol: 0},
			{Start: netip.MustParseAddr("2001:db9::"), End: netip.MustParseAddr("2001:db9::ffff"), Protocol: 6},
		},
		// Both families in one set: a mixed list must not let one family's ranges answer for the
		// other, which is what the family split exists to prevent.
		{
			{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: 0},
			{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ff"), Protocol: 0},
		},
		// A single-address range, the degenerate case a very specific advertisement produces.
		{{Start: netip.MustParseAddr("203.0.113.7"), End: netip.MustParseAddr("203.0.113.7"), Protocol: 0}},
	}
}

// TestRouteMatcherAgreesWithTheLinearScan is the equivalence property.
func TestRouteMatcherAgreesWithTheLinearScan(t *testing.T) {
	t.Parallel()

	addresses := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("9.255.255.255"),
		netip.MustParseAddr("10.0.0.0"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.255.255"),
		netip.MustParseAddr("10.1.0.0"),
		netip.MustParseAddr("10.1.0.1"),
		netip.MustParseAddr("10.1.255.255"),
		netip.MustParseAddr("10.2.0.1"),
		netip.MustParseAddr("192.168.0.0"),
		netip.MustParseAddr("192.168.255.255"),
		netip.MustParseAddr("203.0.113.7"),
		netip.MustParseAddr("203.0.113.8"),
		netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("2001:db8::"),
		netip.MustParseAddr("2001:db8::ff"),
		netip.MustParseAddr("2001:db8::ffff"),
		netip.MustParseAddr("2001:db8::1:0"),
		netip.MustParseAddr("2001:db9::1"),
		netip.MustParseAddr("2001:dba::1"),
		netip.MustParseAddr("::"),
	}
	protocols := []uint8{0, 6, 17, 1, 58, 47}

	for setIndex, routes := range matcherEquivalenceRouteSets() {
		matcher := compileRouteMatcher(routes)
		for _, address := range addresses {
			for _, protocol := range protocols {
				require.Equal(t,
					RoutesContain(routes, address, protocol),
					matcher.contains(address, protocol),
					"route set %d, address %v, protocol %d: the matcher must answer exactly what the "+
						"linear scan answers", setIndex, address, protocol)
			}
		}
	}
}

// TestRouteMatcherHandlesTheEmptySet proves the zero value is usable.
//
// The matcher is stored in the published snapshot, and a session that has not received a
// ROUTE_ADVERTISEMENT yet has no routes at all. Requiring an explicit "no routes" flag at every
// call site would put a branch back on the packet path for a case the zero value already handles.
func TestRouteMatcherHandlesTheEmptySet(t *testing.T) {
	t.Parallel()

	var zero routeMatcher
	require.False(t, zero.contains(netip.MustParseAddr("10.0.0.1"), 6))

	compiled := compileRouteMatcher(nil)
	require.False(t, compiled.contains(netip.MustParseAddr("10.0.0.1"), 6))
}

// TestRouteMatcherDoesNotSortTheCallersSlice is the aliasing guard.
//
// The matcher sorts its own copies. Sorting the caller's slice in place would mutate a
// Configuration that the published snapshot shares with readers -- the same aliasing the snapshot
// design takes care to avoid -- and the corruption would appear as an unrelated routing change
// later.
func TestRouteMatcherDoesNotSortTheCallersSlice(t *testing.T) {
	t.Parallel()

	// Deliberately out of order, so an in-place sort would be visible.
	routes := []AddressRange{
		{Start: netip.MustParseAddr("192.168.0.0"), End: netip.MustParseAddr("192.168.0.255")},
		{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255")},
	}
	original := append([]AddressRange(nil), routes...)

	_ = compileRouteMatcher(routes)

	require.Equal(t, original, routes,
		"compiling a matcher must not reorder the caller's ranges")
}

// TestRouteMatcherFallsBackOnAnOverlappingSet covers the defensive path.
//
// parseRoutes rejects overlapping ranges, so this input cannot come from a capsule -- but the
// matcher is also reachable with a locally configured route set, and a binary search over
// overlapping ranges can return a containing range whose protocol does not match while an earlier
// range would have matched.
//
// The fallback exists so the answer stays correct in that case instead of quietly becoming
// order-dependent. This test states the property rather than the mechanism: the matcher must still
// agree with the scan.
func TestRouteMatcherFallsBackOnAnOverlappingSet(t *testing.T) {
	t.Parallel()

	// A wide UDP range with a narrower TCP range nested inside it. The LAST range starting at or
	// below 10.5.1.1 is the TCP one, so a matcher that trusted the search alone and gave up when
	// the protocol did not match would wrongly answer false for UDP.
	routes := []AddressRange{
		{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.255.255.255"), Protocol: 17},
		{Start: netip.MustParseAddr("10.5.0.0"), End: netip.MustParseAddr("10.5.255.255"), Protocol: 6},
	}
	matcher := compileRouteMatcher(routes)
	address := netip.MustParseAddr("10.5.1.1")

	for _, protocol := range []uint8{6, 17, 1} {
		require.Equal(t, RoutesContain(routes, address, protocol), matcher.contains(address, protocol),
			"an overlapping set must still agree with the scan for protocol %d", protocol)
	}
}
