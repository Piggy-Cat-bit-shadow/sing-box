package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// A declared DEPENDENCY that resolves to a group: the shape that is not a chain
// ---------------------------------------------------------------------------
//
// `L.detour = G` is legal: L reaches its own server through whichever member G picks. The physical
// path is then member -> L -> target - one route per member, each of which ENDS AT L - so L is the hop
// the business flow arrives at, on every one of those routes.
//
// The enumeration treated the members as routes of their own instead, which is the shape these tests
// pin. MEASURED before the fix, with `L` carrying TCP only and a rule delivering UDP to L:
//
//	node "L"   route="L"         chain="L"   pos=0 exit=false entry=false
//	node "m1"  route="G -> m1"   chain="m1"  pos=0 exit=true  entry=true
//	node "m2"  route="G -> m2"   chain="m2"  pos=0 exit=true  entry=true
//	reachable=true failures=0            <- the flow arrives at L and nothing was ever asked of it
//
// That is a FALSE PASS in the check the dry run exists to provide, on a hop the caller can name
// exactly - and the chains were wrong in the same direction on every route.

// dependencyOnGroupFixture is `L.detour = G`, G a selector over two dual-network members, L tcp-only.
func dependencyOnGroupFixture() (*testLeaf, *testGroup, *testRegistry) {
	m1 := dualLeaf("m1")
	m2 := dualLeaf("m2")
	group := tcpGroup("G", "m1", "m1", "m2")
	leaf := tcpLeaf("L", "G")
	registry := newRegistry(m1, m2, group, leaf)
	group.lookup = registry.objects
	return leaf, group, registry
}

// TestADependencyOnAGroupEndsEveryRouteAtTheDeclaringHop is the model statement: L is the far end of
// each member's route, and the members are the hops nearest this device.
func TestADependencyOnAGroupEndsEveryRouteAtTheDeclaringHop(t *testing.T) {
	leaf, _, registry := dependencyOnGroupFixture()

	nodes, err := registry.resolver().Hops(leaf)
	require.NoError(t, err)
	require.Len(t, nodes, 4, "two member routes, and the hops above the group echoed into each")

	// Segment the enumeration into routes the same way the order tests do: a route is a run of
	// consecutive positions, and a new route starts wherever the position does not continue.
	var routes [][]PathNode
	for _, node := range nodes {
		last := len(routes) - 1
		if last >= 0 && node.Position == routes[last][len(routes[last])-1].Position+1 {
			routes[last] = append(routes[last], node)
			continue
		}
		routes = append(routes, []PathNode{node})
	}
	require.Len(t, routes, 2, "one route per member: %v", describeNodes(nodes))

	entryChains := make([]string, 0, 2)
	for _, route := range routes {
		require.Len(t, route, 2, "each route is member -> L: %v", describeNodes(route))
		member, entry := route[0], route[1]
		require.NotEqual(t, "L", member.Tag, "the member is nearest this device: %v", describeNodes(route))
		require.Equal(t, member.Tag, member.PhysicalPath[len(member.PhysicalPath)-1],
			"a node's chain ends at the node: %v", describeNodes(nodes))
		require.Equal(t, 0, member.Position, "the member is nearest this device")
		require.False(t, member.Exit,
			"the member is not where the flow arrives: it is what the declaring hop dials THROUGH")
		require.False(t, businessEntry(member),
			"and no network requirement may be demanded of it in the business flow's name")

		require.Equal(t, "L", entry.Tag)
		require.Equal(t, 1, entry.Position, "L is the far end of that route")
		require.True(t, entry.Exit, "and it is the exit - the routing selected it")
		require.True(t, businessEntry(entry),
			"the business flow ARRIVES at L, so the delivered network is a requirement on it")
		require.Equal(t, []string{member.Tag, "L"}, entry.PhysicalPath,
			"the entry's chain is the route the flow actually takes, device first")
		entryChains = append(entryChains, entry.Path())
	}
	require.ElementsMatch(t, []string{"m1 -> L", "m2 -> L"}, entryChains,
		"the echo is the chain the flow actually takes: %v", describeNodes(nodes))

	leaves, err := registry.resolver().Leaves(leaf)
	require.NoError(t, err)
	require.Len(t, leaves, 2, "one leaf per member route, and the leaf is L on both")
	for _, leave := range leaves {
		require.Equal(t, "L", leave.Tag)
		require.True(t, leave.Exit)
	}
}

// TestADeliveredNetworkIsEnforcedOnAHopThatDialsThroughAGroup is the product-level half: the
// configuration the model above describes is REFUSED, and the failure names L on each route.
func TestADeliveredNetworkIsEnforcedOnAHopThatDialsThroughAGroup(t *testing.T) {
	leaf, _, registry := dependencyOnGroupFixture()

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{leaf}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable(),
		"a rule delivers UDP to outbound/L, L dials through a group, and L carries TCP only: Start must "+
			"refuse the configuration. Report: nodes=%v failures=%v",
		describeChecks(report.Nodes), report.Failures)

	named := make([]string, 0, 2)
	for _, failure := range report.Failures {
		if failure.Leaf == "L" {
			named = append(named, failure.Path)
		}
	}
	require.Len(t, named, 2,
		"one failure per route that reaches L, each naming the chain that carries the defect: %v",
		report.Failures)
	require.ElementsMatch(t, []string{"m1 -> L", "m2 -> L"}, named)
	for _, failure := range report.Failures {
		require.Equal(t, 1, failure.Hop, "and the failing hop is L, at its own packet-order index")
	}
}

// TestADependencyOnAGroupWithADeeperMemberIsStillDeviceFirst is the same shape with a member that has
// a dependency of its own, which is where an echoed prefix and a member descent have to interleave
// correctly rather than merely coexist.
func TestADependencyOnAGroupWithADeeperMemberIsStillDeviceFirst(t *testing.T) {
	d1 := dualLeaf("d1")
	m1 := dualLeaf("m1", "d1")
	m2 := dualLeaf("m2")
	group := tcpGroup("G", "m1", "m1", "m2")
	leaf := tcpLeaf("L", "G")
	registry := newRegistry(d1, m1, m2, group, leaf)
	group.lookup = registry.objects

	nodes, err := registry.resolver().Hops(leaf)
	require.NoError(t, err)

	chains := make(map[string]int, len(nodes))
	for _, node := range nodes {
		chains[node.Tag+" on "+node.Path()] = node.Position
		require.Equal(t, node.Position, len(node.PhysicalPath)-1,
			"Position indexes the chain beside it: %v", describeNodes(nodes))
		require.Equal(t, node.Tag, node.PhysicalPath[len(node.PhysicalPath)-1],
			"and the chain ends at the node: %v", describeNodes(nodes))
	}
	require.Equal(t, map[string]int{
		"d1 on d1":           0,
		"m1 on d1 -> m1":     1,
		"L on d1 -> m1 -> L": 2,
		"m2 on m2":           0,
		"L on m2 -> L":       1,
	}, chains, "each route is device-first, and the hops above the group sit at its far end: %v",
		describeNodes(nodes))

	// L is the far end of BOTH routes, and nothing else is an exit.
	exits := 0
	for _, node := range nodes {
		if node.Exit {
			exits++
			require.Equal(t, "L", node.Tag, "the only exit of either route is the declaring hop")
		}
	}
	require.Equal(t, 2, exits, "one exit per route: %v", describeNodes(nodes))
}
