package physicalpath

import (
	"testing"

	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// P1: one topology, every API, one contract — the DETECTORS
// ---------------------------------------------------------------------------
//
// Every previous round asserted one API at a time, which is how `Build` came to report packet order
// while `Hops` reported descent order for the same graph without anyone noticing. These tests ask all
// the APIs the SAME question about the SAME fixture and fail on any disagreement.
//
// # The three semantic axes, kept apart
//
//	DECLARATION  selected exit -> dependency underlay -> deeper dependency
//	PHYSICAL     device -> deepest underlay -> middle -> selected exit -> target
//	CONTROL      route/root -> outer group -> inner group -> selected member
//
// `Build.Hops`, `Hops()` and `Leaves()` must agree on PHYSICAL. Control never participates in
// physical order. `Exit` is true only for the routing-selected hop of a COMPLETE route, so a route
// truncated by a missing dependency must not promote its truncation point to an exit.

// twoHopRegistry is `exit.detour = entry`, the minimum topology where the two APIs can disagree.
func twoHopRegistry() *testRegistry {
	return newRegistry(tcpLeaf("entry"), tcpLeaf("exit", "entry"))
}

// threeHopRegistry is `c.detour = b`, `b.detour = a`.
func threeHopRegistry() *testRegistry {
	return newRegistry(tcpLeaf("a"), tcpLeaf("b", "a"), tcpLeaf("c", "b"))
}

// TestLeavesNamesTheRoutingSelectedHopOnATwoHopRoute pins the DETECTOR's headline.
//
// A complete two-hop route has exactly one leaf: the hop the routing selected. `c.detour = b`,
// `b.detour = a` makes `c` the selected hop, so `Leaves(c)` must return it.
func TestLeavesNamesTheRoutingSelectedHopOnATwoHopRoute(t *testing.T) {
	registry := twoHopRegistry()
	leaves, err := registry.resolver().Leaves(mustLookup(t, registry.resolver(), "exit"))
	require.NoError(t, err)
	require.Len(t, leaves, 1,
		"a complete route has exactly one leaf, the hop the routing selected. Zero leaves means no "+
			"route is ever reported as able to carry anything, and `Report.Leaves` is empty for every "+
			"configuration. Got %d", len(leaves))
	require.Equal(t, "exit", leaves[0].Tag,
		"and it is the routing-selected hop, which is the FAR end of packet order")
}

// TestHopsAndBuildAgreeOnPacketOrderForOneTopology is the cross-API assertion: the same graph, both APIs,
// the same packet-order index for the same object.
func TestHopsAndBuildAgreeOnPacketOrderForOneTopology(t *testing.T) {
	registry := twoHopRegistry()
	resolver := registry.resolver()
	root := mustLookup(t, resolver, "exit")

	built, err := Build(resolver, TagOrOutbound{Outbound: root}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	nodes, err := resolver.Hops(root)
	require.NoError(t, err)

	buildPosition := make(map[string]int, len(built.Hops))
	for _, hop := range built.Hops {
		buildPosition[hop.DeclaredTag] = hop.Position
	}
	require.NotEmpty(t, buildPosition, "the fixture must produce hops, or this proves nothing")

	for _, node := range nodes {
		expected, present := buildPosition[node.Tag]
		require.True(t, present,
			"Hops reported %q, which Build does not place on this route at all. Nodes: %v",
			node.Tag, nodeRoutes(nodes))
		require.Equal(t, expected, node.Position,
			"the two APIs describe the SAME topology, so %q must have the same packet-order index in "+
				"both. Build says %d, Hops says %d. Hops nodes: %v",
			node.Tag, expected, node.Position, nodeRoutes(nodes))
	}
}

// TestEachNodePositionIndexesItsOwnChain checks the invariant that makes `Position`
// meaningful: a node's position is where it sits in its OWN physical chain.
func TestEachNodePositionIndexesItsOwnChain(t *testing.T) {
	registry := threeHopRegistry()
	nodes, err := registry.resolver().Hops(mustLookup(t, registry.resolver(), "c"))
	require.NoError(t, err)
	require.NotEmpty(t, nodes, "the fixture must produce nodes")

	for _, node := range nodes {
		require.Equal(t, len(node.PhysicalPath)-1, node.Position,
			"%q: Position must be this node's index in its own physical chain %v. A position that "+
				"does not index the chain it describes is worse than no position at all",
			node.Tag, node.PhysicalPath)
	}
}

// TestOneBusinessEntryForEachRoute pins the property the whole requirement calculation rests on.
//
// `advertisedNetworks` and `nodeRequirementFor` both walk the nodes looking for the node where the
// business flow ARRIVES. If a route has none, the requirement is nil and validation is SKIPPED; if a
// route has several, the business network is demanded of a dependency hop.
func TestOneBusinessEntryForEachRoute(t *testing.T) {
	registry := threeHopRegistry()
	nodes, err := registry.resolver().Hops(mustLookup(t, registry.resolver(), "c"))
	require.NoError(t, err)

	entries := make([]string, 0, 1)
	for _, node := range nodes {
		if !node.Exit {
			continue
		}
		entries = append(entries, node.Tag)
	}
	require.Len(t, entries, 1,
		"every route must have EXACTLY ONE node where the flow arrives. Zero means no network "+
			"requirement is ever computed for it and validation is skipped; more than one means a "+
			"dependency hop is demanded the business network. Nodes: %v, entries: %v",
		nodeRoutes(nodes), entries)
	require.Equal(t, "c", entries[0],
		"and it is the routing-selected hop, which is the far end of packet order")
}

// TestATruncatedRouteClaimsNoExit is the missing-dependency rule.
//
// `exit.detour = missing-entry` cannot be a complete route, so nothing in it is an exit. Promoting
// the truncation point would report an unverifiable path as READY.
func TestATruncatedRouteClaimsNoExit(t *testing.T) {
	registry := newRegistry(tcpLeaf("exit", "missing-entry"))
	resolver := registry.resolver()
	root := mustLookup(t, resolver, "exit")

	built, err := Build(resolver, TagOrOutbound{Outbound: root}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.NotEmpty(t, built.Unknowns,
		"the missing dependency must be reported, not silently dropped")

	_, hasExit := built.Exit()
	require.False(t, hasExit,
		"a route with an unresolved dependency is not complete, so it has no exit. Reporting one "+
			"would present an unverifiable path as usable")

	for _, unknown := range built.Unknowns {
		require.GreaterOrEqual(t, unknown.Position, -1,
			"an unknown's position is either a provable slot or -1 for unplaced; a position beyond "+
				"the known hops claims knowledge of a depth this route does not have. Got %d for %q",
			unknown.Position, unknown.Node)
	}

	nodes, err := resolver.Hops(root)
	require.NoError(t, err)
	for _, node := range nodes {
		require.False(t, node.Exit,
			"and no node of a truncated route may claim to be the exit. %q did", node.Tag)
	}
}

// nodeRoutes renders the nodes for a failure message.
func nodeRoutes(nodes []PathNode) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, node.Tag+"@"+itoa(node.Position)+"exit="+boolText(node.Exit))
	}
	return out
}

func boolText(value bool) string {
	if value {
		return "t"
	}
	return "f"
}
