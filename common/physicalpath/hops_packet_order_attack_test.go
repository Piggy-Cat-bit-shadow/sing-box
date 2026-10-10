package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ADVERSARIAL: does Hops() actually agree with Build about packet order?
// ---------------------------------------------------------------------------
//
// PATH-01's claim is that `Build` and `Hops()`/`Leaves()` "now agree that packet order is
// `Hops[0]` = hop nearest THIS DEVICE, and `Exit` = the routing-selected hop", fixed by reversing
// each route once in `reverseRoute`.
//
// `reverseRoute(start)` is called by `enumerateHops` on a member's sub-range ONLY when that member's
// recursion reported `endedRoute`. The root call is made by `Hops` itself, which DISCARDS the
// returned flag:
//
//	_, err = scope.enumerateHops(root, root.Tag(), nil, nil, networksOf(root), true)   // leaves.go:200
//
// So a route whose LAST hop is the root's own node - which is every route of a one-node physical
// chain, and the last segment of every longer chain - is never reversed. Its `Position` keeps the
// value assigned at append time, which is `len(physicalPath) - 1`, and its `Exit` keeps the zero
// value `false`.
//
// The tests below measure the consequence rather than the mechanism.

// TestHopsNumbersTheLastSegmentInPacketOrder is the direct statement: on a completed route the last
// hop of packet order is the routing-selected hop, and its Position must be its index in packet
// order.
func TestHopsNumbersTheLastSegmentInPacketOrder(t *testing.T) {
	// c.detour = b, b.detour = a. Packet order is a, b, c: `a` is the deepest dependency and is the
	// hop nearest this device; `c` is the routing-selected hop and is the exit.
	a := dualLeaf("a")
	b := dualLeaf("b", "a")
	c := dualLeaf("c", "b")
	registry := newRegistry(a, b, c)

	nodes, err := registry.resolver().Hops(c)
	require.NoError(t, err)
	require.Len(t, nodes, 3, "the route has three hops")

	byTag := make(map[string]PathNode, len(nodes))
	for _, node := range nodes {
		byTag[node.Tag] = node
	}

	// The routing-selected hop is `c`. It is the LAST hop in packet order, so its Position is 2.
	require.Equal(t, 2, byTag["c"].Position,
		"`c` is the hop the routing selected, so it is the far end of packet order and its Position "+
			"must be 2; measured %d. Every node: %v", byTag["c"].Position, describeNodes(nodes))
	require.True(t, byTag["c"].Exit,
		"and it is the route's exit; `Exit` must name the routing-selected hop")

	// `a` is nearest this device, so Position 0.
	require.Equal(t, 0, byTag["a"].Position,
		"`a` is the deepest dependency and the hop nearest this device; measured %d. Every node: %v",
		byTag["a"].Position, describeNodes(nodes))

	// Positions are a permutation of 0..n-1 with no repeats, which is what "renumbered in packet
	// order" means. Two nodes sharing a position means an index into the enumeration is not an index
	// into packet order.
	seen := make(map[int]string, len(nodes))
	for _, node := range nodes {
		if previous, taken := seen[node.Position]; taken {
			t.Fatalf("position %d is held by BOTH %q and %q: Position is not a packet-order index "+
				"for this route. Every node: %v", node.Position, previous, node.Tag, describeNodes(nodes))
		}
		seen[node.Position] = node.Tag
	}

	// `businessEntry` reads `Position == len(PhysicalPath)-1`, so it inherits the same defect: on this
	// route NO node is a business entry, and the dry run therefore has no entry point to check the
	// delivered network against.
	entries := 0
	for _, node := range nodes {
		if businessEntry(node) {
			entries++
		}
	}
	require.Equal(t, 1, entries,
		"exactly one hop of a route is where the business flow arrives. Measured %d on this route, so "+
			"`advertisedNetworks` and `anyNodeCarries` skip EVERY node and the network requirement for "+
			"this root becomes empty. Every node: %v", entries, describeNodes(nodes))
}

// TestHopsAgreesWithBuildOnTheSameTopology is PATH-01's claim stated as a comparison between the two
// APIs, on the topology both are documented to describe identically.
func TestHopsAgreesWithBuildOnTheSameTopology(t *testing.T) {
	entry := dualLeaf("entry")
	exit := dualLeaf("exit", "entry")
	registry := newRegistry(entry, exit)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "exit"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Len(t, path.Hops, 2)

	// Build's answer, which is the one the direction claim was proved about.
	require.Equal(t, "entry", path.Hops[0].DeclaredTag, "Build: nearest this device")
	require.Equal(t, 0, path.Hops[0].Position)
	require.Equal(t, 1, path.Hops[1].Position)
	for index, hop := range path.Hops {
		require.Equal(t, index, hop.Position)
	}

	// Hops()'s answer for the same graph.
	nodes, err := registry.resolver().Hops(exit)
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	byTag := make(map[string]PathNode, 2)
	for _, node := range nodes {
		byTag[node.Tag] = node
	}
	byBuild := make(map[string]int, 2)
	for _, hop := range path.Hops {
		byBuild[hop.DeclaredTag] = hop.Position
	}

	for tag, wantPosition := range byBuild {
		require.Equal(t, wantPosition, byTag[tag].Position,
			"the two APIs describe the same topology, so %q must have the same packet-order index in "+
				"both. Build says %d, Hops says %d. Hops nodes: %v",
			tag, wantPosition, byTag[tag].Position, describeNodes(nodes))
	}
	for tag, hop := range map[string]bool{"entry": false, "exit": true} {
		require.Equal(t, hop, byTag[tag].Exit,
			"%q must be the exit in Hops exactly when Build reports it as the exit", tag)
	}
}

// TestLeavesReportsASingleHopRoute is the consumer-visible half: `Leaves` filters on `Exit`, so a
// route whose Exit flag was never set is invisible to it.
//
// The impact is not cosmetic. `Leaves` is documented as "the list a caller that wants 'what can
// carry this flow' should use", and `Report.Leaves()` filters the same flag.
func TestLeavesReportsASingleHopRoute(t *testing.T) {
	direct := dualLeaf("direct")
	registry := newRegistry(direct)

	leaves, err := registry.resolver().Leaves(direct)
	require.NoError(t, err)
	require.Len(t, leaves, 1,
		"a top-level outbound with no dependency is a route with exactly one hop, and that hop is "+
			"where the flow leaves. Leaves() returned %d entries for it", len(leaves))

	// The same object as a GROUP MEMBER is reported, which is what makes the omission a defect
	// rather than a definition: the same route shape is an exit when it is reached through a group
	// and is not one when it is reached directly.
	group := tcpGroup("group", "direct", "direct")
	registry = newRegistry(direct, group)
	group.lookup = registry.objects
	groupLeaves, err := registry.resolver().Leaves(group)
	require.NoError(t, err)
	require.Len(t, groupLeaves, 1,
		"the same single-hop route reached through a group IS enumerated, so the models disagree "+
			"about the same shape depending on how it is reached")
	require.True(t, groupLeaves[0].Exit)
}

// TestAnEndpointMemberThatIsASingleHopIsAnExit is the same defect reached through the endpoint
// shape, which is a top-level root in production (the manager validates every endpoint as a root).
func TestAnEndpointMemberThatIsASingleHopIsAnExit(t *testing.T) {
	endpoint := &testEndpoint{testLeaf: testLeaf{
		tag: "wg", leafType: "wireguard", networks: []string{N.NetworkTCP, N.NetworkUDP},
	}}
	registry := newRegistry(endpoint)

	roots := []adapter.Outbound{endpoint}
	report, err := ValidateRoots(registry.resolver(), roots, nil, []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)

	// The network requirement path still works, because `businessEntry` answers true for a node with
	// an EMPTY chain - so this is not the network defect. What is affected is `Report.Leaves()`.
	require.Len(t, report.Leaves(), 1,
		"an endpoint root with no dependency is a route with one hop, and Report.Leaves() filters on "+
			"the Exit flag, so it must report it. Nodes: %v", describeChecks(report.Nodes))
}

// describeChecks renders a report's nodes, for a failure message.
func describeChecks(checks []HopCheck) []string {
	described := make([]string, 0, len(checks))
	for _, check := range checks {
		described = append(described, check.Hop+"("+check.Path+" pos="+itoa(check.Position)+" exit="+
			map[bool]string{true: "true", false: "false"}[check.Exit]+")")
	}
	return described
}
