package physicalpath

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ADVERSARIAL: `businessEntry` on topologies the existing tests do not build
// ---------------------------------------------------------------------------
//
// `businessEntry` decides ONE thing: "did the business flow ARRIVE at this node", i.e. is this node
// the far end of packet order - the node nothing is dialled THROUGH. It gates
// `nodeRequirementFor`, `advertisedNetworks` and `anyNodeCarries`, so every network verdict in the
// start-time dry run depends on it.
//
// The existing tests cover the shapes the ledger names: a two-hop detour, an endpoint leaf, a group
// chain, and a dependency inside a diamond. The shapes below are the ones the task order names and
// no test builds, and each one is a place the predicate could answer "yes" for a node the flow never
// arrives at (a false PASS) or "no" for the node it does (a false REFUSAL).

// TestBusinessEntryCountsExactlyOneEntryPerRoute pins the predicate as a COUNT rather than as an
// example: on every route of every topology below, exactly one node is the business entry, and it is
// the last hop in packet order.
//
// A predicate that answered true for zero nodes would leave every route unverified while still
// passing a spot check; one that answered true for several would demand the business network of
// dependency hops - the false-rejection class START-01 removed.
func TestBusinessEntryCountsExactlyOneEntryPerRoute(t *testing.T) {
	topologies := []struct {
		name string
		root func() (adapter.Outbound, *testRegistry)
	}{
		{"one-hop leaf", func() (adapter.Outbound, *testRegistry) {
			leaf := dualLeaf("solo")
			return leaf, newRegistry(leaf)
		}},
		{"two-hop detour", func() (adapter.Outbound, *testRegistry) {
			// exit.detour = entry: the device reaches entry's server first.
			entry := dualLeaf("entry")
			exit := dualLeaf("exit", "entry")
			return exit, newRegistry(entry, exit)
		}},
		{"three-hop detour", func() (adapter.Outbound, *testRegistry) {
			a := dualLeaf("a")
			b := dualLeaf("b", "a")
			c := dualLeaf("c", "b")
			return c, newRegistry(a, b, c)
		}},
		{"group member that is ALSO a dependency of another member", func() (adapter.Outbound, *testRegistry) {
			// `shared` is a member of the group AND the dependency of `middle`, which is the other
			// member. Both routes reach it; on one it is an entry, on the other a dependency.
			shared := dualLeaf("shared")
			middle := dualLeaf("middle", "shared")
			group := tcpGroup("group", "middle", "middle", "shared")
			registry := newRegistry(shared, middle, group)
			group.lookup = registry.objects
			return group, registry
		}},
		{"group whose member does not resolve", func() (adapter.Outbound, *testRegistry) {
			present := dualLeaf("present")
			group := tcpGroup("group", "present", "present", "absent")
			registry := newRegistry(present, group)
			group.lookup = registry.objects
			return group, registry
		}},
		{"group with an endpoint member under a detour", func() (adapter.Outbound, *testRegistry) {
			underlay := dualLeaf("underlay")
			endpoint := &testEndpoint{testLeaf: testLeaf{
				tag: "endpoint", leafType: "test", networks: []string{N.NetworkTCP, N.NetworkUDP},
				dependsOn: []string{"underlay"},
			}}
			group := tcpGroup("group", "endpoint", "endpoint")
			registry := newRegistry(underlay, endpoint, group)
			group.lookup = registry.objects
			return group, registry
		}},
	}

	for _, topology := range topologies {
		t.Run(topology.name, func(t *testing.T) {
			root, registry := topology.root()
			nodes, err := registry.resolver().Hops(root)
			require.NoError(t, err)
			require.NotEmpty(t, nodes)

			// Segment the enumeration into routes STRUCTURALLY.
			//
			// A key derived from tags does not work here, and both failures are instructive:
			// `PathNode.Route()` renders the control descent plus the node's own tag, so every node
			// of one route has a different value; `PhysicalPath` is the chain reaching ONE node, so
			// it is a prefix of the route's chain and also differs per node; and the node's own
			// PhysicalPath is built from tags, so no element of it can be relied on to name the
			// route's selected hop.
			//
			// What IS structural: `reverseRoute` numbers each completed route 0..k-1 in packet
			// order, and the routes are emitted consecutively. So a new route starts wherever the
			// position does not continue as previous+1 under the same root.
			var routes [][]PathNode
			for _, node := range nodes {
				if len(routes) == 0 {
					routes = append(routes, []PathNode{node})
					continue
				}
				previous := routes[len(routes)-1]
				last := previous[len(previous)-1]
				if node.Root == last.Root && node.Position == last.Position+1 {
					routes[len(routes)-1] = append(previous, node)
					continue
				}
				routes = append(routes, []PathNode{node})
			}

			describeRoute := func(route []PathNode) string {
				return "root=" + route[0].Root + " size=" + itoa(len(route))
			}

			for _, routeNodes := range routes {
				var entries []PathNode
				for _, node := range routeNodes {
					if businessEntry(node) {
						entries = append(entries, node)
					}
				}
				require.Len(t, entries, 1,
					"every route must have EXACTLY ONE business entry; this one has %d. %s. Nodes: %v. "+
						"A route with none is never verified, and a route with several demands the "+
						"business network of a dependency hop",
					len(entries), describeRoute(routeNodes), describeNodes(routeNodes))

				entry := entries[0]
				require.Equal(t, len(entry.PhysicalPath)-1, entry.Position,
					"the entry is the far end of its own chain: %v", describeNodes(routeNodes))
			}

			// `Exit` is a SEPARATE field from `businessEntry` and must agree with it: leaves.go
			// documents "Exactly one hop per route is the exit". Measured separately because the
			// two are still set by different code paths.
			for _, routeNodes := range routes {
				var exits []PathNode
				for _, node := range routeNodes {
					if node.Exit {
						exits = append(exits, node)
					}
				}
				require.Len(t, exits, 1,
					"every route must have EXACTLY ONE exit, per PathNode.Exit's own contract; this one "+
						"has %d. %s. Nodes: %v. A route with NO exit is invisible to Leaves() and to "+
						"Report.Leaves(), which filter on this flag",
					len(exits), describeRoute(routeNodes), describeNodes(routeNodes))
				require.True(t, businessEntry(exits[0]),
					"the exit and the business entry are the same node on every route: %v",
					describeNodes(routeNodes))
			}
		})
	}
}

// TestAnUnresolvedGroupMemberIsNotABusinessEntry pins the one node shape whose Position and
// PhysicalPath genuinely disagree, which is the case the predicate's doc says it is written for.
//
// An unresolved member is created directly in enumerateHops with
//
//	PhysicalPath: physicalPath        (the chain of the group ABOVE it, length n)
//	Position:     len(physicalPath)   (n, not n-1)
//
// so `len(PhysicalPath)-1 == Position` is FALSE and the node is treated as a dependency. That is the
// right answer - it is not where the flow arrives, it is a reference that names nothing - but it is
// the ordering of those two fields that produces it, so it is pinned here rather than left implicit.
func TestAnUnresolvedGroupMemberIsNotABusinessEntry(t *testing.T) {
	present := dualLeaf("present")
	group := tcpGroup("group", "present", "present", "absent")
	registry := newRegistry(present, group)
	group.lookup = registry.objects

	nodes, err := registry.resolver().Hops(group)
	require.NoError(t, err)

	unresolved := make([]PathNode, 0, 1)
	for _, node := range nodes {
		if node.Tag == "absent" {
			unresolved = append(unresolved, node)
		}
	}
	require.Len(t, unresolved, 1, "the missing member must be reported, not dropped")
	missing := unresolved[0]
	require.False(t, missing.Resolved)
	require.True(t, missing.Exit,
		"the enumeration marks it Exit because nothing below it exists to extend the route")
	require.Equal(t, 0, len(missing.PhysicalPath))
	require.Equal(t, 0, missing.Position,
		"its own chain is empty and its position is the length of the group's chain")
	require.False(t, businessEntry(missing),
		"a member that names nothing is not where the flow arrives, so no network requirement may be "+
			"demanded of it - and it is refused by the existence check instead")

	// The consequence, at the report layer: the unresolved member is a FAILURE, and the resolved one
	// is not, so a network requirement cannot mask it.
	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{group}, nil,
		[]string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable())
	var reasons []string
	for _, failure := range report.Failures {
		if failure.Leaf == "absent" {
			reasons = append(reasons, failure.Reason)
		}
	}
	require.Len(t, reasons, 1, "the missing member is reported exactly once")
	require.Contains(t, reasons[0], "no outbound or endpoint with this tag exists")
}

// TestEveryNodeOfEveryRouteIsReachableAtItsOwnPosition is the independent structural check the
// predicate rests on: `Position` is the node's index into its OWN `PhysicalPath`.
//
// If that ever stopped holding, `businessEntry` would silently answer about the wrong node - and it
// would answer about a node with no network requirement, which is a false PASS rather than a
// visible error.
func TestEveryNodeOfEveryRouteIsReachableAtItsOwnPosition(t *testing.T) {
	shared := dualLeaf("shared")
	middle := dualLeaf("middle", "shared")
	inner := tcpGroup("inner", "middle", "middle", "shared")
	outer := tcpGroup("outer", "inner", "inner")
	registry := newRegistry(shared, middle, inner, outer)
	inner.lookup = registry.objects
	outer.lookup = registry.objects

	paths := 0
	for _, root := range []adapter.Outbound{outer, inner, middle, shared} {
		nodes, err := registry.resolver().Hops(root)
		require.NoError(t, err)
		for _, node := range nodes {
			if len(node.PhysicalPath) == 0 {
				continue
			}
			require.Equal(t, node.Position, len(node.PhysicalPath)-1,
				"node %q on route %q carries Position %d but its own chain has %d elements: %v",
				node.Tag, node.Route(), node.Position, len(node.PhysicalPath), node.PhysicalPath)
			require.Equal(t, node.Tag, node.PhysicalPath[len(node.PhysicalPath)-1],
				"a node's own chain must END at the node")
			paths++
		}
	}
	require.Greater(t, paths, 4, "the fixtures must actually produce nodes, or this proves nothing")
}

// describeNodes renders a route's nodes for a failure message, so a broken count names the nodes
// that produced it rather than only the count.
func describeNodes(nodes []PathNode) []string {
	described := make([]string, 0, len(nodes))
	for _, node := range nodes {
		entry := "dep"
		if businessEntry(node) {
			entry = "ENTRY"
		}
		described = append(described, node.Tag+"("+node.Path()+" pos="+itoa(node.Position)+" "+entry+")")
	}
	return described
}
