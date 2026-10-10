package physicalpath

import (
	"testing"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// PATH-01's contract, stated as AGREEMENT between the two APIs rather than as a
// property of either one
// ---------------------------------------------------------------------------
//
// `Build` walks the selected route; `Hops`/`Leaves` enumerate every route under a root. For a LINEAR
// topology - no group, so exactly one route - they describe the same hops, and the round's defect was
// that they described them in OPPOSITE orders: `Build.Hops[0]` was the hop nearest this device while
// `Hops()[0]` was the hop the routing selected.
//
// `p1_contract_diagnostic_test.go` PRINTS both answers for a table of topologies; it deliberately
// asserts nothing. This file asserts the agreement, topology by topology, so the two APIs cannot
// silently diverge again - including on the truncated shapes, where the disagreement survived the
// first attempt at the fix and was only visible in the diagnostic output.
//
// The truncated rows are the ones worth reading twice: a route whose dependency does not resolve has
// no far end, so `Exit` must be false for every node of it AND `Build.Exit()` must report no exit.
// But the hops that ARE known are still in a known ORDER - `c` is dialled through `b` whether or not
// `b`'s own dependency exists - so the positions must agree exactly.

// agreementCase is one linear topology, with the answer both APIs must give.
type agreementCase struct {
	name string
	// resolver builds the fixture. Every object is a leaf: a GROUP would make the root's route one of
	// several, and the cross-API comparison below is about ONE route.
	resolver func() *Resolver
	root     string
	// order is the packet order both APIs must report, device nearest first.
	order []string
	// truncated marks a route that stopped at a dependency which does not resolve: no node of it may
	// be an exit.
	truncated bool
}

func linearAgreementCases() []agreementCase {
	return []agreementCase{
		{
			name:     "single hop",
			resolver: func() *Resolver { return newRegistry(dualLeaf("direct")).resolver() },
			root:     "direct",
			order:    []string{"direct"},
		},
		{
			name: "two hops",
			resolver: func() *Resolver {
				return newRegistry(dualLeaf("entry"), dualLeaf("exit", "entry")).resolver()
			},
			root:  "exit",
			order: []string{"entry", "exit"},
		},
		{
			name: "three hops",
			resolver: func() *Resolver {
				return newRegistry(dualLeaf("a"), dualLeaf("b", "a"), dualLeaf("c", "b")).resolver()
			},
			root:  "c",
			order: []string{"a", "b", "c"},
		},
		{
			name: "an endpoint as the dependency of a leaf",
			resolver: func() *Resolver {
				endpoint := &testEndpoint{testLeaf: testLeaf{
					tag: "wg", leafType: "wireguard", networks: []string{N.NetworkTCP, N.NetworkUDP},
				}}
				return newRegistry(endpoint, dualLeaf("leaf", "wg")).resolver()
			},
			root:  "leaf",
			order: []string{"wg", "leaf"},
		},
		{
			name: "the deepest dependency does not resolve",
			resolver: func() *Resolver {
				return newRegistry(dualLeaf("exit", "missing-entry")).resolver()
			},
			root:      "exit",
			order:     []string{"exit"},
			truncated: true,
		},
		{
			name: "a dependency in the middle does not resolve",
			resolver: func() *Resolver {
				return newRegistry(dualLeaf("b", "missing-a"), dualLeaf("c", "b")).resolver()
			},
			root:      "c",
			order:     []string{"b", "c"},
			truncated: true,
		},
	}
}

// TestBuildAndHopsAgreeOnEveryLinearTopology is the detector. For each topology it compares, hop by
// hop: the packet ORDER, the POSITION of each hop, and which hop (if any) is the exit.
func TestBuildAndHopsAgreeOnEveryLinearTopology(t *testing.T) {
	for _, testCase := range linearAgreementCases() {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := testCase.resolver()
			root := mustLookup(t, resolver, testCase.root)

			built, err := Build(resolver, TagOrOutbound{Outbound: root}, Options{Network: N.NetworkTCP})
			require.NoError(t, err)
			nodes, err := resolver.Hops(root)
			require.NoError(t, err)

			builtOrder := make([]string, 0, len(built.Hops))
			builtPosition := make(map[string]int, len(built.Hops))
			for _, hop := range built.Hops {
				builtOrder = append(builtOrder, hop.DeclaredTag)
				builtPosition[hop.DeclaredTag] = hop.Position
			}
			nodeOrder := make([]string, 0, len(nodes))
			nodePosition := make(map[string]int, len(nodes))
			for _, node := range nodes {
				nodeOrder = append(nodeOrder, node.Tag)
				nodePosition[node.Tag] = node.Position
			}

			require.Equal(t, testCase.order, builtOrder,
				"Build must report the fixture's packet order, nearest this device first")
			require.Equal(t, builtOrder, nodeOrder,
				"Hops must report the SAME order as Build for the same topology. Build: %v, Hops: %v",
				builtOrder, describeNodes(nodes))
			for tag, position := range builtPosition {
				require.Equal(t, position, nodePosition[tag],
					"%q: Position must be the same index in both APIs. Build says %d, Hops says %d",
					tag, position, nodePosition[tag])
			}

			// Positions index the chain beside them, in both APIs' terms.
			for _, node := range nodes {
				require.Equal(t, len(node.PhysicalPath)-1, node.Position,
					"%q: Position must index its own chain %v", node.Tag, node.PhysicalPath)
				require.Equal(t, node.Tag, node.PhysicalPath[len(node.PhysicalPath)-1],
					"%q: and that chain must end at the node", node.Tag)
			}

			// The exit, which is the field the two APIs disagreed about first.
			exit, hasExit := built.Exit()
			leaves, err := resolver.Leaves(root)
			require.NoError(t, err)
			if testCase.truncated {
				require.False(t, hasExit,
					"a route with an unresolved dependency never reached its far end, so Build must not "+
						"report an exit: got %q", exit.DeclaredTag)
				require.Empty(t, leaves,
					"and no node of it may claim to be one, or Leaves() would present an unverifiable "+
						"path as usable. Nodes: %v", describeNodes(nodes))
				for _, node := range nodes {
					require.False(t, node.Exit, "%q claimed to be the exit of a truncated route", node.Tag)
				}
				return
			}
			require.True(t, hasExit, "a complete route has an exit")
			require.Len(t, leaves, 1, "and Leaves() reports exactly it. Nodes: %v", describeNodes(nodes))
			require.Equal(t, exit.DeclaredTag, leaves[0].Tag,
				"the two APIs must name the SAME far end for one route")
			require.True(t, leaves[0].Exit)
			require.Equal(t, len(nodes)-1, leaves[0].Position, "which is the last hop in packet order")
			require.Equal(t, testCase.order[len(testCase.order)-1], leaves[0].Tag,
				"and it is the far end of the fixture's packet order")
		})
	}
}
