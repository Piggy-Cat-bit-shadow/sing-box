package physicalpath

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------------------------
// Adversary G, D2: the FALSE-DENY direction of `truncatedRouteFailure`.
//
// The change under attack makes `ValidateRoots` report a failure when a root's enumeration
// produced nodes and NOT ONE of them carries `Exit`. It was developed against the false-ALLOW
// direction (`exit.detour = "ghost"` reported reachable), and the question nobody asked is the
// other one: can a configuration that used to be ACCEPTED now be REFUSED.
//
// Legality is decided by the OBJECT GRAPH, not by this test's opinion:
//
//   - `protocol/group` refuses to BUILD a group with no members at all - `missing tags` in
//     NewSelector (protocol/group/selector.go:152), NewURLTest (protocol/group/urltest.go:93) and
//     NewLoadBalance (protocol/group/loadbalance.go:153) - and only those three types are
//     registered (include/registry.go:91-93). `All()` returns the configured tag slice for all
//     three, and no code path reassigns that slice after construction, so a group that exists has
//     at least one candidate at every moment, including before Start.
//   - a declared dependency that does not resolve is refused by
//     adapter/outbound's start-order lint (`dependency[tag] not found for outbound[tag]`), which
//     runs BEFORE this dry run (adapter/outbound/manager.go:139 then :160).
//
// So a case whose graph contains either of those is NOT a legal configuration, and refusing it is
// not a false denial. The cases are still measured, because the difference between "refused here"
// and "refused by a lint that runs first" is what the change's own justification rests on.
// ---------------------------------------------------------------------------------------------

// advgDualGroup is a group fixture carrying both networks, so a network requirement can never be
// the reason a case is refused and the Exit question stays isolated.
func advgDualGroup(tag string, selected string, members ...string) *testGroup {
	return &testGroup{
		tag:       tag,
		groupType: "test-group",
		members:   members,
		networks:  []string{N.NetworkTCP, N.NetworkUDP},
		selected:  selected,
	}
}

// advgD2Case is one configuration the false-deny question is asked of.
type advgD2Case struct {
	name string
	// legal is the determination above, with the shape it comes from written in `shape`.
	legal bool
	shape string
	// wantAccepted is what the POST-change predicate must answer for a LEGAL case. It is the
	// assertion that decides D2; for illegal cases only the verdict is logged.
	wantAccepted bool
	build        func() (*testRegistry, []adapter.Outbound)
}

func advgD2Cases() []advgD2Case {
	return []advgD2Case{
		{
			name:         "control_complete_two_hop",
			legal:        true,
			shape:        "exit.detour = entry, both resolve",
			wantAccepted: true,
			build: func() (*testRegistry, []adapter.Outbound) {
				entry := dualLeaf("entry")
				exit := dualLeaf("exit", "entry")
				registry := newRegistry(entry, exit)
				return registry, []adapter.Outbound{exit}
			},
		},
		{
			name:         "control_hop_detour_to_group_complete",
			legal:        true,
			shape:        "L.detour = G, G a selector over two dual-network members",
			wantAccepted: true,
			build: func() (*testRegistry, []adapter.Outbound) {
				m1 := dualLeaf("m1")
				m2 := dualLeaf("m2")
				group := advgDualGroup("G", "m1", "m1", "m2")
				leaf := dualLeaf("L", "G")
				registry := newRegistry(m1, m2, group, leaf)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{leaf}
			},
		},
		{
			name:         "control_group_root_over_complete_members",
			legal:        true,
			shape:        "G(selector) -> [m1, m2], both complete",
			wantAccepted: true,
			build: func() (*testRegistry, []adapter.Outbound) {
				m1 := dualLeaf("m1")
				m2 := dualLeaf("m2")
				group := advgDualGroup("G", "m1", "m1", "m2")
				registry := newRegistry(m1, m2, group)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{group}
			},
		},
		{
			name:         "control_diamond",
			legal:        true,
			shape:        "G1 -> [leaf, G2], G2 -> leaf; the same leaf is reached by two routes",
			wantAccepted: true,
			build: func() (*testRegistry, []adapter.Outbound) {
				leaf := dualLeaf("leaf")
				inner := advgDualGroup("G2", "leaf", "leaf")
				outer := advgDualGroup("G1", "leaf", "leaf", "G2")
				registry := newRegistry(leaf, inner, outer)
				inner.lookup = registry.objects
				outer.lookup = registry.objects
				return registry, []adapter.Outbound{outer}
			},
		},
		{
			name:         "task_case1_group_root_all_members_unresolvable",
			legal:        false,
			shape:        "G(selector) -> [ghost1, ghost2]; the group declares members no object provides",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				group := advgDualGroup("G", "", "ghost1", "ghost2")
				registry := newRegistry(group)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{group}
			},
		},
		{
			name:         "task_case1b_hop_detour_to_group_all_members_unresolvable",
			legal:        false,
			shape:        "L.detour = G, G -> [ghost1, ghost2]",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				group := advgDualGroup("G", "", "ghost1", "ghost2")
				leaf := dualLeaf("L", "G")
				registry := newRegistry(group, leaf)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{leaf}
			},
		},
		{
			name:         "task_case2_empty_group_as_root",
			legal:        false,
			shape:        "G(selector) with no members, as the root; refused by NewSelector as `missing tags`",
			wantAccepted: true, // the walk produces NO node, which the change deliberately leaves alone
			build: func() (*testRegistry, []adapter.Outbound) {
				group := advgDualGroup("G", "")
				registry := newRegistry(group)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{group}
			},
		},
		{
			name: "task_case3and4_hop_detour_to_group_with_empty_candidate_list",
			// NOT legal: the group object cannot be built. Measured anyway - this is the exact
			// shape the task names, and it is the ONE non-truncation route to "nodes exist and
			// none is an exit" (see the invariants asserted by the random-graph test below).
			legal:        false,
			shape:        "L.detour = G, G with an empty candidate list (All() empty)",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				group := advgDualGroup("G", "")
				leaf := dualLeaf("L", "G")
				registry := newRegistry(group, leaf)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{leaf}
			},
		},
		{
			name:         "task_case3b_nested_empty_group_under_a_hop",
			legal:        false,
			shape:        "L.detour = G1, G1(selector) -> [G2], G2 with an empty candidate list",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				inner := advgDualGroup("G2", "")
				outer := advgDualGroup("G1", "G2", "G2")
				leaf := dualLeaf("L", "G1")
				registry := newRegistry(inner, outer, leaf)
				inner.lookup = registry.objects
				outer.lookup = registry.objects
				return registry, []adapter.Outbound{leaf}
			},
		},
		{
			name:         "task_case3c_empty_group_as_a_member_of_a_root_group",
			legal:        false,
			shape:        "G1(selector) -> [G2], G2 with an empty candidate list, as the root",
			wantAccepted: true, // no node is produced for the empty member at all
			build: func() (*testRegistry, []adapter.Outbound) {
				inner := advgDualGroup("G2", "")
				outer := advgDualGroup("G1", "G2", "G2")
				registry := newRegistry(inner, outer)
				inner.lookup = registry.objects
				outer.lookup = registry.objects
				return registry, []adapter.Outbound{outer}
			},
		},
		{
			name:         "author_case_declared_detour_does_not_exist",
			legal:        false,
			shape:        "exit.detour = ghost, no such object",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				exit := dualLeaf("exit", "ghost")
				registry := newRegistry(exit)
				return registry, []adapter.Outbound{exit}
			},
		},
		{
			name:         "deep_chain_truncated_at_the_deepest_hop",
			legal:        false,
			shape:        "c.detour = b, b.detour = ghost",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				b := dualLeaf("b", "ghost")
				c := dualLeaf("c", "b")
				registry := newRegistry(b, c)
				return registry, []adapter.Outbound{c}
			},
		},
		{
			name: "multi_route_root_one_member_truncated_one_complete",
			// The root has TWO routes and one of them is complete. This case is measured for the
			// OTHER direction of the same predicate: whether a truncated route can still be
			// reported as reachable when a sibling route carries an exit.
			//
			// RECORDED VERDICT CHANGED, after this table was written and because of what it found.
			// The adversary measured `reachable=true failures=0` here and reported it as a residual
			// false-ALLOW: the declared-dependency check ran AFTER an "if any node has Exit, this
			// route is fine" early return, so m1's exit masked m2's truncated route. The integrator
			// moved that check ahead of the exit question and made it per-node, so the same export
			// that told a caller "proven usable" now reports the truncated route. `wantAccepted` is
			// therefore false, and the row is kept - with its history - rather than deleted, because
			// it is the case that proves the per-node reading is the one in force.
			legal:        false,
			shape:        "L.detour = G, G -> [m1 (complete), m2 (detour = ghost)]",
			wantAccepted: false,
			build: func() (*testRegistry, []adapter.Outbound) {
				m1 := dualLeaf("m1")
				m2 := dualLeaf("m2", "ghost")
				group := advgDualGroup("G", "m1", "m1", "m2")
				leaf := dualLeaf("L", "G")
				registry := newRegistry(m1, m2, group, leaf)
				group.lookup = registry.objects
				return registry, []adapter.Outbound{leaf}
			},
		},
	}
}

// TestAdvGD2VerdictTable is the measurement, not the assertion: every case is run through the
// predicate under test and its verdict is logged in a machine-readable line, so the SAME binary
// run against the pre-change file (`go test -overlay=...`) produces the "before" column of the
// same table. The only assertion is the one that decides D2 - a LEGAL case must be accepted.
func TestAdvGD2VerdictTable(t *testing.T) {
	for _, tc := range advgD2Cases() {
		t.Run(tc.name, func(t *testing.T) {
			registry, roots := tc.build()
			report, err := ValidateRoots(registry.resolver(), roots, nil, nil, Declarations{})
			require.NoError(t, err, "the walk itself must not error; only the verdict may change")
			exits := 0
			exitTags := make([]string, 0, len(report.Nodes))
			for _, node := range report.Nodes {
				if node.Exit {
					exits++
					exitTags = append(exitTags, node.Hop)
				}
			}
			t.Logf("ADVG_D2 case=%s legal=%v shape=%q nodes=%d exits=%d exit_tags=%v reachable=%v failures=%d",
				tc.name, tc.legal, tc.shape, len(report.Nodes), exits, exitTags,
				report.Reachable(), len(report.Failures))
			for _, failure := range report.Failures {
				t.Logf("ADVG_D2_FAILURE case=%s %s", tc.name, failure.String())
			}
			if tc.legal {
				require.True(t, report.Reachable(),
					"LEGAL configuration refused: %s (%s); nodes=%v failures=%v",
					tc.name, tc.shape, describeChecks(report.Nodes), report.Failures)
			}
			require.Equal(t, tc.wantAccepted, report.Reachable(),
				"the recorded post-change verdict for %s changed", tc.name)
		})
	}
}

// TestAdvGD2LegalConfigurationsMustStayAccepted is the decision procedure on its own, without the
// illegal cases: every case marked legal must be accepted. It passes under the pre-change
// predicate (where nothing is ever refused for this reason) and it must pass under the
// post-change one. A failure here IS the D2 finding.
func TestAdvGD2LegalConfigurationsMustStayAccepted(t *testing.T) {
	legal := 0
	for _, tc := range advgD2Cases() {
		if !tc.legal {
			continue
		}
		legal++
		t.Run(tc.name, func(t *testing.T) {
			registry, roots := tc.build()
			report, err := ValidateRoots(registry.resolver(), roots, nil, nil, Declarations{})
			require.NoError(t, err)
			require.True(t, report.Reachable(),
				"a LEGAL configuration was refused: %s (%s); nodes=%v failures=%v",
				tc.name, tc.shape, describeChecks(report.Nodes), report.Failures)
		})
	}
	// The control that keeps this test from being vacuous if the table is ever emptied.
	require.GreaterOrEqual(t, legal, 4, "the legal corpus must not shrink to nothing")
}

// ---------------------------------------------------------------------------------------------
// The invariant behind the false-deny question, over RANDOM graphs that are legal by
// construction: every declared dependency resolves, and every group has at least one member - the
// two conditions a configuration file can actually produce.
//
// `truncatedRouteFailure` fires exactly when a root's enumeration produced nodes and no node
// carries Exit, so the question "can a legal graph be refused" is exactly the question "can a
// legal graph enumerate nodes with no exit". This test asks it exhaustively over the shapes the
// generator can reach, including diamonds, nested groups and hops that dial through groups.
// ---------------------------------------------------------------------------------------------

// advgRandomLegalGraph builds an acyclic object graph in which every reference resolves and every
// group has at least one member. Objects are created in order and may only reference objects that
// already exist, which makes the graph acyclic by construction.
func advgRandomLegalGraph(rng *rand.Rand) []adapter.Outbound {
	leafCount := 2 + rng.Intn(4)
	groupCount := 1 + rng.Intn(3)
	var objects []adapter.Outbound
	tags := make([]string, 0, leafCount+groupCount)
	var groups []*testGroup

	ref := func() string {
		if len(tags) == 0 {
			return ""
		}
		return tags[rng.Intn(len(tags))]
	}
	// A physical hop: no dependency, a dependency on an existing object, or a detour through an
	// existing group.
	for index := 0; index < leafCount; index++ {
		tag := fmt.Sprintf("leaf%d", index)
		var leaf *testLeaf
		switch {
		case len(tags) == 0 || rng.Intn(3) == 0:
			leaf = dualLeaf(tag)
		default:
			leaf = dualLeaf(tag, ref())
		}
		objects = append(objects, leaf)
		tags = append(tags, tag)
	}
	// Groups last, each over one or more existing objects.
	for index := 0; index < groupCount; index++ {
		tag := fmt.Sprintf("group%d", index)
		// The member count is bounded by the number of DISTINCT tags that exist, because a group's
		// members are distinct: asking for more distinct members than there are objects is a
		// fixture that can never be satisfied, and the loop below would never end.
		maxMembers := len(tags)
		if maxMembers > 3 {
			maxMembers = 3
		}
		memberCount := 1 + rng.Intn(maxMembers)
		members := make([]string, 0, memberCount)
		// A bounded retry, so a mistake in the bound above fails the test instead of hanging it.
		for attempts := 0; len(members) < memberCount && attempts < 1000; attempts++ {
			candidate := ref()
			already := false
			for _, member := range members {
				if member == candidate {
					already = true
					break
				}
			}
			if !already {
				members = append(members, candidate)
			}
		}
		group := advgDualGroup(tag, members[0], members...)
		groups = append(groups, group)
		objects = append(objects, group)
		tags = append(tags, tag)
	}
	lookup := make(map[string]adapter.Outbound, len(objects))
	for _, object := range objects {
		lookup[object.Tag()] = object
	}
	for _, group := range groups {
		group.lookup = lookup
	}
	return objects
}

func TestAdvGD2RandomLegalGraphsAlwaysProduceAnExit(t *testing.T) {
	rng := rand.New(rand.NewSource(0x41444732))
	rootsVisited := 0
	for trial := 0; trial < 500; trial++ {
		objects := advgRandomLegalGraph(rng)
		registry := newRegistry(objects...)
		resolver := registry.resolver()
		for _, root := range objects {
			nodes, err := resolver.Hops(root)
			require.NoError(t, err, "trial=%d root=%s: a legal graph must not error", trial, root.Tag())
			if len(nodes) == 0 {
				continue
			}
			rootsVisited++
			hasExit := false
			for _, node := range nodes {
				if node.Exit {
					hasExit = true
					break
				}
			}
			require.True(t, hasExit,
				"trial=%d root=%s: this graph is legal (every dependency resolves, every group has "+
					"at least one member) and the walk produced %d nodes with no exit, so the new "+
					"predicate refuses a configuration the product accepts; nodes=%v",
				trial, root.Tag(), len(nodes), describeNodes(nodes))
		}
	}
	require.Greater(t, rootsVisited, 500, "the generator must actually produce enumerable roots")
	t.Logf("ADVG_D2_RANDOM trials=500 roots_enumerated=%d", rootsVisited)
}
