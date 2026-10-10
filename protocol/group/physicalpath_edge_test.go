package group

import (
	"sort"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Per-EDGE tests for the reachable-leaf dry run's network requirement (P4).
//
// # The defect these pin
//
// The dry run decided a node's network requirement with a WHOLE-TREE question:
//
//	if hasNetworkFilteringGroup(resolver, nodes) { ... }
//
// and, per node, with a question about the node's whole CONTROL PATH rather than its parent edge:
//
//	if hasNetworkFilteringGroup(resolver, []PathNode{hop}) {
//		return nil
//	}
//
// `hasNetworkFilteringGroup` returns true when ANY group on the path filters its members by
// network. So a filtering group that is an ANCESTOR - not the group that actually hands this node
// the flow - exempted every node below it from the requirement. The presence of a filtering group
// ANYWHERE became a pass for the whole subtree.
//
// The responsibility belongs to the EDGE. A node is exempt only when the group that handed it the
// flow is the one that filters, because that is the group whose selection refuses an incapable
// member. A filtering group further up hands the flow to the group in between, and that group's own
// selection is the one that decides - and it does not filter.
//
// # The two directions
//
// Both directions matter and they are not symmetric:
//
//   - MISSING a check (the defect): an ancestor's filter shields a subtree whose own group does not
//     filter, so a network that can reach an incapable exit is never reported.
//   - ADDING a false refusal (the trap): reading the exemption per edge must not start demanding a
//     both-networks capability from members of a group that really does filter. That is a legal
//     configuration - it is why `loadbalance` advertises the union of its members - and refusing it
//     would trade a silent hole for a broken startup.
//
// Only a genuine exit carrying the network makes a route capable. A DEEPER UNDERLAY that carries it
// is a dependency: it carries the transport of the hop that dials through it, so it says nothing
// about what the flow entering the root can be.

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// validate runs the production dry run over this world.
func (w *groupWorld) validate(delivered []string, roots ...adapter.Outbound) physicalpath.Report {
	w.t.Helper()
	report, err := physicalpath.ValidateRoots(w.resolver(), roots, nil, delivered, physicalpath.Declarations{})
	require.NoError(w.t, err)
	return report
}

// failures renders every failure, sorted, so a test asserts on the SET rather than on the order the
// walk happened to produce.
func failures(report physicalpath.Report) []string {
	lines := make([]string, 0, len(report.Failures))
	for _, failure := range report.Failures {
		lines = append(lines, failure.String())
	}
	sort.Strings(lines)
	return lines
}

// failingTags names the objects each failure is about, sorted and de-duplicated.
func failingTags(report physicalpath.Report) []string {
	seen := make(map[string]bool)
	tags := make([]string, 0, len(report.Failures))
	for _, failure := range report.Failures {
		if seen[failure.Leaf] {
			continue
		}
		seen[failure.Leaf] = true
		tags = append(tags, failure.Leaf)
	}
	sort.Strings(tags)
	return tags
}

// bothNetworks is what a routing rule with no explicit `network:` cannot prove, and what an explicit
// pair does prove.
var bothNetworks = []string{N.NetworkTCP, N.NetworkUDP}

// ---------------------------------------------------------------------------
// Case 1: selector -> [udp-only, loadbalance(tcp-only, udp-only)]
// ---------------------------------------------------------------------------

// TestOuterSelectorIsNotShieldedByAnInnerFilteringGroup is the case the defect was reported from.
//
// The outer selector does NOT filter, so it hands a TCP flow to whichever member it chose - and one
// of its members is a UDP-only leaf. The inner balancer filtering by network protects only its OWN
// members. The outer edge must therefore be checked, and for BOTH networks.
func TestOuterSelectorIsNotShieldedByAnInnerFilteringGroup(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).add(
		newEdgeLeaf("udp-only", N.NetworkUDP),
		newEdgeLeaf("tcp-only", N.NetworkTCP),
		newEdgeLeaf("udp-member", N.NetworkUDP),
	)
	balancer := world.newLoadBalance("lb", []string{"tcp-only", "udp-member"})
	selector := world.newSelector("sel", []string{"udp-only", "lb"}, "lb")
	world.start(balancer)
	world.start(selector)

	report := world.validate(bothNetworks, selector)

	require.Equal(t, []string{"udp-only"}, failingTags(report),
		"the outer selector does not filter, so its UDP-only member cannot serve the TCP flow "+
			"delivered here; the inner balancer's filter protects the balancer's own members and "+
			"nothing above them")
	require.Contains(t, failures(report)[0], "does not carry tcp")
}

// ---------------------------------------------------------------------------
// Case 2: loadbalance -> selector(tcp-only, udp-only)  <- the whole-tree pass
// ---------------------------------------------------------------------------

// TestInnerSelectorUnderAFilteringGroupIsStillChecked is the defect in its sharpest form.
//
// The balancer filters, but its only member is another group. That inner selector does NOT filter,
// so it hands a UDP flow to its TCP-only member. The outer filter must not exempt the inner
// selector's members from the check: the edge that decides is the inner one.
func TestInnerSelectorUnderAFilteringGroupIsStillChecked(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).add(
		newEdgeLeaf("tcp-only", N.NetworkTCP),
		newEdgeLeaf("udp-only", N.NetworkUDP),
	)
	inner := world.newSelector("inner", []string{"tcp-only", "udp-only"}, "tcp-only")
	outer := world.newLoadBalance("outer", []string{"inner"})
	world.start(inner)
	world.start(outer)

	report := world.validate(bothNetworks, outer)

	require.Equal(t, []string{"tcp-only", "udp-only"}, failingTags(report),
		"`inner` does not filter, so a UDP flow reaching it is handed to tcp-only and a TCP flow "+
			"is handed to udp-only; the outer balancer's filter is an ANCESTOR and protects neither")
}

// ---------------------------------------------------------------------------
// Case 3: selector -> [tcp-only, udp-only] with NO filtering
// ---------------------------------------------------------------------------

// TestSelectorWithNoFilteringNeverClaimsBothNetworksAreSafe is the plain case: with no group
// filtering anywhere, every member must be able to carry what reaches the root.
func TestSelectorWithNoFilteringNeverClaimsBothNetworksAreSafe(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).add(
		newEdgeLeaf("tcp-only", N.NetworkTCP),
		newEdgeLeaf("udp-only", N.NetworkUDP),
	)
	selector := world.newSelector("sel", []string{"tcp-only", "udp-only"}, "tcp-only")
	world.start(selector)

	report := world.validate(bothNetworks, selector)

	require.Equal(t, []string{"tcp-only", "udp-only"}, failingTags(report),
		"nothing here filters, so neither member is safe for both networks and both must be named")
	for _, failure := range report.Failures {
		require.NotContains(t, failure.Reason, "selects its member by network",
			"no group in this configuration selects its member by network, so claiming one does is "+
				"a false statement about the root")
	}
}

// ---------------------------------------------------------------------------
// Case 4: a mixed loadbalance that GENUINELY filters
// ---------------------------------------------------------------------------

// TestFilteringLoadBalanceIsNotRefusedByABlanketRequirement is the false-refusal trap.
//
// A balancing group that filters by network is exactly the configuration the union advertisement
// exists for: a TCP-only member and a UDP-only member together serve both networks, because the
// group refuses to hand a flow to a member that cannot carry it. Demanding both networks of each
// member would refuse a legal configuration.
func TestFilteringLoadBalanceIsNotRefusedByABlanketRequirement(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).add(
		newEdgeLeaf("tcp-only", N.NetworkTCP),
		newEdgeLeaf("udp-only", N.NetworkUDP),
	)
	balancer := world.newLoadBalance("lb", []string{"tcp-only", "udp-only"})
	world.start(balancer)

	report := world.validate(bothNetworks, balancer)

	require.Empty(t, failures(report),
		"each network is served by a member that can carry it and the group refuses the rest, so "+
			"this configuration is legal and must not be refused")
}

// ---------------------------------------------------------------------------
// Case 6: every branch exit is TCP-only, the only UDP object is a deeper underlay
// ---------------------------------------------------------------------------

// TestAllTCPExitsWithADeeperUDPUnderlayFailsClosed is the underlay trap.
//
// The UDP-capable object is a DEPENDENCY of a TCP-only exit, so it carries the transport of the hop
// that dials through it - not the business flow. Counting it would bless a group no UDP flow can be
// served by, so this must fail closed.
func TestAllTCPExitsWithADeeperUDPUnderlayFailsClosed(t *testing.T) {
	t.Parallel()

	underlay := newEdgeLeaf("udp-underlay", N.NetworkTCP, N.NetworkUDP)
	tcpExit := newEdgeLeaf("tcp-exit", N.NetworkTCP)
	tcpExit.dependsOn = []string{"udp-underlay"}
	world := newGroupWorld(t).add(underlay, tcpExit)

	balancer := world.newLoadBalance("lb", []string{"tcp-exit"})
	world.start(balancer)

	report := world.validate(bothNetworks, balancer)

	require.NotEmpty(t, report.Failures,
		"the only UDP-capable object is a deeper UNDERLAY of a TCP-only exit, so no UDP flow given "+
			"to this group can be served; the group must fail closed rather than pass on the "+
			"underlay's answer")
	require.NotContains(t, failingTags(report), "udp-underlay",
		"the failure is about the group that cannot serve the flow, not about the dependency, "+
			"which is doing nothing wrong")
}

// ---------------------------------------------------------------------------
// Case 8: diamonds, several failures, separate roots, declaration order
// ---------------------------------------------------------------------------

// TestDeclarationOrderDoesNotChangeTheFailureSet is the stability requirement: the same graph
// declared in a different order must produce the same verdict.
func TestDeclarationOrderDoesNotChangeTheFailureSet(t *testing.T) {
	t.Parallel()

	build := func(order int) []string {
		first := newGroupWorld(t).add(
			newEdgeLeaf("tcp-only", N.NetworkTCP),
			newEdgeLeaf("udp-only", N.NetworkUDP),
		)
		selector := first.newSelector("sel", []string{"tcp-only", "udp-only"}, "tcp-only")
		first.start(selector)
		if order == 0 {
			// The declaration order of the members differs; the graph does not.
			second := newGroupWorld(t).add(
				newEdgeLeaf("udp-only", N.NetworkUDP),
				newEdgeLeaf("tcp-only", N.NetworkTCP),
			)
			other := second.newSelector("sel", []string{"udp-only", "tcp-only"}, "udp-only")
			second.start(other)
			return failures(second.validate(bothNetworks, other))
		}
		return failures(first.validate(bothNetworks, selector))
	}

	forward := build(0)
	reversed := build(1)

	require.Len(t, forward, 2)
	require.Len(t, reversed, 2)
	require.Equal(t, forward, reversed,
		"the failure SET must not depend on the order the outbounds happen to be declared in")
}

// TestDiamondRoutesBothReachTheSharedExitAndKeepRootsSeparate covers the diamond, two failures under
// one root, and root separation in one graph.
func TestDiamondRoutesBothReachTheSharedExitAndKeepRootsSeparate(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).add(
		newEdgeLeaf("shared-exit", N.NetworkTCP),
		newEdgeLeaf("udp-exit", N.NetworkUDP),
	)
	left := world.newSelector("left", []string{"shared-exit"}, "shared-exit")
	right := world.newSelector("right", []string{"shared-exit"}, "shared-exit")
	outer := world.newSelector("outer", []string{"left", "right", "udp-exit"}, "left")
	for _, object := range []any{left, right, outer} {
		world.start(object)
	}

	report := world.validate(bothNetworks, outer)

	// The shared exit is reached by TWO routes and fails on both, so it is reported per route; the
	// two routes are distinguishable, which is the whole point of enumerating per route.
	var sharedFailures []physicalpath.Failure
	for _, failure := range report.Failures {
		if failure.Leaf == "shared-exit" {
			sharedFailures = append(sharedFailures, failure)
		}
	}
	require.Len(t, sharedFailures, 2,
		"a node reached by two routes is validated once per route, and both routes reach it through "+
			"a selection that does not filter")
	require.NotEqual(t, sharedFailures[0].Route, sharedFailures[1].Route,
		"the two failures must name the two different routes, or they are one failure reported twice")

	require.Contains(t, failingTags(report), "udp-exit",
		"the second, different defect under the same root must be reported too")

	// Roots stay separate: validating the shared exit on its own is a different question, and the
	// answer must be about the shared exit rather than about the group above it.
	alone := world.validate(bothNetworks, world.manager.byTag["shared-exit"])
	require.NotEmpty(t, alone.Failures, "a TCP-only root cannot carry the UDP flow delivered to it")
	require.Equal(t, []string{"shared-exit"}, failingTags(alone),
		"a root validated on its own reports its own tag")
}
