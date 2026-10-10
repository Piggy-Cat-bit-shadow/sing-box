package physicalpath

// PATH-03: a diamond is a legal graph, and each of its routes is its own validation subject.
//
// # The graph these tests build
//
//	outer ── A ── middle ── shared     route A: TCP, and the shared leaf sits at position 1
//	      └─ B ──────────── shared     route B: UDP, and the shared leaf sits at position 0
//
// `shared` is ONE object reached by TWO routes. Everything about it that is not a pure property of
// the object differs between them: which group handed the flow over (so which network it is
// required to carry), which physical chain reaches it (so where in the packet order it sits), and
// whether it is the live route. A de-duplication keyed on the OBJECT collapses the two routes into
// one and silently drops the second route's contract - which is the defect these tests exist for.
//
// # What is NOT route-dependent, and therefore may be cached
//
// `Exit` (the object has no dependency), `Type`, `Resolved` and the object itself are properties of
// the node, identical on every route that reaches it. Nothing here forbids caching those.
//
// # The direction of a physical chain
//
// These tests render a route's physical chain as PathNode.Path() and, in ONE place, compare it as a
// string. That rendering is leaves.go's own contract - the consumer first, its declared dependency
// second - and it is independent of `Path.Hops` packet order in physicalpath.go, which these tests
// deliberately never index.

import (
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// diamondFixture is the graph above. `middle` carries TCP only, and so does `shared`; B carries UDP,
// so route B requires something of `shared` that `shared` cannot do.
type diamondFixture struct {
	outer    *testGroup
	groupA   *testGroup
	groupB   *testGroup
	middle   *testLeaf
	shared   *testLeaf
	registry *testRegistry
}

func newDiamondFixture() *diamondFixture {
	shared := tcpLeaf("shared")
	middle := tcpLeaf("middle", "shared")
	groupA := &testGroup{
		tag: "A", groupType: "test-group", members: []string{"middle"},
		networks: []string{N.NetworkTCP}, selected: "middle",
	}
	groupB := &testGroup{
		tag: "B", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkUDP}, selected: "shared",
	}
	outer := &testGroup{
		tag: "outer", groupType: "test-group", members: []string{"A", "B"},
		networks: []string{N.NetworkTCP, N.NetworkUDP}, selected: "A",
	}
	registry := newRegistry(shared, middle, groupA, groupB, outer)
	for _, group := range []*testGroup{groupA, groupB, outer} {
		group.lookup = registry.objects
	}
	return &diamondFixture{outer: outer, groupA: groupA, groupB: groupB, middle: middle, shared: shared, registry: registry}
}

// TestDiamondValidatesBothRoutesToASharedLeaf is PATH-03's headline: one object reached by two
// routes is two validation subjects, each with its own contract.
//
// The failure it pins is not "a node is missing from a list": it is that route B is UN SERVICEABLE
// and the report cannot say so, because the only node the enumeration produced belongs to route A,
// where the leaf's TCP-only capability is exactly what is required of it.
func TestDiamondValidatesBothRoutesToASharedLeaf(t *testing.T) {
	fixture := newDiamondFixture()

	leaves, err := fixture.registry.resolver().Leaves(fixture.outer)
	require.NoError(t, err)
	require.Len(t, leaves, 2,
		"a leaf reachable by two routes is two validation subjects: the routes require different things of it")

	byRoute := make(map[string]PathNode, len(leaves))
	for _, leaf := range leaves {
		byRoute[leaf.Route()] = leaf
	}
	require.Contains(t, byRoute, "outer -> A -> shared")
	require.Contains(t, byRoute, "outer -> B -> shared",
		"route B is reachable and must be enumerated, not swallowed because route A reached the same object")

	require.Equal(t, []string{N.NetworkTCP}, byRoute["outer -> A -> shared"].RequiredNetworks,
		"route A carries TCP")
	require.Equal(t, []string{N.NetworkUDP}, byRoute["outer -> B -> shared"].RequiredNetworks,
		"route B carries UDP, and therefore requires the shared leaf to carry UDP")
	require.True(t, byRoute["outer -> A -> shared"].IsCurrent,
		"the live route is A, and that is a ROUTE fact, not a node fact")
	require.False(t, byRoute["outer -> B -> shared"].IsCurrent,
		"route B is reachable but is not the route the flow takes right now")

	// Route B's independent validation, expressed as the caller of this enumeration would perform
	// it: every route must be able to serve what its own group advertises.
	unserviceable := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		for _, required := range leaf.RequiredNetworks {
			if !slices.Contains(networksOf(leaf.Outbound), required) {
				unserviceable = append(unserviceable, leaf.Route())
			}
		}
	}
	require.Equal(t, []string{"outer -> B -> shared"}, unserviceable,
		"route B requires UDP of a leaf that carries TCP only; that is route B's defect and route A's "+
			"route must not be the reason it goes unreported")
}

// TestDiamondKeepsPerRoutePhysicalPosition is the second half of the contract: the same node sits at
// a different place on each route, and the enumeration must carry each route's own answer rather
// than whichever route happened to be walked first.
func TestDiamondKeepsPerRoutePhysicalPosition(t *testing.T) {
	fixture := newDiamondFixture()

	nodes, err := fixture.registry.resolver().Hops(fixture.outer)
	require.NoError(t, err)

	type routeContext struct {
		physicalChain string
		position      int
		required      string
	}
	contexts := make(map[string]routeContext, 2)
	for _, node := range nodes {
		if node.Tag != "shared" {
			continue
		}
		contexts[node.Route()] = routeContext{
			physicalChain: node.Path(),
			position:      node.Position,
			required:      strings.Join(node.RequiredNetworks, ","),
		}
	}
	require.Equal(t, map[string]routeContext{
		"outer -> A -> shared": {physicalChain: "middle -> shared", position: 1, required: N.NetworkTCP},
		"outer -> B -> shared": {physicalChain: "shared", position: 0, required: N.NetworkUDP},
	}, contexts,
		"the shared leaf's physical position, chain and requirement are per ROUTE: route A reaches it "+
			"through middle, route B reaches it directly")
}

// TestSharedLeafFailureIsAttributedToItsOwnRoute is the report-layer statement of the same
// property: the failures a caller reads must name the route that carries the defect.
//
// Two routes produce two failures for one object, and the two are distinguishable by more than
// their text: they carry different Routes and different hops. A report layer that de-duplicates by
// the LEAF alone therefore throws away the fact that a second route reaches the object at all -
// which is why de-duplication belongs on identical failure text about the same defect, and nowhere
// else.
func TestSharedLeafFailureIsAttributedToItsOwnRoute(t *testing.T) {
	fixture := newDiamondFixture()

	report, err := ValidateRoots(fixture.registry.resolver(), []adapter.Outbound{fixture.outer}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable())

	type attribution struct {
		route string
		hop   int
	}
	sharedFailures := make([]attribution, 0, 2)
	reasons := make([]string, 0, 2)
	for _, failure := range report.Failures {
		if failure.Leaf != "shared" {
			continue
		}
		sharedFailures = append(sharedFailures, attribution{route: failure.Route, hop: failure.Hop})
		reasons = append(reasons, failure.Reason)
	}
	require.ElementsMatch(t, []attribution{
		{route: "outer -> A -> shared", hop: 1},
		{route: "outer -> B -> shared", hop: 0},
	}, sharedFailures,
		"both routes that reach the leaf must be reported, each with its own hop")
	require.Equal(t, reasons[0], reasons[1],
		"the two failures carry the same defect text and are told apart by their route, not by their wording")

	// The node list itself carries the routes, so a caller can see the routes even when they are
	// usable: the report is not a list of failures only.
	routes := make([]string, 0, len(report.Nodes))
	for _, node := range report.Nodes {
		routes = append(routes, node.Route)
	}
	require.Contains(t, routes, "outer -> A -> shared")
	require.Contains(t, routes, "outer -> B -> shared")
}

// TestADiamondWithACycleIsStillRefused is the guard for the other half of PATH-03: with the global
// de-duplication gone, the recursion stack is the ONLY thing that keeps a malformed graph from
// being followed forever.
//
// It also states what a cycle check MUST be: a cycle is a back edge onto the CURRENT descent. The
// diamond above is a back edge onto a node that a PREVIOUS route already visited and that is not on
// this route's stack, and it must not be reported as a cycle - which is exactly the mistake a
// global "seen" set used as cycle detection makes.
func TestADiamondWithACycleIsStillRefused(t *testing.T) {
	// shared declares a dependency on P, and P is a group whose member is shared again.
	shared := tcpLeaf("shared", "P")
	groupP := &testGroup{
		tag: "P", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkTCP}, selected: "shared",
	}
	groupA := &testGroup{
		tag: "A", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkTCP}, selected: "shared",
	}
	groupB := &testGroup{
		tag: "B", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkTCP}, selected: "shared",
	}
	outer := &testGroup{
		tag: "outer", groupType: "test-group", members: []string{"A", "B"},
		networks: []string{N.NetworkTCP}, selected: "A",
	}
	registry := newRegistry(shared, groupP, groupA, groupB, outer)
	for _, group := range []*testGroup{groupP, groupA, groupB, outer} {
		group.lookup = registry.objects
	}

	_, err := registry.resolver().Hops(outer)
	require.Error(t, err, "a back edge onto the current descent must be refused, not followed")
	require.Contains(t, err.Error(), "cycle")
	require.Contains(t, err.Error(), "shared")
	require.Contains(t, err.Error(), "P")
}

// The combinatorial guard the enumeration needs once it keeps one entry per (node, route) pair is
// in node_budget_test.go, together with the API that configures it.
