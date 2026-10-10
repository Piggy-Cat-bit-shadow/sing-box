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
// A node's chain is the PACKET-ORDER PREFIX that ENDS at it: the hop nearest this device first, the
// node itself last, and nothing beyond it. So a dependency's chain stops at the dependency (the
// entry's chain is the only one that reaches the end of the route), and `Position` - the node's
// packet-order index - is always the last index of the chain beside it. That is the rendering
// leaves.go documents on PathNode.PhysicalPath, and it is independent of `Path.Hops` packet order in
// physicalpath.go, which these tests deliberately never index.
//
// It is NOT the route's whole chain on every node: a chain that continued past the node would make
// "my chain does not continue past me" true for every node of a route at once, which is a predicate
// that cannot name the hop the flow arrives at.

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
		"one leaf PER ROUTE: the routes reach different hops and require different things of them")

	byRoute := make(map[string]PathNode, len(leaves))
	for _, leaf := range leaves {
		byRoute[leaf.Route()] = leaf
	}

	// Route A's leaf is `middle`, because `middle` is the hop A selected - `shared` is its dependency
	// and carries A's own transport, not the business flow. Route B's leaf is `shared` itself.
	require.Contains(t, byRoute, "outer -> A -> middle",
		"route A's leaf is the hop A selected")
	require.Contains(t, byRoute, "outer -> B -> shared",
		"route B reaches the shared object directly and must be enumerated, not swallowed because "+
			"route A reached the same object further down its chain")

	require.Equal(t, []string{N.NetworkTCP}, byRoute["outer -> A -> middle"].RequiredNetworks,
		"route A carries TCP, and a tcp-only hop satisfies it")
	require.Equal(t, []string{N.NetworkUDP}, byRoute["outer -> B -> shared"].RequiredNetworks,
		"route B carries UDP, and therefore requires the shared leaf to carry UDP")
	require.True(t, byRoute["outer -> A -> middle"].IsCurrent,
		"the live route is A, and that is a ROUTE fact, not a node fact")
	require.False(t, byRoute["outer -> B -> shared"].IsCurrent,
		"route B is reachable but is not the route the flow takes right now")

	// `shared` is still enumerated, as route A's DEPENDENCY, and it is not an exit on that route: the
	// traffic does not leave from it, it is dialled THROUGH by `middle`.
	hops, err := fixture.registry.resolver().Hops(fixture.outer)
	require.NoError(t, err)
	var sharedOnRouteA *PathNode
	for index := range hops {
		if hops[index].Tag == "shared" && hops[index].Route() == "outer -> A -> shared" {
			sharedOnRouteA = &hops[index]
		}
	}
	require.NotNil(t, sharedOnRouteA, "the dependency hop must still be enumerated with its own chain")
	require.False(t, sharedOnRouteA.Exit,
		"a dependency is not an exit: the flow is dialled THROUGH it, so nothing leaves from it")
	require.Equal(t, 0, sharedOnRouteA.Position,
		"and it is nearest this device on that route, which is what a dependency of the entry is")

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
		exit          bool
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
			exit:          node.Exit,
			required:      strings.Join(node.RequiredNetworks, ","),
		}
	}
	require.Equal(t, map[string]routeContext{
		// Packet order: the device reaches `shared` first and `middle` second. A node's chain is the
		// prefix that ENDS at it, so on route A - where `shared` is the hop nearest the device and
		// `middle` is dialled through it - the chain stops at `shared`, `middle` is the exit, and the
		// requirement is route A's own.
		"outer -> A -> shared": {physicalChain: "shared", position: 0, exit: false, required: N.NetworkTCP},
		// Route B reaches the shared object directly, so here it is both the entry and the exit, the
		// chain is the whole of route B, and the requirement is route B's.
		"outer -> B -> shared": {physicalChain: "shared", position: 0, exit: true, required: N.NetworkUDP},
	}, contexts,
		"every route-dependent fact about the shared object is per ROUTE: on route A it is a "+
			"dependency of the entry (neither the exit nor the entry point), on route B it is the entry "+
			"itself, and the two routes require different networks of it")
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

	// # What this test was originally written to prove, and why the premise had to change
	//
	// It asserted that the `shared` leaf fails on BOTH routes, so that the two failures could be
	// told apart by their route. Measurement says otherwise, and the reason is the contract rather
	// than a bug: `shared` under route A is a DEPENDENCY hop (the hop nearest the device, and not
	// the route's far end), and a dependency carries the CONSUMER's own transport rather than the
	// business network, so nothing is required of it that it cannot do. `shared` under route B is
	// where the business UDP flow actually arrives, and it carries TCP only - so THAT is the route
	// that fails.
	//
	// The property the name claims is still real and still worth pinning; it just needs a fixture
	// where two routes genuinely fail. See TestTwoRoutesToOneLeafAreBothReported below.

	sharedFailures := make([]struct {
		route string
		hop   int
	}, 0, 2)
	for _, failure := range report.Failures {
		if failure.Leaf != "shared" {
			continue
		}
		sharedFailures = append(sharedFailures, struct {
			route string
			hop   int
		}{route: failure.Route, hop: failure.Hop})
	}
	require.Equal(t, []struct {
		route string
		hop   int
	}{{route: "outer -> B -> shared", hop: 0}}, sharedFailures,
		"only the route that requires UDP of the shared leaf fails: route A reaches it as a "+
			"dependency, where the leaf carries exactly what is asked of it. A failure reported for "+
			"route A here would mean the dry run was demanding the ROOT's business network of a "+
			"dependency hop - the false-rejection class START-01 exists to remove")

	// The route list is still complete, so a caller can see both routes even though only one of
	// them is broken: the report is not a list of failures only.
	routes := make([]string, 0, len(report.Nodes))
	for _, node := range report.Nodes {
		routes = append(routes, node.Route)
	}
	require.Contains(t, routes, "outer -> A -> shared")
	require.Contains(t, routes, "outer -> B -> shared")
}

// TestTwoRoutesToOneLeafAreBothReported is the property the test above was named for, with a fixture
// where it is actually true.
//
// # The defect this pins
//
// The manager de-duplicated failures by LEAF TAG, so once one route had reported a broken leaf, a
// SECOND route to the same leaf could not report its own failure. The two routes are two chances to
// be wrong and they carry different requirements, so a caller was shown one broken route where there
// were two - and because the manager walks its roots in declaration order, WHICH of the two survived
// depended on the order the outbounds happened to be written in.
//
// The key is therefore (route, leaf, hop). The same triple reached twice is still one line, which is
// what the de-duplication was for.
func TestTwoRoutesToOneLeafAreBothReported(t *testing.T) {
	// One leaf that cannot carry UDP, reached by two DIFFERENT routes that both require UDP of it at
	// the position where the business flow arrives.
	shared := &testLeaf{tag: "shared", leafType: "socks", networks: []string{N.NetworkTCP}}
	groupA := &testGroup{
		tag: "A", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkUDP}, selected: "shared",
	}
	groupB := &testGroup{
		tag: "B", groupType: "test-group", members: []string{"shared"},
		networks: []string{N.NetworkUDP}, selected: "shared",
	}
	outer := &testGroup{
		tag: "outer", groupType: "test-group", members: []string{"A", "B"},
		networks: []string{N.NetworkUDP}, selected: "A",
	}
	registry := newRegistry(shared, groupA, groupB, outer)
	for _, group := range []*testGroup{groupA, groupB, outer} {
		group.lookup = registry.objects
	}

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{outer}, nil,
		[]string{N.NetworkUDP}, Declarations{})
	require.NoError(t, err)

	reasonByRoute := make(map[string]string)
	for _, failure := range report.Failures {
		if failure.Leaf != "shared" {
			continue
		}
		reasonByRoute[failure.Route] = failure.Reason
	}
	require.Len(t, reasonByRoute, 2,
		"both routes to the shared leaf are broken and both must be reported; one line for two "+
			"broken routes is how an operator fixes one and ships the other. Reported routes: %v",
		reasonByRoute)
	require.Contains(t, reasonByRoute, "outer -> A -> shared")
	require.Contains(t, reasonByRoute, "outer -> B -> shared")
	require.Equal(t, reasonByRoute["outer -> A -> shared"], reasonByRoute["outer -> B -> shared"],
		"the two failures carry the SAME defect text and are told apart by their route, so a "+
			"de-duplication key that includes the route is what keeps them separate - keying on the "+
			"reason or the leaf alone would collapse them again")
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
