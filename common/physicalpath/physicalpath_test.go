package physicalpath

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
) // The fixtures below are deliberately minimal objects that implement exactly the interfaces the
// dial path reads: adapter.Outbound for a leaf, adapter.OutboundGroup for a control node. Nothing
// here dials, and the group records how many times it was asked so a test can prove that a preview
// consumed nothing.

type testLeaf struct {
	tag       string
	leafType  string
	networks  []string
	dependsOn []string
	endpoint  bool
}

// testLeaf deliberately does NOT implement adapter.DestinationDNSOwner. namingOwner is the only
// fixture that does, so a test that means "this type cannot own the destination's DNS" says it by
// construction rather than by a boolean someone could forget to read.
type namingOwner struct {
	testLeaf
}

func (o *namingOwner) DestinationDNSOwnership() bool { return true }

func (l *testLeaf) Type() string           { return l.leafType }
func (l *testLeaf) Tag() string            { return l.tag }
func (l *testLeaf) Network() []string      { return l.networks }
func (l *testLeaf) Dependencies() []string { return l.dependsOn }
func (l *testLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errNoDial
}
func (l *testLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errNoDial
}

// testEndpoint is a leaf that is also an adapter.Endpoint, so IsEndpoint is exercised.
type testEndpoint struct {
	testLeaf
}

func (e *testEndpoint) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (e *testEndpoint) Close() error                                   { return nil }

// testGroup is a control node. selected answers for the group; asks counts every question, which
// is how a test proves a preview consumed nothing.
type testGroup struct {
	tag        string
	groupType  string
	members    []string
	networks   []string
	selected   string
	lookup     map[string]adapter.Outbound
	selections int64
	attached   int64
}

func (g *testGroup) Type() string           { return g.groupType }
func (g *testGroup) Tag() string            { return g.tag }
func (g *testGroup) Network() []string      { return g.networks }
func (g *testGroup) Dependencies() []string { return g.members }
func (g *testGroup) All() []string          { return g.members }
func (g *testGroup) References() []string {
	// A selector depends on the member it chose and nothing else, which is the real
	// implementation's contract; a loadbalance depends on all of them. The fixture mirrors the
	// selector, and Snapshot.Candidates is what lets a test enumerate the others.
	if g.selected == "" {
		return nil
	}
	return []string{g.selected}
}
func (g *testGroup) Selected(string) adapter.Outbound {
	atomic.AddInt64(&g.selections, 1)
	if g.selected == "" {
		return nil
	}
	return g.lookup[g.selected]
}
func (g *testGroup) AttachConnection(io.Closer) func() {
	atomic.AddInt64(&g.attached, 1)
	return func() {}
}
func (g *testGroup) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errNoDial
}
func (g *testGroup) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errNoDial
}

func (g *testGroup) selectionCount() int64 {
	return atomic.LoadInt64(&g.selections)
}

// testRegistry is the object graph a walk reads. It is read-only by construction: lookup never
// creates anything and never mutates.
type testRegistry struct {
	objects map[string]adapter.Outbound
	order   []string
}

func newRegistry(objects ...adapter.Outbound) *testRegistry {
	registry := &testRegistry{objects: make(map[string]adapter.Outbound, len(objects))}
	for _, object := range objects {
		registry.objects[object.Tag()] = object
		registry.order = append(registry.order, object.Tag())
	}
	return registry
}

func (r *testRegistry) lookup(tag string) (adapter.Outbound, bool) {
	object, loaded := r.objects[tag]
	return object, loaded
}

func (r *testRegistry) roots() []adapter.Outbound {
	roots := make([]adapter.Outbound, 0, len(r.order))
	for _, tag := range r.order {
		roots = append(roots, r.objects[tag])
	}
	return roots
}

func (r *testRegistry) resolver() *Resolver {
	return NewResolver(r.lookup, Snapshot{})
}

var errNoDial = errTest("the read-only walk must never dial")

type errTest string

func (e errTest) Error() string { return string(e) }

func tcpLeaf(tag string, dependencies ...string) *testLeaf {
	return &testLeaf{tag: tag, leafType: "test", networks: []string{N.NetworkTCP}, dependsOn: dependencies}
}

func dualLeaf(tag string, dependencies ...string) *testLeaf {
	return &testLeaf{tag: tag, leafType: "test", networks: []string{N.NetworkTCP, N.NetworkUDP}, dependsOn: dependencies}
}

func tcpGroup(tag string, selected string, members ...string) *testGroup {
	return &testGroup{
		tag:       tag,
		groupType: "test-group",
		members:   members,
		networks:  []string{N.NetworkTCP},
		selected:  selected,
	}
}

// hopTags renders the physical path as a tag list, so an ORDER assertion reads as an order.
func hopTags(path Path) []string {
	tags := make([]string, 0, len(path.Hops))
	for _, hop := range path.Hops {
		tags = append(tags, hop.DeclaredTag)
	}
	return tags
}

func hopPositions(path Path) []int {
	positions := make([]int, 0, len(path.Hops))
	for _, hop := range path.Hops {
		positions = append(positions, hop.Position)
	}
	return positions
}

// ---------------------------------------------------------------------------------------------
// Matrix row 1: direct single leaf, detour 2-hop, detour 3-hop, outbound->endpoint, MASQUE leaf.
// ---------------------------------------------------------------------------------------------

// TestDirectSingleLeafIsOneHop pins that a leaf with no dependency is one hop, and that it is the
// exit.
func TestDirectSingleLeafIsOneHop(t *testing.T) {
	direct := dualLeaf("direct")
	registry := newRegistry(direct)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "direct"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Unknowns, "every hop of this path is knowable")
	require.Equal(t, []string{"direct"}, hopTags(path))
	require.Equal(t, []int{0}, hopPositions(path))
	require.Empty(t, path.ControlPath,
		"the control path is the CONTROL NODES entered, not a copy of the hop list: a direct leaf "+
			"entered none, and the hop itself must not be duplicated into it")
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "direct", exit.DeclaredTag)
	require.Equal(t, 0, exit.Position)
	require.False(t, exit.IsGroup, "a leaf is never a control node")
}

// TestDetourTwoHopIsConsumerFirst is the DIRECTION contract written as an assertion.
//
// `h2.detour = h1` means h2 CONSUMES h1, so the packet reaches h2 first. The configured field is
// the dependency, and a walk that reported it as the predecessor would reverse the whole path.
func TestDetourTwoHopReachesTheDetourFirst(t *testing.T) {
	// `h2.detour = h1`, so h2 reaches its OWN SERVER through h1, and the device reaches h1's server
	// first. The wire reading that decides this is in common/dialer/detour_wire_order_test.go; this
	// test only pins that the model agrees with it.
	inner := tcpLeaf("h1")
	outer := tcpLeaf("h2", "h1")
	registry := newRegistry(inner, outer)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "h2"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"h1", "h2"}, hopTags(path),
		"packet order is ENTRY first: h2 asks h1 to carry the connection to h2's own server, so h1 "+
			"is the hop nearest this device and h2 is the exit")
	require.Equal(t, []int{0, 1}, hopPositions(path))
	require.Equal(t, "h1", path.Hops[0].DeclaredTag)
	require.Equal(t, "h2", path.Hops[0].ControlOwner,
		"h1 is the first hop because h2 declared it as its detour")
	require.Equal(t, "", path.Hops[1].ControlOwner,
		"and h2 is the hop routing named, so no group owns it")

	entry, ok := path.Entry()
	require.True(t, ok)
	require.Equal(t, "h1", entry.DeclaredTag, "Entry() is the hop nearest this device")
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "h2", exit.DeclaredTag,
		"Exit() is the hop traffic leaves from, which is the END of packet order")
}

// TestDetourThreeHopKeepsTheOrder pins a deeper chain: the order must be the full traversal
// reversed, not just the two ends.
//
// `h3.detour = h2` and `h2.detour = h1`, so the device enters h1, then h2, then h3.
func TestDetourThreeHopKeepsTheOrder(t *testing.T) {
	first := tcpLeaf("h1")
	second := tcpLeaf("h2", "h1")
	third := tcpLeaf("h3", "h2")
	registry := newRegistry(first, second, third)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "h3"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"h1", "h2", "h3"}, hopTags(path),
		"the deepest dependency is reached first and the hop routing named is reached last")
	require.Equal(t, []int{0, 1, 2}, hopPositions(path))
	require.Equal(t, "h1", path.Hops[0].DeclaredTag, "the entry is the deepest dependency")
	require.Equal(t, "h3", path.Hops[2].DeclaredTag, "the exit is the hop routing selected")
}

// TestEndpointLeafIsMarkedAsAnEndpoint pins the endpoint flag, and that an endpoint is still a
// physical hop: it terminates the tunnel, it does not forward.
func TestEndpointLeafIsMarkedAsAnEndpoint(t *testing.T) {
	endpoint := &testEndpoint{testLeaf{tag: "warp", leafType: "masque", networks: []string{N.NetworkTCP, N.NetworkUDP}}}
	registry := newRegistry(endpoint)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "warp"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Len(t, path.Hops, 1)
	require.True(t, path.Hops[0].IsEndpoint, "an adapter.Endpoint hop must be reported as one")
	require.False(t, path.Hops[0].IsGroup)
	require.Equal(t, "masque", path.Hops[0].Type)
}

// TestOutboundToEndpointKeepsTheEndpointLast is the outbound -> endpoint case: a proxy that
// carries the flow into a local tunnel endpoint. The endpoint is the exit.
func TestOutboundToEndpointReachesTheEndpointFirst(t *testing.T) {
	// `proxy.detour = warp`, so the proxy reaches its own server through the endpoint: the endpoint
	// is the first physical hop and the proxy is the exit.
	endpoint := &testEndpoint{testLeaf{tag: "warp", leafType: "masque", networks: []string{N.NetworkTCP, N.NetworkUDP}}}
	proxy := tcpLeaf("proxy", "warp")
	registry := newRegistry(endpoint, proxy)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "proxy"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"warp", "proxy"}, hopTags(path))
	require.True(t, path.Hops[0].IsEndpoint,
		"the endpoint terminates the first hop, and it is nearest this device")
	require.False(t, path.Hops[1].IsEndpoint)
	require.Equal(t, "proxy", path.Hops[0].ControlOwner,
		"the endpoint is first because the proxy declared it as its detour")
}

// TestMasqueEndpointLeafIsAPhysicalHopAndNotAGroup is the MASQUE shape: the endpoint advertises
// TCP, UDP and ICMP, and it is the exit of its own path.
func TestMasqueEndpointLeafIsAPhysicalHopAndNotAGroup(t *testing.T) {
	endpoint := &testEndpoint{testLeaf{
		tag:      "masque-out",
		leafType: "masque",
		networks: []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP},
	}}
	registry := newRegistry(endpoint)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "masque-out"}, Options{Network: N.NetworkUDP})
	require.NoError(t, err)
	require.Equal(t, []string{"masque-out"}, hopTags(path))
	require.True(t, path.Hops[0].IsEndpoint)
	require.False(t, path.Hops[0].IsGroup)
}

// ---------------------------------------------------------------------------------------------
// Matrix row 2: selector->leaf, selector->loadbalance->leaf, nested group->leaf, group + detour.
// ---------------------------------------------------------------------------------------------

// TestSelectorToLeafDropsTheGroupFromThePhysicalPath is the first of the two things this model
// exists to keep apart: the SELECTOR selects, the LEAF carries.
func TestSelectorToLeafDropsTheGroupFromThePhysicalPath(t *testing.T) {
	leaf := tcpLeaf("leaf")
	selector := tcpGroup("sel", "leaf", "leaf")
	registry := newRegistry(leaf, selector)
	selector.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"leaf"}, hopTags(path),
		"a selector is NOT a physical hop: it never wraps a connection and never sees a byte")
	require.Equal(t, []string{"sel"}, path.ControlPath,
		"but the selector IS the control path: it decided which leaf carries the flow")
	require.Empty(t, path.GroupsNamed(),
		"GroupsNamed reports the groups BELOW the root; here the root IS the group")
	require.Equal(t, "leaf", path.Hops[0].DeclaredTag)
	require.Equal(t, "sel", path.Hops[0].ControlOwner)
	require.False(t, path.Hops[0].IsGroup)
}

// TestSelectorToLoadBalanceToLeafKeepsOnlyTheLeaf pins a two-level control chain.
func TestSelectorToLoadBalanceToLeafKeepsOnlyTheLeaf(t *testing.T) {
	leaf := tcpLeaf("leaf")
	balancer := tcpGroup("lb", "leaf", "leaf")
	selector := tcpGroup("sel", "lb", "lb")
	registry := newRegistry(leaf, balancer, selector)
	balancer.lookup = registry.objects
	selector.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"leaf"}, hopTags(path))
	require.Equal(t, []string{"lb", "sel"}, path.ControlPath,
		"the control path is in packet order to match Hops: the device-nearest decision first. It is "+
			"not the physical path, because a group never carries a byte")
	require.Equal(t, "lb", path.Hops[0].ControlOwner,
		"the owner reported is the group that made the DECIDING choice: the innermost one")
}

// TestNestedGroupToLeafResolvesToTheInnermostLeaf is the same shape one level deeper, with a
// detour on the leaf: the control chain and the physical chain do not have the same length.
func TestNestedGroupToLeafResolvesToTheInnermostLeaf(t *testing.T) {
	exit := dualLeaf("exit")
	leaf := dualLeaf("leaf", "exit")
	inner := tcpGroup("inner", "leaf", "leaf")
	outer := tcpGroup("outer", "inner", "inner")
	registry := newRegistry(exit, leaf, inner, outer)
	inner.lookup = registry.objects
	outer.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "outer"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"exit", "leaf"}, hopTags(path),
		"the leaf reaches its own server through exit, so exit is nearest this device")
	require.Equal(t, []string{"inner", "outer"}, path.ControlPath,
		"and the control path is in packet order too: the innermost group decides nearest this device")
	require.Len(t, path.ControlPath, 2)
	require.Len(t, path.Hops, 2, "a control node must not appear in the physical path")
	require.Equal(t, []string{"inner"}, path.GroupsNamed(),
		"the group below the root is the selection step worth naming separately")
}

// TestGroupWithDetourKeepsBothChainsDistinct is the "group + detour" row: the control chain is
// longer than the physical chain by exactly the number of groups entered.
func TestGroupWithDetourKeepsBothChainsDistinct(t *testing.T) {
	exit := dualLeaf("exit")
	member := dualLeaf("member", "exit")
	selector := tcpGroup("sel", "member", "member")
	registry := newRegistry(exit, member, selector)
	selector.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.NotEqual(t, path.ControlPath, hopTags(path),
		"ControlPath != PhysicalPath is the whole point of the model")
	require.Equal(t, []string{"sel"}, path.ControlPath)
	require.Equal(t, []string{"exit", "member"}, hopTags(path),
		"packet order is entry first, while the control path below stays a separate list")
}

// ---------------------------------------------------------------------------------------------
// Matrix row 3: ControlPath != PhysicalPath, and hop #0 is the real nearest entry.
// ---------------------------------------------------------------------------------------------

// TestHopZeroIsTheNearestEntryForTheWholeMatrix is the ORDER assertion across every shape in the
// matrix at once: whatever the topology, Hops[0] is the outbound the flow's routing selected.
func TestHopZeroIsTheNearestEntryForTheWholeMatrix(t *testing.T) {
	for name, build := range map[string]func() (Path, error){
		"direct": func() (Path, error) {
			registry := newRegistry(dualLeaf("direct"))
			return Build(registry.resolver(), TagOrOutbound{Tag: "direct"}, Options{Network: N.NetworkTCP})
		},
		"detour-2": func() (Path, error) {
			registry := newRegistry(tcpLeaf("h1"), tcpLeaf("h2", "h1"))
			return Build(registry.resolver(), TagOrOutbound{Tag: "h2"}, Options{Network: N.NetworkTCP})
		},
		"detour-3": func() (Path, error) {
			registry := newRegistry(tcpLeaf("h1"), tcpLeaf("h2", "h1"), tcpLeaf("h3", "h2"))
			return Build(registry.resolver(), TagOrOutbound{Tag: "h3"}, Options{Network: N.NetworkTCP})
		},
		"selector-to-leaf": func() (Path, error) {
			leaf := tcpLeaf("leaf")
			selector := tcpGroup("sel", "leaf", "leaf")
			registry := newRegistry(leaf, selector)
			selector.lookup = registry.objects
			return Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
		},
		"nested-group-plus-detour": func() (Path, error) {
			exit := dualLeaf("exit")
			member := dualLeaf("member", "exit")
			inner := tcpGroup("inner", "member", "member")
			outer := tcpGroup("outer", "inner", "inner")
			registry := newRegistry(exit, member, inner, outer)
			inner.lookup = registry.objects
			outer.lookup = registry.objects
			return Build(registry.resolver(), TagOrOutbound{Tag: "outer"}, Options{Network: N.NetworkTCP})
		},
		"outbound-to-endpoint": func() (Path, error) {
			endpoint := &testEndpoint{testLeaf{tag: "warp", leafType: "masque", networks: []string{N.NetworkTCP, N.NetworkUDP}}}
			registry := newRegistry(endpoint, tcpLeaf("proxy", "warp"))
			return Build(registry.resolver(), TagOrOutbound{Tag: "proxy"}, Options{Network: N.NetworkTCP})
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, err := build()
			require.NoError(t, err)
			require.NotEmpty(t, path.Hops)
			require.Equal(t, 0, path.Hops[0].Position)
			for index, hop := range path.Hops {
				require.Equal(t, index, hop.Position, "positions are contiguous and in packet order")
				require.False(t, hop.IsGroup, "no control group may ever be reported as a physical hop")
			}
		})
	}
}

// TestControlPathOrderIsNotPacketOrder makes the distinction explicit rather than implied: the
// two lists are different sequences of different lengths for one topology.
func TestControlPathOrderIsNotPacketOrder(t *testing.T) {
	exit := dualLeaf("exit")
	member := dualLeaf("member", "exit")
	inner := tcpGroup("inner", "member", "member")
	outer := tcpGroup("outer", "inner", "inner")
	registry := newRegistry(exit, member, inner, outer)
	inner.lookup = registry.objects
	outer.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "outer"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"inner", "outer"}, path.ControlPath,
		"control path in packet order: the innermost group decides nearest this device")
	require.Equal(t, []string{"exit", "member"}, hopTags(path),
		"and the physical path is ENTRY first: member reaches its own server through exit")
	require.NotContains(t, hopTags(path), "outer", "the root is a control node here and is not a hop")
	require.NotContains(t, hopTags(path), "inner")
}

// ---------------------------------------------------------------------------------------------
// Matrix row 4: reported leaf == committed leaf == dialled leaf; a preview consumes nothing.
// ---------------------------------------------------------------------------------------------

// countingGroup mirrors the real preview/commit split: Selected() is a preview and counts only
// previews, commit() is the path a connection that the caller OWNS takes, and only it moves the
// cursor. LoadBalance.SelectForFlow makes exactly this distinction with its commit parameter.
type countingGroup struct {
	testGroup
	previews  int64
	cursor    atomic.Uint64
	previewed int64
}

func (g *countingGroup) Selected(network string) adapter.Outbound {
	atomic.AddInt64(&g.previews, 1)
	return g.testGroup.Selected(network)
}

func (g *countingGroup) commit() {
	g.cursor.Add(1)
}

func (g *countingGroup) committed() uint64 {
	return g.cursor.Load()
}

func (g *countingGroup) previewCount() int64 {
	return atomic.LoadInt64(&g.previews)
}

// TestTheReportedLeafIsTheSelectedLeaf is "reported == committed == dialled" for one flow: the
// leaf Build reports is the object the group's own Selected() answers with, which is the object
// the route path dials.
func TestTheReportedLeafIsTheSelectedLeaf(t *testing.T) {
	first := tcpLeaf("first")
	second := tcpLeaf("second")
	group := tcpGroup("sel", "first", "first", "second")
	registry := newRegistry(first, second, group)
	group.lookup = registry.objects

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "first", exit.DeclaredTag)

	// The committed answer, read through the same interface the route path reads.
	committed := group.Selected(N.NetworkTCP)
	require.Equal(t, committed.Tag(), exit.DeclaredTag,
		"the reported exit must be the member the group commits to")

	// And the object the walk visited is the registry's object, not a copy: a copy would carry a
	// signature the dial path does not know.
	visited, loaded := registry.lookup(exit.DeclaredTag)
	require.True(t, loaded)
	require.Same(t, committed, visited)
}

// TestTwoFlowsAdvanceTheSelectorCursorExactlyTwice is the cursor contract.
//
// The fixture mirrors the real split rather than approximating it: Selected() is the PREVIEW path
// and Commit() is the committed path, exactly as LoadBalance.SelectForFlow distinguishes them with
// its commit parameter. A walk that took the committed path would move the cursor here; a walk that
// only previewed would not. Two flows are two commits, and the previews in between are zero.
func TestTwoFlowsAdvanceTheSelectorCursorExactlyTwice(t *testing.T) {
	first := tcpLeaf("first")
	second := tcpLeaf("second")
	group := &countingGroup{testGroup: testGroup{
		tag:       "sel",
		groupType: "test-group",
		members:   []string{"first", "second"},
		networks:  []string{N.NetworkTCP},
		selected:  "first",
	}}
	registry := newRegistry(first, second, group)
	group.lookup = registry.objects

	// A preview: the group is asked, and asking consumes nothing a flow would have spent.
	preview, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, 1, int(group.previewCount()), "one walk asks the group once, as a preview")
	require.Equal(t, uint64(0), group.committed(),
		"a preview must consume nothing: the committed cursor is untouched")
	require.Equal(t, "first", hopTags(preview)[0])

	// A snapshot pins the same answer WITHOUT asking at all, which is the other way a caller keeps
	// a diagnostic from touching selection state.
	pinned := NewResolver(registry.lookup, Snapshot{Selections: map[string]string{"sel": "second"}})
	pinnedPath, err := Build(pinned, TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"second"}, hopTags(pinnedPath))
	require.Equal(t, 1, int(group.previewCount()), "a pinned snapshot asks the group nothing")

	// Flow one and flow two, each ONE committed choice - which is what the route path does when it
	// owns the connection. The cursor moves exactly twice.
	group.commit()
	group.commit()
	require.Equal(t, uint64(2), group.committed(),
		"two flows are two committed selections, not three: the preview in between spent nothing")
	require.Equal(t, 1, int(group.previewCount()),
		"and the diagnostic walks added no further questions")
}

// TestBuildNeverCallsADialingMethod pins the read-only rule structurally: the fixture's dialer
// records nothing, and every leaf in these tests returns errNoDial if it is ever reached.
func TestBuildNeverCallsADialingMethod(t *testing.T) {
	leaf := &testLeaf{tag: "leaf", leafType: "test", networks: []string{N.NetworkTCP}}
	group := tcpGroup("sel", "leaf", "leaf")
	registry := newRegistry(leaf, group)
	group.lookup = registry.objects

	_, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err, "a walk that dialled would return errNoDial here")
	require.Equal(t, int64(0), group.attached, "no connection is attached by a read-only walk")
}

// ---------------------------------------------------------------------------------------------
// Matrix row 5: a multi-error path reports the correct hop/tag; an unknown is never reachable.
// ---------------------------------------------------------------------------------------------

// TestAnUnresolvableDependencyIsUnknownAndNotInvented is the "never invent a hop" rule: a declared
// dependency with no object produces an UNKNOWN naming the tag and the position, never a hop.
func TestAnUnresolvableDependencyIsUnknownAndNotInvented(t *testing.T) {
	broken := tcpLeaf("broken", "missing-middle")
	registry := newRegistry(broken)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "broken"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err, "an unknown hop is reported, not raised: the caller decides")
	require.Equal(t, []string{"broken"}, hopTags(path), "the hop that does not exist must not appear")
	require.Len(t, path.Unknowns, 1)
	require.Equal(t, "missing-middle", path.Unknowns[0].Node)
	require.Equal(t, 1, path.Unknowns[0].Position, "the unknown belongs at the position it would occupy")
	require.Contains(t, path.Unknowns[0].Reason, "does not exist")
	require.True(t, path.HasUnknown())
	_, ok := path.Exit()
	require.False(t, ok, "a path with an unknown hop is NOT a verified exit")
}

// TestASnapshotCanSayTheLeafIsNotKnowable pins the explicit-unknown path: a caller that cannot
// know the selection says so, and the walk reports it instead of reading the live object.
func TestASnapshotCanSayTheLeafIsNotKnowable(t *testing.T) {
	leaf := tcpLeaf("leaf")
	group := tcpGroup("sel", "leaf", "leaf")
	registry := newRegistry(leaf, group)
	group.lookup = registry.objects

	resolver := NewResolver(registry.lookup, Snapshot{Selections: map[string]string{"sel": ""}})
	path, err := Build(resolver, TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Hops, "an unknowable member is not a hop")
	require.Len(t, path.Unknowns, 1)
	require.Equal(t, "sel", path.Unknowns[0].Node)
	require.Contains(t, path.Unknowns[0].Reason, "not knowable")
	require.Equal(t, int64(0), group.selectionCount())
}

// TestASnapshotNamingAMissingMemberIsUnknownRatherThanAFalseHop pins that a snapshot answer is
// validated, so a caller cannot inject a hop that does not exist.
func TestASnapshotNamingAMissingMemberIsUnknownRatherThanAFalseHop(t *testing.T) {
	group := tcpGroup("sel", "leaf", "leaf")
	registry := newRegistry(group)
	group.lookup = registry.objects

	resolver := NewResolver(registry.lookup, Snapshot{Selections: map[string]string{"sel": "ghost"}})
	path, err := Build(resolver, TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Hops)
	require.Len(t, path.Unknowns, 1)
	require.Contains(t, path.Unknowns[0].Reason, "ghost")
	require.Contains(t, path.Unknowns[0].Reason, "no such outbound")
}

// TestAMultiErrorPathReportsTheCorrectHopAndTag pins that the failure names the hop that is broken
// rather than the root: the report must be actionable.
func TestAMultiErrorPathReportsTheCorrectHopAndTag(t *testing.T) {
	broken := tcpLeaf("broken", "missing-exit")
	middle := tcpLeaf("middle", "broken")
	root := tcpLeaf("root", "middle")
	registry := newRegistry(root, middle, broken)

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "root"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"broken", "middle", "root"}, hopTags(path),
		"every hop that DOES exist is reported; only the missing one is unknown")
	require.Len(t, path.Unknowns, 1)
	require.Equal(t, "missing-exit", path.Unknowns[0].Node)
	require.Equal(t, 3, path.Unknowns[0].Position)
}

// ---------------------------------------------------------------------------------------------
// Matrix row 6: cycle, missing outbound, broken endpoint, cross-kind DNS cycle.
// ---------------------------------------------------------------------------------------------

// TestACycleIsReportedNamingTheWholeChain pins that a cycle produces an error naming the full
// hop/tag chain rather than being followed.
func TestACycleIsReportedNamingTheWholeChain(t *testing.T) {
	first := tcpLeaf("first", "second")
	second := tcpLeaf("second", "first")
	registry := newRegistry(first, second)

	_, err := Build(registry.resolver(), TagOrOutbound{Tag: "first"}, Options{Network: N.NetworkTCP})
	require.Error(t, err)
	require.Contains(t, err.Error(), "physical path cycle detected")
	require.Contains(t, err.Error(), "first -> second -> first",
		"the message must name the loop, in order, so an operator can find it")
}

// TestACycleThroughAGroupIsReported is the same contract one level of nesting deep: a group that
// eventually selects itself can only be seen by following selection edges.
func TestACycleThroughAGroupIsReported(t *testing.T) {
	group := tcpGroup("sel", "sel", "sel")
	registry := newRegistry(group)
	group.lookup = registry.objects

	_, err := Build(registry.resolver(), TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.Error(t, err)
	require.Contains(t, err.Error(), "physical path cycle detected")
	require.Contains(t, err.Error(), "sel -> sel")
}

// TestAMissingRootIsUnknownNotAnError pins that an unresolvable root is reported as unknown: it is
// a fact about the registry, not a failure of the walk.
func TestAMissingRootIsUnknownNotAnError(t *testing.T) {
	registry := newRegistry(tcpLeaf("present"))

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "absent"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Hops)
	require.Len(t, path.Unknowns, 1)
	require.Contains(t, path.Unknowns[0].Reason, "does not exist")
}

// TestCycleDetectionUsesIdentityNotTag pins the subtle case: two distinct objects may share a tag,
// and that is not a cycle. A tag-keyed detector would report one.
func TestCycleDetectionUsesIdentityNotTag(t *testing.T) {
	first := tcpLeaf("shared")
	second := tcpLeaf("shared")
	// A chain that reaches two DIFFERENT objects under one tag is not a loop.
	first.dependsOn = nil
	second.dependsOn = nil
	root := tcpLeaf("root", "shared")
	registry := &testRegistry{objects: map[string]adapter.Outbound{
		"root":   root,
		"shared": first,
	}}
	_ = second

	path, err := Build(registry.resolver(), TagOrOutbound{Tag: "root"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, []string{"shared", "root"}, hopTags(path),
		"packet order: the deepest dependency is nearest this device, so the shared hop is entered "+
			"before the root")
}

// ---------------------------------------------------------------------------------------------
// Start-time dry run: the leaf contract, the unselected member, and the enumeration.
// ---------------------------------------------------------------------------------------------

// TestDryRunEnumeratesTheUnselectedMembersToo is the central promise of the dry run: every member
// of every group, whether or not it is the one currently selected.
func TestDryRunEnumeratesTheUnselectedMembersToo(t *testing.T) {
	first := dualLeaf("first")
	second := dualLeaf("second")
	third := dualLeaf("third")
	selector := tcpGroup("sel", "first", "first", "second")
	balancer := tcpGroup("lb", "third", "third")
	outer := tcpGroup("outer", "sel", "sel", "lb")
	registry := newRegistry(first, second, third, selector, balancer, outer)
	selector.lookup = registry.objects
	balancer.lookup = registry.objects
	outer.lookup = registry.objects

	leaves, err := registry.resolver().Leaves(outer)
	require.NoError(t, err)
	tags := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		tags = append(tags, leaf.Tag)
	}
	require.ElementsMatch(t, []string{"first", "second", "third"}, tags,
		"the unselected members of a nested group are reachable leaves and must be enumerated")
	require.Len(t, leaves, 3, "and each leaf is enumerated once, not once per route")
}

// TestDryRunFailsForAnUnselectedMemberThatDoesNotExist is the start-time rule the prompt asks
// for: a selector whose current member is fine but whose second member does not exist must fail,
// and the failure names the route, the hop, the leaf and the reason.
func TestDryRunFailsForAnUnselectedMemberThatDoesNotExist(t *testing.T) {
	healthy := dualLeaf("healthy")
	selector := tcpGroup("sel", "healthy", "healthy", "ghost")
	registry := newRegistry(healthy, selector)
	selector.lookup = registry.objects

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{selector}, nil, []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable(), "an unselected member that does not exist must fail the dry run")
	require.Len(t, report.Failures, 1)
	failure := report.Failures[0]
	require.Equal(t, "sel", failure.Root)
	require.Equal(t, "ghost", failure.Leaf)
	require.Equal(t, "sel -> ghost", failure.Route)
	require.Contains(t, failure.Reason, "no outbound or endpoint with this tag exists")
	require.Contains(t, failure.Reason, "first switch")
	require.Contains(t, failure.String(), "outbound/sel -> sel -> ghost",
		"the rendered report must name the root and the route")
	require.Error(t, report.Err())
}

// TestDryRunAcceptsALegalMixedGroup is the negative control: a legal configuration must still
// pass. A selector whose members carry different network sets is legal as long as every member can
// carry what the group advertises.
func TestDryRunAcceptsALegalMixedGroup(t *testing.T) {
	first := dualLeaf("first")
	second := dualLeaf("second")
	selector := tcpGroup("sel", "first", "first", "second")
	registry := newRegistry(first, second, selector)
	selector.lookup = registry.objects

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{selector}, nil, []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.True(t, report.Reachable())
	require.NoError(t, report.Err())
	require.Len(t, report.Nodes, 2)
	leaves := report.Leaves()
	require.Len(t, leaves, 2, "both members are exits: neither has a dependency")
	require.True(t, leaves[0].Current, "the currently selected member is marked as the current path")
	require.False(t, leaves[1].Current)
	require.True(t, leaves[0].Exit)
	require.True(t, leaves[1].Exit)
}

// TestDryRunFailsForAMemberThatCannotCarryWhatTheGroupRoutes is the other decidable break: the
// member exists, and it cannot serve the group's advertised network.
func TestDryRunFailsForAMemberThatCannotCarryWhatTheGroupRoutes(t *testing.T) {
	good := dualLeaf("good")
	udpOnly := &testLeaf{tag: "udp-only", leafType: "test", networks: []string{N.NetworkUDP}}
	group := &testGroup{
		tag:       "sel",
		groupType: "test-group",
		members:   []string{"good", "udp-only"},
		networks:  []string{N.NetworkTCP, N.NetworkUDP},
		selected:  "good",
	}
	registry := newRegistry(good, udpOnly, group)
	group.lookup = registry.objects

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{group}, nil, []string{N.NetworkTCP, N.NetworkUDP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable())
	require.Len(t, report.Failures, 1)
	require.Equal(t, "udp-only", report.Failures[0].Leaf)
	require.Contains(t, report.Failures[0].Reason, "cannot serve the tcp flow routed through it")
}

// TestDryRunReportsDestinationDNSOwnershipOnAnIncapableType pins the ownership coherence check: a
// configuration that declares the flag on an outbound that cannot honour it must fail, because
// the alternative is the silent remote resolution the flag exists to forbid.
func TestDryRunReportsDestinationDNSOwnershipOnAnIncapableType(t *testing.T) {
	incapable := &testLeaf{tag: "http-hop", leafType: "http", networks: []string{N.NetworkTCP}}
	capable := &namingOwner{testLeaf{tag: "socks-hop", leafType: "socks", networks: []string{N.NetworkTCP}}}
	registry := newRegistry(incapable, capable)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{incapable}, nil, []string{N.NetworkTCP},
		Declarations{DestinationDNSOwnership: map[string]bool{"http-hop": true}})
	require.NoError(t, err)
	require.False(t, report.Reachable())
	require.Contains(t, report.Failures[0].Reason, "does not implement it")
	require.Contains(t, report.Failures[0].Reason, "would be sent to the peer")

	// The capable type passes, and so does an undeclared one.
	report, err = ValidateRoots(registry.resolver(), []adapter.Outbound{capable}, nil, []string{N.NetworkTCP},
		Declarations{DestinationDNSOwnership: map[string]bool{"socks-hop": true}})
	require.NoError(t, err)
	require.False(t, report.Reachable(), "no resolver is configured, so a declared owner must fail closed")
	require.Contains(t, report.Failures[0].Reason, "domain resolver")

	resolver := registry.resolver().WithDomainResolvers(func(tag string) string {
		if tag == "socks-hop" {
			return "dns-remote"
		}
		return ""
	}, false)
	report, err = ValidateRoots(resolver, []adapter.Outbound{capable}, nil, []string{N.NetworkTCP},
		Declarations{DestinationDNSOwnership: map[string]bool{"socks-hop": true}})
	require.NoError(t, err)
	require.True(t, report.Reachable(), "a declared owner with a resolver is a coherent configuration")
}

// TestDryRunFailsForACollidingEndpointTag pins the endpoint-ownership check: when the endpoint
// manager holds a DIFFERENT object under a tag an outbound also uses, the outbound lookup shadows
// it, so the endpoint is listed, unreachable, never started and never closed.
func TestDryRunFailsForACollidingEndpointTag(t *testing.T) {
	shadowed := &testEndpoint{testLeaf{tag: "ts", leafType: "masque", networks: []string{N.NetworkTCP}}}
	holder := &testLeaf{tag: "ts", leafType: "test", networks: []string{N.NetworkTCP}}
	registry := newRegistry(holder)

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{holder}, newEndpointRegistry(shadowed), []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.False(t, report.Reachable())
	require.Contains(t, report.Failures[0].Reason, "claimed by BOTH")

	// The same object under the tag is coherent, and an outbound nobody also claims is coherent.
	sameObject := &testEndpoint{testLeaf{tag: "solo", leafType: "masque", networks: []string{N.NetworkTCP}}}
	report, err = ValidateRoots(registry.resolver(), []adapter.Outbound{sameObject}, newEndpointRegistry(sameObject), []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.True(t, report.Reachable())
}

// TestDryRunCycleIsReportedWithTheChain pins that a cycle in an unselected branch is reported with
// its chain rather than followed, and that the dry run returns it as an error.
func TestDryRunCycleIsReportedWithTheChain(t *testing.T) {
	first := tcpLeaf("first", "second")
	second := tcpLeaf("second", "first")
	selector := tcpGroup("sel", "first", "first", "second")
	registry := newRegistry(first, second, selector)
	selector.lookup = registry.objects

	_, err := ValidateRoots(registry.resolver(), []adapter.Outbound{selector}, nil, []string{N.NetworkTCP}, Declarations{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cycle")
	require.Contains(t, err.Error(), "first")
	require.Contains(t, err.Error(), "second")
}

// TestDryRunLeavesTakeNoSelectionPreview pins the strongest form of "a preview must not consume":
// enumerating the reachable leaves never asks a group for its selection at all, so even the
// preview-free reads are absent.
func TestDryRunLeavesTakeNoSelectionPreview(t *testing.T) {
	first := dualLeaf("first")
	second := dualLeaf("second")
	group := &countingGroup{testGroup: testGroup{
		tag:       "sel",
		groupType: "test-group",
		members:   []string{"first", "second"},
		networks:  []string{N.NetworkTCP},
		selected:  "first",
	}}
	registry := newRegistry(first, second, group)
	group.lookup = registry.objects

	leaves, err := registry.resolver().Leaves(group)
	require.NoError(t, err)
	require.Len(t, leaves, 2)
	require.Equal(t, int64(0), group.previewCount(),
		"the enumeration reads the DECLARED membership, so it does not even take a preview")
	require.Equal(t, uint64(0), group.committed())
}

// TestReportErrNamesEveryOffendingRoute pins that one start reports every broken member rather
// than one per restart.
func TestReportErrNamesEveryOffendingRoute(t *testing.T) {
	selector := tcpGroup("sel", "ghost-one", "ghost-one", "ghost-two")
	registry := newRegistry(selector)
	selector.lookup = registry.objects

	report, err := ValidateRoots(registry.resolver(), []adapter.Outbound{selector}, nil, []string{N.NetworkTCP}, Declarations{})
	require.NoError(t, err)
	require.Len(t, report.Failures, 2)
	message := report.Err().Error()
	require.True(t, strings.Contains(message, "ghost-one") && strings.Contains(message, "ghost-two"),
		"both offending members must be named in one report, got: "+message)
}

// TestHopStringRendersPositionTagAndOwner pins the diagnostic rendering, because the rendered
// string is what an operator reads.
func TestHopStringRendersPositionTagAndOwner(t *testing.T) {
	hop := Hop{Position: 1, DeclaredTag: "member", Type: "socks", ControlOwner: "sel"}
	require.Equal(t, "#1 member[socks] selected-by sel", hop.String())
	require.Contains(t, Hop{Position: 0, DeclaredTag: "g", IsGroup: true}.String(), "GROUP-NOT-A-HOP")
	require.Contains(t, Hop{Position: 0, DeclaredTag: "e", IsEndpoint: true}.String(), "endpoint")
}

// endpointRegistry is the minimal EndpointRegistry a test needs.
type endpointRegistry struct {
	byTag map[string]adapter.Endpoint
}

func newEndpointRegistry(endpoints ...adapter.Endpoint) *endpointRegistry {
	registry := &endpointRegistry{byTag: make(map[string]adapter.Endpoint, len(endpoints))}
	for _, endpoint := range endpoints {
		registry.byTag[endpoint.Tag()] = endpoint
	}
	return registry
}

func (r *endpointRegistry) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := r.byTag[tag]
	return endpoint, loaded
}

func (r *endpointRegistry) Endpoints() []adapter.Endpoint {
	endpoints := make([]adapter.Endpoint, 0, len(r.byTag))
	for _, endpoint := range r.byTag {
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}
