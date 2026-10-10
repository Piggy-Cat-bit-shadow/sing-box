package route

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// PhysicalPath over REAL groups, asserted through the same resolver the TCP path calls.
//
// # Why the real group types
//
// `group.LoadBalance.CommittedSelections` is the cursor, and the cursor is what a preview must not
// move. A hand-rolled group double would count whatever the test told it to; the real one counts
// what its own selection path did, which is the property under test. These tests therefore build
// `group.NewLoadBalance` and `group.NewSelector` exactly as loadbalance_route_test.go does and reuse
// its fixtures.
//
// # What is being pinned
//
//   - a control group is NOT a physical hop, for a balanced and for a selected flow alike;
//   - the reported exit is the member that was actually DIALED, not a member that was computed;
//   - physicalpath.Hops takes no selection preview at all, so a diagnostic cannot move the cursor;
//   - a preview in the route path consumes nothing, and two committed flows consume exactly two.

// physicalPathFixture builds a two-member balancing group with a selector above it, and returns the
// selector, the balancing group and the members.
func physicalPathFixture(t *testing.T) (adapter.Outbound, *group.LoadBalance, []*routeRecordingOutbound) {
	t.Helper()
	memberA := newRouteRecordingOutbound("A")
	memberB := newRouteRecordingOutbound("B")
	balancer, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{}, memberA, memberB)
	loadBalance, isLoadBalance := balancer.(*group.LoadBalance)
	require.True(t, isLoadBalance)

	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: map[string]adapter.Outbound{
		"A": memberA, "B": memberB, "lb": balancer,
	}}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	createdSelector, err := group.NewSelector(ctx, nil, log.NewNOPFactory().NewLogger("selector"), "sel", option.SelectorOutboundOptions{
		Outbounds: []string{"lb"},
		Default:   "lb",
	})
	require.NoError(t, err)
	selector, isSelector := createdSelector.(*group.Selector)
	require.True(t, isSelector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))
	return selector, loadBalance, []*routeRecordingOutbound{memberA, memberB}
}

// pathResolver adapts the fixture's member manager to the read-only view physicalpath needs.
//
// Every object the walk can reach must be in here, groups included: a lookup that reports "found"
// while holding nothing would make the walk describe an object it cannot see.
func pathResolver(selector adapter.Outbound, balancer adapter.Outbound, members []*routeRecordingOutbound) *physicalpath.Resolver {
	byTag := map[string]adapter.Outbound{"sel": selector}
	if balancer != nil {
		byTag["lb"] = balancer
	}
	for _, member := range members {
		byTag[member.Tag()] = member
	}
	return physicalpath.NewResolver(func(tag string) (adapter.Outbound, bool) {
		object, loaded := byTag[tag]
		return object, loaded
	}, physicalpath.Snapshot{})
}

// TestControlGroupIsNotAPhysicalHopThroughRealGroups asserts the model against the real group
// types: the selector and the balancing group appear on the control path, and neither appears in
// the packet order.
func TestControlGroupIsNotAPhysicalHopThroughRealGroups(t *testing.T) {
	selector, balancer, members := physicalPathFixture(t)

	path, err := physicalpath.Build(pathResolver(selector, balancer, members), physicalpath.TagOrOutbound{Tag: "sel"},
		physicalpath.Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Len(t, path.Hops, 1, "a selector over a loadbalance over a leaf is ONE physical hop")
	require.Equal(t, []string{"lb", "sel"}, path.ControlPath,
		"and TWO control nodes, which is why the two lists must never be reported as one")
	require.NotContains(t, []string{path.Hops[0].DeclaredTag}, "sel")
	require.NotContains(t, []string{path.Hops[0].DeclaredTag}, "lb")
	require.Equal(t, "lb", path.Hops[0].ControlOwner,
		"the owner is the group that made the deciding choice")
	require.Equal(t, 0, path.Hops[0].Position,
		"hop #0 is nearest to this device")
}

// TestTheReportedExitIsTheDialedMemberThroughRealGroups is "reported == committed == dialled" for
// one flow, on the real objects.
func TestTheReportedExitIsTheDialedMemberThroughRealGroups(t *testing.T) {
	selector, balancer, members := physicalPathFixture(t)

	path, err := physicalpath.Build(pathResolver(selector, balancer, members), physicalPathFixtureRoot(),
		physicalpath.Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	exit, ok := path.Exit()
	require.True(t, ok)

	// The same resolution and dial the route path performs, with the commit the connection owns.
	dialedTag, chain := dialThroughRoute(t, selector, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.Equal(t, 1, members[0].dialCount()+members[1].dialCount(), "one flow, one dial")
	require.Equal(t, dialedTag, exit.DeclaredTag,
		"the reported exit must be the member that was actually dialled")
	require.Equal(t, dialedTag, chain[len(chain)-1].Tag(),
		"and the leaf the route path resolved, which is what it dials")
}

// TestPhysicalPathTakesNoSelectionPreviewThroughRealGroups is the strongest cursor statement: the
// diagnostic walk does not move the real balancing group's cursor, and it does not even ask the
// route path's resolver a question.
func TestPhysicalPathTakesNoSelectionPreviewThroughRealGroups(t *testing.T) {
	selector, balancer, members := physicalPathFixture(t)

	before := balancer.CommittedSelections()
	path, err := physicalpath.Build(pathResolver(selector, balancer, members), physicalPathFixtureRoot(),
		physicalpath.Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Equal(t, before, balancer.CommittedSelections(),
		"a diagnostic must not move the cursor: a preview that spent a slot would hand the next flow "+
			"a different member than the one just reported")
	require.Equal(t, "A", path.Hops[0].DeclaredTag,
		"and the first committed choice is still the first member")
}

// TestTwoFlowsAdvanceTheCursorExactlyTwiceWithAPreviewInBetween is the cursor arithmetic of the
// prompt, on real groups: a preview consumes nothing, and two flows that own their connections
// consume exactly two - not three.
func TestTwoFlowsAdvanceTheCursorExactlyTwiceWithAPreviewInBetween(t *testing.T) {
	selector, balancer, members := physicalPathFixture(t)
	require.Equal(t, uint64(0), balancer.CommittedSelections())

	// 1. A preview, exactly as the pre-match path performs it.
	previewTag, previewChain := dialThroughRoute(t, selector, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, false)
	require.Len(t, previewChain, 3)
	require.Equal(t, uint64(0), balancer.CommittedSelections(),
		"a preview whose result is discarded must consume nothing, even though the helper then dials "+
			"the leaf it resolved: what is under test is the GROUP's consumption, and that happens in "+
			"the selection, not in the dial")
	require.Equal(t, "A", previewTag,
		"so the member the preview names is still the member the untouched cursor points at")

	// 2. A diagnostic walk over the same objects, after the preview and before the flows.
	_, err := pathResolver(selector, balancer, members).Hops(selector)
	require.NoError(t, err)
	require.Equal(t, uint64(0), balancer.CommittedSelections(),
		"and the diagnostic must consume nothing either")

	// 3. Two flows that own their connections.
	firstTag, _ := dialThroughRoute(t, selector, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	secondTag, _ := dialThroughRoute(t, selector, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)

	require.Equal(t, uint64(2), balancer.CommittedSelections(),
		"two flows are two committed selections: a preview that consumed would make this three")
	require.Equal(t, previewTag, firstTag,
		"the first committed flow takes the member the preview named, which is only true because "+
			"the preview spent nothing")
	require.NotEqual(t, firstTag, secondTag,
		"and the second flow advances to the next member, which is what two - and only two - "+
			"consumed slots produce")
	require.ElementsMatch(t, []string{firstTag, secondTag}, []string{"A", "B"})
}

// TestPhysicalPathReportsAnUnknownMemberRatherThanInventingOneOnRealGroups pins the honesty rule
// against a real selector: when the caller cannot say which member the group selected, the walk
// reports an unknown rather than reading the live object or guessing a member.
//
// This is the case a control-plane read actually hits - a snapshot that predates a switch, a caller
// that must not touch selection state - and the failure it prevents is a diagnostic that reports a
// leaf no flow is taking.
func TestPhysicalPathReportsAnUnknownMemberRatherThanInventingOneOnRealGroups(t *testing.T) {
	memberA := newRouteRecordingOutbound("A")
	balancer, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{}, memberA)
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: map[string]adapter.Outbound{"A": memberA, "lb": balancer}}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	createdSelector, err := group.NewSelector(ctx, nil, log.NewNOPFactory().NewLogger("selector"), "sel", option.SelectorOutboundOptions{
		Outbounds: []string{"lb"},
		Default:   "lb",
	})
	require.NoError(t, err)
	selector := createdSelector.(*group.Selector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))
	// The selector DOES have a selected member; the snapshot is what says the caller cannot know it.
	require.NotNil(t, selector.Selected(N.NetworkTCP))

	resolver := physicalpath.NewResolver(func(tag string) (adapter.Outbound, bool) {
		switch tag {
		case "sel":
			return selector, true
		case "lb":
			return balancer, true
		case "A":
			return memberA, true
		}
		return nil, false
	}, physicalpath.Snapshot{Selections: map[string]string{"sel": ""}})

	path, err := physicalpath.Build(resolver, physicalPathFixtureRoot(), physicalpath.Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Hops, "a member the caller cannot name must not become a hop")
	require.Len(t, path.Unknowns, 1)
	require.Equal(t, "sel", path.Unknowns[0].Node)
	require.Contains(t, path.Unknowns[0].Reason, "not knowable")
	_, ok := path.Exit()
	require.False(t, ok, "an unknown path is never a verified exit")
	require.Equal(t, []string{"sel"}, path.ControlPath,
		"but the control step that could not be resolved IS reported")
}

// TestPhysicalPathReportsAMemberlessGroupAsUnknownOnRealGroups is the other unknown: the group
// answers, and its answer is "no member".
//
// A balancing group with no candidate for the network answers nil, and a walk that turned that into
// a hop would describe a path the traffic cannot take.
func TestPhysicalPathReportsAMemberlessGroupAsUnknownOnRealGroups(t *testing.T) {
	memberA := newRouteRecordingOutbound("A", N.NetworkTCP)
	// The group routes UDP as well: a UDP selection then has no candidate at all.
	balancer, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{
		Outbounds: []string{"A"},
	}, memberA)
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: map[string]adapter.Outbound{"A": memberA, "lb": balancer}}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	createdSelector, err := group.NewSelector(ctx, nil, log.NewNOPFactory().NewLogger("selector"), "sel", option.SelectorOutboundOptions{
		Outbounds: []string{"lb"},
		Default:   "lb",
	})
	require.NoError(t, err)
	selector := createdSelector.(*group.Selector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))

	resolver := physicalpath.NewResolver(func(tag string) (adapter.Outbound, bool) {
		switch tag {
		case "sel":
			return selector, true
		case "lb":
			return balancer, true
		case "A":
			return memberA, true
		}
		return nil, false
	}, physicalpath.Snapshot{}).WithNetwork(N.NetworkUDP)

	path, err := physicalpath.Build(resolver, physicalPathFixtureRoot(), physicalpath.Options{Network: N.NetworkUDP})
	require.NoError(t, err)
	require.Empty(t, path.Hops, "a group with no member for this network is not a hop")
	require.NotEmpty(t, path.Unknowns)
	require.Equal(t, "lb", path.Unknowns[0].Node,
		"the unknown names the group that could not answer")
	require.Contains(t, path.Unknowns[0].Reason, N.NetworkUDP)
	_, ok := path.Exit()
	require.False(t, ok, "an unknown path is never a verified exit")
}

func physicalPathFixtureRoot() physicalpath.TagOrOutbound {
	return physicalpath.TagOrOutbound{Tag: "sel"}
}

// pathOnlyOutbound is a leaf that exists only to be reached by the diagnostic: it refuses every
// dial, so a test that accidentally dials through it fails loudly instead of quietly succeeding.
type pathOnlyOutbound struct {
	adapter.Outbound
	tag string
}

func (o *pathOnlyOutbound) Type() string      { return "path-only" }
func (o *pathOnlyOutbound) Tag() string       { return o.tag }
func (o *pathOnlyOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *pathOnlyOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errPathOnly
}
func (o *pathOnlyOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errPathOnly
}
func (o *pathOnlyOutbound) AttachConnection(io.Closer) func() { return func() {} }

type pathOnlyError string

func (e pathOnlyError) Error() string { return string(e) }

const errPathOnly = pathOnlyError("this outbound exists only to be described, never to be dialled")
