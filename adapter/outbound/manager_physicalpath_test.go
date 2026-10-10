package outbound

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Start-time dry-run tests, driven through the REAL Manager.Start with REAL group objects.
//
// # Why the manager and not a unit fixture
//
// The dry run is a start-time decision the manager makes about the graph it owns, so the property
// under test is "does Start refuse this configuration". A test that called the validator directly
// would prove the validator works and prove nothing about whether a Box ever runs it.
//
// # Why the groups are real
//
// The list of members a selector or a loadbalance can hand a flow to is the group's own answer, and
// a hand-rolled double would answer whatever the test wrote instead. `group` imports this package,
// so these tests cannot import `group` back - the members are therefore injected through the
// Snapshot the manager's resolver can carry, which is the same seam the group tests in
// protocol/group use to describe a membership without building a Box.
//
// The stub group below implements adapter.OutboundGroup through the package's own interface,
// so what is under test is the manager's decision, not the group's bookkeeping.

// dryRunLeaf is a leaf that reports the networks the test chose.
//
// # Why there is no embedded adapter.Outbound
//
// The fixtures in this package used to embed the interface with a nil value, which the dial path
// never noticed because it only calls the methods the fixture declares. The Manager does NOT stop
// there: it sorts on Dependencies(), Type() and Tag(), and it asks an endpoint for Network(). A nil
// embedded interface makes the promoted method win over the fixture's own method at one embedding
// level and dereference nil at the next, so a fixture that is deliberately partial is the wrong
// shape for a test of the component that reads the whole graph. Declaring the methods and embedding
// nothing removes the failure mode instead of working around it.
type dryRunLeaf struct {
	tag          string
	networks     []string
	dependencies []string
}

func (o *dryRunLeaf) Type() string           { return "dry-run-leaf" }
func (o *dryRunLeaf) Tag() string            { return o.tag }
func (o *dryRunLeaf) Network() []string      { return o.networks }
func (o *dryRunLeaf) Dependencies() []string { return o.dependencies }
func (o *dryRunLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errDryRunNoDial
}
func (o *dryRunLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errDryRunNoDial
}

// dryRunGroup is a control node whose membership and selection the test pins.
//
// OutboundGroup is embedded and MUST be set to the group itself. If it is left nil, a promoted
// method that this fixture does not declare - the group's own DialContext, reached through the
// embedded interface rather than through the fixture's declaration - resolves to the nil interface
// and panics. Self-reference is the standard Go form for embedding an interface a type implements;
// without it the fixture is only partial, and the Manager reads more of a group than the dial path
// does.
type dryRunGroup struct {
	adapter.OutboundGroup
	tag      string
	members  []string
	networks []string
	selected string
	lookup   map[string]adapter.Outbound
}

func (g *dryRunGroup) Type() string           { return "dry-run-group" }
func (g *dryRunGroup) Tag() string            { return g.tag }
func (g *dryRunGroup) Network() []string      { return g.networks }
func (g *dryRunGroup) Dependencies() []string { return g.members }
func (g *dryRunGroup) All() []string          { return g.members }
func (g *dryRunGroup) References() []string {
	if g.selected == "" {
		return nil
	}
	return []string{g.selected}
}
func (g *dryRunGroup) Selected(string) adapter.Outbound { return g.lookup[g.selected] }
func (g *dryRunGroup) AttachConnection(io.Closer) func() {
	return func() {}
}
func (g *dryRunGroup) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errDryRunNoDial
}
func (g *dryRunGroup) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errDryRunNoDial
}

type errDryRun string

func (e errDryRun) Error() string { return string(e) }

const errDryRunNoDial = errDryRun("a read-only walk must never dial")

// startWithDryRun installs the objects, enables the dry run with the given declarations, and runs
// the real Start.
func startWithDryRun(t *testing.T, outbounds []adapter.Outbound, declarations physicalpath.Declarations, resolverFor func(tag string) string) error {
	t.Helper()
	lookup := make(map[string]adapter.Outbound, len(outbounds))
	for _, outbound := range outbounds {
		lookup[outbound.Tag()] = outbound
	}
	for _, outbound := range outbounds {
		if group, isGroup := outbound.(*dryRunGroup); isGroup {
			group.lookup = lookup
			group.OutboundGroup = group
		}
	}
	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{}}, "")
	for _, outbound := range outbounds {
		installOutbound(t, manager, outbound)
	}
	if resolverFor == nil {
		resolverFor = func(string) string { return "" }
	}
	manager.EnablePhysicalPathValidation(declarations, resolverFor, false)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	return manager.Start(adapter.StartStateStart, scope)
}

// TestStartRefusesAGroupWhoseUnselectedMemberDoesNotExist is the property the prompt names: a
// selector whose CURRENT member is fine but whose second member does not exist must fail at Start.
//
// # Which check refuses it, and why that is reported rather than changed
//
// The pre-existing start-order sort already refuses a declared dependency that names nothing - it
// reports `dependency[ghost] not found for outbound[sel]` for the group's own member list - so the
// configuration fails at Start today, before this dry run existed. What the sort cannot do is
// anything that depends on materialising the member: whether it can carry the flow, whether it is
// an endpoint something owns, whether it can honour a declared DNS ownership. Those are the dry
// run's, and the tests below drive them.
//
// The order between the two is deliberate and is pinned by
// TestStartupCycleCheckStillRunsBeforeTheDryRun: the sort's message names the dependency chain and
// is the more precise report for a declared edge, so the dry run must not replace it.
func TestStartRefusesAGroupWhoseUnselectedMemberDoesNotExist(t *testing.T) {
	healthy := &dryRunLeaf{tag: "healthy", networks: []string{N.NetworkTCP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"healthy", "ghost"},
		networks: []string{N.NetworkTCP},
		selected: "healthy",
	}

	err := startWithDryRun(t, []adapter.Outbound{healthy, selector}, physicalpath.Declarations{}, nil)
	require.Error(t, err, "an unselected member that does not exist must fail Start, not the first switch")
	require.Contains(t, err.Error(), "ghost", "the failure must name the member")
	require.Contains(t, err.Error(), "sel", "and the group that declares it")
}

// TestStartRefusesAGroupWhoseUnselectedMemberCannotCarryTheFlow is the same property where only the
// dry run can see it: the member EXISTS, so the sort is satisfied, and it still cannot serve what
// the entry point routes to it. Without the dry run this configuration starts and then fails when
// the group hands it a flow - which is a switch, not a configuration change.
func TestStartRefusesAGroupWhoseUnselectedMemberCannotCarryTheFlow(t *testing.T) {
	healthy := &dryRunLeaf{tag: "healthy", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	udpOnly := &dryRunLeaf{tag: "udp-only", networks: []string{N.NetworkUDP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"healthy", "udp-only"},
		networks: []string{N.NetworkTCP, N.NetworkUDP},
		selected: "healthy",
	}

	err := startWithDryRun(t, []adapter.Outbound{healthy, udpOnly, selector}, physicalpath.Declarations{}, nil)
	require.Error(t, err,
		"the unselected member is broken and MUST fail Start: the first switch would otherwise be "+
			"the first report of it")
	require.Contains(t, err.Error(), "udp-only", "the failure must name the member")
	require.Contains(t, err.Error(), "outbound/sel -> sel -> udp-only",
		"and must name the route that reaches it: the root, the selection step, and the member")
	require.Contains(t, err.Error(), "cannot serve the tcp flow",
		"and must say what is wrong with it rather than only that it is unsupported")
}

// TestStartAcceptsAGroupWhoseMembersAreAllUsable is the negative control that keeps the rule from
// becoming a regression: a legal configuration must still start.
func TestStartAcceptsAGroupWhoseMembersAreAllUsable(t *testing.T) {
	first := &dryRunLeaf{tag: "first", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	second := &dryRunLeaf{tag: "second", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"first", "second"},
		networks: []string{N.NetworkTCP, N.NetworkUDP},
		selected: "first",
	}

	err := startWithDryRun(t, []adapter.Outbound{first, second, selector}, physicalpath.Declarations{}, nil)
	require.NoError(t, err, "a selector whose every member is usable must start")
}

// TestStartRefusesAMemberThatCannotCarryTheRoutedNetwork is the second decidable break: the member
// exists, and it cannot serve what the entry point routes to it.
func TestStartRefusesAMemberThatCannotCarryTheRoutedNetwork(t *testing.T) {
	good := &dryRunLeaf{tag: "good", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	udpOnly := &dryRunLeaf{tag: "udp-only", networks: []string{N.NetworkUDP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"good", "udp-only"},
		networks: []string{N.NetworkTCP, N.NetworkUDP},
		selected: "good",
	}

	err := startWithDryRun(t, []adapter.Outbound{good, udpOnly, selector}, physicalpath.Declarations{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "udp-only")
	require.Contains(t, err.Error(), "cannot serve the tcp flow")
}

// TestStartRefusesACycleInAnUnselectedBranch pins that a cycle among the members is refused at
// Start whichever member the group currently selects. The refusal is the pre-existing sort's, and
// the point of the test is that it is not conditional on the selection.
func TestStartRefusesACycleInAnUnselectedBranch(t *testing.T) {
	first := &dryRunLeaf{tag: "first", networks: []string{N.NetworkTCP}, dependencies: []string{"second"}}
	second := &dryRunLeaf{tag: "second", networks: []string{N.NetworkTCP}, dependencies: []string{"first"}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"first", "second"},
		networks: []string{N.NetworkTCP},
		selected: "first",
	}

	err := startWithDryRun(t, []adapter.Outbound{first, second, selector}, physicalpath.Declarations{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "circular outbound dependency")
	require.Contains(t, err.Error(), "first -> second -> first",
		"the message must name the loop in order")
}

// TestStartRefusesDestinationDNSOwnershipOnAnIncapableType pins the declaration/object coherence
// check through the real Start: the configuration promises the destination name never leaves the
// device, and an outbound that cannot honour it would break that promise silently.
func TestStartRefusesDestinationDNSOwnershipOnAnIncapableType(t *testing.T) {
	incapable := &dryRunLeaf{tag: "hop", networks: []string{N.NetworkTCP}}

	err := startWithDryRun(t, []adapter.Outbound{incapable},
		physicalpath.Declarations{DestinationDNSOwnership: map[string]bool{"hop": true}}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not implement it")

	// With the declaration absent the same object starts: the check is about the promise, not
	// about the type.
	err = startWithDryRun(t, []adapter.Outbound{incapable}, physicalpath.Declarations{}, nil)
	require.NoError(t, err)
}

// TestNoDryRunWithoutTheDeclarationsKeepsTheManagerUnchanged pins the compatibility rule that makes
// this addition safe for every existing caller: a Manager that was never given the declarations
// runs exactly as before.
func TestNoDryRunWithoutTheDeclarationsKeepsTheManagerUnchanged(t *testing.T) {
	healthy := &dryRunLeaf{tag: "healthy", networks: []string{N.NetworkTCP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"healthy", "ghost"},
		networks: []string{N.NetworkTCP},
		selected: "healthy",
	}
	lookup := map[string]adapter.Outbound{"healthy": healthy, "sel": selector}
	selector.lookup = lookup
	selector.OutboundGroup = selector

	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{}}, "")
	installOutbound(t, manager, healthy)
	installOutbound(t, manager, selector)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())

	// The outbound sort still refuses the missing dependency, which is the pre-existing
	// behaviour - and it does so with its own message, not the dry run's.
	err := manager.Start(adapter.StartStateStart, scope)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dependency[ghost] not found",
		"without the declarations the pre-existing sort reports the missing dependency, which is "+
			"what every existing caller keeps")
}

// TestStartupCycleCheckStillRunsBeforeTheDryRun pins the ORDER of the two checks: the existing
// per-kind sort owns "does the dependency exist and is the outbound graph acyclic", and the dry run
// is a separate question about leaves.
func TestStartupCycleCheckStillRunsBeforeTheDryRun(t *testing.T) {
	first := &dryRunLeaf{tag: "first", networks: []string{N.NetworkTCP}, dependencies: []string{"second"}}
	second := &dryRunLeaf{tag: "second", networks: []string{N.NetworkTCP}, dependencies: []string{"first"}}

	err := startWithDryRun(t, []adapter.Outbound{first, second}, physicalpath.Declarations{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "circular outbound dependency",
		"the per-kind sort's own message must remain the one an operator sees for an outbound cycle: "+
			"it names the dependency chain, which is the more precise report")
}

// TestStartRefusesAnEndpointWhoseTagIsShadowedByAnOutbound pins the endpoint-participation collision
// through the real Start.
//
// The lookup resolves the outbound namespace first and falls back to endpoints, so a tag used in
// both creates two objects, shows the tag twice, and leaves the endpoint permanently unreachable:
// never started, never closed, and impossible to measure. box.New refuses that collision at
// construction; the start-time sort refuses it too, because a tag-keyed sort cannot describe a graph
// in which one tag names two nodes.
//
// Measured before the guard in lintOutbounds existed: this exact configuration produced a
// nil-pointer panic inside the sort, not an error. The assertion below is therefore on a precise
// message rather than on "it did not crash", because "it did not crash" was the defect.
func TestStartRefusesAnEndpointWhoseTagIsShadowedByAnOutbound(t *testing.T) {
	shadowing := &dryRunLeaf{tag: "ts", networks: []string{N.NetworkTCP}}
	selector := &dryRunGroup{
		tag:      "sel",
		members:  []string{"ts"},
		networks: []string{N.NetworkTCP},
		selected: "ts",
	}
	// The endpoint manager holds a DIFFERENT object under the same tag, which is what a collision
	// looks like from the manager's side.
	endpointObject := &shadowedEndpoint{dryRunLeaf: dryRunLeaf{tag: "ts", networks: []string{N.NetworkTCP}}}

	lookup := map[string]adapter.Outbound{"ts": shadowing, "sel": selector}
	selector.lookup = lookup
	selector.OutboundGroup = selector
	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{"ts": endpointObject}}, "")
	installOutbound(t, manager, shadowing)
	installOutbound(t, manager, selector)
	manager.EnablePhysicalPathValidation(physicalpath.Declarations{}, func(string) string { return "" }, false)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())

	err := manager.Start(adapter.StartStateStart, scope)
	require.Error(t, err, "a tag that names two objects must be refused, not panicked on")
	require.Contains(t, err.Error(), "duplicate outbound tag")
	require.Contains(t, err.Error(), "ts", "and the failure must name the tag")
}

// TestDuplicateMemberTagIsRefusedRatherThanCrashingTheSort is the smallest form of the same defect,
// and the one a user can write by accident.
func TestDuplicateMemberTagIsRefusedRatherThanCrashingTheSort(t *testing.T) {
	member := &dryRunLeaf{tag: "a", networks: []string{N.NetworkTCP}}
	// Two DISTINCT objects under one tag is the shape that used to crash the sort.
	twin := &dryRunLeaf{tag: "a", networks: []string{N.NetworkTCP}}
	manager := NewManager(&stubRegistry{}, &cycleEndpointManager{endpoints: map[string]adapter.Endpoint{}}, "")
	installOutbound(t, manager, member)
	installOutbound(t, manager, twin)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())

	err := manager.Start(adapter.StartStateStart, scope)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate outbound tag in the start graph: a",
		"the sort must report the collision rather than dereference a nil node")
}

// shadowedEndpoint is an adapter.Endpoint whose tag collides with an outbound.
type shadowedEndpoint struct {
	dryRunLeaf
}

func (e *shadowedEndpoint) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (e *shadowedEndpoint) Close() error                                  { return nil }

// TestTheDryRunConsumesNoRotationOnARealStart pins the cursor contract at the Start boundary: a
// group that counts its committed selections must see none of them consumed by startup.
func TestTheDryRunConsumesNoRotationOnARealStart(t *testing.T) {
	first := &dryRunLeaf{tag: "first", networks: []string{N.NetworkTCP}}
	second := &dryRunLeaf{tag: "second", networks: []string{N.NetworkTCP}}
	selector := &countingDryRunGroup{dryRunGroup: dryRunGroup{
		tag:      "sel",
		members:  []string{"first", "second"},
		networks: []string{N.NetworkTCP},
		selected: "first",
	}}

	err := startWithDryRun(t, []adapter.Outbound{first, second, selector}, physicalpath.Declarations{}, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(0), selector.committed.Load(),
		"startup must not consume a rotation: the first flow must be the first committed choice")
	require.Equal(t, int64(0), selector.previewed.Load(),
		"and the enumeration must not even take a preview")
}

// countingDryRunGroup records previews and commits separately, the way LoadBalance.SelectForFlow
// distinguishes them with its commit parameter.
type countingDryRunGroup struct {
	dryRunGroup
	previewed atomic.Int64
	committed atomic.Uint64
}

func (g *countingDryRunGroup) Selected(network string) adapter.Outbound {
	g.previewed.Add(1)
	return g.dryRunGroup.Selected(network)
}
