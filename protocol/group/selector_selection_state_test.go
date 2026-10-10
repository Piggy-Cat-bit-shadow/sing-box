package group

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Tests for what a selector is allowed to SAY about its selection, as opposed to what it holds.
//
// # The defect these pin (P2)
//
// `Selector.References` returned the FIRST declared member while nothing was selected:
//
//	func (s *Selector) References() []string {
//		selected := s.selected.Load()
//		if selected == nil {
//			return s.tags[:1]
//		}
//		return []string{selected.Tag()}
//	}
//
// Two consumers turn a one-element answer into a statement about LIVE state, because that is the
// contract `adapter.Referrer` documents and the only shape the return type has:
//
//   - common/physicalpath/leaves.go's `selectedTag` requires exactly one reference and uses it to
//     set `PathNode.IsCurrent`, i.e. "this is the path the root resolves to RIGHT NOW".
//   - common/physicalpath/status.go's `controlNode` sets `Decision` from it and `Committed = true`.
//
// So a selector configured `default: B` was reported as having committed `A` - the first declared
// member - while the live slot was empty. That is not a cosmetic label: it is a report claiming
// traffic takes a path it does not take, which is the one thing a path diagnostic exists to
// distinguish.
//
// # Why the answer is "nothing", not "the default"
//
// The obvious repair - return `defaultTag` instead - is still a lie, and a subtler one: `controlNode`
// maps any single reference to `Committed = true`, so a CONFIGURED preference would be displayed as
// a COMMITTED one. The four things a selector can know are not interchangeable:
//
//	ConfiguredDefault       the initial preference in the configuration
//	PersistedSelection      the member the cachefile holds, once validated as legal
//	LiveCommittedSelection  what the live slot actually holds after Start
//	Unknown                 not enough evidence yet
//
// Only the third may be reported as committed. `References` therefore publishes nothing until there
// is something to publish - the same answer `URLTest.References` already gives
// (protocol/group/urltest.go), and the same answer the physicalpath package's own `testGroup`
// fixture gives for an unselected group (common/physicalpath/physicalpath_test.go). The two
// preferences stay readable through `Selector.SelectionStatus`, which names them as preferences.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// edgeLeaf is a member with a DECLARED network set, which is the only thing a walk reads about a
// leaf. It implements every method the walk calls, so nothing here relies on an embedded nil.
type edgeLeaf struct {
	adapter.Outbound
	tag      string
	networks []string
}

func (l *edgeLeaf) Type() string           { return C.TypeDirect }
func (l *edgeLeaf) Tag() string            { return l.tag }
func (l *edgeLeaf) Network() []string      { return l.networks }
func (l *edgeLeaf) Dependencies() []string { return nil }
func (l *edgeLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (l *edgeLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

func newEdgeLeaf(tag string, networks ...string) *edgeLeaf {
	return &edgeLeaf{tag: tag, networks: networks}
}

// recordingCacheFile is the cachefile half of the four states: it holds a persisted selection and
// counts how often it was read, so a test can prove a status read did not go looking for state.
//
// Only the two methods a group uses are implemented; the embedded interface supplies the rest of
// adapter.CacheFile and is never reached, because no group here touches anything else on it.
type recordingCacheFile struct {
	adapter.CacheFile
	selected string
	loads    int
	stores   int
}

func (c *recordingCacheFile) LoadSelected(string) string { c.loads++; return c.selected }
func (c *recordingCacheFile) StoreSelected(_ string, selected string) error {
	c.stores++
	c.selected = selected
	return nil
}

var _ adapter.CacheFile = (*recordingCacheFile)(nil)

// worldManager resolves members by tag, which is how a group expands its own list.
type worldManager struct {
	adapter.OutboundManager
	order []string
	byTag map[string]adapter.Outbound
}

func (m *worldManager) Outbounds() []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(m.order))
	for _, tag := range m.order {
		outbounds = append(outbounds, m.byTag[tag])
	}
	return outbounds
}

func (m *worldManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

// groupWorld is a set of REAL objects over a real registry, with the context services the real
// constructors require. Nothing here stubs a group.
type groupWorld struct {
	t       *testing.T
	ctx     context.Context
	manager *worldManager
	cache   *recordingCacheFile
}

func newGroupWorld(t *testing.T) *groupWorld {
	t.Helper()
	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = service.ContextWith[*runtimecoord.Coordinator](ctx, runtimecoord.New())
	manager := &worldManager{byTag: make(map[string]adapter.Outbound)}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	return &groupWorld{t: t, ctx: ctx, manager: manager}
}

// add registers objects, in the order given, so `Outbounds` reports a stable order.
func (w *groupWorld) add(objects ...adapter.Outbound) *groupWorld {
	for _, object := range objects {
		if _, present := w.manager.byTag[object.Tag()]; !present {
			w.manager.order = append(w.manager.order, object.Tag())
		}
		w.manager.byTag[object.Tag()] = object
	}
	return w
}

// withCache attaches a cachefile carrying a persisted selection, before any group is built.
func (w *groupWorld) withCache(selected string) *groupWorld {
	w.cache = &recordingCacheFile{selected: selected}
	w.ctx = service.ContextWith[adapter.CacheFile](w.ctx, w.cache)
	return w
}

// newSelector builds a REAL selector. It is NOT started: the unstarted state is the one the defect
// lives in.
func (w *groupWorld) newSelector(tag string, tags []string, defaultTag string) *Selector {
	w.t.Helper()
	created, err := NewSelector(w.ctx, nil, log.NewNOPFactory().NewLogger("selector"), tag, option.SelectorOutboundOptions{
		Outbounds: tags,
		Default:   defaultTag,
	})
	require.NoError(w.t, err)
	selector, isSelector := created.(*Selector)
	require.True(w.t, isSelector)
	w.add(selector)
	return selector
}

// newLoadBalance builds a REAL loadbalance group over the given member tags.
func (w *groupWorld) newLoadBalance(tag string, members []string) *LoadBalance {
	w.t.Helper()
	created, err := NewLoadBalance(w.ctx, nil, log.NewNOPFactory().NewLogger("loadbalance"), tag, option.LoadBalanceOutboundOptions{
		Outbounds: members,
	})
	require.NoError(w.t, err)
	group, isGroup := created.(*LoadBalance)
	require.True(w.t, isGroup)
	w.add(group)
	return group
}

// start starts an object through its real lifecycle.
func (w *groupWorld) start(object any) {
	w.t.Helper()
	lifecycle, ok := object.(adapter.Lifecycle)
	require.True(w.t, ok, "the fixture only starts real lifecycle objects")
	require.NoError(w.t, lifecycle.Start(adapter.StartStateStart, &adapter.Scope{}))
}

// resolver is the production resolver over this world, which is the object the dry run and the
// status view both read.
func (w *groupWorld) resolver() *physicalpath.Resolver {
	return physicalpath.NewResolver(w.manager.Outbound, physicalpath.Snapshot{})
}

// controls reads the control path through the REAL consumer: the status view. This is the route by
// which the defect reached a reader.
func (w *groupWorld) controls(network string, root string) physicalpath.PathStatus {
	w.t.Helper()
	return physicalpath.NewStatusView().SnapshotStatus(
		w.resolver(),
		physicalpath.TagOrOutbound{Tag: root},
		physicalpath.Options{Network: network},
	)
}

// decision returns the control node for one group tag, and requires that it is present.
func (w *groupWorld) decision(network string, root string, groupTag string) physicalpath.ControlNode {
	w.t.Helper()
	status := w.controls(network, root)
	for _, control := range status.Controls {
		if control.Tag == groupTag {
			return control
		}
	}
	w.t.Fatalf("the control path of %s does not contain %s: %+v", root, groupTag, status.ControlPath)
	return physicalpath.ControlNode{}
}

// ---------------------------------------------------------------------------
// The RED cases: an unstarted selector must not name a member
// ---------------------------------------------------------------------------

// TestSelectorReferencesNamesNoMemberBeforeItHasOne is the defect itself.
//
// The selector prefers `node-b` and has never selected anything. `References` reports one member,
// which is the maximum information a reader can be given, so the honest answer is NONE.
func TestSelectorReferencesNamesNoMemberBeforeItHasOne(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")

	require.Nil(t, selector.Selected(N.NetworkTCP), "the fixture is unstarted, so nothing is live")

	require.Empty(t, selector.References(),
		"an unstarted selector has committed to no member, so it must publish none; returning the "+
			"first DECLARED member reports a selection that was never made, and `default: node-b` "+
			"makes that member the wrong one as well")
}

// TestStatusDoesNotNameAMemberTheSelectorNeverChose is the same defect at the consumer, where it
// became a claim about live traffic.
func TestStatusDoesNotNameAMemberTheSelectorNeverChose(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.NotEqual(t, "node-a", control.Decision,
		"the configured member is node-b; reporting node-a reports a selection that was never made")
}

// TestStatusDoesNotClaimCommitmentBeforeStart is the second half of the same lie: even a CORRECT
// member name would be wrong here, because nothing has been committed.
func TestStatusDoesNotClaimCommitmentBeforeStart(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.False(t, control.Committed,
		"nothing has been committed before Start, so `Committed` must be false; a preference "+
			"displayed as live is exactly what the four states exist to prevent")
	require.NotEmpty(t, control.Reason,
		"a reader must be told WHY there is no decision rather than being shown a blank")
}

// TestStatusReportsTheCommittedSelectionAfterStart is the positive control for the three above:
// the honest empty answer must not become "the selector never reports anything".
func TestStatusReportsTheCommittedSelectionAfterStart(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")
	world.start(selector)

	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag(),
		"Start must commit the configured default")

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.Equal(t, "node-b", control.Decision)
	require.True(t, control.Committed, "after Start the member IS committed, so status must say so")
	require.Equal(t, []string{"node-b"}, selector.References(),
		"and the published reference is the committed member, which is what the idle walk follows")
}

// ---------------------------------------------------------------------------
// The acceptance matrix
// ---------------------------------------------------------------------------

// TestNoDefaultSelectorCommitsTheFirstMemberOnlyAtStart covers `tags=[A,B]` with NO default.
//
// The first declared member is the fallback Start uses, and it becomes true only at Start. Before
// that it is not a selection, which is the distinction `tags[:1]` erased.
func TestNoDefaultSelectorCommitsTheFirstMemberOnlyAtStart(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP), newEdgeLeaf("node-b", N.NetworkTCP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "")

	require.Empty(t, selector.References(),
		"with no default there is not even a preference, so there is certainly nothing to publish")

	world.start(selector)
	require.Equal(t, "node-a", selector.Selected(N.NetworkTCP).Tag(),
		"Start falls back to the first declared member")
	require.Equal(t, []string{"node-a"}, selector.References())

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.Equal(t, "node-a", control.Decision)
	require.True(t, control.Committed)
}

// TestPersistedSelectionWinsOverTheConfiguredDefault covers `cache=B` with `default=A`.
//
// The two preferences genuinely differ, and the persisted one is what Start restores. Before Start
// neither is live, so the report must name neither as committed.
func TestPersistedSelectionWinsOverTheConfiguredDefault(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		withCache("node-b").
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-a")

	require.Empty(t, selector.References(),
		"the cache names node-b and the default names node-a; neither is committed yet, and "+
			"publishing node-a is the first member rather than even the preference that wins")

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.False(t, control.Committed)

	world.start(selector)
	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag(),
		"the persisted selection is what Start restores")
	require.Equal(t, "node-b", world.decision(N.NetworkTCP, "sel", "sel").Decision)
}

// TestCacheNamingANonMemberIsRefusedAndNotReported covers a cachefile that names a member of no
// list. It must not become a decision, and the fallback must be reported instead.
func TestCacheNamingANonMemberIsRefusedAndNotReported(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		withCache("node-does-not-exist").
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")

	require.Empty(t, selector.References(), "an illegal persisted tag is not a selection either")

	world.start(selector)
	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag(),
		"Start refuses the illegal persisted tag and falls back to the default")

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.Equal(t, "node-b", control.Decision)
	require.NotEqual(t, "node-does-not-exist", control.Decision,
		"a tag that names no member must never be published as the decision")
}

// TestSelectionSwitchIsReportedAfterSelectOutbound covers a real switch through the real API.
func TestSelectionSwitchIsReportedAfterSelectOutbound(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-a")
	world.start(selector)

	require.Equal(t, "node-a", world.decision(N.NetworkTCP, "sel", "sel").Decision)

	require.True(t, selector.SelectOutbound("node-b"))
	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag())

	control := world.decision(N.NetworkTCP, "sel", "sel")
	require.Equal(t, "node-b", control.Decision,
		"the report must follow the switch, and it must agree with what a real selection produces")
	require.True(t, control.Committed)
	require.Equal(t, selector.Selected(N.NetworkUDP).Tag(), control.Decision,
		"the published decision and the live selection must name the same member")
}

// TestRestartRestoresThePersistedSelection covers Close and restart: the switch is persisted, and a
// selector built again over the same cachefile restores it rather than the declared default.
func TestRestartRestoresThePersistedSelection(t *testing.T) {
	t.Parallel()

	first := newGroupWorld(t).
		withCache("").
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := first.newSelector("sel", []string{"node-a", "node-b"}, "node-a")
	first.start(selector)
	require.True(t, selector.SelectOutbound("node-b"))
	require.Equal(t, 1, first.cache.stores, "the switch is persisted")

	// The restart: the same persisted state, a NEW object, and therefore no live slot until Start.
	second := newGroupWorld(t).
		withCache(first.cache.selected).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	restarted := second.newSelector("sel", []string{"node-a", "node-b"}, "node-a")

	require.Empty(t, restarted.References(),
		"the restarted selector has not started, so it has committed to nothing")
	require.False(t, second.decision(N.NetworkTCP, "sel", "sel").Committed)

	second.start(restarted)
	require.Equal(t, "node-b", restarted.Selected(N.NetworkTCP).Tag())
	require.Equal(t, "node-b", second.decision(N.NetworkTCP, "sel", "sel").Decision)
}

// TestNestedSelectorToLoadBalanceDoesNotPublishAFixedCurrent covers `selector -> loadbalance`.
//
// The outer selector owns one decision and the inner balancer owns a per-flow choice. The one thing
// the report must never do is turn the balancer's per-flow choice into a fixed member, or let the
// outer selector's single decision stand in for the inner group's.
func TestNestedSelectorToLoadBalanceDoesNotPublishAFixedCurrent(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP), newEdgeLeaf("node-b", N.NetworkTCP))
	balancer := world.newLoadBalance("lb", []string{"node-a", "node-b"})
	selector := world.newSelector("sel", []string{"lb"}, "lb")

	require.Empty(t, selector.References(), "the outer selector has committed to nothing yet")

	world.start(balancer)
	world.start(selector)

	outer := world.decision(N.NetworkTCP, "sel", "sel")
	require.Equal(t, "lb", outer.Decision, "the outer selector chose the balancer")
	require.True(t, outer.Committed)

	inner := world.decision(N.NetworkTCP, "sel", "lb")
	require.Empty(t, inner.Decision,
		"a balancing group's choice is per flow, so no single member describes this path")
	require.False(t, inner.Committed,
		"reporting a per-flow choice as committed is picking a member the flow may not take")
	require.NotEmpty(t, inner.Reason)
}

// TestLoadBalanceNeverReportsAFixedCurrent is the balancer on its own, which is the "PER FLOW" case
// the matrix names: a round-robin group's next member is not a fact about the live path.
func TestLoadBalanceNeverReportsAFixedCurrent(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP), newEdgeLeaf("node-b", N.NetworkTCP))
	balancer := world.newLoadBalance("lb", []string{"node-a", "node-b"})
	world.start(balancer)

	control := world.decision(N.NetworkTCP, "lb", "lb")
	require.Empty(t, control.Decision, "a per-flow group has no single decision")
	require.False(t, control.Committed)
}

// TestReadingStatusConsumesNoSelection is the read-only requirement: asking for status must not
// change what the group holds and must not advance a rotation.
func TestReadingStatusConsumesNoSelection(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	balancer := world.newLoadBalance("lb", []string{"node-a", "node-b"})
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-b")
	world.start(balancer)
	world.start(selector)

	beforeCursor := balancer.CommittedSelections()
	beforeSelection := selector.Selected(N.NetworkTCP)
	require.NotNil(t, beforeSelection)

	for range 8 {
		status := world.controls(N.NetworkTCP, "sel")
		require.False(t, status.HasUnknown(), "reading status must produce a describable path")
		world.controls(N.NetworkUDP, "sel")
		world.controls(N.NetworkTCP, "lb")
	}

	require.Equal(t, beforeCursor, balancer.CommittedSelections(),
		"a status read must not advance the round-robin cursor")
	require.Same(t, beforeSelection, selector.Selected(N.NetworkTCP),
		"a status read must not move the selector's selection")
	require.Equal(t, beforeSelection.Tag(), world.decision(N.NetworkTCP, "sel", "sel").Decision,
		"and the decision it reports must still be the member the selector really holds")
}

// TestSnapshotDecisionMatchesARealSelectionThenProduces is the agreement assertion the matrix asks
// for: what the report says and what the selector then hands out must be one member.
func TestSnapshotDecisionMatchesARealSelectionThenProduces(t *testing.T) {
	t.Parallel()

	for _, defaultTag := range []string{"node-a", "node-b"} {
		world := newGroupWorld(t).
			add(newEdgeLeaf("node-a", N.NetworkTCP), newEdgeLeaf("node-b", N.NetworkTCP))
		selector := world.newSelector("sel", []string{"node-a", "node-b"}, defaultTag)
		world.start(selector)

		reported := world.decision(N.NetworkTCP, "sel", "sel")
		require.True(t, reported.Committed)

		// What a real selection then produces, for both networks, is the same member.
		require.Equal(t, reported.Decision, selector.Selected(N.NetworkTCP).Tag())
		require.Equal(t, reported.Decision, selector.Selected(N.NetworkUDP).Tag(),
			"the selector holds one member for every network; the report must agree with all of them")
		require.Equal(t, []string{reported.Decision}, selector.References())
	}
}

// ---------------------------------------------------------------------------
// The four states, as SelectionStatus implements them
// ---------------------------------------------------------------------------

// TestSelectionStatusSeparatesTheFourStates is the state model itself: each of the four claims is
// reported as what it is, and none of them is reported as another.
func TestSelectionStatusSeparatesTheFourStates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		tags            []string
		defaultTag      string
		cache           string
		hasCache        bool
		start           bool
		wantState       SelectionState
		wantTag         string
		wantPersisted   string
		wantCommitted   string
		wantRejectedTag string
	}{
		{
			name: "no preference at all is unknown, not a fallback member",
			// The first declared member is what Start would FALL BACK to; it is not a preference,
			// which is why the state is Unknown and the tag is empty rather than "node-a".
			tags: []string{"node-a", "node-b"}, defaultTag: "",
			wantState: SelectionUnknown, wantTag: "",
		},
		{
			name:       "a configured default is configured, and not committed",
			tags:       []string{"node-a", "node-b"},
			defaultTag: "node-b",
			wantState:  SelectionConfigured, wantTag: "node-b",
		},
		{
			name: "a legal persisted member outranks the configured default, and is still not committed",
			tags: []string{"node-a", "node-b"}, defaultTag: "node-a",
			cache: "node-b", hasCache: true,
			wantState: SelectionPersisted, wantTag: "node-b", wantPersisted: "node-b",
		},
		{
			name: "after Start the same member is committed, and only then",
			tags: []string{"node-a", "node-b"}, defaultTag: "node-a",
			cache: "node-b", hasCache: true, start: true,
			wantState: SelectionCommitted, wantTag: "node-b", wantPersisted: "node-b", wantCommitted: "node-b",
		},
		{
			name: "a persisted member this selector does not declare is refused and reported",
			tags: []string{"node-a", "node-b"}, defaultTag: "node-b",
			cache: "node-elsewhere", hasCache: true, start: true,
			wantState: SelectionCommitted, wantTag: "node-b", wantCommitted: "node-b",
			wantRejectedTag: "node-elsewhere",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			world := newGroupWorld(t)
			if testCase.hasCache {
				world.withCache(testCase.cache)
			}
			world.add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
			selector := world.newSelector("sel", testCase.tags, testCase.defaultTag)
			if testCase.start {
				world.start(selector)
			}

			report := selector.SelectionStatus()
			require.Equal(t, testCase.wantState, report.State)
			require.Equal(t, testCase.wantState.String(), report.State.String())
			require.Equal(t, testCase.wantTag, report.Tag)
			require.Equal(t, testCase.wantPersisted, report.Persisted)
			require.Equal(t, testCase.wantRejectedTag, report.PersistedRejected)
			require.Equal(t, testCase.wantCommitted, report.Committed)

			// The invariant that holds in EVERY state: a preference is never reported as committed.
			tag, committed := report.CommittedMember()
			require.Equal(t, report.Committed != "", committed)
			require.Equal(t, report.Committed, tag)
			if report.State != SelectionCommitted {
				require.Empty(t, report.Committed,
					"only SelectionCommitted may carry a committed member; reporting a preference "+
						"here is the defect the four states exist to prevent")
				require.NotEqual(t, SelectionCommitted, report.State)
			}
		})
	}
}

// TestSelectionStatusDoesNotChangeSelectorState is the read-only requirement for the new accessor:
// it must not take a selection, write a preference, or advance anything.
func TestSelectionStatusDoesNotChangeSelectorState(t *testing.T) {
	t.Parallel()

	world := newGroupWorld(t).
		withCache("node-b").
		add(newEdgeLeaf("node-a", N.NetworkTCP, N.NetworkUDP), newEdgeLeaf("node-b", N.NetworkTCP, N.NetworkUDP))
	selector := world.newSelector("sel", []string{"node-a", "node-b"}, "node-a")

	require.Nil(t, selector.Selected(N.NetworkTCP))
	require.Equal(t, SelectionPersisted, selector.SelectionStatus().State)

	for range 8 {
		require.Equal(t, SelectionPersisted, selector.SelectionStatus().State)
	}
	require.Nil(t, selector.Selected(N.NetworkTCP),
		"reporting the preference must not commit it")
	require.Equal(t, 0, world.cache.stores,
		"reporting the preference must not write one")
	require.Zero(t, selector.SelectionStatus().Committed)

	// Once started, the same accessor reports the commitment and still writes nothing.
	world.start(selector)
	storesAfterStart := world.cache.stores
	for range 8 {
		require.Equal(t, "node-b", selector.SelectionStatus().Committed)
	}
	require.Equal(t, storesAfterStart, world.cache.stores, "reading status writes nothing")
	require.Equal(t, "node-b", selector.Selected(N.NetworkTCP).Tag())
}
