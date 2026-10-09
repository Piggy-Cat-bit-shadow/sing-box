package group

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Nested outbound resolution, attribution and interruption.
//
// # The invariant
//
// For any chain of groups, the node that carries the traffic is a LEAF, and every layer that
// describes the flow - selection, history, interruption, attribution - must name that leaf rather
// than any group on the way to it. A nested group makes this non-obvious: `Selected()` on the outer
// group answers with the next GROUP, not with the node.
//
// # Why these tests build real groups
//
// A test that hand-wires `Selected()` proves only that the test can wire it. Every topology below is
// built through the real constructors (`NewSelector`, `NewURLTest`) and the real `Start`, wired by
// DECLARED MEMBER TAGS resolved through the outbound manager - the same edges a configuration
// creates. The call paths asserted on are the product ones: `DialContext`, `ListenPacket`,
// `ResolveURLTestLeaf`, `RealTag`, `MeasurementScope`, `PerformUpdateCheck`, `AttachConnection`.
//
// # Why the leaf records its own tag
//
// The mock leaves record the tag they were dialled under at the moment of the dial. A leaf is the
// last object in a resolved chain, so that tag is by construction the node that carries the
// traffic, and it can be compared against what the outer groups and the history layer claim.

// nestedCall is one connection a leaf handed out.
type nestedCall struct {
	// tag is the leaf's OWN tag: the node this stream is attributed to.
	tag         string
	network     string
	destination string
	// viaListen is set when the call arrived through ListenPacket rather than DialContext, so a
	// test can tell the UDP session path from a UDP dial.
	viaListen bool
	conn      *nestedConn
}

// nestedConn remembers whether it was closed. A group interrupts a selection change by closing the
// connections it owns, so "was this conn closed" is the observable form of that contract.
type nestedConn struct {
	closeCount atomic.Int32
}

func (c *nestedConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *nestedConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *nestedConn) Close() error                     { c.closeCount.Add(1); return nil }
func (c *nestedConn) LocalAddr() net.Addr              { return nil }
func (c *nestedConn) RemoteAddr() net.Addr             { return nil }
func (c *nestedConn) SetDeadline(time.Time) error      { return nil }
func (c *nestedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *nestedConn) SetWriteDeadline(time.Time) error { return nil }

func (c *nestedConn) interrupted() bool { return c.closeCount.Load() > 0 }

type nestedPacketConn struct {
	conn *nestedConn
}

func (c *nestedPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *nestedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (c *nestedPacketConn) Close() error                     { return c.conn.Close() }
func (c *nestedPacketConn) LocalAddr() net.Addr              { return nil }
func (c *nestedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *nestedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *nestedPacketConn) SetWriteDeadline(time.Time) error { return nil }

// nestedLeaf is a leaf outbound that records the tag it was dialled under and the lifecycle of
// every connection it hands out.
type nestedLeaf struct {
	adapter.Outbound
	tag      string
	typeName string
	networks []string

	access sync.Mutex
	calls  []*nestedCall
}

func newNestedLeaf(tag string, typeName string, networks ...string) *nestedLeaf {
	if len(networks) == 0 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &nestedLeaf{tag: tag, typeName: typeName, networks: networks}
}

func (o *nestedLeaf) Type() string {
	if o.typeName == "" {
		return "nested-leaf"
	}
	return o.typeName
}

func (o *nestedLeaf) Tag() string       { return o.tag }
func (o *nestedLeaf) Network() []string { return o.networks }

func (o *nestedLeaf) DialContext(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn := &nestedConn{}
	o.record(&nestedCall{tag: o.tag, network: N.NetworkName(network), destination: destination.String(), conn: conn})
	return conn, nil
}

func (o *nestedLeaf) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn := &nestedConn{}
	o.record(&nestedCall{
		tag: o.tag, network: N.NetworkUDP, destination: destination.String(), viaListen: true, conn: conn,
	})
	return &nestedPacketConn{conn: conn}, nil
}

func (o *nestedLeaf) record(call *nestedCall) {
	o.access.Lock()
	defer o.access.Unlock()
	o.calls = append(o.calls, call)
}

// callLog returns a copy of the call log, so an assertion cannot be invalidated by a later dial.
func (o *nestedLeaf) callLog() []*nestedCall {
	o.access.Lock()
	defer o.access.Unlock()
	return append([]*nestedCall(nil), o.calls...)
}

// dialedTags returns the tags this leaf was dialled under, in order. It is always either empty or
// exactly this leaf's tag: the leaf is the last object in the chain.
func (o *nestedLeaf) dialedTags() []string {
	tags := make([]string, 0, len(o.calls))
	for _, call := range o.callLog() {
		tags = append(tags, call.tag)
	}
	return tags
}

func (o *nestedLeaf) lastCall() *nestedCall {
	calls := o.callLog()
	if len(calls) == 0 {
		return nil
	}
	return calls[len(calls)-1]
}

// nestedTopology builds real Selector and URLTest groups over one outbound manager, wired by
// declared member tags exactly as a configuration wires them.
//
// Nothing here reaches into a group's internals to create an edge: every edge is a tag the group
// declares in its options and resolves through the manager, which is the path a configuration
// takes.
type nestedTopology struct {
	t        *testing.T
	ctx      context.Context
	storage  *urltest.HistoryStorage
	manager  *taggedOutboundManager
	starters []adapter.Lifecycle
}

func newNestedTopology(t *testing.T) *nestedTopology {
	t.Helper()
	manager := &taggedOutboundManager{byTag: make(map[string]adapter.Outbound)}
	storage := urltest.NewHistoryStorage()
	ctx := pause.WithDefaultManager(
		service.ContextWithPtr(
			service.ContextWith[adapter.OutboundManager](context.Background(), manager),
			storage))
	return &nestedTopology{t: t, ctx: ctx, storage: storage, manager: manager}
}

func (f *nestedTopology) add(outbound adapter.Outbound) {
	f.manager.byTag[outbound.Tag()] = outbound
	if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
		f.starters = append(f.starters, lifecycle)
	}
}

func (f *nestedTopology) leaf(tag string, typeName string, networks ...string) *nestedLeaf {
	leaf := newNestedLeaf(tag, typeName, networks...)
	f.add(leaf)
	return leaf
}

func (f *nestedTopology) selector(tag string, interrupt bool, members ...string) *Selector {
	f.t.Helper()
	created, err := NewSelector(f.ctx, nil, log.NewNOPFactory().NewLogger(tag), tag, option.SelectorOutboundOptions{
		Outbounds:                 members,
		InterruptExistConnections: interrupt,
	})
	require.NoError(f.t, err)
	selector, isSelector := created.(*Selector)
	require.True(f.t, isSelector)
	f.add(selector)
	return selector
}

func (f *nestedTopology) urlTest(tag string, link string, interrupt bool, members ...string) *URLTest {
	f.t.Helper()
	created, err := NewURLTest(f.ctx, nil, log.NewNOPFactory().NewLogger(tag), tag, option.URLTestOutboundOptions{
		Outbounds:                 members,
		URL:                       link,
		Interval:                  badoption.Duration(time.Minute),
		IdleTimeout:               badoption.Duration(5 * time.Minute),
		InterruptExistConnections: interrupt,
	})
	require.NoError(f.t, err)
	wrapper, isURLTest := created.(*URLTest)
	require.True(f.t, isURLTest)
	f.add(wrapper)
	return wrapper
}

// start runs every registered group's Start in registration order, which is inner-to-outer because
// a chain is built from its leaf upwards.
func (f *nestedTopology) start() {
	f.t.Helper()
	for _, starter := range f.starters {
		require.NoError(f.t, starter.Start(adapter.StartStateStart, &adapter.Scope{}))
	}
}

func (f *nestedTopology) closeAll() {
	for _, starter := range f.starters {
		if closer, isCloser := starter.(io.Closer); isCloser {
			_ = closer.Close()
		}
	}
}

const (
	nestedLinkA = "https://probe-a.example/generate_204"
	nestedLinkB = "https://probe-b.example/generate_204"
)

// nestedTarget is the destination every shape dials. It is documentation-free on purpose: nothing
// in the code under test may branch on it.
var nestedTarget = M.ParseSocksaddr("198.51.100.7:443")

// walkSelected follows the plain OutboundGroup contract from an outer outbound to whatever it
// answers with, with the cycle guard a caller must have. It is deliberately a DIFFERENT walk from
// ResolveURLTestLeaf (no flow-aware preview): the two must agree on the leaf.
func walkSelected(t *testing.T, outbound adapter.Outbound, network string) adapter.Outbound {
	t.Helper()
	visited := make(map[adapter.Outbound]struct{})
	for {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			return outbound
		}
		if _, seen := visited[outbound]; seen {
			t.Fatalf("Selected() walk entered a cycle at %s", outbound.Tag())
		}
		visited[outbound] = struct{}{}
		next := group.Selected(network)
		if next == nil {
			t.Fatalf("group %s answered Selected(%s) with nil", group.Tag(), network)
		}
		outbound = next
	}
}

// nestedShape is one group topology, expressed as the configuration edges that create it.
type nestedShape struct {
	name     string
	wantLeaf string
	wantType string
	build    func(f *nestedTopology) adapter.Outbound
}

// nestedShapes covers the required topologies, in group-depth order, with a direct, a proxy and an
// endpoint leaf.
func nestedShapes() []nestedShape {
	return []nestedShape{
		{
			name:     "selector to direct leaf",
			wantLeaf: "leaf-direct",
			wantType: C.TypeDirect,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-direct", C.TypeDirect)
				return f.selector("outer", true, "leaf-direct")
			},
		},
		{
			name:     "selector to urltest to proxy leaf",
			wantLeaf: "leaf-proxy",
			wantType: C.TypeVLESS,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-proxy", C.TypeVLESS)
				f.urlTest("inner-ut", nestedLinkA, true, "leaf-proxy")
				return f.selector("outer", true, "inner-ut")
			},
		},
		{
			name:     "urltest to selector to proxy leaf",
			wantLeaf: "leaf-proxy",
			wantType: C.TypeShadowsocks,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-proxy", C.TypeShadowsocks)
				f.selector("inner-sel", true, "leaf-proxy")
				return f.urlTest("outer-ut", nestedLinkA, true, "inner-sel")
			},
		},
		{
			name:     "three groups: selector to urltest to selector to endpoint leaf",
			wantLeaf: "leaf-endpoint",
			wantType: C.TypeWireGuard,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-endpoint", C.TypeWireGuard)
				f.selector("inner-sel", true, "leaf-endpoint")
				f.urlTest("mid-ut", nestedLinkA, true, "inner-sel")
				return f.selector("outer", true, "mid-ut")
			},
		},
		{
			name:     "four groups: selector urltest selector urltest to endpoint leaf",
			wantLeaf: "leaf-endpoint",
			wantType: C.TypeWireGuard,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-endpoint", C.TypeWireGuard)
				f.urlTest("ut-inner", nestedLinkA, true, "leaf-endpoint")
				f.selector("sel-mid", true, "ut-inner")
				f.urlTest("ut-outer", nestedLinkA, true, "sel-mid")
				return f.selector("outer", true, "ut-outer")
			},
		},
		{
			name:     "four groups: urltest selector selector urltest to proxy leaf",
			wantLeaf: "leaf-proxy",
			wantType: C.TypeTrojan,
			build: func(f *nestedTopology) adapter.Outbound {
				f.leaf("leaf-proxy", C.TypeTrojan)
				f.urlTest("ut-inner", nestedLinkA, true, "leaf-proxy")
				f.selector("sel-inner", true, "ut-inner")
				f.selector("sel-mid", true, "sel-inner")
				return f.urlTest("ut-outer", nestedLinkA, true, "sel-mid")
			},
		},
	}
}

// TestNestedShapesResolveToTheLeafThatCarriesTheTraffic is the resolution identity.
//
// For every topology: the walk through Selected() and ResolveURLTestLeaf must land on the same
// LEAF object, RealTag must name it, and dialling the outer group must reach that same object for
// TCP and for UDP.
func TestNestedShapesResolveToTheLeafThatCarriesTheTraffic(t *testing.T) {
	for _, shape := range nestedShapes() {
		t.Run(shape.name, func(t *testing.T) {
			f := newNestedTopology(t)
			outer := shape.build(f)
			f.start()
			t.Cleanup(f.closeAll)

			leaf, loaded := f.manager.byTag[shape.wantLeaf]
			require.True(t, loaded)
			recorder, isLeaf := leaf.(*nestedLeaf)
			require.True(t, isLeaf)
			require.Equal(t, shape.wantType, recorder.Type())

			// --- resolution -------------------------------------------------------------

			resolved, err := ResolveURLTestLeaf(outer, N.NetworkTCP)
			require.NoError(t, err)
			require.Same(t, adapter.Outbound(recorder), resolved,
				"resolution must reach the leaf object, not an intermediate group")
			require.Equal(t, shape.wantLeaf, resolved.Tag())
			require.Equal(t, shape.wantLeaf, RealTag(outer, N.NetworkTCP))

			require.Same(t, resolved, walkSelected(t, outer, N.NetworkTCP),
				"the raw Selected() walk and the resolver must agree on the leaf")

			// --- TCP --------------------------------------------------------------------

			conn, err := outer.DialContext(context.Background(), N.NetworkTCP, nestedTarget)
			require.NoError(t, err)
			require.NoError(t, conn.Close())

			calls := recorder.callLog()
			require.Len(t, calls, 1, "exactly one node dialled")
			require.Equal(t, shape.wantLeaf, calls[0].tag,
				"the tag recorded at the leaf must be the leaf's own tag; an intermediate group "+
					"dialling on its own behalf would record that group instead")
			require.Equal(t, N.NetworkTCP, calls[0].network)
			require.False(t, calls[0].viaListen)

			// --- UDP --------------------------------------------------------------------

			require.Equal(t, shape.wantLeaf, RealTag(outer, N.NetworkUDP))

			packetConn, err := outer.ListenPacket(context.Background(), nestedTarget)
			require.NoError(t, err)
			require.NoError(t, packetConn.Close())

			calls = recorder.callLog()
			require.Len(t, calls, 2, "the UDP session path reached one node")
			require.Equal(t, shape.wantLeaf, calls[1].tag)
			require.Equal(t, N.NetworkUDP, calls[1].network)
			require.True(t, calls[1].viaListen,
				"the packet path must arrive through ListenPacket")
		})
	}
}

// TestNestedResolutionIsPerNetwork covers the TCP and UDP selections separately.
//
// A URLTest publishes one selected member per network, so the leaf an outer group resolves to is a
// function of the network. A resolver that ignored the network would name the TCP node for a UDP
// session - the delay history of one path applied to the other.
func TestNestedResolutionIsPerNetwork(t *testing.T) {
	f := newNestedTopology(t)
	tcpLeaf := f.leaf("leaf-tcp", C.TypeVLESS, N.NetworkTCP)
	udpLeaf := f.leaf("leaf-udp", C.TypeWireGuard, N.NetworkUDP)
	inner := f.urlTest("inner-ut", nestedLinkA, true, "leaf-tcp", "leaf-udp")
	outer := f.selector("outer", true, "inner-ut")
	f.start()
	t.Cleanup(f.closeAll)

	// The real selection update: each network settles on the first member that serves it.
	inner.PerformUpdateCheck()

	state := inner.currentGroup().selected.Load()
	require.NotNil(t, state)
	require.Equal(t, "leaf-tcp", state.tcp.Tag())
	require.Equal(t, "leaf-udp", state.udp.Tag())
	require.NotSame(t, state.tcp, state.udp, "the fixture must select different nodes per network")

	require.Equal(t, "leaf-tcp", RealTag(outer, N.NetworkTCP))
	require.Equal(t, "leaf-udp", RealTag(outer, N.NetworkUDP))

	conn, err := outer.DialContext(context.Background(), N.NetworkTCP, nestedTarget)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, []string{"leaf-tcp"}, tcpLeaf.dialedTags())
	require.Empty(t, udpLeaf.dialedTags())

	packetConn, err := outer.ListenPacket(context.Background(), nestedTarget)
	require.NoError(t, err)
	require.NoError(t, packetConn.Close())
	require.Equal(t, []string{"leaf-udp"}, udpLeaf.dialedTags())
	require.Equal(t, []string{"leaf-tcp"}, tcpLeaf.dialedTags(),
		"the UDP session must not have gone through the TCP node")
}

// TestNestedMemberIsRankedByItsLeafHistory is the history-attribution identity.
//
// A health round expands a nested group down to its leaves and measures each LEAF against the
// round's own target, so the result is stored under the leaf's tag in the PARENT's scope -
// see urlTestBatch.test. Selection must read that entry back by resolving the nested member to the
// same leaf.
//
// Keying the read on the member's own tag - which is the intermediate group's tag - finds nothing,
// so the nested member drops out of the ranking entirely and a worse node wins.
func TestNestedMemberIsRankedByItsLeafHistory(t *testing.T) {
	f := newNestedTopology(t)
	fast := f.leaf("leaf-fast", C.TypeVLESS)
	slow := f.leaf("leaf-slow", C.TypeVLESS)
	other := f.leaf("leaf-other", C.TypeVLESS)

	// The nested group lists its SLOWER leaf first, so only leaf-keyed history can rank it, and
	// the outer group lists the nested group before the node that must lose.
	inner := f.urlTest("inner-ut", nestedLinkA, true, "leaf-slow", "leaf-fast")
	outer := f.urlTest("outer-ut", nestedLinkB, true, "inner-ut", "leaf-other")
	f.start()
	t.Cleanup(f.closeAll)

	innerScope := inner.MeasurementScope()
	outerScope := outer.MeasurementScope()
	require.NotEqual(t, innerScope, outerScope,
		"the two groups measure against different targets, which is the point of the fixture")

	// The inner group's OWN evidence: this is what its own selection reads.
	now := time.Now()
	f.storage.StoreHealthHistory("leaf-fast", innerScope, &adapter.URLTestHistory{Time: now, Delay: 10})
	f.storage.StoreHealthHistory("leaf-slow", innerScope, &adapter.URLTestHistory{Time: now, Delay: 900})

	// The OUTER group's evidence, in the outer group's scope, keyed by the LEAF tags - exactly what
	// the outer group's own round writes when it measures the nested group's leaves.
	f.storage.StoreHealthHistory("leaf-fast", outerScope, &adapter.URLTestHistory{Time: now, Delay: 10})
	f.storage.StoreHealthHistory("leaf-other", outerScope, &adapter.URLTestHistory{Time: now, Delay: 400})

	require.Nil(t, f.storage.LoadURLTestHistoryFor("inner-ut", outerScope),
		"a round measures leaves, never the group's own tag: the fixture must not hold such an entry, "+
			"or the test would pass for the wrong reason")

	inner.PerformUpdateCheck()
	require.Equal(t, "leaf-fast", inner.Selected(N.NetworkTCP).Tag(),
		"the inner group selects on its leaf's 10ms")

	require.Equal(t, "leaf-fast", RealTag(inner, N.NetworkTCP))

	outer.PerformUpdateCheck()
	require.Equal(t, "inner-ut", outer.Selected(N.NetworkTCP).Tag(),
		"the nested member is ranked by its LEAF's 10ms, which beats leaf-other's 400ms")
	require.Equal(t, "leaf-fast", RealTag(outer, N.NetworkTCP))

	conn, err := outer.DialContext(context.Background(), N.NetworkTCP, nestedTarget)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Equal(t, []string{"leaf-fast"}, fast.dialedTags(),
		"the ranked node and the dialled node must be the same object")
	require.Empty(t, slow.dialedTags())
	require.Empty(t, other.dialedTags())
}

// TestNestedChainAttachConnectionReachesEveryLevel is the group half of the interruption contract.
//
// The route layer registers one inbound connection with EVERY group in the resolved chain, so a
// switch at any level closes it. That only works if each level's AttachConnection is reachable and
// remembers the closer; a chain that registered only its outermost group would let an inner switch
// leave the connection running.
func TestNestedChainAttachConnectionReachesEveryLevel(t *testing.T) {
	f := newNestedTopology(t)
	leaf := f.leaf("leaf-a", C.TypeVLESS)
	f.leaf("leaf-b", C.TypeVLESS)
	inner := f.selector("inner-sel", true, "leaf-a", "leaf-b")
	outer := f.selector("outer", true, "inner-sel")
	f.start()
	t.Cleanup(f.closeAll)

	chain := []adapter.Outbound{outer, inner, leaf}
	require.Len(t, chain, 3)

	conn := &nestedConn{}
	var removers []func()
	for _, member := range chain[:2] {
		group, isGroup := member.(adapter.OutboundGroup)
		require.True(t, isGroup)
		removers = append(removers, group.AttachConnection(conn))
	}

	// Switching the INNER group must close a connection carried through the outer group.
	require.True(t, inner.SelectOutbound("leaf-b"))
	require.True(t, conn.interrupted(),
		"a switch of the inner group must interrupt the connections registered with it")

	// And the outer group, independently.
	second := &nestedConn{}
	for _, member := range chain[:2] {
		group, _ := member.(adapter.OutboundGroup)
		removers = append(removers, group.AttachConnection(second))
	}
	require.True(t, inner.SelectOutbound("leaf-a"))
	require.EqualValues(t, 1, second.closeCount.Load(),
		"exactly one interrupt per connection: the two levels must not both close it twice")

	for _, remove := range removers {
		remove()
	}
}

// TestNestedAttachConnectionTouchesTheInnerURLTest pins the idle-resource half.
//
// A connection carried through a nested URLTest group is that group's traffic, so registering it
// must mark the inner group active. Otherwise the outer group's traffic would let the inner group
// be treated as idle and its background checks parked while it is demonstrably carrying flows.
//
// The registration has to happen at EVERY level: an outer group's AttachConnection only knows about
// itself, so the route layer walks the resolved chain and attaches to each group in turn. This test
// pins both halves of that: the outer attachment alone is not enough, and the inner URLTest's own
// AttachConnection is what starts its background work.
func TestNestedAttachConnectionTouchesTheInnerURLTest(t *testing.T) {
	f := newNestedTopology(t)
	f.leaf("leaf-a", C.TypeVLESS)
	inner := f.urlTest("inner-ut", nestedLinkA, true, "leaf-a")
	outer := f.selector("outer", true, "inner-ut")
	f.start()
	t.Cleanup(f.closeAll)

	innerGroup := inner.currentGroup()
	// Touch only starts work on a started group. PostStart would run a probe against a target this
	// fixture cannot reach, so the started flag is set directly and nothing else is faked. lastActive
	// is set to now for the same reason: the loop's first act is an immediate check when the group
	// looks idle, and this test is about the ticker, not about a probe.
	innerGroup.access.Lock()
	innerGroup.started = true
	innerGroup.lastActive.Store(time.Now())
	innerGroup.access.Unlock()

	require.Nil(t, innerGroup.ticker, "the fixture must start with no background work")

	conn := &nestedConn{}

	// The outermost group alone does not reach the inner one.
	removeOuter := outer.AttachConnection(conn)
	defer removeOuter()
	innerGroup.access.Lock()
	touchedByOuter := innerGroup.ticker != nil
	innerGroup.access.Unlock()
	require.False(t, touchedByOuter,
		"an outer group's own AttachConnection speaks only for itself, which is why the route "+
			"layer walks the whole chain")

	// Attaching at the inner level - what the chain walk does - is what marks it active.
	removeInner := inner.AttachConnection(conn)
	defer removeInner()
	innerGroup.access.Lock()
	touchedByChain := innerGroup.ticker != nil
	innerGroup.access.Unlock()
	require.True(t, touchedByChain,
		"a connection registered with the chain is traffic through the inner group, so the "+
			"inner group must be touched; otherwise its checks stay parked while it carries flows")
}

// TestNestedResolutionDetectsCycles is the degenerate case: a configuration can describe a cycle.
//
// The traversal must report it, not follow it. The visited set is by IDENTITY, and there is no
// nesting-depth limit: a legal chain is as deep as the configuration makes it, so a fixed bound
// would refuse a legal topology.
func TestNestedResolutionDetectsCycles(t *testing.T) {
	groupA := &switchingGroup{tag: "cycle-a"}
	groupB := &switchingGroup{tag: "cycle-b"}
	groupA.selectOutbound(groupB)
	groupB.selectOutbound(groupA)

	done := make(chan error, 1)
	go func() {
		_, err := ResolveURLTestLeaf(groupA, N.NetworkTCP)
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "a cycle must be reported")
	case <-time.After(5 * time.Second):
		t.Fatal("resolution did not return for a cycle")
	}
	require.Empty(t, RealTag(groupA, N.NetworkTCP))
}

// TestNestedDeepChainIsNotCapped pins that no legitimate depth is refused.
//
// A fixed hop limit is the obvious way to bound a traversal and the wrong one: it turns a legal
// configuration into a routing failure. The chain here is deeper than any plausible constant and
// must still resolve to its leaf.
func TestNestedDeepChainIsNotCapped(t *testing.T) {
	const depth = 40

	leaf := &nestedLeaf{tag: "deep-leaf", typeName: C.TypeVLESS}
	var current adapter.Outbound = leaf
	for index := 0; index < depth; index++ {
		next := &switchingGroup{tag: "deep-" + strconv.Itoa(index)}
		next.selectOutbound(current)
		current = next
	}

	resolved, err := ResolveURLTestLeaf(current, N.NetworkTCP)
	require.NoError(t, err, "a legal chain of %d groups must resolve", depth)
	require.Same(t, adapter.Outbound(leaf), resolved)
	require.Equal(t, "deep-leaf", RealTag(current, N.NetworkTCP))
}

// TestNestedTopologyRejectsAnEmptyGroupAndAMissingMember pins the two configuration errors a chain
// can be built from, so neither is a silently empty group that resolves to nothing at dial time.
func TestNestedTopologyRejectsAnEmptyGroupAndAMissingMember(t *testing.T) {
	f := newNestedTopology(t)
	f.leaf("leaf-a", C.TypeVLESS)

	// An empty group has nothing to select, so it can never name a leaf.
	_, err := NewSelector(f.ctx, nil, log.NewNOPFactory().NewLogger("empty"), "empty", option.SelectorOutboundOptions{})
	require.Error(t, err, "a selector with no members must be refused when it is built")

	_, err = NewURLTest(f.ctx, nil, log.NewNOPFactory().NewLogger("empty-ut"), "empty-ut", option.URLTestOutboundOptions{
		URL: nestedLinkA, Interval: badoption.Duration(time.Minute), IdleTimeout: badoption.Duration(5 * time.Minute),
	})
	require.Error(t, err, "a urltest group with no members must be refused when it is built")

	// A declared member that no outbound provides is a start failure that names the member.
	created, err := NewSelector(f.ctx, nil, log.NewNOPFactory().NewLogger("missing"), "missing", option.SelectorOutboundOptions{
		Outbounds: []string{"leaf-a", "does-not-exist"},
	})
	require.NoError(t, err)
	startErr := created.(adapter.Lifecycle).Start(adapter.StartStateStart, &adapter.Scope{})
	require.Error(t, startErr, "a declared member that does not exist must fail the start")
	require.Contains(t, startErr.Error(), "does-not-exist",
		"the failure must name the member that is missing")

	createdURLTest, err := NewURLTest(f.ctx, nil, log.NewNOPFactory().NewLogger("missing-ut"), "missing-ut", option.URLTestOutboundOptions{
		Outbounds:   []string{"does-not-exist"},
		URL:         nestedLinkA,
		Interval:    badoption.Duration(time.Minute),
		IdleTimeout: badoption.Duration(5 * time.Minute),
	})
	require.NoError(t, err)
	startErr = createdURLTest.(adapter.Lifecycle).Start(adapter.StartStateStart, &adapter.Scope{})
	require.Error(t, startErr, "a urltest group with a missing member must fail the start")
	require.Contains(t, startErr.Error(), "does-not-exist")
}
