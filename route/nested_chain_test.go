package route

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Nested group resolution and interruption, asserted through the route path.
//
// # The two things this file pins
//
// RESOLUTION. `resolveOutbound` walks a group chain down to the leaf that will carry the flow and
// returns EVERY level. The leaf is what gets dialled, and the whole chain is what the attribution
// layers describe. A walk that stopped at the first level would hand the connection manager a
// group, and would describe the flow with a group's tag.
//
// INTERRUPTION. The route path dials the LEAF, not the groups: `r.connection.NewConnection` is
// given `chain[len(chain)-1]`. The groups' own `DialContext` wrappers - which is where a group
// normally registers a connection with its interrupt list - therefore never run. `registerInterrupt`
// is the only thing that attaches the inbound connection to each group in the chain, so a switch at
// ANY level closes it. Attaching only the outermost group leaves an inner switch unable to interrupt
// the connections it carries.
//
// # Why the groups are real
//
// Every topology below is built from `group.NewSelector` / `group.NewURLTest` and started through
// the real `Start`, wired by declared member tags resolved through an outbound manager. A test that
// hand-rolls a group double proves only that the double implements the interface.

// chainConn remembers whether it was closed. Interruption is observed as a close.
type chainConn struct {
	closes atomic.Int32
}

func (c *chainConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *chainConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *chainConn) Close() error                     { c.closes.Add(1); return nil }
func (c *chainConn) LocalAddr() net.Addr              { return nil }
func (c *chainConn) RemoteAddr() net.Addr             { return nil }
func (c *chainConn) SetDeadline(time.Time) error      { return nil }
func (c *chainConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chainConn) SetWriteDeadline(time.Time) error { return nil }

func (c *chainConn) interrupted() bool { return c.closes.Load() > 0 }

type chainPacketConn struct {
	conn *chainConn
}

func (c *chainPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *chainPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (c *chainPacketConn) Close() error                     { return c.conn.Close() }
func (c *chainPacketConn) LocalAddr() net.Addr              { return nil }
func (c *chainPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *chainPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chainPacketConn) SetWriteDeadline(time.Time) error { return nil }

// chainCall is one connection a leaf handed out, with the tag it was dialled under.
type chainCall struct {
	tag     string
	network string
	conn    *chainConn
}

// chainLeaf is a leaf that records the tag it was dialled under and the connections it handed out.
type chainLeaf struct {
	adapter.Outbound
	tag      string
	networks []string

	access sync.Mutex
	calls  []*chainCall
}

func newChainLeaf(tag string, networks ...string) *chainLeaf {
	if len(networks) == 0 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &chainLeaf{tag: tag, networks: networks}
}

func (o *chainLeaf) Type() string      { return "chain-leaf" }
func (o *chainLeaf) Tag() string       { return o.tag }
func (o *chainLeaf) Network() []string { return o.networks }

func (o *chainLeaf) DialContext(_ context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn := &chainConn{}
	o.record(&chainCall{tag: o.tag, network: N.NetworkName(network), conn: conn})
	return conn, nil
}

func (o *chainLeaf) ListenPacket(_ context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	conn := &chainConn{}
	o.record(&chainCall{tag: o.tag, network: N.NetworkUDP, conn: conn})
	return &chainPacketConn{conn: conn}, nil
}

func (o *chainLeaf) record(call *chainCall) {
	o.access.Lock()
	defer o.access.Unlock()
	o.calls = append(o.calls, call)
}

func (o *chainLeaf) dialedTags() []string {
	o.access.Lock()
	defer o.access.Unlock()
	tags := make([]string, 0, len(o.calls))
	for _, call := range o.calls {
		tags = append(tags, call.tag)
	}
	return tags
}

func (o *chainLeaf) dialCount() int {
	o.access.Lock()
	defer o.access.Unlock()
	return len(o.calls)
}

func (o *chainLeaf) lastConn() *chainConn {
	o.access.Lock()
	defer o.access.Unlock()
	if len(o.calls) == 0 {
		return nil
	}
	return o.calls[len(o.calls)-1].conn
}

// chainFlowHandle is a tun flow whose closure is observable.
type chainFlowHandle struct {
	closed atomic.Bool
}

func (h *chainFlowHandle) CloseFlow() { h.closed.Store(true) }

// nestedRouteFixture builds real groups over one outbound manager.
type nestedRouteFixture struct {
	t       testing.TB
	ctx     context.Context
	storage *urltest.HistoryStorage
	manager *routeGroupManager
	groups  []adapter.Lifecycle
}

func newNestedRouteFixture(t testing.TB) *nestedRouteFixture {
	t.Helper()
	manager := &routeGroupManager{members: make(map[string]adapter.Outbound)}
	storage := urltest.NewHistoryStorage()
	ctx := pause.WithDefaultManager(
		service.ContextWithPtr(
			service.ContextWith[adapter.OutboundManager](context.Background(), manager),
			storage))
	return &nestedRouteFixture{t: t, ctx: ctx, storage: storage, manager: manager}
}

func (f *nestedRouteFixture) add(outbound adapter.Outbound) {
	f.manager.members[outbound.Tag()] = outbound
	if lifecycle, isLifecycle := outbound.(adapter.Lifecycle); isLifecycle {
		f.groups = append(f.groups, lifecycle)
	}
}

func (f *nestedRouteFixture) leaf(tag string, networks ...string) *chainLeaf {
	leaf := newChainLeaf(tag, networks...)
	f.add(leaf)
	return leaf
}

func (f *nestedRouteFixture) selector(tag string, interrupt bool, members ...string) *group.Selector {
	f.t.Helper()
	created, err := group.NewSelector(f.ctx, nil, log.NewNOPFactory().NewLogger(tag), tag, option.SelectorOutboundOptions{
		Outbounds:                 members,
		InterruptExistConnections: interrupt,
	})
	require.NoError(f.t, err)
	selector, isSelector := created.(*group.Selector)
	require.True(f.t, isSelector)
	f.add(selector)
	return selector
}

func (f *nestedRouteFixture) urlTest(tag string, link string, interrupt bool, members ...string) *group.URLTest {
	f.t.Helper()
	created, err := group.NewURLTest(f.ctx, nil, log.NewNOPFactory().NewLogger(tag), tag, option.URLTestOutboundOptions{
		Outbounds:                 members,
		URL:                       link,
		Interval:                  badoption.Duration(time.Minute),
		IdleTimeout:               badoption.Duration(5 * time.Minute),
		InterruptExistConnections: interrupt,
	})
	require.NoError(f.t, err)
	wrapper, isURLTest := created.(*group.URLTest)
	require.True(f.t, isURLTest)
	f.add(wrapper)
	return wrapper
}

// start runs every registered group's Start, inner to outer.
func (f *nestedRouteFixture) start() {
	f.t.Helper()
	for _, lifecycle := range f.groups {
		require.NoError(f.t, lifecycle.Start(adapter.StartStateStart, &adapter.Scope{}))
	}
}

func (f *nestedRouteFixture) closeAll() {
	for _, lifecycle := range f.groups {
		if closer, isCloser := lifecycle.(io.Closer); isCloser {
			_ = closer.Close()
		}
	}
}

const (
	nestedRouteLink = "https://probe.example/generate_204"
)

func nestedRouteMetadata(network string) *adapter.InboundContext {
	return &adapter.InboundContext{Network: network}
}

// nestedRouteShape is one group topology.
type nestedRouteShape struct {
	name      string
	wantChain []string
	build     func(f *nestedRouteFixture) adapter.Outbound
}

func nestedRouteShapes() []nestedRouteShape {
	return []nestedRouteShape{
		{
			name:      "selector to urltest to leaf",
			wantChain: []string{"outer", "inner-ut", "leaf-a"},
			build: func(f *nestedRouteFixture) adapter.Outbound {
				f.leaf("leaf-a")
				f.urlTest("inner-ut", nestedRouteLink, true, "leaf-a")
				return f.selector("outer", true, "inner-ut")
			},
		},
		{
			name:      "selector to urltest to selector to leaf",
			wantChain: []string{"outer", "mid-ut", "inner-sel", "leaf-a"},
			build: func(f *nestedRouteFixture) adapter.Outbound {
				f.leaf("leaf-a")
				f.selector("inner-sel", true, "leaf-a")
				f.urlTest("mid-ut", nestedRouteLink, true, "inner-sel")
				return f.selector("outer", true, "mid-ut")
			},
		},
		{
			name:      "selector urltest selector urltest to leaf",
			wantChain: []string{"outer", "ut-outer", "sel-mid", "ut-inner", "leaf-a"},
			build: func(f *nestedRouteFixture) adapter.Outbound {
				f.leaf("leaf-a")
				f.urlTest("ut-inner", nestedRouteLink, true, "leaf-a")
				f.selector("sel-mid", true, "ut-inner")
				f.urlTest("ut-outer", nestedRouteLink, true, "sel-mid")
				return f.selector("outer", true, "ut-outer")
			},
		},
	}
}

// TestResolveOutboundChainNamesEveryLevelAndTheLeaf is the resolution identity on the data path.
func TestResolveOutboundChainNamesEveryLevelAndTheLeaf(t *testing.T) {
	for _, shape := range nestedRouteShapes() {
		t.Run(shape.name, func(t *testing.T) {
			f := newNestedRouteFixture(t)
			outer := shape.build(f)
			f.start()
			t.Cleanup(f.closeAll)

			metadata := nestedRouteMetadata(N.NetworkTCP)
			chain, err := resolveOutbound(outer, metadata, N.NetworkTCP, true)
			require.NoError(t, err)

			tags := make([]string, 0, len(chain))
			for _, member := range chain {
				tags = append(tags, member.Tag())
			}
			require.Equal(t, shape.wantChain, tags,
				"the chain must name every level, outermost first, and end at the leaf")

			require.Same(t, outer, chain[0])
			leaf, isLeaf := chain[len(chain)-1].(*chainLeaf)
			require.True(t, isLeaf, "the last object in the chain must be the leaf")

			for index, member := range chain[:len(chain)-1] {
				_, isGroup := member.(adapter.OutboundGroup)
				require.True(t, isGroup,
					"chain[%d] (%s) is not a group, so registerInterrupt would not attach to it",
					index, member.Tag())
			}

			// The node the chain names is the node that dials.
			conn, err := chain[len(chain)-1].DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("198.51.100.7:443"))
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			require.Equal(t, []string{shape.wantChain[len(shape.wantChain)-1]}, leaf.dialedTags())
		})
	}
}

// TestResolveOutboundIsNetworkAware covers the network-aware walk.
func TestResolveOutboundIsNetworkAware(t *testing.T) {
	f := newNestedRouteFixture(t)
	tcpLeaf := f.leaf("leaf-tcp", N.NetworkTCP)
	udpLeaf := f.leaf("leaf-udp", N.NetworkUDP)
	inner := f.urlTest("inner-ut", nestedRouteLink, true, "leaf-tcp", "leaf-udp")
	outer := f.selector("outer", true, "inner-ut")
	f.start()
	t.Cleanup(f.closeAll)

	inner.PerformUpdateCheck()

	tcpChain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Same(t, adapter.Outbound(tcpLeaf), tcpChain[len(tcpChain)-1])

	udpChain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkUDP), N.NetworkUDP, true)
	require.NoError(t, err)
	require.Same(t, adapter.Outbound(udpLeaf), udpChain[len(udpChain)-1])
	require.NotSame(t, tcpChain[len(tcpChain)-1], udpChain[len(udpChain)-1],
		"a network-blind walk would name the same node for a TCP flow and a UDP session")
}

// TestRegisterInterruptCoversEveryGroupInTheChain is the interruption contract for TCP.
//
// The route path dials the leaf, so no group's DialContext ever runs and no group registers the
// connection by itself. registerInterrupt is the only registration there is, and a switch at ANY
// level must close the connection.
func TestRegisterInterruptCoversEveryGroupInTheChain(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	f.leaf("leaf-b")
	inner := f.selector("inner-sel", true, "leaf-a", "leaf-b")
	outer := f.selector("outer", true, "inner-sel", "leaf-b")
	f.start()
	t.Cleanup(f.closeAll)

	metadata := nestedRouteMetadata(N.NetworkTCP)
	chain, err := resolveOutbound(outer, metadata, N.NetworkTCP, true)
	require.NoError(t, err)
	require.Len(t, chain, 3)

	conn := &chainConn{}
	remove := registerInterrupt(chain, conn, func(error) {})
	require.NotNil(t, remove)
	t.Cleanup(func() { remove(nil) })

	// A switch of the INNER group must interrupt the connection, even though the connection was
	// resolved from the outer one.
	require.True(t, inner.SelectOutbound("leaf-b"))
	require.True(t, conn.interrupted(),
		"a switch of the inner group must interrupt the connections that traverse it; the route "+
			"path dials the leaf, so registerInterrupt is the only place that registration happens")

	// The outer group's own switch must interrupt too.
	conn2 := &chainConn{}
	remove2 := registerInterrupt(chain, conn2, func(error) {})
	t.Cleanup(func() { remove2(nil) })
	require.True(t, outer.SelectOutbound("leaf-b"))
	require.True(t, conn2.interrupted(), "a switch of the outer group must interrupt as well")
}

// TestRegisterInterruptCoversTheUDPPath is the same contract for packet sessions.
func TestRegisterInterruptCoversTheUDPPath(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	f.leaf("leaf-b")
	inner := f.selector("inner-sel", true, "leaf-a", "leaf-b")
	outer := f.selector("outer", true, "inner-sel", "leaf-b")
	f.start()
	t.Cleanup(f.closeAll)

	chain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkUDP), N.NetworkUDP, true)
	require.NoError(t, err)
	require.Len(t, chain, 3)
	leaf, isLeaf := chain[len(chain)-1].(*chainLeaf)
	require.True(t, isLeaf)

	packetConn, err := leaf.ListenPacket(context.Background(), M.ParseSocksaddr("198.51.100.7:53"))
	require.NoError(t, err)
	require.Equal(t, 1, leaf.dialCount())

	remove := registerInterrupt(chain, packetConn, func(error) {})
	t.Cleanup(func() { remove(nil) })
	require.False(t, leaf.lastConn().interrupted())

	require.True(t, inner.SelectOutbound("leaf-b"))
	require.True(t, leaf.lastConn().interrupted(),
		"a switch of the inner group must close the UDP session that traverses it")
}

// TestSwitchingOneGroupDoesNotInterruptTheOtherGroupsConnections is the isolation contract.
//
// Two outer groups share one leaf object. A switch of the first group's inner group must close the
// first group's connections and leave the second group's alone: the shared leaf is not a shared
// interrupt list, and the registration is per group.
func TestSwitchingOneGroupDoesNotInterruptTheOtherGroupsConnections(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("shared")
	f.leaf("spare")
	innerA := f.selector("inner-a", true, "shared", "spare")
	innerB := f.selector("inner-b", true, "shared", "spare")
	outerA := f.selector("outer-a", true, "inner-a")
	outerB := f.selector("outer-b", true, "inner-b")
	f.start()
	t.Cleanup(f.closeAll)

	chainA, err := resolveOutbound(outerA, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	chainB, err := resolveOutbound(outerB, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Same(t, chainA[len(chainA)-1], chainB[len(chainB)-1],
		"the fixture must genuinely share one leaf object between the two chains")

	connA := &chainConn{}
	removeA := registerInterrupt(chainA, connA, func(error) {})
	t.Cleanup(func() { removeA(nil) })
	connB := &chainConn{}
	removeB := registerInterrupt(chainB, connB, func(error) {})
	t.Cleanup(func() { removeB(nil) })

	require.True(t, innerA.SelectOutbound("spare"))

	require.True(t, connA.interrupted(),
		"the switching group's own connection must be interrupted")
	require.False(t, connB.interrupted(),
		"a group switching must not interrupt another group's connections, even when the two "+
			"groups share the same leaf node")
	require.EqualValues(t, 1, connA.closes.Load())
	require.EqualValues(t, 0, connB.closes.Load())

	// The second chain's own group still owns its connection: the registration is per group, not a
	// property of the shared leaf.
	require.True(t, innerB.SelectOutbound("spare"))
	require.True(t, connB.interrupted(),
		"the second group's own switch must still interrupt its own connection")
}

// TestInnerURLTestSwitchInterruptsThroughTheOuterGroup drives the switch through a URLTest's real
// selection update rather than through an explicit selection, because that is how an inner group
// moves on its own.
func TestInnerURLTestSwitchInterruptsThroughTheOuterGroup(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	f.leaf("leaf-b")
	inner := f.urlTest("inner-ut", nestedRouteLink, true, "leaf-a", "leaf-b")
	outer := f.selector("outer", true, "inner-ut")
	f.start()
	t.Cleanup(f.closeAll)

	scope := inner.MeasurementScope()
	now := time.Now()
	f.storage.StoreHealthHistory("leaf-a", scope, &adapter.URLTestHistory{Time: now, Delay: 10})
	f.storage.StoreHealthHistory("leaf-b", scope, &adapter.URLTestHistory{Time: now, Delay: 900})

	// The first update installs a selection; it is not a switch and must not interrupt.
	inner.PerformUpdateCheck()
	require.Equal(t, "leaf-a", inner.Selected(N.NetworkTCP).Tag())

	chain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "leaf-a", chain[len(chain)-1].Tag())

	conn := &chainConn{}
	remove := registerInterrupt(chain, conn, func(error) {})
	t.Cleanup(func() { remove(nil) })

	// The inner group now moves to the other node.
	f.storage.StoreHealthHistory("leaf-a", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 900})
	f.storage.StoreHealthHistory("leaf-b", scope, &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	inner.PerformUpdateCheck()
	require.Equal(t, "leaf-b", inner.Selected(N.NetworkTCP).Tag())

	require.True(t, conn.interrupted(),
		"an inner URLTest moving its selection must interrupt the connections it carries")

	// The NEW connection goes to the new node.
	nextChain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "leaf-b", nextChain[len(nextChain)-1].Tag())
}

// TestNestedFlowInterrupterCoversEveryGroupInTheChain is the same contract on the pre-match flow
// path, which owns a tun flow rather than a net.Conn.
func TestNestedFlowInterrupterCoversEveryGroupInTheChain(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	f.leaf("leaf-b")
	inner := f.selector("inner-sel", true, "leaf-a", "leaf-b")
	outer := f.selector("outer", true, "inner-sel", "leaf-b")
	f.start()
	t.Cleanup(f.closeAll)

	chain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)

	interrupter := newFlowInterrupter(chain)
	require.NotNil(t, interrupter)

	handle := &chainFlowHandle{}
	interrupter.AttachFlow(handle)
	require.False(t, handle.closed.Load())

	require.True(t, inner.SelectOutbound("leaf-b"))
	require.True(t, handle.closed.Load(),
		"a switch of an inner group must close the flow it carries")

	// Closing the flow detaches it from every group, so a later switch must not close it again.
	handle2 := &chainFlowHandle{}
	interrupter.AttachFlow(handle2)
	interrupter.CloseFlow(tun.FlowCloseFinished)
	require.False(t, handle2.closed.Load())
	require.True(t, inner.SelectOutbound("leaf-a"))
	require.False(t, handle2.closed.Load(),
		"a flow that has already closed must be detached from the chain")
}

// TestResolveOutboundReportsACycleRatherThanLooping is the degenerate case.
//
// A cycle in the group graph must be reported. The walk is unbounded by design - a legal chain is
// as deep as the configuration makes it, and a fixed hop limit would turn a legal topology into a
// routing failure - so the guard has to be a record of what has been visited.
func TestResolveOutboundReportsACycleRatherThanLooping(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.selector("cycle-a", true, "cycle-b")
	f.selector("cycle-b", true, "cycle-a")
	f.start()

	cycleA, loaded := f.manager.members["cycle-a"]
	require.True(t, loaded)

	done := make(chan error, 1)
	go func() {
		_, err := resolveOutbound(cycleA, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err, "a cyclic group graph must be reported as an error")
		t.Logf("cycle reported as: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("resolveOutbound did not return for a cyclic group graph: the walk has no record " +
			"of what it has visited, so it follows the cycle forever instead of reporting it")
	}
}

// TestResolveOutboundRejectsAGroupWithNoUsableMember covers "no available member" and the network
// capability check.
func TestResolveOutboundRejectsAGroupWithNoUsableMember(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-tcp", N.NetworkTCP)
	outer := f.selector("outer", true, "leaf-tcp")
	f.start()
	t.Cleanup(f.closeAll)

	// The selector answers with a TCP-only member; the UDP walk must refuse it rather than dial.
	_, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkUDP), N.NetworkUDP, true)
	require.Error(t, err, "a chain that ends at a node without the network must be refused")
	require.Contains(t, err.Error(), "UDP")
}

// TestNestedGroupDeclaringTheSameMemberTwiceStillResolves covers the duplicate-member case.
//
// A group may list one member twice. That is one edge, and it must not make resolution ambiguous,
// double-register the interruption, or dial twice.
func TestNestedGroupDeclaringTheSameMemberTwiceStillResolves(t *testing.T) {
	f := newNestedRouteFixture(t)
	leaf := f.leaf("leaf-a")
	inner := f.selector("inner-sel", true, "leaf-a", "leaf-a")
	outer := f.selector("outer", true, "inner-sel")
	f.start()
	t.Cleanup(f.closeAll)

	chain, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, []string{"outer", "inner-sel", "leaf-a"}, chainTags(chain))

	conn := &chainConn{}
	remove := registerInterrupt(chain, conn, func(error) {})
	t.Cleanup(func() { remove(nil) })

	// Re-selecting the member the group already has is not a switch, so it must not interrupt, and
	// a duplicated declaration must not have registered the connection twice either.
	require.True(t, inner.SelectOutbound("leaf-a"))
	require.EqualValues(t, 0, conn.closes.Load())
	require.Equal(t, 0, leaf.dialCount())
}

// TestNestedResolutionSurvivesAnInnerClose is the lifecycle degenerate case.
//
// Closing the inner group while the outer one is alive must make resolution report that it cannot
// be resolved, promptly and without a deadlock - not return a stale member and not hang.
func TestNestedResolutionSurvivesAnInnerClose(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	inner := f.urlTest("inner-ut", nestedRouteLink, true, "leaf-a")
	outer := f.selector("outer", true, "inner-ut")
	f.start()
	t.Cleanup(f.closeAll)

	require.NoError(t, inner.Close())

	done := make(chan error, 1)
	go func() {
		_, err := resolveOutbound(outer, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err,
			"a closed inner group has no selection, so the chain cannot resolve to a leaf")
	case <-time.After(5 * time.Second):
		t.Fatal("resolution deadlocked against a closed inner group")
	}
}

func chainTags(chain []adapter.Outbound) []string {
	tags := make([]string, 0, len(chain))
	for _, member := range chain {
		tags = append(tags, member.Tag())
	}
	return tags
}

// TestNestedChainInterruptIsSafeUnderConcurrentSwitchesAndResolutions runs the attach / resolve /
// switch interleavings under the race detector.
//
// The data path resolves a chain on every connection while a control-plane switch may be moving a
// group underneath it, and the connection it just registered may be interrupted before the
// registration returns. Three things have to hold at once: resolution never fails or deadlocks, a
// connection is interrupted by a switch of ITS chain, and a switch of one chain never touches
// another chain's connections even when both end at the same leaf object.
func TestNestedChainInterruptIsSafeUnderConcurrentSwitchesAndResolutions(t *testing.T) {
	f := newNestedRouteFixture(t)
	f.leaf("leaf-a")
	f.leaf("leaf-b")
	innerA := f.selector("inner-a", true, "leaf-a", "leaf-b")
	f.selector("inner-b", true, "leaf-a", "leaf-b")
	outerA := f.selector("outer-a", true, "inner-a", "leaf-b")
	outerB := f.selector("outer-b", true, "inner-b", "leaf-b")
	f.start()
	t.Cleanup(f.closeAll)

	chainA, err := resolveOutbound(outerA, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	chainB, err := resolveOutbound(outerB, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Same(t, chainA[len(chainA)-1], chainB[len(chainB)-1],
		"the two chains must share one leaf object for the isolation half to mean anything")

	const registrations = 32
	connsA := make([]*chainConn, registrations)
	connsB := make([]*chainConn, registrations)
	removers := make([]N.CloseHandlerFunc, 0, registrations*6)
	for index := range registrations {
		connsA[index] = &chainConn{}
		removers = append(removers, registerInterrupt(chainA, connsA[index], func(error) {}))
		connsB[index] = &chainConn{}
		removers = append(removers, registerInterrupt(chainB, connsB[index], func(error) {}))
	}
	t.Cleanup(func() {
		for _, remove := range removers {
			remove(nil)
		}
	})

	var wait sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, resolveErr := resolveOutbound(outerA, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true); resolveErr != nil {
					t.Errorf("resolution failed while a group was switching: %v", resolveErr)
					return
				}
				if _, resolveErr := resolveOutbound(outerB, nestedRouteMetadata(N.NetworkTCP), N.NetworkTCP, true); resolveErr != nil {
					t.Errorf("resolution failed while another chain's group was switching: %v", resolveErr)
					return
				}
			}
		}()
	}

	// Only group A's chain moves.
	for index := range 50 {
		target := "leaf-a"
		if index%2 == 1 {
			target = "leaf-b"
		}
		require.True(t, innerA.SelectOutbound(target))
	}
	close(stop)
	wait.Wait()

	for index := range registrations {
		require.True(t, connsA[index].interrupted(),
			"connection %d of the chain whose inner group switched must be interrupted", index)
		require.False(t, connsB[index].interrupted(),
			"connection %d of the untouched chain must survive, though both chains share the leaf", index)
	}
}
