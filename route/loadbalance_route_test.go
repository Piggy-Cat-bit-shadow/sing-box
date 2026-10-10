package route

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Load balancing, asserted through the route path.
//
// # Why these tests exist in addition to the group's own
//
// A balancing group whose strategy is never consulted, or whose answer is discarded before
// the connection is made, passes every test that asks the group what it would choose. The
// failure mode of this feature is an empty semantic: the configuration looks like it
// balances, and the bytes go somewhere else. So these tests resolve the chain through the
// real resolver - the same function the TCP and UDP paths call, with the same commit flag -
// and then DIAL what the chain names, counting the dials per member.
//
// Selected member, resolved chain leaf and dialed member are asserted to be the same object
// for every flow.

// routeRecordingOutbound is a member that records the connections and packet connections it
// is asked for.
type routeRecordingOutbound struct {
	adapter.Outbound
	tag      string
	networks []string
	access   sync.Mutex
	dials    int
	packets  int
	bytes    int
	// dialErr, when set, is what DialContext reports instead of opening a connection. It
	// exists so the failover path can be driven through the same stub the other route tests
	// use rather than through a parallel set of doubles.
	dialErr error
}

func newRouteRecordingOutbound(tag string, networks ...string) *routeRecordingOutbound {
	if len(networks) == 0 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	return &routeRecordingOutbound{tag: tag, networks: networks}
}

func (o *routeRecordingOutbound) Type() string      { return "recording" }
func (o *routeRecordingOutbound) Tag() string       { return o.tag }
func (o *routeRecordingOutbound) Network() []string { return o.networks }

// Dependencies is declared explicitly rather than promoted from the embedded adapter.Outbound.
//
// The embedded field is nil in every fixture in this package, so the promoted method dereferences a
// nil interface and panics. That was invisible while only the dial path used these objects; a
// read-only walk of the object graph reads Dependencies() on every hop - which is what a detour
// edge IS - so the promoted method would make every diagnostic over these fixtures crash.
// Declaring it with the correct answer, no detour, is what the fixture's own contract already
// implied.
func (o *routeRecordingOutbound) Dependencies() []string { return nil }

func (o *routeRecordingOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	o.access.Lock()
	o.dials++
	err := o.dialErr
	o.access.Unlock()
	if err != nil {
		return nil, err
	}
	return &routeStubConn{}, nil
}

func (o *routeRecordingOutbound) setDialError(err error) {
	o.access.Lock()
	o.dialErr = err
	o.access.Unlock()
}

func (o *routeRecordingOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	o.access.Lock()
	o.packets++
	o.access.Unlock()
	return &routeRecordingPacketConn{owner: o}, nil
}

func (o *routeRecordingOutbound) dialCount() int {
	o.access.Lock()
	defer o.access.Unlock()
	return o.dials
}

func (o *routeRecordingOutbound) packetCount() int {
	o.access.Lock()
	defer o.access.Unlock()
	return o.packets
}

func (o *routeRecordingOutbound) datagramCount() int {
	o.access.Lock()
	defer o.access.Unlock()
	return o.bytes
}

type routeStubConn struct{ net.Conn }

func (c *routeStubConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *routeStubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *routeStubConn) Close() error                     { return nil }
func (c *routeStubConn) LocalAddr() net.Addr              { return nil }
func (c *routeStubConn) RemoteAddr() net.Addr             { return nil }
func (c *routeStubConn) SetDeadline(time.Time) error      { return nil }
func (c *routeStubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *routeStubConn) SetWriteDeadline(time.Time) error { return nil }

type routeRecordingPacketConn struct {
	net.PacketConn
	owner *routeRecordingOutbound
}

func (c *routeRecordingPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	c.owner.access.Lock()
	c.owner.bytes++
	c.owner.access.Unlock()
	return len(payload), nil
}

func (c *routeRecordingPacketConn) Close() error { return nil }

// routeGroupManager resolves group members.
type routeGroupManager struct {
	adapter.OutboundManager
	members map[string]adapter.Outbound
}

func (m *routeGroupManager) Outbounds() []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(m.members))
	for _, member := range m.members {
		outbounds = append(outbounds, member)
	}
	return outbounds
}

func (m *routeGroupManager) Outbound(tag string) (adapter.Outbound, bool) {
	member, loaded := m.members[tag]
	return member, loaded
}

// newRouteLoadBalance builds a started balancing group over the given members.
func newLoadBalanceRouteFixture(t testing.TB, options option.LoadBalanceOutboundOptions, members ...*routeRecordingOutbound) (adapter.Outbound, *urltest.HistoryStorage) {
	t.Helper()
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: make(map[string]adapter.Outbound, len(members))}
	tags := make([]string, 0, len(members))
	for _, member := range members {
		manager.members[member.Tag()] = member
		tags = append(tags, member.Tag())
	}
	if len(options.Outbounds) == 0 {
		options.Outbounds = tags
	}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	created, err := group.NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("loadbalance"), "lb", options)
	require.NoError(t, err)
	loadBalance, isLoadBalance := created.(*group.LoadBalance)
	require.True(t, isLoadBalance)
	require.NoError(t, loadBalance.Start(adapter.StartStateStart, &adapter.Scope{}))
	t.Cleanup(func() {
		require.NoError(t, loadBalance.Close())
	})
	return created, service.PtrFromContext[urltest.HistoryStorage](ctx)
}

// dialThroughRoute resolves the chain the way the TCP path does and dials the leaf the chain
// names, returning the tag that was actually dialed.
//
// This is the whole point of the file: the tag returned is the member whose DialContext ran,
// not the member the resolver said it would use.
func dialThroughRoute(t testing.TB, outbound adapter.Outbound, metadata *adapter.InboundContext, network string, commit bool) (string, []adapter.Outbound) {
	t.Helper()
	chain, err := resolveOutbound(outbound, metadata, network, commit)
	require.NoError(t, err)
	leaf := chain[len(chain)-1]
	if network == N.NetworkUDP {
		packetConn, err := leaf.ListenPacket(context.Background(), M.ParseSocksaddr("93.184.216.34:443"))
		require.NoError(t, err)
		require.NoError(t, packetConn.Close())
	} else {
		conn, err := leaf.DialContext(context.Background(), network, M.ParseSocksaddr("93.184.216.34:443"))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	return leaf.Tag(), chain
}

func lbMetadata(network string, domain string, source string) *adapter.InboundContext {
	metadata := &adapter.InboundContext{Network: network}
	if domain != "" {
		metadata.Domain = domain
	}
	if source != "" {
		metadata.Source = M.ParseSocksaddrHostPort(source, 40000)
	}
	return metadata
}

// loadBalanceCursor reads the group's committed-decision counter, which is the oracle for
// "how many decisions has this group actually made".
func loadBalanceCursor(t *testing.T, outbound adapter.Outbound) uint64 {
	t.Helper()
	return outbound.(*group.LoadBalance).CommittedSelections()
}

func fourRouteMembers() []*routeRecordingOutbound {
	return []*routeRecordingOutbound{
		newRouteRecordingOutbound("A"),
		newRouteRecordingOutbound("B"),
		newRouteRecordingOutbound("C"),
		newRouteRecordingOutbound("D"),
	}
}

// --- round robin through the route path -------------------------------------------------

// TestLoadBalanceRouteRotatesTheDialedMember is the behavioural test the feature stands or
// falls on: eight flows resolved through the route path dial A B C D A B C D.
func TestLoadBalanceRouteRotatesTheDialedMember(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	expected := []string{"A", "B", "C", "D", "A", "B", "C", "D"}
	dialed := make([]string, 0, len(expected))
	for i := 0; i < len(expected); i++ {
		tag, _ := dialThroughRoute(t, outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
		dialed = append(dialed, tag)
	}
	require.Equal(t, expected, dialed,
		"the sequence of members that were actually dialed, not the sequence the group would report")

	// And the dials landed on the members the sequence names.
	for i, member := range members {
		require.Equal(t, 2, member.dialCount(), "member %s at position %d", member.Tag(), i)
	}
}

// TestLoadBalanceRoutePreMatchDoesNotConsumeASelection is the double-selection test.
//
// The pre-match path resolves the same chain with commit false for a verdict that may be
// discarded, and the connection path then resolves it again. If the preview consumed the
// rotation, the committed sequence would be A A C C and two flows would share one slot.
func TestLoadBalanceRoutePreMatchDoesNotConsumeASelection(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	committed := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		metadata := lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9")

		// The preview, exactly as preMatchFlow issues it: the chain is resolved for the
		// bypass verdict and no connection is made from it.
		previewChain, err := resolveOutbound(outbound, metadata, N.NetworkTCP, false)
		require.NoError(t, err)
		previewTag := previewChain[len(previewChain)-1].Tag()

		// The connection the flow actually makes.
		tag, _ := dialThroughRoute(t, outbound, metadata, N.NetworkTCP, true)
		require.Equal(t, previewTag, tag,
			"flow %d: the pre-match verdict named a member the connection did not use", i+1)
		committed = append(committed, tag)
	}
	require.Equal(t, []string{"A", "B", "C", "D", "A", "B", "C", "D"}, committed)
}

// TestLoadBalanceRouteChainLeafMatchesTheDialedMember is the drift check: what the chain
// publishes to the tracker is what was dialed.
func TestLoadBalanceRouteChainLeafMatchesTheDialedMember(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	for i := 0; i < 8; i++ {
		dialed, chain := dialThroughRoute(t, outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
		require.Equal(t, outbound.Tag(), chain[0].Tag(), "the chain starts at the outbound the route matched")
		require.Equal(t, dialed, chain[len(chain)-1].Tag(),
			"the leaf the chain publishes must be the member that was dialed")
		require.Len(t, chain, 2, "a group and its leaf")
	}
}

// --- UDP ---------------------------------------------------------------------------------

// TestLoadBalanceRouteUdpSessionStaysOnOneMember is the per-packet tripwire.
//
// A UDP session resolves once, and every datagram of that session leaves through the member
// it resolved to. Selecting per datagram would scatter one session across members, changing
// the source address under NAT, QUIC and DNS.
func TestLoadBalanceRouteUdpSessionStaysOnOneMember(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	for session := 0; session < 4; session++ {
		metadata := lbMetadata(N.NetworkUDP, "example.com", "192.168.1.9")
		chain, err := resolveOutbound(outbound, metadata, N.NetworkUDP, true)
		require.NoError(t, err)
		leaf := chain[len(chain)-1]

		packetConn, err := leaf.ListenPacket(context.Background(), M.ParseSocksaddr("93.184.216.34:443"))
		require.NoError(t, err)
		for datagram := 0; datagram < 100; datagram++ {
			_, err = packetConn.WriteTo([]byte("datagram"), nil)
			require.NoError(t, err)
		}
		require.NoError(t, packetConn.Close())
	}

	require.Equal(t, uint64(4), loadBalanceCursor(t, outbound),
		"one committed decision per session: a selection made per datagram would advance this 400 times")

	total := 0
	for _, member := range members {
		require.Equal(t, 1, member.packetCount(), "member %s served %d sessions", member.Tag(), member.packetCount())
		require.Equal(t, 100, member.datagramCount(),
			"member %s received %d of the 100 datagrams of the session it served", member.Tag(), member.datagramCount())
		total += member.datagramCount()
	}
	require.Equal(t, 400, total, "every datagram of every session reached exactly one member")
}

// --- nested groups ----------------------------------------------------------------------

// TestLoadBalanceRouteNestedSelectorResolvesToAStableLeaf covers a balancing group inside
// another group: the outer choice is made once and the inner one follows the flow.
func TestLoadBalanceRouteNestedSelectorResolvesToAStableLeaf(t *testing.T) {
	members := fourRouteMembers()
	inner, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: map[string]adapter.Outbound{"lb": inner}}
	for _, member := range members {
		manager.members[member.Tag()] = member
	}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	createdSelector, err := group.NewSelector(ctx, nil, log.NewNOPFactory().NewLogger("selector"), "outer", option.SelectorOutboundOptions{
		Outbounds: []string{"lb"},
		Default:   "lb",
	})
	require.NoError(t, err)
	selector, isSelector := createdSelector.(*group.Selector)
	require.True(t, isSelector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))
	// A Selector owns no background work, so there is nothing to tear down; the balancing
	// group inside it is closed by its own cleanup.

	dialed := make([]string, 0, 4)
	for i := 0; i < 4; i++ {
		tag, chain := dialThroughRoute(t, selector, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
		require.Len(t, chain, 3, "outer group, inner group, leaf")
		require.Equal(t, "outer", chain[0].Tag())
		require.Equal(t, "lb", chain[1].Tag())
		require.Equal(t, tag, chain[2].Tag(), "the leaf is the member that was dialed")
		dialed = append(dialed, tag)
	}
	require.Equal(t, []string{"A", "B", "C", "D"}, dialed,
		"the inner group balances the flows the outer group passes it, one decision per flow")
}

// --- control plane integration ----------------------------------------------------------

// TestLoadBalanceRouteTrafficClassFollowsTheResolvedChain is the fork-specific integration:
// the class is computed over the chain the flow actually took, including the member, so two
// flows through one group on different members can carry different classes.
func TestLoadBalanceRouteTrafficClassFollowsTheResolvedChain(t *testing.T) {
	members := []*routeRecordingOutbound{
		newRouteRecordingOutbound("proxy-a"),
		newRouteRecordingOutbound("bulk-node"),
	}
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	// A class per member, so the class can only be right if it follows the resolved chain.
	policies := TrafficClassPolicies{
		"proxy-a":   option.TrafficClassPolicy{Class: trafficclass.ClassInteractive},
		"bulk-node": option.TrafficClassPolicy{Class: trafficclass.ClassBulk},
	}

	chain, err := resolveOutbound(outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "proxy-a", chain[len(chain)-1].Tag())
	require.Equal(t, trafficclass.ClassInteractive, resolveTrafficClass(chain, policies))

	chain, err = resolveOutbound(outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "bulk-node", chain[len(chain)-1].Tag())
	require.Equal(t, trafficclass.ClassBulk, resolveTrafficClass(chain, policies),
		"the class must be read from the member this flow got, not from the group")

	// The class does not leak between flows: the third flow lands on proxy-a and is classed on
	// its own chain rather than inheriting the bulk class of the flow before it.
	chain, err = resolveOutbound(outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "proxy-a", chain[len(chain)-1].Tag())
	require.Equal(t, trafficclass.ClassInteractive, resolveTrafficClass(chain, policies),
		"a previous flow's class must not be inherited")

	// An explicit policy on the group is the outermost statement and wins, which is the
	// existing precedence: the group is scanned before its member.
	groupPolicy := TrafficClassPolicies{
		"lb":        option.TrafficClassPolicy{Class: trafficclass.ClassBulk},
		"proxy-a":   option.TrafficClassPolicy{Class: trafficclass.ClassInteractive},
		"bulk-node": option.TrafficClassPolicy{Class: trafficclass.ClassDefault},
	}
	chain, err = resolveOutbound(outbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, trafficclass.ClassBulk, resolveTrafficClass(chain, groupPolicy))

	// And the automatic rule still reaches the member through the group when nothing is
	// explicit: the resolver walks outermost to leaf, so an AI-classed member classifies the
	// flow it serves.
	aiMembers := []*routeRecordingOutbound{
		newRouteRecordingOutbound("proxy-a"),
		newRouteRecordingOutbound("\U0001F916 AI"),
	}
	aiOutbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, aiMembers...)
	chain, err = resolveOutbound(aiOutbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "proxy-a", chain[len(chain)-1].Tag())
	require.Equal(t, trafficclass.ClassDefault, resolveTrafficClass(chain, nil))
	chain, err = resolveOutbound(aiOutbound, lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9"), N.NetworkTCP, true)
	require.NoError(t, err)
	require.Equal(t, "\U0001F916 AI", chain[len(chain)-1].Tag())
	require.Equal(t, trafficclass.ClassInteractive, resolveTrafficClass(chain, nil),
		"the member's own automatic class must classify the flow it serves")
}

// --- concurrency ------------------------------------------------------------------------

// TestLoadBalanceRouteConcurrentSelectionsAreDistributed runs selections from many
// goroutines and asserts that every slot was consumed exactly once and that every member was
// used. It is run under -race in CI.
func TestLoadBalanceRouteConcurrentSelectionsAreDistributed(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	const (
		goroutines = 32
		perRoutine = 64
	)
	var waitGroup sync.WaitGroup
	counts := make([]int, len(members))
	var countsLock sync.Mutex
	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for i := 0; i < perRoutine; i++ {
				metadata := lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9")
				chain, err := resolveOutbound(outbound, metadata, N.NetworkTCP, true)
				if err != nil {
					t.Error(err)
					return
				}
				leaf := chain[len(chain)-1]
				tag := leaf.Tag()
				index := -1
				for j, member := range members {
					if member.Tag() == tag {
						index = j
					}
				}
				if index < 0 {
					t.Errorf("selected %s, which is not a member", tag)
					return
				}
				countsLock.Lock()
				counts[index]++
				countsLock.Unlock()
			}
		}()
	}
	waitGroup.Wait()

	total := 0
	for i, count := range counts {
		require.NotZero(t, count, "member %s was never selected", members[i].Tag())
		total += count
	}
	require.Equal(t, goroutines*perRoutine, total, "every selection returned exactly one member")
	// A strict atomic rotation gives an exact split.
	expected := goroutines * perRoutine / len(members)
	for i, count := range counts {
		require.Equal(t, expected, count, "member %s took %d of %d selections", members[i].Tag(), count, total)
	}
}

// --- benchmarks --------------------------------------------------------------------------

// BenchmarkLoadBalanceSelection measures the selection the route path performs per flow. The
// budget is the point: a group that adds an allocation or a contended lock to every
// connection is a cost every configuration would pay for a feature only some use.
func BenchmarkLoadBalanceSelection(b *testing.B) {
	for _, strategy := range []string{"round_robin", "consistent_hashing", "sticky_sessions"} {
		b.Run(strategy, func(b *testing.B) {
			members := make([]*routeRecordingOutbound, 4)
			for i := range members {
				members[i] = newRouteRecordingOutbound("member-" + strconv.Itoa(i))
			}
			created, _ := newLoadBalanceRouteFixture(b, option.LoadBalanceOutboundOptions{Strategy: strategy}, members...)
			metadata := lbMetadata(N.NetworkTCP, "shop.example.com", "192.168.1.9")

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// The committed selection only: this is what a connection costs.
				flowAware := created.(adapter.FlowAwareOutboundGroup)
				if flowAware.SelectForFlow(metadata, N.NetworkTCP, true) == nil {
					b.Fatal("no member")
				}
			}
		})
	}
}
