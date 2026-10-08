package route

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The route path's half of the failover capability.
//
// # Why these tests exercise the decision and not a live Router
//
// Building a Router to route one flow would test the connection manager rather than the
// decision this feature adds. What matters here is narrower and is exactly what the route
// path does: ask whether the matched outbound owns the dial, resolve the chain with the
// commit flag that decision implies, and hand the connection manager the leaf or a shim.
// These tests run that sequence with the same helpers route.go calls.

// routeCopyTunerOutbound is a recording member that also opted into early copy-buffer growth,
// which is how the shim's forwarding is observed.
type routeCopyTunerOutbound struct {
	*routeRecordingOutbound
	early bool
}

func (o *routeCopyTunerOutbound) EarlyConnectionBufferGrowth() bool { return o.early }

func routeFailoverMetadata() *adapter.InboundContext {
	return lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9")
}

func routeFailoverDestination() M.Socksaddr {
	return M.ParseSocksaddr("93.184.216.34:443")
}

// TestRouteFailoverCapabilityOwnsTheDialAndTheSelection is the route half of the contract:
// the preview consumes nothing, the group's dial commits the choice, and a path-dead primary
// is replaced inside the group.
func TestRouteFailoverCapabilityOwnsTheDialAndTheSelection(t *testing.T) {
	members := fourRouteMembers()
	members[0].setDialError(context.DeadlineExceeded)
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)

	metadata := routeFailoverMetadata()
	// The route path's rule: a group that owns the dial owns the selection too, so the walk
	// that builds the chain is a preview.
	chain, owner, err := routeDialDecision(outbound, metadata, N.NetworkTCP)
	require.NoError(t, err)
	require.NotNil(t, owner, "a balancing group with a retry implements the capability")
	require.Equal(t, uint64(0), loadBalanceCursor(t, outbound),
		"the preview must not spend the decision the group's own dial commits")
	require.Equal(t, "A", chain[len(chain)-1].Tag(), "the preview names the attempt that will be made")

	dialer := routeDialer(chain[len(chain)-1], owner, metadata)
	require.IsType(t, &failoverDialer{}, dialer, "the connection manager must be given the shim")

	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, routeFailoverDestination())
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	require.Equal(t, 1, members[0].dialCount(), "the previewed member was attempted once")
	require.Equal(t, 1, members[2].dialCount(), "the retry re-ran the rotation and used the alternate it named")
	require.Equal(t, 0, members[1].dialCount())
	require.Equal(t, uint64(2), loadBalanceCursor(t, outbound),
		"one flow consumed the primary decision and the retry's")
}

// TestRouteWithoutTheCapabilityFallsThroughUnchanged is the compatibility guarantee: a group
// that does not implement the capability takes exactly the path it took before.
func TestRouteWithoutTheCapabilityFallsThroughUnchanged(t *testing.T) {
	members := fourRouteMembers()
	inner, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)

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
	selector := createdSelector.(*group.Selector)
	require.NoError(t, selector.Start(adapter.StartStateStart, &adapter.Scope{}))

	require.Nil(t, routeDialOwner(selector),
		"a group without the capability must not be treated as one")

	metadata := routeFailoverMetadata()
	chain, owner, err := routeDialDecision(selector, metadata, N.NetworkTCP)
	require.NoError(t, err)
	require.Nil(t, owner, "nothing owns the dial, so the walk commits as it always did")
	require.Len(t, chain, 3, "outer group, inner group, leaf")
	require.Equal(t, uint64(1), loadBalanceCursor(t, inner),
		"the chain resolution still commits exactly one selection when nothing owns the dial")

	dialer := routeDialer(chain[len(chain)-1], owner, metadata)
	require.Equal(t, chain[len(chain)-1], dialer,
		"the connection manager is handed the same leaf object it always was")
}

// TestRouteWithoutTheCapabilityOnALeafIsATrivialFallThrough covers the leaf case, which is
// the overwhelmingly common one.
func TestRouteWithoutTheCapabilityOnALeafIsATrivialFallThrough(t *testing.T) {
	leaf := newRouteRecordingOutbound("direct")
	require.Nil(t, routeDialOwner(leaf))
	require.Equal(t, leaf, routeDialer(leaf, nil, routeFailoverMetadata()))
}

// TestRouteFailoverShimForwardsTheCopyBufferOptIn is the one capability the shim has to carry
// across, because it is asked of the DIALER after the connection exists.
func TestRouteFailoverShimForwardsTheCopyBufferOptIn(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)
	owner := routeDialOwner(outbound)
	require.NotNil(t, owner)

	tuner := &routeCopyTunerOutbound{routeRecordingOutbound: newRouteRecordingOutbound("opt-in"), early: true}
	dialer := routeDialer(tuner, owner, routeFailoverMetadata())
	asTuner, isTuner := dialer.(adapter.ConnectionCopyTuner)
	require.True(t, isTuner, "the shim must expose the tuner capability the leaf had")
	require.True(t, asTuner.EarlyConnectionBufferGrowth())

	plain := newRouteRecordingOutbound("plain")
	dialer = routeDialer(plain, owner, routeFailoverMetadata())
	asTuner, isTuner = dialer.(adapter.ConnectionCopyTuner)
	require.True(t, isTuner)
	require.False(t, asTuner.EarlyConnectionBufferGrowth(),
		"a leaf that did not opt in must get the framework default, not early growth")
}

// TestRouteFailoverDoesNotRetryThePacketPath is the stated exclusion. The capability has no
// packet method, and the UDP path hands the connection manager the selected leaf unchanged,
// so a packet session can never be re-opened on another member.
func TestRouteFailoverDoesNotRetryThePacketPath(t *testing.T) {
	members := fourRouteMembers()
	members[0].setDialError(syscall.ECONNREFUSED)
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)

	metadata := lbMetadata(N.NetworkUDP, "example.com", "192.168.1.9")
	chain, err := resolveOutbound(outbound, metadata, N.NetworkUDP, true)
	require.NoError(t, err)
	leaf := chain[len(chain)-1]
	require.Equal(t, "A", leaf.Tag())

	// Whatever the route path does for UDP, it is not routeDialer: the leaf is used as the
	// dialer, so one session resolves once and stays on one member.
	require.IsType(t, &routeRecordingOutbound{}, leaf)
	require.Equal(t, uint64(1), loadBalanceCursor(t, outbound))
}

// TestRouteFailoverDoesNotReSelectPerAddress is the one-flow-one-member guard.
//
// The connection manager dials each candidate address through the same dialer. A group that
// owned the dial would therefore make a fresh choice after the first address failed, and a
// single flow could be carried by two members - the property the whole group exists to
// preserve. A flow with several candidate addresses therefore keeps the old behaviour: one
// committed selection, dialled by the leaf.
func TestRouteFailoverDoesNotReSelectPerAddress(t *testing.T) {
	members := fourRouteMembers()
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)

	metadata := lbMetadata(N.NetworkTCP, "example.com", "192.168.1.9")
	metadata.DestinationAddresses = []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2606:4700::1"),
	}

	// The route path's rule: several candidate addresses mean the group does not own the dial.
	require.NotNil(t, routeDialOwner(outbound), "the group itself has the capability")
	chain, owner, err := routeDialDecision(outbound, metadata, N.NetworkTCP)
	require.NoError(t, err)
	require.Nil(t, owner, "several candidate addresses take the flow out of the capability")
	require.Equal(t, uint64(1), loadBalanceCursor(t, outbound),
		"the flow makes one selection, and it is the resolution that makes it")
	require.Equal(t, chain[len(chain)-1], routeDialer(chain[len(chain)-1], owner, metadata),
		"the leaf dials every candidate address, so the two of them share one member")
}

// routeHandlerOutbound is a member that owns the whole connection: it consumes the client
// connection instead of returning a remote one.
type routeHandlerOutbound struct {
	*routeRecordingOutbound
	access  sync.Mutex
	handled int
}

func (o *routeHandlerOutbound) NewConnection(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
	o.access.Lock()
	o.handled++
	o.access.Unlock()
}

func (o *routeHandlerOutbound) handledCount() int {
	o.access.Lock()
	defer o.access.Unlock()
	return o.handled
}

// TestRouteFailoverGroupOverAConnectionHandlerStillCommitsOnce covers the member that owns the
// whole connection: the group cannot dial it, so the preview must not be left as the flow's
// only resolution or the group would silently stop advancing for those flows.
func TestRouteFailoverGroupOverAConnectionHandlerStillCommitsOnce(t *testing.T) {
	handler := &routeHandlerOutbound{routeRecordingOutbound: newRouteRecordingOutbound("handler")}
	other := newRouteRecordingOutbound("other")

	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &routeGroupManager{members: map[string]adapter.Outbound{}}
	for _, member := range []adapter.Outbound{handler, other} {
		manager.members[member.Tag()] = member
	}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
	created, err := group.NewLoadBalance(ctx, nil, log.NewNOPFactory().NewLogger("loadbalance"), "lb", option.LoadBalanceOutboundOptions{
		Strategy:  "round_robin",
		Failover:  true,
		Outbounds: []string{"handler", "other"},
	})
	require.NoError(t, err)
	loadBalance := created.(*group.LoadBalance)
	require.NoError(t, loadBalance.Start(adapter.StartStateStart, &adapter.Scope{}))
	t.Cleanup(func() {
		require.NoError(t, loadBalance.Close())
	})

	metadata := routeFailoverMetadata()
	chain, owner, err := routeDialDecision(loadBalance, metadata, N.NetworkTCP)
	require.NoError(t, err)
	require.Nil(t, owner, "a member that owns the connection leaves the group nothing to dial")
	require.Len(t, chain, 2)
	require.Equal(t, "handler", chain[len(chain)-1].Tag())
	require.Equal(t, uint64(1), loadBalanceCursor(t, loadBalance),
		"the flow still consumes exactly one decision, even though the group does not dial")
}

// TestRouteFailoverUsesTheCallersDeadline pins that the retry shares the caller's context
// rather than starting a fresh one; the group's attempt sequence is asserted to return
// promptly under an already-nearly-expired deadline rather than hanging.
func TestRouteFailoverUsesTheCallersDeadline(t *testing.T) {
	members := fourRouteMembers()
	members[0].setDialError(context.DeadlineExceeded)
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin", Failover: true}, members...)
	owner := routeDialOwner(outbound)
	require.NotNil(t, owner)

	metadata := routeFailoverMetadata()
	chain, err := resolveOutbound(outbound, metadata, N.NetworkTCP, owner == nil)
	require.NoError(t, err)
	dialer := routeDialer(chain[len(chain)-1], owner, metadata)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, routeFailoverDestination())
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, ctx.Err(), "the whole sequence finished inside the caller's deadline")
}

// TestRouteFailoverIsNotAdvertisedWithoutTheOption is the route half of the migration
// guarantee.
//
// A group whose configuration did not opt in answers routeDialOwner with nil, so
// routeDialDecision resolves with commit and routeDialer returns the resolved leaf. That is
// literally the pre-capability path - not "the retry path, but the retry declines" - which is
// the only form of compatibility an upgrade can promise.
func TestRouteFailoverIsNotAdvertisedWithoutTheOption(t *testing.T) {
	members := fourRouteMembers()
	members[0].setDialError(syscall.ENETUNREACH)
	outbound, _ := newLoadBalanceRouteFixture(t, option.LoadBalanceOutboundOptions{Strategy: "round_robin"}, members...)

	require.Nil(t, routeDialOwner(outbound),
		"a group that did not opt in must not be treated as owning the dial")

	metadata := routeFailoverMetadata()
	chain, owner, err := routeDialDecision(outbound, metadata, N.NetworkTCP)
	require.NoError(t, err)
	require.Nil(t, owner)
	require.Equal(t, uint64(1), loadBalanceCursor(t, outbound),
		"the walk commits exactly as it did before the capability existed")
	require.Equal(t, chain[len(chain)-1], routeDialer(chain[len(chain)-1], owner, metadata),
		"the connection manager is handed the leaf itself, never the shim")

	_, err = chain[len(chain)-1].DialContext(context.Background(), N.NetworkTCP, routeFailoverDestination())
	require.ErrorIs(t, err, syscall.ENETUNREACH)
	require.Equal(t, 1, members[0].dialCount(), "the flow made exactly one attempt")
	for _, member := range members[1:] {
		require.Equal(t, 0, member.dialCount(), "no alternate may be dialled without the opt-in")
	}
}
