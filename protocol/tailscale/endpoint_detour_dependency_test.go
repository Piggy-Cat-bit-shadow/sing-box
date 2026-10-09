//go:build with_tailscale

// Gated on with_tailscale because the endpoint it constructs, NewEndpoint, only exists in that
// configuration (protocol/tailscale/endpoint.go is with_tailscale). Every product profile sets
// the tag, so this only removes a build that could not have compiled anyway: without the
// constraint the untagged test build failed with `undefined: NewEndpoint`.
package tailscale

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Tests for the endpoint's declared position in the outbound graph.
//
// # Why this is a correctness test and not a formality
//
// Every byte this endpoint puts on the wire leaves through the dialer built from its DialerOptions:
// when `detour` is set that dialer is a DetourDialer, so `detour` is a real, always-taken edge of the
// outbound graph. adapter/outbound/manager.go discovers edges through Dependencies() and uses them to
// topologically sort the graph and to refuse a cycle. An undeclared edge is invisible to that sort, so
// the node sorts as a root.
//
// The consequence of missing this one edge is a process-fatal loop: a selector that lists this
// endpoint as a member, with the endpoint's `detour` pointing back at that selector, passes the
// startup check. The first dial through the endpoint then recurses
// Selector.DialContext -> Endpoint.DialContext -> endpointDialer -> DetourDialer -> Selector.DialContext
// and never terminates; Go reports `fatal error: stack overflow`, which is not recoverable.
//
// # Why References() is not the same statement
//
// The endpoint already reports the detour through References(), which feeds the idle-resource walk in
// route/reference.go. That is a different consumer with a different question, and it is not what the
// startup sort reads. Reporting only there is what left the edge invisible.

// detourOutboundManager resolves a fixed tag set, which is all dialer.NewDetour needs to build a
// DetourDialer for the detour named below.
type detourOutboundManager struct {
	adapter.OutboundManager
	members map[string]adapter.Outbound
}

func (m *detourOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.members[tag]
	return outbound, loaded
}

func (m *detourOutboundManager) Default() adapter.Outbound {
	return m.members["underlay"]
}

// detourMember is a stand-in for the outbound the endpoint's underlay travels through.
type detourMember struct {
	adapter.Outbound
	tag string
}

func (o *detourMember) Type() string           { return "detour-member" }
func (o *detourMember) Tag() string            { return o.tag }
func (o *detourMember) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *detourMember) Dependencies() []string { return nil }

// TestTailscaleEndpointDeclaresItsDetourAsADependency is the contract.
//
// The endpoint's dialer travels through `detour`, so the endpoint must name it in Dependencies().
// Anything else leaves a real edge of the dial graph invisible to the startup cycle check.
func TestTailscaleEndpointDeclaresItsDetourAsADependency(t *testing.T) {
	underlay := &detourMember{tag: "underlay"}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &detourOutboundManager{
		members: map[string]adapter.Outbound{"underlay": underlay},
	})

	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("tailscale"), "ts", option.TailscaleEndpointOptions{
		DialerOptions:  option.DialerOptions{Detour: "underlay"},
		StateDirectory: t.TempDir(),
	})
	require.NoError(t, err)

	require.Equal(t, []string{"underlay"}, created.Dependencies(),
		"the endpoint dials through this outbound, so it must declare the edge: without it the "+
			"startup sort cannot see a cycle that closes through this node, and the first dial "+
			"through such a cycle exhausts the stack and kills the process")
}

// TestTailscaleEndpointWithoutDetourDeclaresNothing is the compatibility half.
//
// With no detour there is no edge, so the endpoint must stay a root: inventing a dependency would
// reorder startup and could refuse a legal configuration.
func TestTailscaleEndpointWithoutDetourDeclaresNothing(t *testing.T) {
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &detourOutboundManager{
		members: map[string]adapter.Outbound{"underlay": &detourMember{tag: "underlay"}},
	})

	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("tailscale"), "ts", option.TailscaleEndpointOptions{
		StateDirectory: t.TempDir(),
	})
	require.NoError(t, err)

	require.Empty(t, created.Dependencies(),
		"an endpoint with no detour has no outbound-graph edge to declare")
}

// TestTailscaleEndpointReferencesAgreeWithItsDependencies pins the two accessors to each other.
//
// They answer different questions - the startup sort orders by Dependencies(), the idle-resource walk
// follows References() - but for THIS edge the answer must be the same set. A change that updates one
// and not the other is exactly how the edge went missing, so the disagreement is asserted directly
// rather than left to a reader to notice.
func TestTailscaleEndpointReferencesAgreeWithItsDependencies(t *testing.T) {
	underlay := &detourMember{tag: "underlay"}
	ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &detourOutboundManager{
		members: map[string]adapter.Outbound{"underlay": underlay},
	})

	created, err := NewEndpoint(ctx, nil, log.NewNOPFactory().NewLogger("tailscale"), "ts", option.TailscaleEndpointOptions{
		DialerOptions:  option.DialerOptions{Detour: "underlay"},
		StateDirectory: t.TempDir(),
	})
	require.NoError(t, err)

	referrer, isReferrer := created.(adapter.Referrer)
	require.True(t, isReferrer, "the endpoint reports its detour as a reference; see References()")
	require.Equal(t, created.Dependencies(), referrer.References(),
		"both accessors describe the same dial edge, so they must not disagree about it")
}
