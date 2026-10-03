package outbound

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for a tag collision between the outbound and endpoint namespaces.
//
// # Why this is a correctness problem rather than a naming preference
//
// Outbounds and endpoints are separate collections with separate managers, and Lookup resolves an
// outbound FIRST and falls back to an endpoint only when no outbound matches:
//
//	func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
//	    if outbound, found := m.outboundByTag[tag]; found { return outbound, true }
//	    return m.endpoint.Get(tag)
//	}
//
// Nothing rejects a configuration where one tag is used in both. Both objects are created, and the
// API layer lists both - so a client sees the tag twice - while every lookup resolves to the
// outbound. The endpoint is silently unreachable and unmeasurable.

// collisionEndpoint is an endpoint used to create a collision.
type collisionEndpoint struct {
	adapter.Endpoint
	tag string
}

func (e *collisionEndpoint) Type() string                         { return "collision-endpoint" }
func (e *collisionEndpoint) Tag() string                          { return e.tag }
func (e *collisionEndpoint) Network() []string                    { return []string{"tcp"} }
func (e *collisionEndpoint) Start(stage adapter.StartStage) error { return nil }
func (e *collisionEndpoint) Close() error                         { return nil }

// collisionEndpointManager serves a fixed set of endpoints.
type collisionEndpointManager struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
}

func (m *collisionEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

func (m *collisionEndpointManager) Endpoints() []adapter.Endpoint {
	var endpoints []adapter.Endpoint
	for _, endpoint := range m.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// TestEndpointTagCollisionShadowsTheEndpoint is the defect statement.
//
// An endpoint sharing a tag with an outbound is created and listed but can never be resolved.
func TestEndpointTagCollisionShadowsTheEndpoint(t *testing.T) {
	endpoint := &collisionEndpoint{tag: "shared"}
	endpointManager := &collisionEndpointManager{endpoints: map[string]adapter.Endpoint{"shared": endpoint}}

	manager := NewManager(log.NewNOPFactory().NewLogger("test"), &stubRegistry{}, endpointManager, "")

	outbound := &stubOutbound{tag: "shared"}
	installOutbound(t, manager, outbound)

	resolved, loaded := manager.Outbound("shared")
	require.True(t, loaded)
	require.Same(t, outbound, resolved,
		"an outbound wins the collision, so the endpoint under the same tag can never be resolved")

	// The endpoint is nevertheless installed and listed, so the API shows the tag twice while only
	// one of them is reachable.
	require.Len(t, endpointManager.Endpoints(), 1,
		"the endpoint exists and is listed, so a client sees the tag twice while every lookup "+
			"resolves to the outbound: the endpoint is silently unreachable and unmeasurable")
}

// TestCollidingTagIsDetectable documents the check a configuration layer needs.
//
// The manager cannot reject the collision itself - the two namespaces are populated by different
// managers at different times - so the contract is that a checker can observe it.
func TestCollidingTagIsDetectable(t *testing.T) {
	endpoint := &collisionEndpoint{tag: "shared"}
	endpointManager := &collisionEndpointManager{endpoints: map[string]adapter.Endpoint{"shared": endpoint}}
	manager := NewManager(log.NewNOPFactory().NewLogger("test"), &stubRegistry{}, endpointManager, "")

	_, endpointExists := endpointManager.Get("shared")
	_, outboundExists := manager.outboundByTag["shared"]

	require.True(t, endpointExists && !outboundExists,
		"before the outbound exists, the tag resolves to the endpoint")

	collision := endpointExists && outboundExists
	require.False(t, collision, "no collision yet")

	installOutbound(t, manager, &stubOutbound{tag: "shared"})

	_, endpointExists = endpointManager.Get("shared")
	_, outboundExists = manager.outboundByTag["shared"]
	collision = endpointExists && outboundExists

	require.True(t, collision,
		"the collision is observable from both namespaces, which is what lets a configuration "+
			"check refuse it rather than deploying an unreachable endpoint")
}
