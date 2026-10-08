package outbound

import (
	"context"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests for the startup cycle check and for the node set it covers.
//
// # Why this is the guard that makes a runtime routing loop impossible
//
// A dial follows the outbound graph: a group hands the connection to the member it has selected, and
// a plain outbound hands it to its `detour`. Nothing on the dial path counts hops, so a cycle in that
// graph is not a bad connection - it is unbounded mutual recursion
// (Selector.DialContext -> member.DialContext -> ...), which exhausts the goroutine stack and raises
// a FATAL runtime error that no recover() can contain. The whole process dies.
//
// The dial path is therefore allowed to assume the graph is acyclic, and this sort is what earns that
// assumption. It runs once, before any traffic exists, over every node a dial can reach. A node
// starts only once all of its Dependencies() have started; when a full sweep starts nothing, the
// remaining nodes are walked along their unsatisfied dependencies and the first tag seen twice is
// reported as a cycle.
//
// # Why coverage matters as much as the check itself
//
// The sort can only see the edges a node DECLARES. A node that dials through another outbound while
// reporting no dependency sorts as a root, so a configuration whose detour leads back to it passes
// this check and then recurses on the first dial. That is not hypothetical: it is exactly the shape
// protocol/tailscale/endpoint.go had, where `detour` was reported through References() - which this
// sort does not read - and not through Dependencies().
//
// These tests pin both halves: the check refuses a declared cycle wherever the node lives, and a
// declared dependency is also honoured for start ORDER, so declaring an edge is sufficient to obtain
// both behaviours.
//
// # Why the nodes below double as endpoints
//
// adapter.Endpoint is Lifecycle + Outbound, so any node with a Start method IS an endpoint as far as
// adapter/outbound/manager.go is concerned, and the sort hands it to the endpoint manager rather than
// to scope.Start. The recorder therefore lives on the endpoint manager, and the order it observes is
// the topological order of the whole graph. That is also why this file needs no separate ordering
// hook: one recording point observes every node.

// dependencyNode is a graph node with a caller-chosen dependency list. stubOutbound always reports
// nil dependencies, which is the shape under test rather than a usable one.
type dependencyNode struct {
	adapter.Outbound
	tag          string
	dependencies []string
}

func (o *dependencyNode) Type() string                                       { return "dependency-node" }
func (o *dependencyNode) Tag() string                                        { return o.tag }
func (o *dependencyNode) Network() []string                                  { return []string{"tcp"} }
func (o *dependencyNode) Dependencies() []string                             { return o.dependencies }
func (o *dependencyNode) Start(_ adapter.StartStage, _ *adapter.Scope) error { return nil }
func (o *dependencyNode) Close() error                                       { return nil }

// endpointNode is a node that lives in the endpoint namespace. It exists so a failure names the
// namespace explicitly instead of leaving the reader to infer it from the tag.
type endpointNode struct {
	adapter.Endpoint
	tag          string
	dependencies []string
}

func (e *endpointNode) Type() string                                       { return "endpoint-node" }
func (e *endpointNode) Tag() string                                        { return e.tag }
func (e *endpointNode) Network() []string                                  { return []string{"tcp"} }
func (e *endpointNode) Dependencies() []string                             { return e.dependencies }
func (e *endpointNode) Start(_ adapter.StartStage, _ *adapter.Scope) error { return nil }
func (e *endpointNode) Close() error                                       { return nil }

// cycleEndpointManager serves a fixed endpoint set and records the order nodes were started in.
type cycleEndpointManager struct {
	adapter.EndpointManager
	endpoints map[string]adapter.Endpoint
	started   []string
}

func (m *cycleEndpointManager) Get(tag string) (adapter.Endpoint, bool) {
	endpoint, loaded := m.endpoints[tag]
	return endpoint, loaded
}

func (m *cycleEndpointManager) Endpoints() []adapter.Endpoint {
	tags := make([]string, 0, len(m.endpoints))
	for tag := range m.endpoints {
		tags = append(tags, tag)
	}
	// Sorted so a failure points at the graph rather than at map iteration order.
	slices.Sort(tags)
	endpoints := make([]adapter.Endpoint, 0, len(tags))
	for _, tag := range tags {
		endpoints = append(endpoints, m.endpoints[tag])
	}
	return endpoints
}

func (m *cycleEndpointManager) StartEndpoint(endpoint adapter.Endpoint) error {
	m.started = append(m.started, endpoint.Tag())
	return nil
}

func startCycleFixture(t *testing.T, outbounds []adapter.Outbound, endpoints map[string]adapter.Endpoint) (*cycleEndpointManager, error) {
	t.Helper()
	endpointManager := &cycleEndpointManager{endpoints: endpoints}
	manager := NewManager(&stubRegistry{}, endpointManager, "")
	for _, outbound := range outbounds {
		installOutbound(t, manager, outbound)
	}
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	return endpointManager, manager.Start(adapter.StartStateStart, scope)
}

// TestStartupCycleCheckRefusesACycleThroughAnEndpoint closes the routing-loop class: the closing edge
// may be a selector's member pointing at the endpoint that detours back through that same selector,
// and the cycle must be refused before any traffic exists.
//
// This is the graph a user writes when they route Tailscale's underlay through a selector and also
// list the Tailscale endpoint among that selector's members:
//
//	sel -> ts   (selector member)
//	ts  -> sel  (detour, delivered by endpointDialer)
//
// The first dial through `ts` would recurse until the stack ran out. Start must refuse instead.
func TestStartupCycleCheckRefusesACycleThroughAnEndpoint(t *testing.T) {
	direct := &dependencyNode{tag: "direct"}
	selector := &dependencyNode{tag: "sel", dependencies: []string{"direct", "ts"}}
	tailscale := &endpointNode{tag: "ts", dependencies: []string{"sel"}}

	_, err := startCycleFixture(t,
		[]adapter.Outbound{direct, selector},
		map[string]adapter.Endpoint{"ts": tailscale},
	)

	require.Error(t, err, "a cycle that closes through an endpoint must be refused at start")
	require.Contains(t, err.Error(), "circular outbound dependency",
		"the failure must name the cycle: reporting it as anything else would leave the operator with "+
			"a configuration that starts and then dies on its first dial, which is unrecoverable")
	require.Contains(t, err.Error(), "ts")
	require.Contains(t, err.Error(), "sel")
}

// TestStartupCycleCheckRefusesASelfReferentialEndpoint is the smallest cycle, and the one a `detour`
// naming the node's own tag produces.
func TestStartupCycleCheckRefusesASelfReferentialEndpoint(t *testing.T) {
	tailscale := &endpointNode{tag: "ts", dependencies: []string{"ts"}}

	_, err := startCycleFixture(t, nil, map[string]adapter.Endpoint{"ts": tailscale})

	require.Error(t, err, "an endpoint that detours to itself is a cycle, not a no-op")
	require.Contains(t, err.Error(), "circular outbound dependency")
}

// TestStartupCycleCheckHonoursEndpointDependenciesForOrder is the other half of the contract: once a
// node declares an edge, the sort both orders it and can see cycles through it.
//
// The graph is a diamond, which is legal and must keep working:
//
//	sel -> a -> ts
//	sel -> b -> ts
//	ts  -> direct
func TestStartupCycleCheckHonoursEndpointDependenciesForOrder(t *testing.T) {
	direct := &dependencyNode{tag: "direct"}
	ts := &endpointNode{tag: "ts", dependencies: []string{"direct"}}
	a := &dependencyNode{tag: "a", dependencies: []string{"ts"}}
	b := &dependencyNode{tag: "b", dependencies: []string{"ts"}}
	selector := &dependencyNode{tag: "sel", dependencies: []string{"a", "b"}}

	endpointManager, err := startCycleFixture(t,
		[]adapter.Outbound{direct, a, b, selector},
		map[string]adapter.Endpoint{"ts": ts},
	)
	require.NoError(t, err, "a diamond is acyclic and must start")

	// `a` and `b` are siblings, so their relative order is unspecified; everything else is forced.
	require.Len(t, endpointManager.started, 5)
	require.Equal(t, []string{"direct", "ts", "sel"}, []string{
		endpointManager.started[0], endpointManager.started[1], endpointManager.started[4],
	}, "a node may only start after its declared dependencies, which is what makes one declaration "+
		"sufficient for both ordering and cycle detection")
	require.ElementsMatch(t, []string{"a", "b"}, endpointManager.started[2:4])
	require.Equal(t, "sel", endpointManager.started[4],
		"the group starts last: every member it could select is already up")
}
