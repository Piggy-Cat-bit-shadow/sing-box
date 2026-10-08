package outbound

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// Tests for the cross-kind (DNS transport <-> outbound) cycle validation.
//
// # What is being pinned
//
// The two per-kind sorts each see one namespace. This check sees both, so these tests are written
// as graphs rather than as manager states: a node contributes its own edges, and the assertion is
// about the walk. Every required shape is here - DNS->outbound->DNS, outbound->DNS->outbound, and a
// cycle that closes through a nested selector's member edge - plus the two negative controls that
// matter: an acyclic graph (including a legal diamond) must pass, and a missing target must be left
// to the per-kind sorts rather than misreported as a cycle.

// crossKindTestOutbound is one outbound node: a tag, its outbound-tag edges (a detour or group
// members), and the DNS server it resolves through.
type crossKindTestOutbound struct {
	adapter.Outbound
	tag       string
	dependsOn []string
	resolver  string
	kind      string
}

func (o *crossKindTestOutbound) Type() string           { return o.kind }
func (o *crossKindTestOutbound) Tag() string            { return o.tag }
func (o *crossKindTestOutbound) Network() []string      { return []string{"tcp"} }
func (o *crossKindTestOutbound) Dependencies() []string { return o.dependsOn }
func (o *crossKindTestOutbound) DomainResolverReference() string {
	return o.resolver
}

// A node whose Adapter-style resolver accessor is absent must contribute no resolver edge, so a
// plain outbound cannot be blamed for a cycle it has no edge to.
type crossKindPlainOutbound struct {
	adapter.Outbound
	tag       string
	dependsOn []string
}

func (o *crossKindPlainOutbound) Type() string           { return "plain" }
func (o *crossKindPlainOutbound) Tag() string            { return o.tag }
func (o *crossKindPlainOutbound) Network() []string      { return []string{"tcp"} }
func (o *crossKindPlainOutbound) Dependencies() []string { return o.dependsOn }

// crossKindTestTransport is one DNS transport node: a tag, its DNS-transport dependencies (its own
// domain_resolver), and the outbound its detour names.
type crossKindTestTransport struct {
	adapter.DNSTransport
	tag       string
	dependsOn []string
	detoursTo []string
}

func (t *crossKindTestTransport) Type() string           { return "stub-dns" }
func (t *crossKindTestTransport) Tag() string            { return t.tag }
func (t *crossKindTestTransport) Dependencies() []string { return t.dependsOn }
func (t *crossKindTestTransport) References() []string   { return t.detoursTo }

// crossKindFixture installs the outbound nodes and returns the validator under test.
func crossKindFixture(t *testing.T, outbounds []adapter.Outbound) *Manager {
	t.Helper()
	manager := NewManager(nil, nil, "")
	for _, outbound := range outbounds {
		installOutbound(t, manager, outbound)
	}
	return manager
}

// TestCrossKindCycleRefusesDNSThroughOutboundBackToDNS is the primary shape: the DNS transport's
// detour is an outbound, and that outbound resolves its server through that same transport.
//
// This is the configuration measured through box.New/Start: it starts successfully on the unfixed
// tree and then hangs on the first dial, because the transport's exchange re-enters itself through
// the detour's server resolution. Start must refuse it instead.
func TestCrossKindCycleRefusesDNSThroughOutboundBackToDNS(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "proxy", resolver: "remote", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"proxy"}},
	})

	require.Error(t, err, "a DNS transport whose detour resolves through it must be refused at start")
	require.Contains(t, err.Error(), "circular dependency between DNS server and outbound")
	require.Contains(t, err.Error(), "dns/remote")
	require.Contains(t, err.Error(), "outbound/proxy")
}

// TestCrossKindCycleRefusesOutboundThroughDNSBackToOutbound walks the same 2-cycle from the other
// namespace: an outbound resolves through a transport, and that transport detours back into the
// outbound. It is a separate test because the walk must start from an outbound node too, not only
// from the DNS side.
func TestCrossKindCycleRefusesOutboundThroughDNSBackToOutbound(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "proxy", resolver: "remote", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"proxy"}},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "outbound/proxy")
	require.Contains(t, err.Error(), "dns/remote")
}

// TestCrossKindCycleRefusesACycleThroughANestedSelector is the shape the outbound manager's own
// sort cannot complete on its own.
//
// The DNS transport detours into the selector, the selector selects a member, and the member
// resolves through the DNS transport. The member edge is the selector's Dependencies(), so the walk
// has to follow it - and the cycle must name all three nodes, not report the selector as a
// dependency error.
func TestCrossKindCycleRefusesACycleThroughANestedSelector(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "sel", dependsOn: []string{"proxy"}, kind: "selector"},
		&crossKindTestOutbound{tag: "proxy", resolver: "remote", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"sel"}},
	})

	require.Error(t, err, "a cycle closed through a selector member must be refused")
	require.Contains(t, err.Error(), "dns/remote")
	require.Contains(t, err.Error(), "outbound/sel")
	require.Contains(t, err.Error(), "outbound/proxy")
}

// TestCrossKindCycleReportsTheLoopAndNotItsPrefix covers the DNS-transport-only segment of a mixed
// walk.
//
// `bootstrap` resolves through `remote`, which is a legal prefix when nothing points back at
// bootstrap - and the reported cycle must be exactly the loop, not everything the walk entered
// before it. An operator reading "bootstrap -> remote -> proxy -> remote" would look for an edge
// from proxy to bootstrap that does not exist.
func TestCrossKindCycleReportsTheLoopAndNotItsPrefix(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "proxy", resolver: "remote", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "bootstrap", dependsOn: []string{"remote"}},
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"proxy"}},
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "dns/remote")
	require.Contains(t, err.Error(), "outbound/proxy")
	require.NotContains(t, err.Error(), "dns/bootstrap",
		"the reported path must be the cycle itself, not the legal chain that led into it")
}

// TestCrossKindCycleAcceptsAnAcyclicGraph is the negative control that matters most.
//
// A rejected configuration is a startup failure with no workaround, so a check that refuses legal
// graphs is worse than the hang it replaces. The graph here has every edge kind but no cycle: a DNS
// transport detouring into a proxy, the proxy resolving its server through a second, detour-free
// transport, and a selector with two members reaching shared nodes (a diamond, which the walk must
// not confuse with a back edge).
func TestCrossKindCycleAcceptsAnAcyclicGraph(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "sel", dependsOn: []string{"proxy", "other"}, kind: "selector"},
		&crossKindTestOutbound{tag: "proxy", resolver: "bootstrap", kind: "socks"},
		&crossKindTestOutbound{tag: "other", resolver: "bootstrap", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"sel"}},
		&crossKindTestTransport{tag: "bootstrap"},
	})

	require.NoError(t, err, "an acyclic configuration with the same edge kinds must still start")
}

// TestCrossKindCycleIgnoresMissingTargets keeps the failure attributable.
//
// A detour or resolver naming a tag that does not exist is a configuration error, but it is the
// per-kind sorts' error to report ("dependency not found"), and reporting it here as a cycle would
// send an operator looking for a loop that is not there.
func TestCrossKindCycleIgnoresMissingTargets(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "proxy", dependsOn: []string{"absent-outbound"}, resolver: "absent-transport", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", dependsOn: []string{"absent-transport"}, detoursTo: []string{"absent-outbound"}},
	})

	require.NoError(t, err, "a missing target is not a cycle; the per-kind sorts own that message")
}

// TestCrossKindCycleKeepsTheNamespacesApart pins the node identity.
//
// Outbound tags and DNS server tags are separate namespaces: a configuration may legally use the
// same name for both, and the dial path resolves each name in its own namespace. Merging the nodes
// would invent a cycle out of two unrelated objects.
func TestCrossKindCycleKeepsTheNamespacesApart(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindTestOutbound{tag: "shared", kind: "socks"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "shared", detoursTo: []string{"shared"}},
	})

	require.NoError(t, err,
		"an outbound and a DNS transport sharing a tag are two nodes; the shared name alone is not an edge")
}

// TestCrossKindCycleIgnoresAnOutboundWithoutTheCapability keeps the check additive.
//
// Only an outbound that declares a resolver edge can close a cross-kind cycle. An implementation
// that does not expose DomainResolverReference (a group, an endpoint, a third-party outbound)
// contributes its outbound edges and nothing else.
func TestCrossKindCycleIgnoresAnOutboundWithoutTheCapability(t *testing.T) {
	manager := crossKindFixture(t, []adapter.Outbound{
		&crossKindPlainOutbound{tag: "proxy"},
	})

	err := manager.ValidateCrossKindCycles([]adapter.DNSTransport{
		&crossKindTestTransport{tag: "remote", detoursTo: []string{"proxy"}},
	})

	require.NoError(t, err)
}
