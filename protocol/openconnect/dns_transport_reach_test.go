package openconnect

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The endpoint-owned DNS resolvers must be reachable from the runtime resource walk.
//
// See protocol/openvpn/dns_transport_reach_test.go for the full reasoning: this transport is created
// through the DNS transport manager's registry, the resolvers it builds from the pushed configuration
// are created privately and are not in the manager's list, so the walk reached the wrapper and
// stopped there and every pushed resolver's pool was skipped by the reuse boundary, the trim and the
// DEEP_IDLE release. It forwards the retire ACTION and not the eligibility axis, because it has no
// keep-idle policy of its own - see adapter.IdleConnectionReleaser.
//
// The shape differs from OpenVPN's in one way that matters to this test: the routes here live in a
// SLICE of route structs rather than a map keyed by domain, so the walk over them is the other
// iteration and is asserted separately rather than assumed to be covered.

// countingResolver records a retire and claims no capability beyond it.
type countingResolver struct {
	adapter.DNSTransport
	retires int
}

func (r *countingResolver) CloseIdleConnections() { r.retires++ }

func TestTheEndpointOwnedResolversAreRetireCapable(t *testing.T) {
	var dnsTransport *DNSTransport
	require.Implements(t, (*adapter.IdleConnectionReleaser)(nil), dnsTransport,
		"the runtime resource walk cannot reach the resolvers this transport owns: every pool a "+
			"pushed DoH/DoT/UDP resolver holds is skipped by the reuse boundary, the trim and the "+
			"DEEP_IDLE release")
}

func TestRetiringThisTransportReachesEveryResolverItOwns(t *testing.T) {
	routed := &countingResolver{}
	fallback := &countingResolver{}

	owner := &DNSTransport{
		routes:           []openConnectDNSRoute{{resolvers: []adapter.DNSTransport{routed}}},
		defaultResolvers: []adapter.DNSTransport{fallback},
	}

	require.Implements(t, (*adapter.IdleConnectionReleaser)(nil), owner)
	owner.CloseIdleConnections()

	require.Equal(t, 1, routed.retires, "a resolver held for a pushed route was not reached")
	require.Equal(t, 1, fallback.retires, "a default resolver was not reached")
}
