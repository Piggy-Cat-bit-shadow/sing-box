package openvpn

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The endpoint-owned DNS resolvers must be reachable from the runtime resource walk.
//
// This transport is created through the DNS transport MANAGER's registry, so the reference manager's
// walk reaches it as an ordinary DNS transport. What it OWNS is a second level: the resolvers it
// builds for the configuration the server pushed, created privately through transport.NewUDPRaw /
// NewTLSRaw / NewHTTPSRaw and held in routes / defaultResolvers. Those inner transports are real
// reusable pools - a pushed DoH resolver holds HTTP/2 connections - and they are NOT in the
// manager's list.
//
// So the walk reached the wrapper and stopped there, and the reuse boundary, the memory trim and the
// DEEP_IDLE release all skipped every pushed resolver's pool. That is the same omission the HTTP
// client manager had: a pool that is real, whose owner the walk can see, and which the owner does not
// hand over. Forwarding is the shape protocol/vless already documents for its own transport.
//
// It forwards the retire ACTION and not the eligibility axis on purpose: this transport has no
// keep-idle policy of its own, and requiring one would mean implementing a method with no meaning
// here - which is exactly how the HTTP client manager stayed unreachable.
// See adapter.IdleConnectionReleaser.

// countingResolver records a retire and claims no capability beyond it.
type countingResolver struct {
	adapter.DNSTransport
	retires int
}

func (r *countingResolver) CloseIdleConnections() { r.retires++ }

// TestTheEndpointOwnedResolversAreRetireCapable asserts on the PRODUCTION type, not on a double: a
// double that implements more than the real owner is how the HTTP client gap survived its own test.
func TestTheEndpointOwnedResolversAreRetireCapable(t *testing.T) {
	var dnsTransport *DNSTransport
	require.Implements(t, (*adapter.IdleConnectionReleaser)(nil), dnsTransport,
		"the runtime resource walk cannot reach the resolvers this transport owns: every pool a "+
			"pushed DoH/DoT/UDP resolver holds is skipped by the reuse boundary, the trim and the "+
			"DEEP_IDLE release")
}

// TestRetiringThisTransportReachesEveryResolverItOwns covers both places a resolver is held - the
// per-domain routes and the defaults. A forwarding method that covered only one would leave half the
// pushed pools unreachable and still pass an interface-only test.
func TestRetiringThisTransportReachesEveryResolverItOwns(t *testing.T) {
	routed := &countingResolver{}
	fallback := &countingResolver{}

	owner := &DNSTransport{
		routes:           map[string][]adapter.DNSTransport{"corp.example": {routed}},
		defaultResolvers: []adapter.DNSTransport{fallback},
	}

	require.Implements(t, (*adapter.IdleConnectionReleaser)(nil), owner)
	owner.CloseIdleConnections()

	require.Equal(t, 1, routed.retires, "a resolver held for a pushed route was not reached")
	require.Equal(t, 1, fallback.retires, "a default resolver was not reached")
}
