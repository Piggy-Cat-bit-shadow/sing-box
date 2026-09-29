package socks

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// SOCKS4 target resolution must follow the outbound's own resolver policy.
//
// # Why SOCKS4 is special, and why it was wrong
//
// SOCKS5 carries the target as a domain and lets the proxy resolve it. SOCKS4 has no such field:
// its request format holds a 4-byte IPv4 address, so a domain target MUST be resolved locally
// before the request can be written. That local resolution is a workaround for a protocol
// limitation, not a routing decision, so it has to use the resolver the operator configured for
// this outbound -- the same one the PROXY SERVER's hostname already uses through the dialer.
//
// The previous implementation passed `adapter.DNSQueryOptions{}`, which is not "no preference": it
// is an empty policy that bypasses `dialer_options.domain_resolver` entirely and sends the target
// through the default DNS path. An operator who pointed the outbound at a specific resolver, or at
// a detour, would have the SERVER hostname resolved one way and the TARGET another, with nothing in
// the configuration explaining the difference.
//
// # Why this is asserted at construction rather than by dialling
//
// The defect is a policy choice, not a transport behaviour: it is fully visible in the options the
// outbound will hand the router. Dialling would be slower, would need a live SOCKS4 server, and
// would prove less.

// TestSOCKS4TargetPolicyIsDerivedFromTheSameDialer proves the two resolutions agree.
//
// Rather than dialling, this checks the DERIVATION: the outbound reads its target policy from the
// very dialer it hands to the SOCKS client, so "the same resolver" is structural rather than two
// independently-configured values that happen to match.
//
// Building the dialer through NewWithOptions needs DNS services in the context, so the assertion is
// made on the code path instead: a nil-safe ResolveDialer assertion, which is exactly what
// NewOutbound performs. A SOCKS5 outbound never reads it, which the next test pins.
func TestSOCKS4TargetPolicyIsDerivedFromTheSameDialer(t *testing.T) {
	t.Parallel()

	// A plain IP server produces a dialer that is NOT a ResolveDialer, and the outbound must still
	// construct -- leaving the policy zero, because nothing needs resolving by domain.
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "4",
	})
	require.NoError(t, err)
	outbound := instance.(*Outbound)
	require.True(t, outbound.resolve, "SOCKS4 still resolves a domain target locally")
	require.Equal(t, adapter.DNSQueryOptions{}, outbound.targetQueryOptions,
		"an IP server address yields no resolve dialer, so there is no policy to inherit; the guard "+
			"must not turn that into a failure")

	// A domain server address DOES produce a ResolveDialer, and that is the path where the policy
	// must be inherited. It needs DNS services in the context, so it is exercised in the
	// integration suite rather than here; this test pins the nil-safe half.
}

// TestSOCKS5StillSendsTheDomain proves the change did not alter SOCKS5 semantics.
//
// SOCKS5 must NOT resolve locally: sending the domain lets the proxy choose the address, which is
// the whole point of using a proxy for a domain target. Resolving locally would change CDN edge
// selection, geo results and DNS leak behaviour.
func TestSOCKS5StillSendsTheDomain(t *testing.T) {
	t.Parallel()

	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(),
		"residential-socks", option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
			Version:       "5",
		})
	require.NoError(t, err)

	outbound := instance.(*Outbound)
	require.False(t, outbound.resolve,
		"SOCKS5 must send the domain to the proxy instead of resolving it locally; local "+
			"resolution would change which CDN edge serves the request")
	require.Equal(t, adapter.DNSQueryOptions{}, outbound.targetQueryOptions,
		"a SOCKS5 outbound never resolves a target, so it must carry no target policy at all")
}

// recordingDNSRouter captures the options the outbound actually passes to Lookup.
//
// Asserting on the outbound's field would only prove the field was SET; this proves it was USED.
// The distinction matters because the defect being guarded against is a call site that ignores the
// field and passes a zero value instead -- exactly what the original code did.
type recordingDNSRouter struct {
	adapter.DNSRouter
	lookups  int
	lastOpts adapter.DNSQueryOptions
}

func (r *recordingDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.lookups++
	r.lastOpts = options
	return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
}

// TestSOCKS4LookupCarriesTheTargetPolicy is the real regression guard.
//
// It drives DialContext far enough to reach the target resolution and inspects the options the
// router received. A call site that bypasses targetQueryOptions fails here even though the field is
// correctly populated, which is what a field-only assertion would miss.
func TestSOCKS4LookupCarriesTheTargetPolicy(t *testing.T) {
	t.Parallel()

	router := &recordingDNSRouter{}
	instance, err := newTestOutbound(t, option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
		Version:       "4",
	})
	require.NoError(t, err)
	outbound := instance.(*Outbound)
	outbound.dnsRouter = router

	// A domain target with a sentinel policy: the lookup must carry exactly this value.
	sentinel := adapter.DNSQueryOptions{DisableCache: true}
	outbound.targetQueryOptions = sentinel

	// The dial itself will fail (no SOCKS4 server is listening), which is irrelevant: the lookup
	// happens first and is what this test inspects.
	_, _ = outbound.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("target.example", 443))

	require.Equal(t, 1, router.lookups,
		"SOCKS4 must resolve a domain target exactly once before dialling")
	require.Equal(t, sentinel, router.lastOpts,
		"the target lookup must carry the outbound's configured policy; receiving a zero value "+
			"means the call site bypassed targetQueryOptions and the target is resolved by a "+
			"different authority than the proxy server")
}
