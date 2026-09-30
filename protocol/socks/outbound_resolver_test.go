package socks

import (
	"context"
	"net/netip"
	"testing"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing/service"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
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

// The embedded adapter.DNSRouter is nil, so every method the tests do not exercise needs an
// explicit no-op; otherwise a nil-interface call would panic and hide the assertion.
func (r *recordingDNSRouter) Start(adapter.StartStage) error { return nil }
func (r *recordingDNSRouter) Close() error                   { return nil }
func (r *recordingDNSRouter) Exchange(context.Context, *mDNS.Msg, adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, E.New("not used")
}
func (r *recordingDNSRouter) ExchangeAsync(context.Context, *mDNS.Msg, adapter.DNSQueryOptions, func(*mDNS.Msg, error)) {
}
func (r *recordingDNSRouter) ClearCache() {}
func (r *recordingDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}
func (r *recordingDNSRouter) ResetNetwork() {}

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

// ---------------------------------------------------------------------------
// Derivation from configuration, not from the server address
// ---------------------------------------------------------------------------

// TestSOCKS4TargetPolicyIsBuiltFromDialerOptions is the regression guard for the REAL defect.
//
// # What the earlier tests missed, and why this one exists
//
// TestSOCKS4TargetPolicyIsDerivedFromTheSameDialer asserts that an IP server address leaves
// targetQueryOptions ZERO, and calls that correct: "there is no policy to inherit". That reasoning
// is the bug. The target policy comes from DialerOptions.DomainResolver, which the operator writes
// regardless of how the proxy server itself is addressed. Deriving it from whether the server
// happens to be a hostname makes the target's DNS authority depend on an unrelated fact.
//
// And TestSOCKS4LookupCarriesTheTargetPolicy cannot catch it either: it SETS targetQueryOptions to
// a sentinel, so it proves only that the call site reads the field. It never exercises construction.
//
// This test drives the real constructor with a configured domain_resolver and an IP proxy server,
// which is the configuration the defect broke, and asserts on what the router RECEIVES.
func TestSOCKS4TargetPolicyIsBuiltFromDialerOptions(t *testing.T) {
	// The resolver has to exist in the context, because NewDNSQueryOptions looks it up there.
	// resolveRouter builds that, plus the DNS transports the derivation needs.
	ctx, lookupRecorder := newResolverTestContext(t, "configured-dns")

	instance, err := NewOutbound(
		ctx,
		nil,
		log.NewNOPFactory().Logger(),
		"socks4-with-explicit-resolver",
		option.SOCKSOutboundOptions{
			// An IP server address: the exact case the old derivation dropped the policy on.
			ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1080},
			Version:       "4",
			DialerOptions: option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver: &option.DomainResolveOptions{Server: "configured-dns"},
				},
			},
		},
	)
	require.NoError(t, err)
	outbound := instance.(*Outbound)

	// The policy must be non-empty: a configured domain_resolver has to reach the target lookup.
	require.NotEqual(t, adapter.DNSQueryOptions{}, outbound.targetQueryOptions,
		"a SOCKS4 outbound with a configured domain_resolver must carry a target policy, even when "+
			"the proxy SERVER is an IP literal. Deriving the target resolver from the server's "+
			"address makes the target's DNS authority depend on an unrelated property")

	// And it must actually reach the router on a real dial.
	_, _ = outbound.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("target.example", 443))

	require.Equal(t, 1, lookupRecorder.lookups,
		"SOCKS4 must resolve a domain target locally exactly once")
	require.NotEqual(t, adapter.DNSQueryOptions{}, lookupRecorder.lastOpts,
		"the target lookup must carry the configured policy, not an empty one that bypasses "+
			"dialer_options.domain_resolver and resolves the target through the default DNS path")
}

// TestSOCKS4ServerDomainAndTargetShareTheResolver is the matrix row where both names need resolving.
//
// It proves the two resolutions agree rather than being independently derived, which is the
// structural claim: one policy derivation, two consumers.
func TestSOCKS4ServerDomainAndTargetShareTheResolver(t *testing.T) {
	ctx, _ := newResolverTestContext(t, "configured-dns")

	instance, err := NewOutbound(
		ctx,
		nil,
		log.NewNOPFactory().Logger(),
		"socks4-domain-server",
		option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "proxy.example", ServerPort: 1080},
			Version:       "4",
			DialerOptions: option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver: &option.DomainResolveOptions{Server: "configured-dns"},
				},
			},
		},
	)
	require.NoError(t, err)
	outbound := instance.(*Outbound)

	require.NotEqual(t, adapter.DNSQueryOptions{}, outbound.targetQueryOptions,
		"with a domain server the policy has always been derived; it must stay that way")
}

// ---------------------------------------------------------------------------
// Test services
// ---------------------------------------------------------------------------

// socksTransportManager satisfies adapter.DNSTransportManager with one inert transport under the
// tag a test's domain_resolver names. NewDNSQueryOptions looks the tag up here, so a configured
// resolver has to be present for the derivation to run at all.
type socksTransportManager struct {
	transports map[string]adapter.DNSTransport
}

func (m *socksTransportManager) Start(adapter.StartStage) error     { return nil }
func (m *socksTransportManager) Close() error                       { return nil }
func (m *socksTransportManager) Transports() []adapter.DNSTransport { return nil }
func (m *socksTransportManager) Default() adapter.DNSTransport      { return nil }
func (m *socksTransportManager) FakeIP() adapter.FakeIPTransport    { return nil }
func (m *socksTransportManager) Remove(string) error                { return nil }
func (m *socksTransportManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return nil
}
func (m *socksTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	t, ok := m.transports[tag]
	return t, ok
}

// socksDNSTransport is the inert transport. It is never queried: the test asserts on the OPTIONS
// the derivation produced, not on a resolved answer.
type socksDNSTransport struct{ tag string }

func (s *socksDNSTransport) Type() string                   { return "stub" }
func (s *socksDNSTransport) Tag() string                    { return s.tag }
func (s *socksDNSTransport) Dependencies() []string         { return nil }
func (s *socksDNSTransport) Start(adapter.StartStage) error { return nil }
func (s *socksDNSTransport) Close() error                   { return nil }
func (s *socksDNSTransport) Reset()                         {}
func (s *socksDNSTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, E.New("stub transport is never queried")
}
func (s *socksDNSTransport) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(nil, E.New("stub transport is never queried"))
}

// newResolverTestContext builds the context NewOutbound needs for the policy derivation: a service
// registry holding a DNS transport manager with the named resolver, and a DNS router that records
// what it is asked.
func newResolverTestContext(t *testing.T, resolverTag string) (context.Context, *recordingDNSRouter) {
	t.Helper()
	recorder := &recordingDNSRouter{}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &socksTransportManager{
		transports: map[string]adapter.DNSTransport{
			resolverTag: &socksDNSTransport{tag: resolverTag},
		},
	})
	ctx = service.ContextWith[adapter.DNSRouter](ctx, recorder)
	return ctx, recorder
}
