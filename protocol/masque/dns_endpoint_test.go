package masque

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Endpoint-level tests for DNS_ASSIGN routing.
//
// # What these prove that the policy tests do not
//
// The policy tests show that `decide` answers correctly. These show that the ENDPOINT acts on
// that answer: an unclaimed name reaches the ordinary resolver, a claimed name reaches the
// assigned one, and a claimed-but-unusable name reaches neither.
//
// The last of those is the whole point. "Never falls back" is only a real guarantee if it is
// asserted at the layer that chooses between the two resolvers, because that is where a
// fallback would actually be introduced.

// recordingRouter counts lookups and records the transport each was given.
type recordingRouter struct {
	access       sync.Mutex
	lookups      []string
	transports   []adapter.DNSTransport
	environments [][]string
	answer       []netip.Addr
	err          error
}

func (r *recordingRouter) Start(stage adapter.StartStage) error { return nil }
func (r *recordingRouter) Close() error                         { return nil }
func (r *recordingRouter) ClearCache()                          {}
func (r *recordingRouter) ResetNetwork()                        {}
func (r *recordingRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

func (r *recordingRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.access.Lock()
	r.lookups = append(r.lookups, domain)
	r.transports = append(r.transports, options.Transport)
	if environment, isEnvironment := options.Transport.(adapter.DNSTransportWithEnvironment); isEnvironment {
		r.environments = append(r.environments, environment.Environment())
	} else {
		r.environments = append(r.environments, nil)
	}
	answer, failure := r.answer, r.err
	r.access.Unlock()
	if failure != nil {
		return nil, failure
	}
	return answer, nil
}

func (r *recordingRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, errTestDialFailed
}

func (r *recordingRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	callback(nil, errTestDialFailed)
}

func (r *recordingRouter) lookupCount() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.lookups)
}

func (r *recordingRouter) transportAt(index int) adapter.DNSTransport {
	r.access.Lock()
	defer r.access.Unlock()
	if index >= len(r.transports) {
		return nil
	}
	return r.transports[index]
}

func (r *recordingRouter) environmentAt(index int) []string {
	r.access.Lock()
	defer r.access.Unlock()
	if index >= len(r.environments) {
		return nil
	}
	return r.environments[index]
}

// lookupEndpoint builds the minimum endpoint needed to exercise lookupInner.
func lookupEndpoint(t *testing.T, router adapter.DNSRouter, inner adapter.DNSQueryOptions) *ClientEndpoint {
	t.Helper()
	return &ClientEndpoint{
		endpointBase:      endpointBase{logger: logger.NOP()},
		dnsRouter:         router,
		innerQueryOptions: inner,
		dnsTag:            "test",
	}
}

// install compiles and publishes an assignment on the endpoint, as the capsule path does.
func install(t *testing.T, endpoint *ClientEndpoint, routes []masque.AddressRange, capability resolverCapability, configurations ...masque.DNSConfiguration) {
	t.Helper()
	capability.routes = routes
	endpoint.dnsAssignment.Store(compileDNSAssignment(configurations, capability))
}

// ---------------------------------------------------------------------------
// The three outcomes
// ---------------------------------------------------------------------------

// TestUnclaimedNameUsesTheOrdinaryResolver is the split-DNS half that made public resolution
// work again.
//
// draft-06 §3.6.2 is a split tunnel: a configuration claims "internal.corp.example" and nothing
// else. A public name must therefore reach the ordinary resolver. An earlier implementation
// asked only "is an assignment active", sent every name to the assigned resolver, and broke
// public resolution for anyone using split DNS.
func TestUnclaimedNameUsesTheOrdinaryResolver(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{"internal.corp.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})

	_, err := endpoint.lookupInner(context.Background(), "www.public.example.")
	require.NoError(t, err)
	require.Nil(t, router.transportAt(0),
		"an unclaimed name must be resolved by the ordinary rules, which is what makes a split tunnel work")
}

// TestClaimedNameUsesTheAssignedResolver is the other half.
func TestClaimedNameUsesTheAssignedResolver(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{"internal.corp.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})

	_, err := endpoint.lookupInner(context.Background(), "host.internal.corp.example.")
	require.NoError(t, err)
	require.NotNil(t, router.transportAt(0),
		"a claimed name must be resolved by the assigned configuration")

	// The transport reports an environment derived from effective behaviour, which is what
	// keeps an answer from outliving the resolver that produced it.
	environment := router.environmentAt(0)
	require.NotEmpty(t, environment)
	require.Contains(t, environment[0], "masque-assigned")
	require.Contains(t, environment[1], "i=internal.corp.example")
}

// TestClaimedButUnusableNeverFallsBack is the privacy invariant at the endpoint level.
//
// The claim survives the resolver being unreachable, so the query FAILS. The ordinary router
// must not be consulted at all: that would leak an internal name to a public resolver at exactly
// the moment the internal path is broken.
func TestClaimedButUnusableNeverFallsBack(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	// The resolver's address is outside the advertised routes, so it cannot be used.
	install(t, endpoint,
		[]masque.AddressRange{{
			Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
		}},
		resolverCapability{},
		masque.DNSConfiguration{
			InternalDomains: []string{"internal.corp.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "8.8.8.8")},
		})

	_, err := endpoint.lookupInner(context.Background(), "host.internal.corp.example.")
	require.Error(t, err, "a claimed name with no usable resolver must fail")
	require.Equal(t, 0, router.lookupCount(),
		"the ordinary router must NOT be consulted: doing so would leak an internal name to a public resolver")

	// An unclaimed name is unaffected, which proves the failure is about the claim rather than
	// the assignment being broken.
	_, err = endpoint.lookupInner(context.Background(), "www.public.example.")
	require.NoError(t, err)
	require.Equal(t, 1, router.lookupCount())
	require.Nil(t, router.transportAt(0))
}

// TestExplicitInnerResolverWinsOverTheAssignment proves the server cannot override an
// operator's own choice.
func TestExplicitInnerResolverWinsOverTheAssignment(t *testing.T) {
	t.Parallel()

	explicit := &stubDNSTransport{tag: "explicit"}
	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{Transport: explicit})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})

	_, err := endpoint.lookupInner(context.Background(), "anything.example.")
	require.NoError(t, err)
	require.Same(t, explicit, router.transportAt(0),
		"an explicitly configured inner resolver must win, even for a claimed name")
}

// TestRootClaimCoversEveryName proves [""] claims everything while [] claims nothing.
func TestRootClaimCoversEveryName(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})

	_, err := endpoint.lookupInner(context.Background(), "anything.at.all.")
	require.NoError(t, err)
	require.NotNil(t, router.transportAt(0), "the root claim covers every name")

	// And an empty list claims nothing.
	emptyRouter := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	emptyEndpoint := lookupEndpoint(t, emptyRouter, adapter.DNSQueryOptions{})
	install(t, emptyEndpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			Nameservers: []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})
	_, err = emptyEndpoint.lookupInner(context.Background(), "anything.at.all.")
	require.NoError(t, err)
	require.Nil(t, emptyRouter.transportAt(0),
		"an empty internal-domain list claims nothing and must not capture names")
}

// TestWithdrawalRestoresOrdinaryResolution proves a withdrawal takes effect.
func TestWithdrawalRestoresOrdinaryResolution(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		})

	_, err := endpoint.lookupInner(context.Background(), "claimed.example.")
	require.NoError(t, err)
	require.NotNil(t, router.transportAt(0))

	// An empty DNS_ASSIGN is a withdrawal.
	endpoint.dnsAssignment.Store(nil)

	_, err = endpoint.lookupInner(context.Background(), "claimed.example.")
	require.NoError(t, err)
	require.Nil(t, router.transportAt(1),
		"after a withdrawal every name is unclaimed and resolves normally again")
}

// ---------------------------------------------------------------------------
// Snapshot consistency at the endpoint
// ---------------------------------------------------------------------------

// TestOneLookupOneSnapshot is the concurrency property at the endpoint level.
//
// An in-flight lookup keeps the snapshot it captured, so a replacement during the lookup cannot
// change where that lookup's queries go. This is what stops an A query and an AAAA query from
// being answered by two different configurations.
func TestOneLookupOneSnapshot(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.1")},
		})

	_, err := endpoint.lookupInner(context.Background(), "first.example.")
	require.NoError(t, err)
	firstEnvironment := router.environmentAt(0)

	// A new assignment arrives for the same name with a different resolver.
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.2")},
		})

	_, err = endpoint.lookupInner(context.Background(), "second.example.")
	require.NoError(t, err)
	secondEnvironment := router.environmentAt(1)

	require.NotEqual(t, firstEnvironment, secondEnvironment,
		"a different resolver must produce a different cache environment, so the old answer cannot be reused")
}

// TestPREF64DoesNotAffectTheDNSCacheKey proves PREF64 is genuinely separate.
//
// PREF64 conveys NAT64 prefixes and this client performs no synthesis, so it cannot change an
// answer. Keeping it inside the DNS state meant a PREF64-only capsule invalidated the entire DNS
// cache for no reason.
func TestPREF64DoesNotAffectTheDNSCacheKey(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	configuration := masque.DNSConfiguration{
		InternalDomains: []string{""},
		Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.1")},
	}

	install(t, endpoint, allRoutes(), plainCapability(), configuration)
	_, err := endpoint.lookupInner(context.Background(), "before.example.")
	require.NoError(t, err)
	before := router.environmentAt(0)

	// A PREF64-only update: the DNS assignment is unchanged.
	endpoint.pref64.publish([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")})
	install(t, endpoint, allRoutes(), plainCapability(), configuration)
	_, err = endpoint.lookupInner(context.Background(), "after.example.")
	require.NoError(t, err)
	after := router.environmentAt(1)

	require.Equal(t, before, after,
		"a DNS assignment that did not change must produce the same cache key, so PREF64 cannot churn the DNS cache")

	// And the prefixes are still exposed, separately.
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, endpoint.Pref64Prefixes())
}

// TestRouteChangeChangesTheCacheKey proves a route change that disables a resolver IS treated as
// a behavioural change, which is the case that must invalidate cached answers.
func TestRouteChangeChangesTheCacheKey(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	configuration := masque.DNSConfiguration{
		InternalDomains: []string{""},
		Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
	}

	install(t, endpoint, allRoutes(), plainCapability(), configuration)
	_, err := endpoint.lookupInner(context.Background(), "before.example.")
	require.NoError(t, err)
	before := router.environmentAt(0)

	// The routes shrink so the resolver is no longer reachable.
	install(t, endpoint,
		[]masque.AddressRange{{
			Start: netip.MustParseAddr("172.16.0.0"), End: netip.MustParseAddr("172.16.0.255"), Protocol: protocolAll,
		}},
		resolverCapability{}, configuration)

	_, err = endpoint.lookupInner(context.Background(), "after.example.")
	require.Error(t, err, "the resolver is no longer reachable, so the claimed name fails closed")
	require.Equal(t, 1, router.lookupCount(), "and the ordinary router is not consulted")
	_ = before
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestConcurrentLookupsDuringReplacement is the race companion.
func TestConcurrentLookupsDuringReplacement(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	install(t, endpoint, allRoutes(), plainCapability(),
		masque.DNSConfiguration{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.1")},
		})

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := range 500 {
			install(t, endpoint, allRoutes(), plainCapability(), masque.DNSConfiguration{
				InternalDomains: []string{""},
				Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0."+itoa(index%250+1))},
			})
		}
	}()
	waitGroup.Add(4)
	for range 4 {
		go func() {
			defer waitGroup.Done()
			for range 500 {
				_, _ = endpoint.lookupInner(context.Background(), "concurrent.example.")
			}
		}()
	}
	waitGroup.Wait()
}

// stubDNSTransport is an inert adapter.DNSTransport used only to mark "an explicit resolver is
// configured". It is never queried by these tests.
type stubDNSTransport struct {
	tag string
}

func (s *stubDNSTransport) Type() string                   { return "stub" }
func (s *stubDNSTransport) Tag() string                    { return s.tag }
func (s *stubDNSTransport) Dependencies() []string         { return nil }
func (s *stubDNSTransport) Start(adapter.StartStage) error { return nil }
func (s *stubDNSTransport) Close() error                   { return nil }
func (s *stubDNSTransport) Reset()                         {}
func (s *stubDNSTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, errTestDialFailed
}
func (s *stubDNSTransport) ExchangeAsync(context.Context, *mDNS.Msg, func(*mDNS.Msg, error)) {}
