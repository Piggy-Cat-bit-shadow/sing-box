package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	http "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Constructor-level integration tests.
//
// # Why these exist, and why component tests were not enough
//
// The bootstrap cache and the handshake racer were fully implemented, fully unit-tested and
// completely unreachable from production. Nothing in the runtime ever called
// newBootstrapCache, newBootstrapDialer or masqueConnDialer: the constructor passed the raw
// outbound dialer to the HTTP client and left ClientOptions.HTTP3ConnDialer nil. Every unit
// test passed, because a unit test constructs the component itself.
//
// That is the failure these tests are written to make impossible. They do not build a
// bootstrapCache or a handshakeRacer. They call the REAL NewClientEndpoint and then inspect
// the object it built, so a component that is not wired in cannot pass.
//
// # Why the assertions reach into private fields
//
// The properties under test are exactly "is this field set on the object the constructor
// returned". There is no public surface that reports them, and adding one purely for tests
// would be a new API. Reaching into the package's own private fields from its own test file
// is the honest way to assert on wiring.

// fakeBootstrapRouter is a DNS router that answers the MASQUE server hostname.
//
// It counts lookups and can be made to fail, so a test can prove the bootstrap path really
// ran and really fell back to the cache.
type fakeBootstrapRouter struct {
	access  sync.Mutex
	lookups []string
	answer  []netip.Addr
	fail    bool
	// failAfter makes the first N lookups succeed and everything after fail, which is how
	// a resolver outage during a reconnect is simulated.
	failAfter int
	calls     int
}

func (r *fakeBootstrapRouter) Start(stage adapter.StartStage) error { return nil }
func (r *fakeBootstrapRouter) Close() error                         { return nil }
func (r *fakeBootstrapRouter) ClearCache()                          {}
func (r *fakeBootstrapRouter) ResetNetwork()                        {}
func (r *fakeBootstrapRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}

func (r *fakeBootstrapRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, errTestDialFailed
}

func (r *fakeBootstrapRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	callback(nil, errTestDialFailed)
}

func (r *fakeBootstrapRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.access.Lock()
	defer r.access.Unlock()
	r.calls++
	r.lookups = append(r.lookups, domain)
	if r.fail {
		return nil, errTestBootstrapUnavailable
	}
	if r.failAfter > 0 && r.calls > r.failAfter {
		return nil, errTestBootstrapUnavailable
	}
	return append([]netip.Addr(nil), r.answer...), nil
}

func (r *fakeBootstrapRouter) lookupCount() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.lookups)
}

// buildTestEndpoint constructs a real MASQUE client endpoint.
//
// The context carries a fake DNS router through the service registry, which is the same
// mechanism production uses (service.FromContext), so the constructor takes its normal path
// rather than a test-only one.
func buildTestEndpoint(t *testing.T, router adapter.DNSRouter, serverAddress string, tlsOptions option.OutboundTLSOptions) (adapter.Endpoint, error) {
	t.Helper()
	ctx := newTestRegistryContext(router)
	endpointOptions := option.MASQUEClientEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     serverAddress,
			ServerPort: 443,
		},
		DialerOptions: option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{
					Server: "dns-bootstrap",
				},
			},
		},
		Version: 3,
		Path:    "/",
	}
	// TLS is promoted from an embedded struct, so it cannot be set in the literal.
	endpointOptions.TLS = &tlsOptions
	return NewClientEndpoint(ctx, nil, logger.NOP(), "masque-test", endpointOptions)
}

// newBootstrapTLSOptions builds TLS options that will not be exercised by a real handshake.
func newBootstrapTLSOptions() option.OutboundTLSOptions {
	return option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "masque.example",
		Insecure:   true,
	}
}

// errTestBootstrapUnavailable stands in for a resolver outage.
var errTestBootstrapUnavailable = E.New("test: bootstrap resolver unavailable")

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// TestConstructorWiresBootstrapRecoveryIntoTheDialer is the P0 wiring test.
//
// It proves the object the constructor built actually uses a bootstrap cache, which is what
// was missing: the cache existed and was unit-tested while nothing in the runtime could
// reach it.
func TestConstructorWiresBootstrapRecoveryIntoTheDialer(t *testing.T) {
	t.Parallel()

	router := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err, "the constructor must accept a domain server with a bootstrap resolver")
	defer endpoint.Close()

	clientEndpoint, isClientEndpoint := endpoint.(*ClientEndpoint)
	require.True(t, isClientEndpoint)

	// The HTTP client must be holding the bootstrap dialer, not the raw outbound dialer.
	httpClient := httpClientOf(t, clientEndpoint)
	require.NotNil(t, httpClient, "the constructor must have built an HTTP client")

	// The strongest available assertion: ask the dialer the HTTP client holds whether it
	// is the bootstrap wrapper. A raw dialer cannot answer this.
	_, wired := httpClientDialer(t, clientEndpoint).(*bootstrapDialer)
	require.True(t, wired,
		"the HTTP client must dial through the bootstrap wrapper; if it holds the raw dialer then the recovery cache is unreachable from the runtime, which is exactly the defect this test exists to catch")
}

// TestConstructorLeavesHookNilWithoutAResolver proves the change is conditional.
//
// A server addressed by literal IP has nothing to resolve, so there is no bootstrap list to
// race. In that case the endpoint must behave exactly as it did before: original dialer, nil
// hook, no racer. Substituting a wrapper that can only fail would turn a working endpoint
// into a broken one.
func TestConstructorLeavesHookNilWithoutAResolver(t *testing.T) {
	t.Parallel()

	endpoint, err := buildTestEndpoint(t, nil, "192.0.2.10", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)
	require.Nil(t, http3ConnDialerOf(t, clientEndpoint),
		"an endpoint with no bootstrap resolver must leave the HTTP/3 hook nil so the default dial path is used unchanged")

	_, isWrapper := httpClientDialer(t, clientEndpoint).(*bootstrapDialer)
	require.False(t, isWrapper,
		"with nothing to resolve, the original dialer must be passed through untouched")
}

// TestConstructorSetsTheHTTP3ConnDialer proves Stage 5 is reachable from the runtime.
//
// The hook is the only way the handshake racer can run; if it is nil the racer is dead code
// no matter how well tested it is.
func TestConstructorSetsTheHTTP3ConnDialer(t *testing.T) {
	t.Parallel()

	router := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)
	hook := http3ConnDialerOf(t, clientEndpoint)
	require.NotNil(t, hook,
		"the constructor must install the handshake-racing hook, otherwise the racer never runs in production")
}

// TestConstructorHookRacesTheResolvedCandidates goes one step further than checking the hook
// is non-nil: it CALLS the hook and proves it consults the bootstrap resolver.
//
// A hook that is set but wired to the wrong thing would pass a nil check and still be
// useless, so this drives the real closure.
func TestConstructorHookRacesTheResolvedCandidates(t *testing.T) {
	t.Parallel()

	router := &fakeBootstrapRouter{answer: []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("192.0.2.11"),
	}}
	endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)
	hook := http3ConnDialerOf(t, clientEndpoint)
	require.NotNil(t, hook)

	// Drive the hook. It will fail to connect (nothing is listening), but the point is that it
	// RESOLVED first: the lookup count proves the bootstrap plane ran.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// The connector is supplied BY the transport in production. Here it is a stub, because
	// this test is about the hook consulting the bootstrap resolver, not about QUIC setup.
	connector := func(ctx context.Context, address netip.Addr) (net.Conn, *quic.Conn, error) {
		return nil, nil, errTestDialFailed
	}
	_, _, _ = hook(ctx, M.ParseSocksaddr("masque.example:443"), connector)

	require.GreaterOrEqual(t, router.lookupCount(), 1,
		"invoking the hook must consult the bootstrap resolver; a hook that never resolves would race an empty candidate list")
}

// ---------------------------------------------------------------------------
// Recovery end to end
// ---------------------------------------------------------------------------

// TestBootstrapRecoveryUsesTheCacheAfterTheResolverFails is the Stage 4 acceptance test at
// constructor level.
//
// It proves the sequence the design claims: a successful resolution populates the cache, and
// a LATER total resolver failure still produces a usable candidate list from that cache.
// Without the cache the second call fails, which is the reconnect storm this feature exists
// to survive.
func TestBootstrapRecoveryUsesTheCacheAfterTheResolverFails(t *testing.T) {
	t.Parallel()

	router := &fakeBootstrapRouter{
		answer:    []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		failAfter: 1, // the first lookup works, everything after fails
	}
	endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)
	bootstrap, isBootstrap := httpClientDialer(t, clientEndpoint).(*bootstrapDialer)
	require.True(t, isBootstrap)

	// First attempt: fresh resolution succeeds and populates the cache.
	first, err := bootstrap.resolveCandidates(context.Background(), "masque.example")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, first)

	// Second attempt: the resolver is now failing.
	second, err := bootstrap.resolveCandidates(context.Background(), "masque.example")
	require.NoError(t, err,
		"a resolver outage must fall back to the cache rather than failing the reconnect")
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, second,
		"the cached address must be offered so the connection can still be attempted")

	require.GreaterOrEqual(t, router.lookupCount(), 2,
		"the cache must still try the fresh lookup first; it is a fallback, not a replacement")
}

// TestBootstrapRecoveryRemembersTheWinningAddress proves promote() is reachable and useful:
// the address that actually connected is the one the fallback offers first.
func TestBootstrapRecoveryRemembersTheWinningAddress(t *testing.T) {
	t.Parallel()

	router := &fakeBootstrapRouter{
		answer: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("192.0.2.11"),
		},
		failAfter: 1,
	}
	endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	bootstrap := httpClientDialer(t, endpoint.(*ClientEndpoint)).(*bootstrapDialer)

	_, err = bootstrap.resolveCandidates(context.Background(), "masque.example")
	require.NoError(t, err)

	// The SECOND address is the one that connected, so recovery must offer it first.
	bootstrap.cache.promote(netip.MustParseAddr("192.0.2.11"))

	recovered, err := bootstrap.resolveCandidates(context.Background(), "masque.example")
	require.NoError(t, err)
	require.NotEmpty(t, recovered)
	require.Equal(t, netip.MustParseAddr("192.0.2.11"), recovered[0],
		"the address that actually worked must lead the recovery list")
}

// TestBootstrapCacheIsPerEndpoint proves the recovery state is not shared globally.
//
// Two endpoints must not inherit each other's addresses: the cache is keyed to one server
// hostname, and a shared cache would offer one server's address for another's connection.
func TestBootstrapCacheIsPerEndpoint(t *testing.T) {
	t.Parallel()

	firstRouter := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	firstEndpoint, err := buildTestEndpoint(t, firstRouter, "first.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer firstEndpoint.Close()

	secondRouter := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("198.51.100.20")}}
	secondEndpoint, err := buildTestEndpoint(t, secondRouter, "second.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer secondEndpoint.Close()

	firstBootstrap := httpClientDialer(t, firstEndpoint.(*ClientEndpoint)).(*bootstrapDialer)
	secondBootstrap := httpClientDialer(t, secondEndpoint.(*ClientEndpoint)).(*bootstrapDialer)
	require.NotSame(t, firstBootstrap.cache, secondBootstrap.cache,
		"each endpoint must own its recovery state")

	_, err = firstBootstrap.resolveCandidates(context.Background(), "first.example")
	require.NoError(t, err)

	require.Equal(t, 0, secondBootstrap.cache.cachedForTest(),
		"one endpoint's resolution must not populate another endpoint's cache")
}

// TestConcurrentEndpointConstructionIsIndependent is the race companion.
//
// Endpoints are built at configuration reload, which can overlap with an in-flight
// connection attempt. Each must end up with its own cache and its own hook.
func TestConcurrentEndpointConstructionIsIndependent(t *testing.T) {
	t.Parallel()

	var waitGroup sync.WaitGroup
	var failures atomic.Int64
	endpoints := make([]adapter.Endpoint, 8)
	for index := range endpoints {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			router := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
			endpoint, err := buildTestEndpoint(t, router, "masque.example", newBootstrapTLSOptions())
			if err != nil {
				failures.Add(1)
				return
			}
			endpoints[index] = endpoint
		}()
	}
	waitGroup.Wait()
	require.Zero(t, failures.Load())

	caches := make([]*bootstrapCache, 0, len(endpoints))
	for _, endpoint := range endpoints {
		require.NotNil(t, endpoint)
		bootstrap := httpClientDialer(t, endpoint.(*ClientEndpoint)).(*bootstrapDialer)
		require.NotNil(t, http3ConnDialerOf(t, endpoint.(*ClientEndpoint)))
		caches = append(caches, bootstrap.cache)
		require.NoError(t, endpoint.Close())
	}
	for i := range caches {
		for j := i + 1; j < len(caches); j++ {
			require.NotSame(t, caches[i], caches[j],
				"concurrently built endpoints must not share recovery state")
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// httpClientDialer extracts the dialer the endpoint's HTTP client dials through.
func httpClientDialer(t *testing.T, endpoint *ClientEndpoint) N.Dialer {
	t.Helper()
	return endpoint.httpDialer
}

// http3ConnDialerOf extracts the HTTP/3 hook the endpoint installed.
func http3ConnDialerOf(t *testing.T, endpoint *ClientEndpoint) http.HTTP3ConnDialer {
	t.Helper()
	return endpoint.http3ConnDialer
}

// httpClientOf is kept separate so a nil HTTP client is reported clearly.
func httpClientOf(t *testing.T, endpoint *ClientEndpoint) *http.Client {
	t.Helper()
	return endpoint.httpClient
}

// bootstrapProbeDialer returns a dialer the hook can use without touching the network.
func (c *ClientEndpoint) bootstrapProbeDialer(t *testing.T) N.Dialer {
	t.Helper()
	return &closedPortDialer{}
}

// closedPortDialer always fails, so a hook invocation is cheap and offline.
type closedPortDialer struct{}

func (d *closedPortDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errTestDialFailed
}

func (d *closedPortDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errTestDialFailed
}

// newRacerTestTLSConfig builds a client config for driving the hook directly.
func newRacerTestTLSConfig(t *testing.T) aTLS.Config {
	t.Helper()
	return racerTestTLSConfig(t)
}

// ---------------------------------------------------------------------------
// DNS assignment plane, through the real constructor
// ---------------------------------------------------------------------------

// TestConstructorAcceptsADNSAssignmentAndRoutesOnIt proves the DNS plane is reachable through
// the REAL constructor, not only through a hand-built endpoint.
//
// The bootstrap plane had a dedicated constructor test because it was once wired nowhere. The
// DNS plane needs the same treatment for the same reason: a snapshot that nothing publishes to
// is indistinguishable, from a unit test's point of view, from one that works. This test builds
// a real endpoint, hands it a capsule the way the session does, and then checks that a lookup
// is actually routed by it.
func TestConstructorAcceptsADNSAssignmentAndRoutesOnIt(t *testing.T) {
	t.Parallel()

	lookupRouter := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}
	endpoint, err := buildTestEndpoint(t, lookupRouter, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)

	// Nothing is claimed before an assignment arrives, so a name resolves normally.
	_, err = clientEndpoint.lookupInner(context.Background(), "host.internal.corp.example.")
	require.NoError(t, err)
	require.Nil(t, router0(lookupRouter), "with no assignment every name is unclaimed")

	// The server sends a split-tunnel assignment, as UpdateConfiguration would deliver it.
	clientEndpoint.installAssignedDNS(masque.Configuration{
		Routes: []masque.AddressRange{{
			Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
		}},
		DNS: &masque.DNSAssignment{
			Configurations: []masque.DNSConfiguration{{
				InternalDomains: []string{"internal.corp.example."},
				Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
			}},
		},
	})

	// The claimed name now routes to the assigned configuration.
	_, err = clientEndpoint.lookupInner(context.Background(), "host.internal.corp.example.")
	require.NoError(t, err)
	require.NotNil(t, router0(lookupRouter),
		"the assignment must have been published and be routing the name it claims")

	// And an unclaimed name still resolves normally, which is what makes it a split tunnel.
	_, err = clientEndpoint.lookupInner(context.Background(), "www.public.example.")
	require.NoError(t, err)
	require.Equal(t, 3, lookupRouter.lookupCount())
	require.Nil(t, lookupRouter.transportAt(2), "an unclaimed name must not use the assigned configuration")
}

// TestConstructorKeepsPREF64OutOfTheDNSCacheKey proves the two capsules are independent through
// the real constructor.
func TestConstructorKeepsPREF64OutOfTheDNSCacheKey(t *testing.T) {
	t.Parallel()

	lookupRouter := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}
	endpoint, err := buildTestEndpoint(t, lookupRouter, "masque.example", newBootstrapTLSOptions())
	require.NoError(t, err)
	defer endpoint.Close()

	clientEndpoint := endpoint.(*ClientEndpoint)
	assignment := &masque.DNSAssignment{
		Configurations: []masque.DNSConfiguration{{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
		}},
	}
	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
	}}

	clientEndpoint.installAssignedDNS(masque.Configuration{Routes: routes, DNS: assignment})
	_, err = clientEndpoint.lookupInner(context.Background(), "before.example.")
	require.NoError(t, err)
	before := lookupRouter.environmentAt(0)

	// The same assignment, now with NAT64 prefixes alongside it.
	clientEndpoint.installAssignedDNS(masque.Configuration{
		Routes: routes,
		DNS:    assignment,
		PREF64: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
	})
	_, err = clientEndpoint.lookupInner(context.Background(), "after.example.")
	require.NoError(t, err)
	after := lookupRouter.environmentAt(1)

	require.Equal(t, before, after,
		"PREF64 arriving with an unchanged assignment must not change the DNS cache key")
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, clientEndpoint.Pref64Prefixes(),
		"and the prefixes must still be exposed separately")
}

// router0 returns the transport given to the most recent lookup.
func router0(router *recordingRouter) adapter.DNSTransport {
	router.access.Lock()
	defer router.access.Unlock()
	if len(router.transports) == 0 {
		return nil
	}
	return router.transports[len(router.transports)-1]
}
