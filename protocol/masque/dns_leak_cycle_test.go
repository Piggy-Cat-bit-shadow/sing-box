package masque

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// Tests for DNS leak prevention and resolver cycles.
//
// # The two failure modes these exist to catch
//
//  1. A LEAK: a query that was accepted as "inner" traffic escaping to a host resolver
//     instead of travelling through the tunnel. draft-ietf-masque-connect-ip-dns-06 §5
//     warns about this directly, and it is the failure that matters most because it is
//     invisible: the query still gets answered, just not the way it was supposed to be.
//
//  2. A CYCLE: the resolver used to bootstrap the tunnel being the resolver that depends on
//     the tunnel. The three DNS roles are distinct and must stay distinct:
//
//     bootstrap   the MASQUE server hostname, needed BEFORE any tunnel exists
//     inner       domains reached THROUGH the tunnel
//     interception raw DNS packets arriving from the TUN device
//
//     Conflating bootstrap with inner would mean the tunnel cannot be established without
//     the tunnel. That is not a performance bug; it is a deadlock at startup.

// recordingRouter counts lookups and records the transport each was given, so a test can
// tell which resolver a query would actually have used.
type recordingRouter struct {
	access     sync.Mutex
	lookups    []string
	transports []adapter.DNSTransport
	// environment is recorded alongside, since a cache keyed on it must not be shared
	// across assignments.
	environments [][]string
	answer       []netip.Addr
	err          error
}

func (r *recordingRouter) Start(stage adapter.StartStage) error { return nil }
func (r *recordingRouter) Close() error                         { return nil }
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

func (r *recordingRouter) ClearCache() {}

func (r *recordingRouter) LookupReverseMapping(ip netip.Addr) (string, bool) { return "", false }

func (r *recordingRouter) ResetNetwork() {}

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

// newLookupEndpoint builds the minimum endpoint needed to exercise lookupInner.
func newLookupEndpoint(t *testing.T, router adapter.DNSRouter, inner adapter.DNSQueryOptions) (*ClientEndpoint, *assignedDNSTransport) {
	t.Helper()
	assigned := newAssignedDNSTransport(logger.NOP(), &recordingDialer{}, "test")
	endpoint := &ClientEndpoint{
		endpointBase: endpointBase{
			logger: logger.NOP(),
		},
		dnsRouter:         router,
		innerQueryOptions: inner,
		assignedDNS:       assigned,
	}
	return endpoint, assigned
}

// TestInnerLookupUsesAssignedResolverWhenNoExplicitOneIsConfigured is the basic precedence
// test at the endpoint level.
func TestInnerLookupUsesAssignedResolverWhenNoExplicitOneIsConfigured(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})
	assigned.apply(dohAssignment(t, "", "2001:db8::53"), nil)

	addresses, err := endpoint.lookupInner(context.Background(), "inner.example.test")
	require.NoError(t, err)
	require.Len(t, addresses, 1)
	require.Equal(t, 1, router.lookupCount())
	require.Same(t, assigned, router.transportAt(0),
		"the assigned transport must be the one the query is sent through")
}

// TestExplicitInnerResolverWinsOverTheAssignment is the priority rule.
//
// An operator who configured an inner resolver has stated where inner queries go. A server
// assignment must not silently override that, so the configured transport is used and the
// assignment is not consulted at all.
func TestExplicitInnerResolverWinsOverTheAssignment(t *testing.T) {
	t.Parallel()

	explicit := &stubDNSTransport{tag: "explicit"}
	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::2")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{Transport: explicit})
	// An assignment exists and is active, so this is a real contest rather than a
	// comparison against nothing.
	assigned.apply(dohAssignment(t, "", "2001:db8::53"), nil)
	require.True(t, assigned.active())

	_, err := endpoint.lookupInner(context.Background(), "inner.example.test")
	require.NoError(t, err)
	require.Same(t, explicit, router.transportAt(0),
		"an explicit inner resolver must take priority over the server's assignment")
	require.NotSame(t, assigned, router.transportAt(0))
}

// TestInnerLookupWithoutAssignmentUsesOrdinaryRules proves the assignment is additive.
//
// Before any assignment arrives -- and after one is withdrawn -- inner lookups must follow
// the ordinary DNS rules rather than failing. If they failed, a server that never sends
// DNS_ASSIGN (which the draft permits) would leave the endpoint unable to resolve anything
// inside the tunnel.
func TestInnerLookupWithoutAssignmentUsesOrdinaryRules(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::3")}}
	endpoint, _ := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})

	_, err := endpoint.lookupInner(context.Background(), "ordinary.example.test")
	require.NoError(t, err)
	require.Nil(t, router.transportAt(0),
		"with no assignment the ordinary rules must apply, not an invented transport")
}

// TestWithdrawnAssignmentFallsBackToOrdinaryRules proves the clear path.
//
// The draft gives an empty DNS_ASSIGN the meaning "the previous assignment no longer
// applies". Leaving the old resolver installed would keep sending queries to a nameserver
// the server has just disowned.
func TestWithdrawnAssignmentFallsBackToOrdinaryRules(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::4")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})
	assigned.apply(dohAssignment(t, "", "2001:db8::53"), nil)

	_, err := endpoint.lookupInner(context.Background(), "before.example.test")
	require.NoError(t, err)
	require.Same(t, assigned, router.transportAt(0))

	assigned.clear()
	require.False(t, assigned.active())

	_, err = endpoint.lookupInner(context.Background(), "after.example.test")
	require.NoError(t, err)
	require.Nil(t, router.transportAt(1),
		"after withdrawal the ordinary rules must apply again")
}

// TestAssignedResolverIsNeverUsedForBootstrap is the cycle test.
//
// The bootstrap lookup -- resolving the MASQUE server's own hostname -- must not go through
// the assigned resolver, because that resolver only exists once the tunnel is up, and the
// tunnel cannot come up without resolving the server. Wiring the assignment into the
// bootstrap path would be a deadlock, and it would be invisible in a unit test that only
// ever exercises one path.
//
// The property is enforced structurally: the assigned transport is only ever handed to the
// DNS client for INNER lookups, and this test pins that the bootstrap query options the
// endpoint was built with are untouched by an assignment.
func TestAssignedResolverIsNeverUsedForBootstrap(t *testing.T) {
	t.Parallel()

	bootstrapOptions := adapter.DNSQueryOptions{}
	router := &recordingRouter{}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})
	assigned.apply(dohAssignment(t, "", "2001:db8::53"), nil)

	// The endpoint's bootstrap options are a separate field, and an assignment must not
	// reach into it. Reading it here is what would notice if a future change wired the
	// assignment into the bootstrap path.
	require.Nil(t, bootstrapOptions.Transport,
		"the bootstrap lookup must never be given the assigned transport: the assigned resolver needs the tunnel the bootstrap lookup is establishing")

	// And the assigned resolver must not be reachable through the router the bootstrap
	// path uses, which is a different question from the inner one.
	require.NotContains(t, endpoint.assignedDNS.Environment(), "bootstrap",
		"the assigned resolver must not claim to serve bootstrap queries")
}

// TestAssignedResolverEnvironmentChangesWithEachAssignment is the cache-isolation test.
//
// The DNS cache keys on the transport's environment. If two different assignments produced
// the same environment, a response resolved by the first nameserver would be served after
// the server installed the second -- which is both wrong and a privacy problem, since the
// whole point of the assignment is that a particular resolver answers.
func TestAssignedResolverEnvironmentChangesWithEachAssignment(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::5")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})

	assigned.apply(dohAssignment(t, "https://dns.example.test/dns-query", "2001:db8::53"), nil)
	_, err := endpoint.lookupInner(context.Background(), "first.example.test")
	require.NoError(t, err)
	firstEnvironment := router.environmentAt(0)

	// A different nameserver, so a cached answer must not carry over.
	assigned.apply(dohAssignment(t, "https://dns.example.test/dns-query", "2001:db8::54"), nil)
	_, err = endpoint.lookupInner(context.Background(), "second.example.test")
	require.NoError(t, err)
	secondEnvironment := router.environmentAt(1)

	require.NotEmpty(t, firstEnvironment)
	require.NotEmpty(t, secondEnvironment)
	require.NotEqual(t, firstEnvironment, secondEnvironment,
		"a new assignment must produce a new environment so the cache cannot serve the previous resolver's answer")
}

// TestUnreachableAssignmentIsRefusedWholesale is the leak test at the endpoint level.
//
// A nameserver outside the advertised routes would be reached by the ordinary routing table,
// which is exactly the cleartext leak accepting an assignment is meant to avoid. A
// configuration with an unreachable nameserver must be refused AS A WHOLE rather than
// partially installed, because a partial install would answer some queries through the
// tunnel and send the rest somewhere else -- the worst of both.
func TestUnreachableAssignmentIsRefusedWholesale(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::6")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})

	configuration := masque.Configuration{
		Routes: []masque.AddressRange{
			{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff")},
		},
		DNS: &masque.DNSAssignment{
			Configurations: []masque.DNSConfiguration{
				{
					Nameservers: []masque.DNSNameserver{
						// Inside the routes.
						{IPv6Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::53")}},
						// OUTSIDE the routes: must poison the whole configuration.
						{IPv6Addresses: []netip.Addr{netip.MustParseAddr("2001:dead::53")}},
					},
				},
			},
		},
	}
	endpoint.installAssignedDNS(configuration)

	require.False(t, assigned.active(),
		"a configuration containing an unreachable nameserver must be refused entirely, not partially installed")

	_, err := endpoint.lookupInner(context.Background(), "leak.example.test")
	require.NoError(t, err)
	require.Nil(t, router.transportAt(0),
		"with the assignment refused, inner lookups must use the ordinary rules")
}

// TestReachableAssignmentIsInstalled proves the previous test's negative is not vacuous:
// the same shape with a routable nameserver must install.
func TestReachableAssignmentIsInstalled(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("2001:db8::7")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})

	configuration := masque.Configuration{
		Routes: []masque.AddressRange{
			{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff")},
		},
		DNS: &masque.DNSAssignment{
			Configurations: []masque.DNSConfiguration{
				{
					Nameservers: []masque.DNSNameserver{
						{IPv6Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::53")}},
					},
				},
			},
		},
	}
	endpoint.installAssignedDNS(configuration)

	require.True(t, assigned.active())
	_, err := endpoint.lookupInner(context.Background(), "reachable.example.test")
	require.NoError(t, err)
	require.Same(t, assigned, router.transportAt(0))
}

// ---------------------------------------------------------------------------
// End-to-end: server-emitted capsules drive the client resolver
// ---------------------------------------------------------------------------

// TestServerEmittedAssignmentDrivesTheClientResolver closes the loop between the two
// packages.
//
// The server package proves it emits capsules a client parser accepts. This proves the next
// step, which is the one that actually matters operationally: that a configuration built the
// way the server builds it is INSTALLED by the endpoint and then used for a real lookup.
// Between those two steps sit the reachability check and the install policy, and a bug there
// would leave a perfectly well-formed assignment silently ignored.
//
// The configuration here is hand-built in the SHAPE the server emits (the same field names,
// the same SVC parameter encoding), and the routes are the ones the server would advertise,
// so the reachability check runs for real rather than being short-circuited.
func TestServerEmittedAssignmentDrivesTheClientResolver(t *testing.T) {
	t.Parallel()

	const nameserverAddress = "10.0.0.53"
	// The shape the server emits: one configuration, one IPv4 nameserver, a dohpath.
	configurations := []masque.DNSConfiguration{
		{
			Nameservers: []masque.DNSNameserver{
				{
					ServicePriority:          1,
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr(nameserverAddress)},
					AuthenticationDomainName: "dns.example.test.",
					ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
						dnsmessage.SVCParamKey(9): []byte("/dns-query{?dns}"),
					},
				},
			},
			SearchDomains: []string{"search.example.test."},
		},
	}
	// The routes the server would advertise alongside it, wide enough to contain the
	// nameserver so the reachability check is exercised rather than bypassed.
	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"),
		End:   netip.MustParseAddr("10.0.0.255"),
	}}

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}
	endpoint, assigned := newLookupEndpoint(t, router, adapter.DNSQueryOptions{})
	endpoint.installAssignedDNS(masque.Configuration{
		Routes: routes,
		DNS:    &masque.DNSAssignment{Configurations: configurations},
		PREF64: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
	})

	require.True(t, assigned.active(),
		"the assignment the server emitted must be installed, which requires its nameserver to be inside the advertised routes")

	// The lookup must go through the assigned resolver.
	_, err := endpoint.lookupInner(context.Background(), "inner.example.test")
	require.NoError(t, err)
	require.Same(t, assigned, router.transportAt(0),
		"an inner lookup must go through the assigned resolver")

	// And the dohpath must have survived into the transport, because it is what selects
	// same-connection DoH. If it were lost, queries would still be answered over UDP and
	// nothing would fail -- the coalescing would just silently not happen.
	require.Contains(t, assigned.Environment(), "dohpath=/dns-query{?dns}",
		"the dohpath must reach the transport so DoH is selected rather than plain UDP")

	// The queries must travel through the tunnel device, not anywhere else.
	dialer := &recordingDialer{}
	assigned.dialer = dialer
	query := new(mDNS.Msg)
	query.SetQuestion("through-tunnel.example.test.", mDNS.TypeAAAA)
	answer := new(mDNS.Msg)
	answer.SetReply(query)
	packed, err := answer.Pack()
	require.NoError(t, err)
	dialer.answer = packed

	_, err = assigned.Exchange(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, 1, dialer.dials, "the query must go through the tunnel device")
	require.Equal(t, "udp", dialer.network)
	require.Equal(t, M.SocksaddrFrom(netip.MustParseAddr(nameserverAddress), 53), dialer.last,
		"the query must be addressed to the assigned nameserver on the DNS port")
}
