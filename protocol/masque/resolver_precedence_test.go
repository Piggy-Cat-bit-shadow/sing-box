package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for the resolver precedence:
//
//	explicit inner_domain_resolver  >  server-pushed DNS_ASSIGN  >  normal DNS rules
//
// This is a security property, not a convenience. The operator's explicit configuration
// is the trusted input and a server must not be able to redirect the client's DNS by
// pushing an assignment. The reverse direction matters too: when no explicit resolver is
// set, an assignment that IS routable through the tunnel must actually take effect,
// otherwise the feature is inert.

func testEndpointWithAssignment() *ClientEndpoint {
	return &ClientEndpoint{
		endpointBase: endpointBase{logger: logger.NOP()},
		ctx:          context.Background(),
		assignedDNS:  newAssignedDNSTransport(logger.NOP(), nil, "test-assigned"),
	}
}

func reachableAssignment() masque.Configuration {
	return masque.Configuration{
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		Routes: []masque.AddressRange{{
			Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"),
		}},
		DNS: &masque.DNSAssignment{
			Generation: 1,
			Configurations: []masque.DNSConfiguration{{
				Nameservers: []masque.DNSNameserver{{
					ServicePriority: 1,
					IPv4Addresses:   []netip.Addr{netip.MustParseAddr("10.0.0.53")},
				}},
				InternalDomains: []string{""},
			}},
		},
	}
}

// TestExplicitInnerResolverBeatsServerAssignment is the precedence test.
//
// With an explicit resolver configured, a server-pushed assignment must be recorded and
// IGNORED. Installing it would let the server override the operator's choice of where
// DNS goes, which is exactly the authority an explicit configuration exists to withhold.
func TestExplicitInnerResolverBeatsServerAssignment(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	// An explicit resolver is represented by a non-nil transport in the query options,
	// which is how the router fast path is selected.
	endpoint.innerQueryOptions = adapter.DNSQueryOptions{
		Transport: &stubDNSTransport{tag: "explicit-inner"},
	}

	endpoint.installAssignedDNS(reachableAssignment())

	require.False(t, endpoint.assignedDNS.active(),
		"an explicit inner resolver must prevent the server assignment from being installed")
}

// TestServerAssignmentAppliesWhenNoExplicitResolver is the positive half, so the
// precedence test cannot pass by never installing anything.
func TestServerAssignmentAppliesWhenNoExplicitResolver(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	endpoint.innerQueryOptions = adapter.DNSQueryOptions{}

	endpoint.installAssignedDNS(reachableAssignment())

	require.True(t, endpoint.assignedDNS.active(),
		"with no explicit resolver, a routable assignment must take effect")
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.53")},
		endpoint.assignedDNS.ServerAddresses())
}

// TestUnroutableAssignmentIsRefused is the leak-prevention test at the endpoint level.
//
// draft-ietf-masque-connect-ip-dns-06 §5 warns that an assignment can cause an endpoint
// to use a nameserver OUTSIDE the tunnel. A nameserver outside the advertised routes
// would be reached by the ordinary routing table, so it must not be installed at all.
func TestUnroutableAssignmentIsRefused(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	endpoint.innerQueryOptions = adapter.DNSQueryOptions{}

	configuration := reachableAssignment()
	// A public resolver, outside the advertised 10.0.0.0/24 route.
	configuration.DNS.Configurations[0].Nameservers[0].IPv4Addresses =
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")}

	endpoint.installAssignedDNS(configuration)

	require.False(t, endpoint.assignedDNS.active(),
		"a nameserver outside the advertised routes must be refused, not installed")
}

// TestAssignmentWithoutRoutesIsRefused enforces the draft's ordering rule from the
// receiving side.
//
// §5 requires that DNS_ASSIGN not precede ROUTE_ADVERTISEMENT. Rather than trusting the
// peer to respect the order, an assignment that arrives with no routes in force is
// treated as unroutable.
func TestAssignmentWithoutRoutesIsRefused(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	endpoint.innerQueryOptions = adapter.DNSQueryOptions{}

	configuration := reachableAssignment()
	configuration.Routes = nil

	endpoint.installAssignedDNS(configuration)
	require.False(t, endpoint.assignedDNS.active(),
		"an assignment received before any route advertisement must not be installed")
}

// TestWithdrawnAssignmentClearsTheResolver proves a withdrawal takes effect, rather
// than leaving the previous server-assigned resolver answering queries.
func TestWithdrawnAssignmentClearsTheResolver(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	endpoint.installAssignedDNS(reachableAssignment())
	require.True(t, endpoint.assignedDNS.active())

	withdrawn := reachableAssignment()
	withdrawn.DNS = nil
	endpoint.installAssignedDNS(withdrawn)

	require.False(t, endpoint.assignedDNS.active(),
		"a withdrawn assignment must clear the resolver")
}

// TestPartialReachabilityDropsOnlyTheUnreachableResolver pins the reachability rule.
//
// The unit of the decision is the RESOLVER, not the assignment. Two resolvers in one
// configuration are servers that answer the same questions, so dropping the one whose
// address is outside the tunnel still leaves those questions answered -- by the other,
// inside the tunnel. Refusing the whole configuration instead would discard a usable
// resolver, and refusing the whole assignment would also discard every OTHER configuration,
// including ones for domains that had nothing to do with the unreachable address.
//
// What must never happen is the unreachable resolver being INSTALLED, because its queries
// would leave the tunnel in cleartext. That is what the second assertion checks.
func TestPartialReachabilityDropsOnlyTheUnreachableResolver(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	configuration := reachableAssignment()
	configuration.DNS.Configurations[0].Nameservers = []masque.DNSNameserver{
		{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.53")}},
		{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
	}

	endpoint.installAssignedDNS(configuration)

	require.True(t, endpoint.assignedDNS.active(),
		"the reachable resolver in the configuration must still be installed")

	state := endpoint.assignedDNS.state.Load()
	require.NotNil(t, state)
	require.Len(t, state.configurations, 1)
	require.Len(t, state.configurations[0].resolvers, 1,
		"only the unreachable resolver may be dropped")
	require.Equal(t, netip.MustParseAddr("10.0.0.53"), state.configurations[0].resolvers[0].addresses[0],
		"the resolver that remains must be the reachable one, never the public address")
}

// TestConfigurationWithNoReachableResolverIsDropped proves a configuration whose resolvers
// are ALL unreachable is removed, along with the domains it claimed.
//
// Keeping the configuration with an empty resolver list would make it capture matching
// names and then fail them, which is worse than letting a broader configuration answer.
func TestConfigurationWithNoReachableResolverIsDropped(t *testing.T) {
	t.Parallel()

	endpoint := testEndpointWithAssignment()
	configuration := reachableAssignment()
	configuration.DNS.Configurations[0].Nameservers = []masque.DNSNameserver{
		{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
	}

	endpoint.installAssignedDNS(configuration)

	require.False(t, endpoint.assignedDNS.active(),
		"a configuration with no reachable resolver must be dropped")
}

// TestNameserverWithoutAddressIsNotReachable covers the nameserver-reachable-only-by-name
// shape from the draft's full-tunnel example.
//
// Resolving that name would itself need a resolver, and the addressless form is exactly
// the same-connection DoH case (a later stage). Until that path exists, treating it as
// reachable would install a resolver this transport cannot dial.
func TestNameserverWithoutAddressIsNotReachable(t *testing.T) {
	t.Parallel()

	nameserver := masque.DNSNameserver{
		ServicePriority:          1,
		AuthenticationDomainName: "dns.example.",
		ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
			dnsmessage.SVCParamALPN: {0x02, 'h', '2'},
		},
	}
	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"),
	}}
	require.False(t, nameserverReachable(nameserver, routes),
		"an addressless nameserver must not be treated as tunnel-reachable")
}

// TestNameserverWithAnyUnreachableAddressIsRefused proves one bad address is enough to
// refuse a nameserver, rather than trying the good ones and silently dropping the rest.
func TestNameserverWithAnyUnreachableAddressIsRefused(t *testing.T) {
	t.Parallel()

	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"),
	}}
	nameserver := masque.DNSNameserver{
		ServicePriority: 1,
		IPv4Addresses:   []netip.Addr{netip.MustParseAddr("10.0.0.53")},
		IPv6Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::53")},
	}
	require.False(t, nameserverReachable(nameserver, routes),
		"a nameserver with any address outside the routes must be refused")
}

// stubDNSTransport is an inert adapter.DNSTransport used only to mark "an explicit
// resolver is configured". It is never queried by these tests.
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
