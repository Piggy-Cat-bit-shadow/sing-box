package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for the DNS assignment snapshot: compilation, and the pure policy that reads it.
//
// # The two questions, and why they are separate
//
//	WHICH configuration owns this name?   -> decide(), from the claims alone
//	WHICH resolver inside it can serve it? -> the compiled capability
//
// Ownership never depends on usability. That separation is the whole design: a claimed name
// whose resolver is unreachable must FAIL rather than fall back, and it can only be made to do
// so if the claim survives the resolver being unusable.

// allRoutes permits every address for every protocol, so a test that is not about routing gets
// plain DNS without having to align a range with an address.
func allRoutes() []masque.AddressRange {
	return []masque.AddressRange{
		{Start: netip.MustParseAddr("0.0.0.0"), End: netip.MustParseAddr("255.255.255.255"), Protocol: protocolAll},
		{Start: netip.MustParseAddr("::"), End: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Protocol: protocolAll},
	}
}

// plainCapability describes a client with no HTTP/3 tunnel but full route coverage.
func plainCapability(routes ...masque.AddressRange) resolverCapability {
	if routes == nil {
		routes = allRoutes()
	}
	return resolverCapability{routes: routes}
}

// h3Capability describes a client whose tunnel is HTTP/3 and authenticated for the origins
// given.
func h3Capability(authorities ...string) resolverCapability {
	return resolverCapability{
		tunnelIsHTTP3:     true,
		sameH3Authorities: authorities,
		routes:            allRoutes(),
	}
}

// plainResolver builds a nameserver with no service parameters, which draft-06 treats as
// unencrypted DNS with no encrypted transport offered.
func plainResolver(priority uint16, addresses ...string) masque.DNSNameserver {
	nameserver := masque.DNSNameserver{ServicePriority: priority}
	for _, address := range addresses {
		parsed := netip.MustParseAddr(address)
		if parsed.Is4() {
			nameserver.IPv4Addresses = append(nameserver.IPv4Addresses, parsed)
		} else {
			nameserver.IPv6Addresses = append(nameserver.IPv6Addresses, parsed)
		}
	}
	return nameserver
}

// dohResolver builds the draft's §3.6.1 shape: an authentication domain, alpn, and a dohpath,
// optionally with no address at all.
func dohResolver(priority uint16, authDomain string, dohPath string, addresses ...string) masque.DNSNameserver {
	nameserver := plainResolver(priority, addresses...)
	nameserver.AuthenticationDomainName = authDomain
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamALPN:   {0x02, 'h', '2', 0x02, 'h', '3'},
		dnsmessage.SVCParamKey(7): []byte(dohPath),
	}
	return nameserver
}

// compile builds a snapshot from one configuration, as the endpoint does.
func compile(t *testing.T, capability resolverCapability, internalDomains []string, nameservers ...masque.DNSNameserver) *dnsAssignmentSnapshot {
	t.Helper()
	snapshot := compileDNSAssignment([]masque.DNSConfiguration{{
		Nameservers:     nameservers,
		InternalDomains: internalDomains,
	}}, capability)
	require.NotNil(t, snapshot)
	return snapshot
}

// ---------------------------------------------------------------------------
// InternalDomains: [] versus [""]
// ---------------------------------------------------------------------------

// TestEmptyInternalDomainListClaimsNothing pins the semantics draft-06 actually defines.
//
// §3.5: "Sending an empty string as an internal domain indicates the DNS root; i.e., that the
// corresponding nameserver can resolve all domain names."
//
// It gives no meaning to an EMPTY LIST. An earlier implementation read `len(...) == 0` as "the
// default configuration", which is a guess the specification does not support and which silently
// turned unclaimed names into claimed ones -- the difference between "resolve this publicly" and
// "fail closed".
func TestEmptyInternalDomainListClaimsNothing(t *testing.T) {
	t.Parallel()

	snapshot := compile(t, plainCapability(), nil, plainResolver(1, "192.0.2.1"))

	require.False(t, snapshot.decide("example.com.").claimed,
		"an empty internal-domain list claims nothing, including the root")
	require.False(t, snapshot.decide(".").claimed)
}

// TestRootInternalDomainClaimsEverything is the other half.
func TestRootInternalDomainClaimsEverything(t *testing.T) {
	t.Parallel()

	snapshot := compile(t, plainCapability(), []string{""}, plainResolver(1, "192.0.2.1"))

	for _, name := range []string{"example.com.", "a.b.c.internal.", "."} {
		decision := snapshot.decide(name)
		require.True(t, decision.claimed, "the root claim must cover %s", name)
		require.True(t, decision.usable)
	}
}

// ---------------------------------------------------------------------------
// Longest match
// ---------------------------------------------------------------------------

// TestDecideUsesLongestMatchingInternalDomain proves the most specific claim wins.
//
// A first-match rule would make the result depend on the order the server serialised its
// configurations, so the same logical assignment could route one name two different ways.
func TestDecideUsesLongestMatchingInternalDomain(t *testing.T) {
	t.Parallel()

	snapshot := compileDNSAssignment([]masque.DNSConfiguration{
		{
			InternalDomains: []string{"example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "192.0.2.1")},
		},
		{
			InternalDomains: []string{"corp.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(9, "192.0.2.2")},
		},
		{
			InternalDomains: []string{""},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "192.0.2.3")},
		},
	}, plainCapability())

	for _, testCase := range []struct {
		name     string
		expected string
		reason   string
	}{
		{
			name: "a.corp.example.", expected: "192.0.2.2",
			reason: "the most specific claim wins even though its resolver has the WORST priority: priority orders resolvers within a configuration, it does not rank configurations",
		},
		{name: "corp.example.", expected: "192.0.2.2", reason: "the claimed name itself belongs to it"},
		{name: "b.example.", expected: "192.0.2.1", reason: "under the broader claim, not the specific one"},
		{name: "public.test.", expected: "192.0.2.3", reason: "only the root claim covers this"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			decision := snapshot.decide(testCase.name)
			require.True(t, decision.claimed)
			require.Equal(t, testCase.expected, decision.configuration.resolvers[0].addresses[0].String(), testCase.reason)
		})
	}
}

// TestDecideRespectsLabelBoundaries proves the suffix match starts at a label boundary.
//
// A plain suffix test would route `notcorp.example` to the resolver for `corp.example`, which
// never claimed it.
func TestDecideRespectsLabelBoundaries(t *testing.T) {
	t.Parallel()

	snapshot := compile(t, plainCapability(), []string{"corp.example."}, plainResolver(1, "192.0.2.1"))
	require.False(t, snapshot.decide("notcorp.example.").claimed,
		"the suffix has to begin at a label boundary, or an unrelated name is captured")
	require.True(t, snapshot.decide("a.corp.example.").claimed)
	require.True(t, snapshot.decide("corp.example.").claimed)
}

// TestDecideIsCaseAndRootDotInsensitive proves presentation cannot change routing.
func TestDecideIsCaseAndRootDotInsensitive(t *testing.T) {
	t.Parallel()

	snapshot := compile(t, plainCapability(), []string{"Corp.Example."}, plainResolver(1, "192.0.2.1"))
	for _, name := range []string{"a.corp.example.", "a.CORP.EXAMPLE.", "a.corp.example"} {
		require.True(t, snapshot.decide(name).claimed, "%s must match regardless of case or root dot", name)
	}
}

// ---------------------------------------------------------------------------
// Claimed versus usable
// ---------------------------------------------------------------------------

// TestClaimedButUnusableIsStillClaimed is the privacy invariant.
//
// A configuration whose resolvers cannot be reached keeps its claim, so a query for a claimed
// name fails closed instead of being handed to a public resolver. If the claim disappeared with
// the resolver, an unreachable internal nameserver would silently leak internal names.
func TestClaimedButUnusableIsStillClaimed(t *testing.T) {
	t.Parallel()

	// The resolver's address is outside the advertised routes, so it cannot be used.
	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
	}}
	snapshot := compile(t, resolverCapability{routes: routes},
		[]string{"internal.corp.example."}, plainResolver(1, "8.8.8.8"))

	decision := snapshot.decide("host.internal.corp.example.")
	require.True(t, decision.claimed,
		"the claim must survive its resolver being unusable")
	require.False(t, decision.usable,
		"and the resolver must be reported as unusable, so the caller fails closed")
	require.Equal(t, unusableRouteUnreachable, decision.configuration.resolvers[0].unusable)

	require.False(t, snapshot.decide("www.public.example.").claimed,
		"an unclaimed name is unaffected and still resolves normally")
}

// ---------------------------------------------------------------------------
// Transport selection
// ---------------------------------------------------------------------------

// TestAddresslessDoHIsUsableOnAnH3Tunnel is the draft's §3.6.1 full-tunnel example.
//
// It has NO addresses at all: alpn=h2,h3, a dohpath, and an authentication domain. It is reached
// as a request stream on the connection that already exists, so no tunnel-routed address is
// needed -- which is exactly why the draft omits one.
func TestAddresslessDoHIsUsableOnAnH3Tunnel(t *testing.T) {
	t.Parallel()

	nameserver := dohResolver(1, "masque.example.org.", "/dns-query{?dns}")

	onH3 := compile(t, h3Capability("masque.example.org"), []string{""}, nameserver)
	decision := onH3.decide("example.com.")
	require.True(t, decision.usable, "the draft's full-tunnel example must be usable")
	resolver := decision.configuration.resolvers[0]
	require.Equal(t, assignedTransportDoH, resolver.transport)
	require.Equal(t, "/dns-query", resolver.expandedPath, "the URI Template is expanded for POST")
	require.Empty(t, resolver.usableAddresses, "same-connection DoH uses no nameserver address")

	// On an H2 tunnel the same advertisement cannot be used: same-H3 DoH is unavailable and
	// there is no address for plain DNS.
	onH2 := compile(t, plainCapability(), []string{""}, nameserver)
	h2Decision := onH2.decide("example.com.")
	require.True(t, h2Decision.claimed, "the claim still holds")
	require.False(t, h2Decision.usable, "but nothing can serve it without a live H3 connection")
	require.Equal(t, unusableNoTransport, h2Decision.configuration.resolvers[0].unusable)
}

// TestSameOriginIsRequiredForDoH proves a resolver whose origin does not match the tunnel's
// authenticated origin does not get the same-connection path.
func TestSameOriginIsRequiredForDoH(t *testing.T) {
	t.Parallel()

	nameserver := dohResolver(1, "dns-a.example.", "/dns-query{?dns}", "192.0.2.1")
	snapshot := compile(t, h3Capability("masque.example.org"), []string{""}, nameserver)
	resolver := snapshot.decide("example.com.").configuration.resolvers[0]
	require.NotEqual(t, assignedTransportDoH, resolver.transport,
		"a different origin must not ride on the tunnel's credentials")
	require.Equal(t, assignedTransportPlainUDP, resolver.transport,
		"it falls back to plain DNS, which its address and the routes allow")
}

// TestTrailingRootDotNormalization proves the FQDN spelling the wire uses matches the authority
// spelling HTTP uses.
func TestTrailingRootDotNormalization(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		authority   string
		authDomain  string
		shouldMatch bool
		reason      string
	}{
		{"masque.example", "masque.example.", true, "the wire FQDN and the HTTP authority are the same host"},
		{"masque.example.", "masque.example", true, "and the reverse"},
		{"MASQUE.Example", "masque.example.", true, "host names are case-insensitive"},
		{"masque.example:443", "masque.example.", true, "an explicit default port is the same origin"},
		{"masque.example:8443", "masque.example.", false, "a non-default port is a different origin"},
		{"dns-b.example.", "dns-a.example.", false, "a different host is a different origin"},
	} {
		t.Run(testCase.authority+" vs "+testCase.authDomain, func(t *testing.T) {
			t.Parallel()
			capability := h3Capability(testCase.authority)
			require.Equal(t, testCase.shouldMatch, capability.sameH3AvailableFor(testCase.authDomain), testCase.reason)
		})
	}
}

// TestNoDefaultALPNForbidsCleartext proves the parameter is binding rather than advisory.
//
// draft-06 §3.2: omitting no-default-alpn indicates the nameserver supports unencrypted DNS.
// Its presence therefore means the opposite, and falling back to UDP port 53 would send the query
// to a server that explicitly said not to.
func TestNoDefaultALPNForbidsCleartext(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.AuthenticationDomainName = "a.example."
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamALPN:          {0x03, 'd', 'o', 't'},
		dnsmessage.SVCParamNoDefaultALPN: {},
	}
	// Compiled against an H2 tunnel, so same-H3 DoH is unavailable and only DoT is left.
	snapshot := compile(t, plainCapability(), []string{""}, nameserver)
	decision := snapshot.decide("example.com.")
	require.True(t, decision.claimed)
	require.False(t, decision.usable, "encrypted-only, and DoT is not implemented by this client")
	require.Equal(t, unusableNoTransport, decision.configuration.resolvers[0].unusable)
}

// TestAdvertisedPortIsHonoured proves a server-advertised port is used, not silently defaulted.
func TestAdvertisedPortIsHonoured(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamKey(3): {0x14, 0xE9}, // 5353
	}
	resolver := compile(t, plainCapability(), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]
	require.Equal(t, uint16(5353), resolver.dnsPort(),
		"port is automatically mandatory, so a client that uses the endpoint cannot ignore it")

	// And a DoH resolver with an advertised port uses it rather than the HTTPS default.
	doh := dohResolver(1, "a.example.", "/dns-query{?dns}", "192.0.2.1")
	doh.ServiceParameters[dnsmessage.SVCParamKey(3)] = []byte{0x1F, 0x90} // 8080
	dohResolverSnapshot := compile(t, h3Capability("a.example."), []string{""}, doh).
		decide("example.com.").configuration.resolvers[0]
	require.Equal(t, uint16(8080), dohResolverSnapshot.dohPort())
}

// ---------------------------------------------------------------------------
// Resolver ordering and fallback
// ---------------------------------------------------------------------------

// TestResolversAreOrderedByPriorityWithinAConfiguration proves priority picks among resolvers
// serving the same names, and ties keep the wire order.
func TestResolversAreOrderedByPriorityWithinAConfiguration(t *testing.T) {
	t.Parallel()

	snapshot := compile(t, plainCapability(), []string{""},
		plainResolver(20, "192.0.2.20"),
		plainResolver(5, "192.0.2.5"),
		plainResolver(5, "192.0.2.6"),
	)
	ordered := snapshot.decide("example.com.").configuration.resolversByPriority()
	require.Len(t, ordered, 3)
	require.Equal(t, uint16(5), ordered[0].priority)
	require.Equal(t, uint16(5), ordered[1].priority)
	require.Equal(t, "192.0.2.5", ordered[0].addresses[0].String(), "equal priorities keep the wire order")
	require.Equal(t, "192.0.2.6", ordered[1].addresses[0].String())
	require.Equal(t, uint16(20), ordered[2].priority)
}

// TestUnusableResolverIsRetainedForDiagnosis proves a bad resolver does not remove the
// configuration, so the claim and the reason both survive.
func TestUnusableResolverIsRetainedForDiagnosis(t *testing.T) {
	t.Parallel()

	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
	}}
	snapshot := compile(t, resolverCapability{routes: routes}, []string{""},
		plainResolver(1, "8.8.8.8"),   // outside the routes
		plainResolver(2, "10.0.0.53"), // inside
	)
	decision := snapshot.decide("example.com.")
	require.True(t, decision.usable)
	require.Equal(t, unusableRouteUnreachable, decision.configuration.resolvers[0].unusable,
		"the unusable resolver is kept with its reason, not silently dropped")
	require.Equal(t, unusableNone, decision.configuration.resolvers[1].unusable)
}

// ---------------------------------------------------------------------------
// Capability recompilation
// ---------------------------------------------------------------------------

// TestRouteChangeFlipsResolverUsability proves availability is recomputed when the routes change,
// because usability is a joint property of the advertisement and the client.
func TestRouteChangeFlipsResolverUsability(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "10.0.0.53")
	wide := compile(t, resolverCapability{routes: allRoutes()}, []string{""}, nameserver)
	require.True(t, wide.decide("example.com.").usable)

	narrow := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("172.16.0.0"), End: netip.MustParseAddr("172.16.0.255"), Protocol: protocolAll,
	}}}, []string{""}, nameserver)
	require.False(t, narrow.decide("example.com.").usable,
		"a route change that makes the resolver unreachable must change the decision")
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// TestIdentityIsStableAndEffective proves the cache key describes behaviour, not arrival order.
func TestIdentityIsStableAndEffective(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	first := compile(t, plainCapability(), []string{"corp.example."}, nameserver)
	second := compile(t, plainCapability(), []string{"corp.example."}, nameserver)
	require.Equal(t, first.identity, second.identity,
		"an identical assignment must produce an identical identity, so a repeated capsule does not invalidate the DNS cache")

	differentClaim := compile(t, plainCapability(), []string{"other.example."}, nameserver)
	require.NotEqual(t, first.identity, differentClaim.identity,
		"changing which names are claimed changes answers")

	differentResolver := compile(t, plainCapability(), []string{"corp.example."}, plainResolver(1, "192.0.2.2"))
	require.NotEqual(t, first.identity, differentResolver.identity)
}

// TestIdentityChangesWhenUsabilityChanges proves a route change that disables a resolver is
// treated as a behavioural change.
func TestIdentityChangesWhenUsabilityChanges(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "10.0.0.53")
	usable := compile(t, resolverCapability{routes: allRoutes()}, []string{""}, nameserver)
	unusable := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("172.16.0.0"), End: netip.MustParseAddr("172.16.0.255"), Protocol: protocolAll,
	}}}, []string{""}, nameserver)

	require.NotEqual(t, usable.identity, unusable.identity,
		"a resolver becoming unreachable changes where queries go, so cached answers must not be reused")
}

// ---------------------------------------------------------------------------
// Route protocol awareness
// ---------------------------------------------------------------------------

// TestRouteProtocolMatters proves a route advertised for an unrelated protocol does not make a
// DNS query reachable.
//
// draft-06 §3.2 defines unencrypted DNS as UDP port 53 and TCP port 53, so a TCP-only route
// cannot carry the UDP query the transport starts with, and the TCP retry needs its own coverage.
func TestRouteProtocolMatters(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "10.0.0.53")

	tcpOnly := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolTCP,
	}}}, []string{""}, nameserver)
	require.False(t, tcpOnly.decide("example.com.").usable,
		"a TCP-only route must not make the UDP transport look reachable")

	udpOnly := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolUDP,
	}}}, []string{""}, nameserver)
	decision := udpOnly.decide("example.com.")
	require.True(t, decision.usable)
	resolver := decision.configuration.resolvers[0]
	require.Len(t, resolver.usableAddresses, 1)
	require.Empty(t, resolver.tcpAddresses,
		"the TCP retry is correctly reported as unavailable rather than silently leaving the tunnel")
}

// ---------------------------------------------------------------------------
// Multi-address
// ---------------------------------------------------------------------------

// TestAllUsableAddressesAreKept proves every advertised address is available to the executor.
//
// Using only the first would treat a resolver whose first address is stale as entirely unusable
// and never contact the rest.
func TestAllUsableAddressesAreKept(t *testing.T) {
	t.Parallel()

	resolver := compile(t, plainCapability(), []string{""},
		plainResolver(1, "192.0.2.1", "192.0.2.2", "2001:db8::1")).
		decide("example.com.").configuration.resolvers[0]
	require.Len(t, resolver.usableAddresses, 3)
	require.Len(t, resolver.tcpAddresses, 3)
}

// ---------------------------------------------------------------------------
// Concurrency: one lookup, one snapshot
// ---------------------------------------------------------------------------

// TestReplacementDoesNotAffectACapturedSnapshot is the snapshot-consistency test.
//
// A single DNS lookup issues an A and an AAAA query CONCURRENTLY. If the transport read the
// assignment again per query, a capsule arriving mid-lookup could send the A query through one
// assignment and the AAAA query through the next -- mixing families from two configurations.
//
// The fix is that a lookup captures the snapshot once. This test proves the captured value keeps
// describing the assignment it came from even after the published one is replaced.
func TestReplacementDoesNotAffectACapturedSnapshot(t *testing.T) {
	t.Parallel()

	var published atomic.Pointer[dnsAssignmentSnapshot]
	published.Store(compile(t, plainCapability(), []string{"corp.example."}, plainResolver(1, "192.0.2.1")))

	captured := published.Load()
	require.Equal(t, "192.0.2.1",
		captured.decide("a.corp.example.").configuration.resolvers[0].addresses[0].String())

	// A new assignment arrives, claiming the same name with a different resolver.
	published.Store(compile(t, plainCapability(), []string{"corp.example."}, plainResolver(1, "192.0.2.99")))

	require.Equal(t, "192.0.2.1",
		captured.decide("a.corp.example.").configuration.resolvers[0].addresses[0].String(),
		"the captured snapshot must keep describing the assignment it came from")
	require.Equal(t, "192.0.2.99",
		published.Load().decide("a.corp.example.").configuration.resolvers[0].addresses[0].String(),
		"and the next lookup must see the new one")
}

// TestConcurrentReplacementIsRaceFree exercises capture and replacement together.
func TestConcurrentReplacementIsRaceFree(t *testing.T) {
	t.Parallel()

	var published atomic.Pointer[dnsAssignmentSnapshot]
	published.Store(compile(t, plainCapability(), []string{""}, plainResolver(1, "192.0.2.1")))

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := range 2000 {
			published.Store(compile(t, plainCapability(), []string{""},
				plainResolver(1, "192.0.2."+itoa(index%250+1))))
		}
	}()
	waitGroup.Add(4)
	for range 4 {
		go func() {
			defer waitGroup.Done()
			for range 2000 {
				snapshot := published.Load()
				decision := snapshot.decide("example.com.")
				// Whatever was captured must be internally coherent: the claim and the resolver
				// come from the same snapshot.
				if decision.claimed {
					require.True(t, decision.usable)
					require.NotEmpty(t, decision.configuration.resolvers)
					require.NotEmpty(t, decision.configuration.resolvers[0].addresses)
				}
			}
		}()
	}
	waitGroup.Wait()
}

// TestWithdrawalClearsClaims proves an empty DNS_ASSIGN makes every name unclaimed again.
func TestWithdrawalClearsClaims(t *testing.T) {
	t.Parallel()

	var published atomic.Pointer[dnsAssignmentSnapshot]
	published.Store(compile(t, plainCapability(), []string{""}, plainResolver(1, "192.0.2.1")))
	require.True(t, published.Load().decide("example.com.").claimed)

	// A withdrawal stores nil, and an in-flight lookup keeps whatever it captured.
	captured := published.Load()
	published.Store(nil)

	require.True(t, published.Load() == nil)
	require.True(t, captured.decide("example.com.").claimed,
		"the captured snapshot still describes the assignment that was in force")
	require.False(t, (*dnsAssignmentSnapshot)(nil).decide("example.com.").claimed,
		"and a nil snapshot claims nothing")
}

// ---------------------------------------------------------------------------
// Execution plane
// ---------------------------------------------------------------------------

// recordingDialer counts dials and answers with a canned response, so a test can prove where a
// query went without a network.
type recordingDialer struct {
	access  sync.Mutex
	dials   int
	network string
	last    M.Socksaddr
	answer  []byte
	fail    bool
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.dials++
	d.network = network
	d.last = destination
	answer, fail := d.answer, d.fail
	d.access.Unlock()
	if fail {
		return nil, E.New("test: dial failed")
	}
	return dialTestUDPEcho(answer, network)
}

func (d *recordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("test: not implemented")
}

func (d *recordingDialer) counts() (int, string, M.Socksaddr) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.dials, d.network, d.last
}

// dialTestUDPEcho starts a loopback UDP socket that answers the first datagram, and returns a
// connected socket pointed at it.
func dialTestUDPEcho(answer []byte, network string) (net.Conn, error) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	// The echo serves until the test ends. Two details matter:
	//
	//   - the native transport keeps a background reader on the socket for the life of the
	//     transport, so a mock that answered once and exited would leave that reader blocked
	//     and hang the test;
	//   - the multiplexer assigns its OWN query ID, so the reply must carry the ID from the
	//     query it received. A canned reply with a fixed ID is silently dropped, which is how
	//     an earlier version of this mock produced mysterious timeouts.
	go func() {
		buffer := make([]byte, 4096)
		for {
			read, clientAddress, readErr := server.ReadFromUDP(buffer)
			if readErr != nil {
				server.Close()
				return
			}
			if len(answer) < 2 || read < 2 {
				continue
			}
			reply := append([]byte(nil), answer...)
			// Echo the query's ID so the multiplexer can match the reply to its request.
			reply[0] = buffer[0]
			reply[1] = buffer[1]
			_, _ = server.WriteToUDP(reply, clientAddress)
		}
	}()
	return net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
}

// testQuery builds a packed A query for a name.
func testQuery(t *testing.T, name string) (*mDNS.Msg, []byte) {
	t.Helper()
	message := new(mDNS.Msg)
	message.SetQuestion(name, mDNS.TypeA)
	packed, err := message.Pack()
	require.NoError(t, err)
	return message, packed
}

// testAnswer builds a packed reply to a query.
func testAnswer(t *testing.T, query *mDNS.Msg, address string) []byte {
	t.Helper()
	reply := new(mDNS.Msg)
	reply.SetReply(query)
	packed, err := reply.Pack()
	require.NoError(t, err)
	_ = address
	return packed
}

// TestConfigurationTransportUsesTheDevice proves plain assigned DNS goes through the tunnel
// device and nowhere else.
func TestConfigurationTransportUsesTheDevice(t *testing.T) {
	t.Parallel()

	query, packed := testQuery(t, "tunnel.example.test.")

	dialer := &recordingDialer{answer: testAnswer(t, query, "192.0.2.10")}
	snapshot := compile(t, plainCapability(), []string{""}, plainResolver(1, "10.0.0.53"))
	configuration := snapshot.decide("tunnel.example.test.").configuration
	require.True(t, configuration.hasUsableResolver())

	transport := newConfigurationDNSTransport(logger.NOP(), dialer, "test", configuration, nil)
	response, err := transport.Exchange(testContext(t), query)
	require.NoError(t, err)
	require.NotNil(t, response)

	dials, network, destination := dialer.counts()
	require.Equal(t, 1, dials, "exactly one dial, through the device")
	require.Equal(t, N.NetworkUDP, network)
	require.Equal(t, "10.0.0.53", destination.Addr.String())
	require.Equal(t, uint16(53), destination.Port)
	_ = packed
}

// TestConfigurationTransportTriesEveryAddress proves a failed address does not end the attempt.
func TestConfigurationTransportTriesEveryAddress(t *testing.T) {
	t.Parallel()

	query, _ := testQuery(t, "multi.example.test.")
	answer := testAnswer(t, query, "192.0.2.10")

	// The first address refuses; the second answers. A dialer that fails for one address and
	// succeeds for another is what a partially-reachable resolver looks like.
	dialer := &firstAddressFailsDialer{failing: "10.0.0.1", answer: answer}
	snapshot := compile(t, plainCapability(), []string{""},
		plainResolver(1, "10.0.0.1", "10.0.0.2"))
	configuration := snapshot.decide("multi.example.test.").configuration
	require.Len(t, configuration.resolvers[0].usableAddresses, 2)

	transport := newConfigurationDNSTransport(logger.NOP(), dialer, "test", configuration, nil)
	_, err := transport.Exchange(testContext(t), query)
	require.NoError(t, err, "the second address must be tried after the first fails")
	require.Equal(t, 2, dialer.attempts())
}

// firstAddressFailsDialer fails for one address and answers for any other.
type firstAddressFailsDialer struct {
	access    sync.Mutex
	failing   string
	answer    []byte
	attempts_ int
}

func (d *firstAddressFailsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.attempts_++
	failing, answer := d.failing, d.answer
	d.access.Unlock()
	if destination.Addr.String() == failing {
		return nil, E.New("test: address unreachable")
	}
	return dialTestUDPEcho(answer, network)
}

func (d *firstAddressFailsDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("test: not implemented")
}

func (d *firstAddressFailsDialer) attempts() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.attempts_
}

// TestConfigurationTransportFailsClosedWhenNoResolverIsUsable proves a claimed configuration
// with nothing usable returns an error rather than falling back.
func TestConfigurationTransportFailsClosedWhenNoResolverIsUsable(t *testing.T) {
	t.Parallel()

	query, _ := testQuery(t, "claimed.example.test.")
	routes := []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
	}}
	snapshot := compile(t, resolverCapability{routes: routes}, []string{""}, plainResolver(1, "8.8.8.8"))
	decision := snapshot.decide("claimed.example.test.")
	require.True(t, decision.claimed)
	require.False(t, decision.usable)

	dialer := &recordingDialer{answer: []byte("unused")}
	transport := newConfigurationDNSTransport(logger.NOP(), dialer, "test", decision.configuration, nil)
	_, err := transport.Exchange(testContext(t), query)
	require.Error(t, err, "a claimed name with no usable resolver must fail")

	dials, _, _ := dialer.counts()
	require.Equal(t, 0, dials, "and must not dial anything at all")
}

// TestConfigurationTransportUsesResolverPriority proves the highest-priority usable resolver is
// tried first.
func TestConfigurationTransportUsesResolverPriority(t *testing.T) {
	t.Parallel()

	query, _ := testQuery(t, "priority.example.test.")
	answer := testAnswer(t, query, "192.0.2.10")

	dialer := &recordingDialer{answer: answer}
	snapshot := compile(t, plainCapability(), []string{""},
		plainResolver(20, "10.0.0.20"),
		plainResolver(5, "10.0.0.5"),
	)
	transport := newConfigurationDNSTransport(logger.NOP(), dialer, "test",
		snapshot.decide("priority.example.test.").configuration, nil)
	_, err := transport.Exchange(testContext(t), query)
	require.NoError(t, err)

	_, _, destination := dialer.counts()
	require.Equal(t, "10.0.0.5", destination.Addr.String(),
		"the lowest priority number must be tried first")
}

// TestConfigurationTransportEnvironmentIsDeterministic proves the cache key describes behaviour
// rather than arrival order.
func TestConfigurationTransportEnvironmentIsDeterministic(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	first := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test",
		compile(t, plainCapability(), []string{"corp.example."}, nameserver).configurations[0], nil)
	second := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test",
		compile(t, plainCapability(), []string{"corp.example."}, nameserver).configurations[0], nil)

	require.Equal(t, first.Environment(), second.Environment(),
		"an identical assignment must produce an identical environment")

	changed := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test",
		compile(t, plainCapability(), []string{"corp.example."}, plainResolver(1, "192.0.2.2")).configurations[0], nil)
	require.NotEqual(t, first.Environment(), changed.Environment())
}

// testContext bounds a query so a regression fails in seconds rather than at the package
// timeout, and so a background reader cannot hang the run.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// errTestDialFailed stands in for an unreachable dialer.
var errTestDialFailed = E.New("test: dial failed")
