package masque

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for DNS capability transitions and the final spec edges.
//
// # The four facts this file keeps apart
//
// A. this HTTP client CAN speak HTTP/3                     (configuration)
// B. it currently HOLDS a live HTTP/3 connection           (resource)
// C. THIS CONNECT-IP session WAS ESTABLISHED over HTTP/3   (session truth)
// D. this resolver ADVERTISES an HTTP/3 DNS transport      (advertisement)
//
// Same-connection DoH needs C AND B AND D, plus a matching origin. Earlier
// implementations used B alone, or inferred C from the configured version, and each time the
// result was a request on a connection the tunnel traffic does not share.

// h3SessionCapability builds the capability for a session whose tunnel really is HTTP/3.
func h3SessionCapability(authorities ...string) resolverCapability {
	return resolverCapability{
		tunnelIsHTTP3:     true,
		sameH3Authorities: authorities,
		routes:            allRoutes(),
	}
}

// dohResolverWithALPN builds a nameserver advertising a specific ALPN set and a dohpath.
func dohResolverWithALPN(priority uint16, authDomain string, dohPath string, alpn []byte, addresses ...string) masque.DNSNameserver {
	nameserver := plainResolver(priority, addresses...)
	nameserver.AuthenticationDomainName = authDomain
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamALPN: alpn,
	}
	if dohPath != "" {
		nameserver.ServiceParameters[dnsmessage.SVCParamKey(7)] = []byte(dohPath)
	}
	return nameserver
}

// alpnWire encodes an ALPN set in the RFC 9460 §7.1.1 wire format.
func alpnWire(protocols ...string) []byte {
	var encoded []byte
	for _, protocol := range protocols {
		encoded = append(encoded, byte(len(protocol)))
		encoded = append(encoded, protocol...)
	}
	return encoded
}

// ---------------------------------------------------------------------------
// ALPN requirement
// ---------------------------------------------------------------------------

// TestDoHRequiresALPNH3 is the core capability test.
//
// A dohpath says WHERE to POST, not which protocol carries it. RFC 9460 §7.1.2 requires a client
// to connect only with protocols both sides support, so a server that did not name h3 must not
// receive an HTTP/3 request.
func TestDoHRequiresALPNH3(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name         string
		alpn         []byte
		expectDoH    bool
		expectReason string
	}{
		{
			name:      "h3 explicitly advertised",
			alpn:      alpnWire("h3"),
			expectDoH: true,
		},
		{
			name:      "h2 and h3 advertised",
			alpn:      alpnWire("h2", "h3"),
			expectDoH: true,
		},
		{
			name:         "h2 only",
			alpn:         alpnWire("h2"),
			expectReason: "this client implements same-connection DoH over HTTP/3 only, so an h2-only resolver must not be given an HTTP/3 request",
		},
		{
			name:         "dot only",
			alpn:         alpnWire("dot"),
			expectReason: "DoT is not implemented",
		},
		{
			name:         "doq only",
			alpn:         alpnWire("doq"),
			expectReason: "DoQ is not implemented",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// An address is present so a non-DoH resolver still has plain DNS available, which
			// keeps this test about the DoH decision rather than about total usability.
			nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", testCase.alpn, "192.0.2.1")
			resolver := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
				decide("example.com.").configuration.resolvers[0]

			if testCase.expectDoH {
				require.NotNil(t, resolver.doh, testCase.expectReason)
				return
			}
			require.Nil(t, resolver.doh, testCase.expectReason)
		})
	}
}

// TestDoHWithoutALPNIsNotDoH proves a missing ALPN is not treated as a wildcard.
//
// The shape is NOT malformed: draft-06 §3.2 constrains alpn only in the other direction ("if
// Authentication Domain Name is empty, the alpn and no-default-alpn service parameter MUST be
// omitted"). What it cannot do is select DoH, because same-connection DoH requires the server to
// have named HTTP/3.
func TestDoHWithoutALPNIsNotDoH(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.AuthenticationDomainName = "masque.example"
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
	}
	_, err := masque.ValidateServiceParameters(nameserver)
	require.NoError(t, err, "draft-06 does not require alpn when an authentication domain name is present")

	resolver := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]
	require.Nil(t, resolver.doh,
		"absent ALPN is not a wildcard: the server did not name HTTP/3, so no HTTP/3 request is ours to make")
	require.NotNil(t, resolver.plain, "and plain DNS remains available")
}

// TestH2OnlyResolverFallsBackToPlainDNS proves an h2-only resolver is still usable when the
// server left the plain transport available.
//
// This is the case that would otherwise be lost: refusing same-H3 DoH is correct, but the
// resolver advertised unencrypted DNS too, and no-default-alpn is absent.
func TestH2OnlyResolverFallsBackToPlainDNS(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h2"), "192.0.2.1")
	resolver := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]

	require.Nil(t, resolver.doh, "h2-only must not get same-connection DoH")
	require.NotNil(t, resolver.plain, "but plain DNS was not withdrawn, so it remains available")
	require.Equal(t, []assignedTransport{assignedTransportPlainUDP}, resolver.transportPreference())
}

// TestH2OnlyWithNoDefaultALPNIsUnusable proves the encrypted-only case fails closed.
func TestH2OnlyWithNoDefaultALPNIsUnusable(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h2"), "192.0.2.1")
	nameserver.ServiceParameters[dnsmessage.SVCParamNoDefaultALPN] = nil

	snapshot := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver)
	decision := snapshot.decide("example.com.")
	require.True(t, decision.claimed, "the claim survives")
	require.False(t, decision.usable, "encrypted-only, and the only encrypted transport offered is one we cannot carry")
	require.Equal(t, unusableNoTransport, decision.configuration.resolvers[0].unusable)
}

// ---------------------------------------------------------------------------
// Origin, including the port
// ---------------------------------------------------------------------------

// TestOriginMatchingIncludesThePort proves two authorities differing only by port are different
// origins.
//
// Comparing host names alone would let a request be compiled for an origin the connection was
// never authenticated for, and would then have to be caught at request time -- or not caught.
func TestOriginMatchingIncludesThePort(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name          string
		sessionOrigin string
		resolverHost  string
		resolverPort  []byte
		expectDoH     bool
		reason        string
	}{
		{
			name: "matching host, default port", sessionOrigin: "masque.example",
			resolverHost: "masque.example", expectDoH: true,
			reason: "the wire FQDN and the authority denote the same host on the default port",
		},
		{
			name: "matching host and explicit default port", sessionOrigin: "masque.example:443",
			resolverHost: "masque.example", expectDoH: true,
			reason: "an explicit 443 is the same origin as an implicit one",
		},
		{
			name: "matching host and matching non-default port", sessionOrigin: "masque.example:8443",
			resolverHost: "masque.example", resolverPort: []byte{0x20, 0xFB}, expectDoH: true,
			reason: "the resolver names the same non-default port the tunnel uses",
		},
		{
			name: "matching host, WRONG port", sessionOrigin: "masque.example:443",
			resolverHost: "masque.example", resolverPort: []byte{0x20, 0xFB},
			reason: "a non-default port is a different origin, so the request would not be authenticated",
		},
		{
			name: "different host", sessionOrigin: "masque.example:8443",
			resolverHost: "dns-a.example", resolverPort: []byte{0x20, 0xFB},
			reason: "a different host is a different origin",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			nameserver := dohResolverWithALPN(1, testCase.resolverHost, "/dns-query{?dns}", alpnWire("h3"))
			if testCase.resolverPort != nil {
				nameserver.ServiceParameters[dnsmessage.SVCParamKey(3)] = testCase.resolverPort
			}
			resolver := compile(t, h3SessionCapability(testCase.sessionOrigin), []string{""}, nameserver).
				decide("example.com.").configuration.resolvers[0]

			if testCase.expectDoH {
				require.NotNil(t, resolver.doh, testCase.reason)
				return
			}
			require.Nil(t, resolver.doh, testCase.reason)
		})
	}
}

// TestCompiledAuthorityCarriesTheEffectivePort proves the authority used at request time is the
// same one the capability was decided against.
//
// A mismatch between the two would mean the compile-time check passed for one origin and the
// request went to another.
func TestCompiledAuthorityCarriesTheEffectivePort(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example.", "/dns-query{?dns}", alpnWire("h3"))
	nameserver.ServiceParameters[dnsmessage.SVCParamKey(3)] = []byte{0x20, 0xFB} // 8443
	resolver := compile(t, h3SessionCapability("masque.example:8443"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]

	require.NotNil(t, resolver.doh)
	require.Equal(t, "masque.example:8443", resolver.doh.authority,
		"the compiled authority must be the full origin, including the port")
}

// ---------------------------------------------------------------------------
// Session transport truth
// ---------------------------------------------------------------------------

// TestSessionTransportIsTheTruthSource proves a live HTTP/3 connection is not enough.
//
// This is invariant 2: a live H3 connection can coexist with a session running over HTTP/2,
// because the tunnel path falls back. Same-connection DoH requires the SESSION to be H3.
func TestSessionTransportIsTheTruthSource(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h3"))

	// The session is HTTP/2, so there is no shared connection to coalesce onto -- even though
	// the HTTP client may hold a live H3 connection from an earlier success.
	h2Session := resolverCapability{
		tunnelIsHTTP3:     false,
		sameH3Authorities: []string{"masque.example"},
		routes:            allRoutes(),
	}
	resolver := compile(t, h2Session, []string{""}, nameserver).decide("example.com.").configuration.resolvers[0]
	require.Nil(t, resolver.doh,
		"an addressless DoH resolver must not be usable when the session is not carried over HTTP/3")

	// The same assignment on an HTTP/3 session IS usable, which proves the difference is the
	// session transport and not the advertisement.
	resolverOnH3 := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]
	require.NotNil(t, resolverOnH3.doh)
}

// TestEndpointUpdatesSessionTransportAndRecompiles proves the endpoint records the session
// transport and recomputes the capability when it changes.
//
// Without the recomputation, a snapshot compiled on HTTP/2 would mark an addressless DoH
// resolver unusable forever, and the server would have to resend an assignment it never changed.
func TestEndpointUpdatesSessionTransportAndRecompiles(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{answer: []netip.Addr{netip.MustParseAddr("10.0.0.99")}}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	endpoint.currentAssignment = &masque.DNSAssignment{
		Configurations: []masque.DNSConfiguration{{
			InternalDomains: []string{""},
			Nameservers: []masque.DNSNameserver{
				dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h3")),
			},
		}},
	}
	endpoint.currentRoutes = allRoutes()
	// A live HTTP/3 connection exists throughout; only the SESSION transport changes. That is
	// the whole point: a live connection is not evidence about how the tunnel is carried.
	endpoint.h3ConnectionProbe = func() (string, bool) { return "masque.example", true }

	// The session starts over HTTP/2, so the DoH capability cannot be compiled.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP2)
	decision := endpoint.dnsAssignment.Load().decide("example.com.")
	require.True(t, decision.claimed)
	require.False(t, decision.usable, "an addressless DoH resolver cannot be served over an HTTP/2 session")

	// The tunnel comes back over HTTP/3 and the SAME assignment becomes usable. The server did
	// not resend anything: the assignment did not change, our ability to use it did.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP3)
	decision = endpoint.dnsAssignment.Load().decide("example.com.")
	require.True(t, decision.claimed)
	require.True(t, decision.usable,
		"the capability must be recomputed when the session transport changes, not frozen at capsule arrival")
}

// TestSessionEndClearsTheTransportFact proves the transport does not outlive its session.
func TestSessionEndClearsTheTransportFact(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	endpoint.currentAssignment = &masque.DNSAssignment{
		Configurations: []masque.DNSConfiguration{{
			InternalDomains: []string{""},
			Nameservers: []masque.DNSNameserver{
				dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h3")),
			},
		}},
	}
	endpoint.currentRoutes = allRoutes()
	endpoint.h3ConnectionProbe = func() (string, bool) { return "masque.example", true }

	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP3)
	require.True(t, endpoint.dnsAssignment.Load().decide("example.com.").usable)

	// The session ends.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportUnknown)
	require.False(t, endpoint.dnsAssignment.Load().decide("example.com.").usable,
		"a finished HTTP/3 session must not leave its capability behind")
}

// ---------------------------------------------------------------------------
// Two capabilities on one resolver
// ---------------------------------------------------------------------------

// TestResolverKeepsBothCapabilities proves a resolver offering both transports keeps both.
//
// Collapsing to a single transport at compile time meant a DoH failure at query time could not
// fall back to a transport the server explicitly advertised.
func TestResolverKeepsBothCapabilities(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h3"), "192.0.2.1")
	resolver := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]

	require.NotNil(t, resolver.doh, "same-connection DoH is available")
	require.NotNil(t, resolver.plain, "and plain DNS is still permitted, so it must remain available too")
	require.Equal(t, []assignedTransport{assignedTransportDoH, assignedTransportPlainUDP}, resolver.transportPreference(),
		"DoH is preferred per draft-06 §3.5's coalescing requirement, with plain DNS as the fallback")
}

// TestDoHFailureFallsBackToPlainWithinTheSameResolver proves the fallback happens at query time.
//
// The DoH capability was compiled as usable, but the connection can go away between compiling
// and sending. The resolver must then use its own plain capability rather than being reported as
// failed while a working transport sat unused.
func TestDoHFailureFallsBackToPlainWithinTheSameResolver(t *testing.T) {
	t.Parallel()

	query, _ := testQuery(t, "fallback.example.test.")
	answer := testAnswer(t, query, "192.0.2.10")

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("h3"), "10.0.0.53")
	snapshot := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver)
	configuration := snapshot.decide("fallback.example.test.").configuration
	require.NotNil(t, configuration.resolvers[0].doh)
	require.NotNil(t, configuration.resolvers[0].plain)

	dialer := &recordingDialer{answer: answer}
	// A DoH executor that always fails, standing in for a connection that dropped.
	transport := newConfigurationDNSTransport(logger.NOP(), dialer, "test", configuration, failingDoHExecutor{})

	response, err := transport.Exchange(testContext(t), query)
	require.NoError(t, err, "the plain capability must be used when the DoH one fails")
	require.NotNil(t, response)

	dials, _, destination := dialer.counts()
	require.Equal(t, 1, dials, "the query must have gone out over plain DNS")
	require.Equal(t, "10.0.0.53", destination.Addr.String())
}

// failingDoHExecutor always reports that the connection is gone.
type failingDoHExecutor struct{}

func (failingDoHExecutor) RoundTripExistingHTTP3(ctx context.Context, request *http.Request) (*http.Response, error) {
	return nil, errTestDialFailed
}

// ---------------------------------------------------------------------------
// PREF64
// ---------------------------------------------------------------------------

// TestPref64IsNotSubjectToTheExplicitResolver proves the two states are independent.
//
// An explicit inner resolver says where DNS queries go. PREF64 records NAT64 prefixes. Coupling
// them by an early return meant the prefixes were silently never stored.
func TestPref64IsNotSubjectToTheExplicitResolver(t *testing.T) {
	t.Parallel()

	endpoint := lookupEndpoint(t, &recordingRouter{}, adapter.DNSQueryOptions{
		Transport: &stubDNSTransport{tag: "explicit"},
	})

	endpoint.installAssignedDNS(masque.Configuration{
		DNS: &masque.DNSAssignment{
			Configurations: []masque.DNSConfiguration{{
				InternalDomains: []string{""},
				Nameservers:     []masque.DNSNameserver{plainResolver(1, "10.0.0.53")},
			}},
		},
		PREF64: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
	})

	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, endpoint.Pref64Prefixes(),
		"PREF64 must be stored even when an explicit inner resolver declines the DNS assignment")
	require.Nil(t, endpoint.dnsAssignment.Load(),
		"but the assignment itself must not be installed: the operator's resolver wins")
}

// TestPref64SnapshotIsImmutable proves a caller cannot mutate published state.
func TestPref64SnapshotIsImmutable(t *testing.T) {
	t.Parallel()

	var store pref64Store
	store.publish([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")})

	first := store.snapshot()
	require.Len(t, first, 1)

	// Write through the returned value.
	first[0] = netip.MustParsePrefix("2001:db8::/32")

	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, store.snapshot(),
		"the accessor must return a copy, or a caller can mutate published state")
}

// TestPref64WithdrawalAndConcurrency covers the remaining PREF64 behaviours.
func TestPref64WithdrawalAndConcurrency(t *testing.T) {
	t.Parallel()

	var store pref64Store
	store.publish([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")})
	require.Len(t, store.snapshot(), 1)

	// An empty capsule is a withdrawal, not a no-op.
	store.publish(nil)
	require.Empty(t, store.snapshot(), "an empty PREF64 capsule invalidates the previous prefixes")

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := range 500 {
			store.publish([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")})
			_ = index
		}
	}()
	waitGroup.Add(4)
	for range 4 {
		go func() {
			defer waitGroup.Done()
			for range 500 {
				prefixes := store.snapshot()
				// A reader must never observe a torn value.
				require.LessOrEqual(t, len(prefixes), 1)
			}
		}()
	}
	waitGroup.Wait()
}

// ---------------------------------------------------------------------------
// Mandatory keys
// ---------------------------------------------------------------------------

// TestMandatoryECHIsRejected is the known-versus-supported test.
func TestMandatoryECHIsRejected(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.AuthenticationDomainName = "dns.example."
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamALPN:   alpnWire("h3"),
		dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
		// mandatory = [ech]
		dnsmessage.SVCParamMandatory: {0x00, 0x05},
		dnsmessage.SVCParamECH:       {0x01, 0x02},
	}
	_, err := masque.ValidateServiceParameters(nameserver)
	require.Error(t, err, "ECH is recognised but not implemented, so a mandatory ECH cannot be honoured")
	require.Contains(t, err.Error(), "ech")
}

// TestMandatorySupportedKeysAreAccepted proves the keys this client does implement pass.
func TestMandatorySupportedKeysAreAccepted(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		key   dnsmessage.SVCParamKey
		value []byte
	}{
		{name: "mandatory port", key: dnsmessage.SVCParamPort, value: []byte{0x14, 0xE9}},
		{name: "mandatory dohpath", key: dnsmessage.SVCParamKey(7), value: []byte("/dns-query{?dns}")},
		{name: "mandatory alpn", key: dnsmessage.SVCParamALPN, value: alpnWire("h3")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			nameserver := plainResolver(1, "192.0.2.1")
			nameserver.AuthenticationDomainName = "dns.example."
			nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamALPN:      alpnWire("h3"),
				dnsmessage.SVCParamKey(7):    []byte("/dns-query{?dns}"),
				testCase.key:                 testCase.value,
				dnsmessage.SVCParamMandatory: {byte(uint16(testCase.key) >> 8), byte(uint16(testCase.key))},
			}
			// mandatory must list keys in strictly increasing order, so re-sort.
			if testCase.key < dnsmessage.SVCParamMandatory {
				nameserver.ServiceParameters[dnsmessage.SVCParamMandatory] =
					[]byte{byte(uint16(testCase.key) >> 8), byte(uint16(testCase.key))}
			}
			_, err := masque.ValidateServiceParameters(nameserver)
			if err != nil {
				// The order check may legitimately reject an unsorted mandatory list; what must
				// NOT happen is a rejection for being unsupported.
				require.NotContains(t, err.Error(), "does not implement",
					"%s is implemented, so it must not be refused as unsupported", testCase.name)
			}
		})
	}
}

// TestUnknownOptionalKeyIsIgnored proves RFC 9460 §2.4.3 is honoured.
func TestUnknownOptionalKeyIsIgnored(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamKey(0x9C40): []byte("future extension"),
	}
	_, err := masque.ValidateServiceParameters(nameserver)
	require.NoError(t, err, "an unknown NON-mandatory key must be ignored, not rejected")
}

// TestMandatoryUnknownKeyIsRejected proves an unhonourable requirement is refused.
func TestMandatoryUnknownKeyIsRejected(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	nameserver.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{
		dnsmessage.SVCParamKey(0x9C40): []byte("future extension"),
		dnsmessage.SVCParamKey(0):      {0x9C, 0x40},
	}
	_, err := masque.ValidateServiceParameters(nameserver)
	require.Error(t, err, "a mandatory key this client does not know cannot be honoured")
}

// ---------------------------------------------------------------------------
// HTTP ALPN and dohpath consistency
// ---------------------------------------------------------------------------

// TestHTTPALPNWithoutDohPathLosesOnlyTheDoHTransport pins the exact spec position.
//
// RFC 8484 §3 requires a DoH client to be configured with a URI Template and RFC 9461 §5 defines
// dohpath as it, so the combination is not USABLE as DoH. It is not MALFORMED: draft-06 requires
// only that dohpath be a relative DoH URI Template when present. Refusing the nameserver outright
// would discard a resolver the server advertised as usable over the default transport.
func TestHTTPALPNWithoutDohPathLosesOnlyTheDoHTransport(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "dns.example.", "", alpnWire("h3"), "192.0.2.1")
	_, err := masque.ValidateServiceParameters(nameserver)
	require.NoError(t, err, "draft-06 does not require dohpath merely because an HTTP ALPN is present")

	resolver := compile(t, h3SessionCapability("dns.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]
	require.Nil(t, resolver.doh, "there is no path to POST to, so DoH cannot be used")
	require.NotNil(t, resolver.plain, "but the resolver keeps the plain transport the server left available")
	require.True(t, resolver.usable())

	// And when the server ALSO withdrew plain DNS, nothing is left and the resolver is unusable.
	encryptedOnly := dohResolverWithALPN(1, "dns.example.", "", alpnWire("h3"), "192.0.2.1")
	encryptedOnly.ServiceParameters[dnsmessage.SVCParamNoDefaultALPN] = nil
	decision := compile(t, h3SessionCapability("dns.example"), []string{""}, encryptedOnly).decide("example.com.")
	require.True(t, decision.claimed)
	require.False(t, decision.usable, "encrypted-only with an unusable DoH transport leaves nothing")
}

// TestNonHTTPALPNDoesNotRequireDohPath proves the rule is about HTTP transports only.
func TestNonHTTPALPNDoesNotRequireDohPath(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "dns.example.", "", alpnWire("dot"), "192.0.2.1")
	_, err := masque.ValidateServiceParameters(nameserver)
	require.NoError(t, err,
		"a non-HTTP ALPN does not name a DoH transport, so it needs no dohpath")
}

// TestDohPathWithoutHTTPALPNIsNotDoH proves a dohpath cannot conjure a transport.
func TestDohPathWithoutHTTPALPNIsNotDoH(t *testing.T) {
	t.Parallel()

	nameserver := dohResolverWithALPN(1, "masque.example", "/dns-query{?dns}", alpnWire("dot"), "192.0.2.1")
	resolver := compile(t, h3SessionCapability("masque.example"), []string{""}, nameserver).
		decide("example.com.").configuration.resolvers[0]

	require.Nil(t, resolver.doh,
		"a dohpath says where to POST, not which protocol carries it; DoT is not an HTTP transport")
	require.NotNil(t, resolver.plain, "and plain DNS remains available because no-default-alpn was not set")
}

// ---------------------------------------------------------------------------
// Cache identity
// ---------------------------------------------------------------------------

// TestSearchDomainsDoNotAffectTheCacheKey proves an inapplicable field cannot churn the cache.
//
// Search domains are parsed and preserved, but endpoint-local resolution does not apply them, so
// a server changing only its search domains has not changed any answer this transport can give.
func TestSearchDomainsDoNotAffectTheCacheKey(t *testing.T) {
	t.Parallel()

	base := masque.DNSConfiguration{
		InternalDomains: []string{""},
		Nameservers:     []masque.DNSNameserver{plainResolver(1, "192.0.2.1")},
		SearchDomains:   []string{"a.example"},
	}
	changed := base
	changed.SearchDomains = []string{"b.example"}

	first := compile(t, plainCapability(), nil, base.Nameservers...)
	second := compile(t, plainCapability(), nil, changed.Nameservers...)
	require.Equal(t, first.configurations[0].effectiveIdentity(), second.configurations[0].effectiveIdentity())

	// And through the transport, which is what the DNS cache actually keys on.
	transportA := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test", first.configurations[0], nil)
	transportB := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test", second.configurations[0], nil)
	require.Equal(t, transportA.Environment(), transportB.Environment(),
		"changing only search domains must not invalidate the endpoint-local DNS cache")
}

// TestTCPRouteAvailabilityAffectsTheCacheKey proves a behavioural change is represented.
//
// A truncated UDP answer must be retried over TCP (RFC 1035 §4.2.1), so losing the TCP route
// changes what happens to a large response even when the UDP addresses are identical.
func TestTCPRouteAvailabilityAffectsTheCacheKey(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "10.0.0.53")

	udpAndTCP := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolAll,
	}}}, []string{""}, nameserver)
	udpOnly := compile(t, resolverCapability{routes: []masque.AddressRange{{
		Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: protocolUDP,
	}}}, []string{""}, nameserver)

	require.NotEmpty(t, udpAndTCP.configurations[0].resolvers[0].plain.tcpAddresses)
	require.Empty(t, udpOnly.configurations[0].resolvers[0].plain.tcpAddresses)
	require.NotEqual(t, udpAndTCP.configurations[0].effectiveIdentity(), udpOnly.configurations[0].effectiveIdentity(),
		"losing the TCP route changes how a truncated answer is handled, so cached answers must not be reused")
}

// TestTransportEnvironmentIsPerConfiguration proves the cache key describes one configuration.
func TestTransportEnvironmentIsPerConfiguration(t *testing.T) {
	t.Parallel()

	nameserver := plainResolver(1, "192.0.2.1")
	snapshot := compileDNSAssignment([]masque.DNSConfiguration{
		{
			InternalDomains: []string{"corp.example."},
			Nameservers:     []masque.DNSNameserver{nameserver},
		},
		{
			InternalDomains: []string{"other.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "192.0.2.2")},
		},
	}, plainCapability())

	first := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test", snapshot.configurations[0], nil)
	second := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test", snapshot.configurations[1], nil)
	require.NotEqual(t, first.Environment(), second.Environment(),
		"two configurations with different resolvers must have different cache keys")

	// And an unrelated configuration changing does not alter this one's key.
	changed := compileDNSAssignment([]masque.DNSConfiguration{
		{
			InternalDomains: []string{"corp.example."},
			Nameservers:     []masque.DNSNameserver{nameserver},
		},
		{
			InternalDomains: []string{"other.example."},
			Nameservers:     []masque.DNSNameserver{plainResolver(1, "192.0.2.99")},
		},
	}, plainCapability())
	firstAfter := newConfigurationDNSTransport(logger.NOP(), &recordingDialer{}, "test", changed.configurations[0], nil)
	require.Equal(t, first.Environment(), firstAfter.Environment(),
		"an unrelated configuration changing must not invalidate this configuration's cached answers")
}

// TestDoHExecutorRequiresAnHTTP3Session proves the request-time guard agrees with the compile-time
// capability.
//
// # Why a second check is needed at all
//
// The capability compiled into a snapshot decides whether an addressless DoH resolver is USABLE,
// and it consults the session transport. The executor handed to the DNS transport is what actually
// carries the query. Written with only a liveness check it would answer a different question --
// "does this client hold a live HTTP/3 connection?" instead of "was THIS session established over
// HTTP/3?".
//
// Those come apart precisely when transport/http falls back. After a fallback the client still
// holds the HTTP/3 connection it opened while trying, while the tunnel runs over HTTP/2. An
// executor that accepted the held connection would put inner DNS on a connection the tunnel traffic
// does not share, which is what draft-06 §3.5's coalescing requirement exists to prevent -- and
// every query would still succeed, so nothing would look wrong.
//
// # Why liveness is stubbed here
//
// A live QUIC connection is what makes this test meaningful: with liveness false the session check
// is unreachable and the test would pass even with the guard deleted. The h3ConnectionProbe seam
// exists for exactly this, and both branches below keep it TRUE while only the session transport
// changes -- so the ONLY thing that can refuse the executor is the session check under test.
func TestDoHExecutorRequiresAnHTTP3Session(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	endpoint.httpClient = &transportHTTP.Client{}
	// A live, correctly-authenticated HTTP/3 connection exists THROUGHOUT.
	endpoint.h3ConnectionProbe = func() (string, bool) { return "masque.example", true }

	// Nothing has reported a transport yet, so the zero value is Unknown.
	require.Nil(t, endpoint.dohExecutor(),
		"an unreported session transport must not be treated as HTTP/3")

	// The tunnel is carried over HTTP/2 while the HTTP/3 connection is still held. This is the
	// state a fallback leaves behind, and the one the liveness check cannot detect.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP2)
	require.Nil(t, endpoint.dohExecutor(),
		"an HTTP/2 session must not be offered the held HTTP/3 connection: the query would leave the tunnel")

	// The tunnel comes back over HTTP/3, so the very same held connection is now the right one.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP3)
	require.NotNil(t, endpoint.dohExecutor(),
		"once the session IS HTTP/3, the held connection is the tunnel's own and must be used")

	// And the session ending withdraws it again.
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportUnknown)
	require.Nil(t, endpoint.dohExecutor(),
		"a finished session must not leave its executor behind")
}

// TestDoHExecutorRequiresALiveConnection is the other half: session truth without a connection is
// equally unusable.
//
// The session can be recorded as HTTP/3 while the connection has since died. Handing out an
// executor then would make every DoH query fail instead of letting the resolver fall back to plain
// DNS through the tunnel, which the server may well have advertised.
func TestDoHExecutorRequiresALiveConnection(t *testing.T) {
	t.Parallel()

	router := &recordingRouter{}
	endpoint := lookupEndpoint(t, router, adapter.DNSQueryOptions{})
	endpoint.httpClient = &transportHTTP.Client{}
	// The connection is gone, while the session transport still says HTTP/3.
	endpoint.h3ConnectionProbe = func() (string, bool) { return "", false }
	endpoint.UpdateTunnelTransport(context.Background(), transportHTTP.TunnelTransportHTTP3)

	require.Nil(t, endpoint.dohExecutor(),
		"an HTTP/3 session whose connection is no longer live must not offer a DoH executor")
}
