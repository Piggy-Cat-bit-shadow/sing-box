package masque

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Tests for the assigned-DNS configuration model.
//
// # What this model has to get right
//
// A DNS_ASSIGN may carry several configurations, each owning a set of internal domains. Two
// questions must be answered IN ORDER, and conflating them is the defect this model fixes:
//
//	WHICH configuration answers?  -> longest matching internal domain
//	WHICH resolver inside it?    -> lowest service priority
//
// The previous implementation answered only the second one, globally, across every
// configuration at once. The result was that a resolver for `corp.example.` could answer a
// public name purely because its priority number was lower.

// resolverEndpoint builds one resolver endpoint.
func resolverEndpoint(priority uint16, address string) assignedResolverEndpoint {
	return assignedResolverEndpoint{
		priority:  priority,
		addresses: []netip.Addr{netip.MustParseAddr(address)},
	}
}

// stateFromConfigurations builds a state the way the transport does.
func stateFromConfigurations(configurations []assignedResolverConfiguration) *assignedDNSState {
	return &assignedDNSState{configurations: configurations, hasAssignment: true}
}

// ---------------------------------------------------------------------------
// Domain routing
// ---------------------------------------------------------------------------

// TestConfigurationSelectionUsesLongestMatchingInternalDomain is the domain-routing test.
//
// Three configurations claim overlapping scopes, and each query must reach the most
// specific one. A first-match rule would make the answer depend on the order the server
// serialised its configurations, so the same logical assignment could route one name two
// different ways.
func TestConfigurationSelectionUsesLongestMatchingInternalDomain(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.1")},
		},
		{
			internalDomains: []string{"corp.example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(9, "192.0.2.2")},
		},
		{
			// No internal domains: the default configuration.
			resolvers: []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.3")},
		},
	})

	for _, testCase := range []struct {
		name     string
		expected string
		reason   string
	}{
		{
			name: "a.corp.example.", expected: "192.0.2.2",
			reason: "the most specific internal domain must win even though its resolver has the WORST priority: priority orders resolvers within a configuration, it does not rank configurations",
		},
		{
			name: "corp.example.", expected: "192.0.2.2",
			reason: "the domain itself belongs to the configuration that claims it",
		},
		{
			name: "b.example.", expected: "192.0.2.1",
			reason: "a name under the broader domain, not under the specific one",
		},
		{
			name: "public.test.", expected: "192.0.2.3",
			reason: "nothing claims this name, so the default configuration answers",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			lookup := state.selectForName(testCase.name)
			require.True(t, lookup.found, "a configuration must be selected for %s", testCase.name)
			require.Equal(t, testCase.expected, lookup.endpoint.addresses[0].String(), testCase.reason)
		})
	}
}

// TestConfigurationSelectionRespectsLabelBoundaries proves the suffix match is on a label
// boundary.
//
// A plain strings.HasSuffix would route `notcorp.example` to the resolver for
// `corp.example`, which never claimed it. That is a misroute, not a near miss.
func TestConfigurationSelectionRespectsLabelBoundaries(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"corp.example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.2")},
		},
		{
			resolvers: []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.3")},
		},
	})

	lookup := state.selectForName("notcorp.example.")
	require.True(t, lookup.found)
	require.Equal(t, "192.0.2.3", lookup.endpoint.addresses[0].String(),
		"a name that merely ends with the same characters must not match: the suffix has to start at a label boundary")
}

// TestConfigurationSelectionIsCaseAndDotInsensitive proves the match does not depend on
// presentation.
//
// DNS names are case-insensitive and the root dot is optional in some spellings. A
// case-sensitive comparison would silently send `Corp.Example.` to the default
// configuration.
func TestConfigurationSelectionIsCaseAndDotInsensitive(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"Corp.Example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.2")},
		},
		{
			resolvers: []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.3")},
		},
	})

	for _, name := range []string{"a.corp.example.", "a.CORP.EXAMPLE.", "a.corp.example"} {
		lookup := state.selectForName(name)
		require.True(t, lookup.found)
		require.Equal(t, "192.0.2.2", lookup.endpoint.addresses[0].String(),
			"%s must match regardless of case or the trailing root dot", name)
	}
}

// TestNoMatchingConfigurationFailsClosed proves a name nothing claims is refused when there
// is no default configuration.
//
// Answering from a resolver that never claimed the name is the misrouting this model exists
// to prevent, so the query must fail rather than be sent somewhere plausible.
func TestNoMatchingConfigurationFailsClosed(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"corp.example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.2")},
		},
	})

	lookup := state.selectForName("elsewhere.test.")
	require.False(t, lookup.found,
		"with no default configuration and no matching internal domain, nothing may be selected")
}

// TestConfigurationWithoutResolversDoesNotCaptureNames proves a configuration that cannot
// answer does not swallow names from one that can.
func TestConfigurationWithoutResolversDoesNotCaptureNames(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"corp.example."},
			// No resolvers: unreachable, so dropped during install.
		},
		{
			resolvers: []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.3")},
		},
	})

	lookup := state.selectForName("a.corp.example.")
	require.True(t, lookup.found)
	require.Equal(t, "192.0.2.3", lookup.endpoint.addresses[0].String(),
		"a configuration with no usable resolver must not capture the name; the default must answer instead")
}

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

// TestPriorityOrdersResolversWithinAConfiguration proves priority picks among resolvers
// that serve the SAME domains.
func TestPriorityOrdersResolversWithinAConfiguration(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			resolvers: []assignedResolverEndpoint{
				resolverEndpoint(20, "192.0.2.20"),
				resolverEndpoint(5, "192.0.2.5"),
				resolverEndpoint(10, "192.0.2.10"),
			},
		},
	})

	lookup := state.selectForName("any.test.")
	require.True(t, lookup.found)
	require.Equal(t, "192.0.2.5", lookup.endpoint.addresses[0].String(),
		"the lowest priority number must be preferred")

	ordered := lookup.configuration.resolversByPreference()
	require.Len(t, ordered, 3)
	require.Equal(t, uint16(5), ordered[0].priority)
	require.Equal(t, uint16(10), ordered[1].priority)
	require.Equal(t, uint16(20), ordered[2].priority,
		"the fallback order must be by priority, so a failed resolver falls back within its own configuration")
}

// TestPriorityIsNotComparedAcrossConfigurations is the regression test for the flattening
// defect.
func TestPriorityIsNotComparedAcrossConfigurations(t *testing.T) {
	t.Parallel()

	state := stateFromConfigurations([]assignedResolverConfiguration{
		{
			internalDomains: []string{"corp.example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(1, "192.0.2.1")},
		},
		{
			internalDomains: []string{"public.example."},
			resolvers:       []assignedResolverEndpoint{resolverEndpoint(50, "192.0.2.50")},
		},
	})

	lookup := state.selectForName("host.public.example.")
	require.True(t, lookup.found)
	require.Equal(t, "192.0.2.50", lookup.endpoint.addresses[0].String(),
		"the configuration owning the name must win even though another configuration has a lower priority resolver")
}

// ---------------------------------------------------------------------------
// Metadata isolation
// ---------------------------------------------------------------------------

// TestResolverMetadataIsIsolated is the metadata test.
//
// Two resolvers carry different authentication domains, dohpaths and ports. The state must
// keep them apart, because applying one resolver's origin to another's address would send a
// request to an origin the connection was never authenticated for.
func TestResolverMetadataIsIsolated(t *testing.T) {
	t.Parallel()

	configurations := []masque.DNSConfiguration{
		{
			Nameservers: []masque.DNSNameserver{
				{
					ServicePriority:          1,
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
					AuthenticationDomainName: "a.example.",
					ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
						dnsmessage.SVCParamALPN:   {0x02, 'h', '3'},
						dnsmessage.SVCParamKey(9): []byte("/dns-a{?dns}"),
						dnsmessage.SVCParamKey(3): {0x20, 0xfb}, // 8443
					},
				},
				{
					ServicePriority:          2,
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.2")},
					AuthenticationDomainName: "b.example.",
					ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
						dnsmessage.SVCParamALPN:   {0x02, 'h', '3'},
						dnsmessage.SVCParamKey(9): []byte("/dns-b{?dns}"),
						dnsmessage.SVCParamKey(3): {0x1f, 0x90}, // 8080
					},
				},
			},
		},
	}
	state := buildAssignedDNSState(configurations, nil, 1)
	require.Len(t, state.configurations, 1)
	require.Len(t, state.configurations[0].resolvers, 2)

	first := state.configurations[0].resolvers[0]
	require.Equal(t, "192.0.2.1", first.addresses[0].String())
	require.Equal(t, "a.example.", first.authenticationDomainName)
	require.Equal(t, "/dns-a{?dns}", first.dohPath)
	require.Equal(t, uint16(8443), first.port)
	require.Equal(t, uint16(8443), first.dohPort())

	second := state.configurations[0].resolvers[1]
	require.Equal(t, "192.0.2.2", second.addresses[0].String())
	require.Equal(t, "b.example.", second.authenticationDomainName)
	require.Equal(t, "/dns-b{?dns}", second.dohPath)
	require.Equal(t, uint16(8080), second.port)
	require.Equal(t, uint16(8080), second.dohPort())
}

// TestAssignedDNSStateIsDeepCopied proves the published state does not alias the parsed
// message.
//
// The parsed structures belong to whoever parsed them, and the state is read by other
// goroutines for the lifetime of the assignment. Retaining a caller's slice would let a
// later mutation change live resolver behaviour, and the service-parameter map of byte
// slices is the case most likely to be shared inadvertently.
func TestAssignedDNSStateIsDeepCopied(t *testing.T) {
	t.Parallel()

	configuration := masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamKey(9): []byte("/original"),
				},
			},
		},
		InternalDomains: []string{"corp.example."},
		SearchDomains:   []string{"search.example."},
	}
	state := buildAssignedDNSState([]masque.DNSConfiguration{configuration}, nil, 1)

	// Mutate EVERY input after the state was built.
	configuration.Nameservers[0].IPv4Addresses[0] = netip.MustParseAddr("203.0.113.9")
	configuration.Nameservers[0].ServiceParameters[dnsmessage.SVCParamKey(9)][0] = 'X'
	configuration.InternalDomains[0] = "mutated.example."
	configuration.SearchDomains[0] = "mutated-search.example."

	require.Equal(t, "192.0.2.1", state.configurations[0].resolvers[0].addresses[0].String(),
		"the address must not change when the caller mutates its own slice")
	require.Equal(t, "/original", state.configurations[0].resolvers[0].dohPath,
		"the dohpath must not change when the caller mutates the service parameter bytes")
	require.Equal(t, "corp.example.", state.configurations[0].internalDomains[0])
	require.Equal(t, "search.example.", state.configurations[0].searchDomains[0])
}

// ---------------------------------------------------------------------------
// ALPN and no-default-alpn
// ---------------------------------------------------------------------------

// TestALPNParameterDecoding pins the wire format from RFC 9460 section 7.1.
func TestALPNParameterDecoding(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"h2", "h3"}, decodeALPNList([]byte{0x02, 'h', '2', 0x02, 'h', '3'}))
	require.Equal(t, []string{"h3"}, decodeALPNList([]byte{0x02, 'h', '3'}))
	require.Equal(t, []string{"dot"}, decodeALPNList([]byte{0x03, 'd', 'o', 't'}))
	// The presentation form operators write.
	require.Equal(t, []string{"h2", "h3"}, decodeALPNList([]byte("h2,h3")))
	require.Equal(t, []string{"h3"}, decodeALPNList([]byte(" h3 ")))
	// A length prefix that overruns the value is not length-prefixed form. It falls back to
	// the presentation form, which reads it as the single token it is -- a wrong parse of a
	// wire value is not possible here, because the exact-consumption requirement above
	// rejects anything that is not a complete length-prefixed sequence.
	require.Equal(t, []string{"\x05h"}, decodeALPNList([]byte{0x05, 'h'}),
		"an overrunning length prefix is not length-prefixed form; the fallback yields the raw bytes")
	require.Empty(t, decodeALPNList(nil))
	require.Empty(t, decodeALPNList([]byte("")))
}

// TestTransportSelectionHonoursCapabilities is the transport-capability table.
func TestTransportSelectionHonoursCapabilities(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name          string
		endpoint      assignedResolverEndpoint
		dohAvailable  bool
		expected      assignedTransport
		expectFailure bool
		reason        string
	}{
		{
			name:         "DoH advertised and available",
			endpoint:     assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", dohPath: "/dns-query", alpn: []string{"h3"}},
			dohAvailable: true,
			expected:     assignedTransportDoH,
			reason:       "same-connection DoH is the transport the draft asks for when a proxy is authoritative for the origin",
		},
		{
			name:         "no encrypted transport advertised",
			endpoint:     assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
			dohAvailable: true,
			expected:     assignedTransportPlainUDP,
			reason:       "with nothing advertised, unencrypted DNS is what the resolver offers",
		},
		{
			name:         "ALPN without no-default-alpn still permits unencrypted DNS",
			endpoint:     assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", alpn: []string{"dot"}},
			dohAvailable: false,
			expected:     assignedTransportPlainUDP,
			reason:       "ALPN alone lists capabilities; only no-default-alpn forbids the default",
		},
		{
			name:          "no-default-alpn with DoT only",
			endpoint:      assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", alpn: []string{"dot"}, noDefaultALPN: true},
			dohAvailable:  false,
			expectFailure: true,
			reason:        "DoT is not implemented, and no-default-alpn forbids falling back to cleartext",
		},
		{
			name:          "DoH advertised, unavailable, but no-default-alpn forbids the fallback",
			endpoint:      assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", dohPath: "/dns-query", alpn: []string{"h3"}, noDefaultALPN: true},
			dohAvailable:  false,
			expectFailure: true,
			reason:        "the resolver forbade the default transport, so a cleartext fallback would violate the assignment",
		},
		{
			name:         "DoH advertised, unavailable, but default transport still permitted",
			endpoint:     assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", dohPath: "/dns-query", alpn: []string{"h3"}},
			dohAvailable: false,
			expected:     assignedTransportPlainUDP,
			reason:       "ALPN names transports the resolver also offers; without no-default-alpn, unencrypted DNS is still allowed and must not be refused",
		},
		{
			name:          "DoH offered but no dohpath to query",
			endpoint:      assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, authenticationDomainName: "a.example.", alpn: []string{"h3"}, noDefaultALPN: true},
			dohAvailable:  true,
			expectFailure: true,
			reason:        "DoH was named but no resource path was advertised, so there is nothing to POST to",
		},
		{
			name:          "no-default-alpn but no ALPN listed",
			endpoint:      assignedResolverEndpoint{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, noDefaultALPN: true},
			dohAvailable:  false,
			expectFailure: true,
			reason:        "encrypted-only was demanded but nothing was named as the required protocol",
		},
		{
			name:          "no address to reach",
			endpoint:      assignedResolverEndpoint{authenticationDomainName: "a.example.", alpn: []string{"h3"}},
			dohAvailable:  true,
			expectFailure: true,
			reason:        "there is nothing to connect to",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			transport, err := testCase.endpoint.selectTransport(testCase.dohAvailable)
			if testCase.expectFailure {
				require.Error(t, err, testCase.reason)
				return
			}
			require.NoError(t, err, testCase.reason)
			require.Equal(t, testCase.expected, transport, testCase.reason)
		})
	}
}

// TestNoDefaultALPNRefusesToDowngradeToPlainUDP is the end-to-end form of the rule.
//
// The resolver advertises only h3 with a dohpath and forbids the default transport, and no
// same-connection HTTP/3 client is available. The query must FAIL rather than be sent in
// cleartext, and the tunnel dialer must not be used at all.
func TestNoDefaultALPNRefusesToDowngradeToPlainUDP(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("secure.example.test.", mDNS.TypeAAAA)

	dialer := &recordingDialer{}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.apply(oneConfiguration(masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority:          1,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				AuthenticationDomainName: "a.example.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamALPN:          {0x02, 'h', '3'},
					dnsmessage.SVCParamNoDefaultALPN: {},
					dnsmessage.SVCParamKey(9):        []byte("/dns-query"),
				},
			},
		},
	}), nil)

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err,
		"a resolver that forbids the default transport must not be answered in cleartext")
	require.Equal(t, 0, dialer.dials,
		"no cleartext query may be sent, so the tunnel dialer must not be used at all")
}

// TestNoDefaultALPNFallsBackWithinItsOwnConfiguration proves a usable sibling resolver is
// tried when the preferred one cannot be used.
//
// This is the "try another resolver" behaviour from the spec: an unsupported transport is a
// failure for THAT resolver, not for the query.
func TestNoDefaultALPNFallsBackWithinItsOwnConfiguration(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("fallback.example.test.", mDNS.TypeAAAA)
	answer := new(mDNS.Msg)
	answer.SetReply(query)
	packed, err := answer.Pack()
	require.NoError(t, err)

	dialer := &recordingDialer{answer: packed}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.apply(oneConfiguration(masque.DNSConfiguration{
		Nameservers: []masque.DNSNameserver{
			{
				// Preferred, but DoT-only and no-default-alpn: unusable by this client.
				ServicePriority:          1,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				AuthenticationDomainName: "a.example.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamALPN:          {0x03, 'd', 'o', 't'},
					dnsmessage.SVCParamNoDefaultALPN: {},
				},
			},
			{
				// Lower priority, but plain DNS works.
				ServicePriority: 2,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.2")},
			},
		},
	}), nil)

	response, err := transport.Exchange(context.Background(), query)
	require.NoError(t, err,
		"the query must succeed through the sibling resolver rather than failing outright")
	require.NotNil(t, response)
	require.Equal(t, 1, dialer.dials)
	require.Equal(t, "192.0.2.2", dialer.last.Addr.String(),
		"the usable resolver must be the one dialled, never the unusable preferred one")
}

// TestDoHMetadataComesFromTheSelectedResolver is the cross-resolver contamination test.
//
// Two resolvers in different configurations carry different origins and paths. A query for
// one domain must build its request from THAT resolver's metadata only.
func TestDoHMetadataComesFromTheSelectedResolver(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("host.corp.example.", mDNS.TypeAAAA)

	// A real packed response, so the assertion is about WHERE the request went rather than
	// about a decode failure masking it.
	answer := new(mDNS.Msg)
	answer.SetReply(query)
	packed, err := answer.Pack()
	require.NoError(t, err)

	client := &countingDoHClient{response: packed}
	dialer := &recordingDialer{}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.setDoHClient(client)

	configurationA := masque.DNSConfiguration{
		InternalDomains: []string{"corp.example."},
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority:          1,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				AuthenticationDomainName: "corp-dns.example.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamALPN:   {0x02, 'h', '3'},
					dnsmessage.SVCParamKey(9): []byte("/corp-dns-query"),
					dnsmessage.SVCParamKey(3): {0x20, 0xfb}, // 8443
				},
			},
		},
	}
	configurationB := masque.DNSConfiguration{
		InternalDomains: []string{"public.example."},
		Nameservers: []masque.DNSNameserver{
			{
				ServicePriority:          9,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.2")},
				AuthenticationDomainName: "public-dns.example.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamALPN:   {0x02, 'h', '3'},
					dnsmessage.SVCParamKey(9): []byte("/public-dns-query"),
					dnsmessage.SVCParamKey(3): {0x1f, 0x90}, // 8080
				},
			},
		},
	}
	transport.apply([]masque.DNSConfiguration{configurationA, configurationB}, nil)

	_, err = transport.Exchange(context.Background(), query)
	require.NoError(t, err)

	request := client.firstRequest()
	require.NotNil(t, request)
	require.Equal(t, "corp-dns.example.:8443", request.URL.Host,
		"the authority and port must both come from the selected resolver, never mixed with the other configuration's")
	require.Equal(t, "/corp-dns-query", request.URL.Path,
		"the dohpath must come from the selected resolver")
	require.Equal(t, 0, dialer.dials, "the DoH path must not also dial the tunnel")
}

// TestSearchDomainsAreReportedNotDiscarded proves the parsed search domains reach the
// framework instead of being dropped.
func TestSearchDomainsAreReportedNotDiscarded(t *testing.T) {
	t.Parallel()

	transport := newAssignedDNSTransport(logger.NOP(), &recordingDialer{}, "test")
	transport.apply([]masque.DNSConfiguration{
		{
			Nameservers: []masque.DNSNameserver{
				{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
			},
			SearchDomains: []string{"corp.example.", "example."},
		},
		{
			Nameservers: []masque.DNSNameserver{
				{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}},
			},
			// A duplicate must not be reported twice.
			SearchDomains: []string{"example.", "other.example."},
		},
	}, nil)

	domains := transport.SearchDomains()
	require.Equal(t, []string{"corp.example.", "example.", "other.example."}, domains,
		"every configuration's search domains must be reported, in order and deduplicated")
}

// TestApplyPublishesGenerationInsideTheState proves the generation cannot be observed
// separately from the resolver list it describes.
func TestApplyPublishesGenerationInsideTheState(t *testing.T) {
	t.Parallel()

	transport := newAssignedDNSTransport(logger.NOP(), &recordingDialer{}, "test")
	require.Equal(t, uint64(0), transport.state.Load().generation)

	transport.apply(oneConfiguration(udpAssignment(t, "2001:db8::53")), nil)
	first := transport.state.Load()
	require.Equal(t, uint64(1), first.generation)
	require.NotEmpty(t, first.configurations)

	transport.apply(oneConfiguration(udpAssignment(t, "2001:db8::54")), nil)
	second := transport.state.Load()
	require.Equal(t, uint64(2), second.generation)
	require.NotSame(t, first, second)

	// Each snapshot is internally consistent: its generation describes its own resolvers.
	require.Equal(t, "2001:db8::53", first.configurations[0].resolvers[0].addresses[0].String())
	require.Equal(t, "2001:db8::54", second.configurations[0].resolvers[0].addresses[0].String())
	require.Contains(t, transport.Environment(), "generation=2")
}

// ---------------------------------------------------------------------------
// End-to-end through the tunnel
// ---------------------------------------------------------------------------

// TestExchangeRoutesToTheConfigurationOwningTheName is the end-to-end routing test.
//
// Three configurations claim different scopes and each has its own tunnel destination. The
// address that gets dialled proves which resolver answered, which is the observable that
// matters.
func TestExchangeRoutesToTheConfigurationOwningTheName(t *testing.T) {
	t.Parallel()

	transport := newAssignedDNSTransport(logger.NOP(), &recordingDialer{}, "test")
	transport.apply([]masque.DNSConfiguration{
		{
			InternalDomains: []string{"corp.example."},
			Nameservers: []masque.DNSNameserver{
				{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
			},
		},
		{
			InternalDomains: []string{"example."},
			Nameservers: []masque.DNSNameserver{
				{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}},
			},
		},
		{
			Nameservers: []masque.DNSNameserver{
				{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.3")}},
			},
		},
	}, nil)

	for _, testCase := range []struct {
		name     string
		expected string
	}{
		{name: "a.corp.example.", expected: "192.0.2.1"},
		{name: "b.example.", expected: "192.0.2.2"},
		{name: "public.test.", expected: "192.0.2.3"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			query := new(mDNS.Msg)
			query.SetQuestion(testCase.name, mDNS.TypeAAAA)
			answer := new(mDNS.Msg)
			answer.SetReply(query)
			packed, err := answer.Pack()
			require.NoError(t, err)

			dialer := &recordingDialer{answer: packed}
			transport.dialer = dialer

			_, err = transport.Exchange(context.Background(), query)
			require.NoError(t, err)
			require.Equal(t, 1, dialer.dials)
			require.Equal(t, testCase.expected, dialer.last.Addr.String(),
				"%s must be answered by the configuration that owns it", testCase.name)
			require.Equal(t, M.SocksaddrFrom(netip.MustParseAddr(testCase.expected), 53), dialer.last)
		})
	}
}

// TestExchangeUsesTheTunnelDeviceOnly is the leak assertion for the new dispatch path.
func TestExchangeUsesTheTunnelDeviceOnly(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("tunnel.example.test.", mDNS.TypeAAAA)
	answer := new(mDNS.Msg)
	answer.SetReply(query)
	packed, err := answer.Pack()
	require.NoError(t, err)

	dialer := &recordingDialer{answer: packed}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.apply(oneConfiguration(udpAssignment(t, "192.0.2.53")), nil)

	_, err = transport.Exchange(context.Background(), query)
	require.NoError(t, err)
	require.Equal(t, 1, dialer.dials)
	require.Equal(t, N.NetworkUDP, dialer.network)
	require.Equal(t, M.SocksaddrFrom(netip.MustParseAddr("192.0.2.53"), 53), dialer.last)
}

// TestExchangeReportsNoCoveringConfiguration proves the fail-closed path is reachable.
func TestExchangeReportsNoCoveringConfiguration(t *testing.T) {
	t.Parallel()

	query := new(mDNS.Msg)
	query.SetQuestion("uncovered.test.", mDNS.TypeAAAA)

	dialer := &recordingDialer{}
	transport := newAssignedDNSTransport(logger.NOP(), dialer, "test")
	transport.apply(oneConfiguration(masque.DNSConfiguration{
		InternalDomains: []string{"corp.example."},
		Nameservers: []masque.DNSNameserver{
			{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		},
	}), nil)

	_, err := transport.Exchange(context.Background(), query)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no assigned DNS configuration covers")
	require.Equal(t, 0, dialer.dials, "an uncovered name must not be sent anywhere at all")
}
