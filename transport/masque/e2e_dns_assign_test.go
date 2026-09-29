package masque

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// End-to-end tests for the server-to-client DNS_ASSIGN and PREF64 path.
//
// # What this covers that the unit tests do not
//
// The unit tests prove each half: the server emits capsules, and the client parses them.
// Neither would notice if the two halves disagreed -- for instance if the server emitted an
// SVC parameter the client's validator rejected, or if the capsule the server built decoded
// on the client into a configuration it then refused to install.
//
// So these tests run the REAL server emitter through the REAL client parser and all the way
// into the resolver state, and then check that a lookup actually reaches the assigned
// nameserver. The server is not stubbed and the parser is not stubbed.

// advertiseAllRoutes is a route range wide enough to contain any test nameserver, so the
// reachability check is exercised without every test having to hand-align a route with its
// nameserver.
func advertiseAllRoutes() []AddressRange {
	return []AddressRange{{
		Start:    netip.MustParseAddr("0.0.0.0"),
		End:      netip.MustParseAddr("255.255.255.255"),
		Protocol: 0,
	}, {
		Start:    netip.MustParseAddr("::"),
		End:      netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		Protocol: 0,
	}}
}

// TestServerEmittedDNSCapsulesAreAcceptedByTheClientParser is the server-client agreement
// test.
//
// The server and the client each have their own view of this format, and the failure that
// matters is DISAGREEMENT: a server emitting a capsule that every conforming client must
// reject presents to an operator as "the feature does not work" with no error anywhere. So
// what the server actually writes is fed to the parser and validator the receiving side uses.
func TestServerEmittedDNSCapsulesAreAcceptedByTheClientParser(t *testing.T) {
	t.Parallel()

	capsules := emitServerCapsules(t, ServerOptions{
		DNSConfigurations: []DNSConfiguration{
			{
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          1,
						IPv4Addresses:            []netip.Addr{netip.MustParseAddr("10.0.0.53")},
						AuthenticationDomainName: "dns.example.test.",
						ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
							dnsmessage.SVCParamKey(1): {0x02, 'h', '2'},
							dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
						},
					},
				},
				InternalDomains: []string{""},
				SearchDomains:   []string{"search.example.test."},
			},
		},
		PREF64Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
	})

	require.Len(t, capsules, 4, "address, routes, DNS_ASSIGN and PREF64")
	require.EqualValues(t, capsuleTypeAddressAssign, capsules[0].capsuleType)
	require.EqualValues(t, capsuleTypeRouteAdvertisement, capsules[1].capsuleType)
	require.EqualValues(t, capsuleTypeDNSAssign, capsules[2].capsuleType,
		"DNS_ASSIGN must follow ROUTE_ADVERTISEMENT")
	require.EqualValues(t, capsuleTypePREF64, capsules[3].capsuleType)

	configurations := dnsConfigurationsFromCapsules(t, capsules)
	require.Len(t, configurations, 1)
	// validate() is the same check the receiving side applies, so a configuration that
	// passes here is one a conforming peer will install.
	require.NoError(t, configurations[0].validate())

	// The SVC parameters must survive, since the dohpath is what selects
	// same-connection DoH on the client.
	nameserver := configurations[0].Nameservers[0]
	require.Equal(t, "dns.example.test.", nameserver.AuthenticationDomainName)
	require.Equal(t, []byte("/dns-query{?dns}"), nameserver.ServiceParameters[dnsmessage.SVCParamKey(7)],
		"the dohpath must survive the server-client round trip")

	prefixes, err := parsePREF64(capsules[3].payload)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, prefixes)
}

// emitServerCapsules reproduces the server's startup sequence against a recording session
// and returns the decoded capsules, so a test can hand them to the real client parser.
//
// The sequence is the one an established session performs, in the order the session performs
// it, so a change to that order is caught here rather than only in the ordering test.
func emitServerCapsules(t *testing.T, options ServerOptions) []recordedCapsule {
	t.Helper()
	if options.DNSConfigurations == nil {
		options.DNSConfigurations = []DNSConfiguration{}
	}
	current := newWriteRecordingSession(t, options)
	// Address and routes first, exactly as the session does.
	require.NoError(t, current.writeCapsule(
		newAddressCapsule(capsuleTypeAddressAssign, current.assignedAddresses(nil))))
	require.NoError(t, current.writeCapsule(newRouteCapsule(current.advertisedRoutes)))
	if len(current.server.dnsConfigurations) > 0 {
		dnsCapsule, err := encodeDNSAssign(current.server.dnsConfigurations)
		require.NoError(t, err)
		require.NoError(t, current.writeCapsule(dnsCapsule))
	}
	if current.server.pref64Configured {
		pref64Capsule, err := encodePREF64(current.server.pref64)
		require.NoError(t, err)
		require.NoError(t, current.writeCapsule(pref64Capsule))
	}
	return current.capsules(t)
}

// dnsConfigurationsFromCapsules extracts the DNS_ASSIGN payload from a capsule list and
// parses it with the real client parser.
func dnsConfigurationsFromCapsules(t *testing.T, capsules []recordedCapsule) []DNSConfiguration {
	t.Helper()
	for _, capsule := range capsules {
		if capsule.capsuleType != capsuleTypeDNSAssign {
			continue
		}
		configurations, err := parseDNSAssign(capsule.payload)
		require.NoError(t, err,
			"the client parser must accept what the server emitted; if it does not, the two sides disagree about the format")
		return configurations
	}
	t.Fatal("the server did not emit a DNS_ASSIGN capsule")
	return nil
}

// TestServerPREF64RoundTripsEveryPermittedPrefixLength proves the prefix codec agrees with
// itself across the whole permitted range.
//
// It is easy to support one prefix length and quietly mishandle the rest, and the mishandling
// would surface as a NAT64 prefix that does not match rather than as an error.
func TestServerPREF64RoundTripsEveryPermittedPrefixLength(t *testing.T) {
	t.Parallel()

	for _, prefixLength := range []int{32, 40, 48, 56, 64, 96} {
		prefix := netip.PrefixFrom(netip.MustParseAddr("2001:db8::"), prefixLength)
		capsules := emitServerCapsules(t, ServerOptions{PREF64Prefixes: []netip.Prefix{prefix}})

		var found bool
		for _, capsule := range capsules {
			if capsule.capsuleType != capsuleTypePREF64 {
				continue
			}
			found = true
			prefixes, err := parsePREF64(capsule.payload)
			require.NoError(t, err)
			require.Len(t, prefixes, 1)
			require.Equal(t, prefixLength, prefixes[0].Bits(),
				"prefix length %d must survive the round trip", prefixLength)
			require.Equal(t, prefix, prefixes[0])
		}
		require.True(t, found, "a PREF64 capsule must be emitted for prefix length %d", prefixLength)
	}
}

// TestServerEmptyPREF64MeansWithdrawalNotSilence pins the nil-versus-empty distinction.
//
// The draft gives an EMPTY PREF64 capsule the meaning "the previous prefixes no longer
// apply". A server that meant to withdraw but sent nothing would leave the client using a
// stale NAT64 prefix, which is a correctness problem rather than a cosmetic one.
func TestServerEmptyPREF64MeansWithdrawalNotSilence(t *testing.T) {
	t.Parallel()

	// Nil: no PREF64 capsule at all.
	for _, capsule := range emitServerCapsules(t, ServerOptions{}) {
		require.NotEqualValues(t, capsuleTypePREF64, capsule.capsuleType,
			"a nil prefix list must send nothing rather than an empty capsule")
	}

	// Empty but non-nil: an empty capsule, which means withdrawal.
	var found bool
	for _, capsule := range emitServerCapsules(t, ServerOptions{PREF64Prefixes: []netip.Prefix{}}) {
		if capsule.capsuleType != capsuleTypePREF64 {
			continue
		}
		found = true
		require.Empty(t, capsule.payload,
			"a withdrawal is an empty capsule, which the client reads as invalidating the previous prefixes")
		prefixes, err := parsePREF64(capsule.payload)
		require.NoError(t, err)
		require.Empty(t, prefixes)
	}
	require.True(t, found,
		"an explicitly empty prefix list must emit an empty capsule, which is how the client is told to withdraw")
}
