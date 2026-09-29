package masque

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// decodeCapsulePayload strips the capsule header from an encoded capsule so a test
// can compare the PAYLOAD against a hand-built vector. Comparing whole capsules would
// hide a payload bug behind a correct header, or the reverse.
func decodeCapsulePayload(t *testing.T, capsule *buf.Buffer) []byte {
	t.Helper()
	raw := capsule.Bytes()
	capsuleType, typeLength, valid := decodeVarintChecked(raw)
	require.True(t, valid, "capsule type must decode")
	require.EqualValues(t, capsuleTypeDNSAssignOrPref64(t, raw), capsuleType)
	length, lengthSize, valid := decodeVarintChecked(raw[typeLength:])
	require.True(t, valid, "capsule length must decode")
	payload := raw[typeLength+lengthSize:]
	require.Len(t, payload, int(length), "declared capsule length must match the payload")
	return payload
}

func capsuleTypeDNSAssignOrPref64(t *testing.T, raw []byte) uint64 {
	t.Helper()
	capsuleType, _, valid := decodeVarintChecked(raw)
	require.True(t, valid)
	require.Contains(t, []uint64{capsuleTypeDNSAssign, capsuleTypePREF64}, capsuleType,
		"unexpected capsule type")
	return capsuleType
}

// ---------------------------------------------------------------------------
// PREF64
// ---------------------------------------------------------------------------

// TestPREF64DraftExampleRoundTrips uses the example from the draft itself (§4.3):
// a single 64:ff9b::/96 prefix encoded as 96 followed by twelve bytes.
//
// The draft prints the bytes explicitly, so this pins the wire format against the
// specification rather than against this implementation's own encoder.
func TestPREF64DraftExampleRoundTrips(t *testing.T) {
	t.Parallel()

	// The draft's byte string, verbatim.
	payload := []byte{
		96,
		0x00, 0x64, 0xff, 0x9b, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	prefixes, err := parsePREF64(payload)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}, prefixes,
		"the draft's own example must decode to 64:ff9b::/96")

	// And the encoder must reproduce those exact bytes.
	encoded, err := encodePREF64(prefixes)
	require.NoError(t, err)
	require.Equal(t, payload, decodeCapsulePayload(t, encoded))
}

// TestPREF64AllStandardPrefixLengths covers every length RFC 6052 §2.2 permits.
//
// The syntactically valid lengths are not the same as "any /0../128", and a parser
// that accepted the others would let a peer install a prefix this implementation
// would then misuse during synthesis.
func TestPREF64AllStandardPrefixLengths(t *testing.T) {
	t.Parallel()

	for _, prefixLength := range []int{32, 40, 48, 56, 64, 96} {
		prefix := netip.MustParsePrefix("64:ff9b::/96").Addr()
		candidate := netip.PrefixFrom(prefix, prefixLength).Masked()

		encoded, err := encodePREF64([]netip.Prefix{candidate})
		require.NoError(t, err, "prefix length %d must encode", prefixLength)

		decoded, err := parsePREF64(decodeCapsulePayload(t, encoded))
		require.NoError(t, err, "prefix length %d must decode", prefixLength)
		require.Equal(t, []netip.Prefix{candidate}, decoded,
			"prefix length %d must round-trip", prefixLength)
		require.Equal(t, prefixLength, decoded[0].Bits())
	}
}

func TestPREF64RejectsInvalidPrefixLengths(t *testing.T) {
	t.Parallel()

	// 0 and 128 are the interesting rejects: both are valid IPv6 prefix lengths and
	// neither is a valid NAT64 prefix length, so a parser that only range-checked
	// against 0..128 would accept them.
	for _, prefixLength := range []byte{0, 1, 8, 24, 31, 33, 63, 65, 95, 97, 127, 128, 255} {
		payload := make([]byte, 13)
		payload[0] = prefixLength
		_, err := parsePREF64(payload)
		require.Error(t, err, "prefix length %d must be rejected", prefixLength)
	}
}

// TestPREF64LengthMustBeMultipleOf13 pins the draft's §4.2 rule that a length which
// is not a multiple of 13 makes the capsule malformed.
func TestPREF64LengthMustBeMultipleOf13(t *testing.T) {
	t.Parallel()

	for _, length := range []int{1, 12, 14, 25, 26, 27} {
		_, err := parsePREF64(make([]byte, length))
		require.Error(t, err, "a %d-byte payload must be rejected", length)
	}
	// The boundaries either side of a single prefix. These must be built with a
	// VALID prefix length: a zero-filled buffer has prefix length 0 and would be
	// rejected for that reason, so it cannot demonstrate the length rule either way.
	valid := func(count int) []byte {
		payload := make([]byte, count*13)
		for i := range count {
			payload[i*13] = 96
		}
		return payload
	}
	_, err := parsePREF64(valid(1))
	require.NoError(t, err, "exactly one prefix is valid")
	_, err = parsePREF64(valid(2))
	require.NoError(t, err, "exactly two prefixes are valid")
}

// TestPREF64EmptyCapsuleClearsState pins §4.2: an empty capsule is legal and means no
// NAT64 prefixes are available, which is how a server revokes a previously sent one.
func TestPREF64EmptyCapsuleClearsState(t *testing.T) {
	t.Parallel()

	prefixes, err := parsePREF64(nil)
	require.NoError(t, err)
	require.Empty(t, prefixes, "an empty PREF64 capsule must decode to no prefixes")

	encoded, err := encodePREF64(nil)
	require.NoError(t, err)
	require.Empty(t, decodeCapsulePayload(t, encoded))
}

func TestPREF64RejectsIPv4MappedPrefix(t *testing.T) {
	t.Parallel()

	// ::ffff:0:0/96 style construction: bytes 10-11 set to 0xff.
	payload := []byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	_, err := parsePREF64(payload)
	require.Error(t, err, "an IPv4-mapped prefix must be rejected")
}

func TestPREF64PrefixCountIsBounded(t *testing.T) {
	t.Parallel()

	overLimit := make([]byte, (maxPREF64Prefixes+1)*13)
	_, err := parsePREF64(overLimit)
	require.Error(t, err, "a capsule above the prefix limit must be rejected")

	atLimit := make([]byte, maxPREF64Prefixes*13)
	for i := range maxPREF64Prefixes {
		atLimit[i*13] = 96
	}
	prefixes, err := parsePREF64(atLimit)
	require.NoError(t, err, "exactly at the limit must be accepted")
	require.Len(t, prefixes, maxPREF64Prefixes)
}

// TestPREF64MasksHostBits documents a deliberate divergence from the reference
// implementation, so a future reader does not "fix" it back.
//
// The reference stores whatever it parsed, host bits included, and its own test
// asserts that `2001:db8:0:0:1::/32` survives parsing with the extra bits set. The
// draft supports that reading: the field is a fixed 96-bit prefix that the consumer
// truncates. This implementation masks instead, which is stricter and makes two
// encodings of the same prefix compare equal -- which is what latest-state
// replacement relies on.
func TestPREF64MasksHostBits(t *testing.T) {
	t.Parallel()

	// 2001:db8:0:0:1::/32 -- host bits set beyond the /32.
	payload := []byte{32, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0}
	prefixes, err := parsePREF64(payload)
	require.NoError(t, err, "host bits must not make the capsule malformed")
	require.Len(t, prefixes, 1)
	require.Equal(t, "2001:db8::/32", prefixes[0].String(),
		"the stored prefix must be masked to its length")
}

// ---------------------------------------------------------------------------
// DNS_ASSIGN
// ---------------------------------------------------------------------------

// TestDNSAssignServiceParameterSortingMatchesReference reproduces the reference's own
// byte-exact vector for the sorted-SvcParam case.
//
// The payload below is built by hand, byte for byte, from the reference's
// TestWriteDNSAssignCapsuleSortsServiceParameters. Reproducing it is the strongest
// available check that this implementation's encoder agrees with the reference on
// field order, varint sizes and the strictly-increasing SVCParam rule.
func TestDNSAssignServiceParameterSortingMatchesReference(t *testing.T) {
	t.Parallel()

	nameserver := DNSNameserver{
		ServicePriority:          1,
		AuthenticationDomainName: "resolver.example.",
		ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
			dnsmessage.SVCParamKey(1): {0x02, 'h', '3'}, // alpn
			dnsmessage.SVCParamKey(2): {},               // no-default-alpn
			dnsmessage.SVCParamKey(3): {0, 53},          // port
		},
	}
	encoded, err := encodeDNSAssign([]DNSConfiguration{{
		Nameservers: []DNSNameserver{nameserver},
	}})
	require.NoError(t, err)

	expected := []byte{1} // Nameserver Count
	expected = append(expected, 0, 1)
	expected = append(expected, 0) // IPv4 Address Count
	expected = append(expected, 0) // IPv6 Address Count
	expected = append(expected, byte(len("resolver.example.")))
	expected = append(expected, "resolver.example."...)
	expected = append(expected, 17) // Service Parameters Length
	expected = append(expected, 0, 1, 0, 3, 0x02, 'h', '3')
	expected = append(expected, 0, 2, 0, 0)
	expected = append(expected, 0, 3, 0, 2, 0, 53)
	expected = append(expected, 0) // Internal Domain Count
	expected = append(expected, 0) // Search Domain Count

	require.Equal(t, expected, decodeCapsulePayload(t, encoded),
		"DNS_ASSIGN must match the reference byte for byte")
}

// TestDNSAssignFullTunnelDraftExample encodes the draft's §3.6.1 example and decodes
// it back, which is the configuration a consumer VPN actually sends.
func TestDNSAssignFullTunnelDraftExample(t *testing.T) {
	t.Parallel()

	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			// The draft's example carries no IP addresses: the nameserver is reached
			// by name.
			AuthenticationDomainName: "masque.example.org.",
			ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamKey(1): []byte{0x02, 'h', '2', 0x02, 'h', '3'}, // alpn=h2,h3
				dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),             // dohpath
			},
		}},
		// An empty internal domain means the DNS root: this nameserver resolves
		// everything.
		InternalDomains: []string{""},
	}

	encoded, err := encodeDNSAssign([]DNSConfiguration{configuration})
	require.NoError(t, err)

	decoded, err := parseDNSAssign(decodeCapsulePayload(t, encoded))
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	require.Len(t, decoded[0].Nameservers, 1)

	nameserver := decoded[0].Nameservers[0]
	require.EqualValues(t, 1, nameserver.ServicePriority)
	require.Equal(t, "masque.example.org.", nameserver.AuthenticationDomainName)
	require.Equal(t, []byte{0x02, 'h', '2', 0x02, 'h', '3'},
		nameserver.ServiceParameters[dnsmessage.SVCParamKey(1)])
	require.Equal(t, []byte("/dns-query{?dns}"),
		nameserver.ServiceParameters[dnsmessage.SVCParamKey(7)])
	require.Equal(t, []string{""}, decoded[0].InternalDomains,
		"an empty internal domain means the DNS root and must survive the round trip")
}

// TestDNSAssignSplitTunnelDraftExample covers the §3.6.2 example, whose shape differs
// from the full-tunnel one in the ways that matter: addresses instead of a name, and
// real internal/search domains.
func TestDNSAssignSplitTunnelDraftExample(t *testing.T) {
	t.Parallel()

	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.33")},
			IPv6Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			// Empty, which is legal only because no ALPN parameter is present.
			AuthenticationDomainName: "",
		}},
		InternalDomains: []string{"internal.corp.example."},
		SearchDomains:   []string{"internal.corp.example.", "corp.example."},
	}

	encoded, err := encodeDNSAssign([]DNSConfiguration{configuration})
	require.NoError(t, err)

	decoded, err := parseDNSAssign(decodeCapsulePayload(t, encoded))
	require.NoError(t, err)
	require.Equal(t, []string{"internal.corp.example."}, decoded[0].InternalDomains)
	require.Equal(t, []string{"internal.corp.example.", "corp.example."}, decoded[0].SearchDomains)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.33")},
		decoded[0].Nameservers[0].IPv4Addresses)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		decoded[0].Nameservers[0].IPv6Addresses)
}

// TestDNSAssignMultipleConfigurations proves the repeated DNS Configuration parsing
// works, which is what the draft permits for separate internal domains.
func TestDNSAssignMultipleConfigurations(t *testing.T) {
	t.Parallel()

	configurations := []DNSConfiguration{
		{
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
			InternalDomains: []string{"internal.example."},
		},
		{
			Nameservers: []DNSNameserver{{
				ServicePriority: 2, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")},
			}},
			InternalDomains: []string{""},
		},
	}
	encoded, err := encodeDNSAssign(configurations)
	require.NoError(t, err)

	decoded, err := parseDNSAssign(decodeCapsulePayload(t, encoded))
	require.NoError(t, err)
	require.Len(t, decoded, 2, "both configurations must survive")
	require.Equal(t, []string{"internal.example."}, decoded[0].InternalDomains)
	require.Equal(t, []string{""}, decoded[1].InternalDomains)
}

// ---------------------------------------------------------------------------
// DNS_ASSIGN validation
// ---------------------------------------------------------------------------

func TestDNSAssignValidationRejects(t *testing.T) {
	t.Parallel()

	cases := map[string]DNSConfiguration{
		"zero service priority": {
			Nameservers: []DNSNameserver{{ServicePriority: 0, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}},
		},
		"no address without no-default-alpn": {
			// The draft: without no-default-alpn the nameserver also serves
			// unencrypted DNS, which needs an address.
			Nameservers: []DNSNameserver{{ServicePriority: 1, AuthenticationDomainName: "d.example."}},
		},
		"alpn without authentication domain": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamALPN: {0x02, 'h', '2'},
				},
			}},
		},
		"ipv4hint is forbidden": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamIPv4Hint: {192, 0, 2, 1},
				},
			}},
		},
		"ipv6hint is forbidden": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamIPv6Hint: make([]byte, 16),
				},
			}},
		},
		"ipv6 address in the ipv4 list": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			}},
		},
		"ipv4 address in the ipv6 list": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, IPv6Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
		},
		"ipv4-mapped address in the ipv6 list": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, IPv6Addresses: []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")},
			}},
		},
		"zoned ipv6 address": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, IPv6Addresses: []netip.Addr{netip.MustParseAddr("fe80::1%en0")},
			}},
		},
		"non-FQDN authentication domain": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, AuthenticationDomainName: "not-fqdn",
				IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
		},
		"U-label authentication domain": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, AuthenticationDomainName: "bücher.example.",
				IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
		},
		"empty search domain": {
			Nameservers: []DNSNameserver{{
				ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			}},
			// Empty is legal for INTERNAL domains (root) but not for search domains.
			SearchDomains: []string{""},
		},
	}

	for name, configuration := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, configuration.validate(),
				"the configuration must be rejected")
			// And the encoder must refuse to emit it, so this implementation cannot
			// send what it would reject.
			_, err := encodeDNSAssign([]DNSConfiguration{configuration})
			require.Error(t, err, "the encoder must refuse an invalid configuration")
		})
	}
}

func TestDNSAssignValidationAcceptsUppercaseALabel(t *testing.T) {
	t.Parallel()

	// The IDNA profile is MapForLookup, which lowercases, so an upper-case A-label is
	// legal and must not be rejected. The reference's own tests accept this form.
	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority:          1,
			AuthenticationDomainName: "XN--BCHER-KVA.example.",
			IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}},
	}
	require.NoError(t, configuration.validate())
}

func TestDNSAssignRejectsOversizeCapsule(t *testing.T) {
	t.Parallel()

	oversize := make([]byte, maxDNSAssignCapsuleSize+1)
	_, err := parseDNSAssign(oversize)
	require.Error(t, err, "a capsule above the DNS_ASSIGN limit must be rejected before parsing")
}

// TestDNSAssignRejectsTruncatedInputs walks every truncation point of a valid capsule.
//
// This is the systematic version of the hand-picked malformed cases: a parser that
// reads past the end at ANY prefix length is a panic or a read of adjacent memory, and
// only checking every offset catches the one that was missed.
func TestDNSAssignRejectsTruncatedInputs(t *testing.T) {
	t.Parallel()

	configuration := DNSConfiguration{
		Nameservers: []DNSNameserver{{
			ServicePriority:          1,
			IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			AuthenticationDomainName: "resolver.example.",
			ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamKey(3): {0, 53},
			},
		}},
		InternalDomains: []string{"internal.example."},
		SearchDomains:   []string{"search.example."},
	}
	encoded, err := encodeDNSAssign([]DNSConfiguration{configuration})
	require.NoError(t, err)
	full := decodeCapsulePayload(t, encoded)

	// Truncating to zero bytes is LEGAL: the payload is a repeated structure with no
	// top-level count, so an empty one means "no configurations". That is the draft's
	// shape, not a parser gap, and the loop starts at 1 accordingly.
	for length := 1; length < len(full); length++ {
		// Must not panic, and must not accept a partial structure.
		_, err := parseDNSAssign(full[:length])
		require.Error(t, err, "truncating to %d bytes must be rejected", length)
	}
	// An empty payload is accepted and yields nothing.
	empty, err := parseDNSAssign(nil)
	require.NoError(t, err, "an empty payload is a valid, empty configuration list")
	require.Empty(t, empty)

	// The complete payload must succeed, proving the loop above is not trivially
	// passing because everything fails.
	decoded, err := parseDNSAssign(full)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
}

// TestDNSAssignUsableResolverDetection covers the only selection question this layer can
// answer without a query.
//
// Which CONFIGURATION answers a name, and which RESOLVER within it, both depend on the query
// and are decided in protocol/masque, where the runtime model lives. Asserting a flattening
// rule here would be a second, weaker answer to the same question.
func TestDNSAssignUsableResolverDetection(t *testing.T) {
	t.Parallel()

	require.True(t, (&DNSAssignment{Configurations: []DNSConfiguration{{
		Nameservers: []DNSNameserver{
			{ServicePriority: 10, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		},
	}}}).hasUsableResolver())

	// A priority of zero is not usable: the draft requires a non-zero service priority.
	require.False(t, (&DNSAssignment{Configurations: []DNSConfiguration{{
		Nameservers: []DNSNameserver{
			{ServicePriority: 0, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		},
	}}}).hasUsableResolver())

	// A name-only nameserver IS usable, because same-connection DoH reaches it by name.
	require.True(t, (&DNSAssignment{Configurations: []DNSConfiguration{{
		Nameservers: []DNSNameserver{
			{ServicePriority: 1, AuthenticationDomainName: "dns.example.test."},
		},
	}}}).hasUsableResolver())

	// Neither an address nor a name: nothing to reach.
	require.False(t, (&DNSAssignment{Configurations: []DNSConfiguration{{
		Nameservers: []DNSNameserver{{ServicePriority: 1}},
	}}}).hasUsableResolver())
}

func TestDNSAssignmentEmpty(t *testing.T) {
	t.Parallel()

	var nilAssignment *DNSAssignment
	require.True(t, nilAssignment.Empty())

	require.True(t, (&DNSAssignment{}).Empty())
	require.True(t, (&DNSAssignment{Configurations: []DNSConfiguration{{}}}).Empty())
	require.False(t, (&DNSAssignment{Configurations: []DNSConfiguration{{
		Nameservers: []DNSNameserver{{
			ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}},
	}}}).Empty())
}
