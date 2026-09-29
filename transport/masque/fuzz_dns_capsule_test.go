package masque

import (
	"bytes"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// Fuzzing for the DNS_ASSIGN and PREF64 parsers.
//
// # Why these two are worth fuzzing specifically
//
// Both capsules carry configuration the CLIENT then acts on, and both are parsed from bytes
// the server chose, on a path that runs as soon as the capsule arrives -- before any
// application logic can reject it. Their failure modes are not cosmetic:
//
//   - DNS_ASSIGN decides which resolver inner queries go to. A misparse that produced a
//     plausible-looking address would silently redirect DNS, so the parser must reject
//     anything it cannot read exactly rather than recovering to a default.
//   - PREF64 decides a NAT64 prefix set. A prefix whose host bits were not masked would
//     compare unequal against the same prefix written canonically, so the parser must
//     normalise rather than store whatever bytes it was handed.
//
// The properties asserted are the three that matter for a parser on a network path:
//
//	no panic, whatever the bytes
//	no unbounded allocation driven by a declared length or count
//	anything reported valid must round-trip through the encoder unchanged
//
// The round-trip property is the strongest of the three and is the one that catches subtle
// framing errors: a parser that accepts something the encoder cannot reproduce has accepted
// a message whose meaning depends on which side you ask.

// dnsAssignSeeds builds the corpus for the DNS_ASSIGN fuzzer.
func dnsAssignSeeds() [][]byte {
	seeds := [][]byte{
		// Empty: a valid withdrawal.
		{},
		// A minimal configuration: one nameserver, one IPv6 address, no auth name.
		{1, 0, 1, 0, 0, 1, 0, 0, 0, 0},
		// A configuration with an authentication domain name.
		append([]byte{1, 0, 1, 0, 0, 1, 0, 0, 0, 10}, []byte("dns.test.x.")...),
	}
	// A truncated run at every length, so each partial read is explored. The complete
	// message below is deliberately rich -- a nameserver with both families, an auth
	// name, SVC parameters, then internal and search domains -- because truncating a
	// rich message explores far more paths than truncating a minimal one.
	full := dnsAssignFullVector()
	for length := 0; length < len(full); length++ {
		seeds = append(seeds, full[:length])
	}
	seeds = append(seeds, full)
	// The multi-configuration shape, plus its truncations, so the nested counts and the
	// configuration boundaries are explored rather than only the flat single-config case.
	multi := dnsAssignMultiConfigurationVector()
	for length := 0; length < len(multi); length++ {
		seeds = append(seeds, multi[:length])
	}
	seeds = append(seeds, multi)

	// Impossible counts, which are the classic way to make a parser allocate: a
	// nameserver count and an address count that cannot possibly be backed by the
	// remaining bytes.
	seeds = append(seeds,
		[]byte{255},                             // absurd nameserver count
		[]byte{1, 0, 255},                       // absurd IPv4 count
		[]byte{1, 0, 0, 255},                    // absurd IPv6 count
		[]byte{1, 0, 0, 0, 1},                   // one IPv6 address, no bytes
		[]byte{1, 0, 1, 0, 0, 1, 0, 0, 0},       // auth name length 0, truncated
		[]byte{1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0}, // trailing byte
	)
	// A declared SVC parameter length with nothing behind it.
	seeds = append(seeds, []byte{1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255})
	return seeds
}

// dnsAssignMultiConfigurationVector is a valid payload carrying SEVERAL configurations with
// distinct internal domains and per-nameserver metadata.
//
// It is a seed in its own right because the multi-configuration shape is where the runtime
// model does its most interesting work: configuration boundaries, longest-match internal
// domination, and per-resolver authentication domains, dohpaths, ports and ALPN lists. A
// corpus of single-configuration messages would barely exercise the decoder's nested counts.
func dnsAssignMultiConfigurationVector() []byte {
	assignment := DNSAssignment{
		Configurations: []DNSConfiguration{
			{
				InternalDomains: []string{"corp.example."},
				SearchDomains:   []string{"corp.example."},
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          1,
						IPv4Addresses:            []netip.Addr{netip.MustParseAddr("10.0.0.53")},
						AuthenticationDomainName: "corp-dns.example.",
						ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
							dnsmessage.SVCParamKey(1): {0x02, 'h', '2', 0x02, 'h', '3'},
							dnsmessage.SVCParamKey(3): {0x20, 0xfb},
							dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
						},
					},
					{
						ServicePriority: 2,
						IPv6Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::53")},
					},
				},
			},
			{
				InternalDomains: []string{"example."},
				Nameservers: []DNSNameserver{
					{
						ServicePriority: 1,
						IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
					},
				},
			},
			{
				// No internal domains: the default configuration.
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          1,
						AuthenticationDomainName: "public-dns.example.",
						ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
							dnsmessage.SVCParamKey(1): {0x02, 'h', '3'},
							dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
						},
					},
				},
			},
		},
	}
	encoded, err := encodeDNSAssign(assignment.Configurations)
	if err != nil {
		panic(err)
	}
	defer encoded.Release()
	return bytes.Clone(capsulePayloadForSeed(encoded.Bytes()))
}

// dnsAssignFullVector is one complete, valid DNS_ASSIGN payload used as a fuzz seed and as
// the round-trip subject.
//
// It is built through the ENCODER rather than written out by hand, so the seed cannot drift
// out of sync with the format: if the encoder is wrong the seed is wrong in the same way,
// and the round-trip property still catches it.
func dnsAssignFullVector() []byte {
	assignment := DNSAssignment{
		Configurations: []DNSConfiguration{
			{
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          1,
						IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
						IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::53")},
						AuthenticationDomainName: "dns.example.test.",
						ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
							dnsmessage.SVCParamKey(1): []byte{0},
							dnsmessage.SVCParamKey(3): {0x20, 0xfb},
							dnsmessage.SVCParamKey(7): []byte("/dns-query{?dns}"),
						},
					},
				},
				InternalDomains: []string{"internal.example.test."},
				SearchDomains:   []string{"search.example.test."},
			},
		},
	}
	encoded, err := encodeDNSAssign(assignment.Configurations)
	if err != nil {
		panic(err)
	}
	defer encoded.Release()
	// The seed is a PAYLOAD, which is what the fuzz target feeds the parser.
	return bytes.Clone(capsulePayloadForSeed(encoded.Bytes()))
}

// normalizeDNSConfigurations makes nil and empty slices compare equal.
//
// The codecs cannot preserve the distinction -- a zero count on the wire decodes to whatever
// the parser's make() produces -- so a round-trip comparison must not assert one.
func normalizeDNSConfigurations(configurations []DNSConfiguration) []DNSConfiguration {
	normalized := make([]DNSConfiguration, 0, len(configurations))
	for _, configuration := range configurations {
		entry := configuration
		entry.Nameservers = make([]DNSNameserver, 0, len(configuration.Nameservers))
		for _, nameserver := range configuration.Nameservers {
			nameserverEntry := nameserver
			if len(nameserver.IPv4Addresses) == 0 {
				nameserverEntry.IPv4Addresses = []netip.Addr{}
			}
			if len(nameserver.IPv6Addresses) == 0 {
				nameserverEntry.IPv6Addresses = []netip.Addr{}
			}
			if nameserver.ServiceParameters == nil {
				nameserverEntry.ServiceParameters = map[dnsmessage.SVCParamKey][]byte{}
			}
			entry.Nameservers = append(entry.Nameservers, nameserverEntry)
		}
		if len(configuration.InternalDomains) == 0 {
			entry.InternalDomains = []string{}
		}
		if len(configuration.SearchDomains) == 0 {
			entry.SearchDomains = []string{}
		}
		normalized = append(normalized, entry)
	}
	return normalized
}

// capsulePayload strips a capsule's type and length header, leaving the payload.
//
// The codecs return whole capsules while the parsers take payloads, and confusing the two
// is exactly the mistake that makes a round-trip test pass while testing nothing.
func capsulePayload(t *testing.T, capsule []byte) []byte {
	t.Helper()
	payload, err := capsulePayloadForSeedErr(capsule)
	require.NoError(t, err)
	return payload
}

// capsulePayloadForSeed is capsulePayload for callers without a *testing.T.
func capsulePayloadForSeed(capsule []byte) []byte {
	payload, err := capsulePayloadForSeedErr(capsule)
	if err != nil {
		panic(err)
	}
	return payload
}

func capsulePayloadForSeedErr(capsule []byte) ([]byte, error) {
	_, length, valid := decodeVarintChecked(capsule)
	if !valid {
		return nil, E.New("capsule has no readable type")
	}
	_, payloadLength, valid := decodeVarintChecked(capsule[length:])
	if !valid {
		return nil, E.New("capsule has no readable length")
	}
	start := length + payloadLength
	if start > len(capsule) {
		return nil, E.New("capsule length runs past the buffer")
	}
	return capsule[start:], nil
}

// FuzzDNSAssign checks the DNS_ASSIGN parser against hostile input.
func FuzzDNSAssign(fuzz *testing.F) {
	for _, seed := range dnsAssignSeeds() {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, payload []byte) {
		// A declared length must never drive an allocation larger than the ceiling,
		// whatever the payload claims. The bound is enforced inside the parser; this
		// assertion makes the property visible at the fuzz target.
		require.LessOrEqual(t, len(payload), maxDNSAssignCapsuleSize)

		configurations, err := parseDNSAssign(payload)
		if err != nil {
			// A rejection is a valid outcome: it means the parser refused rather than
			// guessed. Nothing further can be asserted about a rejected payload.
			return
		}

		// Everything reported valid must be internally coherent.
		for _, configuration := range configurations {
			require.NoError(t, configuration.validate(),
				"a configuration the parser accepted must also validate")

			for _, nameserver := range configuration.Nameservers {
				for _, address := range append(append([]netip.Addr(nil), nameserver.IPv4Addresses...), nameserver.IPv6Addresses...) {
					require.True(t, address.IsValid(),
						"an accepted nameserver address must be valid")
					require.False(t, address.Is4In6(),
						"an accepted address must be canonically stored, not 4-in-6")
				}
				require.NoError(t, validateDomainName(nameserver.AuthenticationDomainName, true),
					"an accepted authentication domain must be a valid domain name")

				// SVC parameters must be strictly increasing by key, which is what makes
				// a re-encode deterministic.
				keys := sortedSVCParamKeys(nameserver.ServiceParameters)
				for index := 1; index < len(keys); index++ {
					require.Less(t, uint16(keys[index-1]), uint16(keys[index]),
						"accepted SVC parameter keys must be strictly increasing")
				}
			}
			// Internal domains may be empty -- the draft uses that for the DNS root --
			// while search domains may not, which is why the two are checked with
			// different allowances rather than folded into one loop.
			for _, domain := range configuration.InternalDomains {
				require.NoError(t, validateDomainName(domain, true),
					"an accepted internal domain must be a valid domain name")
			}
			for _, domain := range configuration.SearchDomains {
				require.NoError(t, validateDomainName(domain, false),
					"an accepted search domain must be a valid, non-empty domain name")
			}
		}

		// The strongest property: anything accepted must survive a re-encode and
		// re-parse unchanged. A parser that accepts a message the encoder cannot
		// reproduce has accepted something whose meaning depends on which side reads it.
		reEncoded, encodeErr := encodeDNSAssign(configurations)
		require.NoError(t, encodeErr,
			"a configuration the parser accepted must be encodable")
		reParsed, reparseErr := parseDNSAssign(capsulePayload(t, reEncoded.Bytes()))
		require.NoError(t, reparseErr,
			"re-encoding an accepted configuration must produce a parseable message")
		require.Equal(t, configurations, reParsed,
			"re-encoding an accepted configuration must be lossless")
	})
}

// pref64Seeds builds the corpus for the PREF64 fuzzer.
func pref64Seeds() [][]byte {
	var seeds [][]byte
	// Every prefix length the draft permits.
	for _, length := range []byte{32, 40, 48, 56, 64, 96} {
		entry := make([]byte, 0, 13)
		entry = append(entry, length)
		entry = append(entry, netip.MustParseAddr("2001:db8::").AsSlice()...)
		seeds = append(seeds, entry)
	}
	// Every prefix length the draft does NOT permit, which must be rejected.
	for _, length := range []byte{0, 1, 8, 16, 24, 31, 33, 47, 63, 65, 95, 97, 127, 128, 255} {
		entry := make([]byte, 0, 13)
		entry = append(entry, length)
		entry = append(entry, netip.MustParseAddr("2001:db8::").AsSlice()...)
		seeds = append(seeds, entry)
	}
	// Truncation at every length of a complete two-prefix message.
	full := append(pref64Entry(96, "64:ff9b::"), pref64Entry(64, "2001:db8:64::")...)
	for length := 0; length < len(full); length++ {
		seeds = append(seeds, full[:length])
	}
	seeds = append(seeds, full)
	// A run longer than the ceiling, to prove the count bound holds.
	oversized := make([]byte, 0, (maxPREF64Prefixes+2)*13)
	for range maxPREF64Prefixes + 2 {
		oversized = append(oversized, pref64Entry(64, "2001:db8::")...)
	}
	seeds = append(seeds, oversized)
	// Host bits set below the prefix length, which must be masked off.
	hostBits := pref64Entry(96, "64:ff9b::1.2.3.4")
	seeds = append(seeds, hostBits)
	return seeds
}

// pref64Entry builds one 13-byte PREF64 entry: a prefix-length byte followed by EXACTLY
// 12 address bytes.
//
// The fixed 12 bytes are load-bearing and easy to get wrong: the wire field is 96 bits
// regardless of the prefix length, so an entry built from a full 16-byte netip.Addr would be
// 17 bytes and every boundary calculation downstream would be wrong.
func pref64Entry(prefixLength byte, address string) []byte {
	entry := make([]byte, 0, 13)
	entry = append(entry, prefixLength)
	full := netip.MustParseAddr(address).As16()
	entry = append(entry, full[:12]...)
	return entry
}

// FuzzPREF64 checks the PREF64 parser against hostile input.
func FuzzPREF64(fuzz *testing.F) {
	for _, seed := range pref64Seeds() {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, payload []byte) {
		prefixes, err := parsePREF64(payload)
		if err != nil {
			return
		}
		require.LessOrEqual(t, len(prefixes), maxPREF64Prefixes,
			"an accepted prefix run must respect the count ceiling")

		for _, prefix := range prefixes {
			require.True(t, prefix.IsValid(), "an accepted prefix must be valid")
			require.True(t, prefix.Addr().Is6(), "an accepted prefix must be IPv6")
			// The masked-host-bits property: a prefix the parser reports must be
			// canonical, so that two spellings of the same prefix compare equal.
			require.Equal(t, prefix, prefix.Masked(),
				"an accepted prefix must have its host bits masked")
			switch prefix.Bits() {
			case 32, 40, 48, 56, 64, 96:
			default:
				t.Fatalf("an accepted prefix length must be one the draft permits, got %d", prefix.Bits())
			}
		}

		// Empty input means "withdraw", which is a valid outcome that yields no prefixes.
		if len(payload) == 0 {
			require.Empty(t, prefixes, "an empty capsule must invalidate rather than invent prefixes")
		}

		// Round-trip: what was accepted must be reproducible.
		reEncoded, encodeErr := encodePREF64(prefixes)
		require.NoError(t, encodeErr)
		defer reEncoded.Release()
		// encodePREF64 returns a whole CAPSULE (type + length + payload); the parser
		// takes the payload only, so the header is skipped here.
		reParsed, reparseErr := parsePREF64(capsulePayload(t, reEncoded.Bytes()))
		require.NoError(t, reparseErr)
		require.Equal(t, prefixes, reParsed, "re-encoding accepted prefixes must be lossless")
	})
}

// FuzzDNSAssignEncodeParseRoundTrip fuzzes the ENCODER with arbitrary structure, checking
// that whatever it produces parses back to the same value.
//
// Fuzzing only the parser would leave the other half untested: an encoder that emitted a
// non-canonical message would be accepted by its own parser but rejected by a stricter peer,
// which is the kind of asymmetry that only shows up in interop.
func FuzzDNSAssignEncodeParseRoundTrip(fuzz *testing.F) {
	fuzz.Add([]byte{0})
	fuzz.Add([]byte{1, 0, 1, 0})
	fuzz.Add([]byte{2, 255, 7})

	fuzz.Fuzz(func(t *testing.T, control []byte) {
		// The control bytes drive a small structured input, so the fuzzer can reach
		// deep into the encoder without needing a complex seed format.
		assignment := DNSAssignment{}
		for index, value := range control {
			if index >= 8 {
				break
			}
			configuration := DNSConfiguration{
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          uint16(value),
						IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2." + itoaDecimal(int(value)))},
						AuthenticationDomainName: "dns.example.test.",
					},
				},
			}
			if value&1 != 0 {
				configuration.InternalDomains = []string{"internal.example.test."}
			}
			if value&2 != 0 {
				configuration.SearchDomains = []string{"search.example.test."}
			}
			assignment.Configurations = append(assignment.Configurations, configuration)
		}

		encoded, err := encodeDNSAssign(assignment.Configurations)
		if err != nil {
			return
		}
		defer encoded.Release()
		require.LessOrEqual(t, encoded.Len(), maxDNSAssignCapsuleSize)

		parsed, err := parseDNSAssign(capsulePayload(t, encoded.Bytes()))
		require.NoError(t, err, "the encoder must only produce parseable output")
		// The comparison is on NORMALISED values, because a nil slice and an empty
		// slice are indistinguishable on the wire: the parser always produces the
		// empty non-nil form, so comparing raw values would report a mismatch for a
		// message that round-trips perfectly. Normalising is what makes this an
		// assertion about the WIRE rather than about Go's slice representation.
		require.Equal(t, normalizeDNSConfigurations(assignment.Configurations), normalizeDNSConfigurations(parsed),
			"the encoder and parser must agree, or interop depends on which side reads the message")
	})
}

// TestDNSAssignAndPREF64RejectTruncationAtEveryLength is the deterministic companion to the
// fuzzers.
//
// A fuzzer explores truncation only if it happens to generate it, and a corpus entry can be
// minimised away. This walks every truncation point explicitly, so the property is checked on
// every run rather than probabilistically.
func TestDNSAssignAndPREF64RejectTruncationAtEveryLength(t *testing.T) {
	t.Parallel()

	full := dnsAssignFullVector()
	for length := 0; length < len(full); length++ {
		// Truncation may legitimately parse to FEWER configurations in one case: a
		// prefix of the message could end exactly on a configuration boundary. So the
		// assertion is not "must fail" but "must never panic, and if it succeeds it
		// must be coherent".
		configurations, err := parseDNSAssign(full[:length])
		if err != nil {
			continue
		}
		for _, configuration := range configurations {
			require.NoError(t, configuration.validate(),
				"a truncated message that parsed must still be coherent at length %d", length)
		}
	}

	pref64Full := append(pref64Entry(96, "64:ff9b::"), pref64Entry(64, "2001:db8:64::")...)
	for length := 0; length <= len(pref64Full); length++ {
		// 13 bytes per prefix is exact, so a partial entry cannot be a shorter last
		// prefix: either the bytes end on an entry boundary, or the message is
		// malformed. The two cases are asserted separately below.
		midEntry := length%13 != 0
		if length == 0 {
			// The empty capsule is the withdrawal signal from §4.2, not a malformed
			// run: it must parse to no prefixes rather than be rejected.
			prefixes, err := parsePREF64(nil)
			require.NoError(t, err, "an empty PREF64 capsule invalidates rather than failing")
			require.Empty(t, prefixes)
			continue
		}
		prefixes, err := parsePREF64(pref64Full[:length])
		if midEntry {
			require.Error(t, err,
				"a prefix run truncated mid-entry at length %d must be rejected", length)
			continue
		}
		// On an entry boundary the run is a shorter but complete message, so it must
		// parse -- rejection here would mean the parser mis-frames exact input.
		require.NoError(t, err,
			"a prefix run ending on an entry boundary at length %d must parse", length)
		require.Equal(t, length/13, len(prefixes),
			"a complete run must yield exactly one prefix per 13 bytes")
		for _, prefix := range prefixes {
			require.Equal(t, prefix, prefix.Masked())
		}
	}
}

// TestDNSAssignParserNeverAllocatesFromDeclaredCounts pins the allocation bound.
//
// The classic parser vulnerability is a declared count that is honoured before the bytes
// backing it are checked, so a four-byte input can request gigabytes. The parser must derive
// its allocation from the bytes it can actually see.
func TestDNSAssignParserNeverAllocatesFromDeclaredCounts(t *testing.T) {
	t.Parallel()

	// A nameserver count of 2^21-1 with no nameservers behind it. If the parser sized a
	// slice from this count it would allocate millions of entries for a 3-byte input.
	hugeCount := []byte{0xff, 0xff, 0xff, 0x7f}
	_, err := parseDNSAssign(hugeCount)
	require.Error(t, err, "a declared count with no bytes behind it must be rejected")

	// The same for an address count inside a nameserver.
	_, err = parseDNSAssign([]byte{1, 0, 0xff, 0xff, 0xff, 0x7f})
	require.Error(t, err)

	// And a PREF64 run that declares more prefixes than the ceiling through sheer length.
	oversized := bytes.Repeat([]byte{96}, (maxPREF64Prefixes+1)*13)
	_, err = parsePREF64(oversized)
	require.Error(t, err, "a prefix run beyond the ceiling must be rejected")
}

// TestDNSAssignAddressCountsCannotOverflow is the regression test for an integer overflow
// the fuzzer found.
//
// Both address-count guards read `count*size > len(payload)`. A varint may declare a count
// near 2^64, and the product WRAPS: a wrapped value compares as small, so the guard passed
// and the loop below sliced `payload[:4]` out of an exhausted buffer. The fuzzer reached it
// with a 16-byte input, which is the point worth keeping -- a sixteen-byte message could
// crash the client, and no unit test with hand-written inputs had produced a count that
// large.
//
// The guards now DIVIDE rather than multiply, which cannot overflow and expresses the same
// test.
func TestDNSAssignAddressCountsCannotOverflow(t *testing.T) {
	t.Parallel()

	// The exact input the fuzzer produced, kept verbatim. It must be rejected, not panic.
	overflow := []byte("000\x010000\xe0\x00\x00\x00\x00\x00\x00\x00")
	require.NotPanics(t, func() {
		_, err := parseDNSAssign(overflow)
		require.Error(t, err, "a count that cannot be backed by the payload must be rejected")
	}, "a declared address count must never panic, however large it is")

	// The same shape driven deliberately, so the regression is pinned by construction rather
	// than only by a corpus file: a maximal varint count for each family with a few bytes
	// behind it.
	maxCount := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	for index, payload := range [][]byte{
		append([]byte{1, 0, 0}, maxCount...),                   // huge IPv4 count
		append([]byte{1, 0, 0, 0}, maxCount...),                // huge IPv6 count
		append([]byte{1, 0, 1, 0, 0, 1, 0, 0, 0}, maxCount...), // both, after an auth name
	} {
		require.NotPanics(t, func() {
			_, _ = parseDNSAssign(payload)
		}, "an oversized declared count must never panic (case %d)", index)
	}
}

// svcbEdgeCaseSeeds builds payloads that exercise the SVCB validation paths, which is where a
// malformed advertisement can be mistaken for a usable resolver.
//
// The cases come from the specifications rather than from guesswork:
//
//   - RFC 9460 §7.1.1: alpn pairs MUST exactly fill the value; no-default-alpn MUST be empty
//   - RFC 9460 §7.2:   port is exactly 2 octets
//   - RFC 9460 §8:     mandatory must not list itself, must not repeat, and must reference
//     keys that are present
//   - draft-06 §3.2:   ipv4hint and ipv6hint MUST NOT appear
//   - draft-06 §3.5:   an empty internal domain is the root
func svcbEdgeCaseSeeds() [][]byte {
	var seeds [][]byte

	svcParam := func(key uint16, value []byte) []byte {
		encoded := []byte{byte(key >> 8), byte(key), byte(len(value) >> 8), byte(len(value))}
		return append(encoded, value...)
	}
	// A nameserver with a given SvcParam block, one IPv6 address, and an auth name.
	nameserver := func(parameters []byte) []byte {
		payload := []byte{0, 1}      // ServicePriority = 1
		payload = append(payload, 0) // IPv4 count = 0
		payload = append(payload, 1) // IPv6 count = 1
		payload = append(payload, netip.MustParseAddr("2001:db8::53").AsSlice()...)
		payload = append(payload, byte(len("dns.example.test.")))
		payload = append(payload, "dns.example.test."...)
		payload = append(payload, byte(len(parameters)>>8), byte(len(parameters)))
		return append(payload, parameters...)
	}
	configuration := func(parameters []byte, internalDomain string) []byte {
		payload := []byte{1} // Nameserver Count = 1
		payload = append(payload, nameserver(parameters)...)
		if internalDomain == "" {
			payload = append(payload, 0) // Internal Domain Count = 0
		} else {
			payload = append(payload, 1, byte(len(internalDomain)))
			payload = append(payload, internalDomain...)
		}
		return append(payload, 0) // Search Domain Count = 0
	}

	// A valid h2,h3 ALPN with a dohpath, which is the shape the draft uses.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '2', 0x02, 'h', '3'}), svcParam(7, []byte("/dns-query{?dns}"))...),
		""))
	// The root internal domain.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '3'}), svcParam(7, []byte("/dns-query{?dns}"))...),
		"\x00"))
	// no-default-alpn present with a NON-empty value, which RFC 9460 forbids.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '3'}), svcParam(2, []byte{0x01})...),
		""))
	// A truncated ALPN: the length prefix overruns the value.
	seeds = append(seeds, configuration(svcParam(1, []byte{0x05, 'h'}), ""))
	// A zero-length ALPN identifier.
	seeds = append(seeds, configuration(svcParam(1, []byte{0x00}), ""))
	// A comma-separated ALPN, which is presentation format and not wire format.
	seeds = append(seeds, configuration(svcParam(1, []byte("h2,h3")), ""))
	// A port with the wrong length.
	seeds = append(seeds, configuration(svcParam(3, []byte{0x01}), ""))
	// A port with an empty value.
	seeds = append(seeds, configuration(svcParam(3, nil), ""))
	// mandatory listing itself.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x00, 0x00}), ""))
	// mandatory referencing a key that is not present.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x00, 0x03}), ""))
	// mandatory with an odd number of bytes.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x00}), ""))
	// mandatory listing an unknown key.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x9C, 0x40}), ""))
	// mandatory listing duplicate keys.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x00, 0x01, 0x00, 0x01}), ""))
	// mandatory with keys out of order.
	seeds = append(seeds, configuration(svcParam(0, []byte{0x00, 0x03, 0x00, 0x01}), ""))
	// ipv4hint, which draft-06 forbids.
	seeds = append(seeds, configuration(svcParam(4, []byte{192, 0, 2, 1}), ""))
	// ipv6hint, likewise.
	seeds = append(seeds, configuration(svcParam(6, netip.MustParseAddr("2001:db8::1").AsSlice()), ""))
	// An unknown non-mandatory key, which must be IGNORED rather than rejected.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '3'}), svcParam(0x9C40, []byte("ignored"))...),
		""))
	// dohpath with no dns variable, which RFC 9461 requires.
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query")), ""))
	// An absolute dohpath URI.
	seeds = append(seeds, configuration(svcParam(7, []byte("https://elsewhere.example/dns-query")), ""))
	// A dohpath expansion that is not a path.
	seeds = append(seeds, configuration(svcParam(7, []byte("dns-query{?dns}")), ""))
	// A dohpath with an unterminated expression.
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{?dns")), ""))
	// A h2-only resolver carrying a dohpath: it must not be given an HTTP/3 request.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '2'}), svcParam(7, []byte("/dns-query{?dns}"))...), ""))
	// An h3 resolver carrying no dohpath: there is no resource to POST to.
	seeds = append(seeds, configuration(svcParam(1, []byte{0x02, 'h', '3'}), ""))
	// A non-default port alongside a dohpath, which must be part of the origin.
	seeds = append(seeds, configuration(
		append(svcParam(1, []byte{0x02, 'h', '3'}),
			append(svcParam(3, []byte{0x20, 0xFB}), svcParam(7, []byte("/dns-query{?dns}"))...)...), ""))
	// mandatory listing ECH: recognised, but not implemented, so it cannot be honoured.
	mandatoryECH := append(svcParam(0, []byte{0x00, 0x05}), svcParam(5, []byte{0x01, 0x02})...)
	mandatoryECH = append(svcParam(1, []byte{0x02, 'h', '3'}), mandatoryECH...)
	seeds = append(seeds, configuration(mandatoryECH, ""))
	// A dohpath that is not valid UTF-8.
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query\x80{?dns}")), ""))
	// Malformed URI Template expressions: nested braces, an empty expression, and an
	// unsupported operator.
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{{dns}}")), ""))
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{}")), ""))
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{+dns}")), ""))
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{?dns:3}")), ""))
	seeds = append(seeds, configuration(svcParam(7, []byte("/dns-query{?dns*}")), ""))
	// An absolute dohpath must not be accepted as a relative template.
	seeds = append(seeds, configuration(svcParam(7, []byte("//evil.example/dns-query{?dns}")), ""))
	return seeds
}

// FuzzDNSAssignSVCB focuses on the service-parameter validation.
//
// It is separate from FuzzDNSAssign so the corpus for this shape stays dense: the interesting
// cases are all in a handful of bytes of SvcParam value, and a general-purpose corpus would
// spend almost all its effort elsewhere.
func FuzzDNSAssignSVCB(fuzz *testing.F) {
	for _, seed := range svcbEdgeCaseSeeds() {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, payload []byte) {
		configurations, err := parseDNSAssign(payload)
		if err != nil {
			return
		}
		// Anything accepted must be self-consistent, so it can be re-encoded and re-parsed.
		for _, configuration := range configurations {
			require.NoError(t, configuration.validate())
		}
		encoded, encodeErr := encodeDNSAssign(configurations)
		require.NoError(t, encodeErr,
			"a configuration the parser accepted must be encodable, or validity depends on which side reads it")
		defer encoded.Release()
		reparsed, reparseErr := parseDNSAssign(capsulePayload(t, encoded.Bytes()))
		require.NoError(t, reparseErr)
		require.Equal(t, normalizeDNSConfigurations(configurations), normalizeDNSConfigurations(reparsed))
	})
}

// FuzzDohPathExpansion drives the dohpath URI Template parser with arbitrary text.
//
// # The properties that must hold for EVERY input, valid or not
//
// The parser is the boundary between a server's advertisement and the request path this client
// sends, so the invariants are about what an ACCEPTED template is allowed to produce:
//
//   - the expansion is a usable ":path": absolute, and free of the characters that would change how
//     the request is addressed ("?" would start a query, "#" a fragment, and neither can come from
//     a template whose expressions have been deleted);
//   - the expansion contains no brace, because every expression is removed and RFC 6570 reserves
//     braces in a template;
//   - the expansion is valid UTF-8, since the template it came from was checked as text;
//   - expansion is DETERMINISTIC: the same template must not produce two different paths.
//
// A rejection is always an acceptable outcome -- the parser's job is to refuse what it cannot
// interpret -- so an error is never a failure here. The fuzz target is searching for accepted
// values that break one of the invariants above.
//
// The seeds are the shapes that historically broke this code: the draft's own example, literal
// suffixes (which a "truncate at the first brace" implementation got wrong), expressions that
// expand to nothing, and malformed escapes and var names.
func FuzzDohPathExpansion(fuzz *testing.F) {
	for _, seed := range []string{
		"/dns-query{?dns}",
		"/dns-query",
		"/q{?dns}suffix",
		"{?dns}",
		"/dns-query{dns}",
		"dns-query{?dns}",
		"/dns-query{&dns}",
		"/dns-query{/dns}",
		"/dns-query{.dns}",
		"/dns-query{;dns}",
		"/dns-query{?other,dns}",
		"/dns-query{?dns*}",
		"/dns-query{?dns:3}",
		"/dns-query{?dns,}",
		"/dns-query{}",
		"/dns-query{{dns}}",
		"/dns-query{?dns",
		"/dns-query?dns}",
		"/dns-query{+dns}",
		"/dns-query{#dns}",
		"/dns-query{?.dns}",
		"/dns-query{?dns.}",
		"/dns-query{?dns..query}",
		"/dns-query{?.}",
		"/dns-query{?d-ns}",
		"/dns-query{?dn%2}",
		"/dns-query{?dn%ZZ}",
		"/dns-query{?dn%2Es}",
		"/%E4%B8%AD/dns-query{?dns}",
		"/dns%2Dquery{?dns}",
		"/a%20b{?dns}",
		"/dns-query\x80{?dns}",
		"",
		"/",
		"{?dns}suffix",
		"/q{?dns}{?dns}",
	} {
		fuzz.Add(seed)
	}
	fuzz.Fuzz(func(t *testing.T, template string) {
		expanded, err := ExpandDohPathForPost(template)
		if err != nil {
			return
		}
		require.NotEmpty(t, expanded, "an empty expansion is refused, so it can never be returned")
		require.True(t, strings.HasPrefix(expanded, "/"),
			"an accepted template must expand to an absolute path, got %q from %q", expanded, template)
		require.NotContains(t, expanded, "{",
			"every expression is deleted during expansion, so no brace can survive: %q from %q",
			expanded, template)
		require.NotContains(t, expanded, "}",
			"every expression is deleted during expansion, so no brace can survive: %q from %q",
			expanded, template)
		require.NotContains(t, expanded, "?",
			"a ? would start a query string, changing what is addressed: %q from %q",
			expanded, template)
		require.NotContains(t, expanded, "#",
			"a # would start a fragment, which is never sent to the server: %q from %q",
			expanded, template)
		require.True(t, utf8.ValidString(expanded),
			"an accepted template is valid UTF-8, so its expansion must be too: %q from %q",
			expanded, template)

		// Determinism: expansion depends on the template alone, so a second call must agree. A
		// parser carrying state between calls would show up here.
		again, againErr := ExpandDohPathForPost(template)
		require.Equal(t, err, againErr)
		require.Equal(t, expanded, again)

		// The expansion is used as the ":path" of a request to a FIXED origin, so that is what
		// must be checked. Parsing the expansion on its own would be the wrong question: a path
		// beginning "//" is read as a protocol-relative reference with an AUTHORITY component, so
		// "/{dns}/%00" -> "//%00" is rejected as a standalone URL even though the same string is
		// an ordinary path once an origin is present. A test built on the wrong shape would
		// demand a rule the protocol does not have.
		//
		// What must hold is that the request URL keeps the configured origin and carries exactly
		// this path -- including a leading "//", which must not be allowed to introduce a new
		// host.
		requestURL := "https://doh.example:443" + expanded
		parsed, parseErr := url.Parse(requestURL)
		require.NoError(t, parseErr,
			"an accepted expansion must be usable in a request URL: %q from %q", expanded, template)
		require.Equal(t, "doh.example:443", parsed.Host,
			"the configured origin must survive expansion: %q from %q", expanded, template)
		require.Equal(t, "https", parsed.Scheme,
			"the scheme must survive expansion: %q from %q", expanded, template)
		require.Empty(t, parsed.RawQuery,
			"a query string would change what is addressed: %q from %q", expanded, template)
		require.Empty(t, parsed.Fragment,
			"a fragment is never sent to the server: %q from %q", expanded, template)
	})
}
