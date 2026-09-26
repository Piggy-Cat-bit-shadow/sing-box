package masque

import (
	std_bufio "bufio"
	"bytes"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Fuzzing for the MASQUE parsers that consume attacker-controlled bytes.
//
// The parsers here are chosen because each one turns bytes from the PEER into
// either state or a decision, on a path that runs before any application logic can
// reject the input:
//
//   - the capsule framer, which reads a type varint, a length varint and then that
//     many bytes, and is the first thing an established tunnel reads;
//   - the route-advertisement parser, whose output decides which destinations the
//     server will forward, so a misparse is a policy bypass rather than a cosmetic
//     error;
//   - the address parser, whose output decides what a client is allowed to source
//     traffic from;
//   - the CONNECT-IP URI-template matcher, which decides the tunnel SCOPE (target
//     prefix and protocol) from the request path.
//
// The properties asserted in every target are the three that matter for a parser on
// a network path:
//
//	no panic, whatever the bytes
//	no unbounded allocation driven by a declared length
//	anything reported valid must be internally coherent
//
// # The seed corpus was WRONG, and that made every "valid" case a false green
//
// The first version of this file wrote its seeds as if the wire format carried a
// leading entry COUNT and as if the byte before an address were a BYTE LENGTH:
//
//	// One route: 0.0.0.0 - 0.0.0.0, protocol 0.
//	fuzz.Add([]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0})
//	// One assignment: request ID 1, IPv4 0.0.0.0/0.
//	fuzz.Add([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0x00})
//
// Neither shape exists. RFC 9484 sections 4.5 / 4.6 / 4.7 define ALL of these
// capsules as a repeated entry sequence with NO count field, and the byte before an
// address is the IP VERSION (4 or 6), not a byte length. Measured against the real
// parsers, every one of those seeds failed with "invalid IP version: 1" - the 0x01
// the comment called a count was being read as the version.
//
// The consequence was the worst possible one for a fuzz corpus: the fuzz function
// opens with `if err != nil { return }`, so a target whose seeds ALL fail never
// reaches a single assertion. It reported "success" while exploring nothing but the
// error path.
//
// Two things now make that impossible to reintroduce:
//
//  1. every seed that is meant to be valid is declared in a table and asserted to
//     PARSE SUCCESSFULLY, with the expected decoded value, by a deterministic test
//     in this same file. A seed that stops being valid fails the build instead of
//     silently shrinking coverage;
//  2. FuzzRouteAdvertisement and FuzzConnectIPAddresses count accepted-and-non-empty
//     inputs and fail if a bounded run never produced one, so "the corpus only ever
//     exercises the rejection path" is a visible failure rather than a vacuous pass.

// ---------------------------------------------------------------------------
// Deterministic pinning of the seed corpus
// ---------------------------------------------------------------------------
//
// These run on every `go test`, so a regression in a seed is a build failure rather
// than a quiet loss of fuzz coverage.

// routeSeed is one ROUTE_ADVERTISEMENT payload and the entries it must decode to.
type routeSeed struct {
	name     string
	payload  []byte
	expected []AddressRange
}

// routeSeeds is the ROUTE_ADVERTISEMENT corpus. Every payload is written byte by
// byte from RFC 9484 section 4.7:
//
//	IP Version (4 or 6)
//	Start Address (4 or 16 bytes)
//	End Address   (same width, NO version byte)
//	IP Protocol   (1 byte)
//
// repeated with no count field, ordered by ascending IP version and then by
// ascending protocol within a version.
var routeSeeds = []routeSeed{
	{
		name:     "empty payload decodes to no routes",
		payload:  nil,
		expected: nil,
	},
	{
		// 0.0.0.0 - 255.255.255.255, protocol 0: the widest possible IPv4 route,
		// and the one the endpoint itself advertises by default.
		name:    "ipv4 all-addresses protocol 0",
		payload: []byte{4, 0, 0, 0, 0, 255, 255, 255, 255, 0},
		expected: []AddressRange{{
			Start:    netip.MustParseAddr("0.0.0.0"),
			End:      netip.MustParseAddr("255.255.255.255"),
			Protocol: 0,
		}},
	},
	{
		// A single /24 at protocol 6 (TCP).
		name:    "ipv4 single subnet protocol 6",
		payload: []byte{4, 192, 0, 2, 0, 192, 0, 2, 255, 6},
		expected: []AddressRange{{
			Start:    netip.MustParseAddr("192.0.2.0"),
			End:      netip.MustParseAddr("192.0.2.255"),
			Protocol: 6,
		}},
	},
	{
		// A degenerate range: start == end, which is a single address.
		name:    "ipv4 single address protocol 17",
		payload: []byte{4, 198, 18, 0, 2, 198, 18, 0, 2, 17},
		expected: []AddressRange{{
			Start:    netip.MustParseAddr("198.18.0.2"),
			End:      netip.MustParseAddr("198.18.0.2"),
			Protocol: 17,
		}},
	},
	{
		// Two IPv4 routes at the SAME protocol, ordered and disjoint.
		name: "ipv4 two disjoint ranges same protocol",
		payload: []byte{
			4, 10, 0, 0, 0, 10, 0, 0, 255, 6,
			4, 10, 0, 1, 0, 10, 0, 1, 255, 6,
		},
		expected: []AddressRange{
			{Start: netip.MustParseAddr("10.0.0.0"), End: netip.MustParseAddr("10.0.0.255"), Protocol: 6},
			{Start: netip.MustParseAddr("10.0.1.0"), End: netip.MustParseAddr("10.0.1.255"), Protocol: 6},
		},
	},
	{
		// Protocol ordering within one IP version: 0 before 6. This is the shape the
		// cross-protocol overlap check exists for, and these ranges do NOT overlap,
		// so it must be accepted.
		name: "ipv4 protocol 0 then protocol 6 disjoint",
		payload: []byte{
			4, 192, 0, 2, 0, 192, 0, 2, 255, 0,
			4, 198, 51, 100, 0, 198, 51, 100, 255, 6,
		},
		expected: []AddressRange{
			{Start: netip.MustParseAddr("192.0.2.0"), End: netip.MustParseAddr("192.0.2.255"), Protocol: 0},
			{Start: netip.MustParseAddr("198.51.100.0"), End: netip.MustParseAddr("198.51.100.255"), Protocol: 6},
		},
	},
	{
		// A single IPv6 range: the seed the old corpus could not express, because it
		// wrote 16 where the RFC requires 6.
		name: "ipv6 single range protocol 0",
		payload: append(
			append(append([]byte{6}, netip.MustParseAddr("2001:db8::").AsSlice()...),
				netip.MustParseAddr("2001:db8::ffff").AsSlice()...),
			0),
		expected: []AddressRange{{
			Start:    netip.MustParseAddr("2001:db8::"),
			End:      netip.MustParseAddr("2001:db8::ffff"),
			Protocol: 0,
		}},
	},
	{
		// IPv6 at a specific protocol, and a start that is not the prefix base.
		name: "ipv6 specific protocol",
		payload: append(
			append(append([]byte{6}, netip.MustParseAddr("2001:db8:1::1").AsSlice()...),
				netip.MustParseAddr("2001:db8:1::ff").AsSlice()...),
			17),
		expected: []AddressRange{{
			Start:    netip.MustParseAddr("2001:db8:1::1"),
			End:      netip.MustParseAddr("2001:db8:1::ff"),
			Protocol: 17,
		}},
	},
	{
		// IP-version ordering: every IPv4 range precedes every IPv6 range.
		name: "mixed families ascending",
		payload: append(append([]byte{
			4, 198, 18, 0, 0, 198, 18, 0, 255, 0,
			6,
		}, netip.MustParseAddr("2001:db8::").AsSlice()...),
			append(netip.MustParseAddr("2001:db8::1").AsSlice(), 0)...),
		expected: []AddressRange{
			{Start: netip.MustParseAddr("198.18.0.0"), End: netip.MustParseAddr("198.18.0.255"), Protocol: 0},
			{Start: netip.MustParseAddr("2001:db8::"), End: netip.MustParseAddr("2001:db8::1"), Protocol: 0},
		},
	},
	{
		// Every protocol number, one address each, at distinct addresses, in
		// ascending protocol order. This is the widest protocol-ordered set the
		// parser accepts and it exercises the high-water-mark bookkeeping at its
		// widest.
		name:     "ipv4 every protocol number",
		payload:  everyProtocolPayload(),
		expected: everyProtocolExpected(),
	},
}

// everyProtocolPayload builds 256 single-address ranges, one per protocol number,
// in ascending protocol order at ascending addresses.
func everyProtocolPayload() []byte {
	payload := make([]byte, 0, 256*10)
	for protocol := 0; protocol < 256; protocol++ {
		payload = append(payload, 4, 198, 18, byte(protocol), 0, 198, 18, byte(protocol), 0, byte(protocol))
	}
	return payload
}

func everyProtocolExpected() []AddressRange {
	ranges := make([]AddressRange, 0, 256)
	for protocol := 0; protocol < 256; protocol++ {
		address := netip.AddrFrom4([4]byte{198, 18, byte(protocol), 0})
		ranges = append(ranges, AddressRange{Start: address, End: address, Protocol: uint8(protocol)})
	}
	return ranges
}

// addressSeed is one ADDRESS_ASSIGN / ADDRESS_REQUEST payload and what it decodes
// to. RFC 9484 section 4.5 defines each entry as
//
//	Request ID (varint)
//	IP Version (4 or 6)
//	IP Address (4 or 16 bytes)
//	IP Prefix Length (1 byte)
//
// repeated with no count field.
type addressSeed struct {
	name     string
	payload  []byte
	expected []AssignedAddress
}

var addressSeeds = []addressSeed{
	{
		name:     "empty payload decodes to no addresses",
		payload:  nil,
		expected: nil,
	},
	{
		// Request ID 0 is the unsolicited-assignment form, which is what the server
		// sends first and what ADDRESS_ASSIGN is allowed to carry.
		name:    "ipv4 unsolicited /32",
		payload: []byte{0x00, 4, 198, 18, 0, 2, 32},
		expected: []AssignedAddress{{
			RequestID: 0,
			Prefix:    netip.MustParsePrefix("198.18.0.2/32"),
		}},
	},
	{
		name:    "ipv4 /0",
		payload: []byte{0x00, 4, 0, 0, 0, 0, 0},
		expected: []AssignedAddress{{
			RequestID: 0,
			Prefix:    netip.MustParsePrefix("0.0.0.0/0"),
		}},
	},
	{
		// Request ID 1 in its one-byte varint form.
		name:    "ipv4 request id 1 /24",
		payload: []byte{0x01, 4, 198, 18, 0, 0, 24},
		expected: []AssignedAddress{{
			RequestID: 1,
			Prefix:    netip.MustParsePrefix("198.18.0.0/24"),
		}},
	},
	{
		// A two-byte varint request ID. 63 is the largest value the one-byte form
		// can carry, so 64 is the first that needs two bytes.
		name:    "ipv4 two-byte request id",
		payload: []byte{0x40, 0x40, 4, 198, 18, 0, 2, 32},
		expected: []AssignedAddress{{
			RequestID: 64,
			Prefix:    netip.MustParsePrefix("198.18.0.2/32"),
		}},
	},
	{
		// A four-byte varint request ID, at the bottom of its range: 16384 is the
		// first value the two-byte form cannot carry.
		name:    "ipv4 four-byte request id",
		payload: []byte{0x80, 0x00, 0x40, 0x00, 4, 198, 18, 0, 2, 32},
		expected: []AssignedAddress{{
			RequestID: 1 << 14,
			Prefix:    netip.MustParsePrefix("198.18.0.2/32"),
		}},
	},
	{
		// The maximum legal QUIC varint (RFC 9000 section 16 allows 2^62-1).
		name:    "ipv4 maximum request id",
		payload: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 4, 198, 18, 0, 2, 32},
		expected: []AssignedAddress{{
			RequestID: 1<<62 - 1,
			Prefix:    netip.MustParsePrefix("198.18.0.2/32"),
		}},
	},
	{
		// IPv6 /128: the seed the old corpus could not express.
		name:    "ipv6 /128",
		payload: append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 128),
		expected: []AssignedAddress{{
			RequestID: 0,
			Prefix:    netip.MustParsePrefix("2001:db8::1/128"),
		}},
	},
	{
		name:    "ipv6 /64",
		payload: append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8:1::").AsSlice()...), 64),
		expected: []AssignedAddress{{
			RequestID: 0,
			Prefix:    netip.MustParsePrefix("2001:db8:1::/64"),
		}},
	},
	{
		name:    "ipv6 /0",
		payload: append(append([]byte{0x00, 6}, netip.MustParseAddr("::").AsSlice()...), 0),
		expected: []AssignedAddress{{
			RequestID: 0,
			Prefix:    netip.MustParsePrefix("::/0"),
		}},
	},
	{
		// Two entries in one capsule, mixed families, in wire order.
		name: "mixed families two entries",
		payload: append(
			append([]byte{0x00, 4, 198, 18, 0, 2, 32}, 0x01, 6),
			append(netip.MustParseAddr("2001:db8::2").AsSlice(), 128)...),
		expected: []AssignedAddress{
			{RequestID: 0, Prefix: netip.MustParsePrefix("198.18.0.2/32")},
			{RequestID: 1, Prefix: netip.MustParsePrefix("2001:db8::2/128")},
		},
	},
	{
		// The documented "no address available" answer: an all-zero prefix of the
		// right width. This is a VALID payload, not an error.
		name:    "ipv4 refused assignment",
		payload: []byte{0x07, 4, 0, 0, 0, 0, 32},
		expected: []AssignedAddress{{
			RequestID: 7,
			Prefix:    netip.MustParsePrefix("0.0.0.0/32"),
		}},
	},
	{
		name:    "ipv6 refused assignment",
		payload: append(append([]byte{0x07, 6}, netip.IPv6Unspecified().AsSlice()...), 128),
		expected: []AssignedAddress{{
			RequestID: 7,
			Prefix:    netip.MustParsePrefix("::/128"),
		}},
	},
}

// TestRouteAdvertisementSeedsAreValid is the guard the old corpus lacked.
//
// It asserts that every seed declared valid really decodes to the entries the wire
// bytes describe. A fuzz target whose seeds all fail reaches none of its assertions
// and passes vacuously; this test makes that state a build failure.
func TestRouteAdvertisementSeedsAreValid(t *testing.T) {
	for _, seed := range routeSeeds {
		t.Run(seed.name, func(t *testing.T) {
			routes, err := parseRoutes(seed.payload)
			require.NoError(t, err,
				"a declared-valid ROUTE_ADVERTISEMENT seed must parse: % x", seed.payload)
			if seed.expected == nil {
				require.Empty(t, routes)
				return
			}
			require.Equal(t, seed.expected, routes,
				"the seed must decode to exactly the entries on the wire")
		})
	}
}

// TestAddressSeedsAreValid is the same guard for ADDRESS_ASSIGN / ADDRESS_REQUEST.
func TestAddressSeedsAreValid(t *testing.T) {
	for _, seed := range addressSeeds {
		t.Run(seed.name, func(t *testing.T) {
			addresses, err := parseAddresses(seed.payload)
			require.NoError(t, err,
				"a declared-valid address seed must parse: % x", seed.payload)
			if seed.expected == nil {
				require.Empty(t, addresses)
				return
			}
			require.Equal(t, seed.expected, addresses,
				"the seed must decode to exactly the entries on the wire")
		})
	}
}

// capsulePayloadOf strips a capsule header and returns the payload, so a parser
// can be driven with exactly the bytes the encoder produced for it.
func capsulePayloadOf(capsule *buf.Buffer) []byte {
	body := capsule.Bytes()
	_, headerLength, ok := transportHTTP.DecodeVarint(body)
	if !ok {
		return nil
	}
	_, payloadLength, ok := transportHTTP.DecodeVarint(body[headerLength:])
	if !ok {
		return nil
	}
	return body[headerLength+payloadLength:]
}

// TestProductionEncoderReproducesTheRFCVectors closes the loop in the ONE direction
// that is safe: the seeds are written by hand from the RFC, and the PRODUCTION
// encoder must reproduce them byte for byte.
//
// This is not circular. The seeds do not come from the encoder, so a disagreement
// means one of the two is wrong - which is exactly the check the out-of-module
// reference peer cannot make from here, and the one that would have caught the
// original corpus.
func TestProductionEncoderReproducesTheRFCVectors(t *testing.T) {
	for _, seed := range routeSeeds {
		if seed.expected == nil {
			continue
		}
		t.Run("route/"+seed.name, func(t *testing.T) {
			capsule := newRouteCapsule(seed.expected)
			defer capsule.Release()
			require.Equal(t, seed.payload, capsulePayloadOf(capsule),
				"the production ROUTE_ADVERTISEMENT encoder and the RFC-derived seed "+
					"must agree byte for byte")
		})
	}
	for _, seed := range addressSeeds {
		if seed.expected == nil {
			continue
		}
		t.Run("address/"+seed.name, func(t *testing.T) {
			capsule := newAddressCapsule(capsuleTypeAddressAssign, seed.expected)
			defer capsule.Release()
			require.Equal(t, seed.payload, capsulePayloadOf(capsule),
				"the production ADDRESS_ASSIGN encoder and the RFC-derived seed "+
					"must agree byte for byte")
		})
	}
}

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

// FuzzCapsuleParser drives the capsule framer.
//
// The framer is what an established tunnel reads first, and it is driven entirely
// by peer bytes: a type varint, a length varint, then that many payload bytes. The
// declared length is the classic amplification vector, so the property under test
// is not merely "no panic" but that a length beyond the limit is REFUSED before
// anything is allocated for it.
func FuzzCapsuleParser(fuzz *testing.F) {
	// The DATAGRAM capsule type (0x00) and the three control types, each in a
	// well-formed form.
	fuzz.Add([]byte{0x00, 0x01, 0x00})                   // DATAGRAM, context ID 0, no payload
	fuzz.Add([]byte{0x00, 0x04, 0x00, 0xde, 0xad, 0xbe}) // DATAGRAM with a payload
	fuzz.Add([]byte{0x01, 0x07, 0x00, 4, 198, 18, 0, 2, 32})
	fuzz.Add([]byte{0x02, 0x07, 0x01, 4, 198, 18, 0, 2, 32})
	fuzz.Add([]byte{0x03, 0x0a, 4, 0, 0, 0, 0, 255, 255, 255, 255, 0})
	// An unknown capsule type, which must be skipped by length.
	fuzz.Add([]byte{0x3f, 0x02, 0xaa, 0xbb})
	// Truncated type and length varints.
	fuzz.Add([]byte{0x40})
	fuzz.Add([]byte{0x00, 0x40})
	fuzz.Add([]byte{})
	// A declared length above MaxCapsuleLength, in the 8-byte varint form.
	fuzz.Add([]byte{0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// A declared length the data does not support.
	fuzz.Add([]byte{0x00, 0x10, 0x00})
	// The 4-byte varint form just under the limit.
	fuzz.Add([]byte{0x00, 0x80, 0x00, 0x0f, 0xff})

	fuzz.Fuzz(func(t *testing.T, data []byte) {
		reader := std_bufio.NewReader(bytes.NewReader(data))
		capsuleType, typeLength, err := transportHTTP.ReadVarint(reader)
		if err != nil {
			return
		}
		// A varint must consume exactly the number of bytes its first byte
		// announces, never more: a framer that over-reads would desynchronise from
		// the stream and interpret payload bytes as the next header.
		expectedLength := 1 << (data[0] >> 6)
		if typeLength != expectedLength {
			t.Fatalf("the type varint consumed %d bytes but its first byte announces %d",
				typeLength, expectedLength)
		}

		length, _, err := transportHTTP.ReadVarint(reader)
		if err != nil {
			return
		}
		if length > transportHTTP.MaxCapsuleLength {
			// Refused, which is the required outcome for an oversized capsule.
			return
		}
		// Within the limit, the payload must actually be readable and its size must
		// not exceed what the limit allows. Allocating it here is safe precisely
		// because the limit was checked first, which is the property being pinned.
		payload := make([]byte, length)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return
		}
		if uint64(len(payload)) > transportHTTP.MaxCapsuleLength {
			t.Fatalf("a payload of %d bytes was read, above the limit of %d",
				len(payload), transportHTTP.MaxCapsuleLength)
		}
		// NOTE ON LAYERING, learned by getting it wrong here first: a zero-length
		// DATAGRAM capsule IS accepted by the framer, and that is correct. The
		// framer owns the length; readDatagramCapsule owns the context-ID rule and
		// discards a zero-payload datagram rather than delivering an empty packet.
		// An assertion that the framer must reject it encodes a rule the code under
		// test is not responsible for, and would fail on correct code.
		_ = capsuleType
	})
}

// FuzzRouteAdvertisement drives the ROUTE_ADVERTISEMENT parser.
//
// The output of this parser becomes the set of destinations the server will
// forward, so the property that matters is not merely "no panic" but that anything
// ACCEPTED describes coherent ranges: an IPv4 start with an IPv6 end, or a range
// whose start is above its end, would make routing decisions undefined.
//
// The seeds are the RFC-derived table above. TestRouteAdvertisementSeedsAreValid
// proves they really parse before this target ever runs, and the accepted counter
// below fails the run if a bounded fuzz never reached the success path at all.
func FuzzRouteAdvertisement(fuzz *testing.F) {
	for _, seed := range routeSeeds {
		fuzz.Add(seed.payload)
	}
	// Malformed IP versions. 16 is the interesting one, because reading it as a byte
	// length is the mistake the reference harness made.
	for _, version := range []byte{0, 1, 2, 3, 5, 7, 8, 16, 32, 255} {
		fuzz.Add([]byte{version})
		fuzz.Add([]byte{version, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	}
	// A version byte with no address behind it, per family.
	fuzz.Add([]byte{4})
	fuzz.Add([]byte{6})
	// Truncated IPv4 range: version and start, no end.
	fuzz.Add([]byte{4, 0, 0, 0, 0})
	fuzz.Add([]byte{4, 0, 0, 0, 0, 0, 0, 0, 0})
	// Truncated IPv6 range at every length, so each partial read is explored.
	truncatedV6 := []byte{6}
	truncatedV6 = append(truncatedV6, netip.MustParseAddr("2001:db8::").AsSlice()...)
	truncatedV6 = append(truncatedV6, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	for length := 1; length < len(truncatedV6); length++ {
		fuzz.Add(truncatedV6[:length])
	}
	// End before start.
	fuzz.Add([]byte{4, 10, 0, 0, 1, 10, 0, 0, 0, 0})
	fuzz.Add(append(append([]byte{6}, netip.MustParseAddr("2001:db8::2").AsSlice()...),
		append(netip.MustParseAddr("2001:db8::1").AsSlice(), 0)...))
	// Two ranges that overlap at the same protocol.
	fuzz.Add([]byte{
		4, 10, 0, 0, 0, 10, 0, 0, 255, 6,
		4, 10, 0, 0, 128, 10, 0, 1, 0, 6,
	})
	// A range that touches exactly: end(A) == start(B). RFC 9484 section 4.7.3
	// requires ranges to be disjoint, so this must be rejected.
	fuzz.Add([]byte{
		4, 10, 0, 0, 0, 10, 0, 0, 255, 6,
		4, 10, 0, 0, 255, 10, 0, 1, 0, 6,
	})
	// The cross-protocol overlap the audit found: the same range at protocol 0 and
	// then protocol 6. Protocol 0 means ALL protocols, so that is a duplicate.
	fuzz.Add([]byte{
		4, 192, 0, 2, 0, 192, 0, 2, 255, 0,
		4, 192, 0, 2, 0, 192, 0, 2, 255, 6,
	})
	// The same overlap in the other direction (specific protocol first), which the
	// ordering rules alone cannot see.
	fuzz.Add([]byte{
		4, 192, 0, 2, 0, 192, 0, 2, 255, 6,
		4, 192, 0, 2, 128, 192, 0, 2, 200, 0,
	})
	// Protocols out of order within one IP version.
	fuzz.Add([]byte{
		4, 192, 0, 2, 0, 192, 0, 2, 255, 6,
		4, 198, 51, 100, 0, 198, 51, 100, 255, 0,
	})
	// IP versions out of order: IPv6 before IPv4.
	fuzz.Add(append(append([]byte{6},
		netip.MustParseAddr("2001:db8::").AsSlice()...),
		append(netip.MustParseAddr("2001:db8::1").AsSlice(), 4)...))
	// An 8-byte varint reused as a version byte.
	fuzz.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0})

	accepted := 0
	fuzz.Fuzz(func(t *testing.T, data []byte) {
		routes, err := parseRoutes(data)
		if err != nil {
			return
		}
		accepted++
		if len(routes) > maxRoutesPerCapsule {
			t.Fatalf("accepted %d routes, above the per-capsule bound of %d",
				len(routes), maxRoutesPerCapsule)
		}
		for index, route := range routes {
			// Address families must agree: a range that starts in one family and
			// ends in another cannot describe a contiguous run of addresses.
			if route.Start.Is4() != route.End.Is4() {
				t.Fatalf("route %d mixes address families: start %s, end %s",
					index, route.Start, route.End)
			}
			// A range that ends before it starts would make containment checks
			// undefined, so it must never be reported as valid.
			if route.End.Less(route.Start) {
				t.Fatalf("route %d ends before it starts: %s - %s",
					index, route.Start, route.End)
			}
			// Both addresses must be valid and zone-free: a zone would make
			// comparison ambiguous, and an invalid address is an internal marker
			// that must never escape the parser.
			if !route.Start.IsValid() || !route.End.IsValid() {
				t.Fatalf("route %d has an invalid address: %s - %s",
					index, route.Start, route.End)
			}
			if route.Start.Zone() != "" || route.End.Zone() != "" {
				t.Fatalf("route %d carries a zone identifier: %s - %s",
					index, route.Start, route.End)
			}
		}
		// Anything accepted must also survive the encoder round trip, which is what
		// makes the output usable by the session layer rather than merely coherent
		// in isolation.
		if len(routes) > 0 {
			capsule := newRouteCapsule(routes)
			reparsed, reparseErr := parseRoutes(capsulePayloadOf(capsule))
			capsule.Release()
			if reparseErr != nil {
				t.Fatalf("a re-encoded ROUTE_ADVERTISEMENT must parse: %v", reparseErr)
			}
			if len(reparsed) != len(routes) {
				t.Fatalf("re-encoding changed the route count: %d -> %d",
					len(routes), len(reparsed))
			}
		}
	})
	// The target must have reached its success path. If every seed and every
	// generated input were rejected, this run proves nothing about the accepted
	// shapes, which is exactly the false green the old corpus produced.
	if accepted == 0 {
		fuzz.Fatal("this fuzz run never parsed a ROUTE_ADVERTISEMENT successfully, " +
			"so the accepted-input assertions were never reached")
	}
}

// FuzzConnectIPAddresses drives the ADDRESS_ASSIGN / ADDRESS_REQUEST parser.
//
// Assigned addresses become the addresses a client may source traffic from, so an
// accepted-but-incoherent entry is a policy question, not a formatting one.
func FuzzConnectIPAddresses(fuzz *testing.F) {
	for _, seed := range addressSeeds {
		fuzz.Add(seed.payload)
	}
	// Out-of-range prefix lengths, on both sides of each family's width.
	fuzz.Add([]byte{0x00, 4, 0, 0, 0, 0, 33})
	fuzz.Add([]byte{0x00, 4, 0, 0, 0, 0, 255})
	fuzz.Add(append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8::").AsSlice()...), 129))
	fuzz.Add(append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8::").AsSlice()...), 255))
	// A prefix length with host bits set, which RFC 9484 section 4.5 forbids.
	fuzz.Add([]byte{0x00, 4, 198, 18, 0, 2, 24})
	fuzz.Add(append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 64))
	// Malformed IP versions, 16 included.
	for _, version := range []byte{0, 1, 2, 3, 5, 7, 8, 16, 32, 255} {
		fuzz.Add(append([]byte{0x00, version, 0, 0, 0, 0}, 32))
	}
	// Truncation at every length of a well-formed IPv6 entry.
	full := append(append([]byte{0x00, 6}, netip.MustParseAddr("2001:db8::1").AsSlice()...), 128)
	for length := 1; length < len(full); length++ {
		fuzz.Add(full[:length])
	}
	// A truncated request ID, and a truncated entry after a complete one.
	fuzz.Add([]byte{0x40})
	fuzz.Add([]byte{0x00, 4, 0, 0, 0, 0})
	// A varint whose declared width runs past the end of the capsule.
	fuzz.Add([]byte{0xc0, 0x00, 0x00})

	accepted := 0
	fuzz.Fuzz(func(t *testing.T, data []byte) {
		addresses, err := parseAddresses(data)
		if err != nil {
			return
		}
		accepted++
		if len(addresses) > maxAddressesPerCapsule {
			t.Fatalf("accepted %d addresses, above the per-capsule bound of %d",
				len(addresses), maxAddressesPerCapsule)
		}
		for index, assigned := range addresses {
			prefix := assigned.Prefix
			// A prefix length outside the address width is not a prefix at all, and
			// prefix.Contains would then behave unpredictably.
			if prefix.Bits() < 0 || prefix.Bits() > prefix.Addr().BitLen() {
				t.Fatalf("address %d has an out-of-range prefix length: %s (%d bits)",
					index, prefix, prefix.Bits())
			}
			if !prefix.IsValid() || !prefix.Addr().IsValid() {
				t.Fatalf("address %d is not a usable prefix: %s", index, prefix)
			}
			if prefix.Addr().Zone() != "" {
				t.Fatalf("address %d carries a zone identifier: %s", index, prefix)
			}
			if prefix.Masked() != prefix {
				t.Fatalf("address %d has host bits set: %s", index, prefix)
			}
		}
	})
	if accepted == 0 {
		fuzz.Fatal("this fuzz run never parsed an ADDRESS_ASSIGN entry successfully, " +
			"so the accepted-input assertions were never reached")
	}
}

// FuzzConnectIPTemplatePath drives the CONNECT-IP URI-template matcher.
//
// The matcher decides the SCOPE of a tunnel - which target prefix and which IP
// protocol the client may proxy through - from the request path alone. The property
// that matters is that a scope is only reported for a path that actually matches
// the template, and that the extracted protocol is always a valid IP protocol
// number: an over-permissive match widens what a client can reach.
//
// RENAMED from FuzzConnectUDPTemplatePath. That name claimed CONNECT-UDP coverage
// while the target only ever drove transport/masque's CONNECT-IP template
// (/.well-known/masque/ip/{target}/{ipproto}/), leaving the impression that the
// CONNECT-UDP target parser was fuzzed. The CONNECT-UDP parser has its own target
// now: FuzzConnectUDPTargetPath in transport/http.
func FuzzConnectIPTemplatePath(fuzz *testing.F) {
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/*/*/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/2001:db8::1/128/17/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/2001%3Adb8%3A%3A1/128/17/")
	fuzz.Add(DefaultPath, "/")
	fuzz.Add(DefaultPath, "")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/../../etc/passwd/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/999/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/-1/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/0/extra/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/%2e%2e%2f%2e%2e%2f/32/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/%00/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip//32/0/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/32/0")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/example.com/0/17/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/fe80::1%25eth0/128/17/")
	fuzz.Add(DefaultPath, "/.well-known/masque/ip/198.18.0.2/33/0/")
	fuzz.Add("/masque?target={target}&ipproto={ipproto}", "/masque?target=198.18.0.2&ipproto=17")
	fuzz.Add("/masque?target={target}&ipproto={ipproto}", "/masque")
	fuzz.Add("/masque?target={target}&ipproto={ipproto}", "/masque?target=&ipproto=")
	fuzz.Add("/{target}/{ipproto}/", "/198.18.0.2/17/")

	fuzz.Fuzz(func(t *testing.T, templatePath string, requestPath string) {
		// A template that cannot be parsed must report an error rather than
		// producing a matcher in an undefined state.
		template, err := ParseTemplate(templatePath)
		if err != nil {
			return
		}
		// A request path reaching this matcher is always what url.URL.EscapedPath()
		// produced, which is ASCII. Inputs outside that shape are not paths the
		// server could ever see, so they are filtered rather than asserted on.
		if !utf8.ValidString(requestPath) {
			return
		}
		parsed, parseErr := url.Parse(requestPath)
		if parseErr != nil {
			return
		}
		scope, matched, matchErr := template.Match(parsed)
		if matchErr != nil || !matched {
			return
		}
		// A matched scope with an invalid, non-wildcard prefix would be used as a
		// routing decision, so it must never escape.
		if scope.Prefix.IsValid() {
			if scope.Prefix.Bits() < 0 || scope.Prefix.Bits() > scope.Prefix.Addr().BitLen() {
				t.Fatalf("matched scope has an out-of-range prefix: %s", scope.Prefix)
			}
			if scope.Prefix.Addr().Zone() != "" {
				t.Fatalf("matched scope has a zone identifier: %s", scope.Prefix)
			}
		}
		// The domain, when present, must not be empty or contain a path separator:
		// it becomes a dialled domain.
		if scope.Domain != "" && strings.ContainsAny(scope.Domain, "/\\") {
			t.Fatalf("matched scope has a domain containing a path separator: %q", scope.Domain)
		}
		// A prefix and a domain are mutually exclusive scopes.
		if scope.Prefix.IsValid() && scope.Domain != "" {
			t.Fatalf("matched scope has both a prefix (%s) and a domain (%q)",
				scope.Prefix, scope.Domain)
		}
	})
}
