package reference_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// IPv6 control-capsule wire format in the reference harness.
//
// This file exists because the harness decoder was WRONG for IPv6 and the bug
// was invisible for IPv4. RFC 9484 sections 4.5 / 4.6 / 4.7 open every address
// with a one-byte IP Version whose only legal values are 4 and 6:
//
//	4 means IPv4, and the address that follows is 4 bytes;
//	6 means IPv6, and the address that follows is 16 bytes.
//
// An earlier version of parseAddress / parseAddressWithLength in
// capsule_peer_test.go read that byte as a BYTE LENGTH (4 -> 4 bytes, 16 -> 16
// bytes). IPv4 therefore appeared to work by coincidence -- 4 is both the
// version marker and the IPv4 byte length -- while IPv6 decoded 6 address bytes
// and then misread the rest of the entry. Any IPv6 control capsule the server
// sent was reported as a parse failure.
//
// Nothing here calls the production encoder (transport/masque/capsule.go
// appendAddress). The vectors below are written out byte by byte from the RFC
// and cross-checked against quic-go/connect-ip-go's own writer, which emits
// `byte(4)` / `byte(6)` and then AsSlice(). Generating the "expected" bytes with
// the implementation under test would let production and test be wrong together,
// which is the whole failure mode a reference peer exists to catch.

// The vectors below are the exact bytes connect-ip-go's
// (*addressAssignCapsule).append / (*routeAdvertisementCapsule).append produce
// for the same inputs. They were derived from the reference source
// (capsule.go, pinned at fdd945e3d6009b3cee1b1a66493776d315727549), not from
// sing-box.

// TestReferenceHarnessDecodesIPv6AddressAssign proves the harness reads a real
// IPv6 ADDRESS_ASSIGN payload.
func TestReferenceHarnessDecodesIPv6AddressAssign(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	payload := []byte{0x00}      // Request ID 0: an unsolicited assignment.
	payload = append(payload, 6) // IP Version 6, NOT a byte length.
	payload = append(payload, ipv6.AsSlice()...)
	payload = append(payload, 128) // Prefix Length 128.

	prefix, ok := parseAddressAssign(payload)
	require.True(t, ok, "an IPv6 ADDRESS_ASSIGN entry must parse: % x", payload)
	require.True(t, prefix.IsValid())
	require.Equal(t, netip.PrefixFrom(ipv6, 128), prefix,
		"the decoded prefix must be the one on the wire; reading the version byte "+
			"as a byte length consumes 6 address bytes and misaligns the entry")
}

// TestReferenceHarnessDecodesIPv6AddressAssignWithNonzeroRequestID covers the
// ADDRESS_ASSIGN answer shape, where the Request ID is the client's.
func TestReferenceHarnessDecodesIPv6AddressAssignWithNonzeroRequestID(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8:1:2:3:4:5:6")
	payload := []byte{0x40, 0x2a} // Request ID 42 (two-byte varint).
	payload = append(payload, 6)
	payload = append(payload, ipv6.AsSlice()...)
	payload = append(payload, 64) // A /64 with no host bits set.

	prefix, ok := parseAddressAssign(payload)
	require.True(t, ok, "an IPv6 ADDRESS_ASSIGN with a request ID must parse: % x", payload)
	require.Equal(t, netip.PrefixFrom(ipv6, 64), prefix)
}

// TestReferenceHarnessDecodesIPv6RouteAdvertisement proves the route decoder
// reads IPv6 start and end addresses.
//
// The asymmetry matters: only the START address carries a version byte. The end
// address is raw, because it is guaranteed to be the same family. A decoder that
// expects a version byte before the end address consumes one address byte and
// shifts the protocol, which is the second half of the same bug.
func TestReferenceHarnessDecodesIPv6RouteAdvertisement(t *testing.T) {
	start := netip.MustParseAddr("2001:db8::")
	end := netip.MustParseAddr("2001:db8::ffff")
	payload := []byte{6}
	payload = append(payload, start.AsSlice()...)
	payload = append(payload, end.AsSlice()...)
	payload = append(payload, 17) // UDP.

	routes, ok := parseRouteAdvertisement(payload)
	require.True(t, ok, "an IPv6 ROUTE_ADVERTISEMENT entry must parse: % x", payload)
	require.Len(t, routes, 1)
	require.Equal(t, start, routes[0].StartIP)
	require.Equal(t, end, routes[0].EndIP)
	require.Equal(t, uint8(17), routes[0].IPProtocol)
}

// TestReferenceHarnessDecodesMixedFamilyRouteAdvertisement pins the
// version-ascending order RFC 9484 section 4.7.3 requires: every IPv4 range
// precedes every IPv6 range.
func TestReferenceHarnessDecodesMixedFamilyRouteAdvertisement(t *testing.T) {
	v4Start := netip.MustParseAddr("198.18.0.0")
	v4End := netip.MustParseAddr("198.18.0.255")
	v6Start := netip.MustParseAddr("2001:db8::")
	v6End := netip.MustParseAddr("2001:db8::ffff")

	payload := []byte{4}
	payload = append(payload, v4Start.AsSlice()...)
	payload = append(payload, v4End.AsSlice()...)
	payload = append(payload, 0)
	payload = append(payload, 6)
	payload = append(payload, v6Start.AsSlice()...)
	payload = append(payload, v6End.AsSlice()...)
	payload = append(payload, 0)

	routes, ok := parseRouteAdvertisement(payload)
	require.True(t, ok, "a mixed-family ROUTE_ADVERTISEMENT must parse: % x", payload)
	require.Len(t, routes, 2)
	require.Equal(t, v4Start, routes[0].StartIP)
	require.Equal(t, v4End, routes[0].EndIP)
	require.Equal(t, v6Start, routes[1].StartIP)
	require.Equal(t, v6End, routes[1].EndIP)
}

// TestReferenceHarnessRejectsInvalidIPVersion is the negative half. The version
// byte is not a byte length, so 16 must be REFUSED even though it is a plausible
// length: the only legal values are 4 and 6.
//
// This is the assertion that distinguishes the two readings. A decoder that
// treats the byte as a length accepts 16 happily; a decoder that treats it as an
// IP version rejects it.
func TestReferenceHarnessRejectsInvalidIPVersion(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")

	byteLengthReading := []byte{0x00, 16}
	byteLengthReading = append(byteLengthReading, ipv6.AsSlice()...)
	byteLengthReading = append(byteLengthReading, 128)

	_, ok := parseAddressAssign(byteLengthReading)
	require.False(t, ok,
		"16 is not a legal IP Version. Accepting it means the decoder is still "+
			"reading the first byte as a byte length, which is the bug this file "+
			"exists to lock out. Payload: % x", byteLengthReading)

	for _, version := range []byte{0, 1, 5, 7, 8, 255} {
		payload := []byte{0x00, version}
		payload = append(payload, ipv6.AsSlice()...)
		payload = append(payload, 128)
		_, accepted := parseAddressAssign(payload)
		require.False(t, accepted, "IP Version %d must be refused", version)
	}
}

// TestReferenceHarnessRejectsTruncatedIPv6Entry locks out a decoder that reads
// fewer bytes than the version promises and then succeeds on the remainder.
func TestReferenceHarnessRejectsTruncatedIPv6Entry(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	full := []byte{0x00, 6}
	full = append(full, ipv6.AsSlice()...)
	full = append(full, 128)

	for length := 2; length < len(full); length++ {
		_, ok := parseAddressAssign(full[:length])
		require.False(t, ok,
			"a %d-byte prefix of a %d-byte IPv6 entry must not parse",
			length, len(full))
	}
}
