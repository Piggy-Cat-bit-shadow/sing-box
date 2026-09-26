package reference_test

import (
	"io"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/stretchr/testify/require"
)

// HTTP Datagram capsule framing, reimplemented locally.
//
// RFC 9297 section 3.5 defines a DATAGRAM capsule as type 0x00 followed by a
// varint length and then the datagram payload, whose first field is a varint
// context ID. The reference module cannot import sing-box's capsule package
// (that would defeat the point of testing against an independent peer), so the
// framing is written out here from the RFC.
//
// Writing it independently is a feature rather than duplication: if this file and
// sing-box disagreed about the framing, the interop test would fail, which is
// exactly the class of error an external peer exists to catch.

const (
	// capsuleTypeDatagram is the DATAGRAM capsule type (RFC 9297 section 3.5).
	capsuleTypeDatagram = 0x00
	// capsuleTypeAddressAssign is ADDRESS_ASSIGN (RFC 9484 section 4.5).
	capsuleTypeAddressAssign = 0x01
	// capsuleTypeRouteAdvertisement is ROUTE_ADVERTISEMENT (RFC 9484 section 4.7).
	capsuleTypeRouteAdvertisement = 0x03
)

// putVarint appends a QUIC varint (RFC 9000 section 16).
func putVarint(buffer []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(buffer, byte(value))
	case value < 1<<14:
		return append(buffer, byte(0x40|(value>>8)), byte(value))
	case value < 1<<30:
		return append(buffer, byte(0x80|(value>>24)), byte(value>>16), byte(value>>8), byte(value))
	default:
		return append(buffer, byte(0xc0|(value>>56)), byte(value>>48), byte(value>>40),
			byte(value>>32), byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
}

// readVarint reads a QUIC varint from a stream, returning the value and how many
// bytes it occupied.
func readVarint(reader io.Reader) (uint64, int, error) {
	var first [1]byte
	if _, err := io.ReadFull(reader, first[:]); err != nil {
		return 0, 0, err
	}
	length := 1 << (first[0] >> 6)
	value := uint64(first[0] & 0x3f)
	for index := 1; index < length; index++ {
		var next [1]byte
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			return 0, 0, err
		}
		value = value<<8 | uint64(next[0])
	}
	return value, length, nil
}

// writeDatagramCapsuleToStream writes one DATAGRAM capsule carrying an IP packet
// under context ID 0.
func writeDatagramCapsuleToStream(writer io.Writer, packet []byte) error {
	// Payload is the context ID (0, one byte) followed by the packet.
	payloadLength := 1 + len(packet)
	capsule := []byte{capsuleTypeDatagram}
	capsule = putVarint(capsule, uint64(payloadLength))
	capsule = append(capsule, 0x00) // context ID 0
	capsule = append(capsule, packet...)
	_, err := writer.Write(capsule)
	return err
}

// readDatagramCapsule reads one DATAGRAM capsule and returns its payload with the
// context ID removed.
//
// Control capsules are skipped rather than treated as errors, because the server
// may interleave an ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT with data. The caller
// has usually consumed those already, but the stream is a single ordered byte
// stream, so a robust reader must tolerate whatever order the peer chose.
func readDatagramCapsule(reader io.Reader) ([]byte, error) {
	for {
		capsuleType, _, err := readVarint(reader)
		if err != nil {
			return nil, err
		}
		length, _, err := readVarint(reader)
		if err != nil {
			return nil, err
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		if capsuleType != capsuleTypeDatagram {
			// A control capsule: consumed, not data.
			continue
		}
		contextID, contextLength, ok := decodeVarint(payload)
		if !ok || contextID != 0 || len(payload) == contextLength {
			// An unknown or empty datagram is dropped rather than fatal, which is
			// what RFC 9297 requires of a receiver.
			continue
		}
		return payload[contextLength:], nil
	}
}

// decodeVarint decodes a varint from a byte slice.
func decodeVarint(data []byte) (uint64, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	length := 1 << (data[0] >> 6)
	if len(data) < length {
		return 0, 0, false
	}
	value := uint64(data[0] & 0x3f)
	for index := 1; index < length; index++ {
		value = value<<8 | uint64(data[index])
	}
	return value, length, true
}

// readDatagramCapsuleWithTimeout reads one data capsule with a watchdog, because
// a blocked stream read has no deadline of its own.
//
// A timeout is reported as a test failure rather than an empty result: nothing
// arriving is precisely the symptom of the missing fallback, so it must be
// distinguishable from a capsule that arrived empty.
func readDatagramCapsuleWithTimeout(t *testing.T, reader io.Reader, timeout time.Duration) []byte {
	t.Helper()
	type result struct {
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		payload, err := readDatagramCapsule(reader)
		done <- result{payload, err}
	}()
	select {
	case received := <-done:
		require.NoError(t, received.err,
			"the server must answer a non-datagram CONNECT-IP peer with a "+
				"DATAGRAM capsule on the request stream")
		return received.payload
	case <-time.After(timeout):
		t.Fatal("no DATAGRAM capsule arrived: the server did not fall back to the " +
			"stream capsule path for a peer without datagram support, and the " +
			"tunnel produced nothing")
		return nil
	}
}

// readControlCapsule reads exactly one capsule and returns its type and payload.
//
// This is the single primitive the peers below are built from. Control capsules
// arrive on the SAME ordered byte stream as data capsules, so every reader in this
// file must consume precisely one capsule at a time and never leave a background
// goroutine holding the stream: a stray reader competes with the data path for the
// same bytes, which is the same class of mistake as the production bug this file
// was written alongside.
func readControlCapsule(reader io.Reader) (uint64, []byte, error) {
	capsuleType, _, err := readVarint(reader)
	if err != nil {
		return 0, nil, err
	}
	length, _, err := readVarint(reader)
	if err != nil {
		return 0, nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return capsuleType, payload, nil
}

// readAddressAssignmentAndRoutes reads the two control capsules a CONNECT-IP
// server sends when it accepts a tunnel.
//
// It reads SYNCHRONOUSLY and exactly twice, which is what the server sends and in
// what order. An earlier version of this helper ran a reader goroutine that looped
// until it had seen both capsule types and gave up after a wall-clock deadline;
// that was wrong in a way worth recording, because the symptom (a 20s timeout) said
// nothing about the cause:
//
//   - the goroutine held the stream while the test later tried to read data from
//     it, so the two competed for the same bytes;
//   - it required ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT to BOTH be parsed before
//     it would report anything, so a single parse failure turned into "nothing
//     arrived" rather than naming the capsule that failed.
//
// Reading a fixed number of capsules in order removes both problems and makes a
// failure point at the capsule it happened on.
func readAddressAssignmentAndRoutes(t *testing.T, reader io.Reader) (netip.Prefix, []connectip.IPRoute) {
	t.Helper()

	firstType, firstPayload, err := readControlCapsule(reader)
	require.NoError(t, err, "the server must send its first control capsule")
	require.Equal(t, uint64(capsuleTypeAddressAssign), firstType,
		"the first control capsule must be ADDRESS_ASSIGN (RFC 9484 section 4.5)")

	assigned, ok := parseAddressAssign(firstPayload)
	require.True(t, ok, "the ADDRESS_ASSIGN payload must parse: % x", firstPayload)
	require.True(t, assigned.IsValid())

	secondType, secondPayload, err := readControlCapsule(reader)
	require.NoError(t, err, "the server must send ROUTE_ADVERTISEMENT after "+
		"ADDRESS_ASSIGN")
	require.Equal(t, uint64(capsuleTypeRouteAdvertisement), secondType,
		"the second control capsule must be ROUTE_ADVERTISEMENT (RFC 9484 "+
			"section 4.7); measured order on this endpoint")

	routes, ok := parseRouteAdvertisement(secondPayload)
	require.True(t, ok, "the ROUTE_ADVERTISEMENT payload must parse: % x", secondPayload)

	return assigned, routes
}

// parseAddressAssign decodes the first entry of an ADDRESS_ASSIGN payload.
//
// RFC 9484 section 4.5 defines the payload as a REPEATED sequence of entries, each
//
//	Request ID (varint)
//	IP Version (one byte, 4 or 6)
//	IP Address (4 bytes for version 4, 16 bytes for version 6)
//	IP Prefix Length (one byte)
//
// with no leading count field. A single assignment of 198.18.0.2/32 arrives as
//
//	00                request ID 0 (unsolicited assignment)
//	04 c6 12 00 02    IP Version 4, then the 4 address bytes
//	20                prefix length 32
//
// and a single assignment of 2001:db8::1/128 arrives as
//
//	00                request ID 0
//	06 2001:0db8::1   IP Version 6, then the 16 address bytes
//	80                prefix length 128
//
// CORRECTED: the byte before the address is the IP VERSION and is not a byte
// length. An earlier version of this decoder read it as a byte count (4 -> 4
// bytes, 16 -> 16 bytes). That looked correct for IPv4, because 4 is both the
// version marker and the IPv4 byte length, and was wrong for IPv6, where it
// consumed 6 address bytes and misaligned the prefix length and every following
// entry. Nothing caught it because every control-capsule fixture in this module was
// IPv4.
//
// control_capsule_wire_test.go locks the correction in with vectors written byte by
// byte from the RFC and cross-checked against connect-ip-go's own writer. They
// never call the production encoder, so the harness and the implementation cannot
// be wrong together, which is the only way this class of mistake stays caught.
func parseAddressAssign(payload []byte) (netip.Prefix, bool) {
	// Request ID first, ignored: an unsolicited assignment carries zero.
	if _, n, ok := decodeVarint(payload); ok {
		payload = payload[n:]
	} else {
		return netip.Prefix{}, false
	}
	return parseAssignedPrefix(payload)
}

// parseAssignedPrefix reads an IP address followed by a one-byte prefix length.
func parseAssignedPrefix(payload []byte) (netip.Prefix, bool) {
	if len(payload) < 2 {
		return netip.Prefix{}, false
	}
	address, n, ok := parseAddress(payload)
	if !ok {
		return netip.Prefix{}, false
	}
	payload = payload[n:]
	if len(payload) == 0 {
		return netip.Prefix{}, false
	}
	bits := int(payload[0])
	if bits < 0 || bits > address.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, bits), true
}

// parseAddress reads one IP-version-prefixed address and reports how many bytes
// it consumed.
//
// The byte before the address is the IP VERSION, whose only legal values are 4 and
// 6; the address length follows from it. It is NOT a byte length. See
// parseAddressAssign for the correction history.
func parseAddress(payload []byte) (netip.Addr, int, bool) {
	address, _, consumed, ok := parseVersionedAddress(payload)
	return address, consumed, ok
}

// parseVersionedAddress is the single decoder the address and route parsers share,
// so the IP Version rule is stated exactly once, and reports the address BYTE
// length as well as the bytes consumed.
//
// A zero version byte is refused: no IP Version is 0. The list forms in RFC 9484
// that use 0 as "any address" are capsule-type 0x04 entries, which this suite does
// not decode, so accepting 0 here would invent a wire shape the RFC does not have
// and would let a misaligned buffer decode as something plausible.
func parseVersionedAddress(payload []byte) (netip.Addr, int, int, bool) {
	if len(payload) == 0 {
		return netip.Addr{}, 0, 0, false
	}
	byteLength, valid := addressByteLength(payload[0])
	if !valid {
		// Any other value, 16 included, is not an IP Version.
		return netip.Addr{}, 0, 0, false
	}
	if len(payload) < 1+byteLength {
		return netip.Addr{}, 0, 0, false
	}
	switch byteLength {
	case 4:
		return netip.AddrFrom4([4]byte(payload[1:5])), 4, 5, true
	default:
		return netip.AddrFrom16([16]byte(payload[1:17])), 16, 17, true
	}
}

// addressByteLength maps an IP Version byte to the address length that follows it.
func addressByteLength(version byte) (int, bool) {
	switch version {
	case 4:
		return 4, true
	case 6:
		return 16, true
	default:
		return 0, false
	}
}

// parseRouteAdvertisement decodes a ROUTE_ADVERTISEMENT payload.
//
// RFC 9484 section 4.7 defines the payload as a REPEATED sequence of entries, each
//
//	IP Version (one byte, 4 or 6)
//	Start IP Address (4 or 16 bytes, by version)
//	End IP Address (same width, RAW - no version byte of its own)
//	IP Protocol (one byte)
//
// so an endpoint advertising 0.0.0.0/0 with protocol 0 sends ten bytes:
//
//	04 00 00 00 00    start: IP Version 4, then four address bytes
//	ff ff ff ff       end:   four address bytes, NO version byte
//	00                IP protocol 0 (all protocols)
//
// The asymmetry is the part that is easy to get wrong, and both halves of it have
// now been wrong once: the FIRST version of this decoder expected a second version
// byte before the end address and shifted every following byte, and the second
// version read the single version byte as a byte length. The end address is read
// with the width the start address's version already established.
func parseRouteAdvertisement(payload []byte) ([]connectip.IPRoute, bool) {
	var routes []connectip.IPRoute
	for len(payload) > 0 {
		start, byteLength, n, ok := parseVersionedAddress(payload)
		if !ok {
			return nil, false
		}
		payload = payload[n:]

		// The end address is the same family as the start and carries no version
		// byte of its own.
		if len(payload) < byteLength {
			return nil, false
		}
		var end netip.Addr
		switch byteLength {
		case 4:
			end = netip.AddrFrom4([4]byte(payload[:4]))
		case 16:
			end = netip.AddrFrom16([16]byte(payload[:16]))
		default:
			return nil, false
		}
		payload = payload[byteLength:]

		if len(payload) == 0 {
			return nil, false
		}
		protocol := payload[0]
		payload = payload[1:]

		if end.Less(start) {
			return nil, false
		}
		routes = append(routes, connectip.IPRoute{
			StartIP:    start,
			EndIP:      end,
			IPProtocol: protocol,
		})
	}
	if len(routes) == 0 {
		return nil, false
	}
	return routes, true
}
