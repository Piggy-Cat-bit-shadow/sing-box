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
//	IP Address
//	IP Prefix Length (one byte)
//
// with no leading count field. Measured against sing-box's own encoder:
// a single assignment of 198.18.0.2/32 arrives as
//
//	00                request ID 0 (unsolicited assignment)
//	04 c6 12 00 02    address family byte 4 (IPv4, 32 bits) then the 4 address bytes
//	20                prefix length 32
//
// The family byte is a BIT count, not a byte count: 4 means IPv4 and 6 means
// IPv6, and the address length is therefore family/8. Reading it as a byte length
// consumes 4 bytes for IPv4 (coincidentally right) but only 6 for IPv6 (wrong),
// which is why this is spelled out rather than inferred.
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

// parseAddress reads one address whose first byte is its BYTE length.
//
// MEASURED against this server rather than inferred from the RFC text. A single
// assignment of 198.18.0.2/32 arrives as
//
//	00                request ID 0 (unsolicited assignment)
//	04 c6 12 00 02    family byte 04, then four address bytes
//	20                prefix length 32
//
// so 04 is the number of ADDRESS BYTES (IPv4 = 4, IPv6 = 16), which matches
// sing-box's own encoder (transport/masque/capsule.go appendAddress writes 4 for
// IPv4 and 6... no: it writes 4 for IPv4 and 16 for IPv6, and the byte that
// reaches the wire is the byte count).
//
// The temptation is to read 4 and 6 as "IPv4 and IPv6" version markers, which
// happens to work for IPv4 and breaks IPv6. They are lengths: 4 bytes and 16
// bytes. A zero first byte is the wildcard form the references use to mean "any
// address" for a route endpoint.
func parseAddress(payload []byte) (netip.Addr, int, bool) {
	if len(payload) == 0 {
		return netip.Addr{}, 0, false
	}
	byteLength := int(payload[0])
	if byteLength == 0 {
		return netip.IPv4Unspecified(), 1, true
	}
	if len(payload) < 1+byteLength {
		return netip.Addr{}, 0, false
	}
	switch byteLength {
	case 4:
		return netip.AddrFrom4([4]byte(payload[1:5])), 5, true
	case 16:
		return netip.AddrFrom16([16]byte(payload[1:17])), 17, true
	default:
		return netip.Addr{}, 0, false
	}
}

// parseRouteAdvertisement decodes a ROUTE_ADVERTISEMENT payload.
//
// MEASURED against this server, and the shape is asymmetric in a way that is easy
// to get wrong. For an endpoint advertising 0.0.0.0/0 with protocol 0 the payload
// is ten bytes:
//
//	04 00 00 00 00    start: family byte 04, then four address bytes
//	ff ff ff ff       end:   four address bytes, NO family byte
//	00                IP protocol 0 (all protocols)
//
// Only the START address carries a length byte. The end address is written raw,
// because it is guaranteed to be the same family as the start, and sing-box's own
// encoder does exactly that:
//
//	payload = appendAddress(payload, route.Start)
//	payload = append(payload, route.End.AsSlice()...)
//	payload = append(payload, route.Protocol)
//
// Reading a length byte before the end address therefore consumes one byte of the
// address and shifts everything after it, which is what the first version of this
// decoder did. The end address is now read using the length already established by
// the start.
func parseRouteAdvertisement(payload []byte) ([]connectip.IPRoute, bool) {
	var routes []connectip.IPRoute
	for len(payload) > 0 {
		start, byteLength, n, ok := parseAddressWithLength(payload)
		if !ok {
			return nil, false
		}
		payload = payload[n:]

		// The end address is the same family as the start and carries no length
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

// parseAddressWithLength reads one length-prefixed address and also reports the
// address BYTE length, which the route decoder needs in order to read the
// unprefixed end address that follows.
func parseAddressWithLength(payload []byte) (netip.Addr, int, int, bool) {
	if len(payload) == 0 {
		return netip.Addr{}, 0, 0, false
	}
	byteLength := int(payload[0])
	if byteLength == 0 {
		return netip.IPv4Unspecified(), 0, 1, true
	}
	if len(payload) < 1+byteLength {
		return netip.Addr{}, 0, 0, false
	}
	switch byteLength {
	case 4:
		return netip.AddrFrom4([4]byte(payload[1:5])), 4, 5, true
	case 16:
		return netip.AddrFrom16([16]byte(payload[1:17])), 16, 17, true
	default:
		return netip.Addr{}, 0, 0, false
	}
}
