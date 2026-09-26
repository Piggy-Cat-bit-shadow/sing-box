package masque

import (
	std_bufio "bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// The MASQUE inner IP packet size bound, at the IPv6 boundary.
//
// transport/masque/session.go bounds the payload of one DATAGRAM capsule at
// maxPacketSize and discards anything larger. The value was 65535, which is the
// natural maximum for an IPv4 packet: the IPv4 Total Length field is 16 bits and
// counts the WHOLE packet, header included.
//
// IPv6 is different. Its 16-bit Payload Length field counts everything AFTER the
// 40-byte base header, so the largest ORDINARY (non-jumbogram) IPv6 packet is
//
//	40 (base header) + 65535 (max Payload Length) = 65575 bytes.
//
// This file measures whether the old bound silently discarded a legal packet in that
// 65536..65575 window, and pins the corrected bound.
//
// # What is and is not claimed
//
// RFC 8200 section 4.5 permits a Payload Length of 0 with a Hop-by-Hop Jumbo Payload
// option to carry up to 2^32-1 bytes. JUMBOGRAMS ARE NOT SUPPORTED here and this
// change does not enable them: the bound is raised to the largest ordinary packet and
// no further. The packet parser still decides validity from the actual IP header, so a
// 65575-byte buffer whose Payload Length does not match is rejected by the parser
// rather than by this bound.
//
// sing-tun agrees with the arithmetic: gtcpip/header/ipv6.go defines
// IPv6MaximumPayloadSize = 65535 as "the maximum size of a valid IPv6 payload", i.e.
// the amount after the base header, and its IPv6.IsValid checks
// `dlen > pktSize-IPv6MinimumSize`, which admits a total of 40+65535.

// ipv6PacketTotalSizeMax is the largest ordinary non-jumbogram IPv6 packet.
//
// It is written as an expression rather than as 65575 so the arithmetic is visible at
// the point of use and a reader does not have to take the number on trust.
const ipv6PacketTotalSizeMax = 40 + 65535

// buildIPv6PacketOfTotalSize returns an IPv6 + ICMPv6 packet whose TOTAL length is
// exactly size bytes.
//
// The header is real: version 6, a Payload Length that matches the actual body, a Next
// Header of 58 (ICMPv6) and valid addresses. Only the ICMPv6 checksum is left zero,
// because these tests exercise the SIZE bound and never reach a checksum-validating
// path. Anything that would validate the checksum is noted where it matters.
func buildIPv6PacketOfTotalSize(t *testing.T, size int) []byte {
	t.Helper()
	require.GreaterOrEqual(t, size, 40, "an IPv6 packet cannot be shorter than its base header")
	require.LessOrEqual(t, size, ipv6PacketTotalSizeMax,
		"the builder must not be asked for a jumbogram; this endpoint does not support them")

	source := netip.MustParseAddr("2001:db8::2")
	destination := netip.MustParseAddr("2001:db8::1")

	packet := make([]byte, size)
	packet[0] = 0x60                                         // version 6, traffic class 0, flow label 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(size-40)) // Payload Length
	packet[6] = 58                                           // Next Header: ICMPv6
	packet[7] = 64                                           // Hop Limit
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	// The body is left zeroed: these tests assert on the SIZE decision, not on the
	// contents. A checksum-validating path is not reached.
	packet[40] = 128 // ICMPv6 echo request, so the packet is at least recognisable
	return packet
}

// TestIPv6MaximumOrdinaryPacketIsNotSilentlyDropped is the regression this file exists
// for.
//
// It drives the capsule reader with an IPv6 packet whose total length is in the
// 65536..65575 window that the old 65535 bound excluded, and asserts that the packet
// reaches the handler instead of being discarded.
//
// The test is written against the READER rather than against the constant, because
// asserting on the constant would only restate the change. What matters is that a
// legal packet survives the path a real peer's bytes take.
func TestIPv6MaximumOrdinaryPacketIsNotSilentlyDropped(t *testing.T) {
	for _, size := range []int{65535, 65536, 65575} {
		t.Run(sizeName(size), func(t *testing.T) {
			packet := buildIPv6PacketOfTotalSize(t, size)
			require.Len(t, packet, size)
			require.Equal(t, size-40, int(binary.BigEndian.Uint16(packet[4:6])),
				"the builder must produce a self-consistent Payload Length")

			// Frame the packet as a peer would: a DATAGRAM capsule carrying context ID 0
			// and then the packet.
			capsule := buildDatagramCapsuleFraming(packet)

			handler := &recordingSessionHandler{}
			current := newTestSession(t, bytes.NewReader(capsule), handler, false)
			runFiniteSession(t, current)

			require.Len(t, handler.packets, 1,
				"exactly one packet must reach the handler for a %d-byte IPv6 packet. "+
					"Zero packets means the size bound discarded a legal packet - the "+
					"defect this test exists to catch", size)
			require.Equal(t, size, handler.packets[0].Len(),
				"the delivered packet must be the whole packet, not a truncation")
		})
	}
}

// TestIPv4MaximumPacketStillBounded is the counter-case for IPv4.
//
// Raising the bound to accommodate IPv6 must not leave IPv4 unbounded: the IPv4 Total
// Length field cannot describe more than 65535 bytes, so a larger buffer is not a legal
// IPv4 packet whatever it contains. The bound is on the MASQUE inner packet, so the
// point of this test is that the value is a deliberate maximum rather than "as large as
// the writer likes".
func TestIPv4MaximumPacketStillBounded(t *testing.T) {
	// A maximal IPv4 packet, framed and delivered.
	packet := make([]byte, 65535)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 65535)
	packet[8] = 64
	packet[9] = 1 // ICMPv4
	copy(packet[12:16], netip.MustParseAddr("198.18.0.2").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("198.18.0.1").AsSlice())

	handler := &recordingSessionHandler{}
	current := newTestSession(t, bytes.NewReader(buildDatagramCapsuleFraming(packet)), handler, false)
	runFiniteSession(t, current)
	require.Len(t, handler.packets, 1,
		"a maximal 65535-byte IPv4 packet must be delivered")
	require.Equal(t, 65535, handler.packets[0].Len())

	// And the bound itself must still exist at the IPv6 maximum, so the reader is
	// bounded rather than unlimited.
	require.LessOrEqual(t, maxPacketSize, ipv6PacketTotalSizeMax,
		"the inner packet bound must not exceed the largest ordinary IPv6 packet; "+
			"jumbograms are not supported here, so a larger bound would admit sizes no "+
			"legal non-jumbogram packet can have")
	require.GreaterOrEqual(t, maxPacketSize, 65535,
		"the bound must still admit a maximal IPv4 packet")
	require.GreaterOrEqual(t, maxPacketSize, ipv6PacketTotalSizeMax,
		"the bound must admit the largest ordinary IPv6 packet")
}

// TestOversizedPacketIsDiscardedWithoutKillingTheSession pins what happens ABOVE the
// bound, which is the behaviour the bound exists to produce.
//
// A capsule declaring more than the bound is DISCARDED, and the session continues so
// the next well-formed capsule is still processed. That is the same "drop the
// extension, keep the session" shape the context-ID handling uses, and it is what makes
// the bound a resource limit rather than a fault.
func TestOversizedPacketIsDiscardedWithoutKillingTheSession(t *testing.T) {
	// A capsule whose declared payload is one byte over the bound. The bytes do not have
	// to be a VALID IP packet, because the size gate runs before the parser.
	//
	// The Payload Length field cannot describe this size: 65575-40 is the largest value
	// the 16-bit field holds, and one byte more does not fit. That is exactly why the
	// bound is where it is - the largest packet the header format can describe and the
	// size limit are now the same number, so a buffer beyond it is unrepresentable
	// rather than merely large. The field is set to the largest representable value and
	// the buffer is one byte longer, which is the "header disagrees with the size" shape
	// the parser rejects independently.
	oversized := make([]byte, maxPacketSize+1)
	oversized[0] = 0x60
	binary.BigEndian.PutUint16(oversized[4:6], uint16(maxPacketSize-40))

	good := buildIPv6PacketOfTotalSize(t, 1280)

	framed := append(buildDatagramCapsuleFraming(oversized), buildDatagramCapsuleFraming(good)...)

	handler := &recordingSessionHandler{}
	current := newTestSession(t, bytes.NewReader(framed), handler, false)
	runFiniteSession(t, current)

	require.Len(t, handler.packets, 1,
		"only the well-formed capsule may reach the handler")
	require.Equal(t, 1280, handler.packets[0].Len(),
		"the delivered packet must be the one from the well-formed capsule")
}

// buildDatagramCapsuleFraming frames one payload as a DATAGRAM capsule with context
// ID 0, exactly as a peer would send it.
func buildDatagramCapsuleFraming(payload []byte) []byte {
	// The capsule payload is the context ID (one byte, 0) plus the packet.
	length := uint64(1 + len(payload))
	framed := []byte{capsuleTypeDatagramForTest}
	framed = appendVarint(framed, length)
	framed = append(framed, 0x00)
	return append(framed, payload...)
}

// capsuleTypeDatagramForTest is the DATAGRAM capsule type from RFC 9297 section 3.5.
//
// It is written out here rather than taken from transportHTTP.CapsuleTypeDatagram so
// the framing in this file is independent of the constant the implementation uses. If
// the two ever disagreed, these tests would fail rather than agree with each other.
const capsuleTypeDatagramForTest = 0x00

// appendVarint appends a QUIC varint (RFC 9000 section 16).
func appendVarint(buffer []byte, value uint64) []byte {
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

// recordingSessionHandler records the packets a session delivers, and answers every
// control capsule successfully so a test can drive the data path in isolation.
type recordingSessionHandler struct {
	packets []*buf.Buffer
	// packetsLen mirrors packets by length, because the buffers are released by the
	// session and cannot be inspected afterwards.
	packetsLen []int
}

func (h *recordingSessionHandler) handleAddressAssign([]AssignedAddress) error { return nil }
func (h *recordingSessionHandler) handleAddressRequest([]AssignedAddress) error {
	return nil
}
func (h *recordingSessionHandler) handleRouteAdvertisement([]AddressRange) error {
	return nil
}

func (h *recordingSessionHandler) handlePacket(buffer *buf.Buffer) {
	// Copy the bytes out, because the session owns and releases the buffer.
	payload := append([]byte(nil), buffer.Bytes()...)
	h.packets = append(h.packets, buf.As(payload))
	h.packetsLen = append(h.packetsLen, len(payload))
}

func (h *recordingSessionHandler) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	buffer.Release()
}

// runFiniteSession runs a session over a FINITE in-memory stream and asserts that it
// terminated in the only way such a stream can.
//
// session.run() returns context.Cause, and the capsule loop's terminal condition on a
// finite stream is io.EOF from the reader. So an EOF here is the expected end of input,
// not a failure - and asserting NoError would be wrong, which is what the first version
// of this file did. What the tests care about is which packets the handler RECEIVED, and
// that is asserted by the caller. A non-EOF error would mean the session failed for a
// different reason, so it is still rejected.
func runFiniteSession(t *testing.T, current *session) {
	t.Helper()
	err := current.run()
	if err != nil {
		require.ErrorIs(t, err, io.EOF,
			"a session over a finite in-memory stream may only end with EOF; any other "+
				"error means the capsule reader failed for a reason unrelated to the "+
				"test's subject")
	}
}

// newTestSession builds a session over an in-memory stream so the capsule reader can be
// driven directly.
func newTestSession(t *testing.T, stream *bytes.Reader, handler sessionHandler, queued bool) *session {
	t.Helper()
	return newSession(t.Context(), &readWriteCloser{Reader: std_bufio.NewReader(stream)}, handler, queued)
}

// readWriteCloser adapts a reader into the io.ReadWriteCloser a session needs. Writes
// are discarded, which is correct for these tests: they assert on the READ path.
type readWriteCloser struct {
	Reader *std_bufio.Reader
}

func (c *readWriteCloser) Read(p []byte) (int, error)  { return c.Reader.Read(p) }
func (c *readWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (c *readWriteCloser) Close() error                { return nil }

// sizeName renders a packet size for a subtest name.
func sizeName(size int) string {
	return "ipv6_total_" + itoaForTest(size)
}

func itoaForTest(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [8]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
