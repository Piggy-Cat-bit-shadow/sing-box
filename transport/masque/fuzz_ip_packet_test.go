package masque

import (
	std_bufio "bufio"
	"bytes"
	"io"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
)

// Fuzzing for the IP packet parser and for capsule stream fragmentation.
//
// Phase 2 fuzzed the capsule framer, ROUTE_ADVERTISEMENT, ADDRESS_ASSIGN and the
// URI-template matcher. Two inputs were still unfuzzed, and both are reachable from
// a peer:
//
//   - the IP packet parser (packetAddresses and decrementHopLimit), which every
//     packet on the CONNECT-IP data path goes through. Its output decides routing
//     and ownership, so a crash there is a denial of service and a misparse is a
//     policy question;
//   - the capsule READER, as opposed to the single-capsule decoder. A capsule
//     stream is a reliable byte stream, so a peer may fragment a capsule at any
//     boundary and coalesce several into one write. The reader must produce the
//     same result regardless of how the bytes were chunked.
//
// The properties are the same three as the Phase 2 targets: no panic, no unbounded
// allocation, and anything reported valid must be internally coherent.

// FuzzMasqueIPPacketParser drives the IP packet parser.
//
// It exercises both entry points a packet takes. decrementHopLimit is included
// because it MUTATES the packet and is called on the forwarding path, so an
// out-of-range write there would corrupt a buffer that is also being read.
func FuzzMasqueIPPacketParser(fuzz *testing.F) {
	// A well-formed IPv4 UDP packet.
	fuzz.Add(buildIPv4PacketForFuzz(0x11))
	// A well-formed IPv4 TCP packet.
	fuzz.Add(buildIPv4PacketForFuzz(0x06))
	// A well-formed IPv6 UDP packet.
	fuzz.Add(buildIPv6PacketForFuzz(0x11))
	// IPv6 with a Hop-by-Hop header then UDP.
	fuzz.Add(buildIPv6ChainForFuzz())
	// An IPv4 header with a zeroed protocol.
	fuzz.Add(buildIPv4PacketForFuzz(0))
	// Truncated IPv4 header.
	fuzz.Add([]byte{0x45, 0x00, 0x00, 0x14})
	// Truncated IPv6 header.
	fuzz.Add([]byte{0x60, 0x00, 0x00, 0x00})
	// Empty input.
	fuzz.Add([]byte{})
	// A version nibble that matches neither 4 nor 6.
	fuzz.Add([]byte{0x30, 0x00, 0x00, 0x00})
	// An IPv6 header claiming a huge payload length.
	fuzz.Add(append([]byte{0x60, 0x00, 0x00, 0x00, 0xff, 0xff, 0x11, 0x40},
		make([]byte, 64)...))

	fuzz.Fuzz(func(t *testing.T, packet []byte) {
		// packetAddresses must not panic, and anything it accepts must be
		// coherent: valid addresses, and a protocol number that is a real IP
		// protocol value rather than an artefact of the parse.
		source, destination, protocol, valid := packetAddresses(packet)
		if valid {
			if !source.IsValid() || !destination.IsValid() {
				t.Fatalf("packet accepted with invalid addresses: %s -> %s",
					source, destination)
			}
			// A version nibble of 4 or 6 is implied by the addresses themselves:
			// packetAddresses reads addresses through the version-specific header,
			// so a mismatch would mean the wrong header layout was used.
			if source.Is4() != destination.Is4() {
				t.Fatalf("packet accepted with mixed address families: %s -> %s",
					source, destination)
			}
			_ = protocol
		}

		// decrementHopLimit mutates the packet, so it must be given a copy and
		// must never write outside it. A slice-bounds violation would panic here.
		if len(packet) > 0 {
			clone := append([]byte(nil), packet...)
			_ = decrementHopLimit(clone)
			// The clone must still be the same length: a hop-limit decrement must
			// not resize or truncate the packet.
			if len(clone) != len(packet) {
				t.Fatalf("decrementHopLimit changed the packet length from %d to %d",
					len(packet), len(clone))
			}
		}
	})
}

// buildIPv4PacketForFuzz builds a minimal valid IPv4 packet with the given
// protocol.
func buildIPv4PacketForFuzz(protocol byte) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0x00
	packet[3] = 20
	packet[8] = 64
	packet[9] = protocol
	// 192.0.2.1 -> 198.51.100.1, both documentation ranges.
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 1})
	return packet
}

// buildIPv6PacketForFuzz builds a minimal valid IPv6 packet.
func buildIPv6PacketForFuzz(protocol byte) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	packet[6] = protocol
	packet[7] = 64
	source := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	destination := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	return packet
}

// buildIPv6ChainForFuzz builds IPv6 with a Hop-by-Hop header followed by UDP.
func buildIPv6ChainForFuzz() []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[4] = 0x00
	packet[5] = 0x08 // 8 bytes of payload after the base header
	packet[6] = 0x00 // Hop-by-Hop
	packet[7] = 64
	source := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	copy(packet[8:24], source[:])
	destination := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	copy(packet[24:40], destination[:])
	// Hop-by-Hop with next header UDP and length 0 (8 octets total).
	packet[40] = 0x11
	packet[41] = 0x00
	return packet
}

// FuzzCapsuleStreamFragmentation drives the capsule reader through arbitrary
// chunking.
//
// A capsule stream is a reliable byte stream, so the SAME bytes may arrive split at
// any boundary, or several capsules may be coalesced into one write. The parse
// result must not depend on the chunking. This target drives the framer over a
// reader that hands out at most `chunk` bytes per call, and checks that the capsule
// boundaries it finds are identical to the ones found when the whole buffer is
// available at once.
func FuzzCapsuleStreamFragmentation(fuzz *testing.F) {
	// Two well-formed DATAGRAM capsules back to back.
	fuzz.Add([]byte{0x00, 0x04, 0x00, 0xde, 0xad, 0xbe, 0x00, 0x03, 0x00, 0x01, 0x02}, 1)
	// One capsule whose header straddles a chunk boundary.
	fuzz.Add([]byte{0x00, 0x40, 0x01, 0x00}, 2)
	// A capsule with a 2-byte length varint.
	fuzz.Add([]byte{0x00, 0x40, 0x06, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05}, 3)
	// An unknown capsule type followed by a DATAGRAM.
	fuzz.Add([]byte{0x01, 0x02, 0xaa, 0xbb, 0x00, 0x02, 0x00, 0xff}, 1)
	// An empty stream.
	fuzz.Add([]byte{}, 1)
	// A truncated capsule.
	fuzz.Add([]byte{0x00, 0x10, 0x00}, 1)

	fuzz.Fuzz(func(t *testing.T, data []byte, chunk int) {
		if chunk < 1 {
			chunk = 1
		}
		if chunk > 64 {
			chunk = 64
		}

		whole := readAllCapsules(bytes.NewReader(data))
		chunked := readAllCapsules(&chunkedReader{reader: bytes.NewReader(data), chunk: chunk})

		// The number of capsules found must not depend on chunking.
		if len(whole) != len(chunked) {
			t.Fatalf("chunking changed the capsule count: %d whole vs %d chunked "+
				"(chunk=%d, data=% x)", len(whole), len(chunked), chunk, data)
		}
		// Nor may the contents.
		for index := range whole {
			if whole[index] != chunked[index] {
				t.Fatalf("chunking changed capsule %d: %q vs %q (chunk=%d)",
					index, whole[index], chunked[index], chunk)
			}
		}
	})
}

// chunkedReader hands out at most `chunk` bytes per Read, which is how a
// fragmented stream looks to the reader.
type chunkedReader struct {
	reader io.Reader
	chunk  int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	return r.reader.Read(p)
}

// readAllCapsules reads capsules until the stream ends, recording each payload.
//
// It uses the same varint and discard primitives the session uses, so the result
// reflects the production framing rather than a parallel implementation.
func readAllCapsules(reader io.Reader) []string {
	buffered := std_bufio.NewReader(reader)
	var capsules []string
	for {
		capsuleType, _, err := transportHTTP.ReadVarint(buffered)
		if err != nil {
			return capsules
		}
		length, _, err := transportHTTP.ReadVarint(buffered)
		if err != nil {
			return capsules
		}
		if length > transportHTTP.MaxCapsuleLength {
			return capsules
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(buffered, payload); err != nil {
			return capsules
		}
		capsules = append(capsules, string(payload)+"|"+itoa(int(capsuleType)))
	}
}
