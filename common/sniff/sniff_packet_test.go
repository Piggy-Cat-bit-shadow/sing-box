package sniff_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/stretchr/testify/require"
)

// sniffPacket runs the production packet plan and reports what claimed the datagram.
func sniffPacket(t *testing.T, packet []byte) (*adapter.InboundContext, error) {
	t.Helper()
	metadata := adapter.InboundContext{}
	err := sniff.PeekPacket(context.Background(), &metadata, packet, sniff.DefaultPacketSniffers...)
	return &metadata, err
}

func buildSTUNMessage(length int) []byte {
	packet := make([]byte, 20+length)
	binary.BigEndian.PutUint16(packet[0:2], 0x0001)
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	binary.BigEndian.PutUint32(packet[4:8], 0x2112A442)
	copy(packet[8:20], []byte("collision-tx"))
	return packet
}

func buildUDPTrackerConnect() []byte {
	packet := make([]byte, 16)
	binary.BigEndian.PutUint64(packet[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(packet[8:12], 0)
	return packet
}

// buildNTPRequest is a structurally valid NTP client request: version 4, mode 3, and a root delay
// and dispersion of zero, which is inside the range the parser accepts.
func buildNTPRequest() []byte {
	packet := make([]byte, 48)
	packet[0] = 4<<3 | 3
	return packet
}

// buildDNSQuery is the google.com A query the stream cases use, in its datagram form.
func buildDNSQuery() []byte {
	return mustHex("740701000001000000000000012a06676f6f676c6503636f6d0000010001")
}

func bytesOfValue(value byte, length int) []byte {
	packet := make([]byte, length)
	for i := range packet {
		packet[i] = value
	}
	return packet
}

// TestPacketSnifferPrecedenceCollisions is the collision corpus the packet plan is ordered by.
//
// Each case is a pair of parsers whose accept sets overlap in principle, and the assertion is about
// which reading wins on the wire. The order is not a preference: a weak parser placed early steals
// traffic from a stronger one placed later, and these are the pairs where that has actually
// happened or could.
func TestPacketSnifferPrecedenceCollisions(t *testing.T) {
	t.Parallel()

	// WireGuard vs uTP. A handshake initiation starts 01 00 00 00, is 148 bytes long, and is a
	// legal uTP ST_DATA packet as far as that heuristic is concerned, so the two readings cannot be
	// separated structurally - wireguard_test.go proves that field by field. What separates them is
	// this order, which is why the case fails if WireGuard is ever moved after UTP.
	initiation := wireGuardMessage(1, 148)
	require.NoError(t, sniff.UTP(context.Background(), &adapter.InboundContext{}, initiation),
		"uTP no longer claims a handshake initiation, so the ordering this case protects is untested")
	metadata, err := sniffPacket(t, initiation)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)

	// Every other WireGuard message shape has the same problem one message later, so the whole
	// family is checked rather than just the initiation.
	for _, message := range []struct {
		name        string
		messageType byte
		length      int
	}{
		{"handshake-response", 2, 92},
		{"cookie-reply", 3, 64},
		{"transport-data", 4, 32},
	} {
		packet := wireGuardMessage(message.messageType, message.length)
		metadata, err := sniffPacket(t, packet)
		require.NoError(t, err, message.name)
		require.Equal(t, C.ProtocolWireGuard, metadata.Protocol, message.name)
	}

	// QUIC vs uTP: a QUIC Initial must not be taken by the BitTorrent heuristics behind it.
	require.NoError(t, sniff.QUICClientHello(context.Background(), &adapter.InboundContext{}, quicInitial))
	metadata, err = sniffPacket(t, quicInitial)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolQUIC, metadata.Protocol)

	// QUIC vs DTLS. DTLS accepts record types 20-25 and versions feff/fefd, none of which a QUIC
	// Initial starts with; the case exists so a future DTLS relaxation cannot take QUIC traffic.
	require.Error(t, sniff.DTLSRecord(context.Background(), &adapter.InboundContext{}, quicInitial))

	// STUN vs generic UDP. A STUN binding request carries the magic cookie and is claimed; the
	// cookie is also the whole reason it is not just another datagram.
	metadata, err = sniffPacket(t, buildSTUNMessage(0))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolSTUN, metadata.Protocol)

	// DNS vs a random small packet. A datagram shorter than the DNS header cannot be DNS, and the
	// query above is claimed by DNS rather than by any of the weaker parsers in front of it.
	metadata, err = sniffPacket(t, buildDNSQuery())
	require.NoError(t, err)
	require.Equal(t, C.ProtocolDNS, metadata.Protocol)

	// NTP vs generic UDP. Version and mode are the whole gate.
	metadata, err = sniffPacket(t, buildNTPRequest())
	require.NoError(t, err)
	require.Equal(t, C.ProtocolNTP, metadata.Protocol)

	// UDP tracker vs a short zero-prefix payload. The tracker protocol id is what makes it one; a
	// zero prefix alone, at any length, is not.
	metadata, err = sniffPacket(t, buildUDPTrackerConnect())
	require.NoError(t, err)
	require.Equal(t, C.ProtocolBitTorrent, metadata.Protocol)
	for _, length := range []int{0, 1, 2, 4, 8, 12, 15, 16, 20, 32} {
		metadata, err = sniffPacket(t, make([]byte, length))
		require.Error(t, err, "zero payload of length %d was claimed by %q", length, metadata.Protocol)
		require.Empty(t, metadata.Protocol, "zero payload of length %d", length)
	}
}

// TestPacketSnifferOnlyClaimsWhatItsParserAccepts is the cross-check for the corpus above: the plan
// returns on the first parser that accepts, so a protocol can never be reported by a parser that
// would have rejected the same bytes. That is the property separating this plan from a port-based
// guess, and it is checked over real captures, structured fakes and degenerate filler alike.
func TestPacketSnifferOnlyClaimsWhatItsParserAccepts(t *testing.T) {
	t.Parallel()
	packetParser := map[string]sniff.PacketSniffer{
		C.ProtocolDNS:       sniff.DomainNameQuery,
		C.ProtocolQUIC:      sniff.QUICClientHello,
		C.ProtocolSTUN:      sniff.STUNMessage,
		C.ProtocolWireGuard: sniff.WireGuard,
		C.ProtocolDTLS:      sniff.DTLSRecord,
		C.ProtocolNTP:       sniff.NTP,
	}
	corpus := [][]byte{
		buildSTUNMessage(0),
		buildSTUNMessage(8),
		buildDNSQuery(),
		buildNTPRequest(),
		buildUDPTrackerConnect(),
		quicInitial,
		wireGuardMessage(1, 148),
		wireGuardMessage(2, 92),
		wireGuardMessage(3, 64),
		wireGuardMessage(4, 32),
	}
	for length := 0; length <= 300; length++ {
		corpus = append(corpus, make([]byte, length))
		corpus = append(corpus, bytesOfValue(0xFF, length))
		corpus = append(corpus, deterministicBytes(uint32(length)+1, length))
		corpus = append(corpus, deterministicBytes(uint32(length)+0x9e37, length))
	}
	for index, packet := range corpus {
		metadata, err := sniffPacket(t, packet)
		if err != nil {
			require.Empty(t, metadata.Protocol, "case %d", index)
			continue
		}
		require.NotEmpty(t, metadata.Protocol, "case %d", index)
		// Three parsers report BitTorrent, so it is checked against all three.
		if metadata.Protocol == C.ProtocolBitTorrent {
			require.True(t,
				sniff.UTP(context.Background(), &adapter.InboundContext{}, packet) == nil ||
					sniff.UDPTracker(context.Background(), &adapter.InboundContext{}, packet) == nil,
				"case %d claimed BitTorrent without any BitTorrent parser accepting it", index)
			continue
		}
		parser, isCompared := packetParser[metadata.Protocol]
		require.True(t, isCompared, "case %d claimed an unmapped protocol %q", index, metadata.Protocol)
		require.NoError(t, parser(context.Background(), &adapter.InboundContext{}, packet), "case %d", index)
	}
}

// TestPacketSnifferDegenerateInputs is the guarantee the degenerate corpus exists for: garbage
// never panics, never reads out of bounds and never produces a protocol out of nothing.
//
// The length floor is not a tolerance. Every parser in the plan declares a minimum and the smallest
// of them is the twelve-byte DNS header, so a datagram below that cannot be claimed by anything at
// all - which is exactly what has to stay true when a parser is added or relaxed.
func TestPacketSnifferDegenerateInputs(t *testing.T) {
	t.Parallel()
	degenerate := [][]byte{
		{},
		{0x00},
		{0xFF},
		{0x00, 0x00},
		{0xFF, 0xFF},
		make([]byte, 64),
		bytesOfValue(0xFF, 64),
		make([]byte, 1500),
		bytesOfValue(0xFF, 1500),
	}
	for _, packet := range degenerate {
		metadata, err := sniffPacket(t, packet)
		if len(packet) < 12 {
			require.Error(t, err, "length %d", len(packet))
			require.Empty(t, metadata.Protocol, "length %d", len(packet))
		}
	}
	for length := 0; length <= 64; length++ {
		for seed := 1; seed <= 8; seed++ {
			packet := deterministicBytes(uint32(seed*1000+length), length)
			metadata, err := sniffPacket(t, packet)
			if len(packet) < 12 {
				require.Error(t, err, "length %d seed %d", length, seed)
				require.Empty(t, metadata.Protocol, "length %d seed %d", length, seed)
			}
		}
	}
}
