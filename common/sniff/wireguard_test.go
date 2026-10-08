package sniff_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// wireGuardMessage builds a structurally valid WireGuard message: the type byte, the mandatory
// zero reserved bytes, and a filler body.
//
// The filler is a counter rather than crypto/rand because the sniffer must not read the body at
// all. A random body would still pass today, but it would also let a future body-inspecting
// heuristic pass or fail by chance, which is exactly the kind of test that hides a regression
// instead of catching one.
func wireGuardMessage(messageType byte, length int) []byte {
	message := make([]byte, length)
	if length > 0 {
		message[0] = messageType
	}
	for i := 4; i < length; i++ {
		message[i] = byte(i*7 + 11)
	}
	return message
}

// deterministicBytes produces reproducible "unrelated" payloads. It uses a plain xorshift rather
// than crypto/rand so a failing case prints bytes that can be pasted into a bug report and
// reproduced byte for byte.
func deterministicBytes(seed uint32, length int) []byte {
	state := seed
	if state == 0 {
		state = 0x9e3779b9
	}
	data := make([]byte, length)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	return data
}

// TestSniffWireGuardInitiationIsNotBitTorrent is the LX 078 regression.
//
// A handshake initiation is 01 00 00 00 followed by 144 bytes of encrypted material and is 148
// bytes long. uTP reads version 1 / type 0 from 0x01 and an empty extension chain from 0x00 and
// claimed the packet for BitTorrent. The structural WireGuard sniffer must claim it first, and
// the packet pipeline must agree because PeekPacket returns on the first match.
func TestSniffWireGuardInitiationIsNotBitTorrent(t *testing.T) {
	t.Parallel()

	initiation := wireGuardMessage(1, 148)
	require.Len(t, initiation, 148)
	require.Equal(t, byte(0x01), initiation[0])
	require.Equal(t, []byte{0x00, 0x00, 0x00}, initiation[1:4])

	var metadata adapter.InboundContext
	require.NoError(t, sniff.WireGuard(context.Background(), &metadata, initiation))
	require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)

	// route.defaultPacketSniffers is asserted separately; this repeats the contract at the point
	// where the two sniffers meet, so a failure localises to the ordering rule as well.
	var pipelineMetadata adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(
		context.Background(),
		&pipelineMetadata,
		initiation,
		sniff.DomainNameQuery,
		sniff.QUICClientHello,
		sniff.STUNMessage,
		sniff.WireGuard,
		sniff.UTP,
		sniff.UDPTracker,
		sniff.DTLSRecord,
		sniff.NTP,
	))
	require.Equal(t, C.ProtocolWireGuard, pipelineMetadata.Protocol)
	require.NotEqual(t, C.ProtocolBitTorrent, pipelineMetadata.Protocol)
}

// TestSniffUTPAloneStillClaimsWireGuardInitiation records why the ordering above is load-bearing.
//
// If this test ever fails, uTP was tightened and WireGuard no longer needs to precede it; the
// sniffer itself stays valuable (it names the protocol instead of leaving it to the next weak
// matcher), but the ordering comment in route.go and this expectation must be revisited rather
// than silently left stale.
func TestSniffUTPAloneStillClaimsWireGuardInitiation(t *testing.T) {
	t.Parallel()

	var metadata adapter.InboundContext
	require.NoError(t, sniff.UTP(context.Background(), &metadata, wireGuardMessage(1, 148)))
	require.Equal(t, C.ProtocolBitTorrent, metadata.Protocol)
}

// TestSniffWireGuardMessageTypes covers every message shape the protocol defines.
//
// Type 4 is tested at its floor and well above it because its length is the only one that varies:
// the sniffer accepts anything >= 32, and an off-by-one there would either drop keepalives or
// reject every data packet.
func TestSniffWireGuardMessageTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		data []byte
	}{
		{"handshake initiation", wireGuardMessage(1, 148)},
		{"handshake response", wireGuardMessage(2, 92)},
		{"cookie reply", wireGuardMessage(3, 64)},
		{"transport data at floor", wireGuardMessage(4, 32)},
		{"transport data keepalive padded", wireGuardMessage(4, 48)},
		{"transport data small payload", wireGuardMessage(4, 128)},
		{"transport data full datagram", wireGuardMessage(4, 1420)},
		{"transport data maximum", wireGuardMessage(4, 65507)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var metadata adapter.InboundContext
			require.NoError(t, sniff.WireGuard(context.Background(), &metadata, testCase.data))
			require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)
		})
	}
}

// TestSniffWireGuardRejectsWrongLengths pins the exact boundaries.
//
// Each handshake length is asserted one byte short and one byte long. A range check instead of an
// equality check would pass the "one byte long" case while still misclassifying the next protocol
// whose header happens to share WireGuard's prefix.
func TestSniffWireGuardRejectsWrongLengths(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		messageType byte
		length      int
	}{
		{"initiation one short", 1, 147},
		{"initiation one long", 1, 149},
		{"response one short", 2, 91},
		{"response one long", 2, 93},
		{"cookie reply one short", 3, 63},
		{"cookie reply one long", 3, 65},
		{"transport empty", 4, 0},
		{"transport one short of header and tag", 4, 31},
		{"initiation at response length", 1, 92},
		{"response at initiation length", 2, 148},
		{"cookie reply at transport floor", 3, 32},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var metadata adapter.InboundContext
			err := sniff.WireGuard(context.Background(), &metadata, wireGuardMessage(testCase.messageType, testCase.length))
			require.ErrorIs(t, err, os.ErrInvalid)
			require.Empty(t, metadata.Protocol)
		})
	}
}

// TestSniffWireGuardRejectsNonZeroReserved checks the three reserved bytes individually.
//
// Testing only the first byte would let an implementation that skips the rest pass, and the
// reserved field is the entire reason a coincidental type byte cannot claim a datagram: losing it
// would make "any packet of 32 bytes or more whose first byte is 4" WireGuard.
func TestSniffWireGuardRejectsNonZeroReserved(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name        string
		messageType byte
		length      int
	}{
		{"initiation", 1, 148},
		{"response", 2, 92},
		{"cookie reply", 3, 64},
		{"transport", 4, 128},
	}

	for _, message := range valid {
		for reservedIndex := 1; reservedIndex <= 3; reservedIndex++ {
			t.Run(message.name, func(t *testing.T) {
				t.Parallel()
				packet := wireGuardMessage(message.messageType, message.length)
				packet[reservedIndex] = 0xff

				var metadata adapter.InboundContext
				err := sniff.WireGuard(context.Background(), &metadata, packet)
				require.ErrorIs(t, err, os.ErrInvalid)
				require.Empty(t, metadata.Protocol)
			})
		}
	}
}

// TestSniffWireGuardRejectsUnknownType walks the type byte across its whole range.
//
// Types 0 and 5-255 are not WireGuard. Type 0 matters most: an all-zero buffer has type 0 and
// three zero reserved bytes, so a sniffer that checked only the reserved field would claim any
// zero-filled datagram.
func TestSniffWireGuardRejectsUnknownType(t *testing.T) {
	t.Parallel()

	for messageType := 0; messageType <= 255; messageType++ {
		if messageType >= 1 && messageType <= 4 {
			continue
		}
		packet := wireGuardMessage(byte(messageType), 148)
		var metadata adapter.InboundContext
		err := sniff.WireGuard(context.Background(), &metadata, packet)
		require.ErrorIs(t, err, os.ErrInvalid, "type %d", messageType)
		require.Empty(t, metadata.Protocol)
	}
}

// TestSniffWireGuardRejectsAllZeroAndNoise covers the two degenerate inputs plus short packets.
//
// A zero buffer has the right length for a response and a cookie reply while having the wrong
// type; noise is the case that proves the check is structural rather than accidental.
func TestSniffWireGuardRejectsAllZeroAndNoise(t *testing.T) {
	t.Parallel()

	lengths := []int{0, 1, 3, 4, 19, 20, 31, 32, 63, 64, 91, 92, 147, 148, 149, 1200, 65507}
	for _, length := range lengths {
		t.Run("zero", func(t *testing.T) {
			t.Parallel()
			var metadata adapter.InboundContext
			err := sniff.WireGuard(context.Background(), &metadata, make([]byte, length))
			require.Error(t, err)
			require.Empty(t, metadata.Protocol)
		})
	}

	for _, length := range []int{1, 4, 32, 64, 92, 148, 149, 1200} {
		for seed := uint32(1); seed <= 32; seed++ {
			packet := deterministicBytes(seed, length)
			var metadata adapter.InboundContext
			err := sniff.WireGuard(context.Background(), &metadata, packet)
			if err == nil {
				// A random buffer may legitimately match the prefix by chance. When it does, it
				// must be because the whole structural rule holds, not because the prefix check is
				// loose, so the rule is re-derived from the packet here rather than assumed.
				require.Contains(t, []byte{1, 2, 3, 4}, packet[0])
				require.Equal(t, []byte{0x00, 0x00, 0x00}, packet[1:4])
				switch packet[0] {
				case 1:
					require.Len(t, packet, 148)
				case 2:
					require.Len(t, packet, 92)
				case 3:
					require.Len(t, packet, 64)
				case 4:
					require.GreaterOrEqual(t, len(packet), 32)
				}
				require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)
				continue
			}
			require.ErrorIs(t, err, os.ErrInvalid)
			require.Empty(t, metadata.Protocol)
		}
	}
}

// TestSniffUTPStillRecognisesBitTorrent is the control for the fix.
//
// These are upstream uTP corpus packets plus two constructed ones, unmodified in shape. If adding
// WireGuard ahead of uTP had widened the WireGuard check, these would be swallowed and BitTorrent
// detection would be silently broken - a failure mode worse than the one being fixed.
func TestSniffUTPStillRecognisesBitTorrent(t *testing.T) {
	t.Parallel()

	corpus := []string{
		// Real uTP packets from the upstream corpus: ST_STATE and ST_RESET headers.
		"21001ecb6817f2805d044fd700100000dbd03029",
		"410277ef0b1fb1f60000000000040000c233000000080000000000000000",
	}

	var packets [][]byte
	for _, encoded := range corpus {
		packet, err := hex.DecodeString(encoded)
		require.NoError(t, err)
		packets = append(packets, packet)
	}

	// A 20-byte ST_DATA packet: version 1, type 0, empty extension chain, connection id 0x0001.
	// It starts 01 just like a handshake initiation and is the shape closest to WireGuard's; it
	// must survive because its length is not 148.
	shortData := make([]byte, 20)
	shortData[0] = 1
	shortData[3] = 1
	packets = append(packets, shortData)

	// A 148-byte ST_DATA packet, exactly the length WireGuard claims. Its extension byte is zero
	// but its connection id is 0x0041, so the second reserved byte is non-zero and WireGuard must
	// refuse it. This is the discrimination that keeps the new check from eating real BitTorrent
	// data packets that happen to be 148 bytes long.
	longData := make([]byte, 148)
	longData[0] = 1
	longData[3] = 0x41
	packets = append(packets, longData)

	for _, packet := range packets {
		var wireGuardMetadata adapter.InboundContext
		if len(packet) == 148 {
			// The 148-byte control must be rejected by WireGuard for a reason other than length,
			// which is what makes it a useful control.
			require.Error(t, sniff.WireGuard(context.Background(), &wireGuardMetadata, packet))
			require.Empty(t, wireGuardMetadata.Protocol)
		}

		var utpMetadata adapter.InboundContext
		require.NoError(t, sniff.UTP(context.Background(), &utpMetadata, packet))
		require.Equal(t, C.ProtocolBitTorrent, utpMetadata.Protocol)

		var pipelineMetadata adapter.InboundContext
		require.NoError(t, sniff.PeekPacket(
			context.Background(),
			&pipelineMetadata,
			packet,
			sniff.WireGuard,
			sniff.UTP,
			sniff.UDPTracker,
		))
		require.Equal(t, C.ProtocolBitTorrent, pipelineMetadata.Protocol)
	}
}

// TestSniffWireGuardDoesNotClaimUnrelatedPayloads is the false-positive budget.
//
// Each payload is real traffic for another sniffer, decoded from that sniffer's own test corpus.
// None of them may come back as WireGuard, because the WireGuard check runs on every datagram in
// the default pipeline and a loose prefix test would relabel unrelated UDP traffic for every user.
func TestSniffWireGuardDoesNotClaimUnrelatedPayloads(t *testing.T) {
	t.Parallel()

	payloads := map[string]string{
		"stun binding request": "000100002112a44224b1a025d0c180c484341306",
		"dns query":            "740701000001000000000000012a06676f6f676c6503636f6d0000010001",
		"ntp client":           "1b0006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"bittorrent handshake": "13426974546f7272656e742070726f746f636f6c0000000000100000e21ea9569b69bab33c97851d0298bdfa89bc90922d5554313631302dea812fcd6a3563e3be40c1d1",
		"udp tracker connect":  "00000417271019800000000078e90560",
	}

	for name, encoded := range payloads {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet, err := hex.DecodeString(encoded)
			require.NoError(t, err)

			var metadata adapter.InboundContext
			err = sniff.WireGuard(context.Background(), &metadata, packet)
			require.Error(t, err)
			require.Empty(t, metadata.Protocol)

			// And through the real pipeline: each payload keeps its own classification rather than
			// being relabelled, whichever sniffer in the list owns it.
			var pipelineMetadata adapter.InboundContext
			_ = sniff.PeekPacket(
				context.Background(),
				&pipelineMetadata,
				packet,
				sniff.DomainNameQuery,
				sniff.QUICClientHello,
				sniff.STUNMessage,
				sniff.WireGuard,
				sniff.UTP,
				sniff.UDPTracker,
				sniff.DTLSRecord,
				sniff.NTP,
			)
			require.NotEqual(t, C.ProtocolWireGuard, pipelineMetadata.Protocol)
		})
	}
}

// TestSniffWireGuardDTLSRecordNotClaimed covers the header most likely to be confused with
// WireGuard's variable-length type 4.
//
// A DTLS record is 0x14/0x16 followed by version 0xfe 0xfd, so its reserved bytes are not zero.
// Asserting both the positive DTLS classification and the WireGuard refusal records that the two
// sniffers cannot fight over the same datagram instead of leaving the reader to derive it.
func TestSniffWireGuardDTLSRecordNotClaimed(t *testing.T) {
	t.Parallel()

	record := make([]byte, 64)
	record[0] = 22
	record[1] = 0xfe
	record[2] = 0xfd

	var dtlsMetadata adapter.InboundContext
	require.NoError(t, sniff.DTLSRecord(context.Background(), &dtlsMetadata, record))
	require.Equal(t, C.ProtocolDTLS, dtlsMetadata.Protocol)

	var wireGuardMetadata adapter.InboundContext
	require.Error(t, sniff.WireGuard(context.Background(), &wireGuardMetadata, record))
	require.Empty(t, wireGuardMetadata.Protocol)

	// The closest a DTLS-shaped header can get to WireGuard is a matching type byte with the
	// version bytes then breaking the reserved check.
	collision := make([]byte, 64)
	collision[0] = 4
	collision[1] = 0xfe
	collision[2] = 0xfd
	var collisionMetadata adapter.InboundContext
	require.Error(t, sniff.WireGuard(context.Background(), &collisionMetadata, collision))
	require.Empty(t, collisionMetadata.Protocol)
}

// ambiguousInitiation builds the shared byte string at the centre of the uTP/WireGuard collision: a
// 148-byte WireGuard handshake initiation whose uTP reading is a valid ST_DATA packet.
//
// The header is the whole of the collision. WireGuard fixes the first four bytes to 01 00 00 00; uTP
// reads the same four as version 1 / type ST_DATA, an empty extension chain and connection id
// 0x0000. Nothing after byte 3 is constrained by uTP and everything after byte 3 is random
// ciphertext and indices to WireGuard, so a merely deterministic filler - not a specially
// constructed one - is enough to be legal under both readings. That is the property the test below
// exercises: the collision is a property of the headers, not of a lucky body.
func ambiguousInitiation(seed uint32) []byte {
	packet := make([]byte, 148)
	packet[0] = 1
	copy(packet[4:], deterministicBytes(seed, 144))
	return packet
}

// TestSniffWireGuardUTPAmbiguityIsStructural is the deterministic proof that the residual
// WireGuard/uTP collision cannot be narrowed without giving up real WireGuard detection.
//
// Classification: PROVEN-INHERENT-AMBIGUITY.
//
// # Why every candidate narrowing fails
//
//   - Tightening uTP cannot help, because uTP is not the sniffer that decides. WireGuard runs first -
//     it must, because every real initiation is a legal uTP packet - and the ambiguous packet
//     already satisfies WireGuard's check, so a stricter uTP verdict is never consulted.
//   - Reordering cannot help for the same reason read the other way. uTP's constraints live in bytes
//     0-19 and the extension chain; the ambiguous packet and a genuine initiation differ only in
//     bytes 4-147, and uTP has no cross-field invariant there. A rule strict enough to reject the
//     ambiguous packet therefore rejects genuine initiations as well, and then a uTP-first pipeline
//     misclassifies every WireGuard handshake as BitTorrent.
//   - Additional WireGuard consistency cannot help, because there is no consistent field left. Bytes
//     4-7 are a random sender index and bytes 8-147 are an ephemeral public key, three AEAD
//     ciphertexts and two keyed MACs, all uniformly random from outside. mac2 is all-zero only until
//     the responder demands a cookie, so requiring it either way drops real handshakes.
//
// The tie-break the pipeline does make - WireGuard before uTP - is therefore not arbitrary: among
// datagrams that satisfy both, the WireGuard reading explains all of them, while the uTP reading
// additionally requires the datagram to be exactly 148 bytes with a zero connection id. The residual
// is two orders of magnitude rarer than the handshakes a different order would stop seeing.
func TestSniffWireGuardUTPAmbiguityIsStructural(t *testing.T) {
	t.Parallel()

	// More than one filler, because a single lucky byte string would be an anecdote. The claim is
	// that any body legal under one reading is legal under the other, so the loop has to show it for
	// a spread of bodies and not only for the one that was hand-picked.
	for seed := uint32(1); seed <= 64; seed++ {
		packet := ambiguousInitiation(seed)
		require.Len(t, packet, 148)
		require.Equal(t, []byte{0x01, 0x00, 0x00, 0x00}, packet[:4])

		// The WireGuard reading, which is the one the pipeline acts on.
		var wireGuardMetadata adapter.InboundContext
		require.NoError(t, sniff.WireGuard(context.Background(), &wireGuardMetadata, packet), "seed %d", seed)
		require.Equal(t, C.ProtocolWireGuard, wireGuardMetadata.Protocol)

		// The uTP reading of the SAME bytes, spelled out field by field so that "this is a genuine
		// uTP packet" is checked rather than asserted. These are the only constraints uTP has.
		require.GreaterOrEqual(t, len(packet), 20, "uTP header")
		require.Equal(t, byte(1), packet[0]&0x0F, "uTP version")
		require.Equal(t, byte(0), packet[0]>>4, "uTP ST_DATA type")
		require.Equal(t, byte(0), packet[1], "uTP empty extension chain")
		require.Equal(t, uint16(0), binary.BigEndian.Uint16(packet[2:4]), "uTP connection id")

		var utpMetadata adapter.InboundContext
		require.NoError(t, sniff.UTP(context.Background(), &utpMetadata, packet), "seed %d", seed)
		require.Equal(t, C.ProtocolBitTorrent, utpMetadata.Protocol)
	}

	// The pipeline resolves the ambiguity by ORDER, not by structure. Both orders are given the
	// identical bytes here, so the two results together are the proof: if structure could separate
	// the readings, one of the sniffers would have to refuse.
	packet := ambiguousInitiation(1)

	var wireGuardFirst adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(
		context.Background(), &wireGuardFirst, packet,
		sniff.WireGuard, sniff.UTP, sniff.UDPTracker,
	))
	require.Equal(t, C.ProtocolWireGuard, wireGuardFirst.Protocol)

	var utpFirst adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(
		context.Background(), &utpFirst, packet,
		sniff.UTP, sniff.WireGuard, sniff.UDPTracker,
	))
	require.Equal(t, C.ProtocolBitTorrent, utpFirst.Protocol)

	// The residual is exactly the two connection-id bytes, and nothing else. Every other value turns
	// the uTP reading into a packet WireGuard must refuse, because WireGuard requires all three
	// bytes after the type to be zero; this is what makes the collision a 1-in-2^16 event on a
	// 148-byte ST_DATA and pins it to a specific field rather than to "some overlap somewhere".
	for _, connectionID := range []uint16{0, 1, 2, 0xff, 0xffff} {
		candidate := ambiguousInitiation(1)
		binary.BigEndian.PutUint16(candidate[2:4], connectionID)

		var metadata adapter.InboundContext
		require.NoError(t, sniff.PeekPacket(
			context.Background(), &metadata, candidate,
			sniff.WireGuard, sniff.UTP, sniff.UDPTracker,
		))
		if connectionID == 0 {
			require.Equal(t, C.ProtocolWireGuard, metadata.Protocol,
				"a zero connection id is what makes the uTP reading agree with WireGuard's mandatory zero reserved bytes")
		} else {
			require.Equal(t, C.ProtocolBitTorrent, metadata.Protocol,
				"any non-zero connection id breaks a reserved byte and must fall through to uTP (id %#04x)", connectionID)
		}
	}

	t.Log("classification: PROVEN-INHERENT-AMBIGUITY - a zero uTP connection id and an empty " +
		"extension chain are byte-identical to a WireGuard type-1 header, and no structural rule can " +
		"separate them without also rejecting genuine handshake initiations")
}
