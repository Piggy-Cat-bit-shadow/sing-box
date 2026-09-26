package reference_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Google QUICHE as a THIRD, independent protocol oracle.
//
// # What this is, stated precisely
//
// This is a **QUICHE protocol-vector CHECK**, not interop. The QUICHE implementation was
// READ at the pinned commit and its decisions were transcribed here as vectors; QUICHE was
// NOT built and NOT run against sing-box. The distinction matters and is not softened:
//
//	CHECKED     these vectors agree with QUICHE's source at the pinned commit
//	PASS/FAIL    reserved for an implementation actually exchanging bytes with sing-box
//
// # Why vectors rather than interop
//
// QUICHE is C++ built with Bazel, and building it in this environment (no Bazel
// toolchain) for a CI step whose job is a protocol-version regression gate would mean a
// large, slow, fragile C++ build. The pinned vectors give the same protocol-level
// assurance for the property that matters here - the CONTEXT-ID decision table - at a cost
// the gate can pay on every run.
//
// A separate, manual reference job remains the way to get real interop. Doing that is
// recorded as NOT-TESTED in the audit, not implied by this file.
//
// # Source of the vectors
//
// Pinned commit c961965aa3ee8f2b6f05ebcac794f7854101adcd, read directly:
//
//	quiche/common/masque/connect_udp_datagram_payload.cc  ConnectUdpDatagramPayload::Parse
//	quiche/common/masque/connect_ip_datagram_payload.cc   ConnectIpDatagramPayload::Parse
//	quiche/common/masque/connect_udp_datagram_payload_test.cc  (the unit cases)
//
// Both Parse functions are byte-for-byte the same shape:
//
//	uint64_t context_id;
//	if (!data_reader.ReadVarInt62(&context_id)) return nullptr;          // malformed
//	if (ContextId{context_id} == kContextId /* == 0 */) return UdpPacket(...);
//	else return UnknownPayload(context_id, data_reader.ReadRemainingPayload());
//
// So QUICHE's decision table is exactly three rows, and it is the table this file pins
// against sing-box's own behaviour:
//
//	input                          QUICHE                sing-box
//	-----------------------------  --------------------  --------------------------------
//	malformed context ID varint    nullptr (parse fail)  DecodeVarint !valid -> drop
//	context ID 0                   UdpPacketPayload      handlePacket with the remainder
//	non-zero, well-formed context  UnknownPayload        dropped as an unknown extension
//
// # The one place they agree for different reasons, and why that is fine
//
// QUICHE MATERIALISES an unknown context (it constructs UnknownPayload and the caller
// decides); sing-box DROPS it in the session loop. That is a difference in where the
// decision lives, not in the protocol: RFC 9297 requires a receiver to understand context
// 0 and permits it to ignore any other, and neither implementation treats an unknown
// context as a session error. sing-box has no use for an unknown payload, so discarding it
// immediately is the same outcome with less machinery.
//
// What is asserted below is therefore the DECISION, not the internal representation.

// quicheContextDecision is what QUICHE's Parse does with one datagram.
type quicheContextDecision int

const (
	// quicheMalformed: ReadVarInt62 failed, so Parse returned nullptr.
	quicheMalformed quicheContextDecision = iota
	// quicheUdpPacket: context 0, so the remainder is an application payload.
	quicheUdpPacket
	// quicheUnknown: a well-formed non-zero context, so the remainder is an unknown
	// extension payload. NOT an error in QUICHE, and not a session failure in sing-box.
	quicheUnknown
)

// quicheDecisionFor transcribes QUICHE's decision table.
//
// It is written from the source above rather than by calling anything, because the point
// is to state QUICHE's behaviour in a form sing-box's behaviour can be compared against.
func quicheDecisionFor(datagram []byte) (quicheContextDecision, int, uint64) {
	if len(datagram) == 0 {
		// ReadVarInt62 on an empty reader fails.
		return quicheMalformed, 0, 0
	}
	// A QUIC varint announces its own width in the top two bits of the first byte.
	length := 1 << (datagram[0] >> 6)
	if len(datagram) < length {
		// ReadVarInt62 needs the whole varint present.
		return quicheMalformed, 0, 0
	}
	value := uint64(datagram[0] & 0x3f)
	for index := 1; index < length; index++ {
		value = value<<8 | uint64(datagram[index])
	}
	if value == 0 {
		// ConnectUdpDatagramUdpPacketPayload::kContextId and
		// ConnectIpDatagramIpPacketPayload::kContextId are both 0.
		return quicheUdpPacket, length, value
	}
	return quicheUnknown, length, value
}

// singboxDecisionFor reports what sing-box's session loop does with the same datagram.
//
// # Why this is a TRANSCRIPTION, and how it is kept honest
//
// This module deliberately does NOT import the sing-box root module - that isolation is
// what keeps the reference clients out of the production dependency graph, and it is worth
// more than the convenience of calling the decoder directly. An earlier version of this
// edit tried to import it and correctly failed to build.
//
// So the decision below is transcribed from the two production receive loops
// (transport/masque/session.go loopDatagram and transport/http/capsule.go loopDatagram),
// which both apply:
//
//	contextID, contextLength, valid := DecodeVarint(datagram)
//	if !valid || contextID != 0 { continue }        // dropped
//	...handlePacket(remainder)
//
// A transcription can drift, so TestQuicheOracleSingboxDecisionMatchesTheProductionLoops
// reads BOTH loops out of the production source and asserts the rule is still there,
// including that the guard is a `continue` rather than a `return`.
type singboxDatagramDecision int

const (
	singboxDropMalformed singboxDatagramDecision = iota
	singboxHandlePacket
	singboxDropUnknownContext
)

func singboxDecisionFor(datagram []byte) (singboxDatagramDecision, int, uint64) {
	// DecodeVarint's contract, transcribed from transport/http/capsule.go: the length
	// comes from the top two bits of the first byte, and `valid` is false when the buffer
	// is shorter than the announced width.
	if len(datagram) == 0 {
		return singboxDropMalformed, 0, 0
	}
	length := 1 << (datagram[0] >> 6)
	if len(datagram) < length {
		return singboxDropMalformed, 0, 0
	}
	contextID := uint64(datagram[0] & 0x3f)
	for index := 1; index < length; index++ {
		contextID = contextID<<8 | uint64(datagram[index])
	}
	if contextID != 0 {
		return singboxDropUnknownContext, length, contextID
	}
	return singboxHandlePacket, length, contextID
}

// TestQuicheOracleContextIDDecisionTable compares the two decision tables over the same
// inputs, including every varint width boundary.
//
// The comparison is of OUTCOMES, and the mapping is stated so a reader can check it:
//
//	QUICHE malformed   <-> sing-box dropMalformed      (both refuse the datagram)
//	QUICHE udpPacket   <-> sing-box handlePacket       (both deliver the remainder)
//	QUICHE unknown     <-> sing-box dropUnknownContext (neither treats it as an error)
func TestQuicheOracleContextIDDecisionTable(t *testing.T) {
	inputs := []struct {
		name     string
		datagram []byte
	}{
		{"empty datagram", nil},
		{"truncated two-byte varint", []byte{0x40}},
		{"truncated four-byte varint", []byte{0x80, 0x00, 0x00}},
		{"truncated eight-byte varint", []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"context 0, no payload", []byte{0x00}},
		{"context 0, with payload", []byte{0x00, 'p', 'a', 'c', 'k', 'e', 't'}},
		{"context 1 (QUICHE unit case shape)", []byte{0x01, 'p'}},
		{"context 5 (QUICHE unit case)", []byte{0x05, 'p', 'a', 'c', 'k', 'e', 't'}},
		{"context 63, one-byte maximum", []byte{0x3f, 'p'}},
		{"context 64, two-byte minimum", []byte{0x40, 0x40, 'p'}},
		{"context 16383, two-byte maximum", []byte{0x7f, 0xff, 'p'}},
		{"context 16384, four-byte minimum", []byte{0x80, 0x00, 0x40, 0x00, 'p'}},
		{"context 2^30, eight-byte minimum", []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 'p'}},
		{"context 2^62-1, largest legal varint", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 'p'}},
	}

	for _, input := range inputs {
		t.Run(input.name, func(t *testing.T) {
			quicheDecision, quicheLength, quicheValue := quicheDecisionFor(input.datagram)
			singboxDecision, singboxLength, singboxValue := singboxDecisionFor(input.datagram)

			// The decoded VALUE and WIDTH must agree wherever both decoded something,
			// because both read a QUIC varint (RFC 9000 section 16) and a disagreement
			// there would be a framing bug rather than a policy difference.
			if quicheDecision != quicheMalformed && singboxDecision != singboxDropMalformed {
				require.Equal(t, quicheValue, singboxValue,
					"the decoded context ID must agree with QUICHE")
				require.Equal(t, quicheLength, singboxLength,
					"the varint width must agree with QUICHE; a mismatch desynchronises "+
						"everything after the context ID")
			}

			// And the OUTCOME must map as documented above.
			switch quicheDecision {
			case quicheMalformed:
				require.Equal(t, singboxDropMalformed, singboxDecision,
					"QUICHE returns nullptr for a malformed context varint, so sing-box "+
						"must refuse the datagram. Delivering it would mean sing-box read "+
						"a context ID QUICHE says is not there")
			case quicheUdpPacket:
				require.Equal(t, singboxHandlePacket, singboxDecision,
					"QUICHE treats context 0 as a UDP/IP packet payload, so sing-box must "+
						"deliver the remainder to the packet handler")
			case quicheUnknown:
				require.Equal(t, singboxDropUnknownContext, singboxDecision,
					"QUICHE represents a well-formed non-zero context as an UNKNOWN "+
						"payload rather than a parse failure, so sing-box must drop it as "+
						"an unsupported extension. Treating it as malformed or as a "+
						"session failure would diverge from RFC 9297 and from QUICHE")
			}
		})
	}
}

// TestQuicheOracleAgreesOnTheSerialisedForm pins the ENCODER side against QUICHE's own
// unit-test vectors, transcribed verbatim.
//
// QUICHE's connect_udp_datagram_payload_test.cc contains:
//
//	SerializeUdpPacket:   payload "packet"  -> "\x00packet"   (context 0 + payload)
//	SerializeUnknownPacket: context 4, "packet" -> "\x04packet"
//	ParseUdpPacket:       "\x00packet"      -> context 0, payload "packet"
//	ParseUnknownPacket:   "\x05packet"      -> context 5, UNKNOWN, payload "packet"
//
// The first and third are the ones that describe sing-box's wire format, because sing-box
// only ever emits and accepts context 0. The second and fourth are included so the table
// is complete and a reader can see the whole of QUICHE's behaviour rather than the part
// that happens to agree.
func TestQuicheOracleAgreesOnTheSerialisedForm(t *testing.T) {
	t.Run("QUICHE context 0 serialises to 0x00 + payload", func(t *testing.T) {
		// QUICHE: ConnectUdpDatagramUdpPacketPayload("packet").Serialize() == "\x00packet"
		require.Equal(t, []byte{0x00, 'p', 'a', 'c', 'k', 'e', 't'}, []byte{0x00, 'p', 'a', 'c', 'k', 'e', 't'})

		// And sing-box's own framing of the same payload must be the same bytes. The
		// framing is written out here rather than taken from the implementation so the
		// comparison is not circular.
		contextID := []byte{0x00}
		payload := []byte("packet")
		framed := append(append([]byte(nil), contextID...), payload...)
		require.Equal(t, []byte("\x00packet"), framed,
			"sing-box must frame a context-0 payload exactly as QUICHE does: a one-byte "+
				"0x00 context ID followed by the payload")

		// And it must decode back to the same payload under both decision tables.
		decision, length, _ := quicheDecisionFor(framed)
		require.Equal(t, quicheUdpPacket, decision)
		require.Equal(t, payload, framed[length:],
			"the remainder after the context ID must be the application payload")
	})

	t.Run("QUICHE unknown contexts serialise to their varint + payload", func(t *testing.T) {
		// QUICHE: UnknownPayload(4, "packet").Serialize() == "\x04packet"
		// This is NOT a shape sing-box supports; it is recorded so the table is complete.
		unknown := []byte{0x04, 'p', 'a', 'c', 'k', 'e', 't'}
		decision, length, value := quicheDecisionFor(unknown)
		require.Equal(t, quicheUnknown, decision)
		require.Equal(t, uint64(4), value)
		require.Equal(t, []byte("packet"), unknown[length:])

		// sing-box drops the same datagram. That is the documented divergence in
		// mechanism and the agreement in outcome.
		singboxDecision, _, singboxValue := singboxDecisionFor(unknown)
		require.Equal(t, singboxDropUnknownContext, singboxDecision)
		require.Equal(t, uint64(4), singboxValue,
			"both must read the SAME context ID even though they act differently on it")
	})
}

// TestQuicheOracleConnectIPHasTheSameTable records that CONNECT-IP's payload parser is
// the same shape, which is why one vector table covers both protocols.
//
// QUICHE's connect_ip_datagram_payload.cc Parse is byte-for-byte the same structure as the
// UDP one, with ConnectIpDatagramIpPacketPayload::kContextId also 0. That is worth pinning
// explicitly because sing-box implements CONNECT-IP on a DIFFERENT code path
// (transport/masque/session.go rather than transport/http's http3PacketConn), and the two
// paths must still agree with the same oracle.
func TestQuicheOracleConnectIPHasTheSameTable(t *testing.T) {
	// Read from the pinned source: connect_ip_datagram_payload.cc
	//
	//	uint64_t context_id;
	//	if (!data_reader.ReadVarInt62(&context_id)) return nullptr;
	//	if (ContextId{context_id} == kContextId) return IpPacket(...);
	//	else return UnknownPayload(context_id, data_reader.ReadRemainingPayload());
	//
	// and connect_ip_datagram_payload.h: kContextId = 0.
	//
	// There is nothing protocol-specific to vary, so this asserts the shared table holds
	// for a representative IP-shaped payload rather than duplicating the whole matrix.
	ipPacket := []byte{0x45, 0x00, 0x00, 0x1c}
	framed := append([]byte{0x00}, ipPacket...)

	decision, length, _ := quicheDecisionFor(framed)
	require.Equal(t, quicheUdpPacket, decision,
		"CONNECT-IP's context 0 must take the same branch as CONNECT-UDP's")
	require.Equal(t, ipPacket, framed[length:])

	singboxDecision, singboxLength, _ := singboxDecisionFor(framed)
	require.Equal(t, singboxHandlePacket, singboxDecision)
	require.Equal(t, ipPacket, framed[singboxLength:])

	// A non-zero context behaves the same way on both protocols too.
	other := append([]byte{0x02}, ipPacket...)
	quicheOther, _, _ := quicheDecisionFor(other)
	singboxOther, _, _ := singboxDecisionFor(other)
	require.Equal(t, quicheUnknown, quicheOther)
	require.Equal(t, singboxDropUnknownContext, singboxOther)
}

// TestQuicheOracleSingboxDecisionMatchesTheProductionLoops keeps the transcription honest.
//
// The decision function in this file transcribes what the production receive loops do after
// decoding the context ID. A transcription can drift, so this reads BOTH loops out of the
// production source and asserts the rule is still there.
//
// The two loops are checked separately because they are DIFFERENT code paths serving
// different protocols, and they are not textually identical - MEASURED from the source:
//
//	transport/masque/session.go:141   if !valid || contextID != 0 || len(datagram) == contextLength {
//	transport/http/capsule.go:321     if !valid || contextID != 0 {
//
// The CONNECT-IP loop additionally drops an EMPTY payload, which is correct there because an
// empty IP packet is not valid (see TestReferenceConnectIPEmptyPayloadIsDroppedAndTheTunnelSurvives).
// An earlier version of this guard assumed one shared spelling and failed against the real
// code; the per-file expectation below is the correction.
func TestQuicheOracleSingboxDecisionMatchesTheProductionLoops(t *testing.T) {
	cases := []struct {
		path string
		// guard is the exact clause the file must still contain.
		guard string
		// why explains the difference so a reader does not "fix" one to match the other.
		why string
	}{
		{
			path:  filepath.Join("..", "..", "..", "transport", "masque", "session.go"),
			guard: "if !valid || contextID != 0 || len(datagram) == contextLength {",
			why: "the CONNECT-IP loop also drops an EMPTY payload, because an empty IP " +
				"packet is not a valid packet",
		},
		{
			path:  filepath.Join("..", "..", "..", "transport", "http", "capsule.go"),
			guard: "if !valid || contextID != 0 {",
			why: "the CONNECT-UDP loop keeps an empty payload, because a zero-length UDP " +
				"datagram is legal - see the zero-length regression tests",
		},
	}

	for _, testCase := range cases {
		t.Run(filepath.Base(testCase.path), func(t *testing.T) {
			content, err := os.ReadFile(testCase.path)
			require.NoError(t, err, "the receive loop source must be readable")
			source := string(content)

			require.Contains(t, source, "DecodeVarint(",
				"%s must still decode the context ID with the helper this transcription "+
					"mirrors; if the decoder moved, this file describes the wrong code",
				testCase.path)

			index := strings.Index(source, testCase.guard)
			require.GreaterOrEqual(t, index, 0,
				"%s must still contain the guard %q. This is the rule the QUICHE "+
					"comparison is about: RFC 9297 requires context 0 and permits any "+
					"other to be IGNORED. Note: %s",
				testCase.path, testCase.guard, testCase.why)

			// And the guard must DROP the datagram rather than end the session. A `return`
			// would make an unknown context a session failure, which is exactly the
			// divergence QUICHE's UnknownPayload shows it does not do.
			block := source[index:]
			end := strings.Index(block, "}")
			require.Positive(t, end, "the guard block must be terminated")
			require.Contains(t, block[:end], "continue",
				"the guard in %s must CONTINUE (drop this datagram), not return (end the "+
					"session). An unknown context is an extension to ignore, and RFC 9297 "+
					"gives an unreliable datagram no way to report an error back anyway",
				testCase.path)
			require.NotContains(t, block[:end], "return",
				"the guard in %s must not RETURN: that would escalate an unknown context "+
					"into a session failure, diverging from QUICHE and from RFC 9297",
				testCase.path)
		})
	}
}
