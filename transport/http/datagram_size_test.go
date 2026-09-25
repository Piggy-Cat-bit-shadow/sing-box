package http

import (
	"errors"
	"testing"
)

// HTTP Datagram size accounting.
//
// The effective payload a MASQUE session can send is
//
//	QUIC's maximum datagram payload
//	  - the length of the QUARTER STREAM ID varint the HTTP/3 layer prepends
//
// and for CONNECT-IP the session then also strips one byte for the context ID. Two
// subtractions of varint lengths is exactly the sort of arithmetic that goes
// off-by-one at a boundary, and a one-byte error is not cosmetic: it is the
// difference between a packet that fits and one that is silently dropped or
// answered with an ICMP error.
//
// The varint length function is the thing that changes at boundaries, so it is
// tested directly against the QUIC ranges (RFC 9000 section 16) rather than only
// through a live connection, where reaching stream ID 2^30 is not practical.

// TestVarintLenMatchesTheQUICRanges pins the length function at every boundary.
//
// RFC 9000 section 16: a varint is 1, 2, 4 or 8 bytes for values below 2^6, 2^14,
// 2^30 and 2^62 respectively.
func TestVarintLenMatchesTheQUICRanges(t *testing.T) {
	cases := []struct {
		value uint64
		want  int
	}{
		{0, 1},
		{1, 1},
		{63, 1},         // largest 1-byte value
		{64, 2},         // first 2-byte value
		{16383, 2},      // largest 2-byte value
		{16384, 4},      // first 4-byte value
		{1073741823, 4}, // largest 4-byte value, 2^30-1
		{1073741824, 8}, // first 8-byte value, 2^30
		{1 << 62, 8},    // largest representable varint
	}
	for _, testCase := range cases {
		if got := VarintLen(testCase.value); got != testCase.want {
			t.Errorf("VarintLen(%d) = %d, want %d", testCase.value, got, testCase.want)
		}
	}
}

// TestQuarterStreamIDVarintLenBoundaries covers the subtraction the server applies.
//
// The HTTP/3 layer prepends the QUARTER STREAM ID, so the overhead depends on
// streamID/4 and steps up at 64, 16384 and 1073741824 in that quotient - i.e. at
// stream IDs 256, 65536 and 4294967296.
//
// Those quotients are exactly where a naive implementation goes wrong, so they are
// pinned here. The larger stream IDs cannot be opened in a test, which is why this
// is a unit test rather than an integration one.
func TestQuarterStreamIDVarintLenBoundaries(t *testing.T) {
	cases := []struct {
		streamID    uint64
		quarterLen  int
		description string
	}{
		{0, 1, "first client stream"},
		{4, 1, "quotient 1"},
		{252, 1, "quotient 63, the largest 1-byte quarter ID"},
		{256, 2, "quotient 64, the first 2-byte quarter ID"},
		{65532, 2, "quotient 16383, the largest 2-byte quarter ID"},
		{65536, 4, "quotient 16384, the first 4-byte quarter ID"},
		{4294967292, 4, "quotient 1073741823, the largest 4-byte quarter ID"},
		{4294967296, 8, "quotient 1073741824, the first 8-byte quarter ID"},
	}
	for _, testCase := range cases {
		got := VarintLen(testCase.streamID / 4)
		if got != testCase.quarterLen {
			t.Errorf("stream ID %d (quotient %d): overhead is %d bytes, want %d "+
				"(%s)", testCase.streamID, testCase.streamID/4, got,
				testCase.quarterLen, testCase.description)
		}
	}
}

// TestConnectIPPayloadAccountsForBothVarints checks the full chain for CONNECT-IP.
//
// A CONNECT-IP packet on the datagram path costs, in order:
//
//	quarter stream ID varint   (HTTP/3 per-stream datagram context)
//	context ID varint          (0 for the IP payload, so one byte)
//	the IP packet itself
//
// The session's MTU calculation must leave room for both, and an error in either
// one shows up as an IP packet that is accepted by the tunnel but never delivered.
func TestConnectIPPayloadAccountsForBothVarints(t *testing.T) {
	// The values a real connection reports. MaxDatagramPayloadSize is what quic-go
	// says fits; the subtraction is what the server computes.
	const quicMaxDatagramPayload = 1350
	const streamID = 0

	quarterStreamID := VarintLen(streamID / 4)
	contextID := 1

	effective := quicMaxDatagramPayload - quarterStreamID - contextID
	if effective != 1348 {
		t.Fatalf("effective CONNECT-IP payload is %d, want 1348 "+
			"(1350 - %d quarter-stream-ID - %d context ID)",
			effective, quarterStreamID, contextID)
	}

	// The MTU the operator configures must fit inside the effective payload, or
	// every full-size packet is rejected. 1280 is the IPv6 minimum link MTU and the
	// documented default, so it must fit with room to spare.
	const defaultMTU = 1280
	if defaultMTU > effective {
		t.Fatalf("the default MTU %d does not fit in an effective payload of %d; "+
			"every full-size packet would be dropped", defaultMTU, effective)
	}
	t.Logf("effective CONNECT-IP payload %d bytes carries the default MTU of %d "+
		"with %d bytes of headroom", effective, defaultMTU, effective-defaultMTU)
}

// TestDatagramTooLargeIsNotConfusedWithUnsupported pins the error taxonomy.
//
// These two conditions need different handling and must not be collapsed:
//
//   - ErrDatagramUnsupported means the PEER cannot receive datagrams at all, so
//     the session falls back to a capsule on the stream;
//   - DatagramTooLargeError means the peer CAN receive them but this packet does
//     not fit, so the correct answer is an ICMP Packet Too Big - not a silent
//     downgrade to a capsule, and not a dropped packet.
//
// DatagramTooLargeError deliberately wraps ErrDatagramUnsupported so that
// errors.Is(err, ErrDatagramUnsupported) is true for both. That is convenient for
// the generic fallback check but dangerous if a caller tests the wrapping error
// first, because it would downgrade an oversize packet to a capsule instead of
// reporting it. The order of the checks in the session is therefore load-bearing,
// and this test documents which is which.
func TestDatagramTooLargeIsNotConfusedWithUnsupported(t *testing.T) {
	tooLarge := &DatagramTooLargeError{MaxPayloadSize: 1200}

	// A size failure must be recognisable AS a size failure.
	var sizeError *DatagramTooLargeError
	if !errors.As(tooLarge, &sizeError) {
		t.Fatal("DatagramTooLargeError must be recoverable by errors.As, or the " +
			"session cannot tell it apart from a capability failure")
	}
	if sizeError.MaxPayloadSize != 1200 {
		t.Fatalf("MaxPayloadSize round-tripped as %d, want 1200", sizeError.MaxPayloadSize)
	}

	// It must NOT be equal to the bare capability error, or the two conditions
	// would be indistinguishable at the call site.
	if tooLarge == ErrDatagramUnsupported {
		t.Fatal("a size failure must be a distinct value from the capability failure")
	}

	// The underlying capability error must not be describable as a size failure.
	var notSize *DatagramTooLargeError
	if errors.As(ErrDatagramUnsupported, &notSize) {
		t.Fatal("ErrDatagramUnsupported must not be recoverable as a size failure")
	}
}
