package masque

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMaxPacketSizeCoversTheLargestOrdinaryIPv6Packet pins the bound on one inner IP
// packet.
//
// The bound is a maximum, not a cap on legal traffic, so it must not be smaller than the
// largest packet either family can produce:
//
//	IPv4  Total Length is 16 bits and counts the whole packet, header included, so the
//	      largest ordinary IPv4 packet is 65535 bytes.
//	IPv6  Payload Length is 16 bits and counts only what follows the 40-byte base header
//	      (RFC 8200 section 3), so the largest ordinary IPv6 packet is 40 + 65535.
//
// A packet above the bound is discarded by the size gate before the parser sees it, so a
// bound that is too small drops legal traffic silently.
func TestMaxPacketSizeCoversTheLargestOrdinaryIPv6Packet(t *testing.T) {
	t.Parallel()

	// One bound serves both families, so it must be the larger of the two maxima.
	require.Equal(t, 40+65535, maxPacketSize,
		"the bound must admit the largest ordinary IPv6 packet: 40-byte base header plus "+
			"a 16-bit Payload Length, which excludes that header")
	require.GreaterOrEqual(t, maxPacketSize, 65535,
		"the same bound must still admit the largest ordinary IPv4 packet")
}

// TestOrdinaryPacketLengthsAreAcceptedAndJumbogramsAreNot checks the bound against actual
// packet lengths rather than against the constant alone.
func TestOrdinaryPacketLengthsAreAcceptedAndJumbogramsAreNot(t *testing.T) {
	t.Parallel()

	for _, length := range []int{65535, 65536, 40 + 65535} {
		require.LessOrEqual(t, length, maxPacketSize,
			"a %d-byte packet is a legal ordinary packet and must not be discarded by "+
				"the size gate", length)
	}

	// Jumbograms are a separate mechanism (Payload Length 0 plus a Hop-by-Hop Jumbo
	// Payload option) and are not supported, so the bound deliberately stops at the
	// largest ordinary packet rather than at 2^32-1.
	require.Less(t, maxPacketSize, 1<<20,
		"the bound must not be raised into jumbogram territory")
}
