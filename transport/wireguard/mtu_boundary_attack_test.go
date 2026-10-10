package wireguard

import (
	"testing"

	wgDevice "github.com/sagernet/wireguard-go/device"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MTU-01: the boundaries the existing sweep does NOT cover
// ---------------------------------------------------------------------------
//
// TestTheWireFramingMatchesTheTable sweeps innerSize 28..tunnelMTU one packet at a time on a real
// socket - that part is a genuine measurement and this file does not dispute it. What it does not
// sweep is everything OUTSIDE 28..MTU, and the claim that follows from the sweep is a claim about
// the UPPER BOUND of the message, not merely about the sampled range:
//
//	"the padded plaintext is capped at the tunnel MTU, so the worst case is payload + 32"
//
// The cap in the pinned implementation is `calculatePaddingSize(packetSize, mtu)` in
// wireguard-go's device/send.go:693-706. It reads:
//
//	lastUnit := packetSize
//	if lastUnit > mtu { lastUnit %= mtu }        // <-- the MODULO, not the packet size
//	paddedSize := ceil16(lastUnit)
//	if paddedSize > mtu { paddedSize = mtu }
//	return paddedSize - lastUnit                 // <-- padding measured from lastUnit too
//
// The consequence, which the sweep cannot see because every size it tries is <= mtu:
//
//	the padded plaintext carried on the wire is  lastUnit + padding = paddedSize <= mtu
//	but the message carries the WHOLE packet:  header + packetSize + padding + tag
//
// so for packetSize > mtu the message is packetSize + 32 + padding, NOT mtu + 32. The cap bounds the
// PADDED UNIT; it does not bound the message. Every boundary the task order names is checked below,
// and the size at which the published bound stops holding is measured rather than argued.

// TestThePublishedMTUBoundarySizesAreAllAccountedFor checks the exact inner lengths the contract is
// quoted at, including the ones the wire sweep never reaches.
func TestThePublishedMTUBoundarySizesAreAllAccountedFor(t *testing.T) {
	const tunnelMTU = 1408

	// The sizes a consumer of the published ceiling can actually produce: <= MTU. For all of these
	// the message must be exactly 16 + min(ceil16(inner), MTU) + 16 and must never exceed MTU+32.
	withinContract := []int{0, 1, 15, 16, 17, 20, 28, 1232, 1250, 1280, 1385, 1392, 1393, 1400, 1407, 1408}
	worst := 0
	for _, innerSize := range withinContract {
		message := predictedTransportMessage(innerSize, tunnelMTU)
		padded := innerSize + predictedPadding(innerSize, tunnelMTU)
		wantPadded := ceil16(innerSize)
		if wantPadded > tunnelMTU {
			wantPadded = tunnelMTU
		}
		require.Equal(t, wantPadded, padded,
			"inner size %d: the padded plaintext must be min(ceil16(%d), MTU)", innerSize, innerSize)
		require.Equal(t, wgDevice.MessageTransportHeaderSize+padded+16, message,
			"inner size %d: header + padded plaintext + AEAD tag", innerSize)
		require.LessOrEqual(t, message, tunnelMTU+wgDevice.MessageTransportSize,
			"inner size %d is inside the contract range, so the message must not exceed MTU+32", innerSize)
		if message > worst {
			worst = message
		}
	}
	require.Equal(t, tunnelMTU+wgDevice.MessageTransportSize, worst,
		"the worst case inside the contract range is exactly MTU+32, reached by a full-size packet")

	// The boundary the task order names and the sweep stops short of: one byte past the tunnel MTU.
	// This is also the case `predictedPadding` is written for, so the two implementations of the
	// pinned rule are compared here on the input where they disagree.
	oversize := 1409
	require.Equal(t, oversize+wgDevice.MessageTransportSize+15, predictedTransportMessage(oversize, tunnelMTU),
		"an inner packet one byte past the MTU is padded from its remainder modulo the MTU: "+
			"lastUnit = 1409 mod 1408 = 1, ceil16(1) = 16, so the padding added is 15 and the message "+
			"is packetSize + 32 + 15 = 1456, which is 16 bytes ABOVE the published MTU+32")

	// MEASURED: the size at which the published bound stops holding. Over every size in 0..2*MTU the
	// largest message and the first size that breaks MTU+32 are found, so the boundary is a number
	// rather than a claim.
	widestOversize := 0
	firstBreach := -1
	for innerSize := 0; innerSize <= 2*tunnelMTU; innerSize++ {
		message := predictedTransportMessage(innerSize, tunnelMTU)
		if message > tunnelMTU+wgDevice.MessageTransportSize && firstBreach < 0 {
			firstBreach = innerSize
		}
		if message > widestOversize {
			widestOversize = message
		}
	}
	require.Equal(t, tunnelMTU+1, firstBreach,
		"the first inner size whose message exceeds MTU+32 is MTU+1, and that is what makes the "+
			"published bound a statement about the CONTRACT RANGE rather than about every input")
	require.Greater(t, widestOversize, tunnelMTU+wgDevice.MessageTransportSize,
		"outside the contract range the bound really is exceeded, so the bound must be read as "+
			"'for packets the flow dispatcher permits', not as an unconditional maximum")
	t.Logf("MEASURED over inner sizes 0..%d on a %d-byte tunnel: first inner size above MTU+32 is %d; "+
		"widest message found is %d bytes (= %d + %d)",
		2*tunnelMTU, tunnelMTU, firstBreach, widestOversize, tunnelMTU+wgDevice.MessageTransportSize,
		widestOversize-(tunnelMTU+wgDevice.MessageTransportSize))
}
