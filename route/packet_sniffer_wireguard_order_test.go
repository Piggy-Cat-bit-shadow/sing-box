package route

import (
	"context"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// wireGuardSnifferTestInitiation builds the exact packet shape from LX 078: type 1, the three
// reserved bytes left zero, and a deterministic body. The body is a counter so a failure is
// reproducible, and because the sniffer must never look at it.
func wireGuardSnifferTestInitiation() []byte {
	packet := make([]byte, 148)
	packet[0] = 1
	for i := 4; i < len(packet); i++ {
		packet[i] = byte(i*7 + 11)
	}
	return packet
}

// TestDefaultPacketSniffersClassifyWireGuardBeforeUTP exercises the registered list itself rather
// than a copy of it.
//
// This is the end-to-end pipeline the route layer runs on every datagram, so it is the only
// assertion that can catch a future edit that reorders defaultPacketSniffers or drops WireGuard
// from it. PeekPacket returns on the first match, which makes the outcome a direct read-out of
// the ordering: with WireGuard absent the same packet comes back as BitTorrent.
func TestDefaultPacketSniffersClassifyWireGuardBeforeUTP(t *testing.T) {
	t.Parallel()

	initiation := wireGuardSnifferTestInitiation()
	require.Len(t, defaultPacketSniffers, 8)
	require.Len(t, initiation, 148)

	var metadata adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(context.Background(), &metadata, initiation, defaultPacketSniffers...))
	require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)
	require.NotEqual(t, C.ProtocolBitTorrent, metadata.Protocol)

	// The control: without WireGuard in the list the very same packet is BitTorrent, which is the
	// pre-fix behaviour and the reason the new entry has to come first. The entry is identified by
	// function pointer because PacketSniffer is one opaque func type with no comparable name.
	wireGuardPointer := reflect.ValueOf(sniff.WireGuard).Pointer()
	withoutWireGuard := make([]sniff.PacketSniffer, 0, len(defaultPacketSniffers))
	for _, sniffer := range defaultPacketSniffers {
		if reflect.ValueOf(sniffer).Pointer() == wireGuardPointer {
			continue
		}
		withoutWireGuard = append(withoutWireGuard, sniffer)
	}
	require.Len(t, withoutWireGuard, len(defaultPacketSniffers)-1)
	var controlMetadata adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(context.Background(), &controlMetadata, initiation, withoutWireGuard...))
	require.Equal(t, C.ProtocolBitTorrent, controlMetadata.Protocol)
}

// TestDefaultPacketSniffersStillClassifyBitTorrent guards the other direction of the LX 078 fix.
//
// A uTP data packet begins with the same 0x01 nibble pair as a WireGuard initiation. If the
// WireGuard entry had been placed first with a looser check, this packet - a real 148-byte uTP
// data packet with a non-zero connection id - would be stolen from BitTorrent, trading one false
// positive for a worse one.
func TestDefaultPacketSniffersStillClassifyBitTorrent(t *testing.T) {
	t.Parallel()

	utpData := make([]byte, 148)
	utpData[0] = 1 // version 1, type 0 (ST_DATA)
	utpData[3] = 0x41
	utpData[19] = 0x2a

	var metadata adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(context.Background(), &metadata, utpData, defaultPacketSniffers...))
	require.Equal(t, C.ProtocolBitTorrent, metadata.Protocol)

	udpTracker, err := hex.DecodeString("00000417271019800000000078e90560")
	require.NoError(t, err)
	var trackerMetadata adapter.InboundContext
	require.NoError(t, sniff.PeekPacket(context.Background(), &trackerMetadata, udpTracker, defaultPacketSniffers...))
	require.Equal(t, C.ProtocolBitTorrent, trackerMetadata.Protocol)
}
