package rule

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

// TestRuleActionSniffRegistersWireGuard pins the wiring of the named sniffer path.
//
// route.defaultPacketSniffers is only used when a sniff action lists no names. A config that does
// list names takes this path, and because build() walks the user's list in order, registration has
// to be correct here too or LX 078 survives in exactly the configs that asked for BitTorrent.
func TestRuleActionSniffRegistersWireGuard(t *testing.T) {
	t.Parallel()

	initiation := make([]byte, 148)
	initiation[0] = 1
	for i := 4; i < len(initiation); i++ {
		initiation[i] = byte(i*7 + 11)
	}

	utpPacket, err := hex.DecodeString("21001ecb6817f2805d044fd700100000dbd03029")
	require.NoError(t, err)

	cases := []struct {
		name         string
		snifferNames []string
	}{
		{"wireguard alone", []string{C.ProtocolWireGuard}},
		{"wireguard before bittorrent", []string{C.ProtocolWireGuard, C.ProtocolBitTorrent}},
		{"bittorrent before wireguard", []string{C.ProtocolBitTorrent, C.ProtocolWireGuard}},
		{"bittorrent alone", []string{C.ProtocolBitTorrent}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			action := &RuleActionSniff{SnifferNames: testCase.snifferNames}
			require.NoError(t, action.build())
			require.NotEmpty(t, action.PacketSniffers)

			// WireGuard must come before UTP in the assembled list, whichever order the names were
			// written in and whether or not "wireguard" was named at all.
			wireGuardIndex := -1
			utpIndex := -1
			for index, sniffer := range action.PacketSniffers {
				pointer := reflect.ValueOf(sniffer).Pointer()
				switch pointer {
				case reflect.ValueOf(sniff.WireGuard).Pointer():
					if wireGuardIndex == -1 {
						wireGuardIndex = index
					}
				case reflect.ValueOf(sniff.UTP).Pointer():
					if utpIndex == -1 {
						utpIndex = index
					}
				}
			}
			require.NotEqual(t, -1, wireGuardIndex, "WireGuard must be registered")
			if utpIndex != -1 {
				require.Less(t, wireGuardIndex, utpIndex, "WireGuard must precede UTP")
			}

			var metadata adapter.InboundContext
			require.NoError(t, sniff.PeekPacket(context.Background(), &metadata, initiation, action.PacketSniffers...))
			require.Equal(t, C.ProtocolWireGuard, metadata.Protocol)
			require.NotEqual(t, C.ProtocolBitTorrent, metadata.Protocol)

			// The uTP control only applies when the config actually asked for BitTorrent; with
			// only "wireguard" named there is no sniffer that should claim the uTP packet.
			if utpIndex == -1 {
				return
			}
			var utpMetadata adapter.InboundContext
			require.NoError(t, sniff.PeekPacket(context.Background(), &utpMetadata, utpPacket, action.PacketSniffers...))
			require.Equal(t, C.ProtocolBitTorrent, utpMetadata.Protocol)
		})
	}
}
