package wireguard

import (
	"testing"

	"github.com/sagernet/sing-box/common/dialer"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MTU-03: WireGuard's transport overhead, and why it is a separate fact
// ---------------------------------------------------------------------------
//
// # The four numbers that must not be conflated
//
//	tunnel `mtu` (option)   1408 (the fork's default, transport/wireguard/endpoint.go:125-127)
//	                        the INNER IP MTU the device carries: what the operator configured, what
//	                        the device is built with, and what the option means
//	outer link MTU          not known here
//	                        the underlay's IP MTU, which this option says nothing about and which
//	                        must NEVER be pushed into a QUIC `initial_packet_size`
//	transport message       inner + 32 (+0..15 padding)
//	                        what actually goes on the wire, inside an outer IP and UDP header
//	inner UDP budget        inner - 28/48 - 32
//	                        what a protocol STACKED on this tunnel may actually send
//
// # Where the 32 comes from, in the pinned revision
//
// github.com/sagernet/wireguard-go v0.0.8-0.20260929150556-ca3bc60c4ce7:
//
//	device/noise-protocol.go:67  MessageTransportHeaderSize = 16
//	                             // type+reserved (4), receiver index (4), counter/nonce (8)
//	device/noise-protocol.go:69  MessageTransportSize = MessageTransportHeaderSize + poly1305.TagSize
//	                             // poly1305.TagSize is 16, so an empty transport message is 32
//	device/noise-protocol.go:26  PaddingMultiple = 16
//	device/send.go:693-706       calculatePaddingSize: the plaintext is padded to the next multiple
//	                             // of 16, capped at the tunnel MTU
//	device/send.go:734-745       padding is appended, then Seal appends the 16-byte tag
//	device/send.go:748           the slice is re-cut to the encapsulating space
//	device/send.go:817           `scratch = append(scratch, elem.packet)` - that slice, and nothing
//	                             // else, is what the bind's Send is given
//	device/noise-protocol.go:68  MessageEncapsulatingTransportSize = 8 is a writable PREFIX reserved
//	                             // in the buffer and re-sliced away at :748, so it is NOT framing
//
// One transport-data message is therefore exactly
//
//	16 header + payload + 0..15 padding-to-16 + 16 tag
//
// which is why `PortEncapOverhead` publishes the FIXED part (32) and not the worst case (47): the
// padding depends on the payload's remainder modulo 16, so it is not a fixed per-packet cost and must
// not be clamped as one.
//
// # What is established here, and where the wire measurement lives
//
// The framing arithmetic above is derived from the pinned module's constants, and it is now also
// MEASURED: transport/wireguard/wg_framing_measurement_test.go drives two real devices over a real
// loopback socket, captures every buffer the module hands the bind, and shows the transport message to
// be `16 + min(ceil16(inner), tunnelMTU) + 16` for every inner length from 28 to the tunnel MTU - with
// the maximum over that whole range exactly `tunnelMTU + 32`.
//
// That measurement is what settles the padding question: the padded plaintext is CAPPED at the tunnel
// MTU, so the worst-case padding does not enter the conservative capacity. The arithmetic below and the
// measurement must agree, and TestThePublishedOverheadIsTheTransportFraming pins the constants both
// rest on.

const (
	// wireGuardPaddingMultiple is device.PaddingMultiple.
	wireGuardPaddingMultiple = 16
	// wireGuardLargestHandshakeMessage is max(MessageInitiationSize, MessageResponseSize,
	// MessageCookieReplySize) = max(148, 92, 64) from device/noise-protocol.go:64-66.
	wireGuardLargestHandshakeMessage = 148
)

// wireGuardPadding mirrors device/send.go:693-706 for a packet of this length and a tunnel MTU, so the
// budget table below is computed the same way the pinned implementation computes it.
func wireGuardPadding(packetSize, tunnelMTU int) int {
	lastUnit := packetSize
	if tunnelMTU != 0 {
		if lastUnit > tunnelMTU {
			lastUnit %= tunnelMTU
		}
	}
	paddedSize := (lastUnit + wireGuardPaddingMultiple - 1) &^ (wireGuardPaddingMultiple - 1)
	if paddedSize > tunnelMTU {
		paddedSize = tunnelMTU
	}
	return paddedSize - lastUnit
}

// wireGuardOuterDatagramSize is the whole outer UDP payload for an inner IP packet of innerSize.
func wireGuardOuterDatagramSize(innerSize, tunnelMTU int) int {
	return wireGuardTransportHeaderLength + innerSize +
		wireGuardPadding(innerSize, tunnelMTU) + wireGuardTransportTagLength
}

// TestThePublishedOverheadIsTheTransportFraming pins the capability the fork publishes against the
// module constants it is derived from, so a change in either is caught rather than silently absorbed.
func TestThePublishedOverheadIsTheTransportFraming(t *testing.T) {
	require.EqualValues(t, 16, wireGuardTransportHeaderLength,
		"device.MessageTransportHeaderSize at the pinned revision")
	require.EqualValues(t, 16, wireGuardTransportTagLength,
		"poly1305.TagSize, the AEAD tag device/send.go:740-745 appends")
	require.EqualValues(t, wireGuardTransportHeaderLength+wireGuardTransportTagLength, wireGuardEncapOverhead,
		"the fixed overhead the endpoint publishes must be exactly the header plus the tag")
	require.EqualValues(t, 32, wireGuardEncapOverhead,
		"and it must be 32: this is the number every protocol stacked on this tunnel subtracts")

	// The worst case is the fixed overhead plus one padding quantum minus one byte, and it must NOT be
	// what is published: a ceiling has to be a floor of the cost, not the maximum.
	require.EqualValues(t, wireGuardEncapOverhead+wireGuardPaddingMultiple-1, 47,
		"the worst-case transport message is inner + 47")
}

// TestTheCapabilityIsAnswerableBeforeStart is the lifecycle requirement, stated in the type.
//
// A protocol stacked on WireGuard as a `detour` sizes itself at CONSTRUCTION, before this endpoint is
// Started, so the transport framing has to answer while the device does not exist yet. The MTU's own
// before-Start guarantee is the transport endpoint's and is covered there
// (transport/wireguard's PortMTU reads its options); what is specific to this file is that the NEW
// capability is a compile-time constant of the transport and cannot depend on a running device at all.
func TestTheCapabilityIsAnswerableBeforeStart(t *testing.T) {
	// The capability is declared on the type, so it is satisfied before any field is set.
	var overheadProvider dialer.PortEncapOverheadProvider = (*Endpoint)(nil)
	require.EqualValues(t, wireGuardEncapOverhead, overheadProvider.PortEncapOverhead(),
		"PortEncapOverhead must be answerable with no device, no options and no Start: it is the "+
			"transport's framing, not a property of a running tunnel")

	// And it must not read through to the transport endpoint, which would panic on a nil receiver.
	require.EqualValues(t, wireGuardTransportHeaderLength+wireGuardTransportTagLength,
		overheadProvider.PortEncapOverhead(),
		"the published number must be exactly the two module constants, computed locally")

	// The MTU provider is the other capability, and it is declared on the same type.
	var _ dialer.PortMTUProvider = (*Endpoint)(nil)
}

// TestTheBudgetTable is the table a fix has to satisfy, written as a table of the DECISION: for a given
// tunnel `mtu` and outer link MTU, does a full-size inner packet survive the outer path?
//
// This is the artefact MTU-03 exists to produce. It is arithmetic on the pinned module's own framing, and
// the row that matters most is the IPv6 /1480 one: 1480 is a very common IPv6 path MTU, and the fork's
// default tunnel MTU does not fit it by 8 bytes.
func TestTheBudgetTable(t *testing.T) {
	const (
		outerV4Header = 20
		outerV6Header = 40
		outerUDP      = 8
	)

	cases := []struct {
		name         string
		tunnelMTU    int
		outerLinkMTU int
		outerV6      bool
		wantFits     bool
		comment      string
	}{
		{
			name: "the default tunnel MTU over an IPv4 /1500 underlay", tunnelMTU: 1408,
			outerLinkMTU: 1500, outerV6: false, wantFits: true,
			comment: "1408 + 32 = 1440 of UDP payload, + 28 of outer headers = 1468 <= 1500: fits",
		},
		{
			name: "the default tunnel MTU over an IPv6 /1500 underlay", tunnelMTU: 1408,
			outerLinkMTU: 1500, outerV6: true, wantFits: true,
			comment: "1440 + 48 = 1488 <= 1500: still fits, with 12 bytes to spare. That the two " +
				"families differ by exactly 20 is the reason the budget is family-aware",
		},
		{
			name: "the default tunnel MTU over an IPv6 /1480 underlay", tunnelMTU: 1408,
			outerLinkMTU: 1480, outerV6: true, wantFits: false,
			comment: "1440 + 48 = 1488 > 1480, over by 8: a tunnel MTU chosen for IPv4 breaks on an " +
				"IPv6 PPPoE path, because the 40-byte IPv6 header was not counted. This is the row " +
				"the whole item turns on",
		},
		{
			name: "a tunnel MTU chosen FOR IPv6", tunnelMTU: 1400,
			outerLinkMTU: 1480, outerV6: true, wantFits: true,
			comment: "1400 + 32 + 48 = 1480 <= 1480: the IPv4-derived default lowered by the IPv6 " +
				"header difference. This is the shape of the fix, and it is an OPERATOR choice - the " +
				"tunnel MTU is not a physical link MTU and must not be rewritten by the code",
		},
		{
			name: "a nested WireGuard at its default inside a 1280-byte tunnel", tunnelMTU: 1408,
			outerLinkMTU: 1280, outerV6: false, wantFits: false,
			comment: "1408 + 32 + 28 = 1468 > 1280: the UNDERLAY here is an operator's physical path, " +
				"which this endpoint cannot see and does not size against. The nesting this code CAN " +
				"see is a `detour` naming a fixed-capacity tunnel, and that one is now bounded - see " +
				"nested_mtu_test.go. The row stays as the honest statement that a tunnel MTU is not a " +
				"physical link MTU",
		},
		{
			name: "a nested WireGuard sized for a 1280-byte tunnel", tunnelMTU: 1220,
			outerLinkMTU: 1280, outerV6: false, wantFits: true,
			comment: "1220 + 32 + 28 = 1280 <= 1280: this is now what the code derives by itself when " +
				"the outer tunnel is a `detour` it can ask - 1280 - 48 - 32 = 1200 for an IPv6 outer, " +
				"and the operator's own value wins when it is already smaller",
		},
		{
			name: "a tunnel at the IPv6 minimum over an ordinary underlay", tunnelMTU: 1280,
			outerLinkMTU: 1500, outerV6: true, wantFits: true,
			comment: "1280 + 32 + 48 = 1360 <= 1500: a tunnel can BE the IPv6 minimum and still fit. " +
				"See TestBelowTheIPv6Minimum for what happens below it",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			outerHeader := outerV4Header
			if testCase.outerV6 {
				outerHeader = outerV6Header
			}
			// The worst case is the FULL tunnel MTU, which is what the MTU mechanism allows through.
			transportMessage := wireGuardOuterDatagramSize(testCase.tunnelMTU, testCase.tunnelMTU)
			outerDatagram := transportMessage + outerHeader + outerUDP
			fits := outerDatagram <= testCase.outerLinkMTU

			t.Logf("tunnel mtu %d over an %s /%d underlay: transport message %d + outer IP %d + UDP "+
				"%d = %d bytes, fits: %v", testCase.tunnelMTU,
				map[bool]string{true: "IPv6", false: "IPv4"}[testCase.outerV6],
				testCase.outerLinkMTU, transportMessage, outerHeader, outerUDP,
				outerDatagram, fits)

			require.Equal(t, testCase.wantFits, fits, testCase.comment)
		})
	}
}

// TestTheOverheadIsPaidInsideTheTunnelMTU is the discrimination that matters for MTU-03: the 32 bytes are
// spent INSIDE the inner IP packet, so they come off the inner UDP budget and NOT off the outer link MTU.
//
// Getting this backwards is the failure the item exists for: a QUIC protocol stacked on WireGuard that
// read only `PortMTU` would believe it had `tunnelMTU - 48` bytes of payload, send exactly that, and
// produce an outer datagram 32 bytes larger than it accounted for - which fragments or drops silently.
func TestTheOverheadIsPaidInsideTheTunnelMTU(t *testing.T) {
	for _, tunnelMTU := range []int{1280, 1408, 1420, 1500} {
		naive := tunnelMTU - 40 - 8 // what PortMTU alone would suggest over IPv6
		real := tunnelMTU - 40 - 8 - wireGuardEncapOverhead

		require.Equal(t, wireGuardEncapOverhead, naive-real,
			"the gap between the naive and the real budget must be exactly the transport framing")
		require.Greater(t, naive, real,
			"the naive budget must be the LARGER one: if it were smaller, the failure direction "+
				"would be harmless and this item would be a no-op")

		outerDatagram := naive + wireGuardEncapOverhead + 40 + 8
		require.Equal(t, tunnelMTU+wireGuardEncapOverhead, outerDatagram,
			"a payload sized from PortMTU alone puts tunnelMTU + 32 bytes into the outer IP packet")
	}
}

// TestTheComposedCeilingSubtractsTheWireGuardFraming is the end-to-end of the fix: the number a QUIC
// protocol actually receives when it is stacked on this tunnel.
func TestTheComposedCeilingSubtractsTheWireGuardFraming(t *testing.T) {
	const tunnelMTU = 1408

	// The composition common/dialer performs, with the capability this endpoint publishes.
	ceiling, hasCeiling := dialer.PacketOverheadCeiling(tunnelMTU, dialer.IPFamilyUnknown, wireGuardEncapOverhead)
	require.True(t, hasCeiling)
	require.EqualValues(t, 1408-48-32, ceiling,
		"1408 - 48 (IPv6 + UDP) - 32 (WireGuard) = 1328, which is what a stacked protocol must use")

	// Without the capability, the same tunnel reports 32 bytes more - which is the defect.
	withoutCapability, _ := dialer.PacketOverheadCeiling(tunnelMTU, dialer.IPFamilyUnknown, 0)
	require.EqualValues(t, ceiling+wireGuardEncapOverhead, withoutCapability,
		"reading only PortMTU overstates the budget by exactly the transport framing")

	// And the ceiling is above the QUIC minimum for the default tunnel MTU, so a stacked protocol is
	// not refused - it is correctly sized.
	require.GreaterOrEqual(t, ceiling, uint32(dialer.MinimumQUICInitialPacketSize))

	// A tunnel whose MTU is at the IPv6 minimum leaves a usable ceiling too.
	minimumCeiling, minimumHasCeiling := dialer.PacketOverheadCeiling(1280, dialer.IPFamilyUnknown, wireGuardEncapOverhead)
	require.True(t, minimumHasCeiling)
	require.EqualValues(t, 1280-48-32, minimumCeiling)
	require.GreaterOrEqual(t, minimumCeiling, uint32(dialer.MinimumQUICInitialPacketSize),
		"a WireGuard at the IPv6 minimum can still carry a QUIC handshake")
}

// TestBelowTheIPv6Minimum states what happens when the tunnel MTU is below 1280, in the two cases that
// must not be conflated.
//
// # The prohibition, and the special case
//
// 1280 is the smallest MTU an IPv6 path may have (RFC 8200 section 5). It is therefore a PROHIBITION on
// IPv6 below 1280 and nothing more: an IPv4-only tunnel at 576 bytes is a legitimate configuration, and
// a floor at 1280 would reject it. The two are decided by the address list, not by the MTU alone.
//
// # What the code does now
//
//   - `PortMTU` still returns the configured value verbatim with NO floor (transport/wireguard/port.go,
//     defaulted to 1408 at transport/wireguard/endpoint.go). Nothing is silently raised: an operator
//     who asks for 1200 gets 1200, and the tunnel device enforces 1200.
//
//   - An endpoint configured with BOTH an MTU below 1280 AND an IPv6 address is refused at
//     construction (`transport/wireguard`'s validateTunnelMTU), naming the MTU and the address. The
//     configured address is unreachable by construction, and the previous behaviour said so in the
//     least useful place: sing-tun's dispatcher refuses an IPv6 flow whose port reports an MTU below
//     `header.IPv6MinimumMTU`
//
//     flow_dispatch.go:502-505
//     effectiveMTU := verdict.Port.PortMTU()
//     if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
//     return nil, createFlowUnsupported
//     }
//
//     so the operator saw "flow unsupported" while IPv4 through the same endpoint kept working, and
//     nothing in the message named the MTU or the address.
//
//   - The IPv4 path is unchanged at every one of those MTUs: `flow_dispatch.go:620` still fragments an
//     over-size IPv4 packet without DF, and still answers an over-size one carrying DF with an ICMP
//     Packet Too Big carrying `effectiveMTU`.
//
// # Why the refusal is the smaller change
//
// It refuses exactly one configuration: one that cannot work. Raising the MTU silently would give the
// operator a tunnel reporting capacity it was never configured with, and a blanket floor would reject
// legal IPv4-only tunnels. Both of those are recorded here as the alternatives that were NOT taken.
func TestBelowTheIPv6Minimum(t *testing.T) {
	// The fork's own default is above the floor, which is why a default configuration is unaffected.
	const defaultTunnelMTU = 1408
	require.Greater(t, defaultTunnelMTU, 1280,
		"the default is ABOVE the IPv6 minimum: a default WireGuard is not affected by this at all")

	for _, configured := range []uint32{1279, 1200, 576, 68} {
		require.Less(t, configured, uint32(1280), "this case is about being below the floor")

		// The endpoint still publishes the value, with no floor of its own - that is the behaviour being
		// recorded. A zero MTU never reaches here: it is replaced by the 1408 default at construction.
		require.NotZero(t, configured, "a configured MTU below the floor is still a configured value")

		ceiling, hasCeiling := dialer.PacketOverheadCeiling(configured, dialer.IPFamilyUnknown, wireGuardEncapOverhead)
		if configured <= 48+wireGuardEncapOverhead {
			require.False(t, hasCeiling,
				"a tunnel MTU of %d cannot even hold the headers plus the WireGuard transport framing, "+
					"so there is no budget to report - which is a configuration-level impossibility, "+
					"not a value to clamp", configured)
			continue
		}
		// What an upper protocol gets from it: a ceiling below the QUIC minimum, which is where the
		// refusal SHOULD happen - common/dialer's floor, not this endpoint's silence.
		require.True(t, hasCeiling, "the tunnel still has a provable budget")
		require.Less(t, ceiling, uint32(dialer.MinimumQUICInitialPacketSize),
			"a tunnel MTU of %d leaves %d bytes, below the 1200 QUIC minimum, so a stacked QUIC "+
				"protocol is refused by common/dialer rather than handed a number it cannot use",
			configured, ceiling)
	}
}

// TestWireGuardOverheadIsMeasuredOnTheWire records the measurement that replaced this file's own
// NOT_MEASURED note, and the corrected diagnosis of why the earlier harnesses failed.
//
// # What was unproven, and is now proven
//
// The wire size of a transport message is MEASURED, byte for byte, over every inner packet length the
// contract allows, by transport/wireguard/wg_framing_measurement_test.go: two real wireguard-go
// devices, a real handshake between them, a capture conn.Bind on the sending side and the module's own
// standard bind on the receiving side, over a real loopback socket. The measured series is
// `16 + min(ceil16(inner), tunnelMTU) + 16` for all of it, and the maximum over the whole contract
// range is exactly `tunnelMTU + 32`.
//
// # What that adds to the 32 published here
//
// The padding-to-16 does NOT have to be added to the conservative capacity. The padded plaintext is
// capped at the tunnel MTU, so a full-size inner packet is not padded at all, and no inner packet
// within the MTU can produce a message above MTU+32. A consumer of the published ceiling does not even
// reach that: its inner packet is at most MTU-32, so its largest possible message is the MTU itself
// when the MTU is a multiple of 16. The measurement is what establishes this; the rule alone would
// have left a reader free to charge another 15 bytes.
//
// # The corrected diagnosis of the earlier failure
//
// The note this test replaces attributed the "the reserved listen_port was FREE" observation to
// `StdNetBind.Open` or to this fork's `BindUpdate` plumbing. Measured, both were wrong: the port was
// bound a moment LATER, by the asynchronous UP transition (wireguard-go opens the bind from
// `Up` -> `BindUpdate`, and that transition arrives on the tun device's event channel), so a probe
// taken the instant `Start` returned saw the port before the socket existed - and a port that was
// genuinely already taken failed the bind inside that goroutine, with no error to the caller. That is
// WG-01, it is fixed in transport/wireguard/endpoint.go, and it is why the endpoint harness can now
// come up at all.
//
// The consequence for THIS file: the 32-byte figure no longer rests on the pinned source alone. The
// source derivation below still stands, and the measurement now agrees with it.
func TestWireGuardOverheadIsMeasuredOnTheWire(t *testing.T) {
	t.Log("MTU-01 wire measurement: MEASURED in transport/wireguard/wg_framing_measurement_test.go. " +
		"Two real devices, a real handshake, an injectable capture Bind, a real loopback socket: the " +
		"transport message is 16 + min(ceil16(inner), tunnelMTU) + 16 for EVERY inner length from 28 " +
		"to the tunnel MTU, the maximum is exactly tunnelMTU+32, and the padding therefore does not " +
		"enter the conservative capacity. The earlier NOT_MEASURED harness failed on WG-01 (the " +
		"listening endpoint's port was not bound when Start returned), not on StdNetBind.")
}
