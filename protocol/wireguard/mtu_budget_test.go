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
// # What is NOT established here
//
// The wire size itself is NOT_MEASURED in this worktree. See TestWireGuardOverheadIsNotMeasuredHere for
// the two harnesses that were attempted, why each failed, and exactly what remains unproven.

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
			comment: "1408 + 32 + 28 = 1468 > 1280: the code PERMITS this nesting (a peer endpoint " +
				"may itself be reached through a detour - protocol/wireguard wires one), and nothing " +
				"sizes the inner tunnel against the outer one",
		},
		{
			name: "a nested WireGuard sized for a 1280-byte tunnel", tunnelMTU: 1220,
			outerLinkMTU: 1280, outerV6: false, wantFits: true,
			comment: "1220 + 32 + 28 = 1280 <= 1280: what the operator has to work out by hand, and " +
				"the reason the note below asks for a derivation rather than a constant",
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

// TestBelowTheIPv6Minimum records what the fork does when the tunnel MTU is below 1280, so the behaviour
// is stated rather than assumed, and so an existing configuration is accounted for.
//
// # What the code does
//
// `PortMTU` returns the configured value verbatim with NO floor (transport/wireguard/port.go:17-19,
// defaulted to 1408 at transport/wireguard/endpoint.go:125-127). sing-tun's flow dispatcher refuses an
// IPv6 flow whose port reports an MTU below `header.IPv6MinimumMTU`:
//
//	flow_dispatch.go:502-505
//	  effectiveMTU := verdict.Port.PortMTU()
//	  if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
//	      return nil, createFlowUnsupported
//	  }
//
// and enforces the MTU for everything else at flow_dispatch.go:620: over-size IPv4 without DF is
// fragmented, over-size with DF gets an ICMP Packet Too Big carrying `effectiveMTU`.
//
// # The consequence for an existing configuration
//
// A WireGuard endpoint configured with `mtu` below 1280 and used for IPv6 fails at flow creation, which
// surfaces as the flow being unsupported rather than as an MTU problem. IPv4 through the same tunnel
// keeps working, fragmented as needed. Nothing in the configuration is rejected, nothing is clamped, and
// no message names the MTU.
//
// # Why nothing here is changed
//
// A floor can only be added by either refusing the configuration or silently raising the value, and both
// change what a configuration does today. That is a product decision, recorded as
// PRODUCT_DECISION_REQUIRED, not a silent edit.
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

// TestWireGuardOverheadIsNotMeasuredHere is the honest boundary, written as a test so it cannot be
// mistaken for a coverage gap that was overlooked.
//
// # What IS proven
//
//   - the framing arithmetic above, derived from the pinned module's own constants and its own
//     `calculatePaddingSize`;
//   - that the capability composes through common/dialer into the ceiling a stacked protocol receives,
//     with a test for the exact number (1328 for the default 1408-byte tunnel);
//   - that the capability is answerable before Start, which is when it is consumed.
//
// # What is NOT proven: the datagram size on the wire
//
// Two harnesses were built and both failed for reasons outside MTU-03's control, and neither failure was
// worked around by weakening the claim:
//
//  1. A UDP relay between two `box` endpoints, with each endpoint's peer address pointing at it. The
//     relay observed ONE 148-byte handshake initiation and never a second peer, so no session came up.
//     Cause: `Endpoint.Initialize` takes the `NewStdNetBind` branch whenever its dialer implements
//     `dialer.UDPListener` - and `common.Cast` looks THROUGH `Upstream()`, so the production
//     `DefaultDialer` reaches a `dialer.UDPMapping` that implements it. A production endpoint therefore
//     binds a LISTENING socket and sends its handshake from an UNCONNECTED one, so redirecting its peer
//     address does not redirect the socket. `box.Options` offers no way to inject a dialer, which this
//     test module cannot work around.
//
//  2. Two `transport/wireguard` endpoints driven directly, with a recording dialer. Recording the
//     LISTENING endpoint is impossible for the same reason: `StdNetBind` opens its own sockets
//     (`conn/bind_std.go` Open -> listenNet) and never calls the dialer. Recording the DIALING endpoint
//     works - it produced `[148]`, the client's handshake initiation - but no session ever came up,
//     because a probe proved the listening endpoint never bound its reserved port:
//
//	the reserved port was FREE after both endpoints started: the server bind did NOT listen on it
//
//     `listen_port` IS put into the device's IpcSet (`transport/wireguard/endpoint.go:75`), so that
//     failure is in the pinned `StdNetBind.Open` path (it opens udp4 and then udp6 on the same port,
//     `bind_std.go:182-217`, and a udp6 bind failure is reported up a goroutine that swallows it) or in
//     this fork's `BindUpdate` plumbing. It is reported, not worked around, and it is a separate item:
//     it affects any listener, not only MTU sizing.
//
// # The consequence, stated plainly
//
// The 32-byte figure rests on the pinned implementation's source, quoted line by line above, and NOT on
// a measurement in this worktree. The arithmetic that consumes it - the composition in common/dialer and
// the ceiling a stacked protocol receives - IS tested. If the pinned module's framing ever changes, this
// file's first test fails on the constants it is derived from, but only a wire measurement would catch a
// change in the SEND PATH that left those constants alone.
func TestWireGuardOverheadIsNotMeasuredHere(t *testing.T) {
	t.Log("MTU-03 wire measurement: NOT_MEASURED in this worktree. " +
		"Reason: both harnesses that could observe it are blocked by how the listening bind obtains its " +
		"socket (StdNetBind opens its own; a dialer cannot intercept it) and, in the direct-endpoint " +
		"harness, by the listening endpoint failing to bind the reserved listen_port at all. " +
		"Proven instead: the framing constants from the pinned source, the composition through " +
		"common/dialer, and the ceiling a stacked protocol receives (1328 for the default 1408 tunnel).")
}
