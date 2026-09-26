package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

// The Packet Too Big evidence chain.
//
// When a MASQUE inner IP packet is too large for a QUIC DATAGRAM, the endpoint must
// tell the sender with an ICMP error rather than silently dropping the packet or
// retrying it as a capsule. RFC 9484 relies on that: a CONNECT-IP client learns the
// tunnel MTU from the ICMP message and shrinks its packets, which is the same feedback
// loop a real link provides. Without it a client sending a large packet gets no signal
// at all and simply loses traffic.
//
// The arithmetic the code performs, in order:
//
//	QUIC DATAGRAM limit (from quic-go's DatagramTooLargeError)
//	  minus the HTTP/3 Quarter Stream ID overhead   (transport/http/server_h3.go)
//	  minus the context ID 0 varint (1 byte)        (transport/masque/session.go)
//	  = the inner IP packet size the tunnel can carry
//
// and if the inner packet does not fit, the packet is discarded on the datagram path
// and an ICMP error is generated. It must NOT be re-sent as a capsule: RFC 9484 treats
// the two as different transports with different failure semantics, and silently
// promoting an oversized datagram to a reliable capsule would deliver a packet the
// sender was told did not fit.
//
// # What this file proves, and what it does not
//
// It proves the ICMP error GENERATION: type, code, advertised MTU and checksum, for both
// families, with the quoted original packet. The end-to-end case (a real oversized reply
// triggering this on a live HTTP/3 tunnel) is attempted separately and is NOT claimed
// here; see TestReferenceConnectIPPacketTooBigOverHTTP3.

// buildTestIPv4Packet builds a minimal but VALID IPv4 packet.
//
// "Valid" matters: sing-tun's BuildICMPError refuses to build a reply for a packet it
// cannot parse, and RFC 1122 forbids answering several classes of packet at all. A
// fixture that produced a malformed packet would fail this test for a reason that has
// nothing to do with MTU.
func buildTestIPv4Packet(t *testing.T, source netip.Addr, destination netip.Addr, payloadLength int) []byte {
	t.Helper()
	require.True(t, source.Is4() && destination.Is4())

	total := 20 + payloadLength
	require.LessOrEqual(t, total, 65535, "an IPv4 packet cannot exceed 65535 bytes")

	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234) // identification
	packet[8] = 64
	packet[9] = 17 // UDP: a protocol the ICMP rules always permit
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())

	// A minimal UDP header, so the payload is coherent rather than arbitrary bytes.
	if payloadLength >= 8 {
		binary.BigEndian.PutUint16(packet[20:22], 4242)
		binary.BigEndian.PutUint16(packet[22:24], 4243)
		binary.BigEndian.PutUint16(packet[24:26], uint16(payloadLength))
	}

	// sing-tun validates the IPv4 header checksum before building a reply, so it must be
	// correct or the error is never generated.
	ipHeader := header.IPv4(packet)
	ipHeader.SetChecksum(0)
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	return packet
}

// buildTestIPv6Packet builds a minimal but valid IPv6 packet.
func buildTestIPv6Packet(t *testing.T, source netip.Addr, destination netip.Addr, payloadLength int) []byte {
	t.Helper()
	require.True(t, source.Is6() && destination.Is6())

	total := 40 + payloadLength
	packet := make([]byte, total)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(payloadLength))
	packet[6] = 17 // UDP
	packet[7] = 64
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	if payloadLength >= 8 {
		binary.BigEndian.PutUint16(packet[40:42], 4242)
		binary.BigEndian.PutUint16(packet[42:44], 4243)
		binary.BigEndian.PutUint16(packet[44:46], uint16(payloadLength))
	}
	return packet
}

// TestPacketTooBigIPv4Shape pins the ICMPv4 Destination Unreachable / Fragmentation
// Needed message the endpoint generates.
//
// Every field is asserted, because each one is separately load-bearing for a client:
//
//	type/code   the client must recognise this as "fragmentation needed"
//	MTU         the value the client will adopt for its next packet
//	source      the endpoint's tunnel address, not the original destination
//	destination the ORIGINAL source, so the message returns to the sender
//	quoted      enough of the original packet to demultiplex the flow
func TestPacketTooBigIPv4Shape(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.2")
	gateway := netip.MustParseAddr("198.18.0.1")
	original := buildTestIPv4Packet(t, source, gateway, 1400)

	const advertisedMTU = 1280

	reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, gateway, netip.Addr{}, advertisedMTU, PacketHeadroom)
	require.True(t, built, "an ICMPv4 Fragmentation Needed must be built for a valid "+
		"oversized packet; a false here means the original was rejected as unparseable")
	defer reply.Release()

	packet := reply.Bytes()
	require.GreaterOrEqual(t, len(packet), 20+8, "the reply must carry IPv4 + ICMP headers")

	ipHeader := header.IPv4(packet)
	require.True(t, ipHeader.IsValid(len(packet)),
		"the generated IPv4 header must be self-consistent")

	// The reply travels FROM the endpoint's tunnel address TO the original sender.
	// Sending it to the original DESTINATION would be wrong: the sender is the one that
	// must learn the MTU.
	require.Equal(t, gateway, ipHeader.SourceAddr(),
		"the PTB source must be the endpoint's own tunnel address")
	require.Equal(t, source, ipHeader.DestinationAddr(),
		"the PTB destination must be the ORIGINAL SENDER, so it can shrink its packets")
	require.Equal(t, uint8(64), ipHeader.TTL(),
		"the reply must carry the synthesized TTL sing-tun uses")

	icmpHeader := header.ICMPv4(ipHeader.Payload())
	require.Equal(t, header.ICMPv4DstUnreachable, icmpHeader.Type(),
		"ICMPv4 PTB is a Destination Unreachable")
	require.Equal(t, header.ICMPv4FragmentationNeeded, icmpHeader.Code(),
		"the code must be 4 (Fragmentation Needed and DF set), which is what tells a "+
			"client to reduce its packet size")

	require.Equal(t, uint16(advertisedMTU), icmpHeader.MTU(),
		"the advertised MTU must be the value the sender is told to use")

	// The IPv4 checksum must be correct, because a receiver that validates it - which
	// every real stack does - would otherwise discard the very message meant to help it.
	verifyIPv4Checksum(t, packet)

	// The ICMP checksum must be correct for the same reason.
	verifyICMPv4Checksum(t, icmpHeader)

	// The quoted original must be present and must be the ORIGINAL packet, so the sender
	// can identify which flow was affected.
	quoted := icmpHeader.Payload()
	require.NotEmpty(t, quoted, "the ICMP error must quote the original packet")

	// A Port Unreachable or similar would have no MTU field; a Fragmentation Needed for
	// a packet that could not be parsed would have failed `built` above. Both are
	// already excluded, so this asserts the quotation is the packet we sent.
	require.Equal(t, original[:len(quoted)], quoted,
		"the quoted bytes must be a prefix of the ORIGINAL packet, not of the reply")
}

// TestPacketTooBigIPv6Shape pins the ICMPv6 Packet Too Big message.
//
// The ICMPv6 checksum covers an IPv6 pseudo-header, so a message built without it is
// silently discarded by the receiver - which for this feature means the client never
// learns the MTU and simply keeps losing packets. That makes the checksum a functional
// requirement rather than a formality, and it is verified here explicitly.
func TestPacketTooBigIPv6Shape(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::2")
	gateway := netip.MustParseAddr("2001:db8::1")
	original := buildTestIPv6Packet(t, source, gateway, 1400)

	const advertisedMTU = 1280

	reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, netip.Addr{}, gateway, advertisedMTU, PacketHeadroom)
	require.True(t, built, "an ICMPv6 Packet Too Big must be built for a valid oversized "+
		"packet")
	defer reply.Release()

	packet := reply.Bytes()
	require.GreaterOrEqual(t, len(packet), 40+8)

	ipHeader := header.IPv6(packet)
	require.True(t, ipHeader.IsValid(len(packet)),
		"the generated IPv6 header must be self-consistent")

	require.Equal(t, gateway, ipHeader.SourceAddr(),
		"the PTB source must be the endpoint's own tunnel address")
	require.Equal(t, source, ipHeader.DestinationAddr(),
		"the PTB destination must be the ORIGINAL SENDER")
	require.Equal(t, uint8(header.ICMPv6ProtocolNumber), uint8(header.IPv6(packet).NextHeader()),
		"the next header must be 58 (ICMPv6)")

	icmpHeader := header.ICMPv6(ipHeader.Payload())
	require.Equal(t, header.ICMPv6PacketTooBig, icmpHeader.Type(),
		"ICMPv6 PTB is type 2")
	require.Equal(t, header.ICMPv6UnusedCode, icmpHeader.Code(),
		"the code must be 0 (unused)")

	require.Equal(t, uint32(advertisedMTU), icmpHeader.MTU(),
		"the advertised MTU must be the value the sender is told to use")

	// The ICMPv6 checksum covers the IPv6 pseudo-header (RFC 8200 section 8.1), so it is
	// recomputed here from the packet's OWN addresses rather than assumed.
	expected := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHeader,
		Src:    ipHeader.SourceAddressSlice(),
		Dst:    ipHeader.DestinationAddressSlice(),
	})
	require.Equal(t, expected, icmpHeader.Checksum(),
		"the ICMPv6 checksum must cover the IPv6 pseudo-header. A message without it is "+
			"discarded by every conforming receiver, so the client would never learn the "+
			"tunnel MTU")

	quoted := icmpHeader.Payload()
	require.NotEmpty(t, quoted, "the ICMPv6 error must quote the original packet")
	require.Equal(t, original[:len(quoted)], quoted,
		"the quoted bytes must be a prefix of the ORIGINAL packet")
}

// TestPacketTooBigMTUIsClampedToTheProtocolMinimum pins the lower bound.
//
// RFC 8200 section 5 requires every link to carry at least 1280 bytes, and RFC 1191
// gives IPv4 a floor of 68. Advertising less would invite a client to send packets below
// the minimum the path must support, which breaks PMTU discovery in the other direction.
// sing-tun clamps both, and this pins that the clamp is in effect.
func TestPacketTooBigMTUIsClampedToTheProtocolMinimum(t *testing.T) {
	gateway4 := netip.MustParseAddr("198.18.0.1")
	gateway6 := netip.MustParseAddr("2001:db8::1")

	t.Run("ipv4 small mtu is raised to the protocol minimum", func(t *testing.T) {
		source := netip.MustParseAddr("198.18.0.2")
		original := buildTestIPv4Packet(t, source, gateway4, 200)
		reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, gateway4, netip.Addr{}, 1, PacketHeadroom)
		require.True(t, built)
		defer reply.Release()

		icmpHeader := header.ICMPv4(header.IPv4(reply.Bytes()).Payload())
		require.GreaterOrEqual(t, icmpHeader.MTU(), uint16(header.IPv4MinimumMTU),
			"an advertised IPv4 MTU below the protocol minimum (%d) must be raised; got %d",
			header.IPv4MinimumMTU, icmpHeader.MTU())
	})

	t.Run("ipv6 small mtu is raised to the protocol minimum", func(t *testing.T) {
		source := netip.MustParseAddr("2001:db8::2")
		original := buildTestIPv6Packet(t, source, gateway6, 200)
		reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, netip.Addr{}, gateway6, 1, PacketHeadroom)
		require.True(t, built)
		defer reply.Release()

		icmpHeader := header.ICMPv6(header.IPv6(reply.Bytes()).Payload())
		require.GreaterOrEqual(t, icmpHeader.MTU(), uint32(header.IPv6MinimumMTU),
			"an advertised IPv6 MTU below %d must be raised; got %d",
			header.IPv6MinimumMTU, icmpHeader.MTU())
	})
}

// TestPacketTooBigMTUUpperBoundIsEncodedSafely pins the IPv4 upper bound.
//
// The ICMPv4 MTU field is 16 bits, so a larger advertised value cannot be represented.
// sing-tun clamps to 0xffff rather than truncating, and a truncation would be worse than
// useless: it could advertise a SMALLER MTU than the real limit and make the client
// shrink its packets for no reason.
func TestPacketTooBigMTUUpperBoundIsEncodedSafely(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.2")
	gateway := netip.MustParseAddr("198.18.0.1")
	original := buildTestIPv4Packet(t, source, gateway, 200)

	reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, gateway, netip.Addr{}, 1<<20, PacketHeadroom)
	require.True(t, built)
	defer reply.Release()

	icmpHeader := header.ICMPv4(header.IPv4(reply.Bytes()).Payload())
	require.Equal(t, uint16(0xffff), icmpHeader.MTU(),
		"an MTU above the 16-bit field must saturate at 0xffff rather than wrap. A "+
			"wrapped value could be SMALLER than the real limit and make the client "+
			"shrink unnecessarily")
}

// TestPacketTooBigQuotedPacketIsBounded pins that the quotation cannot make the reply
// larger than the minimum IPv4 datagram.
//
// RFC 1812 section 4.3.2.3 recommends quoting as much of the original as fits without
// exceeding 576 bytes including headers, so the error itself is never larger than the
// problem it reports. If the reply grew with the original packet, a peer could make the
// endpoint emit replies far larger than the trigger and amplify traffic.
func TestPacketTooBigQuotedPacketIsBounded(t *testing.T) {
	source := netip.MustParseAddr("198.18.0.2")
	gateway := netip.MustParseAddr("198.18.0.1")

	// A maximal IPv4 packet, so the quote is given every opportunity to be too long.
	original := buildTestIPv4Packet(t, source, gateway, 65535-20)

	reply, built := buildICMPError(original, tun.ICMPErrorPacketTooBig, gateway, netip.Addr{}, 1280, PacketHeadroom)
	require.True(t, built)
	defer reply.Release()

	const ipv4MinimumProcessableDatagramSize = 576
	require.LessOrEqual(t, len(reply.Bytes()), ipv4MinimumProcessableDatagramSize,
		"the ICMPv4 error must fit within %d bytes including headers, so the reply is "+
			"never larger than the trigger. Got %d bytes for a %d-byte original",
		ipv4MinimumProcessableDatagramSize, len(reply.Bytes()), len(original))
}

// verifyIPv4Checksum recomputes the IPv4 header checksum from the packet.
//
// The convention was MEASURED rather than assumed, because sing-tun's accessor is easy
// to misread: CalculateChecksum() returns the one's-complement sum of the header with
// the checksum field in place, so a VALID header yields 0xffff... except that this
// implementation reads the stored field as part of the sum and returns the raw
// accumulator instead. The reliable check is therefore the standard one: recompute the
// sum over the header with the field zeroed, complement it, and compare with what is
// stored.
func verifyIPv4Checksum(t *testing.T, packet []byte) {
	t.Helper()

	ipHeader := header.IPv4(packet)
	stored := ipHeader.Checksum()

	// Copy the header so zeroing the field does not disturb the packet under test.
	headerLength := int(ipHeader.HeaderLength())
	require.LessOrEqual(t, headerLength, len(packet))
	copied := make([]byte, headerLength)
	copy(copied, packet[:headerLength])

	copiedHeader := header.IPv4(copied)
	copiedHeader.SetChecksum(0)
	expected := ^copiedHeader.CalculateChecksum()

	require.Equal(t, expected, stored,
		"the IPv4 header checksum is invalid (stored %#04x, expected %#04x). Every real "+
			"stack validates it, so a wrong checksum means the client discards the MTU "+
			"signal and keeps losing packets", stored, expected)
}

// verifyICMPv4Checksum recomputes the ICMPv4 checksum.
//
// sing-tun's ICMPv4Checksum returns the complemented sum, which IS the value written
// into the field - measured, not assumed. So the check is equality with the stored
// value, and computing it over the header with the real checksum in place is correct
// because the function skips bytes 2:4 itself.
func verifyICMPv4Checksum(t *testing.T, icmpHeader header.ICMPv4) {
	t.Helper()
	require.Equal(t, icmpHeader.Checksum(), header.ICMPv4Checksum(icmpHeader, 0),
		"the ICMPv4 checksum is invalid; the message would be discarded by the receiver")
}

// TestPacketTooBigCanBeAddressedToAnExplicitPeer covers buildICMPErrorTo.
//
// It exists because of a defect the live HTTP/3 test found and the tests above could
// not: those all build an error for a packet that arrived FROM a peer, where
// addressing the reply to the packet's source is correct. The endpoint's own PTB path
// is the other direction - the packet that did not fit is one the endpoint was SENDING
// INTO a tunnel - and there the source is frequently the ENDPOINT's own tunnel address.
// Addressing the error to it means the peer that needs the message never receives it.
//
// MEASURED on a live asymmetric tunnel before the fix:
//
//	reply src=198.18.0.1 dst=198.18.0.1   quoted src=198.18.0.1 dst=198.18.0.2
//	lookup(198.18.0.1) -> not found       client received: nothing
//
// The rewrite also has to maintain the checksums, which is what the second half of this
// test pins: the IPv4 checksum covers the addresses and the ICMPv6 checksum covers them
// through the pseudo-header, so an address change without a recomputation produces an
// error every real stack discards - indistinguishable, from the peer's side, from the
// delivery failure being fixed.
func TestPacketTooBigCanBeAddressedToAnExplicitPeer(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		// The oversized packet is one the ENDPOINT generated, so its source is the
		// gateway - the exact shape that made the old addressing wrong.
		gateway := netip.MustParseAddr("198.18.0.1")
		peer := netip.MustParseAddr("198.18.0.2")
		oversized := buildTestIPv4Packet(t, gateway, peer, 1400)

		const advertisedMTU = 1280

		reply, built := buildICMPErrorTo(oversized, tun.ICMPErrorPacketTooBig,
			gateway, netip.Addr{}, peer, advertisedMTU, PacketHeadroom)
		require.True(t, built)
		defer reply.Release()

		packet := reply.Bytes()
		ipHeader := header.IPv4(packet)
		require.True(t, ipHeader.IsValid(len(packet)),
			"the header must stay self-consistent after the destination rewrite")

		require.Equal(t, gateway, ipHeader.SourceAddr(),
			"the error must still come from the endpoint's tunnel address")
		require.Equal(t, peer, ipHeader.DestinationAddr(),
			"the error must be addressed to the PEER whose tunnel could not carry the "+
				"packet, not to the source of the oversized packet (which here is the "+
				"endpoint itself, so the peer would never learn the MTU)")

		icmpHeader := header.ICMPv4(ipHeader.Payload())
		require.Equal(t, header.ICMPv4DstUnreachable, icmpHeader.Type())
		require.Equal(t, header.ICMPv4FragmentationNeeded, icmpHeader.Code())
		require.Equal(t, uint16(advertisedMTU), icmpHeader.MTU())

		// Recomputing the checksum is the part that makes the rewrite deliverable.
		verifyIPv4Checksum(t, packet)
		verifyICMPv4Checksum(t, icmpHeader)

		// The quoted packet is unchanged by the rewrite: it must still identify the
		// packet that was too large, not the error that reports it.
		quoted := icmpHeader.Payload()
		require.Equal(t, oversized[:len(quoted)], quoted,
			"rewriting the destination must not disturb the quoted original, or the "+
				"peer cannot tell which flow was affected")
	})

	t.Run("ipv6", func(t *testing.T) {
		gateway := netip.MustParseAddr("2001:db8:1::1")
		peer := netip.MustParseAddr("2001:db8:1::2")
		oversized := buildTestIPv6Packet(t, gateway, peer, 1400)

		const advertisedMTU = 1280

		reply, built := buildICMPErrorTo(oversized, tun.ICMPErrorPacketTooBig,
			netip.Addr{}, gateway, peer, advertisedMTU, PacketHeadroom)
		require.True(t, built)
		defer reply.Release()

		packet := reply.Bytes()
		ipHeader := header.IPv6(packet)
		require.True(t, ipHeader.IsValid(len(packet)))

		require.Equal(t, gateway, ipHeader.SourceAddr())
		require.Equal(t, peer, ipHeader.DestinationAddr(),
			"the ICMPv6 error must be addressed to the peer")

		icmpHeader := header.ICMPv6(ipHeader.Payload())
		require.Equal(t, header.ICMPv6PacketTooBig, icmpHeader.Type())
		require.Equal(t, header.ICMPv6UnusedCode, icmpHeader.Code())

		// IPv6 has no header checksum, so the only integrity field is the ICMPv6 one
		// - and it covers the addresses through the pseudo-header. A rewrite that
		// skipped it would leave a message every receiver drops.
		require.Equal(t, icmpHeader.Checksum(), header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHeader,
			Src:    ipHeader.SourceAddressSlice(),
			Dst:    ipHeader.DestinationAddressSlice(),
		}), "the ICMPv6 checksum must be recomputed for the rewritten destination")
	})
}
