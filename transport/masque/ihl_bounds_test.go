package masque

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

// IPv4 IHL boundary regression coverage.
//
// A peer chooses every byte of a datagram, including the IHL field that declares how long
// the IPv4 header is. The checksum recomputation in decrementHopLimit slices
// b[:HeaderLength()], so a declared length that is shorter than the 20-byte minimum, or
// longer than the bytes actually present, makes that expression either invert its bounds or
// overrun the slice. Both panic the serving goroutine, which a peer can trigger at will:
// a remote denial of service.
//
// These tests exist because the ORIGINAL bug was not that a helper lacked a check. It was
// that the check in packetAddresses validates the length the header DECLARES
// (IPTransportProtocol -> IPv4.IsValid) and callers then assumed that implied the bytes were
// present. A 20-byte packet with IHL=6 satisfies IsValid and still overruns. So the coverage
// below deliberately includes the REAL CALL CHAINS - serverSession.handlePacket and
// Server.WritePacketBuffers - and not only the helper, because a check that lives in the
// wrong place passes a helper-only test and still panics in production.

// ipv4WithIHL builds an IPv4 packet asserting a specific IHL, with the given number of bytes
// actually present.
//
// present is the true slice length and may be shorter than the header the IHL declares,
// which is exactly the hostile shape under test. totalLength is written verbatim so a case
// can lie about the packet length the way a real attacker's packet would.
func ipv4WithIHL(ihl uint8, present int, totalLength uint16, source netip.Addr, destination netip.Addr, protocol uint8, ttl uint8) []byte {
	packet := make([]byte, present)
	if present > 0 {
		packet[0] = 0x40 | (ihl & 0x0f) // version 4, chosen IHL
	}
	if present > 2 {
		packet[2] = byte(totalLength >> 8)
	}
	if present > 3 {
		packet[3] = byte(totalLength)
	}
	if present > 8 {
		packet[8] = ttl
	}
	if present > 9 {
		packet[9] = protocol
	}
	if present >= 16 {
		copy(packet[12:16], source.AsSlice())
	}
	if present >= 20 {
		copy(packet[16:20], destination.AsSlice())
	}
	return packet
}

// TestDecrementHopLimitIHLBoundaries is the unit-level case table.
//
// Each entry names the shape an attacker or a broken peer can produce. The assertion is
// uniform and deliberately weak about the RESULT: the function may accept or reject, because
// both are defensible for some of these shapes. What it may never do is panic, and it may
// never report success for a header it did not fully contain - reporting success would mean
// it wrote a checksum over bytes outside the packet.
func TestDecrementHopLimitIHLBoundaries(t *testing.T) {
	valid4 := netip.MustParseAddr("198.18.0.2")
	valid4Destination := netip.MustParseAddr("198.18.0.3")

	for _, testCase := range []struct {
		name string
		// ihl is the value written into the header's IHL field.
		ihl uint8
		// present is how many bytes the slice actually holds.
		present int
		// totalLength is written verbatim into the Total Length field.
		totalLength uint16
		// wantAccepted is true only for shapes whose declared header IS present.
		wantAccepted bool
		note         string
	}{
		{
			name: "IHL 0", ihl: 0, present: 20, totalLength: 20,
			wantAccepted: false,
			note: "an IHL of 0 declares a zero-length header, which inverts the " +
				"b[:0] slice bounds in the checksum computation",
		},
		{
			name: "IHL 1 below the minimum", ihl: 1, present: 20, totalLength: 20,
			wantAccepted: false,
			note:         "declares 4 bytes header, below the 20-byte minimum",
		},
		{
			name: "IHL 4 below the minimum", ihl: 4, present: 20, totalLength: 20,
			wantAccepted: false,
			note:         "declares 16 bytes header, one word below the minimum",
		},
		{
			name: "IHL 5 with 20 bytes present", ihl: 5, present: 20, totalLength: 20,
			wantAccepted: true,
			note:         "the ordinary, well-formed packet",
		},
		{
			name: "IHL 6 but only 20 bytes present", ihl: 6, present: 20, totalLength: 24,
			wantAccepted: false,
			note: "THE ORIGINAL BUG: IsValid accepts a 24-byte total length against a " +
				"20-byte slice, and the checksum then slices b[:24]",
		},
		{
			name: "IHL 15 maximum with only 20 bytes present", ihl: 15, present: 20, totalLength: 60,
			wantAccepted: false,
			note:         "the largest legal IHL (60 bytes) declared against a 20-byte slice",
		},
		{
			name: "IHL 15 maximum fully present", ihl: 15, present: 60, totalLength: 60,
			wantAccepted: true,
			note: "the largest legal header, fully present: must still be accepted so " +
				"the bound is not set so tight that legal option-bearing packets are " +
				"rejected",
		},
		{
			name: "IHL 5 truncated to 19 bytes", ihl: 5, present: 19, totalLength: 20,
			wantAccepted: false,
			note:         "one byte short of the minimum",
		},
		{
			name: "IHL 5 truncated to 4 bytes", ihl: 5, present: 4, totalLength: 20,
			wantAccepted: false,
			note:         "only the first word present",
		},
		{
			name: "IHL 5 truncated to 1 byte", ihl: 5, present: 1, totalLength: 20,
			wantAccepted: false,
			note:         "only the version/IHL byte present",
		},
		{
			name: "empty packet", ihl: 5, present: 0, totalLength: 0,
			wantAccepted: false,
			note:         "an empty slice has no version nibble at all",
		},
		{
			name: "total length far beyond the slice", ihl: 5, present: 20, totalLength: 65535,
			wantAccepted: true,
			note: "the HEADER is fully present, so the hop limit can be decremented " +
				"safely; a lying total length is a separate concern handled where the " +
				"payload is read, not here",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			packet := ipv4WithIHL(testCase.ihl, testCase.present, testCase.totalLength,
				valid4, valid4Destination, uint8(header.UDPProtocolNumber), 64)

			var accepted bool
			requireNotPanicking(t, testCase.note, func() {
				accepted = decrementHopLimit(packet)
			})

			if accepted != testCase.wantAccepted {
				t.Fatalf("decrementHopLimit accepted=%v, want %v (IHL=%d declared %d bytes, "+
					"%d present): %s",
					accepted, testCase.wantAccepted, testCase.ihl, int(testCase.ihl)*4,
					testCase.present, testCase.note)
			}
			// Acceptance must never have written outside the slice. A successful
			// decrement is allowed to change the TTL and the checksum only.
			if accepted && testCase.present > 0 && header.IPv4(packet).TTL() != 63 {
				t.Fatalf("an accepted packet did not have its TTL decremented: %d",
					header.IPv4(packet).TTL())
			}
		})
	}
}

// TestDecrementHopLimitIPv6Boundaries covers the other family.
//
// The IPv6 branch reads only the Hop Limit at a fixed offset, so it is a smaller surface
// than IPv4's variable-length header, but it must still reject a slice that does not
// contain a full header rather than reading past it.
func TestDecrementHopLimitIPv6Boundaries(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		present      int
		wantAccepted bool
	}{
		{name: "full 40-byte header", present: header.IPv6MinimumSize, wantAccepted: true},
		{name: "one byte short", present: header.IPv6MinimumSize - 1, wantAccepted: false},
		{name: "8 bytes", present: 8, wantAccepted: false},
		{name: "empty", present: 0, wantAccepted: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			packet := make([]byte, testCase.present)
			if testCase.present > 0 {
				packet[0] = 0x60 // version 6
			}
			if testCase.present > 7 {
				packet[7] = 64 // hop limit
			}
			var accepted bool
			requireNotPanicking(t, "IPv6 header bounds", func() {
				accepted = decrementHopLimit(packet)
			})
			if accepted != testCase.wantAccepted {
				t.Fatalf("decrementHopLimit accepted=%v, want %v for %d bytes present",
					accepted, testCase.wantAccepted, testCase.present)
			}
		})
	}
}

// TestForwardingPathRejectsShortAndMalformedHeaders drives the REAL ingress path.
//
// This is the assertion that matters for the original defect. decrementHopLimit is reached
// through serverSession.handlePacket, whose only prior validation is packetAddresses. A
// helper-only test cannot show that the production path is safe, because the bug was a gap
// between what packetAddresses proved and what the caller assumed.
//
// Every shape below is fed to handlePacket as a peer would deliver it. None may panic; the
// session must survive so it can keep serving.
func TestForwardingPathRejectsShortAndMalformedHeaders(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
	})
	probe := &ownershipProbeHandler{}
	server.handler = probe

	peer := netip.MustParseAddr("198.18.0.3")
	session := tunnelSession(t, server, []netip.Addr{peer}, []AddressRange{{
		Start:    netip.MustParseAddr("203.0.113.0"),
		End:      netip.MustParseAddr("203.0.113.255"),
		Protocol: 0,
	}})
	registerSession(server, session)
	defer server.releaseSession(session)

	gateway := server.inet4Address
	remote := netip.MustParseAddr("203.0.113.9")

	for _, testCase := range []struct {
		name   string
		packet []byte
		note   string
	}{
		{
			name:   "IHL 6 with 20 bytes",
			packet: ipv4WithIHL(6, 20, 24, gateway, remote, uint8(header.UDPProtocolNumber), 64),
			note:   "the original overrun shape, through the real call chain",
		},
		{
			name:   "IHL 0",
			packet: ipv4WithIHL(0, 20, 20, gateway, remote, uint8(header.UDPProtocolNumber), 64),
			note:   "inverted slice bounds",
		},
		{
			name:   "IHL 15 with 20 bytes",
			packet: ipv4WithIHL(15, 20, 60, gateway, remote, uint8(header.UDPProtocolNumber), 64),
			note:   "largest declared header, absent in fact",
		},
		{
			name:   "truncated 10-byte IPv4",
			packet: ipv4WithIHL(5, 10, 20, gateway, remote, uint8(header.UDPProtocolNumber), 64),
			note:   "below the minimum header size",
		},
		{
			name:   "truncated 4-byte IPv4",
			packet: []byte{0x45, 0x00, 0x00, 0x14},
			note:   "only the first word",
		},
		{
			name:   "empty packet",
			packet: []byte{},
			note:   "no version nibble",
		},
		{
			name:   "truncated IPv6",
			packet: []byte{0x60, 0x00, 0x00, 0x00},
			note:   "below the IPv6 minimum header size",
		},
		{
			name:   "IPv6 claiming a huge payload length",
			packet: append([]byte{0x60, 0x00, 0x00, 0x00, 0xff, 0xff, 0x11, 0x40}, make([]byte, 64)...),
			note:   "declared payload exceeds the slice",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// ownedPacketBuffer copies into a managed buffer, so a leak here would be
			// attributable to the production path rather than to the fixture.
			packet := ownedPacketBuffer(testCase.packet)
			requireNotPanicking(t, testCase.note, func() {
				session.handlePacket(packet)
			})
			// Whatever the branch taken, nothing may be left queued for this shape: a
			// malformed packet has no valid destination to be delivered to.
			if queued := drainQueuedPackets(t, session); len(queued) != 0 {
				t.Fatalf("a malformed packet produced %d queued deliveries: %s",
					len(queued), testCase.note)
			}
		})
	}
}

// TestDeviceIngressRejectsShortAndMalformedHeaders drives the other production entry point.
//
// Server.WritePacketBuffers is the device -> tunnel direction and reaches
// decrementHopLimit through Server.route and the session's forwarding path. It is a
// different call chain from handlePacket, so it needs its own coverage: a bound enforced on
// one path does not automatically cover the other.
func TestDeviceIngressRejectsShortAndMalformedHeaders(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix(ownershipTestPrefix)},
	})
	probe := &ownershipProbeHandler{}
	server.handler = probe

	peer := netip.MustParseAddr("198.18.0.3")
	session := tunnelSession(t, server, []netip.Addr{peer}, []AddressRange{{
		Start:    netip.MustParseAddr("203.0.113.0"),
		End:      netip.MustParseAddr("203.0.113.255"),
		Protocol: 0,
	}})
	registerSession(server, session)
	defer server.releaseSession(session)

	remote := netip.MustParseAddr("203.0.113.9")

	for _, testCase := range []struct {
		name   string
		packet []byte
		note   string
	}{
		{
			name:   "IHL 6 with 20 bytes",
			packet: ipv4WithIHL(6, 20, 24, peer, remote, uint8(header.TCPProtocolNumber), 64),
			note:   "the original overrun shape on the device ingress chain",
		},
		{
			name:   "IHL 0",
			packet: ipv4WithIHL(0, 20, 20, peer, remote, uint8(header.TCPProtocolNumber), 64),
			note:   "inverted slice bounds",
		},
		{
			name:   "IHL 15 with 20 bytes",
			packet: ipv4WithIHL(15, 20, 60, peer, remote, uint8(header.TCPProtocolNumber), 64),
			note:   "largest declared header, absent in fact",
		},
		{
			name:   "truncated 10-byte IPv4",
			packet: ipv4WithIHL(5, 10, 20, peer, remote, uint8(header.TCPProtocolNumber), 64),
			note:   "below the minimum header size",
		},
		{
			name:   "empty packet",
			packet: []byte{},
			note:   "no version nibble",
		},
		{
			name:   "truncated IPv6",
			packet: []byte{0x60, 0x00, 0x00, 0x00},
			note:   "below the IPv6 minimum header size",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			packet := ownedPacketBuffer(testCase.packet)
			requireNotPanicking(t, testCase.note, func() {
				server.WritePacketBuffers([]*buf.Buffer{packet}, false)
			})
		})
	}

	// The session must still be usable after being fed malformed input: a panic-free
	// crash is not the bar, staying in service is. A well-formed packet must still be
	// forwarded after all of the above, so the bounds cannot have been tightened so far
	// that the legitimate path broke.
	healthy := ownedPacketBuffer(buildOwnershipIPv4Packet(peer, remote,
		uint8(header.TCPProtocolNumber), 64))
	server.WritePacketBuffers([]*buf.Buffer{healthy}, false)
	if delivered := drainQueuedPacketsUntil(t, session, 1); len(delivered) != 1 {
		t.Fatalf("after malformed input the session forwarded %d well-formed packets, "+
			"want 1: the bounds must reject only packets that are actually malformed",
			len(delivered))
	}
}

// requireNotPanicking runs fn and reports a panic as a failure with the case's note.
//
// Recovering rather than letting the panic escape keeps the whole case table running, so a
// single failing shape reports which one it was instead of aborting the binary.
func requireNotPanicking(t *testing.T, note string, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("unexpected panic (%s): %v", note, recovered)
		}
	}()
	fn()
}
