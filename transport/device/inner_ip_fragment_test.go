// Inner-IP packet capture at a fixed tunnel MTU.
//
// # What this file measures, and what the hysteria2 first-datagram test does NOT
//
// protocol/hysteria2/chrome_parrot_first_datagram_test.go measures the length of the first UDP
// payload quic-go hands to the socket layer. That number is a UDP PAYLOAD. Whether the complete IP
// packet built from it fits the tunnel it is about to enter is a different question, decided one
// layer down by the Go stack behind the MASQUE endpoint, and nothing in that file observes an IP
// packet.
//
// This file observes the IP packets. It drives the production device (`transport/device`), whose
// non-system stack is what `protocol/masque` builds for both its client and server endpoints
// (protocol/masque/endpoint.go newDeviceOptions -> device.New), and captures what that device hands
// to its packet writer:
//
//	device.ListenPacket -> tun.Go.ListenUDP -> tun.GoUDPConn.WriteTo
//	  -> GoUDPConn.transmit
//	       builds the complete IPv6/IPv4 packet: network header + UDP header + payload
//	       if len(packet) <= mtu: one writeDatagram
//	       else:                  goWriteFragmented -> fragmentIPv6Packet / fragmentIPv4Packet
//	  -> MemoryTun outbound queue -> device packet writer   <- THIS test's observation point
//
// So every buffer captured here is one complete IP packet (or one complete fragment of one), which
// is exactly the evidence a claim about the 1280-byte inner MTU needs.
//
// # The three sizes that must not be confused
//
//	inner IP MTU       1280        the tunnel's own MTU, what this file fixes and measures against
//	inner UDP budget   MTU - 40 - 8 = 1232 for IPv6, MTU - 20 - 8 = 1252 for IPv4
//	                   the largest UDP payload that fits without fragmenting
//	outer QUIC packet  1250        what the pinned quic-go forces under ChromeParrot, measured in
//	                   the hysteria2 test, and NOT an inner IP MTU
//
// The arithmetic that connects them is asserted at the bottom of this file, on the measured packet
// sizes rather than on the constants, so a change in the pinned stack shows up as a failure.
package device

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

const (
	// tunnelMTU is the MASQUE endpoint default (protocol/masque/endpoint.go, `mtu` option default),
	// and the value the whole question is about.
	tunnelMTU = 1280

	// innerIPv6Address / innerIPv4Address are the tunnel's own addresses. The local address of a
	// packet decides which family the stack builds, so both are configured.
	innerIPv6Address = "fd00::1"
	innerIPv4Address = "10.0.0.1"

	// outerDestination is where a payload is sent TO. It is inside the tunnel's address space as far
	// as this test is concerned: the device only builds and emits the packet.
	outerIPv6Destination = "2001:db8::10"
	outerIPv4Destination = "192.0.2.10"

	// ipv6HeaderSize, udpHeaderSize and ipv6FragmentHeaderSize are RFC 8200 / 768 / 8200 sizes.
	ipv6HeaderSize         = 40
	ipv4HeaderSize         = 20
	udpHeaderSize          = 8
	ipv6FragmentHeaderSize = 8

	// captureWatchdog is a hang detector. All of this is in-process and synchronous: the write
	// returns only after the fragments have been queued.
	captureWatchdog = 10 * time.Second
)

// packetCapture is the device's packet writer: the observation point. It records one entry per
// buffer, because the stack emits each fragment as its own buffer in the batch.
type packetCapture struct {
	access  sync.Mutex
	packets [][]byte
}

func (c *packetCapture) write(packetBuffers []*buf.Buffer) error {
	c.access.Lock()
	defer c.access.Unlock()
	for _, packetBuffer := range packetBuffers {
		c.packets = append(c.packets, append([]byte(nil), packetBuffer.Bytes()...))
	}
	return nil
}

func (c *packetCapture) snapshot() [][]byte {
	c.access.Lock()
	defer c.access.Unlock()
	return append([][]byte(nil), c.packets...)
}

func (c *packetCapture) count() int {
	c.access.Lock()
	defer c.access.Unlock()
	return len(c.packets)
}

// awaitPackets waits until at least want packets have been captured. Every fragment of one UDP write
// is enqueued before the write returns, so this returns on the first poll in practice; the wait is
// here so the test cannot report "no fragments" merely because it looked too early.
func (c *packetCapture) awaitPackets(t *testing.T, want int) [][]byte {
	t.Helper()
	deadline := time.Now().Add(captureWatchdog)
	for {
		packets := c.snapshot()
		if len(packets) >= want {
			return packets
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d packet(s) reached the device's packet writer within %s, want at least %d",
				len(packets), captureWatchdog, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// newTunnelDevice builds the production device on its non-system stack at tunnelMTU, with both
// families configured, and returns it with its capture attached.
func newTunnelDevice(t *testing.T) (Device, *packetCapture) {
	t.Helper()
	capture := &packetCapture{}
	instance, err := New(Options{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
		// System=false is the pure Go stack: the MASQUE endpoint's default, and the only path that
		// can be measured in-process without CAP_NET_ADMIN.
		System: false,
		MTU:    tunnelMTU,
		Configuration: Configuration{
			Address: []netip.Prefix{
				netip.MustParsePrefix(innerIPv6Address + "/128"),
				netip.MustParsePrefix(innerIPv4Address + "/32"),
			},
		},
	})
	require.NoError(t, err)
	require.EqualValues(t, tunnelMTU, instance.PortMTU(),
		"the device must report the MTU it was built with, or the arithmetic below is about a "+
			"number nothing enforces")
	instance.SetPacketWriter(capture.write)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { _ = instance.Close() })
	return instance, capture
}

// ---------------------------------------------------------------------------
// IPv6: the case the 1280 MTU actually constrains
// ---------------------------------------------------------------------------

// TestInnerIPv6FragmentationAtTunnelMTU is the measurement: for each payload size, how many complete
// IPv6 packets does the device emit, and what is in them.
//
// The expectations are derived from the measured packets, not from the constants: the sizes below
// state which side of the boundary each payload falls on, and the fragment header contents are parsed
// out of the bytes that were actually written.
func TestInnerIPv6FragmentationAtTunnelMTU(t *testing.T) {
	const (
		// 1280 - 40 - 8: the largest IPv6 UDP payload that fits the tunnel with nothing to spare.
		ipv6MaxPayload = tunnelMTU - ipv6HeaderSize - udpHeaderSize
		// 1280 - 40 - 8 - 8: what a fragment can carry, because the fragment header is part of the
		// packet that has to fit.
		ipv6MaxFragmentPayload = (tunnelMTU - ipv6HeaderSize - ipv6FragmentHeaderSize) &^ 7
	)

	cases := []struct {
		payloadLength int
		fragments     int
		why           string
	}{
		{1200, 1, "below the budget with room to spare"},
		{ipv6MaxPayload - 1, 1, "one byte below the budget"},
		{ipv6MaxPayload, 1, "exactly the budget: 40 + 8 + 1232 == 1280, so there is nothing to fragment"},
		{ipv6MaxPayload + 1, 2, "one byte over the budget: the packet no longer fits and must be fragmented"},
		{1250, 2, "the payload the pinned quic-go forces under ChromeParrot"},
		{1280, 2, "a full-MTU payload, for the shape of a larger split"},
	}

	for _, testCase := range cases {
		t.Run(payloadSizeName(testCase.payloadLength), func(t *testing.T) {
			instance, capture := newTunnelDevice(t)
			writeUDPPayload(t, instance, outerIPv6Destination, testCase.payloadLength)
			packets := capture.awaitPackets(t, testCase.fragments)

			require.Len(t, packets, testCase.fragments,
				"payload %d (%s): expected %d IPv6 packet(s)", testCase.payloadLength, testCase.why,
				testCase.fragments)

			// Every emitted packet must fit the tunnel MTU. This is the property the whole file is
			// about: nothing the device emits may exceed the MTU it was built with.
			for index, packet := range packets {
				require.LessOrEqual(t, len(packet), tunnelMTU,
					"fragment %d of payload %d is %d bytes, which exceeds the %d-byte tunnel MTU",
					index, testCase.payloadLength, len(packet), tunnelMTU)
			}

			if testCase.fragments == 1 {
				require.Equal(t, 6, int(packets[0][0]>>4),
					"the single packet must be IPv6 (version nibble 6)")
				require.Equal(t, 17, int(packets[0][6]),
					"a single unfragmented packet's next header must be UDP (17); a fragment header "+
						"(44) here would mean the packet was fragmented anyway")
				require.Equal(t, ipv6HeaderSize+udpHeaderSize+testCase.payloadLength, len(packets[0]),
					"the complete IPv6 packet is the header, the UDP header and the payload")
				return
			}

			assertIPv6Fragments(t, packets, testCase.payloadLength, ipv6MaxFragmentPayload)
		})
	}
}

// assertIPv6Fragments parses every fragment out of the bytes that were written and checks the
// fragment header against RFC 8200: next header, offset, more-fragments flag and identification.
//
// The reassembly total is compared against the IPv6 PAYLOAD of the original packet - the UDP header
// plus the UDP payload - because that is what the fragments divide. Comparing it against the UDP
// payload alone is off by the 8-byte UDP header, which is the kind of error this assertion exists to
// catch rather than to make.
func assertIPv6Fragments(t *testing.T, packets [][]byte, payloadLength, maxFragmentPayload int) {
	t.Helper()

	// The identification is the same for every fragment of one datagram - it is what reassembly
	// matches on - and it is what distinguishes "one datagram split" from "two datagrams written".
	identification := binary.BigEndian.Uint32(packets[0][ipv6HeaderSize+4 : ipv6HeaderSize+8])
	require.NotZero(t, identification, "the fragment identification must be set")

	reassembled := 0
	for index, packet := range packets {
		require.Equal(t, 6, int(packet[0]>>4), "fragment %d must be IPv6", index)
		require.Equal(t, 44, int(packet[6]),
			"fragment %d's IPv6 next header must be the Fragment header (44)", index)

		fragmentHeader := packet[ipv6HeaderSize : ipv6HeaderSize+ipv6FragmentHeaderSize]
		require.Equal(t, 17, int(fragmentHeader[0]),
			"fragment %d must declare UDP (17) as the next header after reassembly", index)
		require.Equal(t, byte(0), fragmentHeader[1], "the reserved byte must be zero")

		value := binary.BigEndian.Uint16(fragmentHeader[2:4])
		offset := int(value &^ 1)
		moreFragments := value&1 == 1
		require.Equal(t, 0, offset%8, "fragment %d's offset must be a multiple of 8 bytes", index)
		require.Equal(t, reassembled, offset,
			"fragment %d's offset must continue where the previous fragment ended", index)

		require.Equal(t, identification, binary.BigEndian.Uint32(fragmentHeader[4:8]),
			"fragment %d must carry the datagram's identification", index)

		carried := len(packet) - ipv6HeaderSize - ipv6FragmentHeaderSize
		require.LessOrEqual(t, carried, maxFragmentPayload,
			"fragment %d carries %d bytes, more than the %d a %d-byte MTU can hold once the IPv6 "+
				"and fragment headers are accounted for", index, carried, maxFragmentPayload, tunnelMTU)

		isLast := index == len(packets)-1
		if isLast {
			require.False(t, moreFragments,
				"the last fragment must clear the more-fragments flag")
		} else {
			require.True(t, moreFragments,
				"fragment %d is not the last, so it must set the more-fragments flag", index)
			require.Equal(t, maxFragmentPayload, carried,
				"a non-final fragment must be filled to the maximum, or the data would not reassemble "+
					"in the order the offsets describe")
		}

		require.LessOrEqual(t, binary.BigEndian.Uint16(packet[4:6]),
			uint16(ipv6FragmentHeaderSize+carried),
			"fragment %d's payload length must account for its fragment header and its bytes", index)

		reassembled += carried
	}

	require.Equal(t, payloadLength+udpHeaderSize, reassembled,
		"the fragments must reassemble to exactly the IPv6 payload that was written: the UDP header "+
			"(%d bytes) plus the %d-byte UDP payload", udpHeaderSize, payloadLength)
}

// ---------------------------------------------------------------------------
// IPv4: the control, where the same payload sizes fit
// ---------------------------------------------------------------------------

// TestInnerIPv4FragmentationAtTunnelMTU is the IPv4 control. The same payload that needs two IPv6
// packets because of the 40-byte header fits an IPv4 packet, and the arithmetic is asserted rather
// than assumed: IPv4's header is 20 bytes smaller and it has no separate fragment header - the offset
// and flags live in the base header - so the two families do NOT share a boundary.
//
// # Why the first IPv4 fragment is capped at 1256 and not 1260
//
// RFC 791 requires every fragment except the last to carry a multiple of 8 bytes, so the fragment
// payload is snapped DOWN to a multiple of 8. 1280 - 20 = 1260, and 1260 &^ 7 = 1256. MEASURED: a
// 1253-byte payload produces a 1276-byte first fragment (1256 carried) and a 25-byte second one.
// That four-byte cost is the RFC's, not a defect, and the assertion below pins it so a change in the
// snapping is visible.
func TestInnerIPv4FragmentationAtTunnelMTU(t *testing.T) {
	const (
		// 1280 - 20 - 8
		ipv4MaxPayload = tunnelMTU - ipv4HeaderSize - udpHeaderSize
		// (1280 - 20) rounded down to a multiple of 8, which is what RFC 791 requires of a
		// non-final fragment.
		ipv4MaxFragmentPayload = (tunnelMTU - ipv4HeaderSize) &^ 7
	)

	require.Equal(t, 1252, ipv4MaxPayload,
		"the IPv4 inner budget at a 1280-byte MTU is 1252 bytes of UDP payload")
	require.Equal(t, 1256, ipv4MaxFragmentPayload,
		"a fragment carries 1256 bytes, because 1280 - 20 = 1260 is snapped down to a multiple of 8")
	require.Equal(t, ipv6HeaderSize-ipv4HeaderSize,
		(tunnelMTU-ipv4HeaderSize-udpHeaderSize)-(tunnelMTU-ipv6HeaderSize-udpHeaderSize),
		"the two families' budgets differ by exactly the header difference (40 - 20)")

	cases := []struct {
		payloadLength int
		fragments     int
		firstLength   int
		why           string
	}{
		{1250, 1, 1278, "the ChromeParrot payload fits IPv4 at this MTU: 20 + 8 + 1250 == 1278"},
		{ipv4MaxPayload, 1, 1280, "exactly the IPv4 budget: 20 + 8 + 1252 == 1280"},
		{ipv4MaxPayload + 1, 2, 1276,
			"one byte over the IPv4 budget, so it fragments - and the first fragment is 1276, not 1280, " +
				"because 1256 is the largest multiple of 8 that fits"},
	}

	for _, testCase := range cases {
		t.Run(payloadSizeName(testCase.payloadLength), func(t *testing.T) {
			instance, capture := newTunnelDevice(t)
			writeUDPPayload(t, instance, outerIPv4Destination, testCase.payloadLength)
			packets := capture.awaitPackets(t, testCase.fragments)
			require.Len(t, packets, testCase.fragments,
				"payload %d (%s): expected %d IPv4 packet(s)", testCase.payloadLength, testCase.why,
				testCase.fragments)
			require.Equal(t, testCase.firstLength, len(packets[0]),
				"payload %d: the first packet's length. %s", testCase.payloadLength, testCase.why)

			for index, packet := range packets {
				require.LessOrEqual(t, len(packet), tunnelMTU,
					"fragment %d of payload %d is %d bytes, which exceeds the %d-byte tunnel MTU",
					index, testCase.payloadLength, len(packet), tunnelMTU)
				require.Equal(t, 4, int(packet[0]>>4),
					"fragment %d must be IPv4 (version nibble 4)", index)
				require.EqualValues(t, len(packet), binary.BigEndian.Uint16(packet[2:4]),
					"fragment %d's total-length field must account for the whole fragment", index)
			}

			if testCase.fragments == 1 {
				require.Equal(t, 17, int(packets[0][9]),
					"an unfragmented IPv4 packet's protocol must be UDP (17)")
				require.Equal(t, ipv4HeaderSize+udpHeaderSize+testCase.payloadLength, len(packets[0]),
					"the complete IPv4 packet is the header, the UDP header and the payload")
				require.EqualValues(t, 0, binary.BigEndian.Uint16(packets[0][6:8])&0x2000,
					"an unfragmented packet must not have the more-fragments flag set")
				return
			}

			// Fragmented: the identification lives in the IPv4 header and is shared, the offset is
			// in 8-byte units, and the more-fragments flag is bit 13 of the flags/fragment field.
			identification := binary.BigEndian.Uint16(packets[0][4:6])
			require.NotZero(t, identification, "the IPv4 identification must be set")
			reassembled := 0
			for index, packet := range packets {
				require.EqualValues(t, identification, binary.BigEndian.Uint16(packet[4:6]),
					"fragment %d must carry the datagram's identification", index)
				flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
				offsetBytes := int(flagsAndOffset&0x1fff) * 8
				moreFragments := flagsAndOffset&0x2000 != 0
				require.Equal(t, reassembled, offsetBytes,
					"fragment %d's offset must continue where the previous fragment ended", index)
				carried := len(packet) - ipv4HeaderSize
				require.LessOrEqual(t, carried, ipv4MaxFragmentPayload,
					"fragment %d carries %d bytes, more than the %d the IPv4 budget allows",
					index, carried, ipv4MaxFragmentPayload)
				if index == len(packets)-1 {
					require.False(t, moreFragments, "the last fragment must clear the more-fragments flag")
				} else {
					require.True(t, moreFragments,
						"fragment %d is not the last, so it must set the more-fragments flag", index)
					require.Equal(t, 0, carried%8,
						"fragment %d is not the last, so RFC 791 requires its payload to be a multiple "+
							"of 8 bytes", index)
				}
				reassembled += carried
			}
			require.Equal(t, testCase.payloadLength+udpHeaderSize, reassembled,
				"the fragments must reassemble to exactly the IPv4 payload that was written: the UDP "+
					"header (%d bytes) plus the %d-byte UDP payload", udpHeaderSize, testCase.payloadLength)
		})
	}
}

// ---------------------------------------------------------------------------
// The arithmetic that connects the three sizes
// ---------------------------------------------------------------------------

// TestTheChromeParrotPayloadDoesNotFitInnerIPv6 pins the product-level consequence, from the measured
// packets rather than from constants.
//
// The pinned quic-go forces a 1250-byte UDP payload whenever ChromeParrot is set, and hysteria2 sets
// it by default. Over an inner IPv6 tunnel of 1280 bytes the budget is 1232, so that payload is 18
// bytes over and the stack splits it. The test asserts both halves: the split happens (so a claim
// that "nothing fragments" would fail here), and every emitted packet still fits the MTU (so a claim
// that "fragmentation is broken" would fail too).
//
// What this does NOT establish: that any real network carries the fragments. Whether a path drops
// IPv6 fragments is a property of that path, and no test on this host can decide it.
func TestTheChromeParrotPayloadDoesNotFitInnerIPv6(t *testing.T) {
	const chromeParrotUDPPayload = 1250

	ipv6Budget := tunnelMTU - ipv6HeaderSize - udpHeaderSize
	require.Equal(t, 1232, ipv6Budget,
		"the IPv6 inner budget at a 1280-byte MTU is 1232 bytes of UDP payload")
	require.Greater(t, chromeParrotUDPPayload, ipv6Budget,
		"the ChromeParrot payload must be over the IPv6 inner budget - this is the whole problem")

	instance, capture := newTunnelDevice(t)
	writeUDPPayload(t, instance, outerIPv6Destination, chromeParrotUDPPayload)
	packets := capture.awaitPackets(t, 2)

	require.Len(t, packets, 2,
		"the 1250-byte payload must be split into two IPv6 packets at a 1280-byte MTU. A single "+
			"packet here would mean the framing arithmetic is different from the %d+%d+%d the "+
			"budget is derived from", ipv6HeaderSize, udpHeaderSize, ipv6Budget)
	total := 0
	for _, packet := range packets {
		require.LessOrEqual(t, len(packet), tunnelMTU)
		total += len(packet)
	}
	// Two packets carry the original IPv6 payload (the UDP header plus 1250 bytes), each behind its
	// own IPv6 header and its own fragment header. Note what is NOT doubled: the UDP header. It is
	// inside the payload being fragmented, so it appears once - counting it twice is an easy and
	// silent way to overstate the overhead by 8 bytes.
	require.Equal(t, chromeParrotUDPPayload+udpHeaderSize+2*(ipv6HeaderSize+ipv6FragmentHeaderSize), total,
		"the fragments carry the UDP header and the payload once, plus an IPv6 header and a fragment "+
			"header per fragment")
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeUDPPayload writes one payload from the device to a literal-address destination.
//
// The destination is a literal address on purpose: a domain would make this test depend on a
// resolver, and nothing about the framing question involves one. It is also passed to ListenPacket
// so the socket is created on the family the packet must be built in: a socket bound to the IPv6
// address cannot emit an IPv4 packet, and the device refuses rather than guessing, which is why the
// IPv4 cases below would otherwise fail with "address family not supported".
func writeUDPPayload(t *testing.T, instance Device, destination string, payloadLength int) {
	t.Helper()
	destinationAddress := netip.MustParseAddr(destination)
	destinationPort := netip.AddrPortFrom(destinationAddress, 443)

	packetConn, err := instance.ListenPacket(context.Background(),
		M.SocksaddrFromNet(net.UDPAddrFromAddrPort(destinationPort)))
	require.NoError(t, err, "the device must be able to open a packet socket on its own addresses")
	defer packetConn.Close()

	payload := make([]byte, payloadLength)
	for index := range payload {
		payload[index] = byte(index)
	}
	written, err := packetConn.WriteTo(payload, net.UDPAddrFromAddrPort(destinationPort))
	require.NoError(t, err)
	require.Equal(t, payloadLength, written,
		"a packet write reports the payload it accepted; the FRAMING is what this file checks")
}

// payloadSizeName turns a payload length into a sub-test name.
func payloadSizeName(payloadLength int) string {
	return "payload_" + itoa(payloadLength)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
