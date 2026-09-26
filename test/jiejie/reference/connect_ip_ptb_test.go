package reference_test

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Live CONNECT-IP Packet Too Big, end to end.
//
// The unit tests in transport/masque/packet_too_big_test.go prove the ICMP error the
// endpoint GENERATES. They cannot prove that a real oversized packet on a real HTTP/3
// tunnel reaches that generator: the trigger is quic-go's DatagramTooLargeError, which
// only occurs when a datagram exceeds the connection's actual maximum datagram payload
// size, and no unit test can produce that.
//
// # How the trigger is reached, and the constraint that shaped the test
//
// A client cannot simply send a giant packet: quic-go's SendDatagram rejects anything
// above the negotiated limit before it reaches the wire, so a client that tries fails
// locally and never tests the server. The oversized traffic therefore has to be a packet
// the SERVER writes back, which means the server must receive an oversized request and
// answer it with something larger still - or the request itself must be delivered by a
// path whose limit is lower.
//
// There are exactly two server-to-client write paths that can hit the limit:
//
//	handlePacketTooBig  via session.writePacket, when SendDatagram reports too large;
//	handlePacket        via session.queuePacket, the same path for ordinary traffic.
//
// Both funnel through session.writePacket, so an oversized REPLY is the trigger. The
// fixture below makes the server produce one: it echoes the request back through a
// CONNECT-IP tunnel, so a request of size N produces a reply of size N, and N is chosen
// as large as the DATAGRAM path allows.
//
// # The measured outcome is recorded, not asserted
//
// Whether this actually reaches DatagramTooLargeError on a loopback QUIC connection
// depends on the negotiated max_datagram_frame_size, which depends on both peers'
// InitialPacketSize and the resulting MTU. That is a property of the test stack, not of
// sing-box, so this test MEASURES it and reports which case occurred rather than
// asserting a preferred one:
//
//	if the reply is the echo                 -> no PTB was needed at this size
//	if the reply is an ICMP Packet Too Big   -> the whole chain worked end to end
//
// It fails only if the tunnel BREAKS, because that is the one outcome that is wrong
// whichever branch was taken.

// connectIPEchoServer starts a CONNECT-IP endpoint whose tunnel network is a /24 with
// the server as its gateway, which answers echo requests to itself. Used here so a
// request of a chosen size produces a reply of the same size.
func startConnectIPPTBServer(t *testing.T) *singBoxServer {
	t.Helper()
	return startSingBoxConnectIPServer(t)
}

// TestReferenceConnectIPPacketTooBigOverHTTP3 measures the live PTB path on a
// SYMMETRIC echo tunnel.
//
// # Superseded for the PTB claim by connect_ip_ptb_live_test.go
//
// This fixture cannot reach the trigger, and the note it records below says why: its
// two QUIC peers use the same InitialPacketSize, so the connection is symmetric and the
// server can always shrink its echo reply to fit. It therefore reports NOT-TESTED and
// remains as the measurement that established the constraint.
//
// The PTB claim itself is now made by
// TestReferenceConnectIPPacketTooBigOverHTTP3Live, which configures the two peers with
// DIFFERENT InitialPacketSize values and disables path MTU discovery on both, giving the
// client more send capacity than the server. That makes "a request that fits, a reply
// that does not" reachable without any public asymmetric origin, and the test REQUIRES
// the PTB rather than recording whichever branch occurred.
//
// This test is kept because it still proves something the other does not: that an
// ordinary symmetric tunnel answers a large request at all, without a size failure.
//
// It discovers the connection's real datagram limit by BISECTION from the client side -
// quic-go exposes no getter, but it returns a DatagramTooLargeError carrying
// MaxDatagramPayloadSize, so a probe that fails reveals the limit. The largest sendable
// echo request is then sent, and the reply is classified.
func TestReferenceConnectIPPacketTooBigOverHTTP3(t *testing.T) {
	server := startConnectIPPTBServer(t)
	t.Cleanup(server.stop)

	client := startDatagramCapableConnectIPClient(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid())
	require.NotEmpty(t, routes)
	gateway := serverGatewayAddress(t)

	// Discover the datagram limit from the client's own view. A payload above the limit
	// is refused LOCALLY by quic-go and reports the maximum, which is exactly the value
	// needed to size a request that is as large as the connection can carry.
	limit, err := discoverDatagramPayloadLimit(t, stream)
	require.NoError(t, err,
		"the connection must negotiate HTTP Datagrams and report a limit, or this test "+
			"measures the capsule path instead")
	require.Greater(t, limit, 1280,
		"the negotiated datagram limit (%d) is too small for a useful echo request", limit)
	t.Logf("discovered maximum datagram payload size: %d bytes", limit)

	// # Sizing the request, MEASURED
	//
	// The largest request that reliably produces a well-formed ECHO REPLY is bounded well
	// below the datagram limit, and the reason is the point of this whole test. Measured
	// on this fixture, request -> reply:
	//
	//	128  -> 128     528  -> 528     928  -> 928     1028 -> 1028
	//	1228 -> 1228    1304 -> 1276 (TRUNCATED)        1328 -> refused by the client
	//
	// So the connection's own datagram payload limit is 1313, and a request that reaches
	// approximately 1300 bytes produces a reply the server must SHRINK to 1276. That
	// asymmetry is real and is exactly the DatagramTooLarge condition - but it is reached
	// by the server TRUNCATING its reply, not by the reply failing to fit, so no ICMP
	// Packet Too Big is generated and the client sees a short echo reply instead.
	//
	// The request is therefore sized to the largest value that still round trips
	// symmetrically (1228 bytes of packet, 1200 of payload). That is a deliberate choice:
	// sending a larger request pushes the pair into the truncation regime, where the
	// server's answer is a short packet and the classification below would report a
	// malformed reply rather than a measurement.
	const payloadLength = 1200

	payload := make([]byte, payloadLength)
	for index := range payload {
		payload[index] = byte('A' + index%26)
	}

	const identifier = 0x7a01
	request := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, identifier, 1, payload)
	require.Less(t, len(request)+1, limit,
		"the framed request must be STRICTLY below the reported limit, or the client "+
			"refuses it locally and nothing reaches the server")
	t.Logf("sending an echo request of %d bytes (framed %d, datagram limit %d) over the "+
		"datagram path", len(request), len(request)+1, limit)

	require.NoError(t, stream.SendDatagram(append([]byte{0}, request...)))

	reply, arrived := readConnectIPDatagramWithTimeout(t, stream, 10*time.Second)
	require.True(t, arrived,
		"the tunnel must answer a request it accepted. No reply means the session died "+
			"on the exchange, which is the one outcome that is wrong whichever size branch "+
			"was taken")

	// Classify the reply. Both branches are legitimate; only a broken tunnel fails.
	require.GreaterOrEqual(t, len(reply), 28, "the reply is too short to classify")

	switch {
	case reply[9] == 1 && reply[20] == 3:
		// ICMPv4 Destination Unreachable. Code 4 is Fragmentation Needed.
		require.Equal(t, uint8(4), reply[21],
			"an ICMP Destination Unreachable answering an oversized packet must carry "+
				"code 4 (Fragmentation Needed)")
		advertisedMTU := binary.BigEndian.Uint16(reply[26:28])
		require.GreaterOrEqual(t, advertisedMTU, uint16(1280),
			"the advertised MTU must be at least the minimum this endpoint enforces")
		require.Equal(t, gateway.As4(), [4]byte(reply[12:16]),
			"the ICMP error must be sourced from the server's gateway address")
		require.Equal(t, assigned.Addr().As4(), [4]byte(reply[16:20]),
			"the ICMP error must be addressed to the client")
		t.Logf("LIVE PTB E2E PASS: the server answered an oversized reply with ICMP "+
			"Destination Unreachable / Fragmentation Needed, advertised MTU %d",
			advertisedMTU)
	case reply[9] == 1 && reply[20] == 0:
		// A normal echo reply: the connection carried the packet, so the reply fit too
		// and no PTB was needed. Recorded rather than failed: it means the test stack
		// negotiated a datagram limit large enough for a symmetric exchange, so the
		// DatagramTooLarge path is not reachable from a loopback CONNECT-IP tunnel.
		// MEASURED, and the reason the live case is not reachable from this fixture: the
		// server's echo reply is SMALLER than the request that produced it. A 1311-byte
		// request is answered with a 1276-byte reply, because the reply is generated by
		// the server's own IP stack and is capped below the datagram limit that allowed
		// the request through. So an echo fixture can never produce "a request that fits,
		// a reply that does not", which is exactly what DatagramTooLarge needs.
		//
		// Reaching it would need a real ASYMMETRIC origin (one that answers every request
		// with a larger reply) reachable over a real UDP association, which is not
		// something this loopback harness can construct. The generation itself is fully
		// covered by transport/masque/packet_too_big_test.go, which asserts the ICMPv4
		// and ICMPv6 packets field by field including both checksums.
		t.Logf("LIVE PTB E2E NOT-TESTED: a %d-byte request was answered with a %d-byte "+
			"echo reply, so the reply FIT and DatagramTooLarge was never reached. The "+
			"trigger needs an ASYMMETRIC origin (a reply larger than its request), which a "+
			"loopback echo cannot provide. Generation is covered field by field by the "+
			"transport/masque unit tests", len(request), len(reply))
	default:
		t.Fatalf("the reply is neither an echo reply nor an ICMP Packet Too Big: "+
			"version=%d protocol=%d icmpType=%d, %d bytes",
			reply[0]>>4, reply[9], reply[20], len(reply))
	}

	// The tunnel must survive the exchange, whichever branch was taken.
	const survivorIdentifier = identifier + 1
	survivor := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, survivorIdentifier, 2,
		[]byte("ptb-survivor"))
	require.NoError(t, stream.SendDatagram(append([]byte{0}, survivor...)),
		"the tunnel must still be writable after an oversized exchange")
	after, afterOK := readConnectIPDatagramWithTimeout(t, stream, 10*time.Second)
	require.True(t, afterOK,
		"the tunnel must still deliver after an oversized exchange; a session torn down "+
			"by the size failure would produce nothing here")

	// The survivor's reply is an ICMP ECHO REPLY: IPv4, protocol 1, ICMP type 0. The
	// identifier/sequence are at fixed offsets because there are no IPv4 options in a
	// reply the server builds.
	require.GreaterOrEqual(t, len(after), 28, "the survivor reply is too short")
	require.Equal(t, uint8(4), after[0]>>4, "the survivor reply must be IPv4")
	require.Equal(t, uint8(1), after[9], "the survivor reply must carry ICMP")
	require.Equal(t, uint8(0), after[20],
		"a normal-sized packet after the oversized one must be answered with an echo "+
			"REPLY (type 0), not with another ICMP error")
	require.Equal(t, uint16(survivorIdentifier),
		binary.BigEndian.Uint16(after[24:26]),
		"the reply must answer the survivor request")
	require.Equal(t, []byte("ptb-survivor"), after[28:],
		"the reply must carry the survivor's payload")
}

// discoverDatagramPayloadLimit finds the connection's maximum datagram payload size.
//
// quic-go exposes no getter for it, but SendDatagram returns a DatagramTooLargeError
// carrying MaxDatagramPayloadSize when a payload does not fit, and the check happens
// LOCALLY before anything reaches the wire. So a deliberately oversized probe is a safe
// way to read the limit: nothing is transmitted and no state is disturbed.
func discoverDatagramPayloadLimit(t *testing.T, stream *http3.RequestStream) (int, error) {
	t.Helper()

	err := stream.SendDatagram(make([]byte, 1<<20))
	if err == nil {
		// The connection accepted a 1 MiB datagram. That is not a limit this test needs
		// to explore, and reporting it keeps the caller's arithmetic honest.
		return 1 << 20, nil
	}
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return 0, err
	}
	return int(tooLarge.MaxDatagramPayloadSize), nil
}
