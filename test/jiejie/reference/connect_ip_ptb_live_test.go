package reference_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/stretchr/testify/require"
)

// Live CONNECT-IP Packet Too Big, end to end, over a REAL HTTP/3 tunnel.
//
// # What this closes, and why the previous fixture could not
//
// The ICMP error the endpoint GENERATES is covered field by field by
// transport/masque/packet_too_big_test.go. What no unit test can reach is the
// TRIGGER: quic-go's DatagramTooLargeError, which only occurs when a datagram
// exceeds the connection's real maximum datagram payload size. The earlier live
// fixture could not reach it either, and recorded why in a MEASURED note: its
// echo tunnel is SYMMETRIC, so a request large enough to matter produced an echo
// reply the server could always shrink to fit. "A request that fits, a reply that
// does not" is the condition DatagramTooLarge needs, and a symmetric loopback
// tunnel cannot produce it. That fixture therefore reported NOT-TESTED, correctly.
//
// # How the asymmetry is manufactured without a public origin
//
// quic-go computes a connection's datagram send limit from BOTH peers' advertised
// frames and the LOCAL conservative payload estimate, and the local estimate is
// seeded from the connection's own InitialPacketSize and only ever GROWS. So
// configuring the two peers with different InitialPacketSize values, and disabling
// path MTU discovery on both so nothing later raises either estimate, yields a
// connection whose two directions genuinely have different capacities.
//
// MEASURED on this fixture by reading the limit quic-go reports (see
// discoverDatagramPayloadLimit; the value is measured, never hard-coded):
//
//	server InitialPacketSize 1350, client InitialPacketSize 1350 -> client send limit 1313
//	server InitialPacketSize 1350, client InitialPacketSize 1452 -> client send limit 1415
//
// The client can therefore SEND a 1400-byte packet that the SERVER cannot send
// back, because the server's own estimate stays pinned at 1350 minus the QUIC
// header overhead. That is exactly "request fits, reply does not", built from the
// two peers' own configuration rather than from a cooperative origin.
//
// # The failure this test found
//
// Running it against the unmodified endpoint produced no PTB at all, and the
// reason was a real defect in the delivery path rather than in the trigger. The
// oversized packet is one the endpoint was SENDING INTO the tunnel, so
// buildICMPError addressed the error to that packet's SOURCE - which for an
// endpoint-generated packet (the echo reply here) is the endpoint's own tunnel
// address. Routing the error by its destination then looked up the ENDPOINT's
// address, which lookup() refuses by design because that address is the server's
// and not a client's, so no session matched and the error was handed to the local
// device instead of into the tunnel. MEASURED, before the fix:
//
//	DatagramTooLarge maxPayload=1312 mtu=1311 pktlen=1345
//	reply src=198.18.0.1 dst=198.18.0.1   quoted src=198.18.0.1 dst=198.18.0.2
//	lookup(198.18.0.1) -> not found       client received: nothing
//
// The endpoint now addresses the error to the peer that owns the failing tunnel
// and queues it on that same session. See serverSession.handlePacketTooBig.

// The two peer configurations that create the asymmetry. The client's larger
// value is what gives it more send capacity than the server has.
const (
	ptbServerInitialPacketSize = 1350
	ptbClientInitialPacketSize = 1452
	ptbTunnelMTU               = 1400
)

// startConnectIPAsymmetricPTBServer starts a CONNECT-IP endpoint configured for
// the asymmetric datagram-capacity fixture.
//
// It is deliberately SEPARATE from startSingBoxConnectIPServer rather than an
// option on it. The asymmetry is the entire mechanism of this test, and a shared
// fixture that quietly stopped setting it would turn the test back into the
// symmetric one that cannot reach the trigger - while still passing. Keeping the
// configuration local makes that regression impossible to introduce by editing a
// different test's fixture.
//
// disable_path_mtu_discovery is required on the server: quic-go's payload estimate
// grows when PMTU discovery raises the path MTU, and a grown estimate would let the
// server send the reply and remove the trigger.
func startConnectIPAsymmetricPTBServer(t *testing.T) *singBoxServer {
	t.Helper()

	// masque-server is an ENDPOINT registered only by the FULL registry. The
	// production minimal registry registers no endpoints, so this reports
	// NOT-TESTED against that binary rather than failing.
	requireFullRegistryBuild(t)

	return startSingBoxWithConfig(t, map[string]any{
		"endpoints": []any{
			map[string]any{
				"type":                       "masque-server",
				"tag":                        "masque-ip-in",
				"listen":                     "127.0.0.1",
				"version":                    []int{3},
				"address":                    []string{connectIPTunnelPrefix},
				"mtu":                        ptbTunnelMTU,
				"initial_packet_size":        ptbServerInitialPacketSize,
				"disable_path_mtu_discovery": true,
				"users": []any{
					map[string]any{
						"username": referenceTestUser,
						"password": referenceTestPassword,
					},
				},
			},
		},
	})
}

// startAsymmetricConnectIPClient dials the endpoint with the larger
// InitialPacketSize that gives this peer more send capacity than the server.
//
// It is a separate constructor rather than a parameter on
// startConnectIPControlPeer, so the existing CONNECT-IP tests keep their exact
// previous QUIC configuration. Changing a shared helper's dial parameters would
// silently re-specify every other test in this package.
func startAsymmetricConnectIPClient(t *testing.T, server *singBoxServer) *connectIPControlPeer {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, server.address(), &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{
		EnableDatagrams:         true,
		InitialPacketSize:       ptbClientInitialPacketSize,
		DisablePathMTUDiscovery: true,
	})
	require.NoError(t, err)

	transport := &http3.Transport{EnableDatagrams: true}
	peer := &connectIPControlPeer{
		clientConn:     transport.NewClientConn(quicConn),
		transport:      transport,
		quicConn:       quicConn,
		enableDatagram: true,
	}
	t.Cleanup(func() {
		peer.clientConn.CloseWithError(0, "")
		transport.Close()
		_ = quicConn.CloseWithError(0, "")
	})
	return peer
}

// TestReferenceConnectIPPacketTooBigOverHTTP3Live asserts the live PTB path.
//
// Unlike the earlier fixture, this one REQUIRES a Packet Too Big. The asymmetry is
// constructed deliberately, so a missing PTB is a failure of the code under test
// rather than an unreachable branch - which is the whole difference between this
// test and the NOT-TESTED record it replaces.
func TestReferenceConnectIPPacketTooBigOverHTTP3Live(t *testing.T) {
	server := startConnectIPAsymmetricPTBServer(t)
	t.Cleanup(server.stop)

	client := startAsymmetricConnectIPClient(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid(), "the endpoint must assign the client an address")
	require.NotEmpty(t, routes, "the endpoint must advertise routes")
	gateway := serverGatewayAddress(t)

	// Read the connection's real datagram send limit from the peer's own view.
	// quic-go exposes no getter, but an oversized SendDatagram is refused LOCALLY
	// and reports the maximum, so nothing is transmitted and no state is disturbed.
	clientLimit, err := discoverDatagramPayloadLimit(t, stream)
	require.NoError(t, err,
		"the connection must negotiate HTTP Datagrams and report a limit, or this "+
			"test would measure the capsule fallback instead of the datagram path")

	// The mechanism, asserted rather than assumed: the client's own send capacity
	// must exceed what the server's smaller InitialPacketSize can carry. If this
	// ever stops holding, the trigger is gone and every later assertion would be
	// vacuous, so it is checked here with the discovered values.
	require.Greater(t, clientLimit, ptbServerInitialPacketSize-40,
		"the client's discovered datagram limit (%d) must exceed the server's own "+
			"send capacity, which is why the peers use different InitialPacketSize "+
			"values. Without that asymmetry a symmetric echo can always shrink its "+
			"reply to fit and DatagramTooLarge is unreachable", clientLimit)
	t.Logf("negotiated: client send limit=%d bytes, server InitialPacketSize=%d, tunnel MTU=%d",
		clientLimit, ptbServerInitialPacketSize, ptbTunnelMTU)

	// # Sizing the trigger packet
	//
	// Three constraints, all measured rather than hard-coded:
	//
	//   - len(packet) must be BELOW the configured tunnel MTU, so the PTB cannot
	//     have come from the endpoint's own MTU check. That would be a false
	//     positive: handlePacket's size handling would reject it without any
	//     involvement from DatagramTooLarge.
	//   - the framed packet (context ID + packet) must be at or below the client's
	//     discovered send limit, or the CLIENT refuses it locally and nothing
	//     reaches the server at all.
	//   - it must be large enough that the server's echo reply does not fit in the
	//     server's smaller send capacity.
	//
	// The range is derived from the discovered limit, and the exact trigger size is
	// then MEASURED by walking up from the largest always-safe size.
	require.Greater(t, clientLimit, 1, "a datagram limit of at most 1 byte cannot carry a packet")
	triggerCeiling := min(clientLimit-1, ptbTunnelMTU-1)

	var (
		ptbReply    []byte
		triggerSize int
	)
	// Walk upward and stop at the FIRST size that produces a PTB. Starting from the
	// top and working down would report a larger size than necessary and make the
	// "advertised MTU < original packet" relationship harder to read.
	for size := 1200; size <= triggerCeiling; size += 16 {
		payload := make([]byte, size-28)
		for index := range payload {
			payload[index] = byte('A' + index%26)
		}
		packet := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, uint16(0x7b00+size), 1, payload)
		require.Less(t, len(packet), ptbTunnelMTU,
			"the trigger packet must be strictly below the configured tunnel MTU, or a "+
				"PTB could be produced by the endpoint's own MTU handling instead of by "+
				"the HTTP/3 datagram capacity this test exists to exercise")
		require.LessOrEqual(t, len(packet)+1, clientLimit,
			"the framed packet must fit the client's own send limit, or quic-go refuses "+
				"it locally and the server never sees it")

		require.NoError(t, stream.SendDatagram(append([]byte{0}, packet...)))

		reply, arrived := readConnectIPDatagramWithTimeout(t, stream, 5*time.Second)
		require.True(t, arrived,
			"the tunnel must answer a %d-byte echo request. No reply means the session "+
				"died on the exchange, which is wrong at every size", len(packet))

		if len(reply) >= 28 && reply[9] == 1 && reply[20] == 3 {
			ptbReply = reply
			triggerSize = len(packet)
			break
		}
		// A normal echo reply means the packet fit in both directions. Continue
		// upward: the asymmetry only bites once the reply no longer fits.
		require.GreaterOrEqual(t, len(reply), 28,
			"a reply too short to classify at size %d", len(packet))
		require.Equal(t, uint8(1), reply[9],
			"the reply to an echo request must carry ICMP, got protocol %d at size %d",
			reply[9], len(packet))
	}

	require.NotNil(t, ptbReply,
		"NO Packet Too Big was produced anywhere in 1200..%d bytes. The asymmetric "+
			"fixture exists precisely to make the datagram-capacity trigger reachable, "+
			"so its absence is a failure of the PTB path and not an unreachable branch",
		triggerCeiling)

	// # The PTB is real, and it came from the datagram capacity
	t.Logf("LIVE PTB TRIGGERED at packet size %d (tunnel MTU %d, client limit %d)",
		triggerSize, ptbTunnelMTU, clientLimit)

	require.Equal(t, uint8(4), ptbReply[0]>>4, "the PTB must be IPv4")
	require.Equal(t, uint8(1), ptbReply[9], "the PTB must carry ICMP")
	require.Equal(t, uint8(3), ptbReply[20],
		"the PTB must be an ICMP Destination Unreachable")
	require.Equal(t, uint8(4), ptbReply[21],
		"an ICMP Destination Unreachable for an oversized packet must carry code 4 "+
			"(Fragmentation Needed)")

	advertisedMTU := binary.BigEndian.Uint16(ptbReply[26:28])
	require.GreaterOrEqual(t, advertisedMTU, uint16(minimumLinkMTUForAssertions),
		"the advertised MTU must be at least the minimum the endpoint enforces")
	require.Less(t, int(advertisedMTU), triggerSize,
		"the advertised MTU (%d) must be BELOW the original packet size (%d), or the "+
			"error does not describe this packet", advertisedMTU, triggerSize)
	require.Less(t, int(advertisedMTU), ptbTunnelMTU,
		"the advertised MTU (%d) must be below the configured tunnel MTU (%d). If it "+
			"equalled the tunnel MTU the PTB could have been produced by the endpoint's "+
			"own MTU check rather than by the HTTP/3 datagram capacity, which is the "+
			"distinction this test exists to make", advertisedMTU, ptbTunnelMTU)

	// Addressing: from the gateway, to the assigned client. This is the assertion
	// that failed before the handlePacketTooBig fix, where the error was addressed
	// to the endpoint's own address and never reached the tunnel.
	require.Equal(t, gateway.As4(), [4]byte(ptbReply[12:16]),
		"the PTB must be sourced from the endpoint's gateway address")
	require.Equal(t, assigned.Addr().As4(), [4]byte(ptbReply[16:20]),
		"the PTB must be addressed to the client that sent the oversized packet. An "+
			"error addressed to the endpoint itself is delivered to the local device "+
			"and the peer never learns the packet was too big")

	// Checksums. The endpoint recomputes the IPv4 header checksum after rewriting
	// the destination, so a stale checksum would be a real defect rather than a
	// detail: the peer's stack discards the error and it looks exactly like the
	// delivery failure being fixed.
	require.Equal(t, uint16(0), internetChecksum(ptbReply[:20]),
		"the IPv4 header checksum must verify after the destination rewrite")
	require.Equal(t, uint16(0), internetChecksum(ptbReply[20:]),
		"the ICMP checksum must verify")

	// The quoted packet must be the one that was too large: at minimum the original
	// IP header plus the 8 bytes RFC 792 requires.
	require.GreaterOrEqual(t, len(ptbReply), 28+28,
		"the PTB must quote at least the original IP header and 8 bytes of its payload")
	quoted := ptbReply[28:]
	require.Equal(t, uint8(4), quoted[0]>>4, "the quoted packet must be IPv4")
	require.Equal(t, gateway.As4(), [4]byte(quoted[12:16]),
		"the quoted packet's source must match the request that was too large")
	require.Equal(t, assigned.Addr().As4(), [4]byte(quoted[16:20]),
		"the quoted packet's destination must match the request that was too large")

	// # The tunnel survives
	//
	// DatagramTooLarge plus a generated PTB must not tear the session down. This is
	// the assertion that makes the difference between "reported the problem" and
	// "reported the problem and kept working".
	const survivorIdentifier = 0x5150
	survivor := buildICMPv4EchoRequest(t, assigned.Addr(), gateway, survivorIdentifier, 2,
		[]byte("ptb-survivor"))
	require.NoError(t, stream.SendDatagram(append([]byte{0}, survivor...)),
		"the tunnel must still be writable after an oversized exchange")

	after, afterOK := readConnectIPDatagramWithTimeout(t, stream, 10*time.Second)
	require.True(t, afterOK,
		"the tunnel must still deliver after the PTB; a session torn down by the size "+
			"failure would produce nothing here")
	require.GreaterOrEqual(t, len(after), 28, "the survivor reply is too short")
	require.Equal(t, uint8(4), after[0]>>4, "the survivor reply must be IPv4")
	require.Equal(t, uint8(1), after[9], "the survivor reply must carry ICMP")
	require.Equal(t, uint8(0), after[20],
		"a normal-sized packet after the oversized one must be answered with an echo "+
			"REPLY (type 0), not with another ICMP error")
	require.Equal(t, uint16(survivorIdentifier), binary.BigEndian.Uint16(after[24:26]),
		"the reply must answer the survivor request by identifier")
	require.Equal(t, []byte("ptb-survivor"), after[28:],
		"the reply must carry the survivor's payload, proving the tunnel is intact "+
			"rather than merely answering")
}

// minimumLinkMTUForAssertions mirrors the endpoint's own minimumLinkMTU, which is
// the floor below which session.writePacket refuses to build an error at all
// (transport/masque/session.go).
//
// It is restated rather than referenced because this package is a separate Go
// module that must not import the root module: doing so would let the reference
// clients reach the shipped dependency graph, which the harness exists to prevent.
// A live PTB below this value is impossible, so an assertion using it cannot be
// vacuous.
const minimumLinkMTUForAssertions = 1280

// IPv6 is not covered by a live PTB test here.
//
// The outcome is recorded in the audit rather than asserted, and the reason is
// measured rather than assumed: the same asymmetry that makes IPv4 reachable was
// attempted for IPv6, and the IPv6 endpoint clamps the advertised MTU to the IPv6
// minimum link MTU (RFC 8200 section 5), while the ICMPv6 error body is smaller
// than its IPv4 counterpart. Whether a given size pair triggers ICMPv6 Packet Too
// Big therefore depends on IPv6 header arithmetic rather than on the same margin
// the IPv4 fixture has, and claiming a live IPv6 result requires its own measured
// fixture. The GENERATION of the IPv6 error, including the pseudo-header checksum,
// is covered field by field by transport/masque/packet_too_big_test.go.

// Compile-time references so an unused import cannot mask a broken file.
var (
	_ = netip.Addr{}
	_ = url.Parse
	_ = uritemplate.New
	_ = http.MethodConnect
)
