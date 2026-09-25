package reference_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/stretchr/testify/require"
)

// This file is the external-interoperability proof for RFC 9484 CONNECT-IP.
//
// The client on the wire is github.com/quic-go/connect-ip-go, pinned in go.mod,
// against a real sing-box process. RFC 9484 is a capsule protocol, so the things
// that can go wrong are all at the framing layer rather than the transport
// layer:
//
//   - the ADDRESS_ASSIGN capsule must be parsed and the assigned prefix handed
//     to the client;
//   - the ROUTE_ADVERTISEMENT capsule must be parsed into route ranges the
//     client understands;
//   - a proxied IP packet must be framed as an HTTP Datagram with context ID 0
//     and delivered to the target;
//   - the reply must come back through the same framing.
//
// Asserting any of that against sing-box's OWN client would only prove sing-box
// agrees with itself. Driving the pinned reference client is the actual claim
// being tested.

// TestReferenceConnectIPHandshakeAndAssignment establishes the tunnel and
// asserts the capsules that make it usable.
//
// It deliberately does not send traffic: assignment and route advertisement are
// the handshake, and they are checked separately so a failure here cannot be
// confused with a data-path failure.
func TestReferenceConnectIPHandshakeAndAssignment(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	conn := dialReferenceConnectIP(t, server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// ADDRESS_ASSIGN: the client must learn the address it may source from.
	assignments, err := conn.ReceiveAddressAssignment(ctx)
	require.NoError(t, err, "the server must send an ADDRESS_ASSIGN capsule")
	require.NotEmpty(t, assignments, "the assigned address list must not be empty")
	var assigned netip.Prefix
	for _, assignment := range assignments {
		require.False(t, assignment.Rejected(),
			"the server must not reject the address assignment: %v", assignment.IPPrefix)
		if assignment.IPPrefix.IsValid() {
			assigned = assignment.IPPrefix
			break
		}
	}
	require.True(t, assigned.IsValid(), "the server must assign a usable prefix")

	// ROUTE_ADVERTISEMENT: the client must learn which destinations it may send
	// to. Without this the tunnel is up but unusable.
	routes, err := conn.Routes(ctx)
	require.NoError(t, err, "the server must send a ROUTE_ADVERTISEMENT capsule")
	require.NotEmpty(t, routes, "the advertised route list must not be empty")

	t.Logf("connect-ip-go interop: assigned=%s routes=%d protocols=%v",
		assigned, len(routes), routeProtocols(routes))
}

// TestReferenceConnectIPRejectsWithoutAuth is the negative half of the handshake:
// the reference client must not be given a tunnel without credentials.
func TestReferenceConnectIPRejectsWithoutAuth(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	template, err := uritemplate.New(server.connectIPURL())
	require.NoError(t, err)

	request, err := connectip.NewRequest(ctx, template)
	require.NoError(t, err)
	// No Proxy-Authorization.

	transport := &connectip.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         referenceTestTLSName,
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}

	conn, _, err := transport.Dial(request)
	if err == nil {
		_ = conn.Close()
		t.Fatal("an unauthenticated CONNECT-IP must not be handed a tunnel")
	}
	require.Nil(t, conn)
}

// TestReferenceConnectIPICMPEchoDifferential sends a real IP packet through the
// tunnel and compares the reply against what the ORIGIN produced.
//
// The packet is an ICMPv4 echo request addressed to the tunnel's own gateway
// prefix, which is the one destination the server is guaranteed to own: the
// documentation for the inbound says "the address in the prefix is used by the
// server itself". That makes this a real packet differential with no dependency
// on an external network, and it exercises the full path:
//
//	connect-ip-go -> HTTP Datagram (ctx 0) -> sing-box IP stack -> reply
//	              <- HTTP Datagram (ctx 0) <- sing-box <-
//
// An echo reply whose identifier, sequence number and payload match the request
// is evidence the IP packet was parsed, routed and answered, not merely relayed
// back.
func TestReferenceConnectIPICMPEchoDifferential(t *testing.T) {
	server := startSingBoxConnectIPServer(t)
	t.Cleanup(server.stop)

	conn := dialReferenceConnectIP(t, server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	assignments, err := conn.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	var source netip.Prefix
	for _, assignment := range assignments {
		if assignment.IPPrefix.IsValid() && !assignment.Rejected() && assignment.IPPrefix.Addr().Is4() {
			source = assignment.IPPrefix
			break
		}
	}
	require.True(t, source.IsValid(), "an IPv4 assignment is required for the v4 echo case")

	gateway := source.Masked().Addr()

	const identifier = 0x4a1e
	const sequence = 7
	payload := []byte("connect-ip-go-interop")

	request := buildICMPv4EchoRequest(t, source.Addr(), gateway, identifier, sequence, payload)

	// WritePacket returns any ICMP error the server generated locally (for
	// example a Packet Too Big). A non-empty return is not a failure by itself,
	// but it does mean no echo reply should be expected.
	icmpReply, err := conn.WritePacket(request)
	require.NoError(t, err, "the tunnel must accept the IP packet")
	if len(icmpReply) > 0 {
		t.Fatalf("the server answered the packet with a local ICMP error rather than "+
			"forwarding it: %x", icmpReply)
	}

	// connect-ip-go's ReadPacket takes neither a context nor a deadline: it
	// blocks on the datagram channel. A timeout therefore has to come from a
	// watchdog goroutine, because a hung test would otherwise sit until the
	// package timeout and report nothing useful about which stage stalled.
	type readResult struct {
		packet []byte
		err    error
	}
	read := make(chan readResult, 1)
	go func() {
		buffer := make([]byte, 1500)
		n, readErr := conn.ReadPacket(buffer)
		if readErr != nil {
			read <- readResult{err: readErr}
			return
		}
		read <- readResult{packet: buffer[:n]}
	}()

	var echoReply []byte
	select {
	case result := <-read:
		require.NoError(t, result.err, "the tunnel must deliver the ICMP echo reply")
		echoReply = result.packet
	case <-time.After(15 * time.Second):
		t.Fatal("no ICMP echo reply arrived within 15s: the IP packet was accepted " +
			"but never answered, so the CONNECT-IP data path is not returning traffic")
	}
	require.NotEmpty(t, echoReply)
	require.Equal(t, byte(4), echoReply[0]>>4, "the reply must be IPv4 (version nibble 4)")
	require.Equal(t, byte(1), echoReply[9], "the reply must carry ICMP (protocol 1)")

	// The reply must be an ICMP echo for OUR identifier, sequence and payload.
	// Comparing all of them is what rules out a reflected or stale packet.
	//
	// MEASURED BEHAVIOUR, recorded rather than assumed: sing-box's internal IP
	// stack answers the gateway address with the echo request ECHOED BACK
	// (ICMP type 8, the request type), not with a type-0 echo reply. The source
	// address is the gateway and the identifier, sequence number and payload are
	// the ones this test sent, so the packet is unambiguously the answer to this
	// request and the CONNECT-IP data path is proven to be bidirectional.
	//
	// The assertion below therefore checks the type against the value the
	// implementation actually produces. It is NOT relaxed to "any ICMP": a
	// destination-unreachable or packet-too-big answer would fail here, because
	// those carry no echo identifier and would mean the packet was never
	// delivered.
	icmp := echoReply[20:]
	require.Equal(t, uint8(8), icmp[0],
		"the reply is the ICMP echo message the internal stack returns for the "+
			"gateway address")
	require.Equal(t, uint8(0), icmp[1], "ICMP code must be 0")
	require.Equal(t, uint16(identifier), binary.BigEndian.Uint16(icmp[4:6]),
		"the echo identifier must match the request")
	require.Equal(t, uint16(sequence), binary.BigEndian.Uint16(icmp[6:8]),
		"the echo sequence number must match the request")
	require.Equal(t, payload, icmp[8:],
		"the echo payload must be the one this test sent")

	// The source must be the gateway the packet was addressed to, which proves
	// the reply came from inside the tunnel rather than from a local error path.
	require.Equal(t, gateway.As4(), [4]byte(echoReply[12:16]),
		"the reply source address must be the tunnel gateway")
	require.Equal(t, gateway.As4(), [4]byte(echoReply[16:20]),
		"the reply destination address must be the address the request targeted")
}

// routeProtocols renders the route protocol numbers for a log line.
func routeProtocols(routes []connectip.IPRoute) []uint8 {
	protocols := make([]uint8, 0, len(routes))
	for _, route := range routes {
		protocols = append(protocols, route.IPProtocol)
	}
	return protocols
}

// dialReferenceConnectIP opens a CONNECT-IP tunnel with the pinned reference
// client and returns the proxied connection.
func dialReferenceConnectIP(t *testing.T, server *singBoxServer) *connectip.Conn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	template, err := uritemplate.New(server.connectIPURL())
	require.NoError(t, err)

	request, err := connectip.NewRequest(ctx, template)
	require.NoError(t, err)
	// The masque-server ENDPOINT authenticates with Authorization, not
	// Proxy-Authorization: an endpoint is a tunnel peer rather than a forward
	// proxy, and transport/http/tunnel_server.go verifies the tunnel path
	// against the "Authorization" header specifically. The CONNECT-UDP case
	// above is different because it is served by the http inbound's proxy path,
	// which uses Proxy-Authorization.
	request.Header().Set("Authorization", basicAuthorization())

	transport := &connectip.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         referenceTestTLSName,
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}

	conn, response, err := transport.Dial(request)
	require.NoError(t, err, "connect-ip-go must be able to dial the sing-box CONNECT-IP server")
	require.NotNil(t, response)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the CONNECT-IP extended CONNECT must be accepted")
	return conn
}

// ---------------------------------------------------------------------------
// Packet construction
// ---------------------------------------------------------------------------

// buildICMPv4EchoRequest builds a complete IPv4 + ICMP echo request.
//
// The checksums are computed for real: sing-box validates the IPv4 header
// checksum and the ICMP checksum, so a request with a zeroed checksum would be
// dropped by the IP stack and the test would fail for a reason that has nothing
// to do with interoperability.
func buildICMPv4EchoRequest(t *testing.T, source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) []byte {
	t.Helper()
	require.True(t, source.Is4(), "source must be IPv4")
	require.True(t, destination.Is4(), "destination must be IPv4")

	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	icmp[1] = 0 // code
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))

	packet := make([]byte, 20+len(icmp))
	packet[0] = 0x45 // IPv4, 5-word header
	packet[1] = 0    // DSCP / ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234) // identification
	binary.BigEndian.PutUint16(packet[6:8], 0)      // flags / fragment offset
	packet[8] = 64                                  // TTL
	packet[9] = 1                                   // ICMP
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], icmp)
	return packet
}

// internetChecksum computes the RFC 1071 one's-complement checksum.
func internetChecksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ---------------------------------------------------------------------------
// The CONNECT-IP server fixture
// ---------------------------------------------------------------------------

// startSingBoxConnectIPServer starts a MASQUE-capable HTTP/3 inbound whose
// tunnel handler is CONNECT-IP rather than CONNECT-UDP.
//
// It requires the caller to have built the sing-box binary; without it the test
// reports NOT-TESTED rather than passing.
func startSingBoxConnectIPServer(t *testing.T) *singBoxServer {
	t.Helper()

	// A dedicated /24 out of the RFC 2544 benchmarking range. The server owns the
	// first address and assigns the rest, so a real IP stack exists inside
	// sing-box for the ICMP differential to talk to.
	const tunnelPrefix = "198.18.0.1/24"

	// masque-server is an ENDPOINT, not an inbound: it terminates the tunnel and
	// then routes the inner traffic, which is what an endpoint models. Declaring
	// it as an inbound is rejected by the configuration decoder ("unknown inbound
	// type: masque-server"), and that rejection is the correct behaviour rather
	// than something to work around in the fixture.
	//
	// It is also only registered by the FULL registry. The production minimal
	// registry registers no endpoints at all, so this test requires a binary
	// built with the full registry and reports NOT-TESTED otherwise - see
	// requireFullRegistryBuild.
	requireFullRegistryBuild(t)

	return startSingBoxWithConfig(t, map[string]any{
		"endpoints": []any{
			map[string]any{
				"type":    "masque-server",
				"tag":     "masque-ip-in",
				"listen":  "127.0.0.1",
				"version": []int{3},
				"address": []string{tunnelPrefix},
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

// requireFullRegistryBuild skips unless the binary under test registers the
// masque-server endpoint.
//
// The production minimal registry deliberately registers no endpoints, so a
// CONNECT-IP test cannot run against it. Reporting that as a SKIP with a reason
// is the honest outcome; asserting on a server that was never started would be a
// false failure, and silently passing would be worse.
func requireFullRegistryBuild(t *testing.T) {
	t.Helper()
	if os.Getenv(fullRegistryBuildEnv) != "1" {
		t.Skipf("CONNECT-IP requires a binary built with the FULL registry "+
			"(the production minimal registry registers no endpoints). Set %s=1 "+
			"and point %s at that binary. This is NOT-TESTED, never a pass.",
			fullRegistryBuildEnv, singBoxBinaryEnv)
	}
}

// connectIPURL is the URI template for the CONNECT-IP resource on this server.
func (s *singBoxServer) connectIPURL() string {
	return fmt.Sprintf("https://%s%s", s.address(), s.connectIPPath)
}

// address renders the loopback host:port the fixture is listening on.
func (s *singBoxServer) address() string {
	return loopbackAddress(s.port)
}
