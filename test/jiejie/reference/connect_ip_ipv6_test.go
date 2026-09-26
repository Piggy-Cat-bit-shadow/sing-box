package reference_test

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Live IPv6 control capsules.
//
// The control_capsule_wire_test.go vectors prove the harness decoder is right
// against bytes written from the RFC. This file proves the same decoder against
// bytes a REAL sing-box CONNECT-IP endpoint produced for an IPv6 tunnel, which is
// the other half: a decoder can be correct in isolation and still disagree with
// the implementation.
//
// It exists because every control-capsule fixture in this module was IPv4, and the
// decoder bug it pins was invisible for IPv4 by coincidence (the IP Version byte
// is 4, which is also the IPv4 address length). An IPv6 tunnel is the only fixture
// that can fail on it.

// connectIPv6TunnelPrefix is the IPv6 tunnel network. The server owns the first
// address and assigns the rest. 2001:db8::/32 is the RFC 3849 documentation
// prefix, so it can never be a real destination.
const (
	connectIPv6TunnelPrefix = "2001:db8:1::1/64"
	connectIPv6ServerAddr   = "2001:db8:1::1"
)

// startSingBoxConnectIPv6Server starts a masque-server endpoint whose tunnel
// network is IPv6.
//
// The endpoint derives its ROUTE_ADVERTISEMENT from the intersection of the
// requested target and its own advertised routes, restricted to the address
// families it can actually assign, so an IPv6 `address` produces IPv6 ranges on
// the wire. That is what makes the v6 decoder reachable at all.
func startSingBoxConnectIPv6Server(t *testing.T) *singBoxServer {
	t.Helper()
	requireFullRegistryBuild(t)

	return startSingBoxWithConfig(t, map[string]any{
		"endpoints": []any{
			map[string]any{
				"type":    "masque-server",
				"tag":     "masque-ip6-in",
				"listen":  "127.0.0.1",
				"version": []int{3},
				"address": []string{connectIPv6TunnelPrefix},
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

// TestReferenceConnectIPv6ControlCapsulesAgainstRealServer drives the IPv6
// control capsules through a real server and the corrected decoder.
//
// Three things are asserted, and the third is the one that only an IPv6 fixture
// can catch:
//
//  1. an IPv6 ADDRESS_ASSIGN arrives and decodes to a v6 prefix;
//  2. an IPv6 ROUTE_ADVERTISEMENT arrives and decodes to v6 ranges;
//  3. every route's start and end are BOTH IPv6, which is only possible if the
//     version byte was read as a version and the end address was read at the right
//     offset.
//
// A decoder that reads 6 address bytes for IPv6 cannot satisfy (1) at all, and one
// that reads a version byte before the end address satisfies (2) only by
// misreading the protocol as part of an address.
func TestReferenceConnectIPv6ControlCapsulesAgainstRealServer(t *testing.T) {
	server := startSingBoxConnectIPv6Server(t)
	t.Cleanup(server.stop)

	conn := dialReferenceConnectIP(t, server)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	assignments, err := conn.ReceiveAddressAssignment(ctx)
	require.NoError(t, err, "the server must send an ADDRESS_ASSIGN capsule")
	require.NotEmpty(t, assignments)

	var assigned netip.Prefix
	for _, assignment := range assignments {
		require.False(t, assignment.Rejected(),
			"the server must not reject the assignment: %v", assignment.IPPrefix)
		if assignment.IPPrefix.IsValid() && assignment.IPPrefix.Addr().Is6() {
			assigned = assignment.IPPrefix
			break
		}
	}
	require.True(t, assigned.IsValid(),
		"an IPv6 tunnel must be assigned an IPv6 address; got %v", assignments)
	require.True(t, netip.MustParsePrefix(connectIPv6TunnelPrefix).Contains(assigned.Addr()),
		"the assignment %s must fall inside the configured tunnel prefix %s",
		assigned, connectIPv6TunnelPrefix)
	require.NotEqual(t, netip.MustParseAddr(connectIPv6ServerAddr), assigned.Addr(),
		"the server must not assign its own address to the client")

	routes, err := conn.Routes(ctx)
	require.NoError(t, err, "the server must send a ROUTE_ADVERTISEMENT capsule")
	require.NotEmpty(t, routes, "an IPv6 tunnel must advertise at least one route")

	for index, route := range routes {
		require.True(t, route.StartIP.Is6(),
			"route %d start %s must be IPv6: a v4 start here means the version byte "+
				"was not read as a version", index, route.StartIP)
		require.True(t, route.EndIP.Is6(),
			"route %d end %s must be IPv6: a v4 end here means the end address was "+
				"read at the wrong offset", index, route.EndIP)
		require.False(t, route.EndIP.Less(route.StartIP),
			"route %d must not end before it starts: %s - %s",
			index, route.StartIP, route.EndIP)
	}

	t.Logf("connect-ip IPv6 interop: assigned=%s routes=%d protocols=%v",
		assigned, len(routes), routeProtocols(routes))
}

// TestReferenceConnectIPv6DatagramCapsuleFallback runs the IPv6 tunnel over the
// CAPSULE path, which is the path the production CONNECT-IP transport uses when a
// peer declines HTTP Datagrams.
//
// A datagram-capable reference client would take the datagram path and never
// exercise the capsule decoder for v6, so this uses the datagram-disabled peer.
func TestReferenceConnectIPv6DatagramCapsuleFallback(t *testing.T) {
	server := startSingBoxConnectIPv6Server(t)
	t.Cleanup(server.stop)

	client := startDatagramDisabledConnectIPClient(t, server)
	stream, response := client.openTunnel(t, server)
	defer response.Body.Close()

	assigned, routes := readAddressAssignmentAndRoutes(t, stream)
	require.True(t, assigned.IsValid(), "an IPv6 address must be assigned")
	require.True(t, assigned.Addr().Is6(),
		"the capsule decoder must read an IPv6 assignment as IPv6; got %s", assigned)
	require.NotEmpty(t, routes)
	for index, route := range routes {
		require.True(t, route.StartIP.Is6() && route.EndIP.Is6(),
			"route %d must be IPv6 on both ends: %s - %s",
			index, route.StartIP, route.EndIP)
	}

	t.Logf("connect-ip IPv6 capsule fallback: assigned=%s routes=%d",
		assigned, len(routes))

	// One real packet round trip over the capsule path, to prove the data path
	// works with an IPv6 inner packet and not merely the control plane.
	gateway := netip.MustParseAddr(connectIPv6ServerAddr)
	require.True(t, assigned.Contains(gateway) == false,
		"the gateway must be the server's own address, not the client's")

	const identifier = 0x39f1
	const sequence = 3
	packet := buildICMPv6EchoRequest(t, assigned.Addr(), gateway, identifier, sequence,
		[]byte("connect-ip-v6-capsule"))

	require.NoError(t, writeDatagramCapsuleToStream(stream, packet))
	reply := readDatagramCapsuleWithTimeout(t, stream, 15*time.Second)
	require.NotEmpty(t, reply, "the server must answer an IPv6 echo request")
	require.Equal(t, byte(6), reply[0]>>4, "the reply must be IPv6")
	require.Equal(t, byte(58), reply[6], "the reply must carry ICMPv6 (next header 58)")

	icmp := reply[40:]
	require.Equal(t, uint8(129), icmp[0],
		"the server must answer with an ICMPv6 echo REPLY (type 129); type 128 "+
			"would mean the request was reflected rather than answered")
	require.Equal(t, uint8(0), icmp[1], "ICMPv6 code must be 0")
	require.Equal(t, uint16(identifier), binary.BigEndian.Uint16(icmp[4:6]))
	require.Equal(t, uint16(sequence), binary.BigEndian.Uint16(icmp[6:8]))
}

// buildICMPv6EchoRequest builds a complete IPv6 + ICMPv6 echo request with real
// checksums, because the server's IP stack validates both the IPv6 payload length
// and the ICMPv6 checksum (which covers the IPv6 pseudo-header).
func buildICMPv6EchoRequest(t *testing.T, source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) []byte {
	t.Helper()
	require.True(t, source.Is6(), "source must be IPv6")
	require.True(t, destination.Is6(), "destination must be IPv6")

	icmp := make([]byte, 8+len(payload))
	icmp[0] = 128 // echo request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], ipv6Checksum(source, destination, 58, icmp))

	packet := make([]byte, 40+len(icmp))
	packet[0] = 0x60 // IPv6
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(icmp)))
	packet[6] = 58 // ICMPv6
	packet[7] = 64 // Hop Limit
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	copy(packet[40:], icmp)
	return packet
}

// ipv6Checksum computes the ICMPv6 checksum, which includes the IPv6
// pseudo-header (RFC 8200 section 8.1).
func ipv6Checksum(source netip.Addr, destination netip.Addr, nextHeader byte, payload []byte) uint16 {
	pseudo := make([]byte, 0, 40+len(payload))
	pseudo = append(pseudo, source.AsSlice()...)
	pseudo = append(pseudo, destination.AsSlice()...)
	pseudo = append(pseudo, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	pseudo = append(pseudo, 0, 0, 0, nextHeader)
	pseudo = append(pseudo, payload...)
	return internetChecksum(pseudo)
}
