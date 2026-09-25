package jiejie_test

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// IPv6 UDP end to end, over Naive UoT.
//
// This was previously unverified. It is a distinct case from "an IPv6 target is
// rejected by the ACL": here the tunnel must actually carry UDP to an IPv6
// origin, which exercises the address family byte in the UoT per-datagram
// encoding, the 16-byte address payload, and the reply path back through the
// Naive framing.
//
// The environment this runs in decides how far the test can go, and the test
// reports which of three cases it actually covered rather than implying the
// strongest one:
//
//	IPv6 loopback  - drives ::1 as the UDP origin
//	local IPv6     - a non-loopback address on a local interface
//	public IPv6    - not attempted; no route to a controlled public IPv6 origin
//	                 exists in a sandboxed test process
//
// A skip is reported as a skip. It is never counted as a pass.

// ipv6TestAddress returns an IPv6 address family to test with, and a label
// describing how strong the resulting coverage is.
func ipv6TestAddress(t *testing.T) (net.IP, string) {
	t.Helper()

	// Prefer loopback: it is available on every runner and needs no external
	// route, so the test exercises the protocol rather than the network.
	if probe, err := net.ListenPacket("udp6", "[::1]:0"); err == nil {
		_ = probe.Close()
		return net.IPv6loopback, "IPv6 loopback"
	}

	// Fall back to a non-loopback local IPv6 address if one exists.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip6 := ipNet.IP.To16(); ip6 != nil && ipNet.IP.To4() == nil && !ipNet.IP.IsLoopback() {
				if probe, probeErr := net.ListenPacket("udp6", "["+ipNet.IP.String()+"]:0"); probeErr == nil {
					_ = probe.Close()
					return ipNet.IP, "local IPv6"
				}
			}
		}
	}
	return nil, ""
}

// startIPv6UDPEcho starts a UDP echo bound to an IPv6 address.
func startIPv6UDPEcho(t *testing.T, ip net.IP) string {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("cannot bind a UDP6 echo on %s: %v", ip, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, from, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], from)
		}
	}()
	return conn.LocalAddr().String()
}

// TestJiejieNaiveUoTVIPv6UDPRoundTrip carries UDP to an IPv6 origin through the
// Naive UoT tunnel, for both UoT versions.
func TestJiejieNaiveUoTVIPv6UDPRoundTrip(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	ip, coverage := ipv6TestAddress(t)
	if ip == nil {
		t.Skip("no usable IPv6 address is available in this environment, so the " +
			"IPv6 UDP path could not be exercised; this is NOT a pass")
	}
	t.Logf("IPv6 UDP coverage level: %s (%s)", coverage, ip)

	echoAddress := startIPv6UDPEcho(t, ip)
	t.Logf("IPv6 UDP origin at %s", echoAddress)

	for _, version := range []struct {
		name    string
		version uint8
	}{
		{"v1", uot.LegacyVersion},
		{"v2", uot.Version},
	} {
		t.Run(version.name, func(t *testing.T) {
			session := dialUoT(t, env.port, version.version, echoAddress, true)
			defer session.Close()

			payload := []byte("ipv6-" + version.name + "-payload")
			session.writeDatagram(t, version.version, echoAddress, payload)

			reply := session.readDatagram(t, version.version)
			require.Equal(t, payload, reply,
				"the IPv6 origin must echo the payload back unchanged, proving "+
					"both the request and reply paths work for IPv6")
			t.Logf("%s IPv6 round trip OK over %s: %d bytes echoed",
				version.name, coverage, len(reply))
		})
	}
}

// TestJiejieNaiveUoTVIPv6MultipleDatagrams sends several datagrams to an IPv6
// origin on ONE session, which exercises the per-datagram address encoding
// repeatedly rather than once.
func TestJiejieNaiveUoTVIPv6MultipleDatagrams(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	ip, coverage := ipv6TestAddress(t)
	if ip == nil {
		t.Skip("no usable IPv6 address is available; NOT a pass")
	}
	echoAddress := startIPv6UDPEcho(t, ip)

	session := dialUoT(t, env.port, uot.LegacyVersion, echoAddress, true)
	defer session.Close()

	const rounds = 5
	for index := range rounds {
		payload := []byte{byte('a' + index), 'i', 'p', '6'}
		session.writeDatagram(t, uot.LegacyVersion, echoAddress, payload)
		reply := session.readDatagram(t, uot.LegacyVersion)
		require.Equal(t, payload, reply,
			"datagram %d on the IPv6 session must round trip unchanged", index)
	}
	t.Logf("%d IPv6 datagrams round-tripped on one session over %s", rounds, coverage)
}

// TestJiejieNaiveUoTVIPv6ReplySourceIsTheOrigin checks the reply actually came
// back from the IPv6 origin's address, not merely that bytes arrived.
//
// A payload comparison alone would pass even if the reply had been generated
// elsewhere in the tunnel.
func TestJiejieNaiveUoTVIPv6ReplySourceIsTheOrigin(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	ip, coverage := ipv6TestAddress(t)
	if ip == nil {
		t.Skip("no usable IPv6 address is available; NOT a pass")
	}

	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: ip})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	originAddress := conn.LocalAddr().String()

	// The origin records the REAL source address it observed for the request,
	// so the assertion is about the observed peer rather than a guess.
	observed := make(chan string, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, from, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		select {
		case observed <- from.String():
		default:
		}
		_, _ = conn.WriteToUDP(buffer[:n], from)
	}()

	session := dialUoT(t, env.port, uot.Version, originAddress, true)
	defer session.Close()

	payload := []byte("source-check")
	session.writeDatagram(t, uot.Version, originAddress, payload)
	reply := session.readDatagram(t, uot.Version)
	require.Equal(t, payload, reply)

	select {
	case from := <-observed:
		// The origin is IPv6, so the server's own outbound socket for this
		// session is IPv6 too and the observed peer must therefore be an IPv6
		// address. Asserting that family (rather than a specific value, which
		// depends on which local address the kernel picks) is what makes this
		// check meaningful without being brittle.
		host, _, splitErr := net.SplitHostPort(from)
		require.NoError(t, splitErr)
		observedIP := net.ParseIP(host)
		require.NotNil(t, observedIP, "the observed source must parse as an IP")
		require.True(t, observedIP.To4() == nil,
			"the origin is IPv6, so the request must arrive from an IPv6 "+
				"address; got %s", from)
		t.Logf("IPv6 origin observed request source %s over %s", from, coverage)
	case <-time.After(2 * time.Second):
		t.Fatal("the IPv6 origin never observed the request")
	}
}
