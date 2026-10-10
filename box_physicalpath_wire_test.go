package box_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

// START-01/D on the WIRE: business UDP delivered through UoT over a TCP-only middle hop.
//
// # Why a start assertion is not enough for this row
//
// The dry run's whole claim about this configuration is that a TCP-only hop can be correct under a
// UDP-carrying outbound because UDP-over-TCP is a legal conversion. If that claim were wrong, the
// "fix" would have replaced a false refusal with a false acceptance - a configuration that starts
// and then cannot carry the flow it was accepted for. The only evidence that settles it is a real
// datagram arriving at a real UDP peer after traversing the TCP-only hop, so the fixture below is
// three real instances and a real SOCKS5 client.
//
// # The topology, and why each hop exists
//
//	client box: socks inbound  <-- the test's UDP ASSOCIATE
//	  outbound uot     socks -> serverU, udp_over_tcp enabled, detour = middle
//	  outbound middle  socks -> serverM, network = tcp,        detour = exit
//	  outbound exit    socks -> serverU, network = tcp,udp
//
// The configured `detour` is a DEPENDENCY: `uot.detour = middle` means uot's own connection to its
// server is dialled by middle, and middle's connection to ITS server is dialled by exit. So the
// UoT session - the TCP connection carrying the UDP datagram - traverses `middle`, whose declared
// network set is exactly ["tcp"]. serverM is what makes that traversal real rather than nominal:
// it is the SOCKS proxy middle asks to reach serverU.
func TestUoTOverATCPOnlyMiddleHopCarriesTheDatagram(t *testing.T) {
	echoPort, stopEcho := startUDPEcho(t)
	defer stopEcho()

	serverUPort := freeTCPPort(t)
	serverMPort := freeTCPPort(t)
	clientPort := freeTCPPort(t)
	startSocksServer(t, serverUPort)
	startSocksServer(t, serverMPort)

	client, err := newBoxFromConfig(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [
    {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "network": ["tcp", "udp"]},
    {"type": "socks", "tag": "middle", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "network": "tcp", "detour": "exit"},
    {"type": "socks", "tag": "uot", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "udp_over_tcp": {"enabled": true}, "detour": "middle"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "uot"},
      {"network": "tcp", "outbound": "uot"}
    ]
  }
}`, clientPort, serverUPort, serverMPort, serverUPort))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Start(),
		"the dry run must accept a TCP-only middle hop under a UoT outbound")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	target := M.ParseSocksaddrHostPort("127.0.0.1", echoPort)
	packetConn, err := dialer.ListenPacket(ctx, target)
	require.NoError(t, err, "the client's own SOCKS inbound must offer UDP ASSOCIATE")
	defer packetConn.Close()

	payload := []byte("uot-through-a-tcp-only-hop")
	_, err = packetConn.WriteTo(payload, target)
	require.NoError(t, err)
	require.NoError(t, packetConn.SetReadDeadline(time.Now().Add(15*time.Second)))
	buffer := make([]byte, 2048)
	read, _, err := packetConn.ReadFrom(buffer)
	require.NoError(t, err,
		"the datagram must come back: a TCP-only middle hop is only legal if the UoT session "+
			"actually carries UDP over the TCP connection that traverses it")
	require.Equal(t, string(payload), string(buffer[:read]))
}

// TestTCPOnlyExitCarriesTCP is START-01/C on the wire: the exit declares tcp only, the routes
// deliver tcp only, and a TCP connection through it must work.
func TestTCPOnlyExitCarriesTCP(t *testing.T) {
	targetPort, stopTarget := startTCPEcho(t)
	defer stopTarget()

	serverPort := freeTCPPort(t)
	clientPort := freeTCPPort(t)
	startSocksServer(t, serverPort)

	client, err := newBoxFromConfig(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [
    {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "direct", "tag": "udp-capable"},
    {"type": "socks", "tag": "tcp-exit", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"network": "tcp", "outbound": "tcp-exit"},
      {"network": "udp", "outbound": "udp-capable"}
    ]
  }
}`, clientPort, serverPort))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Start(),
		"a TCP-only exit reached only by TCP routes must start beside a UDP-carrying outbound")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	require.NoError(t, err, "TCP must remain usable through the TCP-only exit")
	defer conn.Close()

	payload := []byte("tcp-through-a-tcp-only-exit")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(15*time.Second)))
	buffer := make([]byte, 2048)
	read, err := conn.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, string(payload), string(buffer[:read]))
}

// TestUoTOverATCPOnlyMiddleHopRequiresTheMiddleHop is the control that keeps the wire test from
// passing vacuously.
//
// The same topology with middle's server replaced by a port nothing listens on must NOT deliver the
// datagram. Without this, a `detour` that was silently dropped - or a fixture whose UDP flow never
// reached the chain at all - would look exactly like the pass above.
func TestUoTOverATCPOnlyMiddleHopRequiresTheMiddleHop(t *testing.T) {
	echoPort, stopEcho := startUDPEcho(t)
	defer stopEcho()

	serverUPort := freeTCPPort(t)
	deadMiddlePort := freeTCPPort(t)
	clientPort := freeTCPPort(t)
	startSocksServer(t, serverUPort)

	client, err := newBoxFromConfig(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [
    {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "network": ["tcp", "udp"]},
    {"type": "socks", "tag": "middle", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "network": "tcp", "detour": "exit"},
    {"type": "socks", "tag": "uot", "server": "127.0.0.1", "server_port": %d,
     "version": "5", "udp_over_tcp": {"enabled": true}, "detour": "middle"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "uot"}
    ]
  }
}`, clientPort, serverUPort, deadMiddlePort, serverUPort))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Start(),
		"reachability is not a start-time fact: nothing dials until a flow exists")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	target := M.ParseSocksaddrHostPort("127.0.0.1", echoPort)
	packetConn, err := dialer.ListenPacket(ctx, target)
	require.NoError(t, err)
	defer packetConn.Close()

	_, err = packetConn.WriteTo([]byte("lost"), target)
	require.NoError(t, err, "the write is accepted locally; the middle hop fails underneath it")
	require.NoError(t, packetConn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buffer := make([]byte, 2048)
	_, _, err = packetConn.ReadFrom(buffer)
	require.Error(t, err,
		"the datagram must NOT arrive when the TCP-only middle hop cannot be reached: the UoT "+
			"session is carried by that hop, and a test that passes without it proves nothing")
}

// freeTCPPort reserves a loopback port and releases it, so an instance under test can bind it.
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	return port
}

// startSocksServer starts a real instance whose SOCKS inbound is the server end of a hop: it
// answers CONNECT for the hop above it, and its default outbound reaches the destination.
func startSocksServer(t *testing.T, port uint16) {
	t.Helper()
	instance, err := newBoxFromConfig(t, fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [
    {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": %d}
  ]
}`, port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })
	require.NoError(t, instance.Start())
}

// startUDPEcho answers every datagram with itself, which is all the flow needs to be proven.
func startUDPEcho(t *testing.T) (uint16, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			read, addr, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:read], addr)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port), func() {
		_ = conn.Close()
		<-done
	}
}

// startTCPEcho answers with the bytes it received, for the TCP usability row.
func startTCPEcho(t *testing.T) (uint16, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 2048)
				read, readErr := conn.Read(buffer)
				if readErr != nil {
					return
				}
				_, _ = conn.Write(buffer[:read])
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port), func() {
		_ = listener.Close()
		<-done
	}
}
