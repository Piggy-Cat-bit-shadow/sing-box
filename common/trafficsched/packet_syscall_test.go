//go:build linux || netbsd || darwin

package trafficsched

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The packet-batch tests in gate_test.go use a fixture whose batch writers are its own, which
// proves the forwarding SHAPE. These use real UDP sockets, which prove the thing the shape exists
// for: bufio.CreatePacketBatchWriter falls back to createSyscallPacketBatchWriter, that fallback
// needs a raw connection the gate deliberately does not expose, and without the forwarding every
// UDP batch would silently become a per-packet loop. A fixture cannot show that, because a fixture
// is not a syscall.

func newUDPPair(t *testing.T, connected bool) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	var client *net.UDPConn
	if connected {
		client, err = net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	} else {
		client, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func readDatagram(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	payload := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(payload)
	require.NoError(t, err)
	return payload[:n]
}

// TestPacketGatePreservesTheConnectedSyscallBatch is the discriminator: the gate must reach a real
// syscall batch writer and every datagram in the batch must arrive.
func TestPacketGatePreservesTheConnectedSyscallBatch(t *testing.T) {
	server, client := newUDPPair(t, true)
	gate := NewPacketGate(bufio.NewPacketConn(client), nil)

	writer, created := bufio.CreateConnectedPacketBatchWriter(gate)
	require.True(t, created,
		"a gate over a real connected UDP socket must still expose the syscall batch writer; if "+
			"this is false the gate dropped the capability and production silently degrades to "+
			"one syscall per packet")

	buffers := []*buf.Buffer{newTestBuffer("alpha"), newTestBuffer("beta"), newTestBuffer("gamma")}
	require.NoError(t, writer.WriteConnectedPacketBatch(buffers))

	received := []string{
		string(readDatagram(t, server)),
		string(readDatagram(t, server)),
		string(readDatagram(t, server)),
	}
	require.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, received,
		"every datagram in the batch must be delivered, in one batch, through the gate")
}

// TestPacketGatePreservesTheDestinationSyscallBatch is the same rule for an unconnected socket,
// where each datagram carries its own destination.
func TestPacketGatePreservesTheDestinationSyscallBatch(t *testing.T) {
	server, client := newUDPPair(t, false)
	gate := NewPacketGate(bufio.NewPacketConn(client), nil)

	writer, created := bufio.CreatePacketBatchWriter(gate)
	require.True(t, created,
		"an unconnected socket must keep the destination-carrying batch writer through the gate")

	destination := M.SocksaddrFromNet(server.LocalAddr()).Unwrap()
	buffers := []*buf.Buffer{newTestBuffer("one"), newTestBuffer("two")}
	require.NoError(t, writer.WritePacketBatch(buffers, []M.Socksaddr{destination, destination}))

	received := []string{string(readDatagram(t, server)), string(readDatagram(t, server))}
	require.ElementsMatch(t, []string{"one", "two"}, received)
}
