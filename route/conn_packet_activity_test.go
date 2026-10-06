package route

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// destinationReportingSource offers datagrams that name their destination, which the generic packet
// path passes to the writer. It must not be a batch waiter: this is about the plain per-datagram
// path, which is where the counters are invoked from packetCopySession.Transfer.
type destinationReportingSource struct {
	remaining   int
	payload     []byte
	destination M.Socksaddr
}

func (s *destinationReportingSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if s.remaining <= 0 {
		return M.Socksaddr{}, io.EOF
	}
	s.remaining--
	if _, err := buffer.Write(s.payload); err != nil {
		return M.Socksaddr{}, err
	}
	return s.destination, nil
}

// packetActivityFixture builds a copy pair over a real, UNCONNECTED UDP socket.
//
// Unconnected matters: the packet writer sends with WriteTo, and a pre-connected socket refuses
// that outright ("use of WriteTo with pre-connected connection"), so the copy would fail before any
// counter ran and the test would be measuring its own fixture.
func packetActivityFixture(t *testing.T) (N.PacketWriter, *destinationReportingSource, func()) {
	t.Helper()
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	source := &destinationReportingSource{
		remaining:   3,
		payload:     make([]byte, 64),
		destination: M.SocksaddrFromNet(sink.LocalAddr()),
	}
	return bufio.NewPacketConn(sink), source, func() { _ = sink.Close() }
}

// TestPacketCopyRecordsActivity is the fix for a packet connection that could never prove it was
// alive.
//
// A transition reclaims only what it can prove is idle, and "no transfer has ever been observed" is
// deliberately not idle - that is what a spliced connection looks like from userspace. But a packet
// connection had no observation at all, so every UDP flow stayed in that state for the life of the
// tunnel and was protected indefinitely: a drain that never ends, the opposite failure from the one
// the protection was added for.
func TestPacketCopyRecordsActivity(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = manager.Close() })

	destination, source, cleanup := packetActivityFixture(t)
	defer cleanup()

	state := managedConnState{createdAt: time.Now(), generation: manager.generation.Load()}
	require.Zero(t, state.lastActive.Load(), "activity was recorded before anything was sent")

	var done atomic.Bool
	manager.packetConnectionCopy(
		context.Background(), source, destination, false, &done, nil, nil, nil, &state)

	require.NotZero(t, state.lastActive.Load(),
		"the copy loop moved datagrams but the connection still reports no observed activity, so a "+
			"transition would protect it forever")
}

// TestPacketCopyWithoutStateIsUnchanged keeps the fast path honest: a connection the manager does not
// own carries no counter and must behave exactly as it did before.
func TestPacketCopyWithoutStateIsUnchanged(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = manager.Close() })

	destination, source, cleanup := packetActivityFixture(t)
	defer cleanup()

	var done atomic.Bool
	manager.packetConnectionCopy(
		context.Background(), source, destination, false, &done, nil, nil, nil, nil)
}

// TestManagedConnStateIsFoundThroughWrappers is what makes the copy-site observation reach the
// connection it is about.
//
// By the time a connection arrives at the copy loops it may sit under the dialer's power counters or
// a protocol's own wrapper. Asserting only on the outermost value would observe nothing for exactly
// those connections - the ones with a counter already attached.
func TestManagedConnStateIsFoundThroughWrappers(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = manager.Close() })

	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer socket.Close()

	tracked, isTracked := manager.TrackPacketConn(socket).(*trackedPacketConn)
	require.True(t, isTracked)
	require.Equal(t, &tracked.managedConnState, managedConnStateOf(tracked))

	wrapped := bufio.NewCounterPacketConn(tracked, nil, nil)
	require.Equal(t, &tracked.managedConnState, managedConnStateOf(wrapped),
		"the walk did not reach the managed connection under a wrapper")

	require.Nil(t, managedConnStateOf(M.Socksaddr{}))
	require.Nil(t, managedConnStateOf(nil))
}
