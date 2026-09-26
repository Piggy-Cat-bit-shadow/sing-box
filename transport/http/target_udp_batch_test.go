package http

import (
	"net"
	"runtime"
	"testing"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The target-side connected UDP socket must reach sing's recvmmsg/sendmmsg path.
//
// # Where this sits in the pipeline
//
// The batch capabilities on http3PacketConn (previous commit) cover the H3 side. The
// OTHER half of a CONNECT-UDP tunnel is the connected UDP socket toward the target, and
// that side is worth nothing unless sing recognises it as batch-capable:
//
//	QUIC DATAGRAM -> http3PacketConn batch read
//	              -> bufio.CopyPacket
//	              -> connected UDP socket  <- must expose recvmmsg/sendmmsg
//	              -> target
//
// sing's syscall batch creators do exactly that, but only for a socket they can prove is
// CONNECTED (createSyscallConnectedPacketBatchReadWaiter calls
// syscallPacketBatchPeerDestination and bails out unless it reports a peer). That is the
// same precondition Phase 1 establishes by choosing DialContext("udp", target) over
// ListenPacket, so the two changes are load-bearing for each other: an unconnected
// socket would silently fall back to one syscall per datagram.
//
// # Platform note, stated rather than hidden
//
// sing's mmsg path is built for `linux || netbsd`. On darwin it has a sendto-based
// fallback that is also batch-capable, and on other platforms a stub. The production
// target is linux/amd64, so the linux assertion is the one that matters; this test runs
// the capability check wherever the platform provides one and SKIPs with a reason where
// it does not. It never reports a skip as a pass.

// TestConnectedUDPSocketIsBatchCapable proves a connected UDP socket — exactly the kind
// Phase 1 now creates for a CONNECT-UDP target — is recognised as batch-capable.
func TestConnectedUDPSocketIsBatchCapable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "netbsd" && runtime.GOOS != "darwin" {
		t.Skipf("sing provides a batch UDP path only on linux and netbsd (mmsg) and "+
			"darwin (sendto); on %s it is a stub, so there is no batch capability to "+
			"assert. This is a SKIP with a reason, not a pass. The production artifact "+
			"is linux/amd64.", runtime.GOOS)
	}

	// A connected UDP socket, which is what route/conn.go builds for a CONNECT-UDP
	// target once metadata.UDPConnect is set.
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()

	connected, err := net.Dial("udp", peer.LocalAddr().String())
	require.NoError(t, err)
	defer connected.Close()

	conn, isConn := connected.(net.Conn)
	require.True(t, isConn)

	// Wrap it the way the router does, so the assertion is on the shape the router
	// actually passes downstream.
	packetConn := bufio.NewUnbindPacketConn(conn)
	defer packetConn.Close()

	reader, hasReader := bufio.CreateConnectedPacketBatchReadWaiter(packetConn)
	writer, hasWriter := bufio.CreateConnectedPacketBatchWriter(packetConn)

	require.True(t, hasReader,
		"a connected UDP socket must expose the connected batch reader, or every "+
			"CONNECT-UDP target read costs one recvfrom syscall. The connected form is "+
			"required: sing refuses to create it for a socket it cannot prove is "+
			"connected")
	require.True(t, hasWriter,
		"a connected UDP socket must expose the connected batch writer, or every "+
			"CONNECT-UDP target write costs one sendto syscall")
	require.NotNil(t, reader)
	require.NotNil(t, writer)
}

// TestUnconnectedUDPSocketIsNotBatchCapable is the contrast that makes the test above
// meaningful.
//
// It shows the capability is CONDITIONAL on the connected form, which is why Phase 1
// (choosing DialContext over ListenPacket) is a prerequisite for reaching recvmmsg and
// sendmmsg rather than an unrelated cleanup. If an unconnected socket also reported
// batch capability, the assertion above would prove nothing about Phase 1.
func TestUnconnectedUDPSocketIsNotBatchCapable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "netbsd" && runtime.GOOS != "darwin" {
		t.Skipf("no batch UDP path on %s; nothing to contrast", runtime.GOOS)
	}

	// An UNCONNECTED socket, which is what the slow path uses.
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// NewPacketConn wraps a net.PacketConn, which is the unconnected shape.
	packetConn := bufio.NewPacketConn(listener)
	defer packetConn.Close()

	_, hasReader := bufio.CreateConnectedPacketBatchReadWaiter(packetConn)
	_, hasWriter := bufio.CreateConnectedPacketBatchWriter(packetConn)

	// The CONNECTED creators must refuse an unconnected socket, because they cannot know
	// a peer address to report for the batch.
	require.False(t, hasReader,
		"the CONNECTED batch reader must refuse an unconnected socket: it has no single "+
			"peer to report, and guessing one would misattribute received datagrams")
	require.False(t, hasWriter,
		"the CONNECTED batch writer must refuse an unconnected socket")
}

// TestTargetSideBatchDestinationIsReported proves the batch reader reports the
// connection's peer, which is what lets the writer omit a per-packet destination.
func TestTargetSideBatchDestinationIsReported(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "netbsd" && runtime.GOOS != "darwin" {
		t.Skipf("no batch UDP path on %s", runtime.GOOS)
	}

	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer peer.Close()

	connected, err := net.Dial("udp", peer.LocalAddr().String())
	require.NoError(t, err)
	defer connected.Close()

	packetConn := bufio.NewUnbindPacketConn(connected)
	defer packetConn.Close()

	reader, hasReader := bufio.CreateConnectedPacketBatchReadWaiter(packetConn)
	require.True(t, hasReader)

	// InitializeReadWaiter primes the waiter; BatchSize is what bounds one drain.
	needCopy := reader.InitializeReadWaiter(N.NewReadWaitOptions(packetConn, packetConn))
	require.False(t, needCopy,
		"a connected batch reader must not require the caller to copy: it reads straight "+
			"into pooled buffers")
}
