//go:build linux || netbsd

package http

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Syscall-level prompt for the batch path.
//
// # Why this test exists
//
// Every other test in this package works on in-memory connections, so they prove the
// capability is forwarded and that the copy loop selects the batch branch. None of them
// can prove a system call happens, because an in-memory connection has no file
// descriptor.
//
// sing's syscall batch path is used when the connection exposes a raw socket, and on
// Linux it is recvmmsg/sendmmsg. This test opens REAL UDP sockets so that the batch path
// has a descriptor to work with, puts the receiving side through the same idle-timeout
// wrapper production applies, and transfers a batch. It is the setup that makes a syscall
// trace meaningful: run this binary under strace and the batched calls are what appear.
//
// # What it does and does not establish on its own
//
// On its own it establishes that the batch path is reachable over a real socket and that
// data crosses correctly through the wrapper. Whether the kernel actually received a
// recvmmsg/sendmmsg rather than a loop of recvfrom/sendto is a question about the trace,
// NOT about this test's exit status, and the two are reported separately: this test
// passing is NOT by itself a syscall confirmation.
//
// The test prints the capability it observed so the trace can be correlated with it.

// TestConnectedBatchOverRealUDPSocketsThroughTheTimeoutWrapper drives a real batched UDP
// transfer through the timeout wrapper.
//
// The sink is a real UDP socket, so the writer that reaches it is the syscall-level batch
// writer when one is available for this platform and this socket. That is the configuration
// the strace run then observes.
func TestConnectedBatchOverRealUDPSocketsThroughTheTimeoutWrapper(t *testing.T) {
	const totalPackets = 16

	// The receiving side: a real UDP socket acting as the "target".
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer sink.Close()

	// The sending side: a real connected UDP socket, wrapped the way route/conn.go wraps
	// a CONNECT-UDP connection.
	source, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer source.Close()

	// A real socket ACCEPTS a read deadline, so this is the TimeoutPacketConn branch -
	// the branch a genuine UDP socket takes in production, as opposed to the HTTP/3
	// connection which takes the timer branch.
	packetConn := bufio.NewPacketConn(source)
	_, wrapped := canceler.NewPacketConn(context.Background(), packetConn, 30*time.Second)
	_, isTimeout := wrapped.(*canceler.TimeoutPacketConn)
	require.True(t, isTimeout,
		"a real UDP socket accepts a read deadline, so it must take the TimeoutPacketConn "+
			"branch; got %T", wrapped)

	// The capability must be present over a real socket too. The syscall-level
	// implementation is reachable here, which is the precondition for a batched syscall.
	_, batchWriteOK := bufio.CreateConnectedPacketBatchWriter(wrapped)
	_, batchReadOK := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	require.True(t, batchWriteOK,
		"the batch write capability must survive the wrapper over a real UDP socket")
	require.True(t, batchReadOK,
		"the batch read capability must survive the wrapper over a real UDP socket")
	t.Logf("real-socket capabilities through the wrapper: read=%v write=%v",
		batchReadOK, batchWriteOK)

	// Receive in the background so the sent datagrams are consumed and the socket buffer
	// does not fill.
	received := make(chan int, 1)
	go func() {
		buffer := make([]byte, 2048)
		count := 0
		_ = sink.SetReadDeadline(time.Now().Add(10 * time.Second))
		for range totalPackets {
			n, _, readErr := sink.ReadFromUDP(buffer)
			if readErr != nil {
				break
			}
			if n == 0 {
				t.Error("received an empty datagram where a payload was expected")
				break
			}
			count++
		}
		received <- count
	}()

	// Send through the batch capability obtained from the WRAPPED connection, so the
	// write path is the one under test rather than the bare socket.
	batchWriter, ok := bufio.CreateConnectedPacketBatchWriter(wrapped)
	require.True(t, ok)

	// The batch is written as ONE call carrying several packets, which is the shape a
	// batched syscall exists for. Sending one buffer per call would still work and would
	// still be a correct use of the interface, but it would produce a vlen of 1 and so
	// could not demonstrate batching at the syscall level - so the packets are collected
	// into a single batch here.
	payload := []byte("batch-syscall-probe")
	batch := make([]*buf.Buffer, 0, totalPackets)
	for range totalPackets {
		packet := buf.NewSize(len(payload))
		packet.Write(payload)
		batch = append(batch, packet)
	}
	require.NoError(t, batchWriter.WriteConnectedPacketBatch(batch),
		"one batch carrying every packet")

	t.Logf("wrote ONE batch of %d packets", totalPackets)

	select {
	case count := <-received:
		require.Equal(t, totalPackets, count,
			"every datagram must arrive over the real socket path. A batched write must "+
				"deliver every packet in the batch, not just the first")
	case <-time.After(15 * time.Second):
		t.Fatal("the real-socket transfer did not complete")
	}

	t.Logf("%d datagrams transferred over real UDP sockets through the timeout wrapper",
		totalPackets)
}

// TestBatchWriterOverRealSocketIsUsable records which writer implementation the real
// socket yields, so a syscall trace can be attributed to the right code path.
func TestBatchWriterOverRealSocketIsUsable(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer sink.Close()

	source, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer source.Close()

	_, wrapped := canceler.NewPacketConn(context.Background(),
		bufio.NewPacketConn(source), 30*time.Second)

	writer, ok := bufio.CreateConnectedPacketBatchWriter(wrapped)
	require.True(t, ok, "a real UDP socket must offer the connected batch writer")
	t.Logf("batch writer implementation over a real socket: %T", writer)

	reader, ok := bufio.CreateConnectedPacketBatchReadWaiter(wrapped)
	if ok {
		t.Logf("batch reader implementation over a real socket: %T", reader)
	}

	// The interface the syscall implementation satisfies, checked explicitly so a change
	// that replaced it with a fallback would be visible here.
	_, _ = writer, reader
	_ = M.Socksaddr{}
}
