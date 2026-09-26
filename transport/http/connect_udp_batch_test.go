package http

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The H3 CONNECT-UDP connection must expose the CONNECTED batch capabilities, and
// bufio.CopyPacket must actually select them.
//
// # Why this needs a capability test rather than a "the interfaces exist" test
//
// Declaring an interface is not the same as reaching the fast path. bufio.CopyPacket
// resolves capabilities in a fixed order and silently falls back, so a connection that
// implements the wrong variant, or implements it and reports false, keeps working
// perfectly while running one packet at a time. Nothing fails; the tunnel is just slow.
//
// So these tests assert what CopyPacket WOULD select, using sing's own resolver
// functions rather than a hand-rolled type assertion. That way a change to sing's
// resolution order is reflected here instead of being masked by a local copy of the
// rules.

// TestHTTP3ConnectUDPExposesConnectedBatchCapabilities asserts the capabilities
// CopyPacket looks for.
func TestHTTP3ConnectUDPExposesConnectedBatchCapabilities(t *testing.T) {
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	readWaiter, isReadWaiter := bufio.CreateConnectedPacketBatchReadWaiter(conn)
	require.True(t, isReadWaiter,
		"an H3 CONNECT-UDP connection must offer the CONNECTED batch read waiter: its "+
			"destination is fixed, so the connected form is the correct one and "+
			"CopyPacket prefers it over the single-packet path")
	require.NotNil(t, readWaiter)

	writer, isWriter := bufio.CreateConnectedPacketBatchWriter(conn)
	require.True(t, isWriter,
		"an H3 CONNECT-UDP connection must offer the CONNECTED batch writer so a batch "+
			"of target replies is forwarded under one lock")
	require.NotNil(t, writer)

	// The single-packet capabilities must still exist: they are the fallback when
	// CopyPacket declines the batch path (for example under LowMemory).
	require.Implements(t, (*N.PacketConn)(nil), conn)
}

// TestHTTP3ConnectUDPBatchWaiterRespectsTheBatchBound proves the drain is bounded.
//
// An unbounded drain would let one burst turn into an arbitrarily large allocation on
// the copy goroutine. The bound is what keeps the queue's backpressure meaningful: the
// channel still holds the overflow, so nothing is lost and order is preserved.
func TestHTTP3ConnectUDPBatchWaiterRespectsTheBatchBound(t *testing.T) {
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	// The queue capacity bounds how much can be outstanding, so the test fills it
	// exactly. Overflowing it would block the test rather than exercise the drain.
	queued := cap(conn.packets)
	require.Greater(t, queued, 8, "the queue must be large enough to batch")
	for index := range queued {
		conn.packets <- buf.As([]byte{byte(index)})
	}

	const batchSize = 8
	waiter, _ := bufio.CreateConnectedPacketBatchReadWaiter(conn)
	waiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: batchSize})

	buffers, destination, err := waiter.WaitReadConnectedPackets()
	require.NoError(t, err)
	require.Len(t, buffers, batchSize,
		"the drain must stop at the batch bound; an unbounded drain turns a burst into "+
			"an arbitrarily large allocation")
	require.Equal(t, M.ParseSocksaddr("192.0.2.1:443"), destination,
		"the batch waiter must report the connection's fixed destination")

	// Order must be preserved: the channel is FIFO and the drain takes from the front.
	for index, buffer := range buffers {
		require.Equal(t, byte(index), buffer.Bytes()[0],
			"batch item %d must be the %dth queued datagram; reordering would corrupt "+
				"a UDP stream's ordering", index, index)
		buffer.Release()
	}

	// The remainder must still be queued, not discarded.
	require.Equal(t, queued-batchSize, len(conn.packets),
		"everything past the batch bound must stay queued for the next round")
	for len(conn.packets) > 0 {
		(<-conn.packets).Release()
	}
}

// TestHTTP3ConnectUDPBatchWaiterPreservesZeroLength proves the batch path keeps the
// empty-datagram distinction the ingress already guarantees.
func TestHTTP3ConnectUDPBatchWaiterPreservesZeroLength(t *testing.T) {
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	conn.packets <- buf.As(nil)

	waiter, _ := bufio.CreateConnectedPacketBatchReadWaiter(conn)
	waiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	buffers, _, err := waiter.WaitReadConnectedPackets()
	require.NoError(t, err)
	require.Len(t, buffers, 1, "a zero-length datagram is a delivered packet")
	require.Zero(t, buffers[0].Len())
	buffers[0].Release()
}

// TestHTTP3ConnectUDPBatchWaiterReturnsOnClose proves a closed connection unblocks a
// parked batch read rather than leaking a goroutine.
func TestHTTP3ConnectUDPBatchWaiterReturnsOnClose(t *testing.T) {
	conn := newHTTP3PacketConn(&datagramFeedingStream{}, M.ParseSocksaddr("192.0.2.1:443"), nil)

	waiter, _ := bufio.CreateConnectedPacketBatchReadWaiter(conn)
	waiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	done := make(chan error, 1)
	go func() {
		_, _, err := waiter.WaitReadConnectedPackets()
		done <- err
	}()

	// Give the waiter a moment to park, then close.
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, conn.Close())

	select {
	case err := <-done:
		require.Error(t, err,
			"a closed connection must surface an error rather than blocking forever")
	case <-time.After(5 * time.Second):
		t.Fatal("the batch waiter did not return after Close; a parked reader would " +
			"leak a goroutine on every tunnel teardown")
	}
}

// batchRecordingStream records the datagrams and capsules a batch writer emits.
type batchRecordingStream struct {
	access sync.Mutex
	// datagrams holds the payload of every successfully sent datagram.
	datagrams [][]byte
	// capsules holds every payload written through the capsule path.
	capsules [][]byte
	// sendErr, when set, is returned by SendDatagram.
	sendErr error
	// datagramsEnabled reports the negotiated capability.
	datagramsEnabled bool
}

func (s *batchRecordingStream) DatagramsEnabled() bool { return s.datagramsEnabled }

func (s *batchRecordingStream) Read([]byte) (int, error) { select {} }

func (s *batchRecordingStream) Write(p []byte) (int, error) {
	s.access.Lock()
	defer s.access.Unlock()
	// A capsule write is a type varint, a length varint and the payload; the test only
	// needs to know that the capsule path was taken and what it carried.
	s.capsules = append(s.capsules, append([]byte(nil), p...))
	return len(p), nil
}

func (s *batchRecordingStream) Close() error { return nil }

func (s *batchRecordingStream) SendDatagram(payload []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.datagrams = append(s.datagrams, append([]byte(nil), payload...))
	return nil
}

func (s *batchRecordingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *batchRecordingStream) recordedDatagrams() [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	return append([][]byte(nil), s.datagrams...)
}

func (s *batchRecordingStream) recordedCapsules() [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	return append([][]byte(nil), s.capsules...)
}

// TestHTTP3ConnectUDPBatchWriterSendsOneDatagramPerPacket proves a batch does not merge
// packets.
//
// This is the correctness property a batching change is most likely to break: each
// application UDP datagram must stay its own datagram, because merging two payloads
// into one would silently change what the far end receives.
func TestHTTP3ConnectUDPBatchWriterSendsOneDatagramPerPacket(t *testing.T) {
	stream := &batchRecordingStream{datagramsEnabled: true}
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	payloads := [][]byte{[]byte("one"), []byte("two"), {}, []byte("four")}
	batch := make([]*buf.Buffer, 0, len(payloads))
	for _, payload := range payloads {
		batch = append(batch, buf.As(payload))
	}

	writer, _ := bufio.CreateConnectedPacketBatchWriter(conn)
	require.NoError(t, writer.WriteConnectedPacketBatch(batch))

	sent := stream.recordedDatagrams()
	require.Len(t, sent, len(payloads),
		"a batch of %d datagrams must produce %d datagrams, not one merged payload",
		len(payloads), len(payloads))

	for index, datagram := range sent {
		// Each datagram is a one-byte context ID followed by the payload.
		require.Equal(t, byte(0x00), datagram[0],
			"datagram %d must carry context ID 0", index)
		require.Equal(t, payloads[index], datagram[1:],
			"datagram %d must carry exactly its own payload", index)
	}
}

// TestHTTP3ConnectUDPBatchWriterFallsBackToCapsules proves the batch path keeps the
// capsule fallback for a peer that did not negotiate HTTP Datagrams.
func TestHTTP3ConnectUDPBatchWriterFallsBackToCapsules(t *testing.T) {
	stream := &batchRecordingStream{datagramsEnabled: false}
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	batch := []*buf.Buffer{buf.As([]byte("a")), buf.As([]byte("b"))}

	writer, _ := bufio.CreateConnectedPacketBatchWriter(conn)
	require.NoError(t, writer.WriteConnectedPacketBatch(batch))

	require.Empty(t, stream.recordedDatagrams(),
		"a peer without datagram support must never receive a datagram")
	require.Len(t, stream.recordedCapsules(), 2,
		"each packet must be written as its own DATAGRAM capsule")
}

// TestHTTP3ConnectUDPBatchWriterFallsBackOnTooLarge proves a size failure stays a size
// decision and does not close the tunnel.
//
// DatagramTooLarge means the payload does not fit a datagram, not that the peer cannot
// read a capsule, so the correct response is a capsule. Treating it as a transport
// error would tear down a tunnel that could have carried the packet.
func TestHTTP3ConnectUDPBatchWriterFallsBackOnTooLarge(t *testing.T) {
	stream := &batchRecordingStream{
		datagramsEnabled: true,
		sendErr:          &DatagramTooLargeError{MaxPayloadSize: 1200},
	}
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	writer, _ := bufio.CreateConnectedPacketBatchWriter(conn)
	require.NoError(t, writer.WriteConnectedPacketBatch([]*buf.Buffer{buf.As([]byte("big"))}),
		"a datagram that is too large must be carried as a capsule, not treated as a "+
			"transport failure")

	require.Empty(t, stream.recordedDatagrams())
	require.Len(t, stream.recordedCapsules(), 1)
}

// TestHTTP3ConnectUDPBatchWriterPropagatesRealErrors is the guard against downgrading a
// transport failure into a silent protocol change.
//
// A real QUIC connection error must reach the caller so the session closes. If it were
// swallowed into a capsule write, a broken connection would look like a peer that
// merely declined datagrams.
func TestHTTP3ConnectUDPBatchWriterPropagatesRealErrors(t *testing.T) {
	transportErr := &net.OpError{Op: "write", Err: errTransportTestSentinel}
	stream := &batchRecordingStream{datagramsEnabled: true, sendErr: transportErr}
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	writer, _ := bufio.CreateConnectedPacketBatchWriter(conn)
	err := writer.WriteConnectedPacketBatch([]*buf.Buffer{buf.As([]byte("x"))})
	require.Error(t, err,
		"a real transport error must be returned, not converted into a capsule write")
	require.Empty(t, stream.recordedCapsules(),
		"a transport error must not silently switch the tunnel to capsules")
}

// errTransportTestSentinel marks a non-datagram transport failure in the test above.
var errTransportTestSentinel = errors.New("transport failure")
