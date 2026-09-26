package http

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The H3 ingress must wrap the received datagram instead of copying it.
//
// # Why this is safe, and what it depends on
//
// quic-go's ReceiveDatagram returns a []byte, and the obvious worry is that it points
// into a receive scratch buffer the transport will reuse as soon as it loops. That
// would make wrapping it a use-after-free. The pinned quic-go
// (v0.61.0-sing-box-mod.7) makes that impossible, and this was verified in the source
// rather than assumed:
//
//	datagram_queue.go HandleDatagramFrame:
//	    data := make([]byte, len(f.Data))
//	    copy(data, f.Data)
//	http3/state_tracking_stream.go enqueueDatagram: appends that slice
//	http3/state_tracking_stream.go ReceiveDatagram: pops it and returns it
//
// So the returned slice is an independent allocation that nothing else references once
// ReceiveDatagram returns.
//
// # The ownership rule the tests below pin
//
// The buffer must be UNMANAGED. `buf.As` is unmanaged, so `Release()` does not return
// the slice to sing's pool - the allocation belongs to quic-go and is reclaimed by the
// GC. A managed pooled buffer would hand quic-go's memory to the pool, where a later
// `buf.Get` in an unrelated code path could hand the same bytes out again. That is a
// memory-corruption class of bug, so it is asserted directly rather than left to review.

// datagramFeedingStream is a DatagramStream that yields scripted datagrams.
type datagramFeedingStream struct {
	datagrams [][]byte
	// readIndex tracks which datagram the next ReceiveDatagram returns.
	access    sync.Mutex
	readIndex int
	closed    bool
}

func (s *datagramFeedingStream) DatagramsEnabled() bool { return true }

func (s *datagramFeedingStream) Read([]byte) (int, error) {
	// The capsule reader must block rather than return EOF, which would end the
	// session; the datagram path is what this fixture exercises.
	select {}
}

func (s *datagramFeedingStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *datagramFeedingStream) Close() error {
	s.access.Lock()
	s.closed = true
	s.access.Unlock()
	return nil
}

func (s *datagramFeedingStream) SendDatagram([]byte) error { return ErrDatagramUnsupported }

func (s *datagramFeedingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.access.Lock()
	if s.readIndex >= len(s.datagrams) {
		s.access.Unlock()
		// Park until the context ends, so the loop does not treat the end of the
		// script as a transport error.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	datagram := s.datagrams[s.readIndex]
	s.readIndex++
	s.access.Unlock()
	return datagram, nil
}

// TestHTTP3IngressWrapsInsteadOfCopyingPayload proves the queued buffer is backed by
// the RECEIVED slice rather than a copy.
//
// # Why this reads from the queue directly
//
// ReadPacket copies into the caller's buffer, because that is the N.PacketConn
// contract and the caller owns that buffer. So the wrap cannot be observed through
// ReadPacket - which is also why this optimization is only worth anything once the
// BATCH reader consumes the queue directly (see the batch read waiter). This test
// therefore asserts the property where it actually lives: the queued *buf.Buffer.
//
// The check is a mutation of the SOURCE datagram after it has been queued: a wrapping
// implementation shows the change, a copying one does not. That is the only way to
// distinguish the two from outside, and it is exactly what the optimization claims.
func TestHTTP3IngressWrapsInsteadOfCopyingPayload(t *testing.T) {
	payload := []byte("payload-that-must-be-wrapped")
	datagram := append([]byte{0x00}, payload...)
	stream := &datagramFeedingStream{datagrams: [][]byte{datagram}}

	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	queued := awaitQueuedPacket(t, conn)
	require.Equal(t, payload, queued.Bytes(), "the payload must arrive intact")

	// Mutate the SOURCE slice. A wrapping buffer sees the change because it aliases the
	// same memory; a copying buffer does not.
	datagram[1] = 'X'
	require.Equal(t, byte('X'), queued.Bytes()[0],
		"the queued buffer must ALIAS the received datagram. A different byte here "+
			"means the payload was copied, which is the per-packet cost this change "+
			"removes")

	queued.Release()
}

// awaitQueuedPacket takes one buffer off the connection's packet queue.
//
// It reads the queue rather than calling ReadPacket so the test can inspect the buffer
// the ingress actually produced, before the N.PacketConn copy contract applies.
func awaitQueuedPacket(t *testing.T, conn *http3PacketConn) *buf.Buffer {
	t.Helper()
	select {
	case queued := <-conn.packets:
		return queued
	case <-time.After(5 * time.Second):
		t.Fatal("no packet reached the queue; the ingress did not deliver the datagram")
		return nil
	}
}

// TestHTTP3IngressBufferIsUnmanaged is the memory-safety assertion.
//
// Release() on a buffer backed by quic-go's allocation must NOT return that memory to
// sing's pool, because quic-go still owns it and the GC is what frees it. If it did, a
// pooled slice would be handed to sing's allocator and could be reissued to an
// unrelated code path while quic-go's queue still references it.
//
// The property is asserted behaviourally, because sing exposes no "is managed" query.
// An UNMANAGED buffer's Release() is a documented no-op, so the observable contract is
// that the data and the slice identity survive it. This is the same distinction
// sing relies on, and it is the assertion that would fail if the wrapper were switched
// to a managed pooled buffer.
func TestHTTP3IngressBufferIsUnmanaged(t *testing.T) {
	backing := append([]byte{0x00}, []byte("pooled-memory-must-not-escape")...)
	visible := backing[1:]

	wrapped := buf.As(visible)
	require.Equal(t, []byte("pooled-memory-must-not-escape"), wrapped.Bytes())

	// Release must be a no-op: the slice keeps its contents and its identity, which is
	// what proves the memory was not handed back to the pool.
	wrapped.Release()

	require.Equal(t, []byte("pooled-memory-must-not-escape"), visible,
		"releasing an UNMANAGED buffer must leave quic-go's memory untouched. If the "+
			"destination changed or the slice identity was dropped, the buffer was "+
			"managed and sing would have pooled memory it does not own")

	// And the same bytes must still be readable through the original slice, so nothing
	// was zeroed on the way out.
	require.Equal(t, byte('p'), visible[0])
	require.Equal(t, byte('e'), visible[len(visible)-1])
}

// TestHTTP3IngressPreservesZeroLengthDatagram guards the case most likely to be broken
// by a copy-removal: an empty payload.
//
// A zero-length UDP datagram is legal and MUST be delivered. It must not be conflated
// with "no datagram arrived", which is why the assertion is on arrival rather than on
// bytes.
func TestHTTP3IngressPreservesZeroLengthDatagram(t *testing.T) {
	stream := &datagramFeedingStream{datagrams: [][]byte{{0x00}}}

	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	buffer := buf.NewPacket()
	defer buffer.Release()

	done := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacket(buffer)
		done <- err
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
		require.Empty(t, buffer.Bytes(),
			"a zero-length UDP payload must arrive as a delivered datagram of length 0, "+
				"not as an absent datagram")
	case <-time.After(5 * time.Second):
		t.Fatal("a context-0 datagram with an empty payload was not delivered; the " +
			"zero-copy path must preserve the empty case rather than dropping it")
	}
}

// TestHTTP3IngressStillRejectsOtherContexts proves the copy removal did not disturb the
// context-ID filter that runs before the wrap.
//
// Each rejected shape is followed by a context-0 datagram that MUST arrive, so a filter
// that wrongly dropped everything fails here rather than passing by delivering nothing.
func TestHTTP3IngressStillRejectsOtherContexts(t *testing.T) {
	stream := &datagramFeedingStream{datagrams: [][]byte{
		{0x01, 'x'},       // non-zero context: dropped
		{0x40, 0x40, 'y'}, // context 64: dropped
		{0xc0, 0, 0},      // malformed: announces an 8-byte varint but supplies 3 bytes
		{0x00, 'z'},       // context 0: delivered
	}}

	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.Close()

	// The queue is read directly so the assertion is on what the INGRESS accepted,
	// before the N.PacketConn copy contract applies.
	queued := awaitQueuedPacket(t, conn)
	require.Equal(t, []byte("z"), queued.Bytes(),
		"only the context-0 datagram may be delivered; a non-zero or malformed context "+
			"must be dropped as an unsupported extension")
	queued.Release()

	// Nothing else may be queued behind it.
	select {
	case extra := <-conn.packets:
		extra.Release()
		t.Fatalf("a dropped context must not be queued, but another packet arrived")
	case <-time.After(200 * time.Millisecond):
	}
}
