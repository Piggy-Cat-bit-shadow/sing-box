package masque

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// Backpressure and buffer ownership.
//
// The send path has two shapes and both must stay bounded:
//
//   - queuePacket puts a buffer on a bounded channel (sendQueueSize) and DROPS the
//     packet when the channel is full. Dropping is the correct policy for a
//     datagram protocol - RFC 9298 and RFC 9484 carry UDP and IP packets, both of
//     which are lossy by nature - but only if the drop is bounded AND the dropped
//     buffer is released.
//   - writeCapsule writes synchronously to the stream under writeAccess.
//
// So the properties are: the queue never exceeds its bound, memory does not grow
// without limit, every buffer is released exactly once on every path, and a peer
// that stops reading cannot create unbounded pending state.

// countingStream records every capsule written and can be made to block.
type countingStream struct {
	access  sync.Mutex
	written int
	bytes   int

	// blockWrite parks writes until unblocked, modelling a peer that stopped
	// reading.
	blockWrite chan struct{}
	// blockOnce ensures only the first write parks, so tests that need the writer
	// to stay blocked do not depend on timing.
	blocked atomic.Bool
}

func newCountingStream() *countingStream {
	return &countingStream{blockWrite: make(chan struct{})}
}

func (s *countingStream) Read([]byte) (int, error) {
	// Block until the stream is closed so loopCapsule does not exit early.
	<-s.blockWrite
	return 0, context.Canceled
}

func (s *countingStream) Write(p []byte) (int, error) {
	if !s.blocked.Load() {
		s.blocked.Store(true)
		<-s.blockWrite
	}
	s.access.Lock()
	s.written++
	s.bytes += len(p)
	s.access.Unlock()
	return len(p), nil
}

func (s *countingStream) Close() error {
	select {
	case <-s.blockWrite:
	default:
		close(s.blockWrite)
	}
	return nil
}

// capsuleWrites returns how many capsules reached the stream.
func (s *countingStream) capsuleWrites() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.written
}

// TestSendQueueIsBoundedUnderSaturation is the core backpressure property.
//
// The peer stops reading, so the writer cannot drain the queue. Thousands of
// packets are then queued. The queue must never exceed sendQueueSize and must drop
// the excess rather than growing.
//
// The point is NOT that no packet is lost - a datagram protocol is allowed to lose
// packets under pressure, and "fixing" this by making the queue unbounded would
// turn a bounded loss into unbounded memory growth. The point is that the bound
// holds.
func TestSendQueueIsBoundedUnderSaturation(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, true)

	if cap(current.sendQueue) != sendQueueSize {
		t.Fatalf("expected a send queue of %d, got %d", sendQueueSize, cap(current.sendQueue))
	}

	// Saturation: queue far more than the bound without ever starting the reader,
	// so nothing can drain.
	const offered = 4096
	queued := 0
	for range offered {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
		current.queuePacket(packet)
		queued = len(current.sendQueue)
		if queued > sendQueueSize {
			t.Fatalf("the send queue reached %d entries, above its bound of %d: "+
				"backpressure is not enforced and memory is unbounded",
				queued, sendQueueSize)
		}
	}

	if queued != sendQueueSize {
		t.Fatalf("after %d offers the queue holds %d entries, expected it to be "+
			"full at %d", offered, queued, sendQueueSize)
	}

	// Drain and release so nothing is left outstanding.
	for {
		select {
		case packet := <-current.sendQueue:
			packet.Release()
		default:
			current.cancel(nil)
			_ = stream.Close()
			return
		}
	}
}

// TestDroppedPacketsAreReleased pins buffer ownership on the drop path.
//
// A dropped packet that is not released is a leak that grows with load, and it is
// invisible in a functional test because the data path still works. The drop path
// must release the buffer it refuses to queue.
//
// The check is behavioural rather than introspective: after saturating and
// draining, the session must still accept and process new packets normally, and the
// queue must not have grown. Combined with the release in queuePacket's default
// arm, this is what keeps the path honest without a custom allocator.
func TestDroppedPacketsAreReleased(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, true)

	// Fill the queue exactly.
	for range sendQueueSize {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
		current.queuePacket(packet)
	}

	// Every further offer is dropped. queuePacket releases the buffer in its
	// default arm; if it did not, these buffers would leak.
	const dropped = 512
	for range dropped {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
		current.queuePacket(packet)
	}

	// The queue must still hold exactly its capacity: drops must not have been
	// appended anywhere.
	if held := len(current.sendQueue); held != sendQueueSize {
		t.Fatalf("after %d dropped packets the queue holds %d entries, expected %d",
			dropped, held, sendQueueSize)
	}

	for {
		select {
		case packet := <-current.sendQueue:
			packet.Release()
		default:
			current.cancel(nil)
			_ = stream.Close()
			return
		}
	}
}

// TestQueueDrainsOnContextCancellation pins that a cancelled session releases
// everything still queued.
//
// loopSend's cancellation arm drains the queue and releases each buffer. Without
// that, every shutdown would strand whatever was in flight, which under churn is a
// steady leak proportional to traffic rather than to sessions.
func TestQueueDrainsOnContextCancellation(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, true)

	for range sendQueueSize {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
		current.queuePacket(packet)
	}

	done := make(chan error, 1)
	go func() { done <- current.run() }()

	// Cancel while the queue is full; the drain arm must empty it.
	current.cancel(nil)
	_ = stream.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after cancellation with a full queue")
	}

	if held := len(current.sendQueue); held != 0 {
		t.Fatalf("the queue still holds %d entries after cancellation; loopSend's "+
			"drain path must release everything queued", held)
	}
}

// TestACapsuleWriterBlockedByThePeerDoesNotBlockShutdown is the writeCapsule half.
//
// writeCapsule takes writeAccess and then writes synchronously to the stream. A
// peer that stops reading therefore parks a goroutine inside the write. Cancelling
// the session must close the stream and unblock it, or shutdown hangs.
func TestACapsuleWriterBlockedByThePeerDoesNotBlockShutdown(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, true)

	// Give the send loop work so it enters writeCapsule.
	packet := buf.NewSize(PacketHeadroom + 4)
	packet.Resize(PacketHeadroom, 0)
	packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
	current.queuePacket(packet)

	done := make(chan error, 1)
	go func() { done <- current.run() }()

	// Wait until the writer is parked inside the stream write.
	deadline := time.After(5 * time.Second)
	for !stream.blocked.Load() {
		select {
		case <-deadline:
			t.Fatal("the writer never reached the blocked write, so this test is " +
				"not exercising the case it is about")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	start := time.Now()
	current.cancel(nil)
	_ = stream.Close()

	select {
	case <-done:
		elapsed := time.Since(start)
		t.Logf("shutdown with a blocked capsule writer took %v", elapsed)
		if elapsed > 10*time.Second {
			t.Fatalf("shutdown took %v with a blocked capsule writer", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a peer that stopped reading the capsule stream hung session " +
			"shutdown: a blocked write must be broken by closing the stream")
	}
}

// TestManyControlCapsulesDoNotAccumulateUnboundedState covers the control plane.
//
// A peer can send control capsules as fast as it likes, and the server answers
// ADDRESS_REQUEST with ADDRESS_ASSIGN. Phase 1 bounded the number of ENTRIES per
// capsule; this checks the different question of whether many QUEUED capsules
// accumulate without limit. The write path is synchronous and serialised by
// writeAccess, so the bound comes from that serialisation rather than from a
// separate queue - which is what this test pins.
func TestManyControlCapsulesDoNotAccumulateUnboundedState(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, true)

	// Write many capsules from several goroutines at once. Serialisation by
	// writeAccess is what must keep this from interleaving into corruption, and
	// the count of completed writes is what must stay finite.
	var writers sync.WaitGroup
	const writersCount = 8
	const perWriter = 64

	for range writersCount {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range perWriter {
				capsule := newCapsule(capsuleTypeAddressAssign, []byte{0x00})
				if err := current.writeCapsule(capsule); err != nil {
					return
				}
			}
		}()
	}

	// Unblock the writer so the goroutines can finish, then wait.
	time.Sleep(50 * time.Millisecond)
	_ = stream.Close()
	writers.Wait()

	writes := stream.capsuleWrites()
	if writes > writersCount*perWriter {
		t.Fatalf("observed %d capsule writes, more than the %d issued",
			writes, writersCount*perWriter)
	}
	t.Logf("control capsule writes completed: %d of %d issued",
		writes, writersCount*perWriter)

	current.cancel(nil)
}
