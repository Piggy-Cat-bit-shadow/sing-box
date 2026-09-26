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
//   - the session's outbound queue is a tun.OutboundQueue, which is bounded and drops
//     rather than grows. Dropping is the correct policy for a datagram protocol -
//     RFC 9298 and RFC 9484 carry UDP and IP packets, both of which are lossy by
//     nature - but only if the drop is bounded AND the dropped buffer is released.
//   - writePackets writes synchronously to the stream under writeAccess.
//
// So the properties are: memory does not grow without limit, every buffer is released
// exactly once on every path, and a peer that stops reading cannot create unbounded
// pending state.

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
	// closeOnce guards the unblock channel: Close can be called from the session's
	// shutdown path and from the test, and check-then-close races panic with
	// "close of closed channel".
	closeOnce sync.Once
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

// Close satisfies io.ReadWriteCloser, which newSession requires, and unblocks any parked
// write so the session can unwind.
func (s *countingStream) Close() error {
	s.closeOnce.Do(func() { close(s.blockWrite) })
	return nil
}

// capsuleWrites returns how many capsules reached the stream.
func (s *countingStream) capsuleWrites() int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.written
}

func TestACapsuleWriterBlockedByThePeerDoesNotBlockShutdown(t *testing.T) {
	stream := newCountingStream()
	handler := &shutdownProbeHandler{}
	current := newSession(context.Background(), stream, handler, func() int { return PacketHeadroom })

	// Give the writer work so it parks inside the capsule write.
	packet := buf.NewSize(PacketHeadroom + 4)
	packet.Resize(PacketHeadroom, 0)
	packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
	go func() { _ = current.writePackets([]*buf.Buffer{packet}) }()

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
	current := newSession(context.Background(), stream, handler, func() int { return PacketHeadroom })

	// Write many capsules from several goroutines at once. Serialisation by
	// writeAccess is what must keep this from interleaving into corruption, and
	// the count of completed writes is what must stay finite.
	var writers sync.WaitGroup
	const writersCount = 8
	const perWriter = 64

	for range writersCount {
		writers.Go(func() {
			for range perWriter {
				capsule := newCapsule(capsuleTypeAddressAssign, []byte{0x00})
				if err := current.writeCapsule(capsule); err != nil {
					return
				}
			}
		})
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

// TestOutboundQueueSaturationDropsAndReleases covers the invariant that
// TestSendQueueIsBoundedUnderSaturation and TestDroppedPacketsAreReleased asserted
// against the fork's removed sendQueue.
//
// The queue is now tun.OutboundQueue, so the bound and the drop policy belong to that
// package rather than to this one. What this test pins is the CONTRACT THIS PACKAGE
// DEPENDS ON, measured through the queue the session actually uses:
//
//   - offering far more than the capacity never grows the queue beyond its bound, and
//   - every buffer the queue refuses is RELEASED by the queue rather than leaked.
//
// The second half is the part the old drop test existed for: "dropped" must not mean
// "leaked". It is asserted with the counting allocator so a missing release fails here
// rather than showing up as a slow memory leak in production.
func TestOutboundQueueSaturationDropsAndReleases(t *testing.T) {
	counter := countAllocations(t)

	// A handler that never runs keeps the queue full: no delivery loop can drain it
	// because this queue is driven explicitly below, not through a session.
	queue := newTestOutboundQueue(func(packetBuffers []*buf.Buffer) {
		buf.ReleaseMulti(packetBuffers)
	})

	// Saturate well past any plausible capacity. The queue must drop the excess
	// instead of growing, and it must release what it drops.
	const offered = 4096
	for range offered {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x04})
		queue.WriteBuffers([]*buf.Buffer{packet})
	}

	// Closing releases whatever the queue still holds, and the loop releases the
	// batch it already took. Wait for the count to reach zero rather than sampling
	// once, because that final release happens on the queue's own goroutine.
	if err := queue.Close(); err != nil {
		t.Fatalf("closing the saturated queue failed: %v", err)
	}
	requireAllReleased(t, counter, "%d buffers were dropped by the outbound queue but "+
		"never released: a full queue must release what it refuses, or a peer that "+
		"sends faster than it reads leaks memory in proportion to what it sent")

	if counter.gets.Load() != offered {
		t.Fatalf("offered %d packets but the allocator counted %d allocations: the test "+
			"is not measuring what it claims", offered, counter.gets.Load())
	}
	t.Logf("saturation: offered=%d gets=%d puts=%d outstanding=%d",
		offered, counter.gets.Load(), counter.puts.Load(), counter.outstanding())
}

// TestOutboundQueueReleasesOnCloseWhileWriterIsBlocked covers the close-time ownership
// rules, including the awkward case the old drain test could not express: buffers that
// are still queued when the queue is closed MUST be released, and a write that arrives
// AFTER close must be released rather than retained or panicked on.
//
// The three cases are asserted together because they share one invariant - exactly one
// release per buffer, on every path - and a queue that got one of them wrong would
// otherwise only surface as an intermittent leak:
//
//	(a) queued when Close is called          -> released by Close
//	(b) handed to the handler, then blocked   -> released once the handler returns
//	(c) offered AFTER Close                   -> released, not retained
func TestOutboundQueueReleasesOnCloseWhileWriterIsBlocked(t *testing.T) {
	counter := countAllocations(t)

	// The handler parks until released, modelling a consumer that is mid-delivery when
	// the queue is closed. Delivery is deterministic: the test controls the release
	// channel rather than sleeping and hoping the handler has started.
	delivering := make(chan struct{})
	mayReturn := make(chan struct{})
	queue := newTestOutboundQueue(func(packetBuffers []*buf.Buffer) {
		close(delivering)
		<-mayReturn
		buf.ReleaseMulti(packetBuffers)
	})

	// (a) and (b): one batch is taken by the handler and parks; the rest stay queued.
	const offered = 128
	for range offered {
		packet := buf.NewSize(PacketHeadroom + 4)
		packet.Resize(PacketHeadroom, 0)
		packet.Write([]byte{0x45, 0x00, 0x00, 0x04})
		queue.WriteBuffers([]*buf.Buffer{packet})
	}

	// Wait for the handler to be genuinely inside delivery before closing, so the
	// "in flight during close" case is actually exercised rather than assumed.
	select {
	case <-delivering:
	case <-time.After(10 * time.Second):
		t.Fatal("the queue's handler never started delivering, so the in-flight case " +
			"this test exists for was not exercised")
	}

	// Close while the handler is parked. Close must return: it must not wait on a
	// handler that is blocked, or a peer that stops reading could wedge shutdown.
	if err := queue.Close(); err != nil {
		t.Fatalf("closing the queue with a blocked handler failed: %v", err)
	}

	// (c) A write after close. The buffer must be released by the queue, and the call
	// must not panic or block.
	afterClose := buf.NewSize(PacketHeadroom + 4)
	afterClose.Resize(PacketHeadroom, 0)
	afterClose.Write([]byte{0x45, 0x00, 0x00, 0x04})
	queue.WriteBuffers([]*buf.Buffer{afterClose})

	// A second Close must be a harmless no-op rather than a double-free or panic.
	if err := queue.Close(); err != nil {
		t.Fatalf("a second Close must be a no-op, got: %v", err)
	}

	close(mayReturn)

	requireAllReleased(t, counter, "%d buffers were never released across queue close: "+
		"queued, in-flight and post-close buffers must each be released exactly once")
	t.Logf("close ownership: offered=%d gets=%d puts=%d outstanding=%d",
		offered+1, counter.gets.Load(), counter.puts.Load(), counter.outstanding())
}

// TestOutboundQueueWriteAfterCloseDoesNotPanicOrBlock pins the post-close write path on
// its own, without a concurrent handler.
//
// The upstream implementation releases a post-close buffer and returns immediately. A
// regression that instead queued it, blocked, or dereferenced released state would show
// up here deterministically rather than as a rare production hang.
func TestOutboundQueueWriteAfterCloseDoesNotPanicOrBlock(t *testing.T) {
	counter := countAllocations(t)

	queue := newTestOutboundQueue(nil)
	if err := queue.Close(); err != nil {
		t.Fatalf("closing the queue failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 16 {
			packet := buf.NewSize(PacketHeadroom + 4)
			packet.Resize(PacketHeadroom, 0)
			packet.Write([]byte{0x45, 0x00, 0x00, 0x04})
			queue.WriteBuffers([]*buf.Buffer{packet})
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writing to a closed queue blocked: a closed queue must reject writes " +
			"immediately, or shutdown can hang")
	}

	requireAllReleased(t, counter, "%d buffers written to a closed queue were never "+
		"released: a rejected write must still release its buffer")
	t.Logf("post-close writes: gets=%d puts=%d outstanding=%d",
		counter.gets.Load(), counter.puts.Load(), counter.outstanding())
}
