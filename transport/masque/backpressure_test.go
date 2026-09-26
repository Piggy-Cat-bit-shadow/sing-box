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
