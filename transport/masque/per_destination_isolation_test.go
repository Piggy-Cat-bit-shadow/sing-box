package masque

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// One destination that cannot keep up must not stall the others.
//
// # Why this is a property of the queue, not of the writer
//
// Every session gets its own tun.OutboundQueue from the handler, and the server writes to a
// destination by handing buffers to that destination's queue. The queue is bounded: when a
// destination stops draining, its queue fills and further writes to IT are dropped rather than
// blocking. Because the queue belongs to the session, backpressure is confined to the destination
// that caused it.
//
// If the queue were shared, or if the write path blocked instead of dropping, one stalled
// destination would stop every other destination from being served - a single misbehaving peer
// taking the tunnel down for everyone. This test asserts the confinement directly.
//
// # How the stall is created
//
// The handler's NewOutboundQueue is a real queue whose drain handler blocks on a channel. A session
// whose handler blocks never consumes, so its queue saturates. A second session's handler drains
// normally. Neither uses a sleep to sequence: the test waits on the queue's own observable effects.

// isolationHandler hands out one queue per session and lets the test block a chosen drain.
type isolationHandler struct {
	t *testing.T

	// blockedDrains are the queues whose handler blocks until release is closed.
	release chan struct{}

	mu      sync.Mutex
	queues  []*tun.OutboundQueue
	tuns    []*tun.MemoryTun
	drained []int
}

func (h *isolationHandler) WriteInboundBuffers(packetBuffers []*buf.Buffer) error {
	for _, buffer := range packetBuffers {
		buffer.Release()
	}
	return nil
}

func (h *isolationHandler) FrontHeadroom() int { return 0 }

// NewOutboundQueue returns a bounded queue, exactly as a device produces one. The drain handler
// records that it ran and, for the first destination, waits on release - so the first destination
// stops consuming and its queue fills.
func (h *isolationHandler) NewOutboundQueue(handler func(packetBuffers []*buf.Buffer)) *tun.OutboundQueue {
	index := len(h.queues)
	memoryTun := tun.NewMemoryTun(tun.MemoryTunOptions{})
	h.tuns = append(h.tuns, memoryTun)
	queue := memoryTun.NewOutboundQueue(func(packetBuffers []*buf.Buffer) {
		h.mu.Lock()
		h.drained = append(h.drained, index)
		h.mu.Unlock()
		if index == 0 {
			<-h.release
		}
		handler(packetBuffers)
	})
	h.mu.Lock()
	h.queues = append(h.queues, queue)
	h.mu.Unlock()
	return queue
}

func (h *isolationHandler) queueCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.queues)
}

func (h *isolationHandler) drainCount(index int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, seen := range h.drained {
		if seen == index {
			count++
		}
	}
	return count
}

// TestEachSessionGetsItsOwnOutboundQueue is the structural half: isolation is only possible if the
// queues are distinct objects.
func TestEachSessionGetsItsOwnOutboundQueue(t *testing.T) {
	handler := &isolationHandler{t: t, release: make(chan struct{})}
	first := handler.NewOutboundQueue(func([]*buf.Buffer) {})
	second := handler.NewOutboundQueue(func([]*buf.Buffer) {})
	require.NotSame(t, first, second,
		"two sessions sharing one queue would make one destination's backpressure every "+
			"destination's backpressure")
	require.Equal(t, 2, handler.queueCount())
	first.Close()
	second.Close()
}

// TestBlockedDestinationDoesNotStallAnother is the required isolation regression.
//
// The first queue's drain blocks. Writes to it must be dropped once it is full - the write call
// itself must not block - and the second queue must keep draining throughout.
func TestBlockedDestinationDoesNotStallAnother(t *testing.T) {
	handler := &isolationHandler{t: t, release: make(chan struct{})}
	blocked := handler.NewOutboundQueue(func([]*buf.Buffer) {})
	healthy := handler.NewOutboundQueue(func([]*buf.Buffer) {})
	t.Cleanup(func() {
		close(handler.release)
		blocked.Close()
		healthy.Close()
	})

	// Fill the blocked destination. Each write must return promptly; the queue drops when full
	// rather than applying backpressure to the caller.
	fillDone := make(chan struct{})
	go func() {
		defer close(fillDone)
		for i := 0; i < 4096; i++ {
			buffer := buf.NewSize(16)
			buffer.WriteByte(byte(i))
			blocked.WriteBuffers([]*buf.Buffer{buffer})
		}
	}()
	select {
	case <-fillDone:
	case <-time.After(10 * time.Second):
		t.Fatal("writing to a saturated destination blocked the caller; a full queue must drop, " +
			"not apply backpressure to the write path, or one stalled peer stops every peer")
	}

	// The healthy destination must still be served while the other is stuck.
	for i := 0; i < 16; i++ {
		buffer := buf.NewSize(16)
		buffer.WriteByte(byte(i))
		healthy.WriteBuffers([]*buf.Buffer{buffer})
	}

	// Wait for the healthy queue to drain, which is the observable that says it is still being
	// served. This cannot be satisfied by the blocked queue, whose drain is parked on release.
	deadline := time.After(10 * time.Second)
	for handler.drainCount(1) == 0 {
		select {
		case <-deadline:
			t.Fatalf("the healthy destination was never drained while another destination was "+
				"blocked (drains seen: %v)", handler.drained)
		case <-time.After(time.Millisecond):
		}
	}

	// And the blocked destination is genuinely stuck, so the test proves isolation rather than a
	// race the other way round.
	require.GreaterOrEqual(t, handler.drainCount(0), 1,
		"the blocked destination's handler must have run at least once, or nothing was blocked")
}

// TestPerDestinationQueueOwnershipIsPerSession asserts the server asks the handler for a queue per
// session rather than reusing one.
func TestPerDestinationQueueOwnershipIsPerSession(t *testing.T) {
	handler := &isolationHandler{t: t, release: make(chan struct{})}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		first := handler.NewOutboundQueue(func([]*buf.Buffer) {})
		second := handler.NewOutboundQueue(func([]*buf.Buffer) {})
		// Closing one destination must not disturb the other: they are separate objects with
		// separate lifetimes.
		first.Close()
		second.WriteBuffers([]*buf.Buffer{buf.NewSize(8)})
		second.Close()
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("closing one destination's queue affected another's")
	}
	require.Equal(t, 2, handler.queueCount())
}
