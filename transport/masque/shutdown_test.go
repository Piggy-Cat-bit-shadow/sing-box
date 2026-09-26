package masque

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// Active-tunnel shutdown and resource reclamation.
//
// Server.Close cancels every live session, which releases addresses, removes
// route advertisements and unblocks the per-session goroutines. These tests
// measure that it actually does so, in bounded time, because the failure modes are
// invisible to a functional test: a tunnel that keeps working right up until the
// process exits hides a leaked goroutine, a retained address and a blocked writer.

// shutdownProbeHandler counts what a session delivers and how often its teardown
// path runs.
type shutdownProbeHandler struct {
	packets int
}

func (h *shutdownProbeHandler) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *shutdownProbeHandler) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *shutdownProbeHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *shutdownProbeHandler) handlePacket(*buf.Buffer)                      { h.packets++ }
func (h *shutdownProbeHandler) handlePacketTooBig(*buf.Buffer, int)           {}

// TestServerCloseReleasesEverySessionBounded is the core shutdown case.
//
// It registers several sessions the way a real tunnel establishment does, closes
// the server, and requires that every session ends and every address is returned.
// The bound matters: a Close that waits for a peer that never reads is a hang, and
// a hang during shutdown is worse than a leak because it stops the whole process
// from exiting.
func TestServerCloseReleasesEverySessionBounded(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	const sessionCount = 8
	sessions := make([]*serverSession, 0, sessionCount)
	for index := range sessionCount {
		address := netip.MustParseAddr("198.18.0." + itoa(index+2))
		current := noopSession(server, []netip.Addr{address}, []AddressRange{{
			Start: netip.MustParseAddr("203.0.113.0"), End: netip.MustParseAddr("203.0.113.255"),
		}})
		registerSession(server, current)
		sessions = append(sessions, current)
	}

	server.access.RLock()
	registered := len(server.addresses)
	advertised := len(server.advertisements)
	server.access.RUnlock()
	if registered != sessionCount {
		t.Fatalf("expected %d registered addresses, got %d", sessionCount, registered)
	}
	if advertised != sessionCount {
		t.Fatalf("expected %d advertisements, got %d", sessionCount, advertised)
	}

	// Close must return promptly.
	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Server.Close did not return within 10s: shutdown is not bounded, " +
			"which means a blocked writer or a peer that stopped reading can hang " +
			"the whole process exit")
	}

	// Every session must observe cancellation.
	//
	// NOTE which context: serverSession embeds *session, so current.ctx resolves to
	// the SESSION's cancellable context - the one Close cancels - while the
	// serverSession.ctx field is shadowed and belongs to the admission path. An
	// earlier version of this test asserted on a background context nothing ever
	// cancels, and reported "not cancelled" against a working Close.
	for index, current := range sessions {
		select {
		case <-current.session.ctx.Done():
		case <-time.After(5 * time.Second):
			t.Fatalf("session %d was not cancelled by Close", index)
		}
		if cause := context.Cause(current.session.ctx); cause != net.ErrClosed {
			t.Fatalf("session %d was cancelled with %v, expected net.ErrClosed so a "+
				"shutdown is distinguishable from a peer-initiated close", index, cause)
		}
	}

	// The address pool must be free again: releaseSession runs in the session's
	// deferred teardown, so this asserts that teardown actually happened.
	pool := server.pools[0]
	reused := make(map[netip.Addr]struct{})
	for range 253 {
		address, allocated := pool.allocate()
		if !allocated {
			t.Fatal("the pool was exhausted after shutdown, so Close did not return " +
				"the addresses its sessions held; a server that is restarted in the " +
				"same process would refuse clients")
		}
		if _, duplicate := reused[address]; duplicate {
			t.Fatalf("address %s was double-assigned after shutdown", address)
		}
		reused[address] = struct{}{}
	}
}

// TestSessionShutdownUnblocksABlockedWriter is the bounded-shutdown guarantee at
// the session level.
//
// A peer that stops reading the capsule stream leaves a write blocked inside the
// stream. Shutdown must break that, or the goroutine never exits and Close never
// returns. The probe stream models exactly that: Write parks until the stream is
// closed.
func TestSessionShutdownUnblocksABlockedWriter(t *testing.T) {
	stream := newBlockingWriteStream()
	handler := &shutdownProbeHandler{}

	current := newSession(context.Background(), stream, handler, func() int { return PacketHeadroom })

	// Queue the packet BEFORE starting run, so loopSend has work the moment it
	// starts. Queueing afterwards would race the reader: run calls loopCapsule
	// synchronously, and a probe reader that blocks leaves no window in which the
	// queue can be filled deterministically.
	packet := buf.NewSize(PacketHeadroom + 4)
	packet.Resize(PacketHeadroom, 0)
	packet.Write([]byte{0x45, 0x00, 0x00, 0x00})
	go func() { _ = current.writePackets([]*buf.Buffer{packet}) }()

	done := make(chan error, 1)
	go func() { done <- current.run() }()

	// Wait for the writer to be genuinely blocked inside the capsule write.
	select {
	case <-stream.writeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe stream's writer never blocked, so this test is not " +
			"exercising the case it is about")
	}

	// Now shut down and require the whole session to unwind.
	start := time.Now()
	current.cancel(nil)
	_ = stream.Close()

	select {
	case <-done:
		elapsed := time.Since(start)
		t.Logf("session unwound in %v with a blocked writer", elapsed)
		if elapsed > 10*time.Second {
			t.Fatalf("shutdown took %v with a blocked writer; it must be bounded", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() never returned although the stream was closed: closing the " +
			"stream must unblock a writer parked inside it, otherwise a peer that " +
			"stops reading can hang session teardown indefinitely")
	}
}

// blockingWriteStream models a peer that has stopped reading.
type blockingWriteStream struct {
	writeStarted chan struct{}
	closed       chan struct{}
	// closeOnce guards the close. Close can be called from several places at
	// once - the session's shutdown path and the test's cleanup - and a bare
	// "select on closed then close" is a check-then-act race that panics with
	// "close of closed channel". sync.Once is the correct primitive.
	closeOnce sync.Once
	// startedOnce guards the one-shot signal so a second Write does not block on
	// a full channel.
	startedOnce sync.Once
}

func newBlockingWriteStream() *blockingWriteStream {
	return &blockingWriteStream{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

// Read blocks until the stream is closed.
//
// It deliberately does NOT return immediately: run drives loopCapsule
// synchronously, so a reader that returned at once would take run to its cleanup
// path before loopSend ever got to call Write, and the blocked-writer case would
// never be reached.
func (s *blockingWriteStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, context.Canceled
}

// Write parks until Close, which is what a full send buffer on a peer that stopped
// reading looks like from the writer's point of view.
func (s *blockingWriteStream) Write(p []byte) (int, error) {
	s.startedOnce.Do(func() {
		close(s.writeStarted)
	})
	select {
	case <-s.closed:
		return 0, context.Canceled
	case <-time.After(30 * time.Second):
		// A bound so a broken Close surfaces as a test failure rather than a
		// hung test binary.
		return 0, context.DeadlineExceeded
	}
}

func (s *blockingWriteStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// TestRepeatedShutdownDoesNotAccumulateGoroutines measures the lifecycle in bulk.
//
// A single clean shutdown proves little: a leak of one goroutine per session is
// invisible in one run and fatal after ten thousand. This opens and closes many
// sessions in sequence and requires the goroutine count to come back down.
func TestRepeatedShutdownDoesNotAccumulateGoroutines(t *testing.T) {
	server := newTestServer(t, ServerOptions{
		Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/24")},
	})

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const rounds = 200
	for round := range rounds {
		stream := newBlockingWriteStream()
		handler := &shutdownProbeHandler{}
		current := &serverSession{
			session:    newSession(context.Background(), stream, handler, func() int { return PacketHeadroom }),
			server:     server,
			ctx:        context.Background(),
			addresses:  []netip.Addr{netip.MustParseAddr("198.18.0.2")},
			peerRoutes: nil,
		}
		registerSession(server, current)

		done := make(chan error, 1)
		go func() { done <- current.run() }()

		current.cancel(nil)
		_ = stream.Close()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("session %d did not unwind within 5s", round)
		}

		if err := server.Close(); err != nil {
			t.Fatalf("Close failed on round %d: %v", round, err)
		}
		server.releaseSession(current)
	}

	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	after := runtime.NumGoroutine()

	t.Logf("goroutines baseline=%d after %d shutdown cycles=%d", baseline, rounds, after)
	// Allow generous slack for runtime and test-harness goroutines, but require
	// that the count does not scale with the number of rounds.
	if after > baseline+40 {
		t.Fatalf("goroutines grew from %d to %d across %d open/close cycles; "+
			"teardown is leaving something behind per session",
			baseline, after, rounds)
	}
}

// itoa is a tiny local helper so this file needs no extra import.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
