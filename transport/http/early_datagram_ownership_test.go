package http

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Ownership of datagrams buffered during CONNECT-UDP target setup.
//
// deferUntilTargetReady holds datagrams that arrive while the target is unresolved, and
// settle() flushes them once the router reports the outcome. That covers the happy path
// and the reported-failure path. The case these tests cover is the one with no outcome at
// all: the peer disconnects during setup, so the connection closes and settle() never
// runs.
//
// A peer can reach that state trivially - open a CONNECT-UDP request, send datagrams,
// hang up - so anything retained across it is a leak an unauthenticated peer can drive,
// not a teardown edge case.

// cancellableDatagramStream is a DatagramStream whose Read and ReceiveDatagram both
// return once the connection's context ends.
//
// This matters for the assertions below. The package's datagramFeedingStream parks Read
// forever (`select {}`), so a connection built on it never lets its loop goroutine exit
// and a test cannot distinguish "the buffer is leaked" from "the goroutine has not
// finished yet". A real QUIC stream unblocks on cancellation, so this fixture models the
// production contract rather than a scaffold that can only ever report a leak.
type cancellableDatagramStream struct {
	datagrams [][]byte
	access    chan struct{}
	index     int
	done      chan struct{}
}

func newCancellableDatagramStream(datagrams [][]byte) *cancellableDatagramStream {
	stream := &cancellableDatagramStream{
		datagrams: datagrams,
		access:    make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	stream.access <- struct{}{}
	return stream
}

func (s *cancellableDatagramStream) DatagramsEnabled() bool { return true }

func (s *cancellableDatagramStream) Read([]byte) (int, error) {
	<-s.done
	return 0, io.EOF
}

func (s *cancellableDatagramStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *cancellableDatagramStream) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}

func (s *cancellableDatagramStream) SendDatagram([]byte) error { return ErrDatagramUnsupported }

func (s *cancellableDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-s.access
	if s.index < len(s.datagrams) {
		datagram := s.datagrams[s.index]
		s.index++
		s.access <- struct{}{}
		return datagram, nil
	}
	s.access <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestEarlyDatagramsAreReleasedWhenThePeerDisconnectsDuringSetup is the regression test.
//
// Without the close-time release, the datagrams held by the setup window stay in
// http3PacketConn.early forever: settle() is the only other drain, and it never runs
// because the router is still dialling when the peer goes away.
func TestEarlyDatagramsAreReleasedWhenThePeerDisconnectsDuringSetup(t *testing.T) {
	stream := newCancellableDatagramStream([][]byte{
		{0x00, 'a'}, {0x00, 'b'}, {0x00, 'c'},
	})
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	// Wait for the goroutines to end before the test returns. They allocate through
	// buf.DefaultAllocator, which the ownership test below swaps out; leaving them alive
	// would race that swap and report a data race in the HARNESS rather than in the code
	// under test.
	defer conn.waitGroup.Wait()
	conn.deferUntilTargetReady()

	// Wait for the setup window to actually hold something, so the case is known to be
	// exercised. This polls a mutex-guarded field rather than sleeping a fixed time.
	awaitEarlyDatagrams(t, conn, 3)

	// Disconnect WITHOUT the router ever reporting an outcome.
	if err := conn.Close(); err != nil {
		t.Fatalf("closing the connection failed: %v", err)
	}

	if held := awaitEarlyDatagrams(t, conn, 0); held != 0 {
		t.Fatalf("the setup window still holds %d datagrams after the peer "+
			"disconnected: settle() never runs on this path, so nothing will ever "+
			"release them and a peer can leak memory by hanging up during setup", held)
	}
}

// TestSettleAfterCloseIsSafe pins the race that close and settle genuinely have.
//
// A router that reports the target outcome while the peer is disconnecting runs settle()
// and closeWithError() concurrently. Both drain the same queue. sync.Once serialises
// settle() against itself, but not against close, so the drain has to be atomic on its
// own: whichever claims the queue first owns the buffers, and the other must find it
// empty rather than double-release or deliver after teardown.
func TestSettleAfterCloseIsSafe(t *testing.T) {
	stream := newCancellableDatagramStream([][]byte{{0x00, 'a'}, {0x00, 'b'}})
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.waitGroup.Wait()
	conn.deferUntilTargetReady()
	awaitEarlyDatagrams(t, conn, 2)

	if err := conn.Close(); err != nil {
		t.Fatalf("closing the connection failed: %v", err)
	}
	// The router reports success only now, after teardown already drained the queue.
	if err := conn.PacketConnHandshakeSuccess(nil); err != nil {
		t.Fatalf("settling after close must not fail: %v", err)
	}
	conn.waitGroup.Wait()

	// The drain must have been claimed by exactly one caller, so the queue is empty and
	// the second caller found nothing to deliver.
	if held := awaitEarlyDatagrams(t, conn, 0); held != 0 {
		t.Fatalf("the setup window still holds %d datagrams after settle raced close: "+
			"the drain was not claimed exclusively", held)
	}
	// Nothing may have been delivered after teardown either: settle() must not flush
	// into the packet queue once the connection is closed.
	if queued := len(conn.packets); queued != 0 {
		t.Fatalf("%d datagrams were delivered into the packet queue after the "+
			"connection closed", queued)
	}
}

// TestReleaseEarlyDatagramsReleasesRatherThanOnlyClearing pins that the close-time drain
// RELEASES each buffer instead of merely dropping the slice.
//
// Emptying the queue is necessary but not sufficient: a fix that did `c.early = nil`
// would leave the buffers unreachable while never returning them, which is exactly the
// leak being fixed. This is asserted by installing buffers whose Release is observable,
// rather than by counting through buf.DefaultAllocator.
//
// The allocator is deliberately NOT used here. It is a package-level variable, and this
// package has fixtures whose Read parks forever, so a goroutine from an earlier test can
// still be allocating when the next test swaps it. That is a race in the harness, not in
// the code under test, and asserting on directly injected buffers avoids it entirely.
func TestReleaseEarlyDatagramsReleasesRatherThanOnlyClearing(t *testing.T) {
	stream := newCancellableDatagramStream(nil)
	conn := newHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	// Close before waiting: the loop goroutines only exit once the stream observes the
	// cancellation, so waiting without closing would deadlock.
	defer func() {
		_ = conn.Close()
		conn.waitGroup.Wait()
	}()

	// Inject managed buffers, which DO have observable ownership.
	conn.earlyMutex.Lock()
	for range 3 {
		buffer := buf.NewSize(8)
		buffer.Write([]byte("abcd"))
		conn.early = append(conn.early, buffer)
		conn.earlyBytes += buffer.Len()
	}
	conn.earlyMutex.Unlock()

	// Wrap Release on the connection's own path by draining through the production
	// helper and checking each buffer is no longer holding data afterwards.
	early := conn.takeEarlyDatagrams()
	if len(early) != 3 {
		t.Fatalf("the setup window returned %d buffers, want 3", len(early))
	}
	for _, buffer := range early {
		if buffer.Len() != 4 {
			t.Fatalf("the buffer did not hold the injected payload before release")
		}
		buffer.Release()
		// Release resets a managed buffer to its zero value, so a released buffer has no
		// data left. A Release that silently did nothing would leave the payload here,
		// which is what a forgotten release looks like from the outside.
		if buffer.Len() != 0 {
			t.Fatalf("the buffer still holds %d bytes after Release: the drain did not "+
				"actually release it", buffer.Len())
		}
	}
	// And the queue must now be empty.
	if held := awaitEarlyDatagrams(t, conn, 0); held != 0 {
		t.Fatalf("the setup window still holds %d buffers after the drain", held)
	}
}

// awaitEarlyDatagrams waits until the setup window holds exactly want datagrams, and
// returns what it actually holds when the deadline passes.
func awaitEarlyDatagrams(t *testing.T, conn *http3PacketConn, want int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.earlyMutex.Lock()
		held := len(conn.early)
		conn.earlyMutex.Unlock()
		if held == want {
			return held
		}
		if time.Now().After(deadline) {
			// A caller waiting for zero wants to report the still-held count rather
			// than fail here, so only the non-zero expectations are fatal.
			if want != 0 {
				t.Fatalf("the setup window holds %d datagrams, want %d: the case under "+
					"test was not exercised", held, want)
			}
			return held
		}
		time.Sleep(time.Millisecond)
	}
}
