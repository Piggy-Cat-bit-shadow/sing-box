package http

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Regression tests for the deferred-activation state machine of http3PacketConn.
//
// # The bug these exist to prevent
//
// Deferred mode used to be applied AFTER construction:
//
//	conn := newHTTP3PacketConn(stream, destination, localAddr)  // activated = true
//	                                                            // go loopDatagram()  <- reader already running
//	conn.deferUntilTargetReady()                                // activated = false
//
// A datagram received between those two statements was delivered on the strength of a
// 200 that had not been sent yet. It is a TOCTOU in the API, not a slip in one caller:
// the constructor started readers in a state the caller then had to correct.
//
// Two further defects lived in the same state machine:
//
//   - loopCapsule() wrote to c.packets UNCONDITIONALLY, so an HTTP Datagram Capsule
//     could be delivered during the setup window even once the datagram path withheld
//     it properly.
//   - `activated` was an atomic read outside earlyMutex while the early queue was
//     appended under it, so settle() could activate and detach between a reader's
//     "observe deferred" and "append". The buffer was then accepted by the bounded
//     policy and stranded forever: never delivered, never released.
//
// # Why the tests are built this way
//
// Both defects are scheduling-dependent, so a test that merely constructs a connection
// and looks at the queue will usually pass even on broken code - it passes on this
// machine today. Each test below therefore FORCES the interleaving with channels
// instead of hoping for it. No sleeps are used to "probably" hit the window; the gated
// stream hands control back to the test at the exact point of interest.

// gatedDatagramStream hands out one scripted datagram, but reports when the reader
// goroutine has entered ReceiveDatagram and then blocks until the test releases it.
//
// That gives a test deterministic control over the moment a datagram is in flight,
// which is what makes the constructor race reproducible rather than probabilistic.
type gatedDatagramStream struct {
	// entered is closed when ReceiveDatagram has been called.
	entered chan struct{}
	// release unblocks the pending ReceiveDatagram.
	release chan struct{}
	// payload is returned once, after release.
	payload []byte
	// closed is closed by Close, releasing the parked Read.
	closed chan struct{}

	once     sync.Once
	closeOne sync.Once
}

func newGatedDatagramStream(payload []byte) *gatedDatagramStream {
	return &gatedDatagramStream{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		payload: payload,
		closed:  make(chan struct{}),
	}
}

func (s *gatedDatagramStream) DatagramsEnabled() bool { return true }

func (s *gatedDatagramStream) Read(p []byte) (int, error) {
	// Block until the stream is closed, rather than returning EOF: the capsule reader
	// must not end the session while the datagram path is under test.
	//
	// It blocks on a CHANNEL that Close() closes, not on `select {}`. A permanent
	// block would leave this goroutine parked with no way to release it, and since the
	// test waits on conn.waitGroup, the test binary would hang at exit even after every
	// assertion passed.
	<-s.closed
	return 0, io.EOF
}

func (s *gatedDatagramStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *gatedDatagramStream) Close() error {
	s.closeOne.Do(func() { close(s.closed) })
	return nil
}

func (s *gatedDatagramStream) SendDatagram([]byte) error { return ErrDatagramUnsupported }

func (s *gatedDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	var first bool
	s.once.Do(func() { first = true })
	if !first {
		// Park so the loop does not treat the end of the script as a transport error.
		<-ctx.Done()
		return nil, ctx.Err()
	}
	close(s.entered)
	select {
	case <-s.release:
		return s.payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestDeferredConstructorStartsReadersAlreadyDeferred is the direct regression test for
// the constructor race.
//
// It forces the worst case: the reader goroutine reaches ReceiveDatagram and is holding
// a datagram, all BEFORE the test looks at the connection. On the old code the deferral
// had not been applied yet at that point, so `activated` was still true and the datagram
// went straight to the packet queue.
//
// With the constructor-time mode there is no such moment: the connection is created
// deferred, so a reader can never observe anything else.
func TestDeferredConstructorStartsReadersAlreadyDeferred(t *testing.T) {
	t.Parallel()

	stream := newGatedDatagramStream([]byte{0x00, 'a'})
	conn := newDeferredHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.waitGroup.Wait()
	defer conn.Close()

	// Wait for the reader goroutine to be INSIDE ReceiveDatagram, holding a datagram.
	select {
	case <-stream.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader goroutine never called ReceiveDatagram")
	}

	// Release it. The datagram is now in flight and the reader will try to deliver it.
	close(stream.release)

	// It must be HELD, never delivered. This is the assertion the old code failed: with
	// activated still true at this point, the packet reached conn.packets.
	select {
	case packet := <-conn.packets:
		packet.Release()
		t.Fatal("a datagram was delivered before the target was confirmed; the " +
			"connection was constructed active and only deferred afterwards, so the " +
			"already-running reader slipped a packet past the setup window")
	case <-time.After(300 * time.Millisecond):
	}

	// And it must be held in the EARLY queue, not dropped: the client is entitled to
	// send immediately after its request.
	requireEarlyHeld(t, conn, 1)

	// Confirming the target releases it, in order.
	if err := conn.PacketConnHandshakeSuccess(nil); err != nil {
		t.Fatal(err)
	}
	packet := awaitQueuedPacket(t, conn)
	if got := packet.Bytes(); string(got) != "a" {
		t.Fatalf("released payload = %q, want %q", got, "a")
	}
	packet.Release()
}

// TestDeferredCapsuleWithholdsDeliveryUntilReady covers the second defect: the DATAGRAM
// Capsule path must obey the same deferred semantics as the HTTP Datagram path.
//
// It previously wrote to c.packets unconditionally. A capsule carrying CONNECT-UDP
// payload could therefore be delivered during the setup window even after the datagram
// path was fixed - the same leak through the other transport.
func TestDeferredCapsuleWithholdsDeliveryUntilReady(t *testing.T) {
	t.Parallel()

	// A capsule stream, not a datagram stream: this exercises loopCapsule.
	conn := newDeferredHTTP3PacketConn(newCapsuleScriptStream(capsuleScriptPayload()), M.ParseSocksaddr("192.0.2.1:443"), nil)
	defer conn.waitGroup.Wait()
	defer conn.Close()

	// Give loopCapsule a chance to read and try to deliver its capsule.
	select {
	case packet := <-conn.packets:
		packet.Release()
		t.Fatal("a DATAGRAM capsule was delivered during the setup window; the " +
			"capsule path must obey the same deferred gating as the datagram path")
	case <-time.After(300 * time.Millisecond):
	}

	// It must be held, not dropped.
	requireEarlyHeld(t, conn, 1)

	if err := conn.PacketConnHandshakeSuccess(nil); err != nil {
		t.Fatal(err)
	}
	packet := awaitQueuedPacket(t, conn)
	if got := packet.Bytes(); string(got) != "capsule-payload" {
		t.Fatalf("released capsule payload = %q, want %q", got, "capsule-payload")
	}
	packet.Release()
}

// TestDeferredActivationNoPacketLostAtTransition is the transition stress test.
//
// It repeatedly races "a datagram arrives while deferred" against "the handshake
// succeeds", which is the window in which the old atomic-flag split could strand a
// buffer: the reader observed deferred, settle() activated and detached the queue, and
// the reader then appended to the detached slice.
//
// The property asserted is the one a bounded queue can actually promise: every buffer
// the policy ACCEPTED is eventually delivered. Stranding - accepted, never delivered -
// is the failure mode, and it is invisible to a test that only checks "no early
// delivery".
func TestDeferredActivationNoPacketLostAtTransition(t *testing.T) {
	t.Parallel()

	const iterations = 1000

	for i := 0; i < iterations; i++ {
		// A stream whose Read is releasable by Close. The package's shared
		// datagramFeedingStream parks on a bare `select {}`, so a connection built on it
		// can never be waited on - which is why the tests using it never call
		// waitGroup.Wait. This test DOES wait, to prove no goroutine is left behind, so
		// it needs a fixture that can actually be torn down.
		stream := newGatedDatagramStream(nil)
		conn := newDeferredHTTP3PacketConn(stream, M.ParseSocksaddr("192.0.2.1:443"), nil)

		// Race the two sides of the transition.
		var start sync.WaitGroup
		start.Add(1)

		accepted := make(chan bool, 1)
		go func() {
			start.Wait()
			// This is exactly what a reader does for one received datagram, using the
			// production entry point so the test cannot pass against a different path
			// than the one that runs.
			accepted <- conn.enqueueInboundPacket(buf.As([]byte("x")))
		}()

		go func() {
			start.Wait()
			_ = conn.PacketConnHandshakeSuccess(nil)
		}()

		start.Done()

		// Collect the outcome. enqueueInboundPacket returning true means the buffer was
		// either queued or held; either way it is owned by the connection and MUST be
		// delivered or released - never left in a detached slice.
		if <-accepted {
			// Wait for the delivery the policy promised.
			select {
			case packet := <-conn.packets:
				packet.Release()
			case <-time.After(2 * time.Second):
				// Nothing arrived. Either it was refused by a bound (which reports
				// false, so we would not be here) or it was stranded.
				conn.earlyMutex.Lock()
				stranded := len(conn.early)
				conn.earlyMutex.Unlock()
				conn.Close()
				t.Fatalf("iteration %d: enqueueInboundPacket accepted the buffer but "+
					"nothing was delivered; %d buffer(s) left in the early queue after "+
					"settle() had already run, so they can never be flushed",
					i, stranded)
			}
		}

		conn.Close()
		conn.waitGroup.Wait()
	}
}

// capsuleScriptStream serves one pre-framed DATAGRAM capsule, then parks.
//
// It is the capsule-path counterpart of gatedDatagramStream: it drives loopCapsule
// rather than loopDatagram, which is what makes the "the capsule path must also honour
// the deferred window" assertion meaningful.
type capsuleScriptStream struct {
	reader   *bytes.Reader
	closed   chan struct{}
	closeOne sync.Once
}

func newCapsuleScriptStream(payload []byte) *capsuleScriptStream {
	return &capsuleScriptStream{
		reader: bytes.NewReader(payload),
		closed: make(chan struct{}),
	}
}

func (s *capsuleScriptStream) DatagramsEnabled() bool { return true }

func (s *capsuleScriptStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err == io.EOF {
		// Park until Close, rather than return EOF, so the capsule loop does not end
		// the session before the test has inspected the setup window. Blocking on a
		// channel Close can release - rather than on `select {}` - keeps the test
		// binary from hanging at exit.
		<-s.closed
		return 0, io.EOF
	}
	return n, err
}

func (s *capsuleScriptStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *capsuleScriptStream) Close() error {
	s.closeOne.Do(func() { close(s.closed) })
	return nil
}

func (s *capsuleScriptStream) SendDatagram([]byte) error { return ErrDatagramUnsupported }

func (s *capsuleScriptStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// capsuleScriptPayload frames one DATAGRAM capsule carrying `body` under context ID 0,
// which is the shape readDatagramCapsule accepts.
func capsuleScriptPayload() []byte {
	return capsuleScriptPayloadFor("capsule-payload")
}

func capsuleScriptPayloadFor(body string) []byte {
	var out []byte
	// Capsule type, then length. Both are QUIC varints; the DATAGRAM capsule type is 0
	// and every value here is small enough to fit the one-byte form.
	out = append(out, byte(CapsuleTypeDatagram))
	// Payload length = context ID varint (1 byte, value 0) + body.
	out = append(out, byte(1+len(body)))
	out = append(out, 0x00)
	out = append(out, body...)
	return out
}

// requireEarlyHeld asserts the early queue currently holds exactly `want` datagrams.
//
// It polls the mutex-guarded field rather than sleeping a fixed amount, so a slow
// scheduler does not turn into a flaky failure.
func requireEarlyHeld(t *testing.T, conn *http3PacketConn, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.earlyMutex.Lock()
		held := len(conn.early)
		conn.earlyMutex.Unlock()
		if held == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the setup window holds %d datagram(s), want %d", held, want)
		}
		time.Sleep(time.Millisecond)
	}
}
