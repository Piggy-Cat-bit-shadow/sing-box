package mixed

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"

	socksinbound "github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing/common/bufio"
)

// ---------------------------------------------------------------------------
// P0-2 (ownership half): the first-use hand-over must be exactly-once and
// happens-before, not "whichever goroutine looks first".
//
// # Who calls into the wrapper concurrently
//
// The routing core runs one copy goroutine per direction over the connection the
// handshake handed to the router (route/conn.go NewConnection: the two `go
// m.connectionCopy(...)` calls). Both directions re-resolve the wrapper chain as
// soon as their first transfer completes, because a non-replaceable wrapper is
// what makes the copy loop decline the kernel path:
//
//   - upload:   N.UnwrapCountReader(source) walks ReaderWithUpstream, so it calls
//     FirstPayloadConn.ReaderReplaceable() on the upload goroutine
//     (sing/common/bufio/copy.go, CopyWithCounters -> refreshUnwrap), and
//     FirstPayloadConn.Read() on that same goroutine.
//   - download: N.UnwrapCountWriter(destination) walks WriterWithUpstream, so it
//     calls FirstPayloadConn.WriterReplaceable() on the download goroutine, and
//     FirstPayloadConn.Write() on that same goroutine.
//
// Nothing orders the two first uses against each other: the first transfer in
// each direction is driven by bytes from opposite peers. The wrapper's capture
// must therefore be exactly-once and published with a happens-before edge. An
// unsynchronized "resolved" flag with a separately published delegate is not
// that: both goroutines observe it unresolved, both consult the parser's reader,
// and the loser publishes its (now empty) result over the winner's payload. The
// consequence is not a stale flag: the payload the client sent in the handshake
// segment is dropped, and the tunnel silently starts mid-stream.
//
// These tests pin the ownership rule at the wrapper with a barrier that makes
// both first uses start at the same instant, and with conserved accounting:
// every byte the client wrote is delivered exactly once.
// ---------------------------------------------------------------------------

// routedEarlyDataConn returns the wrapper the handshake built, reached through
// the same Upstream() hop the copy loops take when they unwrap the chain. The
// router receives sing's LazyConn (the handshake wraps the connection before it
// invokes the handler), so this asserts the wrapper really is in the path rather
// than constructing one by hand.
func routedFirstPayloadConn(t *testing.T, routed *capturedConn) *socksinbound.FirstPayloadConn {
	t.Helper()
	upstream, isUpstream := routed.conn.(interface{ Upstream() any })
	if !isUpstream {
		t.Fatalf("routed connection %T does not expose Upstream()", routed.conn)
	}
	wrapper, isWrapper := upstream.Upstream().(*socksinbound.FirstPayloadConn)
	if !isWrapper {
		t.Fatalf("routed connection upstream is %T, want *socksinbound.FirstPayloadConn", upstream.Upstream())
	}
	return wrapper
}

// TestEarlyDataFirstUseIsSerialized drives the two production entries into the
// wrapper at the same instant and requires the buffered payload to survive.
func TestEarlyDataFirstUseIsSerialized(t *testing.T) {
	payload := bytes.Repeat([]byte{0x3C}, 256)
	handshake := socks5NoAuth("example.com", 443, nil)
	stream := append(append([]byte{}, handshake...), payload...)

	harness := newInboundHarness(t, nil)
	conn := newScriptedConn(stream)
	harness.newConnection(context.Background(), conn, testSource(), nil)
	routed := harness.router.waitConnection(t)
	wrapper := routedFirstPayloadConn(t, routed)

	// The barrier is the point: both goroutines are released together, so both
	// can observe the unresolved wrapper.
	start := make(chan struct{})
	var (
		wait      sync.WaitGroup
		uploaded  []byte
		readErr   error
		writeErr  error
		uploadN   bool
		downloadN bool
	)
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		// Upload copy: capability probe, then the read that moves the buffer.
		uploadN = wrapper.ReaderReplaceable()
		uploaded, readErr = readExact(wrapper, len(payload))
	}()
	go func() {
		defer wait.Done()
		<-start
		// Download copy: capability probe, then a write. The write must not
		// consume or move the buffered inbound payload.
		downloadN = wrapper.WriterReplaceable()
		_, writeErr = wrapper.Write([]byte{0x05, 0x00})
	}()
	close(start)
	wait.Wait()

	if writeErr != nil {
		t.Fatalf("download-side write: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("upload-side read: %v (got %d/%d bytes; the buffered payload was dropped)", readErr, len(uploaded), len(payload))
	}
	if !bytes.Equal(uploaded, payload) {
		t.Fatalf("payload mismatch\n got: %x\nwant: %x", uploaded, payload)
	}
	// A payload handed over twice would show up here: the double has never been
	// asked for more bytes than the client wrote.
	if delivered := conn.bytesDelivered(); delivered > len(stream) {
		t.Fatalf("read %d bytes from a %d byte stream: bytes were replayed", delivered, len(stream))
	}
	// A delegate with a non-empty buffer is exactly what makes the copy loop
	// decline the kernel path, so the read side must report "not replaceable"
	// while the payload is still buffered. The write side is unaffected by
	// inbound buffering, and its "replaceable" answer is what proves the delegate
	// exists at the moment of the probe.
	if uploadN {
		t.Fatal("read side reported replaceable while the payload was still buffered: the copy loop would splice past it")
	}
	if !downloadN {
		t.Fatal("write side reported not-replaceable, so no buffered delegate was installed")
	}
}

// TestEarlyDataFirstUseIsSerializedRepeatedly runs the same interleaving many
// times over freshly built wrappers. Each round is a new object, so this is many
// independent chances to publish the delegate twice rather than one repetition
// of the same state.
func TestEarlyDataFirstUseIsSerializedRepeatedly(t *testing.T) {
	payload := bytes.Repeat([]byte{0x77}, 128)
	handshake := socks5NoAuth("example.com", 443, nil)
	stream := append(append([]byte{}, handshake...), payload...)

	for round := 0; round < 200; round++ {
		harness := newInboundHarness(t, nil)
		conn := newScriptedConn(stream)
		harness.newConnection(context.Background(), conn, testSource(), nil)
		routed := harness.router.waitConnection(t)
		wrapper := routedFirstPayloadConn(t, routed)

		start := make(chan struct{})
		var (
			wait     sync.WaitGroup
			uploaded []byte
			readErr  error
		)
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_ = wrapper.ReaderReplaceable()
			uploaded, readErr = readExact(wrapper, len(payload))
		}()
		go func() {
			defer wait.Done()
			<-start
			_ = wrapper.WriterReplaceable()
			_, _ = wrapper.Write([]byte{0x05, 0x00})
		}()
		close(start)
		wait.Wait()

		if readErr != nil {
			t.Fatalf("round %d: upload read: %v (got %d/%d bytes)", round, readErr, len(uploaded), len(payload))
		}
		if !bytes.Equal(uploaded, payload) {
			t.Fatalf("round %d: payload mismatch\n got: %x\nwant: %x", round, uploaded, payload)
		}
	}
}

// TestEarlyDataCopyLoopsConservePayload runs the REAL copy loops (the same
// function the routing core calls) in both directions over the routed
// connection, and requires the payload to arrive at the far end byte for byte,
// exactly once.
//
// This is the end-to-end half of the ownership rule: the barrier tests above
// prove the wrapper serializes its first use, and this one proves the copy loops
// that drive it do not lose or duplicate the payload.
//
// # Why the SOCKS reply is written before the loops start
//
// sing's LazyConn writes its reply lazily, on the first read or write, and
// records that in a plain bool (`responseWritten`) that both copy directions
// then read through ReaderReplaceable/WriterReplaceable. That field is written
// by one goroutine and read by the other with no synchronization at all: a race
// in the pinned sing module, not in this repository, which reproduces in this
// very test when the pre-write below is removed (WriterReplaceable on the
// download goroutine against the deferred store in ConnHandshakeSuccess on the
// upload goroutine). It is reported separately rather than papered over; the
// pre-write is here so that this test measures the payload contract it is about
// instead of failing on an external component's race. It does not hide the
// payload bug this test exists for: the payload still moves through the wrapper.
func TestEarlyDataCopyLoopsConservePayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0x11}, 300)
	handshake := socks5NoAuth("example.com", 443, nil)
	stream := append(append([]byte{}, handshake...), payload...)

	harness := newInboundHarness(t, nil)
	conn := newScriptedConn(stream)
	harness.newConnection(context.Background(), conn, testSource(), nil)
	routed := harness.router.waitConnection(t)

	// Force the lazy SOCKS reply out on this goroutine, before either copy loop
	// exists, so the flag the two loops read is already settled.
	if _, err := routed.conn.Write(nil); err != nil {
		t.Fatalf("write SOCKS reply: %v", err)
	}

	clientSide, remoteSide := net.Pipe()

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = bufio.CopyWithIncreateBuffer(remoteSide, routed.conn, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	}()
	go func() {
		defer wait.Done()
		_, _ = bufio.CopyWithIncreateBuffer(routed.conn, remoteSide, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	}()

	got, err := readExact(clientSide, len(payload))
	if err != nil {
		t.Fatalf("read payload at the far end: %v (got %d/%d bytes)", err, len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload at the far end\n got: %x\nwant: %x", got, payload)
	}
	if delivered := conn.bytesDelivered(); delivered > len(stream) {
		t.Fatalf("read %d bytes from a %d byte stream: bytes were replayed", delivered, len(stream))
	}
	_ = clientSide.Close()
	_ = remoteSide.Close()
	_ = routed.conn.Close()
	wait.Wait()
}
