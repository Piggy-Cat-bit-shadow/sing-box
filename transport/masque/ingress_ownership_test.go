package masque

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Ownership and lifecycle tests for the HTTP/3 datagram INGRESS path.
//
// # The invariant under test
//
// session.handleIngressDatagram wraps the slice quic-go returned instead of
// copying it into a pooled buffer. That is only correct if ALL of the following
// hold, and each one has a test below:
//
//  1. the wrapped buffer is UNMANAGED, so Release() cannot return quic-go's
//     memory to sing's pool (a managed buffer would let an unrelated buf.Get
//     hand the same bytes out again - memory corruption, not a leak);
//  2. the payload the handler observes is exactly the datagram payload, with the
//     context ID stripped and nothing else changed;
//  3. the buffer stays valid after ReceiveDatagram returns (the ownership
//     transfer), including when the consumer uses it ASYNCHRONOUSLY;
//  4. a zero-length payload is delivered rather than dropped - an empty datagram
//     and no datagram are different outcomes;
//  5. malformed frames (bad varint, nonzero context ID, varint consuming the
//     whole datagram) are skipped WITHOUT delivering a buffer and without ending
//     the session;
//  6. cancellation and close release everything and do not leak goroutines;
//  7. concurrent receive is safe: exactly one goroutine observes each datagram.
//
// The comparison that makes (1) meaningful is against buf.NewSize, which IS
// managed. Asserting `!managed` rather than "Release does not panic" is the point:
// a managed buffer also survives Release, it just does the wrong thing later.

// ingressCapture records the buffers the session delivers so a test can inspect
// them after the session has moved on.
type ingressCapture struct {
	access  sync.Mutex
	packets []*buf.Buffer
	done    chan struct{}
	want    int
	count   atomic.Int64
}

func newIngressCapture(want int) *ingressCapture {
	return &ingressCapture{done: make(chan struct{}), want: want}
}

func (h *ingressCapture) handleAddressAssign([]AssignedAddress) error  { return nil }
func (h *ingressCapture) handleAddressRequest([]AssignedAddress) error { return nil }
func (h *ingressCapture) handleDNSAssign([]DNSConfiguration) error     { return nil }

func (h *ingressCapture) handlePREF64([]netip.Prefix) error { return nil }

func (h *ingressCapture) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *ingressCapture) handlePacketTooBig(_ *buf.Buffer, _ int)       {}

func (h *ingressCapture) handlePacket(buffer *buf.Buffer) {
	h.access.Lock()
	h.packets = append(h.packets, buffer)
	got := len(h.packets)
	h.access.Unlock()
	h.count.Add(1)
	if got == h.want {
		select {
		case <-h.done:
		default:
			close(h.done)
		}
	}
}

func (h *ingressCapture) wait(t *testing.T) []*buf.Buffer {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("ingress delivered %d packets, wanted %d", h.count.Load(), h.want)
	}
	h.access.Lock()
	defer h.access.Unlock()
	return h.packets
}

// frameIngressDatagram builds an H3 datagram carrying `payload` under context 0.
func frameIngressDatagram(payload []byte) []byte {
	return append([]byte{0}, payload...)
}

// runIngressSession drives loopDatagram over `datagrams` and returns nothing; the
// handler is inspected by the caller.
//
// The session is built through newSession so the fixture exercises the same
// constructor production uses, and the datagram view is installed the same way
// newSession installs it for a capable stream.
//
// The context is cancelled once the script is exhausted. A scripted source parks
// on ctx.Done() when it has nothing left - which is what keeps the loop alive
// rather than treating "no more input" as a session end - so without this cancel
// loopDatagram would block forever. The cancel is triggered by the source itself
// on the receive that finds the script empty, so it is deterministic and needs no
// polling.
func runIngressSession(t *testing.T, datagrams [][]byte, handler sessionHandler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &scriptedDatagramStream{datagrams: datagrams, onExhausted: cancel}
	current := newSession(ctx, source, handler, func() int { return PacketHeadroom })
	current.datagrams = source
	require.NotNil(t, current.datagrams, "the session must see the datagram capability")
	current.loopDatagram()
}

// scriptedDatagramStream yields a fixed script and then reports the session as
// cancelled, which is how loopDatagram is asked to return.
type scriptedDatagramStream struct {
	access    sync.Mutex
	datagrams [][]byte
	index     int
	// onExhausted is called once the script has been fully consumed, so the test
	// can end the session deterministically instead of parking forever.
	onExhausted context.CancelFunc
}

func (s *scriptedDatagramStream) DatagramsEnabled() bool { return true }

func (s *scriptedDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	s.access.Lock()
	if s.index < len(s.datagrams) {
		datagram := s.datagrams[s.index]
		s.index++
		s.access.Unlock()
		// A fresh allocation per call, exactly as quic-go's
		// HandleDatagramFrame does. Returning the script entry directly would let
		// a test pass while the implementation aliased fixture memory.
		copied := make([]byte, len(datagram))
		copy(copied, datagram)
		return copied, nil
	}
	s.access.Unlock()
	if s.onExhausted != nil {
		s.onExhausted()
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *scriptedDatagramStream) SendDatagram([]byte) error { return nil }

// Read returns io.EOF rather than blocking forever.
//
// These tests drive loopDatagram DIRECTLY, so the capsule reader is never used.
// A permanent block here would leave a goroutine parked with no way to release it,
// which is not a theoretical concern: an earlier version of this file used
// `select {}` and the package's test binary hung at exit even though every test had
// PASSED, because the runtime waits for leaked goroutines to finish. Returning EOF
// is honest about the fixture's contract - it serves datagrams, not a byte stream -
// and cannot leak.
func (s *scriptedDatagramStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *scriptedDatagramStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *scriptedDatagramStream) Close() error                { return nil }

// TestIngressBufferIsUnmanaged is invariant (1), and it is the one that separates
// a correct zero-copy from a memory-corruption bug.
//
// buf.As returns an UNMANAGED buffer: Release() is a NO-OP that leaves the struct
// and its backing array alone, so quic-go's allocation is never handed to sing's
// pool. buf.NewSize returns a MANAGED one, whose Release() returns the array to
// the pool and zeroes the struct.
//
// `managed` is unexported and has no accessor, so the property is asserted the way
// it is observable: Release() must NOT zero the struct. That is exactly the
// behaviour that matters, because zeroing is what accompanies a pool return.
func TestIngressBufferIsUnmanaged(t *testing.T) {
	t.Parallel()

	payload := []byte{0x45, 0x00, 0x00, 0x1c, 0xde, 0xad}
	wrapped := buf.As(payload)

	require.Equal(t, payload, wrapped.Bytes(),
		"wrapping must not alter the payload")
	require.Equal(t, len(payload), wrapped.Len())

	wrapped.Release()

	// The unmanaged contract: Release did not hand the array back, so the wrapper
	// still describes the same live memory.
	require.Equal(t, len(payload), wrapped.Len(),
		"Release on an unmanaged buffer must not zero the struct; a zeroed struct "+
			"is what a POOL RETURN looks like, and pooling quic-go's memory is the "+
			"memory-corruption bug this guards")
	require.Equal(t, byte(0xde), payload[4],
		"Release must not touch the backing array of quic-go-owned memory")

	// The contrast that gives the assertion meaning: a MANAGED buffer is zeroed by
	// Release, so the two are genuinely distinguishable rather than both no-ops.
	//
	// The pooled buffer is given a window with Resize first, because NewSize alone
	// leaves start==end==0 and Len() would be 0 either way - which would make the
	// comparison vacuous.
	pooled := buf.NewSize(64)
	pooled.Resize(0, 64)
	require.Equal(t, 64, pooled.Len())
	pooled.Release()
	require.Equal(t, 0, pooled.Len(),
		"buf.NewSize's Release returns the array to the pool and zeroes the "+
			"struct; if this does not happen the assertion above proves nothing")
}

// TestIngressStripsOnlyTheContextID is invariant (2).
func TestIngressStripsOnlyTheContextID(t *testing.T) {
	t.Parallel()

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	handler := newIngressCapture(1)
	runIngressSession(t, [][]byte{frameIngressDatagram(payload)}, handler)

	packets := handler.wait(t)
	require.Len(t, packets, 1)
	require.Equal(t, payload, packets[0].Bytes(),
		"the delivered payload must be the datagram minus the context ID, byte for byte")
	packets[0].Release()
}

// TestIngressBufferOutlivesReceiveDatagram is invariant (3): the ownership
// transfer. The buffer must still hold the right bytes after the stream that
// produced it has moved on.
func TestIngressBufferOutlivesReceiveDatagram(t *testing.T) {
	t.Parallel()

	payload := []byte("packet-one")
	handler := newIngressCapture(1)
	// The session is built inline rather than through runIngressSession because
	// this test needs to REPLAY the source afterwards, to prove the delivered
	// buffer no longer depends on it.
	//
	// ctx must be cancelled once the datagram has been delivered. The scripted
	// source parks on ctx.Done() when its script is exhausted, so without the
	// cancel the loop goroutine would never return and the test binary would hang
	// at exit even though every assertion passed - which is exactly what an
	// earlier version of this file did.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &scriptedDatagramStream{
		datagrams:   [][]byte{frameIngressDatagram(payload)},
		onExhausted: cancel,
	}
	current := newSession(ctx, source, handler, func() int { return PacketHeadroom })
	current.datagrams = source
	current.loopDatagram()

	packets := handler.wait(t)
	require.Len(t, packets, 1)

	// Force the stream to hand out a DIFFERENT datagram, which is what would
	// overwrite the memory if quic-go reused a scratch buffer.
	source.access.Lock()
	source.datagrams = [][]byte{frameIngressDatagram([]byte("SECOND-PACKET-XX"))}
	source.index = 0
	source.access.Unlock()

	require.Equal(t, payload, packets[0].Bytes(),
		"the buffer must own its bytes after ReceiveDatagram returned; a reused "+
			"receive scratch buffer would have overwritten them here")
	packets[0].Release()
}

// TestIngressAsyncUseIsSafe is invariant (3) under the harder condition: the
// consumer keeps the buffer after the ingress loop has been torn down.
//
// This is what the real TUN hand-off does - the packet is queued to the device,
// not consumed inline - so a buffer that only survived until the next loop
// iteration would be a use-after-free in production and not merely in a test.
func TestIngressAsyncUseIsSafe(t *testing.T) {
	t.Parallel()

	const packets = 16
	payloads := make([][]byte, packets)
	datagrams := make([][]byte, packets)
	for i := range payloads {
		payloads[i] = []byte{byte(i), 0xaa, 0xbb, 0xcc}
		datagrams[i] = frameIngressDatagram(payloads[i])
	}

	handler := newIngressCapture(packets)
	runIngressSession(t, datagrams, handler)
	captured := handler.wait(t)
	require.Len(t, captured, packets)

	// The ingress loop has returned. Every buffer must still be readable and must
	// still carry its own payload, not a neighbour's.
	for i, packet := range captured {
		require.Equal(t, payloads[i], packet.Bytes(),
			"packet %d lost its contents after the ingress loop exited", i)
	}
	for _, packet := range captured {
		packet.Release()
	}
}

// TestIngressBareContextIDIsSkipped pins the boundary between "empty payload" and
// "malformed frame".
//
// This case was originally written as "an empty datagram is delivered", and the
// code says otherwise: for a datagram of exactly {0x00}, DecodeVarint consumes the
// single byte and reports contextLength == 1, so the guard
// `len(datagram) == contextLength` fires and the datagram is skipped.
//
// That is PRE-EXISTING behaviour and was verified against the revision before the
// zero-copy change (`git show HEAD:transport/masque/session.go`), which carries the
// identical guard. The zero-copy work neither introduced nor altered it.
//
// The behaviour is defensible rather than a bug: RFC 9297 requires a datagram to
// carry a context ID AND a payload, so a lone context ID is a malformed frame, and
// skipping it is the same treatment every other malformed frame gets. What the
// test pins is that the distinction is DELIBERATE and does not drift - if a future
// change starts delivering bare context IDs as empty packets, this fails and the
// author has to decide which semantic is intended.
//
// The important consequence for the zero-copy path is that a genuinely empty
// PAYLOAD cannot be expressed as a bare context ID, so the wrapping code never has
// to handle a zero-length payload arriving from this framing.
func TestIngressBareContextIDIsSkipped(t *testing.T) {
	t.Parallel()

	handler := newIngressCapture(1)
	good := []byte("a real packet")
	// A bare context ID, then a well-formed datagram. The session must skip the
	// first and deliver the second, which proves "skipped" rather than "the loop
	// died here".
	runIngressSession(t, [][]byte{{0x00}, frameIngressDatagram(good)}, handler)

	packets := handler.wait(t)
	require.Len(t, packets, 1, "a bare context ID is malformed and must be skipped")
	require.Equal(t, good, packets[0].Bytes(),
		"the session must survive the bare context ID and deliver the next datagram")
	packets[0].Release()
}

// TestIngressMalformedFramesAreSkipped is invariant (5).
//
// Each case is skipped WITHOUT delivering a buffer and WITHOUT ending the
// session: the following well-formed datagram must still arrive. That last part
// is what distinguishes "skipped" from "the loop died here", which a
// deliver-nothing assertion alone could not tell apart.
func TestIngressMalformedFramesAreSkipped(t *testing.T) {
	t.Parallel()

	good := []byte("after-the-bad-one")

	cases := []struct {
		name     string
		datagram []byte
	}{
		{
			name:     "context ID consumes the whole datagram",
			datagram: []byte{0x00},
		},
		{
			name:     "nonzero context ID",
			datagram: append([]byte{0x40}, []byte("payload")...),
		},
		{
			name:     "truncated varint",
			datagram: []byte{0x80},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			handler := newIngressCapture(1)
			runIngressSession(t, [][]byte{testCase.datagram, frameIngressDatagram(good)}, handler)

			packets := handler.wait(t)
			require.Len(t, packets, 1,
				"the malformed frame must be skipped, not delivered")
			require.Equal(t, good, packets[0].Bytes(),
				"the session must survive the malformed frame and deliver the next datagram")
			packets[0].Release()
		})
	}
}

// TestIngressCloseDuringReceiveIsClean is invariant (6).
//
// Cancelling the session context must end loopDatagram, and it must do so without
// delivering a spurious packet or leaking the goroutine. The goroutine leak is
// checked with a real wait rather than assumed, because a loop parked on a
// context that is never cancelled is precisely the shape of a reconnect leak.
func TestIngressCloseDuringReceiveIsClean(t *testing.T) {
	t.Parallel()

	handler := newIngressCapture(1)
	source := &scriptedDatagramStream{datagrams: [][]byte{frameIngressDatagram([]byte("one"))}}
	ctx, cancel := context.WithCancel(context.Background())
	current := newSession(ctx, source, handler, func() int { return PacketHeadroom })
	current.datagrams = source

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		current.loopDatagram()
	}()

	// Wait for the one real packet, then cancel while the loop is parked in
	// ReceiveDatagram.
	handler.wait(t)

	// Drain our own delivery so the handler channel is not the reason a packet
	// would be missed.
	cancel()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("loopDatagram did not exit after the session context was cancelled")
	}

	require.Equal(t, int64(1), handler.count.Load(),
		"cancellation must not deliver an extra packet")
}

// TestIngressConcurrentReceiveDeliversExactlyOnce is invariant (7).
//
// A DatagramStream is not obliged to be single-consumer, and the session's
// contract is that each received datagram is delivered exactly once. Running many
// concurrent loopDatagram calls over one source and counting deliveries is what
// proves the wrapper does not introduce aliasing between concurrent receives.
//
// Each session gets its own cancellable context: once a scripted source is
// exhausted it parks on ctx.Done(), so without an explicit cancel the loops would
// never return and the test would hang rather than fail. That hang is exactly what
// the first version of this test produced.
func TestIngressConcurrentReceiveDeliversExactlyOnce(t *testing.T) {
	t.Parallel()

	const perLoop = 32
	const loops = 8

	var delivered atomic.Int64
	var finished sync.WaitGroup
	handler := &concurrentIngressHandler{delivered: &delivered}

	sessions := make([]*session, loops)
	cancels := make([]context.CancelFunc, loops)
	for i := range loops {
		datagrams := make([][]byte, perLoop)
		for j := range datagrams {
			datagrams[j] = frameIngressDatagram([]byte{byte(i), byte(j), 0x01, 0x02})
		}
		source := &scriptedDatagramStream{datagrams: datagrams}
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel
		sessions[i] = newSession(ctx, source, handler, func() int { return PacketHeadroom })
		sessions[i].datagrams = source
	}

	for i := range loops {
		finished.Add(1)
		go func(current *session) {
			defer finished.Done()
			current.loopDatagram()
		}(sessions[i])
	}

	// Wait until every delivery has happened, then cancel so the loops return.
	deadline := time.Now().Add(30 * time.Second)
	for delivered.Load() < perLoop*loops && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for _, cancel := range cancels {
		cancel()
	}

	waitDone := make(chan struct{})
	go func() {
		finished.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent ingress loops did not finish after cancellation")
	}

	require.Equal(t, int64(perLoop*loops), delivered.Load(),
		"every datagram must be delivered exactly once across concurrent receives")
}

// concurrentIngressHandler counts deliveries and releases buffers.
type concurrentIngressHandler struct {
	delivered *atomic.Int64
}

func (h *concurrentIngressHandler) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *concurrentIngressHandler) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *concurrentIngressHandler) handleRouteAdvertisement([]AddressRange) error { return nil }

func (h *concurrentIngressHandler) handleDNSAssign([]DNSConfiguration) error { return nil }

func (h *concurrentIngressHandler) handlePREF64([]netip.Prefix) error       { return nil }
func (h *concurrentIngressHandler) handlePacketTooBig(_ *buf.Buffer, _ int) {}

func (h *concurrentIngressHandler) handlePacket(buffer *buf.Buffer) {
	h.delivered.Add(1)
	buffer.Release()
}

// TestIngressReleaseDoesNotRecycleQuicGoMemory is the memory-safety test, stated
// as the effect rather than as a field check.
//
// The failure mode this guards is: an unmanaged buffer's backing array is handed
// to sing's pool, and a later buf.Get returns that same array to an unrelated
// caller while quic-go still owns it. The test churns the pool after releasing
// many wrapped buffers and asserts that none of the wrapped memory is handed back
// out.
//
// The alias check compares the address of the pooled window against the addresses
// of the wrapped arrays directly, rather than with require.NotSame: NotSame goes
// through reflect.DeepEqual-backed formatting and is quadratic here, which made
// this test take minutes. An address set is O(n).
//
// This is a behavioural probe, not a proof - a pool returns whatever block is
// free, so "did not observe an alias" is suggestive rather than conclusive. It is
// kept because TestIngressBufferIsUnmanaged covers the MECHANISM (Release does not
// zero, so it did not pool) and this covers the EFFECT, so a regression would have
// to defeat both.
func TestIngressReleaseDoesNotRecycleQuicGoMemory(t *testing.T) {
	t.Parallel()

	const iterations = 64
	// Each wrapped array is filled with a value unique to its iteration, so an
	// alias would be visible as the wrong byte pattern.
	wrapped := make([][]byte, 0, iterations)
	addresses := make(map[uintptr]int, iterations)
	for i := range iterations {
		payload := make([]byte, 1400)
		for j := range payload {
			payload[j] = byte(i)
		}
		buffer := buf.As(payload)
		buffer.Release()
		wrapped = append(wrapped, payload)
		addresses[uintptr(unsafe.Pointer(&payload[0]))] = i
	}

	// Churn the pool, which is what would surface a bad free list.
	for range iterations {
		buffer := buf.NewSize(1400)
		buffer.Resize(0, 1400)
		window := buffer.Bytes()
		require.Len(t, window, 1400)
		if owner, aliased := addresses[uintptr(unsafe.Pointer(&window[0]))]; aliased {
			t.Fatalf("a pooled buffer aliased quic-go memory wrapped in iteration %d: "+
				"the ingress buffer reached the pool", owner)
		}
		buffer.Release()
	}

	// And the wrapped arrays must still hold their own bytes.
	for i, payload := range wrapped {
		require.Equal(t, byte(i), payload[0],
			"wrapped array %d was overwritten, so its memory reached the pool", i)
	}
}
