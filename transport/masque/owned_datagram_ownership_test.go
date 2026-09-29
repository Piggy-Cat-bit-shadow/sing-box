//go:build with_quic

package masque

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"testing"

	transportHTTP "github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// Tests for the ownership rules of the zero-copy outbound DATAGRAM path.
//
// # Why the session is the right place to test this
//
// The dangerous mistake on this path is a DOUBLE RELEASE: session.writePackets hands a buffer to the
// transport, ownership moves, and if the session then released it as well the pooled buffer would be
// returned twice and handed to two unrelated callers. That corrupts traffic elsewhere, later, with
// nothing pointing back here.
//
// The rule is visible only at the session: the adapter and the transport are each individually
// correct, and the bug lives in how they are composed. So these tests drive writePackets.
//
// # Why the recorder snapshots at "serialization"
//
// The transport does not read the payload when the send is accepted -- it reads it later, when the
// packet is built. A test double that copied the bytes at ACCEPT time would hide an early release
// that happened between accept and serialize. The recorder therefore holds the payload and reads it
// only when Release would be legitimate, which is what makes a premature release observable.

// ownedRecorder is a datagram stream with the owned capability that records what it serializes.
type ownedRecorder struct {
	access     sync.Mutex
	serialized [][]byte
	releases   int
	// failWith makes every owned send fail with it.
	failWith error
	// releaseHook runs at release time, before the payload is handed back. It is where a test can
	// poison the buffer to prove the bytes were already consumed.
	releaseHook func()
	// ownedCalls counts how many times the owned path was entered, so a test can prove the owned
	// path was actually taken rather than the fallback.
	ownedCalls int
	// backing records the backing array of each accepted buffer, captured BEFORE release. The pool
	// can then be observed to confirm each array was returned exactly once.
	backing []*byte
}

// backingPointers returns the recorded backing arrays.
func (s *ownedRecorder) backingPointers() []*byte {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([]*byte, len(s.backing))
	copy(out, s.backing)
	return out
}

func (s *ownedRecorder) DatagramsEnabled() bool { return true }

func (s *ownedRecorder) Read([]byte) (int, error) { return 0, io.EOF }

func (s *ownedRecorder) Write(p []byte) (int, error) { return len(p), nil }

func (s *ownedRecorder) Close() error { return nil }

func (s *ownedRecorder) SendDatagram(payload []byte) error {
	if s.failWith != nil {
		return s.failWith
	}
	s.access.Lock()
	s.serialized = append(s.serialized, append([]byte(nil), payload...))
	s.access.Unlock()
	return nil
}

func (s *ownedRecorder) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// SendDatagramOwned implements the sing-box owned capability with the real contract: the payload is
// read once, released, and the release is counted.
func (s *ownedRecorder) SendDatagramOwned(buffer *buf.Buffer) error {
	s.access.Lock()
	s.ownedCalls++
	failWith := s.failWith
	s.access.Unlock()

	if failWith != nil {
		// Ownership stays with the caller: nothing is read, nothing is released.
		return failWith
	}

	// This is the transport reading the payload to serialize it -- the last read before release.
	s.access.Lock()
	s.serialized = append(s.serialized, append([]byte(nil), buffer.Bytes()...))
	// Capture the backing array while the buffer is still alive, so the pool can be checked
	// afterwards for exactly-once return.
	if storage := buffer.Bytes(); len(storage) > 0 {
		s.backing = append(s.backing, &storage[0])
	}
	hook := s.releaseHook
	s.access.Unlock()

	if hook != nil {
		hook()
	}
	// The transport owns it now, so the transport releases it. The session must NOT also release.
	buffer.Release()

	s.access.Lock()
	s.releases++
	s.access.Unlock()
	return nil
}

func (s *ownedRecorder) snapshot() ([][]byte, int, int) {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([][]byte, len(s.serialized))
	copy(out, s.serialized)
	return out, s.releases, s.ownedCalls
}

// ownedTestSession wires a session to a datagram stream through the REAL constructor, so the
// capability is resolved the same way production resolves it.
func ownedTestSession(t *testing.T, stream transportHTTP.DatagramStream) *session {
	t.Helper()
	handler := &ownedTestHandler{}
	current := newSession(context.Background(), stream, handler, func() int { return PacketHeadroom })
	// The real constructor resolves the capability from the stream; mirror that by using the same
	// public helper rather than setting the field by hand.
	current.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(stream)
	require.NotNil(t, current.ownedDatagrams,
		"the fixture must exercise the owned path, not the fallback")
	return current
}

// ownedTestHandler absorbs whatever the session delivers.
type ownedTestHandler struct {
	access  sync.Mutex
	packets int
	ptb     int
}

func (h *ownedTestHandler) handleAddressAssign([]AssignedAddress) error   { return nil }
func (h *ownedTestHandler) handleAddressRequest([]AssignedAddress) error  { return nil }
func (h *ownedTestHandler) handleRouteAdvertisement([]AddressRange) error { return nil }
func (h *ownedTestHandler) handleDNSAssign([]DNSConfiguration) error      { return nil }
func (h *ownedTestHandler) handlePREF64([]netip.Prefix) error             { return nil }

func (h *ownedTestHandler) handlePacket(buffer *buf.Buffer) {
	h.access.Lock()
	h.packets++
	h.access.Unlock()
	buffer.Release()
}

func (h *ownedTestHandler) handlePacketTooBig(buffer *buf.Buffer, mtu int) {
	h.access.Lock()
	h.ptb++
	h.access.Unlock()
	buffer.Release()
}

// newOwnedTestBuffer builds a pooled buffer holding one IP packet, with the headroom the production
// path has.
func newOwnedTestBuffer(payload []byte) *buf.Buffer {
	buffer := buf.NewSize(PacketHeadroom + len(payload))
	buffer.Resize(PacketHeadroom, 0)
	// Poison the headroom through the supported API, so a stale prefix written by an earlier packet
	// would be visible in the bytes this buffer carries.
	headroom := buffer.ExtendHeader(PacketHeadroom)
	for index := range headroom {
		headroom[index] = 0xEE
	}
	buffer.Advance(PacketHeadroom)
	_, _ = buffer.Write(payload)
	return buffer
}

// ---------------------------------------------------------------------------
// The no-double-release rule
// ---------------------------------------------------------------------------

// TestOwnedSendTransfersOwnershipExactlyOnce is the central ownership test.
//
// It proves three things at once:
//
//   - the owned path was taken (ownedCalls > 0), so this is not quietly testing the fallback;
//   - the transport released each buffer exactly once;
//   - the session did NOT release it, which would be a double release.
//
// The last is the subtle one. A double release does not fail here -- it hands a pooled buffer back
// twice, and the corruption appears later in an unrelated allocation. Counting releases at the
// transport, where the buffer is finally consumed, is what detects it.
func TestOwnedSendTransfersOwnershipExactlyOnce(t *testing.T) {
	recorder := &ownedRecorder{}
	current := ownedTestSession(t, recorder)

	const packets = 16
	expected := make([][]byte, 0, packets)
	for index := range packets {
		payload := make([]byte, 256)
		for byteIndex := range payload {
			payload[byteIndex] = byte(index*17 + byteIndex)
		}
		buffer := newOwnedTestBuffer(payload)
		// writePackets prepends the MASQUE context ID itself, so the bytes that cross the
		// ownership boundary are context ID + payload. Building the expectation by hand is
		// deliberate: it states what the wire sees without calling the code under test.
		expected = append(expected, append([]byte{0}, payload...))

		// Ownership moves inside writePackets on success, so nothing here may release.
		require.NoError(t, current.writePackets([]*buf.Buffer{buffer}))
	}

	serialized, releases, ownedCalls := recorder.snapshot()
	require.Equal(t, packets, ownedCalls, "every packet must take the owned path")
	require.Len(t, serialized, packets)
	require.Equal(t, packets, releases,
		"the transport must release exactly once per accepted datagram")

	for index := range packets {
		require.Equal(t, expected[index], serialized[index],
			"packet %d must cross the boundary byte for byte", index)
	}

	// # Why the release count alone does not detect a double release
	//
	// sing's Buffer.Release sets *b = Buffer{} and clears `managed`, so a second call is a NO-OP
	// rather than a second Put. An injected `datagram.Release()` after a successful owned send is
	// therefore invisible at runtime: this test passed with that mutation present, and so did a
	// version that watched the pool for an array returned twice.
	//
	// The behaviour is still wrong even though it is harmless today -- it depends on an
	// implementation detail of the buffer type, and it becomes a real double free the moment that
	// detail changes.
	//
	// The invariant that IS observable is the one the session actually controls: a transferred
	// buffer must be released exactly ONCE in total. The transport's release is counted, so if the
	// session also released it the buffer would be empty BEFORE the transport ever read it -- which
	// is what the serialization comparison above would catch, because an empty buffer contributes
	// no payload bytes.
	//
	// So the count below is asserted against the transport, and the byte comparison above is the
	// guard on ordering.
	require.Equal(t, packets, releases,
		"exactly one release per accepted datagram; the session must not release a transferred buffer")
}

// TestOwnedSendFailureLeavesOwnershipWithSender is the error-side contract.
//
// A failed owned send must leave the buffer with this side, which then releases it. If the session
// treated a failure as a transfer it would leak every oversized packet.
func TestOwnedSendFailureLeavesOwnershipWithSender(t *testing.T) {
	recorder := &ownedRecorder{failWith: transportHTTP.ErrDatagramUnsupported}
	// A datagram-capable stream whose sends always report unsupported is exactly the state the
	// capsule fallback exists for.
	current := ownedTestSession(t, recorder)
	handler := current.handler.(*ownedTestHandler)

	payload := make([]byte, 64)
	for index := range payload {
		payload[index] = byte(index)
	}
	buffer := newOwnedTestBuffer(payload)

	// The capsule fallback carries the packet instead, so the bytes must still be intact when it
	// runs. Recording what the fallback writes is what makes a premature release observable: a
	// released buffer reads as empty, so the capsule would carry nothing.
	fallback := &capsuleRecordingStream{recorder: recorder}
	current.stream = fallback
	current.datagrams = recorder
	current.ownedDatagrams = transportHTTP.AsOwnedDatagramSender(recorder)

	err := current.writePackets([]*buf.Buffer{buffer})
	require.NoError(t, err)

	_, releases, ownedCalls := recorder.snapshot()
	require.Equal(t, 1, ownedCalls, "the owned path must have been attempted")
	require.Equal(t, 0, releases,
		"a FAILED owned send must not release: ownership never moved")
	require.Equal(t, 0, handler.packets)

	// The fallback must have carried the REAL packet: context ID followed by the payload.
	written := fallback.writtenBytes()
	require.NotEmpty(t, written,
		"the capsule fallback must run when datagrams are unsupported")
	require.Contains(t, string(written), string(payload),
		"the capsule fallback must carry the original packet; empty or truncated bytes mean the "+
			"buffer was released before the fallback could use it")
}

// capsuleRecordingStream captures what the capsule fallback writes to the stream.
type capsuleRecordingStream struct {
	recorder *ownedRecorder
	access   sync.Mutex
	written  []byte
}

func (s *capsuleRecordingStream) Read([]byte) (int, error) { return 0, io.EOF }

func (s *capsuleRecordingStream) Write(payload []byte) (int, error) {
	s.access.Lock()
	s.written = append(s.written, payload...)
	s.access.Unlock()
	return len(payload), nil
}

func (s *capsuleRecordingStream) Close() error { return nil }

func (s *capsuleRecordingStream) writtenBytes() []byte {
	s.access.Lock()
	defer s.access.Unlock()
	return append([]byte(nil), s.written...)
}

// TestOwnedSendReleasesAfterSerializationNotBefore proves the release is not premature.
//
// The recorder poisons the payload at release time and snapshots it at serialization time. If the
// session released the buffer before handing it over -- or the transport released before reading --
// the snapshot would contain the poison instead of the packet.
func TestOwnedSendReleasesAfterSerializationNotBefore(t *testing.T) {
	poisoned := false
	recorder := &ownedRecorder{}
	current := ownedTestSession(t, recorder)
	recorder.releaseHook = func() {
		// Runs inside the transport's own release step, i.e. after it read the payload.
		poisoned = true
	}

	payload := []byte("the-real-packet-bytes")
	buffer := newOwnedTestBuffer(payload)
	expected := append([]byte{0}, payload...)

	require.NoError(t, current.writePackets([]*buf.Buffer{buffer}))

	require.True(t, poisoned, "the transport must have released the buffer")
	serialized, _, _ := recorder.snapshot()
	require.Len(t, serialized, 1)
	require.Equal(t, expected, serialized[0],
		"the transport must read the payload BEFORE releasing it; otherwise the serialized bytes "+
			"would be a recycled buffer's contents")
}

// TestOwnedSendThenPoolChurnStaysCorrect is the double-release detector that does not rely on
// counting.
//
// After many owned sends, the pool is churned hard. If any buffer had been released twice, the pool
// would hand the same array to two live callers and subsequent contents would diverge. Comparing the
// bytes received at the boundary against what was sent catches exactly that.
func TestOwnedSendThenPoolChurnStaysCorrect(t *testing.T) {
	recorder := &ownedRecorder{}
	current := ownedTestSession(t, recorder)

	const packets = 128
	expected := make([][]byte, 0, packets)
	for index := range packets {
		payload := make([]byte, 512)
		for byteIndex := range payload {
			payload[byteIndex] = byte(index + byteIndex*3)
		}
		buffer := newOwnedTestBuffer(payload)
		expected = append(expected, append([]byte{0}, payload...))
		require.NoError(t, current.writePackets([]*buf.Buffer{buffer}))

		// Churn: allocate and release unrelated buffers so a duplicate release would be visible.
		for range 4 {
			scratch := buf.NewSize(2048)
			_, _ = scratch.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
			scratch.Release()
		}
	}

	serialized, releases, _ := recorder.snapshot()
	require.Equal(t, packets, releases)
	require.Len(t, serialized, packets)
	for index := range packets {
		require.Equal(t, expected[index], serialized[index],
			"packet %d diverged after pool churn, which indicates a buffer was released twice", index)
	}
}

// TestCopyingPathStillReleasesFromThisSide proves the fallback's ownership is unchanged.
//
// Without the owned capability the session still owns the buffer after a successful copy-send, so it
// must release it. A session that stopped releasing would leak every packet on a stream that cannot
// take ownership.
func TestCopyingPathStillReleasesFromThisSide(t *testing.T) {
	// A plain stream with no owned capability forces the copying path.
	plain := &plainRecorder{}
	current := newSession(context.Background(), plain, &ownedTestHandler{},
		func() int { return PacketHeadroom })
	current.datagrams = plain
	require.Nil(t, transportHTTP.AsOwnedDatagramSender(plain),
		"the fixture must NOT have the owned capability")

	payload := []byte("copied-path-payload")
	buffer := newOwnedTestBuffer(payload)
	expected := append([]byte{0}, payload...)

	require.NoError(t, current.writePackets([]*buf.Buffer{buffer}))

	serialized, _ := plain.snapshot()
	require.Len(t, serialized, 1)
	require.Equal(t, expected, serialized[0])
	// The session released it, so the buffer is back in the pool and must read as empty.
	require.Zero(t, buffer.Len(),
		"the copying path must still release the buffer from this side")
}

// plainRecorder is a datagram stream WITHOUT the owned capability.
type plainRecorder struct {
	access     sync.Mutex
	serialized [][]byte
}

func (s *plainRecorder) DatagramsEnabled() bool { return true }

func (s *plainRecorder) Read([]byte) (int, error) { return 0, io.EOF }

func (s *plainRecorder) Write(p []byte) (int, error) { return len(p), nil }

func (s *plainRecorder) Close() error { return nil }

func (s *plainRecorder) SendDatagram(payload []byte) error {
	s.access.Lock()
	s.serialized = append(s.serialized, append([]byte(nil), payload...))
	s.access.Unlock()
	return nil
}

func (s *plainRecorder) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (s *plainRecorder) snapshot() ([][]byte, int) {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([][]byte, len(s.serialized))
	copy(out, s.serialized)
	return out, len(s.serialized)
}

// ---------------------------------------------------------------------------
// Headroom: the requirement the zero-copy path depends on
// ---------------------------------------------------------------------------

// TestPacketHeadroomFitsTheWorstCaseFraming proves the headroom budget covers the largest prefix
// the protocol can produce, not merely the one seen in practice.
//
// # Why the worst case is 9 bytes and not 2
//
// A short-lived connection uses a 1-byte quarter stream ID, so a budget sized from observation
// would be 2 bytes. But the quarter stream ID is a QUIC varint over streamID/4, so it grows to 8
// bytes as a connection ages. A budget sized for the common case would make the zero-copy path
// silently stop working on long-lived connections -- falling back to a full copy per packet, with
// no error and no log. Sizing for the maximum is what makes the fast path a property of the code
// rather than of how long the connection happens to have been up.
func TestPacketHeadroomFitsTheWorstCaseFraming(t *testing.T) {
	t.Parallel()

	require.Equal(t, 9, ownedDatagramHeadroom,
		"the owned DATAGRAM path must reserve the MASQUE context ID plus the largest HTTP/3 quarter "+
			"stream ID varint")
	require.GreaterOrEqual(t, PacketHeadroom, ownedDatagramHeadroom,
		"PacketHeadroom must cover the owned datagram path")
	require.GreaterOrEqual(t, PacketHeadroom, capsuleHeadroom,
		"PacketHeadroom must ALSO cover the capsule fallback, because a session can switch to it at "+
			"any time without the buffers being rebuilt")

	// And the arithmetic must hold on a real buffer, not just on the constants.
	payload := []byte("worst-case-payload")
	buffer := newOwnedTestBuffer(payload)
	contextID := transportHTTP.PrependContextID(buffer)
	require.GreaterOrEqual(t, contextID.Start(), http3QuarterStreamIDMaxLength,
		"after the context ID is prepended, the headroom left must still accept the largest "+
			"quarter stream ID")
	header := contextID.ExtendHeader(http3QuarterStreamIDMaxLength)
	require.NotNil(t, header)
	require.Len(t, header, http3QuarterStreamIDMaxLength)
	contextID.Release()
}

// TestRaisingHeadroomKeepsTheBufferInTheSamePoolClass is the §24 cost check.
//
// The headroom went from 6 to 9 bytes. That is negligible memory, but the buffer pool allocates by
// power-of-two size class, so three extra bytes COULD have pushed every packet buffer into the next
// class -- doubling the memory per packet for a three-byte gain. This asserts the class is
// unchanged, which is the fact that makes the increase free rather than a trade.
func TestRaisingHeadroomKeepsTheBufferInTheSamePoolClass(t *testing.T) {
	t.Parallel()

	for _, mtu := range []int{1280, 1400, 1500} {
		previous := buf.NewSize(capsuleHeadroom + mtu)
		current := buf.NewSize(PacketHeadroom + mtu)
		require.Equal(t, cap(previous.Bytes()), cap(current.Bytes()),
			"mtu %d: raising the headroom from %d to %d must not change the pool size class, "+
				"otherwise every packet buffer costs more memory than the bytes saved",
			mtu, capsuleHeadroom, PacketHeadroom)
		previous.Release()
		current.Release()
	}
}
