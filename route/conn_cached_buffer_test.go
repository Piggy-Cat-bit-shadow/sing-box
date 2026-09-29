package route

import (
	"errors"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// The cached first payload, and whether it reaches the destination without a copy.
//
// # What the first payload is, and why it is worth a fast path
//
// A connection with sniffing enabled hands the first bytes to a N.CachedReader, which holds them in
// a pooled *buf.Buffer. Those bytes are written to the destination before the ordinary copy loop
// starts.
//
// A pooled buffer already carries exactly the geometry a framing writer needs: front headroom, rear
// headroom, and a length. The plain Write([]byte) path discards all of it -- the writer receives a
// bare slice and, if it frames in place, must allocate a new buffer and copy the payload in. That
// is one full payload copy on the FIRST bytes of every connection, which is also where latency
// matters most.
//
// # The rule these tests pin
//
// The decision is made from the destination writer's OWN advertised geometry, never from a protocol
// name:
//
//	buffer.Len()  <= writer.WriterMTU()
//	buffer.Start() >= writer.FrontHeadroom()
//	buffer.FreeLen() >= writer.RearHeadroom()
//
// When all three hold the buffer is handed over and the writer consumes it. When any fails the
// original path runs and the caller releases. Nothing is resized or relocated to force a fit,
// because moving the payload to gain headroom would be the copy the fast path exists to avoid.

// geometryWriter is a destination that advertises geometry and records how it was written to.
//
// The capabilities are exposed through the wrappers below rather than as methods on this type,
// because a Go method is either present or absent: a single type cannot conditionally satisfy
// WriterWithMTU. The wrappers let a test build a destination with exactly the capability set it
// means to exercise.
type geometryWriter struct {
	access sync.Mutex

	// advertised geometry
	frontHeadroom int
	rearHeadroom  int
	writerMTU     int

	// recorded
	bufferWrites  int
	plainWrites   int
	lastPlainData []byte
	lastBufferLen int
	// failBufferWrite makes WriteBuffer report an error, exercising the ownership-on-error branch.
	failBufferWrite bool
}

func (w *geometryWriter) Write(p []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	w.plainWrites++
	w.lastPlainData = append([]byte(nil), p...)
	return len(p), nil
}

func (w *geometryWriter) writeBuffer(buffer *buf.Buffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.failBufferWrite {
		return errors.New("test: WriteBuffer failed")
	}
	w.bufferWrites++
	w.lastBufferLen = buffer.Len()
	buffer.Release()
	return nil
}

// plainDestination is a writer with NO buffer capability, such as a plain TCP conn.
type plainDestination struct{ *geometryWriter }

// bufferDestination accepts buffers but advertises no geometry: the three checks are vacuous.
type bufferDestination struct{ *geometryWriter }

func (w bufferDestination) WriteBuffer(buffer *buf.Buffer) error { return w.writeBuffer(buffer) }

// mtuDestination advertises only an MTU.
type mtuDestination struct{ *geometryWriter }

func (w mtuDestination) WriteBuffer(buffer *buf.Buffer) error { return w.writeBuffer(buffer) }
func (w mtuDestination) WriterMTU() int                       { return w.geometryWriter.writerMTU }

// headroomDestination advertises only headroom.
type headroomDestination struct{ *geometryWriter }

func (w headroomDestination) WriteBuffer(buffer *buf.Buffer) error { return w.writeBuffer(buffer) }
func (w headroomDestination) FrontHeadroom() int {
	return w.geometryWriter.frontHeadroom
}
func (w headroomDestination) RearHeadroom() int { return w.geometryWriter.rearHeadroom }

// fullDestination advertises both, which is what the Naive writer does.
type fullDestination struct{ *geometryWriter }

func (w fullDestination) WriteBuffer(buffer *buf.Buffer) error { return w.writeBuffer(buffer) }
func (w fullDestination) WriterMTU() int                       { return w.geometryWriter.writerMTU }
func (w fullDestination) FrontHeadroom() int {
	return w.geometryWriter.frontHeadroom
}
func (w fullDestination) RearHeadroom() int { return w.geometryWriter.rearHeadroom }

// newCachedBuffer builds a pooled buffer with the given headroom and payload length.
//
// spareCapacity is how much room is left AFTER the payload, which is where a framing writer appends
// its padding. It is a parameter rather than a constant because rear headroom is one of the three
// geometry requirements, and a fixture that always left plenty would make that check untestable --
// which is exactly how the first version of this file passed a case it should have failed.
func newCachedBuffer(headroom, payloadLen, spareCapacity int) *buf.Buffer {
	buffer := buf.NewSize(headroom + payloadLen + spareCapacity)
	buffer.Resize(headroom, 0)
	for index := 0; index < payloadLen; index++ {
		buffer.WriteByte(byte(index))
	}
	return buffer
}

// TestCachedBufferIsHandedOverWhenGeometryFits is the fast-path case.
//
// The buffer has the headroom and the length the writer asks for, so it must reach WriteBuffer and
// never touch the plain Write path.
func TestCachedBufferIsHandedOverWhenGeometryFits(t *testing.T) {
	t.Parallel()

	writer := &geometryWriter{
		frontHeadroom: 3,
		rearHeadroom:  255,
		writerMTU:     65278,
	}
	destination := fullDestination{writer}

	// A buffer with plenty of room on both sides and a small payload.
	cached := newCachedBuffer(64, 1000, 512)
	payloadLen := cached.Len()

	err, handedOver := writeCachedBuffer(destination, cached)
	require.NoError(t, err)
	require.True(t, handedOver,
		"a buffer with the writer's geometry must be handed over, not copied through Write")

	writer.access.Lock()
	defer writer.access.Unlock()
	require.Equal(t, 1, writer.bufferWrites, "WriteBuffer must have been used")
	require.Zero(t, writer.plainWrites, "the copying path must not have been used")
	require.Equal(t, payloadLen, writer.lastBufferLen)
}

// TestCachedBufferFallsBackWhenGeometryDoesNotFit covers each of the three requirements failing
// independently, because they are checked separately and a single combined test would not show
// which one is enforced.
func TestCachedBufferFallsBackWhenGeometryDoesNotFit(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name          string
		frontHeadroom int
		rearHeadroom  int
		writerMTU     int
		headroom      int
		payloadLen    int
		spareCapacity int
		reason        string
	}{
		{
			name: "payload exceeds WriterMTU", frontHeadroom: 3, rearHeadroom: 255, writerMTU: 512,
			headroom: 64, payloadLen: 1000, spareCapacity: 512,
			reason: "a payload larger than the writer's MTU must not be handed over",
		},
		{
			name: "insufficient front headroom", frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278,
			headroom: 1, payloadLen: 100, spareCapacity: 512,
			reason: "the header cannot be prepended into the buffer, so it must be copied",
		},
		{
			name: "insufficient rear headroom", frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278,
			headroom: 64, payloadLen: 100, spareCapacity: 10,
			reason: "padding cannot be appended into the buffer, so it must be copied",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			writer := &geometryWriter{
				frontHeadroom: testCase.frontHeadroom,
				rearHeadroom:  testCase.rearHeadroom,
				writerMTU:     testCase.writerMTU,
			}
			destination := fullDestination{writer}

			cached := newCachedBuffer(testCase.headroom, testCase.payloadLen, testCase.spareCapacity)
			// Rear headroom is whatever the fixture left after the payload; shrink it when the test
			// wants it tight by using a buffer sized exactly.
			expected := append([]byte(nil), cached.Bytes()...)

			err, handedOver := writeCachedBuffer(destination, cached)
			require.NoError(t, err)
			require.False(t, handedOver, testCase.reason)

			writer.access.Lock()
			defer writer.access.Unlock()
			require.Equal(t, 1, writer.plainWrites,
				"the fallback must go through Write")
			require.Zero(t, writer.bufferWrites,
				"the buffer must NOT be handed over when the geometry does not fit")
			require.Equal(t, expected, writer.lastPlainData,
				"the fallback must deliver the same bytes")
			cached.Release()
		})
	}
}

// TestCachedBufferFallsBackWithoutExtendedWriter covers a destination that cannot take buffers at
// all, such as a plain TCP conn.
func TestCachedBufferFallsBackWithoutExtendedWriter(t *testing.T) {
	t.Parallel()

	writer := &geometryWriter{}
	destination := plainDestination{writer}

	cached := newCachedBuffer(64, 256, 512)
	expected := append([]byte(nil), cached.Bytes()...)

	err, handedOver := writeCachedBuffer(destination, cached)
	require.NoError(t, err)
	require.False(t, handedOver)

	writer.access.Lock()
	defer writer.access.Unlock()
	require.Equal(t, 1, writer.plainWrites)
	require.Equal(t, expected, writer.lastPlainData)
	cached.Release()
}

// TestCachedBufferOwnershipOnWriteBufferError is the ownership case that matters most.
//
// On success the writer consumes the buffer, so the caller must not release it. On FAILURE the
// writer did not take it, so the caller must release it -- reporting handedOver=true there would
// leak the buffer, and reporting it here as false would be a double release.
func TestCachedBufferOwnershipOnWriteBufferError(t *testing.T) {
	t.Parallel()

	writer := &geometryWriter{
		frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278,
		failBufferWrite: true,
	}
	destination := fullDestination{writer}

	cached := newCachedBuffer(64, 100, 512)
	err, handedOver := writeCachedBuffer(destination, cached)
	require.Error(t, err, "the writer's error must be reported")
	require.False(t, handedOver,
		"a FAILED WriteBuffer must not report a hand-off, or the caller would leak the buffer")

	// The caller releases, which must be safe because the writer did not consume it.
	cached.Release()
	require.Zero(t, cached.Len(), "the buffer is back in the pool after the caller released it")
}

// TestCachedBufferWithoutGeometryCapabilitiesIsHandedOver proves a writer that accepts buffers but
// advertises nothing is still given the buffer directly.
//
// A writer with no MTU or headroom requirement has nothing to violate, so the three checks are
// vacuous and the direct hand-off is correct -- the same reading sing's own CalculateMTU applies to
// a plain net.Conn.
func TestCachedBufferWithoutGeometryCapabilitiesIsHandedOver(t *testing.T) {
	t.Parallel()

	writer := &geometryWriter{}
	destination := bufferDestination{writer}

	cached := newCachedBuffer(8, 4096, 512)
	err, handedOver := writeCachedBuffer(destination, cached)
	require.NoError(t, err)
	require.True(t, handedOver,
		"a writer that advertises no geometry has none to satisfy")

	writer.access.Lock()
	defer writer.access.Unlock()
	require.Equal(t, 1, writer.bufferWrites)
}

// TestCachedBufferFastPathDeliversIdenticalBytes is the correctness guard across both paths.
//
// Whatever route the bytes take, the destination must see the same payload. A fast path that
// silently dropped or truncated the first payload would break every sniffed connection.
func TestCachedBufferFastPathDeliversIdenticalBytes(t *testing.T) {
	t.Parallel()

	const payloadLen = 8192

	// The bytes that would reach the wire through each path.
	var viaFastPath, viaFallback []byte

	fastWriter := &recordingExtendedWriter{recordingWriter: &recordingWriter{}}
	cachedFast := newCachedBuffer(64, payloadLen, 512)
	viaFastPath = append([]byte(nil), cachedFast.Bytes()...)
	err, handedOver := writeCachedBuffer(fastWriter, cachedFast)
	require.NoError(t, err)
	require.True(t, handedOver)
	require.Equal(t, viaFastPath, fastWriter.bufferData,
		"the handed-over buffer must be the payload, unmodified")
	// The writer consumed it, so the test must not release it.

	plainWriter := &recordingWriter{}
	cachedFallback := newCachedBuffer(64, payloadLen, 512)
	viaFallback = append([]byte(nil), cachedFallback.Bytes()...)
	err, handedOver = writeCachedBuffer(plainWriter, cachedFallback)
	require.NoError(t, err)
	require.False(t, handedOver)
	require.Equal(t, viaFallback, plainWriter.plainData)
	cachedFallback.Release()

	require.Equal(t, viaFastPath, viaFallback,
		"both paths must carry the same bytes")
}

// recordingWriter records the payload it received through either path.
type recordingWriter struct {
	bufferData []byte
	plainData  []byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.plainData = append([]byte(nil), p...)
	return len(p), nil
}

// recordingExtendedWriter adds the buffer-taking capability.
type recordingExtendedWriter struct{ *recordingWriter }

func (w recordingExtendedWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.bufferData = append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	return nil
}
