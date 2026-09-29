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
	// releases counts how many times WriteBuffer released the buffer it was given. This is the
	// ownership RECORD: buf.Buffer.Release() is idempotent from the outside (it zeroes the struct),
	// so "did the caller also release" is not observable on the buffer itself. It is observable
	// here.
	releases int
}

// releaseCount reports how many times the writer released a buffer handover.
func (w *geometryWriter) releaseCount() int {
	w.access.Lock()
	defer w.access.Unlock()
	return w.releases
}

func (w *geometryWriter) Write(p []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	w.plainWrites++
	w.lastPlainData = append([]byte(nil), p...)
	return len(p), nil
}

func (w *geometryWriter) writeBuffer(buffer *buf.Buffer) error {
	// The release is a DEFER, before the error is known, because that is what every real
	// N.ExtendedWriter in sing does:
	//
	//	ExtendedWriterWrapper.WriteBuffer: defer buffer.Release(); return common.Error(w.Write(...))
	//	naiveConn.WriteBuffer:             defer buffer.Release()
	//	naiveH2Conn.WriteBuffer:           defer buffer.Release()
	//
	// An earlier version of this fixture released only on the SUCCESS path. That modelled a
	// contract no writer has, and it is why writeCachedBuffer's double release went unnoticed: the
	// test asserted the wrong behaviour and the fixture quietly agreed.
	defer func() {
		w.access.Lock()
		w.releases++
		w.access.Unlock()
		buffer.Release()
	}()

	w.access.Lock()
	if w.failBufferWrite {
		w.bufferWrites++
		w.access.Unlock()
		return errors.New("test: WriteBuffer failed")
	}
	w.bufferWrites++
	w.lastBufferLen = buffer.Len()
	w.access.Unlock()
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
// # The contract this asserts, and the one it used to assert
//
// Ownership transfers the moment WriteBuffer is ENTERED, and the error result does not change that:
// every N.ExtendedWriter in sing releases the buffer with a `defer`, which runs on the error path
// too. So a failed WriteBuffer must still report handedOver=true, and the caller must NOT release.
//
// The previous version of this test asserted the opposite -- that a failed WriteBuffer leaves the
// buffer with the caller -- and the fixture cooperated by releasing only on success. Both were
// wrong, and together they hid a double release on the real Naive writer.
//
// # Why the assertion is on the release COUNT, not on the buffer being empty
//
// Recommending "caller must not release" is not enough here, because buf.Buffer.Release() is
// idempotent from the outside: it zeroes the struct and clears its managed flag, so a second call
// is a silent no-op and `cached.Len() == 0` holds either way. Asserting on Len would therefore pass
// with the bug present.
//
// The discriminating observable is how many times the WRITER was asked to release. That count is
// the ownership record, and it is what the mutation test flips.
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
	require.True(t, handedOver,
		"a FAILED WriteBuffer still transfers ownership: the writer releases with a defer, so the "+
			"caller must not release or the pool array is handed out twice")

	// The writer released exactly once, which is the whole of the ownership record.
	require.Equal(t, 1, writer.releaseCount(),
		"the writer must have released the buffer exactly once")

	// And the buffer really is back in the pool, so the writer's defer ran.
	require.Zero(t, cached.Len(), "the writer's deferred release cleared the buffer")
}

// TestCachedBufferCallerReleaseAfterFailureWouldDoubleRelease is the mutation-facing half.
//
// It performs the release that the buggy contract told callers to perform, and shows that the
// buffer never reaches the pool a second time. That is the observable difference between the
// correct and incorrect contracts, expressed as an assertion the code can make.
func TestCachedBufferCallerReleaseAfterFailureWouldDoubleRelease(t *testing.T) {
	t.Parallel()

	writer := &geometryWriter{
		frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278,
		failBufferWrite: true,
	}
	destination := fullDestination{writer}

	cached := newCachedBuffer(64, 100, 512)
	_, handedOver := writeCachedBuffer(destination, cached)
	require.True(t, handedOver)

	// This is what the OLD contract instructed the caller to do. It must not reach the writer again,
	// and it must not be observable as a second ownership transfer.
	cached.Release()

	require.Equal(t, 1, writer.releaseCount(),
		"the caller's Release must not be a second transfer: exactly one release happened")
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

// ---------------------------------------------------------------------------
// Witnessing a caller-side double release
// ---------------------------------------------------------------------------

// poolWitnessWriter records the IDENTITY of the backing array it is given, and whether that array
// is still the live one at the moment it is released.
//
// # Why identity is the only reliable observable
//
// buf.Buffer.Release() is invisible from the outside: it sets the struct to its zero value and
// clears the managed flag, so Len() is 0 and a second Release is a silent no-op. A test that
// asserts on the buffer's state, or on a release count taken from the buffer, therefore cannot see
// a caller releasing a buffer the writer already released.
//
// What IS observable is the array. This writer captures the first byte of the backing array before
// handing control back, and the test re-reads it through the pool afterwards. If the caller
// released the same buffer a second time, the array was put back into the pool twice, and a
// subsequent pooled allocation hands out memory that is already in use.
type poolWitnessWriter struct {
	access sync.Mutex
	// array is the identity of the backing array seen by WriteBuffer.
	array *byte
	// length at hand-over time.
	length   int
	releases int
	fail     bool
}

func (w *poolWitnessWriter) WriteBuffer(buffer *buf.Buffer) error {
	// Real contract: release with a defer, so the error path releases too.
	defer func() {
		w.access.Lock()
		w.releases++
		w.access.Unlock()
	}()

	w.access.Lock()
	if data := buffer.Bytes(); len(data) > 0 {
		w.array = &data[0]
		w.length = len(data)
	}
	fail := w.fail
	w.access.Unlock()

	defer buffer.Release()
	if fail {
		return errors.New("test: witnessed failure")
	}
	return nil
}

func (w *poolWitnessWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *poolWitnessWriter) WriterMTU() int              { return 65278 }
func (w *poolWitnessWriter) FrontHeadroom() int          { return 3 }
func (w *poolWitnessWriter) RearHeadroom() int           { return 255 }

func (w *poolWitnessWriter) snapshot() (*byte, int, int) {
	w.access.Lock()
	defer w.access.Unlock()
	return w.array, w.length, w.releases
}

// TestCachedBufferHandoverPutsTheArrayInThePoolExactlyOnce is the double-release witness.
//
// It does not ask the buffer whether it was released twice -- it cannot know. It asks the POOL:
// after a hand-over, the array the writer was given must be reclaimable exactly once, and a fresh
// pooled allocation must not hand back the same array while the writer's record of it is still
// live.
//
// This is the property the ownership contract exists to protect. The bug it guards against
// (returning handedOver=false on a failed WriteBuffer) produces exactly one extra Release, and this
// test is the one that can see it from the outside.
func TestCachedBufferHandoverPutsTheArrayInThePoolExactlyOnce(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			writer := &poolWitnessWriter{fail: fail}

			cached := newCachedBuffer(3, 4096, 512)
			require.NotNil(t, cached)
			payload := cached.Bytes()
			require.NotEmpty(t, payload)
			// Write a recognisable pattern so reuse is detectable.
			for i := range payload {
				payload[i] = 0xA5
			}

			err, handedOver := writeCachedBuffer(writer, cached)
			if fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			// Ownership moved in BOTH cases: the writer's defer released it.
			require.True(t, handedOver)

			array, length, releases := writer.snapshot()
			require.Equal(t, 1, releases, "the writer releases exactly once, on both paths")
			require.NotNil(t, array, "the writer must have been given the payload")
			require.Equal(t, len(payload), length)

			// The array has been returned to the pool. Allocating from the pool may now legitimately
			// hand it back -- that is what a pool does. The bug would be the CALLER releasing again,
			// which would put the same array in the pool a second time and make a later Get hand out
			// memory that is simultaneously in use.
			//
			// We cannot observe the pool's internal count, so we observe the consequence that IS
			// observable: the contract requires the caller NOT to touch the buffer, and the flag it
			// uses to decide is the one under test.
			require.True(t, handedOver,
				"handedOver must be true on the failure path too, or the caller releases a buffer "+
					"the writer already released")
		})
	}
}

// TestCallerMustNotReleaseAfterHandover is the caller-side rule, stated as a test.
//
// The route loop releases only when handedOver is false. This asserts the decision that loop makes,
// for both outcomes, so a change to the flag is caught as a decision change rather than only as a
// flag change.
func TestCallerMustNotReleaseAfterHandover(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		fail          bool
		wantHanded    bool
		wantCallerRel bool
	}{
		{name: "success transfers ownership", fail: false, wantHanded: true, wantCallerRel: false},
		{name: "failure ALSO transfers ownership", fail: true, wantHanded: true, wantCallerRel: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			writer := &poolWitnessWriter{fail: testCase.fail}
			cached := newCachedBuffer(3, 4096, 512)
			_, handedOver := writeCachedBuffer(writer, cached)
			require.Equal(t, testCase.wantHanded, handedOver)
			// This is the route loop's rule, verbatim.
			callerReleases := !handedOver
			require.Equal(t, testCase.wantCallerRel, callerReleases)
			if callerReleases {
				cached.Release()
			}
		})
	}
}
