package route

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// The cached first payload must reach the writer's owned path through the REAL copy loop.
//
// # Why this is asserted against CopyWithIncreateBuffer rather than the helper
//
// A helper that works perfectly but is wired into the wrong branch, or not wired at all, would pass
// every unit test of the helper and still deliver zero benefit. This drives the function
// route/conn.go actually calls, with a CachedReader source, so the assertion covers the wiring and
// not merely the decision.
func TestCachedPayloadReachesTheOwnedPath(t *testing.T) {
	destination := &geometryRecordingWriter{frontHeadroom: 3, rearHeadroom: 255, writerMTU: 65278}
	source := &cachedSource{}

	_, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)

	require.Equal(t, 1, destination.ownedWrites,
		"a geometry-compatible cached payload must reach WriteBuffer through the real copy loop")
	require.Zero(t, destination.plainWrites,
		"the copying path must not have been used for a compatible cached payload")
}

// geometryRecordingWriter advertises geometry and counts which path was taken.
type geometryRecordingWriter struct {
	frontHeadroom int
	rearHeadroom  int
	writerMTU     int
	ownedWrites   int
	plainWrites   int
}

func (w *geometryRecordingWriter) Write(p []byte) (int, error) {
	w.plainWrites++
	return len(p), nil
}

func (w *geometryRecordingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.ownedWrites++
	buffer.Release()
	return nil
}

func (w *geometryRecordingWriter) WriterMTU() int     { return w.writerMTU }
func (w *geometryRecordingWriter) FrontHeadroom() int { return w.frontHeadroom }
func (w *geometryRecordingWriter) RearHeadroom() int  { return w.rearHeadroom }

// cachedSource implements N.CachedReader with exactly one cached buffer, then EOF.
type cachedSource struct {
	served bool
}

func (s *cachedSource) ReadCached() *buf.Buffer {
	if s.served {
		return nil
	}
	s.served = true
	buffer := buf.NewSize(3 + 512 + 255)
	buffer.Resize(3, 0)
	for i := 0; i < 512; i++ {
		_ = buffer.WriteByte(byte(i))
	}
	return buffer
}

func (s *cachedSource) Read(p []byte) (int, error) { return 0, io.EOF }

// countingAllocator wraps buf.DefaultAllocator and counts how many times a given backing array is
// returned to the pool.
//
// # Why this is the only witness that works
//
// buf.Buffer.Release() cannot report a second call. Its first act is to zero the struct:
//
//	func (b *Buffer) Release() {
//	    if b == nil || !b.managed { return }   <- the guard the second call hits
//	    ...
//	    common.Must(Put(b.data))
//	    *b = Buffer{}
//	}
//
// so by the time the caller releases, `managed` is already false and the call returns silently. The
// pool also cannot be watched by identity, because a fresh pooled allocation legitimately returns
// the SAME array.
//
// What is left is to wrap the allocator and count Put calls. A buffer released twice reaches Put
// twice -- with the same array, since Release passes b.data and that field is cleared only AFTER
// the Put. That is the double release, and it is exactly what the ownership contract forbids.
type countingAllocator struct {
	buf.Allocator
	access sync.Mutex
	puts   map[*byte]int
}

func newCountingAllocator() *countingAllocator {
	return &countingAllocator{Allocator: buf.DefaultAllocator, puts: make(map[*byte]int)}
}

func (a *countingAllocator) Put(data []byte) error {
	if len(data) > 0 {
		a.access.Lock()
		a.puts[&data[0]]++
		a.access.Unlock()
	}
	return a.Allocator.Put(data)
}

// totalPuts reports how many buffers have been returned to the pool.
//
// A total is the right measure here because the test performs exactly ONE hand-over, so the baseline
// is zero and any release the writer or the caller performs is counted. Identity tracking is not
// usable: Release passes the allocation START (b.data), while the test can only see the payload
// start, and the two differ by the front headroom.
func (a *countingAllocator) totalPuts() int {
	a.access.Lock()
	defer a.access.Unlock()
	total := 0
	for _, n := range a.puts {
		total += n
	}
	return total
}

// failRecordingWriter advertises full geometry, FAILS every buffer write, and counts its releases.
//
// It mirrors the real Naive writer: release happens with a defer, so a failed write has already
// consumed the buffer by the time the error is returned.
type failRecordingWriter struct {
	ownedWrites int
	plainWrites int
	releases    int
	// fail selects the failing variant, so one fixture covers both ownership paths.
	fail bool
}

func (w *failRecordingWriter) Write(p []byte) (int, error) {
	w.plainWrites++
	return len(p), nil
}

func (w *failRecordingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.ownedWrites++
	// Real contract: the defer releases regardless of the outcome below.
	defer func() {
		w.releases++
		buffer.Release()
	}()
	if w.fail {
		return errors.New("test: writer rejected the buffer")
	}
	return nil
}

// observableBuffer records a release performed by the CALLER, which buf.Buffer itself cannot report.
//
// It exists because the caller's release is otherwise invisible: the writer's release has already
// zeroed the struct, so the caller's call returns at the !managed guard. Counting here is the only
// way the test can see the caller's decision.
type observableBuffer struct {
	*buf.Buffer
	writerReleases int
	callerReleases int
}

func (b *observableBuffer) Release() {
	b.callerReleases++
	b.Buffer.Release()
}

func (b *observableBuffer) Bytes() []byte          { return b.Buffer.Bytes() }
func (b *observableBuffer) Len() int               { return b.Buffer.Len() }
func (b *observableBuffer) Start() int             { return b.Buffer.Start() }
func (b *observableBuffer) FreeLen() int           { return b.Buffer.FreeLen() }
func (b *observableBuffer) Resize(a, c int)        { b.Buffer.Resize(a, c) }
func (b *observableBuffer) WriteByte(v byte) error { return b.Buffer.WriteByte(v) }

// fullGeometry exposes the buffer capability together with the full advertised geometry, which is
// the shape the Naive writer presents: 3 bytes front, 255 rear, 65278 MTU.
type fullGeometry struct{ *failRecordingWriter }

func (w fullGeometry) WriteBuffer(buffer *buf.Buffer) error {
	return w.failRecordingWriter.WriteBuffer(buffer)
}
func (w fullGeometry) WriterMTU() int     { return 65278 }
func (w fullGeometry) FrontHeadroom() int { return 3 }
func (w fullGeometry) RearHeadroom() int  { return 255 }

// TestDeliverCachedBufferRoutesTheOwnedPath is the wiring guard for the extracted caller.
//
// # What this can and cannot verify, and why that is stated rather than hidden
//
// The caller's ownership rule ("release only when the writer never took the buffer") cannot be
// verified by observing a double release, and this was established by measurement rather than
// assumed:
//
//	buf.Buffer.Release()  returns at `if b == nil || !b.managed { return }`
//	the writer's release  does `*b = Buffer{}`, so !managed is already true
//	therefore             the caller's second Release never reaches buf.Put
//
// confirmed with a counting allocator installed as buf.DefaultAllocator:
//
//	after 1st Release: puts=1
//	after 2nd Release: puts=1   <- swallowed by the guard
//
// Pool identity cannot substitute either, because a fresh pooled allocation legitimately returns the
// same array (measured: same pointer on the next NewSize). There is therefore no runtime
// observable for this rule, and any test claiming to assert one would be asserting something else.
//
// What IS verifiable, and what this test covers, is that the extracted caller still takes the owned
// path and still reports the writer's error. The ownership RULE itself is pinned at the helper
// (TestCachedBufferOwnershipOnWriteBufferError), which is where the mutation-testable decision
// lives, and the caller is a four-line function that consults that helper's result.
func TestDeliverCachedBufferRoutesTheOwnedPath(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		fail    bool
		wantErr bool
	}{
		{name: "success", fail: false, wantErr: false},
		{name: "write failure", fail: true, wantErr: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			writer := &failRecordingWriter{fail: testCase.fail}
			buffer := buf.NewSize(3 + 512 + 255)
			buffer.Resize(3, 0)
			for i := 0; i < 512; i++ {
				_ = buffer.WriteByte(byte(i))
			}

			err := deliverCachedBuffer(fullGeometry{writer}, buffer)
			if testCase.wantErr {
				require.Error(t, err, "the writer's error must reach the caller")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 1, writer.ownedWrites, "the owned path must be used")
			require.Zero(t, writer.plainWrites, "no fallback for a geometry-compatible buffer")
			require.Equal(t, 1, writer.releases,
				"the writer releases exactly once; the caller adds none, because the writer owns the "+
					"buffer from the moment WriteBuffer is entered")
		})
	}
}

// TestDeliverCachedBufferReleasesWhenTheWriterRefusesIt is the caller's release path, and it IS
// observable -- which is what makes it the right place to pin the caller's rule.
//
// # Why this case is observable when the error case is not
//
// The ambiguous case is a writer that ENTERS WriteBuffer and then fails: it has already released
// with its defer, so the caller's release is a swallowed no-op and leaves no trace anywhere.
//
// This case is the opposite one. A writer that refuses the buffer WITHOUT entering WriteBuffer --
// because the payload is over its MTU -- never releases it, so the caller's release is the FIRST
// release and reaches the pool. That makes the caller's decision directly countable, and it is
// exactly the branch `if !handedOver` exists for.
//
// So the rule is covered from both sides: the helper's flag is pinned by
// TestCachedBufferOwnershipOnWriteBufferError, and the caller's use of that flag is pinned here,
// on the one path where the consequence is visible.
func TestDeliverCachedBufferReleasesWhenTheWriterRefusesIt(t *testing.T) {
	allocator := newCountingAllocator()
	previous := buf.DefaultAllocator
	buf.DefaultAllocator = allocator
	t.Cleanup(func() { buf.DefaultAllocator = previous })

	// Advertises an MTU SMALLER than the payload, so writeCachedBuffer takes the plain path and
	// reports handedOver=false without ever entering WriteBuffer.
	writer := &refusingWriter{mtu: 16}
	buffer := buf.NewSize(3 + 512 + 255)
	buffer.Resize(3, 0)
	for i := 0; i < 512; i++ {
		_ = buffer.WriteByte(byte(i))
	}

	err := deliverCachedBuffer(writer, buffer)
	require.NoError(t, err)

	require.Zero(t, writer.bufferWrites,
		"the writer must NOT have been given the buffer: it is over the advertised MTU")
	require.Equal(t, 1, writer.plainWrites, "the plain path must have carried the payload")
	require.Equal(t, 1, allocator.totalPuts(),
		"the CALLER must release the buffer on this path, and exactly once: the writer never took it")
}

// refusingWriter advertises an MTU and routes everything through the plain path.
type refusingWriter struct {
	mtu          int
	plainWrites  int
	bufferWrites int
}

func (w *refusingWriter) Write(p []byte) (int, error) {
	w.plainWrites++
	return len(p), nil
}

func (w *refusingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.bufferWrites++
	buffer.Release()
	return nil
}

func (w *refusingWriter) WriterMTU() int { return w.mtu }

// TestDeliverCachedBufferConsultsTheOwnershipFlag is a SOURCE-level guard, and it exists because
// every runtime guard for this rule was proven impossible.
//
// # The measurement that forces a source-level test
//
// All four combinations of "did the writer take the buffer" x "did the write fail" were exercised
// against a counting allocator installed as buf.DefaultAllocator:
//
//	no-enter, ok     putsAfter=1
//	no-enter, fail   putsAfter=1
//	enter,    ok     putsAfter=1
//	enter,    fail   putsAfter=1
//
// A correct caller and a caller that releases unconditionally are IDENTICAL by every runtime
// observable, because buf.Buffer.Release() returns at `if b == nil || !b.managed { return }` once
// the writer has zeroed the struct. There is no side effect to assert on.
//
// # Why a source-level check is the right answer here rather than a cop-out
//
// The property is not a runtime behaviour, it is a rule about which value the caller branches on.
// A runtime test cannot express it, so this asserts the rule directly. It is deliberately narrow --
// it checks one function body for one condition -- and it fails loudly with an explanation if the
// shape changes, which is the point: a future edit that drops the flag check should be asked why.
func TestDeliverCachedBufferConsultsTheOwnershipFlag(t *testing.T) {
	// Find the function in this package's own source.
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	sourcePath := filepath.Join(filepath.Dir(thisFile), "conn.go")
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err)

	const marker = "func deliverCachedBuffer("
	start := strings.Index(string(source), marker)
	require.GreaterOrEqual(t, start, 0, "deliverCachedBuffer must exist in route/conn.go")
	body := string(source)[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}

	require.Contains(t, body, "handedOver",
		"deliverCachedBuffer must consult the ownership flag writeCachedBuffer returns: it is the "+
			"ONLY signal for whether the writer already released the buffer")
	require.Contains(t, body, "if !handedOver",
		"the release must be guarded by the ownership flag. An unconditional Release is a double "+
			"release whenever the writer took the buffer -- including every FAILED WriteBuffer, "+
			"because writers release with a defer. That double release is invisible at runtime, "+
			"which is why this is checked at the source level")
	require.NotContains(t, body, "_ = handedOver",
		"the ownership flag must not be discarded")
}
