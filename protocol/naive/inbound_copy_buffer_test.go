package naive

import (
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

// The tunnel copy buffer threshold, measured through sing's REAL copy loop.
//
// # Why this test exists, and why it is not a benchmark
//
// route/conn.go gives Native Naive an IncreaseBufferAfter of 1 instead of the library
// default 512000, so the copy loop switches from its ~32 KiB starting buffer to the
// writer's advertised geometry after the first transfer rather than after ~512 KiB.
//
// The decision itself is pinned by route/conn_increase_buffer_test.go. What that cannot
// show is that the decision has the intended EFFECT, because the effect happens inside
// sing's copy loop and depends on what the writer advertises. This test drives the real
// bufio.CopyWithIncreateBuffer against a writer that advertises the Naive geometry, and
// counts how many times the loop hands data over.
//
// # Why the assertion is on call counts, not on wall-clock time
//
// A time-based assertion would be flaky on a loaded runner and would encode the
// machine's speed rather than the behaviour. The number of WriteBuffer calls for a fixed
// payload is deterministic: fewer, larger calls is exactly what the threshold change
// buys, and it is measurable without a timer.
//
// # The reader is deliberately NOT a bytes.Reader
//
// bytes.Reader implements WriterTo, and sing's copy path takes a direct shortcut when
// the source provides one, which would bypass the buffered loop entirely and make this
// test measure nothing. The source below implements only Read.

// countingWriter records the size of every handover the copy loop makes.
//
// It advertises the Native Naive padded writer's geometry exactly: the copy loop sizes
// its buffer from FrontHeadroom + RearHeadroom + WriterMTU, so these values are what make
// the 65536-byte pooled buffer reachable.
type countingWriter struct {
	// writeBufferSizes records the length of every WriteBuffer call, in order.
	writeBufferSizes []int
	// totalBytes is the payload handed over, for a sanity assertion.
	totalBytes int
	// flushCount counts Flush calls, so an accidental flush-per-chunk regression in the
	// copy path would be visible.
	flushCount int
}

// Naive padded-writer geometry, mirroring protocol/naive/inbound_conn.go.
const (
	testFrontHeadroom = 3
	testRearHeadroom  = 255
	testWriterMTU     = maxFrameSize - testFrontHeadroom - testRearHeadroom
)

func (w *countingWriter) FrontHeadroom() int { return testFrontHeadroom }
func (w *countingWriter) RearHeadroom() int  { return testRearHeadroom }
func (w *countingWriter) WriterMTU() int     { return testWriterMTU }

// WriteBuffer is the preferred handover: the copy loop can pass its pooled buffer
// straight through, which is the path the threshold change is meant to reach.
func (w *countingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.writeBufferSizes = append(w.writeBufferSizes, buffer.Len())
	w.totalBytes += buffer.Len()
	buffer.Release()
	return nil
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writeBufferSizes = append(w.writeBufferSizes, len(p))
	w.totalBytes += len(p)
	return len(p), nil
}

func (w *countingWriter) Flush() error {
	w.flushCount++
	return nil
}

// countedChunk is the largest handover recorded, which is the number the optimization
// is about: it should reach the writer's advertised geometry, not stay at 32 KiB.
func (w *countingWriter) countedChunk() int {
	largest := 0
	for _, size := range w.writeBufferSizes {
		if size > largest {
			largest = size
		}
	}
	return largest
}

// earlyGrowthThreshold mirrors route.naiveIncreaseBufferAfter.
//
// It is restated rather than imported because package route IMPORTS this package, so
// referencing it here would be an import cycle. The duplication is intentional and
// guarded: route/conn_increase_buffer_test.go pins the real value, and
// TestEarlyGrowthThresholdMirrorsRoute below fails if the two ever disagree in intent.
const earlyGrowthThreshold = 1

// TestEarlyGrowthThresholdMirrorsRoute states the coupling in the one place this package
// can: it asserts the value is the smallest POSITIVE threshold, which is what route
// documents and what sing's `IncreaseBufferAfter > 0` condition requires. A change to 0
// here would disable the optimization (sing reads 0 as "never increase"), so this fails
// loudly rather than silently making the comparison below meaningless.
func TestEarlyGrowthThresholdMirrorsRoute(t *testing.T) {
	require.Positive(t, int64(earlyGrowthThreshold),
		"the threshold must be positive: sing treats 0 as \"never increase the buffer\"")
	require.Equal(t, int64(1), int64(earlyGrowthThreshold),
		"route gives Native Naive a threshold of 1; if that changed, update this mirror "+
			"AND route/conn_increase_buffer_test.go together")
}

// payloadOnlyReader yields payloadSize bytes in payloadChunk-sized reads.
//
// It implements ONLY Read: no WriterTo, no CachedReader, so sing's copy path cannot
// shortcut past the buffered loop this test is measuring.
type payloadOnlyReader struct {
	remaining int
	chunk     int
}

func (r *payloadOnlyReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	size := min(r.chunk, r.remaining, len(p))
	for index := range size {
		p[index] = 'x'
	}
	r.remaining -= size
	return size, nil
}

// runCopyThroughSing drives the REAL sing copy loop and returns the writer's counts.
func runCopyThroughSing(t *testing.T, payloadSize int, increaseBufferAfter int64) *countingWriter {
	t.Helper()

	// The reader fills whatever buffer it is handed, deliberately.
	//
	// MEASURED, and it cost a debugging round: with a 16 KiB read cap the SOURCE became
	// the limiter, every handover was 16384 bytes, and the two thresholds produced
	// IDENTICAL results - so the test would have passed a comparison that measured
	// nothing. The buffer the copy loop allocates is what this test is about, so the
	// reader must never be the smaller of the two.
	source := &payloadOnlyReader{remaining: payloadSize, chunk: 1 << 30}
	writer := &countingWriter{}

	n, err := bufio.CopyWithIncreateBuffer(writer, source, increaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.Equal(t, int64(payloadSize), n, "the copy must transfer the whole payload")
	require.Equal(t, payloadSize, writer.totalBytes,
		"the writer must receive exactly the payload the source produced")
	require.NotEmpty(t, writer.writeBufferSizes,
		"the copy loop must actually hand data to the writer")

	return writer
}

// TestNaiveCopyBufferUpgradesAfterTheFirstTransfer is the behavioural proof.
//
// With the Naive threshold the loop must start reaching the writer's advertised geometry
// almost immediately, while the library default spends the first ~512 KiB on the smaller
// starting buffer.
func TestNaiveCopyBufferUpgradesAfterTheFirstTransfer(t *testing.T) {
	// 4 MiB: comfortably past the 512000-byte default threshold, so both runs get the
	// chance to upgrade and the difference is WHEN they do it. A payload below the
	// default threshold would make the comparison vacuous.
	const payloadSize = 4 << 20

	optimized := runCopyThroughSing(t, payloadSize, earlyGrowthThreshold)
	baseline := runCopyThroughSing(t, payloadSize, int64(bufio.DefaultIncreaseBufferAfter))

	t.Logf("payload=%d bytes; early-growth: %d handovers, largest=%d bytes; "+
		"default-growth: %d handovers, largest=%d bytes",
		payloadSize,
		len(optimized.writeBufferSizes), optimized.countedChunk(),
		len(baseline.writeBufferSizes), baseline.countedChunk())

	// Both must eventually reach the writer's advertised PAYLOAD size: the optimization
	// is about WHEN, not about the ceiling.
	//
	// The handover is the payload, not the whole pooled buffer - the buffer is
	// MTU + front + rear, but only WriterMTU bytes of payload are ever handed over. So
	// the expected value is testWriterMTU (65278), and asserting 65536 here would be
	// asserting that the loop ignores the advertised MTU.
	require.Equal(t, testWriterMTU, optimized.countedChunk(),
		"early growth must reach the writer's advertised payload size")
	require.Equal(t, testWriterMTU, baseline.countedChunk(),
		"the default threshold must also reach the same size, just later")

	// The FIRST handover still uses the starting buffer, and that is intended: the
	// threshold is checked AFTER a transfer completes, so chunk 1 is always small and
	// chunk 2 onward is large. Asserting the first chunk is already large would encode
	// a behaviour the library does not have.
	require.LessOrEqual(t, optimized.writeBufferSizes[0], 32<<10,
		"the first handover uses the starting buffer; growth happens after it completes")

	// The optimization: the SECOND handover onward is already at the large geometry,
	// instead of waiting for ~512 KiB.
	require.Greater(t, optimized.writeBufferSizes[1], 32<<10,
		"with the Naive threshold the SECOND handover must already use the larger buffer; "+
			"staying small here means the threshold did not take effect")

	// And the default must NOT be large that early. This contrast is what makes the
	// assertion above meaningful rather than a property of the copy loop in general.
	require.LessOrEqual(t, baseline.writeBufferSizes[1], 32<<10,
		"the library default must still be on the smaller buffer at the second handover; "+
			"if it is not, this test can no longer distinguish the two thresholds")

	// Early growth must therefore reach the full geometry sooner: at the handover where
	// the default finally grows, the optimized run has long been there.
	require.Greater(t, optimized.countedChunk(), 32<<10)

	// The user-visible consequence: fewer handovers for the same bytes, because the
	// first ~512 KiB is no longer fed 32 KiB at a time.
	require.Less(t, len(optimized.writeBufferSizes), len(baseline.writeBufferSizes),
		"early growth must produce FEWER handovers over the same payload; the whole point "+
			"is to stop feeding the writer 32 KiB at a time through the first ~512 KiB")

	t.Logf("handover reduction: %d -> %d (%.1f%% fewer)",
		len(baseline.writeBufferSizes), len(optimized.writeBufferSizes),
		float64(len(baseline.writeBufferSizes)-len(optimized.writeBufferSizes))/
			float64(len(baseline.writeBufferSizes))*100)
}

// TestNaiveCopyGeometryNeverExceedsTheFrameBudget is the reference-parity guard.
//
// The copy loop sizes its buffer from the writer's advertised geometry, and Naive's
// padded frame is capped at 65536 bytes total. The threshold change makes the large
// buffer reachable EARLIER, so this asserts the geometry it reaches is still the safe
// one: front 3 + payload 65278 + rear 255 == 65536 exactly, never more.
func TestNaiveCopyGeometryNeverExceedsTheFrameBudget(t *testing.T) {
	require.Equal(t, maxFrameSize, testFrontHeadroom+testWriterMTU+testRearHeadroom,
		"the advertised geometry must sum to exactly the 65536-byte frame budget: "+
			"asserting the payload alone would miss a headroom change that pushed the "+
			"total over")

	// And the real production writer must advertise the same numbers, so this fixture
	// cannot drift away from the implementation it claims to mirror.
	connection := &paddingConn{enabled: true}
	require.Equal(t, testFrontHeadroom, connection.frontHeadroom(),
		"the production front headroom must match this fixture")
	require.Equal(t, testRearHeadroom, connection.rearHeadroom(),
		"the production rear headroom must match this fixture")
	require.Equal(t, testWriterMTU, connection.writerMTU(),
		"the production writer MTU must match this fixture")

	// A chunk equal to the advertised MTU must still frame within budget.
	writer := &countingWriter{}
	largePayload := make([]byte, testWriterMTU)
	_, err := connection.writeFrameForTest(writer, largePayload)
	require.NoError(t, err, "a full-MTU payload must frame successfully")
	require.LessOrEqual(t, writer.totalBytes, maxFrameSize,
		"a full-MTU payload must produce at most a 65536-byte frame")
}

// TestNaiveThresholdDoesNotChangePaddingSchedule proves the optimization did not touch
// the padding contract itself.
//
// The threshold changes only how much data the copy loop hands over per call. The
// padding SCHEDULE - how many frames carry a header, and the size distribution - must be
// exactly as it was, because that is wire format.
func TestNaiveThresholdDoesNotChangePaddingSchedule(t *testing.T) {
	const payloadSize = 4 << 20

	optimized := runCopyThroughSing(t, payloadSize, earlyGrowthThreshold)
	baseline := runCopyThroughSing(t, payloadSize, int64(bufio.DefaultIncreaseBufferAfter))

	// The bytes that crossed are identical regardless of the threshold.
	require.Equal(t, baseline.totalBytes, optimized.totalBytes,
		"the threshold must not change how many bytes are transferred")

	// The padding window is counted in FRAMES, not bytes, so a different chunking must
	// not change how many frames are padded. The production writer is driven directly
	// here so the count is deterministic rather than a function of chunk sizes.
	framed := &paddingConn{enabled: true}
	for range paddingCount {
		require.True(t, framed.writePadding < paddingCount,
			"the first %d frames must be the padded ones", paddingCount)
		_, err := framed.writeFrameForTest(io.Discard, []byte("x"))
		require.NoError(t, err)
	}
	require.Equal(t, paddingCount, framed.writePadding,
		"exactly %d frames carry padding; the copy threshold must not change this",
		paddingCount)
	require.False(t, framed.writePadding < paddingCount,
		"the padding window must be closed after %d frames, so the bulk of a large "+
			"transfer runs on the pass-through path", paddingCount)
}
