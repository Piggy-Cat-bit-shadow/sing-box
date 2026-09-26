package naive

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
)

// BenchmarkNaiveH2BulkTransfer measures the real HTTP/2 tunnel bulk write path.
//
// Scope, and why this exists next to bench_test.go: the benchmarks there measure
// the padding codec with a caller-supplied buffer and a caller-supplied writer.
// That answers "how fast is framing" but not "how much of the tunnel's work is
// framing". This one drives the actual copy engine
// (bufio.CopyWithIncreateBuffer) into a real naiveH2Conn, so the measured cost is
// the whole write side of a Naive HTTP/2 tunnel: buffer allocation and growth,
// the padding frame codec, the write into the stream writer, and the flush that
// makes the data visible to the peer.
//
// The subject is the buffer-growth threshold on that copy engine. The engine
// starts with a 32 KiB buffer and switches to the connection's full
// WriterMTU + headroom size only after n >= IncreaseBufferAfter bytes have been
// copied; for every protocol but Naive that threshold is
// bufio.DefaultIncreaseBufferAfter (512000). Naive hands the engine a threshold of
// 1, so it grows after the first transfer. This benchmark is what shows the
// difference in engine behaviour rather than in options.
//
// The two subtests differ ONLY in that threshold, so a difference in their
// numbers is the threshold's effect and nothing else.
//
// What this deliberately does not model: the kernel, TLS, the network, the
// outbound leg, or HTTP/2 flow control against a real peer. It is a CPU and
// allocation measurement of this package's write path under the production copy
// engine. It is offline, deterministic, needs no root, and sleeps nowhere.

// benchH2PayloadSize is the payload moved per iteration.
//
// 8 MiB is chosen so the run is unambiguously in the steady-state bulk regime:
// it is 16x the 512000-byte default threshold, so the default-growth case has
// long since switched to its large buffer, and 128 maximum-size padded frames, so
// the frame codec is exercised many times over. A smaller payload would either
// not cross the default threshold at all (measuring only the cold 32 KiB path) or
// cross it so late that the run is dominated by the startup transient rather than
// by bulk throughput.
const benchH2PayloadSize = 8 << 20

// benchH2Writer is a minimal http.ResponseWriter standing in for an HTTP/2 stream.
//
// It implements exactly the two interfaces the tunnel path actually exercises:
//
//   - io.Writer, which is what naiveH2Conn writes frames into.
//   - FlushError() error, which http.ResponseController prefers when present.
//     Implementing this rather than a bare http.Flusher is deliberate: the tunnel
//     must be able to observe a flush failure, and routing the benchmark through
//     the same interface the production path uses keeps the measured call
//     identical to the shipped one.
//
// It counts flushes and bytes so a caller can assert the path was really driven
// end to end, and it discards data rather than accumulating it: buffering 8 MiB
// per iteration would make the benchmark measure heap growth instead of the
// tunnel, and would make its allocation figures meaningless.
type benchH2Writer struct {
	header http.Header

	bytes   int64
	flushes int64
	// flushErr, when set, makes every flush fail. Production always leaves it nil;
	// it exists so a test can prove the benchmark's writer is wired to the real
	// error propagation rather than to a no-op Flush.
	flushErr error
}

func newBenchH2Writer() *benchH2Writer {
	return &benchH2Writer{header: make(http.Header)}
}

func (w *benchH2Writer) Header() http.Header { return w.header }

func (w *benchH2Writer) Write(p []byte) (int, error) {
	w.bytes += int64(len(p))
	return len(p), nil
}

func (w *benchH2Writer) WriteHeader(int) {}

// FlushError is found through http.ResponseController, which is how naiveH2Conn
// flushes. Returning the recorded error is what makes a flush failure observable.
func (w *benchH2Writer) FlushError() error {
	w.flushes++
	return w.flushErr
}

// benchH2Conn builds a naiveH2Conn over the given writer, exactly as
// Inbound.ServeHTTP builds it for the HTTP/2 branch (see inbound.go): the reader
// is the request body, the writer is the response writer, and the flusher is a
// ResponseController over that writer.
func benchH2Conn(writer http.ResponseWriter, body io.Reader) *naiveH2Conn {
	return &naiveH2Conn{
		reader:        body,
		writer:        writer,
		flusher:       http.NewResponseController(writer),
		remoteAddress: nil,
		// Padding enabled: the production HTTP/2 path enables it when the client
		// sends the Padding header, which is the interesting case for framing cost.
		paddingConn: paddingConn{enabled: true},
	}
}

// benchH2Source is the copy source: an in-memory reader that advertises the
// destination's buffer geometry the way a real connection does.
//
// It must not implement io.WriterTo. If it did, the copy engine would take its
// own fast path and the tunnel write path under test would be bypassed entirely.
// ReadBuffer is provided so the engine reads straight into the pooled buffer it
// will hand to the destination, which is what the production path does; without
// it the engine falls back to reading into a temporary slice.
type benchH2Source struct {
	remaining int64
}

func (s *benchH2Source) Read(p []byte) (int, error) {
	if s.remaining <= 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), s.remaining)
	// Fill deterministically; content is irrelevant to the write path and this
	// keeps the benchmark reproducible.
	for i := range p[:n] {
		p[i] = 'x'
	}
	s.remaining -= n
	return int(n), nil
}

// ReadBuffer reads directly into the buffer the copy engine will pass on, which
// is the path the engine prefers when the source supports it.
func (s *benchH2Source) ReadBuffer(buffer *buf.Buffer) error {
	n, err := s.Read(buffer.FreeBytes())
	if n > 0 {
		buffer.Extend(n)
	}
	return err
}

// runBenchH2Transfer drives one full payload through the copy engine and returns
// what the destination observed.
//
// It asserts the transfer completed intact, so a benchmark that silently stopped
// early (for example because a flush error aborted the loop) fails loudly instead
// of reporting a flattering number for partial work.
func runBenchH2Transfer(b testing.TB, increaseBufferAfter int64) (int64, int64) {
	b.Helper()

	destination := newBenchH2Writer()
	tunnel := benchH2Conn(destination, http.NoBody)
	source := &benchH2Source{remaining: benchH2PayloadSize}

	written, err := bufio.CopyWithIncreateBuffer(tunnel, source, increaseBufferAfter, 8)
	if err != nil {
		b.Fatalf("bulk transfer failed: %v", err)
	}
	if written != benchH2PayloadSize {
		b.Fatalf("transfer moved %d bytes, want %d", written, benchH2PayloadSize)
	}
	// Every payload byte is framed, so the destination must have seen at least
	// the payload plus one 3-byte header per frame. Checking this proves the data
	// really travelled through the padding codec rather than around it.
	if destination.bytes < benchH2PayloadSize {
		b.Fatalf("destination saw %d bytes, less than the %d-byte payload; the "+
			"transfer did not go through the framing path",
			destination.bytes, benchH2PayloadSize)
	}
	return destination.bytes, destination.flushes
}

// BenchmarkNaiveH2BulkTransfer is the comparison: the same payload, the same
// destination, differing only in when the copy engine grows its buffer.
func BenchmarkNaiveH2BulkTransfer(b *testing.B) {
	for _, testCase := range []struct {
		name    string
		after   int64
		comment string
	}{
		{
			name:    "default-growth",
			after:   bufio.DefaultIncreaseBufferAfter,
			comment: "the shared threshold: 512000 bytes before the buffer grows",
		},
		{
			name:    "early-growth",
			after:   1,
			comment: "the Naive threshold: grow after the first transfer",
		},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			// Report the state that was actually measured, so the two subtests
			// can never be confused for each other when someone reads the output.
			b.Logf("%s: increaseBufferAfter=%d (%s)", testCase.name, testCase.after, testCase.comment)
			b.ReportAllocs()
			b.SetBytes(benchH2PayloadSize)
			// Warm the first iteration into the timer deliberately: the point of
			// the Naive threshold is that the early transfer is cheap, so excluding
			// it would hide the very effect under measurement.
			b.ResetTimer()
			for range b.N {
				runBenchH2Transfer(b, testCase.after)
			}
		})
	}
}

// BenchmarkNaiveH2BulkTransferBuffers isolates the buffer geometry each threshold
// settles into, without the frame codec in the way.
//
// This is the mechanism behind the comparison above. With the Naive threshold the
// engine reaches the connection's full WriterMTU payload buffer immediately; with
// the shared threshold it spends the first 512000 bytes in the 32 KiB default
// buffer and only then grows. Reporting the handover count and the largest
// handover size makes that difference a number rather than an inference.
func BenchmarkNaiveH2BulkTransferBuffers(b *testing.B) {
	for _, testCase := range []struct {
		name  string
		after int64
	}{
		{"default-growth", bufio.DefaultIncreaseBufferAfter},
		{"early-growth", 1},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(benchH2PayloadSize)
			b.ResetTimer()
			for range b.N {
				counts := measureH2Handovers(b, testCase.after)
				if counts.frames == 0 {
					b.Fatal("no frames were handed over")
				}
			}
			b.StopTimer()
			// Record the geometry once, outside the timed region: it is a
			// property of the threshold, not of the iteration count.
			counts := measureH2Handovers(b, testCase.after)
			b.ReportMetric(float64(counts.frames), "handovers")
			b.ReportMetric(float64(counts.largest), "largest-handover-B")
			b.ReportMetric(float64(counts.smallFrames), "small-handovers")
		})
	}
}

// handoverStats summarises what the copy engine handed to the destination.
type handoverStats struct {
	frames int
	// largest is the biggest single handover in bytes.
	largest int
	// smallFrames counts handovers at or below the 32 KiB default buffer, i.e.
	// transfers that happened before the engine grew.
	smallFrames int
}

// measureH2Handovers runs one transfer and records the size of every handover.
func measureH2Handovers(b testing.TB, increaseBufferAfter int64) handoverStats {
	b.Helper()

	recorder := &handoverRecorder{header: make(http.Header)}
	tunnel := benchH2Conn(recorder, http.NoBody)
	source := &benchH2Source{remaining: benchH2PayloadSize}

	written, err := bufio.CopyWithIncreateBuffer(tunnel, source, increaseBufferAfter, 8)
	if err != nil {
		b.Fatalf("bulk transfer failed: %v", err)
	}
	if written != benchH2PayloadSize {
		b.Fatalf("transfer moved %d bytes, want %d", written, benchH2PayloadSize)
	}
	return recorder.stats
}

// handoverRecorder records the size of each write the copy engine makes.
//
// Sizes are measured on the RAW write, before the padding codec adds its header
// and padding, so the numbers are the engine's buffer sizes rather than the wire
// sizes.
type handoverRecorder struct {
	header http.Header
	stats  handoverStats
}

func (w *handoverRecorder) Header() http.Header { return w.header }

func (w *handoverRecorder) Write(p []byte) (int, error) {
	size := len(p)
	w.stats.frames++
	if size > w.stats.largest {
		w.stats.largest = size
	}
	if size <= 32<<10 {
		w.stats.smallFrames++
	}
	return size, nil
}

func (w *handoverRecorder) WriteHeader(int) {}

func (w *handoverRecorder) FlushError() error { return nil }

// TestBenchH2WriterDrivesTheRealFlushPath proves the benchmark's stand-in writer
// is wired to the production flush contract rather than to a no-op.
//
// A benchmark whose Flush silently does nothing would measure a tunnel that never
// flushes, which is not the shipped behaviour: naiveH2Conn.WriteBuffer flushes
// after every frame and turns a flush failure into a write error. This checks that
// a flush failure really does fail the write through this writer, which is what
// makes the benchmark's numbers attributable to the shipped path.
func TestBenchH2WriterDrivesTheRealFlushPath(t *testing.T) {
	writer := newBenchH2Writer()
	writer.flushErr = errFlushFailed
	tunnel := benchH2Conn(writer, http.NoBody)

	_, err := tunnel.Write([]byte("payload"))
	if err == nil {
		t.Fatal("a flush failure must surface as a write error, so the benchmark " +
			"writer is connected to the real flush path")
	}
	if writer.flushes == 0 {
		t.Fatal("the write must have attempted a flush")
	}

	// And the healthy case must succeed, so the benchmark is not measuring an
	// error path.
	healthy := newBenchH2Writer()
	healthyTunnel := benchH2Conn(healthy, http.NoBody)
	if _, err = healthyTunnel.Write([]byte("payload")); err != nil {
		t.Fatalf("a healthy flush must not fail the write: %v", err)
	}
	if healthy.flushes != 1 {
		t.Fatalf("expected exactly one flush per write, got %d", healthy.flushes)
	}
}

// TestBenchH2SourceReachesTheLargeBuffer pins the mechanism the benchmark compares.
//
// It is the executable statement of the claim: with the Naive threshold the copy
// engine reaches a large handover immediately, and with the shared default it
// spends the opening 512000 bytes in small ones. Without this, a change that
// accidentally made both subtests identical would leave the benchmark comparing
// nothing while still producing numbers.
func TestBenchH2SourceReachesTheLargeBuffer(t *testing.T) {
	early := measureH2Handovers(t, 1)
	def := measureH2Handovers(t, bufio.DefaultIncreaseBufferAfter)

	// The first handover is small in both cases: the engine decides to grow only
	// AFTER a transfer completes, so the threshold can never affect frame one.
	if early.largest < 32<<10 {
		t.Fatalf("expected the early-growth largest handover to be a full buffer, got %d",
			early.largest)
	}
	if def.largest < 32<<10 {
		t.Fatalf("expected the default-growth largest handover to be a full buffer, got %d",
			def.largest)
	}

	// The difference is how much work happens in the small buffer first.
	if early.smallFrames >= def.smallFrames {
		t.Fatalf("early growth must spend fewer handovers in the small buffer: "+
			"early=%d default=%d", early.smallFrames, def.smallFrames)
	}
	t.Logf("small handovers: early-growth=%d default-growth=%d (largest %d bytes each)",
		early.smallFrames, def.smallFrames, early.largest)

	// Both must finish the payload: this is a difference in efficiency, not in
	// correctness.
	if early.frames == 0 || def.frames == 0 {
		t.Fatal("both thresholds must complete the transfer")
	}
}

// TestBenchH2RecorderSeesFramedWrites proves the benchmark destination observes
// framed data, not the raw payload.
//
// Without this, a future refactor could route the benchmark around the padding
// codec (for example by calling the underlying writer directly) and the benchmark
// would keep reporting plausible numbers while measuring a path that does not
// exist in production.
func TestBenchH2RecorderSeesFramedWrites(t *testing.T) {
	// One payload that fits inside a single maximum-size frame, so exactly one
	// handover is expected. The frame budget is maxFrameSize (65536) minus the
	// 3-byte header and up to 255 bytes of padding, so the payload must stay at or
	// below WriterMTU (65278). A larger write is legitimately split across several
	// frames by the codec, which would make the one-handover assertion below fail
	// for a reason unrelated to what is being checked here.
	geometry := benchH2Conn(newBenchH2Writer(), http.NoBody)
	payloadSize := geometry.WriterMTU()
	if payloadSize <= 0 {
		t.Fatalf("the connection must advertise a positive frame payload size, got %d", payloadSize)
	}

	recorder := &handoverRecorder{header: make(http.Header)}
	tunnel := benchH2Conn(recorder, http.NoBody)

	// Drive a payload through the tunnel's own write path.
	payload := make([]byte, payloadSize)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("framed write failed: %v", err)
	}

	if recorder.stats.frames != 1 {
		t.Fatalf("a %d-byte write must produce exactly one frame, got %d",
			payloadSize, recorder.stats.frames)
	}
	// A padded frame is strictly larger than its payload: 2 bytes of length,
	// 1 byte of padding length, plus 0..255 padding bytes.
	if recorder.stats.largest <= payloadSize {
		t.Fatalf("the framed write (%d bytes) must exceed the payload (%d bytes), "+
			"otherwise the padding codec was bypassed",
			recorder.stats.largest, payloadSize)
	}
	if overhead := recorder.stats.largest - payloadSize; overhead < 3 || overhead > 3+255 {
		t.Fatalf("frame overhead must be 3..258 bytes, got %d", overhead)
	}
}

// BenchmarkNaiveH2BulkTransferSizes reports the per-handover cost at each buffer
// size the engine uses, so the growth threshold's benefit has a concrete basis.
//
// The engine moves between two regimes: a 32 KiB default buffer and the
// connection's full WriterMTU payload buffer (65278 bytes for a padded Naive
// connection). This measures the per-byte cost in each, which is the input to
// "how much is spent before the buffer grows".
func BenchmarkNaiveH2BulkTransferSizes(b *testing.B) {
	for _, size := range []int{
		32 << 10,                   // the engine's default buffer
		writerMTUPayloadForBench(), // the grown buffer
	} {
		b.Run(fmt.Sprintf("handover-%dB", size), func(b *testing.B) {
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				// Build the buffer the way the copy engine does: sized for the
				// payload plus the connection's front and rear headroom, with the
				// headroom applied before writing. The headroom is read from a real
				// padded connection rather than hard-coded, so it stays correct if
				// the frame geometry ever moves.
				//
				// Order matters and mirrors ReadWaitOptions.NewBuffer:
				// Resize(front, 0) sets b.end = b.start + 0, so the whole payload
				// area is ahead of end and FreeLen() is the full size. Reserve(rear)
				// then removes the rear headroom from CAPACITY, which is what stops
				// a later write from claiming it. Reserving first and writing after
				// would consume the rear headroom as payload and leave the buffer
				// with none, which is exactly the "free=0" failure this build
				// guards against.
				geometry := benchH2Conn(newBenchH2Writer(), http.NoBody)
				front, rear := geometry.FrontHeadroom(), geometry.RearHeadroom()
				buffer := buf.NewSize(size + front + rear)
				buffer.Resize(front, 0)
				if buffer.FreeLen() < size {
					b.Fatalf("buffer is too small for the payload: free=%d need=%d",
						buffer.FreeLen(), size)
				}
				buffer.Reserve(rear)
				buffer.Write(payload)
				if buffer.Start() != front || buffer.Len() != size {
					b.Fatalf("buffer geometry is wrong: start=%d len=%d, want start=%d len=%d",
						buffer.Start(), buffer.Len(), front, size)
				}
				// Reserve takes the rear headroom out of capacity, so it is
				// verified through Cap(), not FreeLen(): after the payload is
				// written FreeLen() is legitimately 0, and the reserved bytes are
				// exactly the ones Cap() no longer counts. The payload plus the
				// reserved rear headroom must still fit the allocation.
				if long := buffer.Cap() + rear; long < size {
					b.Fatalf("buffer kept %d bytes of capacity plus %d reserved, less than the %d-byte payload",
						buffer.Cap(), rear, size)
				}
				if buffer.RawCap() != size+front+rear {
					b.Fatalf("buffer must be allocated for payload plus headroom: raw=%d want=%d",
						buffer.RawCap(), size+front+rear)
				}
				destination := newBenchH2Writer()
				tunnel := benchH2Conn(destination, http.NoBody)
				// Post-window: padding has already been sent, so this is the raw
				// bulk path. Setting writePadding to paddingCount takes it past the
				// window without touching the wire format.
				tunnel.paddingConn.writePadding = paddingCount
				b.StartTimer()
				if err := tunnel.WriteBuffer(buffer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// writerMTUPayloadForBench is the payload size of a fully padded Naive frame,
// derived from the constants rather than hard-coded: maxFrameSize minus the
// 3-byte header and the 255-byte maximum padding. Kept as a function so the
// derivation is visible and stays correct if the constants ever move.
func writerMTUPayloadForBench() int {
	connection := &paddingConn{enabled: true}
	return connection.writerMTU()
}
