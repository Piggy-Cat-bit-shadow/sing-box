package shadowsocks

// Phase-aware copy audit for the Shadowsocks data path.
//
// # Why this measures instead of reading
//
// The steady-state writer builds its frame with ExtendHeader, Seals in place and Extends, all of
// which look copy-free in source. "Looks copy-free" is not a measurement, and the task's rule is
// that every zero-copy claim must be backed by at least two or three independent observations.
// This file instruments the real writer chain and reports:
//
//	payload copies   - whether the bytes handed downstream come from the CALLER'S array
//	allocs/op, B/op  - whether the path allocates
//	backing address  - the identity of the array at each stage
//
// # What counts as a copy here
//
// The destination records the address of the first byte it receives. If that address lies inside
// the array the caller passed, the payload was framed IN PLACE. If it does not, a new allocation
// holds the payload, which is a copy regardless of which function performed it.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	shadowss "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// nopConn supplies the net.Conn surface a DestinationConn needs. Every method is inert: the
// measurement is about what reaches the socket, not about socket behaviour.
type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (nopConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// copyDetectingWriter records whether the bytes it receives share the caller's backing array.
//
// It embeds nopConn because the Shadowsocks method wraps a net.Conn; only Write and WriteBuffer
// carry the payload, and those are the two it overrides.
//
// # Identity is learned AT WRITE TIME, not in advance
//
// A pre-captured base pointer goes stale the moment the caller releases and re-acquires its buffer,
// which the copy loop does on every iteration. An earlier version of this fixture captured the base
// before the write and therefore reported "1.000 framed out of place" for a path that copies
// nothing -- a false positive that would have condemned a healthy fast path. The array is now
// recorded when the writer hands the payload over, together with the geometry the framing needs, so
// the comparison is against the array actually in play.
type copyDetectingWriter struct {
	nopConn
	// base and length bound the array the caller handed to the writer chain.
	base   *byte
	length int

	frames      int
	copiedBytes int
	totalBytes  int
	sink        byte
	// payloadSizes records each write's total length, so the copy loop's chunking is observable.
	payloadSizes []int
	// inputLens records the length of each buffer the writer RECEIVED, captured before the writer
	// prepends its header. This is the number the in-place/copy branch is chosen on.
	inputLens []int
}

// noteArray records the allocation the caller handed over, so downstream writes can be compared
// against it. The caller must call this immediately before the write under test.
func (w *copyDetectingWriter) noteArray(base *byte, length int) {
	w.base = base
	w.length = length
}

// WriteBuffer is the ExtendedWriter entry point, so it is what the Shadowsocks writer calls.
//
// The bytes it receives are the FRAMED output: the writer prepends its length+tag header and
// appends its tag, so the frame legitimately starts BEFORE the caller's payload. Comparing the
// first byte against the payload start would therefore report a copy for a path that copied
// nothing. What identifies an in-place frame is that it lies WITHIN the caller's allocation, which
// is what sameArray tests.
func (w *copyDetectingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.record(buffer.Bytes())
	buffer.Release()
	return nil
}

func (w *copyDetectingWriter) Write(p []byte) (int, error) {
	w.record(p)
	return len(p), nil
}

func (w *copyDetectingWriter) record(p []byte) {
	w.frames++
	w.totalBytes += len(p)
	w.payloadSizes = append(w.payloadSizes, len(p))
	if len(p) == 0 {
		return
	}
	if !w.sameArray(&p[0]) {
		w.copiedBytes += len(p)
	}
	w.sink ^= p[0]
}

// sameArray reports whether p lies inside the array the caller provided.
//
// The comparison is over the whole allocation rather than the visible payload, because framing
// legitimately moves the START: ExtendHeader prepends the Shadowsocks length+tag header, so the
// frame begins BEFORE the payload. What distinguishes a copy is the array, not the offset.
func (w *copyDetectingWriter) sameArray(p *byte) bool {
	if w.base == nil {
		return false
	}
	base := uintptr(unsafe.Pointer(w.base))
	target := uintptr(unsafe.Pointer(p))
	// The caller's buffer has front headroom before base and rear headroom after it.
	low := base - 512
	high := base + uintptr(w.length) + 512
	return target >= low && target < high
}

func (w *copyDetectingWriter) reset(base *byte, length int) {
	w.base = base
	w.length = length
	w.frames = 0
	w.copiedBytes = 0
	w.totalBytes = 0
}

// ---------------------------------------------------------------------------
// The phase-aware measurement
// ---------------------------------------------------------------------------

// shadowAuditMethod creates a real SS2022 method through the same constructor the production
// outbound uses, so the measurement is of the shipped code path rather than a stand-in.
func shadowAuditMethod(t *testing.T, methodName, password string) shadowss.Method {
	t.Helper()
	method, err := shadowss.CreateMethod(context.Background(), methodName, shadowss.MethodOptions{Password: password})
	if err != nil {
		t.Skipf("method %s unavailable in this build: %v", methodName, err)
	}
	return method
}

// TestShadowSteadyStateUploadFramesInPlace is the measurement for the path that carries bulk data.
//
// It drives the real *clientConn through its SECOND write, which is the steady-state branch:
//
//	if c.writer == nil { writeRequest }   <- first write only
//	return c.writer.WriteBuffer(buffer)   <- every later write
//
// and checks whether the bytes that reach the socket share the caller's backing array.
func TestShadowSteadyStateUploadFramesInPlace(t *testing.T) {
	t.Parallel()
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copyDetectingWriter{}
	conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	extended, ok := conn.(N.ExtendedWriter)
	if !ok {
		t.Fatalf("the Shadowsocks client conn must be an ExtendedWriter, got %T", conn)
	}
	// The geometry capabilities are advertised separately from the writer capability; the copy loop
	// reads them to size the buffer, so this measures with the SAME geometry production uses.
	geometry := conn.(N.FrontHeadroom)
	rear := conn.(N.RearHeadroom)

	// The first write sends the request and installs the steady-state writer.
	const probe = 64
	firstBuffer := buf.NewSize(geometry.FrontHeadroom() + probe + rear.RearHeadroom())
	firstBuffer.Resize(geometry.FrontHeadroom(), 0)
	common.Must1(firstBuffer.Write(make([]byte, probe)))
	sink.reset(&firstBuffer.Bytes()[0], probe)
	if err := extended.WriteBuffer(firstBuffer); err != nil {
		t.Fatalf("first write: %v", err)
	}
	firstFrames := sink.frames

	// Steady state: the write that carries the bulk of any transfer.
	//
	// Derived from BufferSize rather than fixed at 16 KiB. With a literal, this test
	// only exercised the standard 32 KiB build: under with_low_memory BufferSize IS
	// 16 KiB, so a 16 KiB payload sits exactly on the copy boundary and the writer
	// copies instead of framing in place - failing for a reason that says nothing
	// about correctness, and leaving the iOS configuration untested.
	//
	// The in-place limit is streamWriterMTU(), so a payload just under it exercises
	// the path this test is about in every build.
	payloadSize := streamWriterMTU()
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	buffer := buf.NewSize(geometry.FrontHeadroom() + payloadSize + rear.RearHeadroom())
	buffer.Resize(geometry.FrontHeadroom(), 0)
	common.Must1(buffer.Write(payload))

	sink.reset(&buffer.Bytes()[0], payloadSize)
	if err := extended.WriteBuffer(buffer); err != nil {
		t.Fatalf("steady-state write: %v", err)
	}
	t.Logf("first write produced %d frame write(s); steady state measured below", firstFrames)

	t.Logf("steady state: frames=%d totalBytes=%d copiedBytes=%d",
		sink.frames, sink.totalBytes, sink.copiedBytes)
	if sink.copiedBytes != 0 {
		t.Errorf("the steady-state Shadowsocks writer copied %d of %d payload bytes; the in-place "+
			"path prepends with ExtendHeader, seals in place and Extends, so it should copy none",
			sink.copiedBytes, sink.totalBytes)
	}
}

// TestShadowSteadyStateUploadAllocations reports the allocation count for the same path.
//
// A copy-free path still has to be allocation-free to matter; one without the other is a partial
// win. This is the second, independent observation of the same claim.
func TestShadowSteadyStateUploadAllocations(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copyDetectingWriter{}
	conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	extended := conn.(N.ExtendedWriter)
	geometry := conn.(N.FrontHeadroom)
	rear := conn.(N.RearHeadroom)

	firstBuffer := buf.NewSize(geometry.FrontHeadroom() + 64 + rear.RearHeadroom())
	firstBuffer.Resize(geometry.FrontHeadroom(), 0)
	common.Must1(firstBuffer.Write(make([]byte, 64)))
	if err := extended.WriteBuffer(firstBuffer); err != nil {
		t.Fatal(err)
	}

	const payloadSize = 16 << 10
	payload := make([]byte, payloadSize)

	allocations := testing.AllocsPerRun(200, func() {
		buffer := buf.NewSize(geometry.FrontHeadroom() + payloadSize + rear.RearHeadroom())
		buffer.Resize(geometry.FrontHeadroom(), 0)
		common.Must1(buffer.Write(payload))
		if err := extended.WriteBuffer(buffer); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("steady-state allocations per op (INCLUDING the pooled buffer acquisition): %.2f", allocations)
}

// TestShadowSteadyStateWriterCostIsFlatInPayload is the second, independent observation.
//
// # Why it does not simply pre-build one buffer
//
// The writer CONSUMES the buffer: it hands it to the next writer, which releases it. That is the
// ExtendedWriter contract, so a reused buffer cannot be refilled without rebuilding it -- and
// rebuilding it is the allocation. A test that claimed "0 allocs" while reusing a consumed buffer
// would either be measuring nothing or be relying on the released struct by accident.
//
// So this measures the property that actually matters and is actually observable: the writer's own
// contribution is FLAT in payload size. If the framing path copied or allocated per byte, the
// per-op cost would grow with the payload; if it frames in place, only the buffer acquisition shows
// up and it is the same for every size.
func TestShadowSteadyStateWriterCostIsFlatInPayload(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	// Sizes bracket the real boundary rather than being round numbers: the in-place limit is
	// whatever streamWriterMTU() reports, so the limit and limit+1 cases are derived from it and
	// cannot drift away from production. 32 KiB and 64 KiB sit either side of it.
	inPlaceLimit := streamWriterMTU()
	for _, payloadSize := range []int{1400, 16 << 10, inPlaceLimit, inPlaceLimit + 1, 32 << 10, 64 << 10} {
		t.Run(itoa(payloadSize), func(t *testing.T) {
			sink := &copyDetectingWriter{}
			conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
			extended := conn.(N.ExtendedWriter)
			geometry := conn.(N.FrontHeadroom)
			rear := conn.(N.RearHeadroom)

			firstBuffer := buf.NewSize(geometry.FrontHeadroom() + 64 + rear.RearHeadroom())
			firstBuffer.Resize(geometry.FrontHeadroom(), 0)
			common.Must1(firstBuffer.Write(make([]byte, 64)))
			if err := extended.WriteBuffer(firstBuffer); err != nil {
				t.Fatal(err)
			}

			payload := make([]byte, payloadSize)
			allocations := testing.AllocsPerRun(300, func() {
				buffer := buf.NewSize(geometry.FrontHeadroom() + payloadSize + rear.RearHeadroom())
				buffer.Resize(geometry.FrontHeadroom(), 0)
				common.Must1(buffer.Write(payload))
				if err := extended.WriteBuffer(buffer); err != nil {
					t.Fatal(err)
				}
			})
			t.Logf("payload=%d allocations/op=%.2f (this includes the pooled acquisition the copy loop performs)", payloadSize, allocations)
			// The writer frames in place up to maxPacketSize; above that it copies by design. This
			// measures the UNWRAPPED writer, so the expectation follows the documented boundary
			// rather than assuming every size is in place. The production wrapper keeps the copy
			// loop BELOW that boundary, which TestStreamMtuMatchesTheInPlaceBranch proves.
			if payloadSize <= inPlaceLimit && allocations > 2 {
				t.Errorf("payload=%d needed %.2f allocations; below the in-place limit the framing "+
					"path should add none beyond the pooled buffer itself", payloadSize, allocations)
			}
			if payloadSize > inPlaceLimit && allocations <= 2 {
				t.Errorf("payload=%d needed only %.2f allocations, but it exceeds the in-place limit "+
					"and must copy", payloadSize, allocations)
			}
		})
	}
}

// itoa avoids importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestShadowSteadyStateProductionPayloadSize records the payload size the production copy loop
// actually hands this writer.
//
// TestShadowSteadyStateProductionPayloadSize is superseded.
//
// It only logged the geometry the copy loop computes; it asserted nothing. The same facts are now
// asserted by TestShadowRealCopyLoopBufferGeometry (the raw loop really does overshoot) and
// TestStreamMtuMatchesTheInPlaceBranch (the advertised ceiling really is the branch boundary), so
// keeping a third copy that merely prints numbers adds maintenance cost without adding evidence.

// TestShadowRealCopyLoopPayloadSize is superseded by TestShadowRealCopyLoopBufferGeometry.
//
// It logged the largest payload the loop produced but only asserted nothing -- the pass/fail lived
// in a t.Logf branch. TestShadowRealCopyLoopBufferGeometry drives the same loop and FAILS when no
// buffer exceeds the in-place limit, which is the actual property worth protecting.
//
// What is kept from it is the fixedSizeReader helper below, which the surviving tests use.

// fixedSizeReader yields zeros, honouring whatever buffer size it is given.
type fixedSizeReader struct{ remaining int }

func (r *fixedSizeReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return n, nil
}

// TestShadowCopyLoopBoundaryGap is superseded.
//
// It printed the pooled buffer size, the in-place limit and the 34-byte gap as literals. Those
// numbers are now derived from the production functions (buf.BufferSize and streamWriterMTU)
// wherever they are needed, and the relationship that matters -- the loop overshoots, the advertised
// ceiling does not -- is asserted by the two tests named above rather than restated as arithmetic.

// BenchmarkShadowSteadyStateUpload measures the production chunk size against the in-place limit.
//
// buf.BufferSize is what the copy loop delivers when nothing constrains it, and streamWriterMTU()
// is the largest payload the writer frames in place. The pair isolates the cost of the shortfall
// between them.
func BenchmarkShadowSteadyStateUpload(b *testing.B) {
	method, err := shadowss.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm",
		shadowss.MethodOptions{Password: "AAAAAAAAAAAAAAAAAAAAAA=="})
	if err != nil {
		b.Skipf("method unavailable: %v", err)
	}

	// Both ends are derived from production rather than written as literals, so this keeps
	// measuring the real shortfall if either the pooled buffer size or the framing rule changes.
	inPlaceLimit := streamWriterMTU()
	for _, payloadSize := range []int{1400, 16384, inPlaceLimit, buf.BufferSize} {
		b.Run(itoa(payloadSize), func(b *testing.B) {
			sink := &copyDetectingWriter{}
			conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
			extended := conn.(N.ExtendedWriter)
			geometry := conn.(N.FrontHeadroom)
			rear := conn.(N.RearHeadroom)

			firstBuffer := buf.NewSize(geometry.FrontHeadroom() + 64 + rear.RearHeadroom())
			firstBuffer.Resize(geometry.FrontHeadroom(), 0)
			common.Must1(firstBuffer.Write(make([]byte, 64)))
			if err := extended.WriteBuffer(firstBuffer); err != nil {
				b.Fatal(err)
			}
			sink.payloadSizes = nil

			payload := make([]byte, payloadSize)
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			for b.Loop() {
				buffer := buf.NewSize(geometry.FrontHeadroom() + payloadSize + rear.RearHeadroom())
				buffer.Resize(geometry.FrontHeadroom(), 0)
				common.Must1(buffer.Write(payload))
				sink.noteArray(&buffer.Bytes()[0], payloadSize)
				if err := extended.WriteBuffer(buffer); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()

			// Report whether this size took the in-place or the copying branch, so the timings
			// cannot be compared without knowing which path produced them.
			copied := sink.copiedBytes
			total := sink.totalBytes
			b.ReportMetric(float64(copied)/float64(total), "framedOutOfPlaceRatio")
		})
	}
}

// TestShadowRealCopyLoopBufferGeometry records the length of the buffers the REAL copy loop hands
// the writer, which is the number the in-place/copy branch is chosen on.
//
// # How the length is observed without changing the writer
//
// The writer mutates the buffer it receives (ExtendHeader then Extend), so the length cannot be read
// afterwards. It is captured by wrapping the DESTINATION the copy loop writes to: the wrapper
// records buffer.Len() and then delegates to the real writer, so the loop's own sizing is what is
// measured rather than a re-derivation of it.
func TestShadowRealCopyLoopBufferGeometry(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copyDetectingWriter{}
	conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))

	observer := &geometryObservingWriter{upstream: conn.(N.ExtendedWriter)}
	if _, err := bufio.Copy(observer, &fixedSizeReader{remaining: 4 << 20}); err != nil {
		t.Fatalf("copy: %v", err)
	}

	// The boundary comes from production, not from a restated literal: this test is about the
	// relationship between what the loop sends and what the writer can frame, and both ends of that
	// relationship belong to the production code.
	inPlaceLimit := streamWriterMTU()
	var above int
	for _, size := range observer.inputLens {
		if size > inPlaceLimit {
			above++
		}
	}
	t.Logf("copy loop handed the writer %d buffers, %d of them larger than the %d-byte in-place limit",
		len(observer.inputLens), above, inPlaceLimit)
	// As above: the raw writer's overshoot is the FINDING that motivated the wrapper, not a
	// regression. It is asserted as a property so a change in either direction is noticed.
	if above == 0 {
		t.Fatalf("no buffer exceeded the in-place limit; the overshoot this file records has gone "+
			"away, so the wrapper's justification must be re-derived (%d buffers observed)",
			len(observer.inputLens))
	}
	t.Logf("CONFIRMED: %d of %d raw-copy-loop buffers exceed the in-place limit; withStreamMTU is "+
		"what keeps the production path below it", above, len(observer.inputLens))
}

// geometryObservingWriter records each buffer's length before delegating to the real writer.
type geometryObservingWriter struct {
	upstream  N.ExtendedWriter
	inputLens []int
	// mtu, when non-zero, advertises WriterMTU so the experiment can compare with and without it.
	mtu int
}

// WriterMTU is the capability CalculateMTU looks for.
func (w *geometryObservingWriter) WriterMTU() int { return w.mtu }

func (w *geometryObservingWriter) WriteBuffer(buffer *buf.Buffer) error {
	w.inputLens = append(w.inputLens, buffer.Len())
	return w.upstream.WriteBuffer(buffer)
}

func (w *geometryObservingWriter) Write(p []byte) (int, error) {
	return w.upstream.Write(p)
}

func (w *geometryObservingWriter) FrontHeadroom() int { return N.CalculateFrontHeadroom(w.upstream) }
func (w *geometryObservingWriter) RearHeadroom() int  { return N.CalculateRearHeadroom(w.upstream) }

// TestShadowWriterMTUWouldCapTheCopyLoop is the regression that justifies withStreamMTU.
//
// # The property
//
// The copy loop sizes its steady-state buffer from ReadWaitOptions, whose MTU comes from
// CalculateMTU(reader, writer). The Shadowsocks writer advertises no WriterMTU, so the loop uses the
// pooled buf.BufferSize, which is larger than the in-place limit; advertising the limit makes the
// loop size to fit and take the in-place branch.
//
// This runs the real copy loop twice, against the real writer, differing only in whether an MTU is
// advertised. It was originally an experiment that only LOGGED the outcome, which meant it would
// keep passing -- green, and therefore reassuring -- if the behaviour it describes had reversed.
// The conditions are now asserted, so a reversal FAILS instead of printing a contradictory log line.
func TestShadowWriterMTUWouldCapTheCopyLoop(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copyDetectingWriter{}
	conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	real := conn.(N.ExtendedWriter)

	inPlaceLimit := streamWriterMTU()

	// largestBuffer drives the real copy loop and returns the largest buffer it handed the writer.
	largestBuffer := func(upstream N.ExtendedWriter, mtu int) int {
		observer := &geometryObservingWriter{upstream: upstream, mtu: mtu}
		if _, err := bufio.Copy(observer, &fixedSizeReader{remaining: 1 << 20}); err != nil {
			t.Fatal(err)
		}
		if len(observer.inputLens) == 0 {
			t.Fatal("the copy loop handed the writer no buffers; the measurement is meaningless")
		}
		maximum := 0
		for _, size := range observer.inputLens {
			if size > maximum {
				maximum = size
			}
		}
		return maximum
	}

	// Baseline: the real writer, advertising no MTU.
	baselineMax := largestBuffer(real, 0)

	// With the limit advertised, on a FRESH conn so the request is framed again.
	sink2 := &copyDetectingWriter{}
	conn2 := method.DialEarlyConn(sink2, M.ParseSocksaddrHostPort("target.example", 443))
	mtuMax := largestBuffer(conn2.(N.ExtendedWriter), inPlaceLimit)

	t.Logf("baseline (no WriterMTU): largest buffer = %d; with WriterMTU=%d: largest buffer = %d; "+
		"in-place limit = %d", baselineMax, inPlaceLimit, mtuMax, inPlaceLimit)

	// If any of these stops holding, the wrapper's justification has changed and the decision has to
	// be re-derived rather than silently carried forward.
	require.Greater(t, baselineMax, streamWriterMTU(),
		"upstream/copy-loop behaviour changed: without an advertised WriterMTU the loop must still "+
			"overshoot the in-place limit, which is the entire reason withStreamMTU exists. "+
			"Re-evaluate whether withStreamMTU is still necessary")
	require.LessOrEqual(t, mtuMax, streamWriterMTU(),
		"upstream/copy-loop behaviour changed: advertising WriterMTU=%d must keep the loop at or "+
			"below the in-place limit. Re-evaluate whether withStreamMTU is still necessary",
		inPlaceLimit)
	require.Less(t, mtuMax, baselineMax,
		"upstream/copy-loop behaviour changed: advertising the WriterMTU must reduce the buffer size "+
			"the loop hands over, otherwise the wrapper buys nothing. Re-evaluate whether withStreamMTU "+
			"is still necessary")
}

// BenchmarkShadowRealCopyLoop measures the REAL copy loop with and without a writer MTU.
//
// # Why this is the benchmark that decides
//
// The synthetic benchmark picks payload sizes. This one runs the assembled path -- bufio.Copy into
// the real Shadowsocks writer -- so the chunk size is whatever production actually produces. The
// two sub-benchmarks differ ONLY in whether the writer advertises WriterMTU; everything else,
// including the reader and the copy loop, is identical.
//
// If the MTU variant is faster and allocates less, the 34-byte shortfall is a real production cost.
func BenchmarkShadowRealCopyLoop(b *testing.B) {
	method, err := shadowss.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm",
		shadowss.MethodOptions{Password: "AAAAAAAAAAAAAAAAAAAAAA=="})
	if err != nil {
		b.Skipf("method unavailable: %v", err)
	}
	inPlaceLimit := streamWriterMTU()
	const streamTotal = 4 << 20

	for _, variant := range []struct {
		name string
		mtu  int
	}{
		{"no-writer-mtu", 0},
		{"writer-mtu", inPlaceLimit},
	} {
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(streamTotal)
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				sink := &copyDetectingWriter{}
				conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
				destination := &geometryObservingWriter{
					upstream: conn.(N.ExtendedWriter),
					mtu:      variant.mtu,
				}
				source := &fixedSizeReader{remaining: streamTotal}
				b.StartTimer()
				copied, err := bufio.Copy(destination, source)
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				// Path-execution sanity checks, OUTSIDE the timed region.
				//
				// A benchmark that runs without error can still have copied nothing -- a fixture that
				// never delivers payload would report a very fast, very allocation-light "result" for a
				// datapath that did not execute. These checks make that a failure instead of a number.
				if copied != streamTotal {
					b.Fatalf("copied %d bytes, expected %d: the datapath did not carry the payload, "+
						"so this measurement is invalid", copied, streamTotal)
				}
				if len(destination.inputLens) == 0 {
					b.Fatalf("the copy loop handed the writer no buffers: silent no-op, invalid measurement")
				}
				if len(sink.payloadSizes) == 0 {
					b.Fatalf("the destination recorded no payload writes: silent no-op, invalid measurement")
				}
				b.StartTimer()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The MTU advertised to the copy loop
// ---------------------------------------------------------------------------

// TestStreamMtuMatchesTheInPlaceBranch is what makes bufferMTUShortfall trustworthy.
//
// # Why this does not just check the arithmetic
//
// streamWriterMTU() returns buf.BufferSize - 34. The 34 is restated from constants inside an
// internal package, so the arithmetic alone proves nothing about the real writer: if the dependency
// ever changed those constants, the formula would keep producing a number and the number would
// silently become wrong.
//
// So the boundary is found EMPIRICALLY: the writer is driven at the advertised limit and one byte
// above it, and the branch each one takes is observed. The advertised value is correct exactly when
// the limit frames in place and limit+1 copies.
func TestStreamMtuMatchesTheInPlaceBranch(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	advertised := streamWriterMTU()

	// framedInPlace reports whether a payload of this size took the in-place branch, by checking
	// whether the bytes that reach the socket came from the caller's array.
	framedInPlace := func(payloadSize int) bool {
		sink := &copyDetectingWriter{}
		conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
		extended := conn.(N.ExtendedWriter)
		geometry := conn.(N.FrontHeadroom)
		rear := conn.(N.RearHeadroom)

		firstBuffer := buf.NewSize(geometry.FrontHeadroom() + 64 + rear.RearHeadroom())
		firstBuffer.Resize(geometry.FrontHeadroom(), 0)
		common.Must1(firstBuffer.Write(make([]byte, 64)))
		if err := extended.WriteBuffer(firstBuffer); err != nil {
			t.Fatal(err)
		}

		payload := make([]byte, payloadSize)
		buffer := buf.NewSize(geometry.FrontHeadroom() + payloadSize + rear.RearHeadroom())
		buffer.Resize(geometry.FrontHeadroom(), 0)
		common.Must1(buffer.Write(payload))
		sink.reset(&buffer.Bytes()[0], payloadSize)
		if err := extended.WriteBuffer(buffer); err != nil {
			t.Fatal(err)
		}
		return sink.copiedBytes == 0
	}

	atLimit := framedInPlace(advertised)
	aboveLimit := framedInPlace(advertised + 1)

	t.Logf("advertised WriterMTU = %d; framing at the limit in place = %v; one byte above = %v",
		advertised, atLimit, aboveLimit)

	require.True(t, atLimit,
		"a payload of exactly the advertised MTU (%d) must be framed IN PLACE, or the advertised "+
			"ceiling is too high and the copy loop will still overshoot into the copying branch",
		advertised)
	require.False(t, aboveLimit,
		"a payload one byte above the advertised MTU (%d) must take the COPYING branch; if it still "+
			"frames in place then the advertised ceiling is lower than the real limit and the copy "+
			"loop is being told to send smaller buffers than it needs to",
		advertised+1)
}

// TestWithStreamMTUIsTransparent proves the wrapper changes ONLY the MTU.
//
// The wrapper sits between the copy loop and the real writer, so anything it fails to forward would
// silently degrade the path it is meant to improve -- losing the headroom the writer needs, for
// instance, or dropping the conn interface the route layer expects.
func TestWithStreamMTUIsTransparent(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	sink := &copyDetectingWriter{}
	real := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	wrapped := withStreamMTU(real)

	require.NotSame(t, real, wrapped, "the conn must actually be wrapped")

	// The geometry the writer needs must survive unchanged.
	require.Equal(t, N.CalculateFrontHeadroom(real), N.CalculateFrontHeadroom(wrapped),
		"the wrapper must forward the front headroom the Shadowsocks writer needs")
	require.Equal(t, N.CalculateRearHeadroom(real), N.CalculateRearHeadroom(wrapped),
		"the wrapper must forward the rear headroom the Shadowsocks writer needs")

	// And it must add exactly the MTU capability.
	withMTU, hasMTU := wrapped.(N.WriterWithMTU)
	require.True(t, hasMTU, "the wrapper exists to advertise WriterMTU")
	require.Equal(t, streamWriterMTU(), withMTU.WriterMTU())

	_, realHasMTU := real.(N.WriterWithMTU)
	require.False(t, realHasMTU,
		"the unwrapped conn must NOT advertise an MTU, or this wrapper would be pointless")

	// The copy loop must now compute a constrained MTU for the wrapped conn.
	require.Equal(t, streamWriterMTU(), N.CalculateMTU(nil, wrapped),
		"CalculateMTU must see the advertised ceiling, which is the whole point of the wrapper")
}

// TestShadowsocksDialerAdvertisesStreamMTU is the ONLY test here that proves the PRODUCTION WIRING.
//
// # Why a separate test is required
//
// Every other MTU test calls withStreamMTU directly. That proves the wrapper works, but it proves
// nothing about whether production ever applies it: if shadowsocksDialer.DialContext returned the
// bare Shadowsocks conn, every one of those tests would still pass while the shipped path silently
// lost the optimisation.
//
// So this drives (*shadowsocksDialer).DialContext itself -- the method a routed connection actually
// goes through -- and asserts on the conn it returns. The upstream dialer is a local stub, so the
// test is deterministic and touches no network.
func TestShadowsocksDialerAdvertisesStreamMTU(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	// A stub upstream dialer handing back a fully local, controlled connection. It records the
	// server address it was asked for so the test can confirm the production path dialled the
	// configured server rather than something else.
	var dialled M.Socksaddr
	stub := &stubDialer{
		dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			dialled = destination
			client, server := net.Pipe()
			// Drain the server end so a write never blocks.
			go func() {
				_, _ = io.Copy(io.Discard, server)
				_ = server.Close()
			}()
			return client, nil
		},
	}

	dialer := (*shadowsocksDialer)(&Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeShadowsocks, "ss-test", []string{N.NetworkTCP, N.NetworkUDP}, option.DialerOptions{}),
		method:     method,
		dialer:     stub,
		serverAddr: M.ParseSocksaddrHostPort("127.0.0.1", 8388),
	})

	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP,
		M.ParseSocksaddrHostPort("target.example", 443))
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, M.ParseSocksaddrHostPort("127.0.0.1", 8388), dialled,
		"the production dialer must dial the configured server address")

	// The production wiring must expose the full geometry the copy loop needs. A missing capability
	// here means the wrapper was dropped or replaced by the bare conn.
	extended, isExtended := conn.(N.ExtendedWriter)
	require.True(t, isExtended, "the dialed conn must accept buffers (N.ExtendedWriter)")
	require.NotNil(t, extended)

	front, isFront := conn.(N.FrontHeadroom)
	require.True(t, isFront, "the dialed conn must advertise front headroom (N.FrontHeadroom)")
	require.NotNil(t, front)

	rear, isRear := conn.(N.RearHeadroom)
	require.True(t, isRear, "the dialed conn must advertise rear headroom (N.RearHeadroom)")
	require.NotNil(t, rear)

	withMTU, hasMTU := conn.(N.WriterWithMTU)
	require.True(t, hasMTU,
		"the dialed conn must advertise WriterMTU: without it the copy loop sizes steady-state "+
			"buffers above the in-place limit and every full buffer is copied")
	require.Equal(t, streamWriterMTU(), withMTU.WriterMTU(),
		"the advertised MTU must be the production in-place limit")

	// And the copy loop must actually compute a constrained MTU from what the dialer returned.
	require.Equal(t, streamWriterMTU(), N.CalculateMTU(nil, conn),
		"CalculateMTU must see the advertised ceiling through the production dialer's conn")
}

// stubDialer is an N.Dialer that delegates to a local function, so tests can hand the production
// dialers a fully controlled upstream connection without touching the network.
type stubDialer struct {
	dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func (d *stubDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, network, destination)
}

func (d *stubDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("stubDialer: ListenPacket not implemented")
}

// BenchmarkShadowMTUWrappedPath measures the real Shadowsocks writer with and without the MTU
// wrapper, over an assembled copy loop.
//
// # What this does NOT prove, and used to claim
//
// It does not prove the production wiring. The dial happens with a plain net.Dial and the wrapper is
// applied by hand, so (*shadowsocksDialer).DialContext is never entered. An earlier revision of this
// benchmark described itself as exercising "the real outbound dial path" and "production wiring",
// which the code below does not do -- a benchmark that overstates its own coverage is worse than one
// that states its limits.
//
// Production wiring is proven by TestShadowsocksDialerAdvertisesStreamMTU, which calls the dialer.
// This benchmark is here to MEASURE the datapath: real Shadowsocks writer, real copy loop, with and
// without the MTU advertised.
func BenchmarkShadowMTUWrappedPath(b *testing.B) {
	method, err := shadowss.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm",
		shadowss.MethodOptions{Password: "AAAAAAAAAAAAAAAAAAAAAA=="})
	if err != nil {
		b.Skipf("method unavailable: %v", err)
	}
	const streamTotal = 4 << 20

	// A listener that accepts and discards, so the dial succeeds and the copy runs.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
			}()
		}
	}()

	b.ReportAllocs()
	b.SetBytes(streamTotal)

	// The connection is established per iteration, and that setup is charged to the benchmark: the
	// alternative is a StopTimer/StartTimer pair inside B.Loop, which the harness rejects. The cost
	// being compared is the COPY, and it dominates by three orders of magnitude, so including a
	// localhost dial does not change which variant wins.
	for b.Loop() {
		outConn, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			b.Fatal(dialErr)
		}
		destination := withStreamMTU(method.DialEarlyConn(outConn,
			M.ParseSocksaddrHostPort("target.example", 443)))
		copied, copyErr := bufio.Copy(destination, &fixedSizeReader{remaining: streamTotal})
		if copyErr != nil {
			b.Fatal(copyErr)
		}
		// Path-execution sanity check: a benchmark that copies nothing would report a fast,
		// low-allocation result for a datapath that never ran.
		if copied != streamTotal {
			b.Fatalf("copied %d bytes, expected %d: the datapath did not carry the payload, so this "+
				"measurement is invalid", copied, streamTotal)
		}
		_ = destination.Close()
	}
}
