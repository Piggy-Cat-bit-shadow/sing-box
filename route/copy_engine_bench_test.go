package route

import (
	"io"
	"strconv"
	"testing"

	"github.com/sagernet/sing/common/bufio"
)

// Measurements of the copy engine the route layer actually calls.
//
// # Why this file exists beside direct_offload_bench_test.go
//
// That file measures the two userspace LAYERS with `io.Copy`: the kernel socket pair (L2) and the
// buffered path (L3) as the standard library expresses them. It is a fair model of the syscall
// difference, and its own comment says the two are indistinguishable on loopback. What it does NOT
// exercise is the engine this tree really runs bytes through:
// `route/conn.go` calls `bufio.CopyWithIncreateBuffer(copyWriter, source, increaseBufferAfter,
// bufio.DefaultBatchSize)`, and the packet path calls `bufio.CopyPacketWithCounters`. Those are
// different code with their own buffer ownership, and an audit of copies per byte has to measure
// the code that runs rather than the code that models it.
//
// # What is measured, and what is NOT claimed
//
// The numbers below are ALLOCATION and BYTE-CHURN measurements (`-benchmem`: B/op, allocs/op) for a
// fixed payload, on in-memory endpoints. They answer "how much does the engine allocate to move N
// bytes", which is what decides whether a buffer is pooled and reused.
//
// They are NOT a wall-clock claim and NOT a system-wide improvement. In-memory endpoints remove the
// network entirely, which is deliberate: the network cost is identical for every variant here, so
// including it would only add variance. The throughput column is therefore a property of this rig
// on loopback and must never be quoted as a product throughput.
//
// # The rig is fixed, not borrowed
//
// The source is a reader that produces a fixed payload and then EOF, and the destination is a
// writer that discards. Neither implements `io.ReaderFrom`/`io.WriterTo`, so the engine cannot hand
// the work to the kernel, which is the point: this measures the userspace copy path's own
// allocation behaviour. `earlyConnectionBufferIncreaseAfter` and the default threshold are
// benchmarked separately, because the route layer passes one or the other depending on whether the
// destination or the outbound opted in (route/conn.go:connectionIncreaseBufferAfter).

// fixedPayloadReader produces size bytes and then EOF, by copying from a shared payload.
type fixedPayloadReader struct {
	remaining int
	payload   []byte
}

func (r *fixedPayloadReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	chunk := min(len(p), len(r.payload), r.remaining)
	copied := copy(p[:chunk], r.payload[:chunk])
	r.remaining -= copied
	return copied, nil
}

// discardWriter consumes everything without retaining it.
type discardWriter struct{ written int64 }

func (w *discardWriter) Write(p []byte) (int, error) {
	w.written += int64(len(p))
	return len(p), nil
}

const copyEnginePayload = 4 << 20

func benchmarkTCPCopyEngine(b *testing.B, increaseBufferAfter int64, batchSize int) {
	const chunk = 64 * 1024
	payload := make([]byte, chunk)
	b.SetBytes(copyEnginePayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		source := &fixedPayloadReader{remaining: copyEnginePayload, payload: payload}
		destination := &discardWriter{}
		b.StartTimer()
		copied, err := bufio.CopyWithIncreateBuffer(destination, source, increaseBufferAfter, batchSize)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		if copied != copyEnginePayload {
			b.Fatalf("copied %d bytes, expected %d", copied, copyEnginePayload)
		}
	}
}

// BenchmarkRouteTCPCopyEngineDefaultThreshold measures the call route/conn.go makes for a
// destination that did not opt into early buffer growth.
func BenchmarkRouteTCPCopyEngineDefaultThreshold(b *testing.B) {
	for _, sizes := range []struct {
		name  string
		after int64
		batch int
	}{
		{"default-512000", bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize},
		{"early-optin", earlyConnectionBufferIncreaseAfter, bufio.DefaultBatchSize},
		{"batch-1", bufio.DefaultIncreaseBufferAfter, 1},
	} {
		sizes := sizes
		b.Run(sizes.name, func(b *testing.B) {
			benchmarkTCPCopyEngine(b, sizes.after, sizes.batch)
		})
	}
}

// BenchmarkRouteTCPCopyEngineBySize reports the fixed cost per run separately from the per-byte
// cost, which is what tells a pooled buffer from a per-call allocation: if the buffer were
// allocated per call, allocs/op would grow with the payload.
func BenchmarkRouteTCPCopyEngineBySize(b *testing.B) {
	for _, size := range []int{64 << 10, 1 << 20, 4 << 20} {
		b.Run(strconv.Itoa(size>>10)+"KiB", func(b *testing.B) {
			payload := make([]byte, 64*1024)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				source := &fixedPayloadReader{remaining: size, payload: payload}
				destination := &discardWriter{}
				b.StartTimer()
				copied, err := bufio.CopyWithIncreateBuffer(destination, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				if copied != int64(size) {
					b.Fatalf("copied %d bytes, expected %d", copied, size)
				}
			}
		})
	}
}
