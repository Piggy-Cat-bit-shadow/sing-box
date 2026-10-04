package trafficsched

import (
	"io"
	"strconv"
	"testing"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The gate sits on the write path of every managed upload, so its own cost is charged to every
// byte. These benchmarks answer one question: what does the gate itself cost when it decides
// nothing?
//
// The three cases are deliberately nested so the answer can be attributed:
//
//	raw             the writer alone                     - the floor
//	gate(nil flow)  the shape without any scheduling     - the wrapper's cost
//	gate(flow)      the real shape, uncontended NORMAL   - the wrapper plus the fast path
//
// A configuration with no interactive traffic only ever runs the third case, and it must be
// indistinguishable from the first two in allocation count.

// sizeName keeps the benchmark names uniform across the size and shape axes.
func sizeName(shape string, size int) string {
	return shape + "/" + strconv.Itoa(size)
}

type benchSink struct {
	extended bool
}

func (s *benchSink) Write(p []byte) (int, error) { return len(p), nil }

func (s *benchSink) WriteBuffer(buffer *buf.Buffer) error {
	buffer.Release()
	return nil
}

// BenchmarkStreamWriteTax measures a single write at each size the copy loop produces.
func BenchmarkStreamWriteTax(b *testing.B) {
	sizes := []int{256, 4096, 65536}
	for _, size := range sizes {
		payload := make([]byte, size)

		b.Run(sizeName("raw", size), func(b *testing.B) {
			sink := &benchSink{}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				_, _ = sink.Write(payload)
			}
		})

		b.Run(sizeName("gate-nil-flow", size), func(b *testing.B) {
			gate := NewGate(&benchSink{}, nil)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				_, _ = gate.Write(payload)
			}
		})

		b.Run(sizeName("gate-uncontended", size), func(b *testing.B) {
			scheduler := NewScheduler(Options{})
			flow := scheduler.NewFlow(trafficclass.ClassDefault)
			gate := NewGate(&benchSink{}, flow)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				_, _ = gate.Write(payload)
				flow.done()
			}
		})

		// The shaped path with a rate far above what the writes need, so every write is admitted on
		// the spot and only the SHAPING MACHINERY is being measured - the queue push, the credit
		// check, the per-flow period. This is the case a configured-but-generous rate runs, and the
		// allocation count is the property that matters: a shaped write that allocated would turn a
		// rate limit into a garbage source.
		b.Run(sizeName("gate-paced-generous", size), func(b *testing.B) {
			scheduler := NewScheduler(Options{Mode: ModePaced, RateSource: NewFixedRate(1 << 40)})
			flow := scheduler.NewFlow(trafficclass.ClassDefault)
			gate := NewGate(&benchSink{}, flow)
			b.Cleanup(func() { _ = scheduler.Close() })
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				_, _ = gate.Write(payload)
				flow.done()
			}
		})
	}
}

// BenchmarkStreamWriteBufferTax is the path the TUN upload actually takes: the read waiter hands
// the copy loop an owned buffer and the loop writes it with WriteBuffer.
func BenchmarkStreamWriteBufferTax(b *testing.B) {
	const size = 16384

	b.Run("raw", func(b *testing.B) {
		sink := &benchSink{}
		b.ReportAllocs()
		b.SetBytes(size)
		for b.Loop() {
			_ = sink.WriteBuffer(buf.NewSize(size))
		}
	})

	b.Run("gate-nil-flow", func(b *testing.B) {
		gate := NewGate(&benchSink{}, nil)
		b.ReportAllocs()
		b.SetBytes(size)
		for b.Loop() {
			_ = gate.(N.ExtendedWriter).WriteBuffer(buf.NewSize(size))
		}
	})

	b.Run("gate-uncontended", func(b *testing.B) {
		scheduler := NewScheduler(Options{})
		flow := scheduler.NewFlow(trafficclass.ClassDefault)
		gate := NewGate(&benchSink{}, flow)
		b.ReportAllocs()
		b.SetBytes(size)
		for b.Loop() {
			_ = gate.(N.ExtendedWriter).WriteBuffer(buf.NewSize(size))
			flow.done()
		}
	})
}

// countingReader hands out the same buffer repeatedly so the copy-loop benchmarks measure the
// copy path rather than buffer allocation.
type countingReader struct {
	remaining int
	size      int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := r.size
	if n > len(p) {
		n = len(p)
	}
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return n, nil
}

// BenchmarkCopyLoopTax measures the gate where it actually lives: inside the copy loop, on a
// stream. It is the number that matters for throughput, because it includes the engine's own
// per-write bookkeeping next to the gate's.
func BenchmarkCopyLoopTax(b *testing.B) {
	const (
		total = 8 << 20
		chunk = 16384
	)

	b.Run("raw", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(total)
		for b.Loop() {
			sink := &benchSink{}
			_, _ = io.Copy(sink, &countingReader{remaining: total, size: chunk})
		}
	})

	b.Run("gate-uncontended", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(total)
		for b.Loop() {
			scheduler := NewScheduler(Options{})
			flow := scheduler.NewFlow(trafficclass.ClassDefault)
			gate := NewGate(&benchSink{}, flow)
			_, _ = io.Copy(gate, &countingReader{remaining: total, size: chunk})
			flow.done()
		}
	})
}

// BenchmarkPacketGateTax measures the UDP shapes. A batch must stay one call and one admission.
func BenchmarkPacketGateTax(b *testing.B) {
	newBatch := func(count int) ([]*buf.Buffer, []M.Socksaddr) {
		buffers := make([]*buf.Buffer, count)
		destinations := make([]M.Socksaddr, count)
		for index := range buffers {
			buffers[index] = buf.NewSize(1400)
		}
		return buffers, destinations
	}

	b.Run("single-packet/raw", func(b *testing.B) {
		sink := &packetSink{}
		b.ReportAllocs()
		for b.Loop() {
			_ = sink.WritePacket(buf.NewSize(1024), M.Socksaddr{})
		}
	})

	b.Run("single-packet/gate", func(b *testing.B) {
		scheduler := NewScheduler(Options{})
		flow := scheduler.NewFlow(trafficclass.ClassDefault)
		gate := NewPacketGate(&packetSink{}, flow)
		b.ReportAllocs()
		for b.Loop() {
			_ = gate.WritePacket(buf.NewSize(1024), M.Socksaddr{})
			flow.done()
		}
	})

	b.Run("batch-64/raw", func(b *testing.B) {
		sink := &packetSink{}
		batchWriter, _ := sink.CreatePacketBatchWriter()
		b.ReportAllocs()
		for b.Loop() {
			buffers, destinations := newBatch(64)
			_ = batchWriter.WritePacketBatch(buffers, destinations)
		}
	})

	b.Run("batch-64/gate", func(b *testing.B) {
		scheduler := NewScheduler(Options{})
		flow := scheduler.NewFlow(trafficclass.ClassDefault)
		gate := NewPacketGate(&packetSink{}, flow)
		batchWriter, _ := gate.(N.PacketBatchWriteCreator).CreatePacketBatchWriter()
		b.ReportAllocs()
		for b.Loop() {
			buffers, destinations := newBatch(64)
			_ = batchWriter.WritePacketBatch(buffers, destinations)
			flow.done()
		}
	})
}
