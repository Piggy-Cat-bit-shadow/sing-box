package http

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Benchmarks comparing the batch path with the per-packet fallback through the timeout
// wrapper.
//
// # What is measured, and what is NOT claimed
//
// These are CPU-side measurements of the copy loop and the wrapper: how many packets one
// call carries and how much work per packet the wrapper adds. They do NOT measure a
// system call, a NIC, a real tunnel or a VPS, and no throughput number is derived from
// them. A batching fix is expected to show up here as fewer calls per packet, which is
// the mechanism; the end-to-end effect is a separate measurement that this environment
// cannot produce.
//
// # The three cases
//
//	bare-batch          the connected batch path with NO timeout wrapper
//	fallback-per-packet the same traffic forced through one packet per call
//	timeout-batch       the connected batch path THROUGH the idle-timeout wrapper
//
// The pair that matters for this change is `timeout-batch` against
// `fallback-per-packet`: it is the comparison between "the wrapper keeps batching" and
// "the wrapper drops to one packet at a time", which is exactly the regression the fix
// removes. `bare-batch` is the reference for how much the wrapper itself costs.

// errBenchDrained ends a benchmark copy once the fixture has nothing left to give.
var errBenchDrained = errors.New("benchmark fixture drained")

// benchPayloadSizes are the payload sizes named in the task.
var benchPayloadSizes = []int{64, 1200}

// benchBatchSizes are the batch sizes named in the task.
var benchBatchSizes = []int{1, 8, 32, 64}

// benchBatchSource feeds a fixed payload repeatedly and offers the batch capability.
type benchBatchSource struct {
	payload []byte
	left    int
}

func (s *benchBatchSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if s.left <= 0 {
		return M.Socksaddr{}, errBenchDrained
	}
	s.left--
	buffer.Write(s.payload)
	return M.ParseSocksaddr("192.0.2.10:443"), nil
}

func (s *benchBatchSource) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (s *benchBatchSource) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *benchBatchSource) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errBenchDrained
}

func (s *benchBatchSource) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errBenchDrained
}

func (s *benchBatchSource) Close() error { return nil }

func (s *benchBatchSource) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (s *benchBatchSource) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (s *benchBatchSource) SetDeadline(t time.Time) error      { return os.ErrInvalid }

func (s *benchBatchSource) CreateConnectedPacketBatchReadWaiter() (N.ConnectedPacketBatchReadWaiter, bool) {
	return &benchBatchReadWaiter{source: s}, true
}

type benchBatchReadWaiter struct {
	source *benchBatchSource
	size   int
}

func (w *benchBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.size = options.BatchSize
	if w.size <= 0 {
		w.size = 1
	}
	return false
}

func (w *benchBatchReadWaiter) WaitReadConnectedPackets() ([]*buf.Buffer, M.Socksaddr, error) {
	if w.source.left <= 0 {
		return nil, M.Socksaddr{}, errBenchDrained
	}
	want := w.size
	if want > w.source.left {
		want = w.source.left
	}
	buffers := make([]*buf.Buffer, 0, want)
	for range want {
		packet := buf.NewSize(len(w.source.payload))
		packet.Write(w.source.payload)
		buffers = append(buffers, packet)
	}
	w.source.left -= want
	return buffers, M.ParseSocksaddr("192.0.2.10:443"), nil
}

// benchDestination consumes payloads and counts the two routes.
type benchDestination struct {
	batches      int
	singleWrites int
	payloads     int
}

func (d *benchDestination) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	d.singleWrites++
	d.payloads++
	buffer.Release()
	return nil
}

func (d *benchDestination) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errBenchDrained
}

func (d *benchDestination) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (d *benchDestination) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errBenchDrained
}

func (d *benchDestination) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errBenchDrained
}

func (d *benchDestination) Close() error { return nil }

func (d *benchDestination) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (d *benchDestination) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (d *benchDestination) SetDeadline(t time.Time) error      { return os.ErrInvalid }

func (d *benchDestination) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &benchBatchWriter{destination: d}, true
}

type benchBatchWriter struct {
	destination *benchDestination
}

func (w *benchBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.destination.batches++
	w.destination.payloads += len(buffers)
	buf.ReleaseMulti(buffers)
	return nil
}

// benchReadWaitOptions is the geometry the copy path uses.
func benchReadWaitOptions(batchSize int) N.ReadWaitOptions {
	return N.ReadWaitOptions{
		FrontHeadroom: 3,
		RearHeadroom:  255,
		MTU:           1500,
		BatchSize:     batchSize,
	}
}

// BenchmarkTimeoutWrapperBatchPath measures the three cases.
//
// Reported metrics: ns/op, MB/s and allocs/op from the harness, plus packets-per-op and
// the calls-per-packet ratio, which is the number that actually describes batching.
func BenchmarkTimeoutWrapperBatchPath(b *testing.B) {
	for _, payloadSize := range benchPayloadSizes {
		for _, batchSize := range benchBatchSizes {
			payload := make([]byte, payloadSize)
			for index := range payload {
				payload[index] = byte('x')
			}

			b.Run(benchName("bare-batch", payloadSize, batchSize), func(b *testing.B) {
				runBatchBenchmark(b, payload, batchSize, false, false)
			})
			b.Run(benchName("fallback-per-packet", payloadSize, batchSize), func(b *testing.B) {
				runBatchBenchmark(b, payload, batchSize, true, false)
			})
			b.Run(benchName("timeout-batch", payloadSize, batchSize), func(b *testing.B) {
				runBatchBenchmark(b, payload, batchSize, false, true)
			})
		}
	}
}

// runBatchBenchmark drives one iteration of the copy path.
//
// forceFallback drops the batch capability from the destination so the copy loop takes the
// per-packet route; that is how the "before" case is produced on the same machine as the
// "after" case, which is the only way the comparison is meaningful.
func runBatchBenchmark(b *testing.B, payload []byte, batchSize int, forceFallback, wrap bool) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))

	for range b.N {
		b.StopTimer()

		// One batch worth of packets per iteration, so ns/op and packets/op are directly
		// related and the batch size is visible in the result.
		source := &benchBatchSource{payload: payload, left: batchSize}
		destination := &benchDestination{}

		var sourceReader N.PacketReader = source
		var destinationWriter N.PacketWriter = destination
		if forceFallback {
			destinationWriter = &benchPlainDestination{destination: destination}
		}

		var cleanup func()
		if wrap {
			ctx, cancel := context.WithCancelCause(context.Background())
			_, wrappedSource := canceler.NewPacketConn(ctx, source, 30*time.Second)
			sourceReader = wrappedSource
			cleanup = func() { cancel(net.ErrClosed) }
		}

		b.StartTimer()
		_, _ = bufio.CopyPacket(destinationWriter, sourceReader)
		b.StopTimer()

		if cleanup != nil {
			cleanup()
		}

		if destination.payloads != batchSize {
			b.Fatalf("expected %d packets delivered, got %d", batchSize, destination.payloads)
		}
		b.StartTimer()

		// Recorded once per iteration; ReportMetric keeps the last value, which is stable
		// because every iteration moves the same number of packets.
		b.ReportMetric(float64(destination.batches), "batches")
		b.ReportMetric(float64(destination.singleWrites), "single-writes")
		b.ReportMetric(float64(batchSize), "packets/op")
	}
}

// benchPlainDestination offers no batch capability, forcing the per-packet route.
type benchPlainDestination struct {
	destination *benchDestination
}

func (d *benchPlainDestination) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return d.destination.WritePacket(buffer, destination)
}

func (d *benchPlainDestination) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return d.destination.ReadPacket(buffer)
}

func (d *benchPlainDestination) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (d *benchPlainDestination) ReadFrom(p []byte) (int, net.Addr, error) {
	return d.destination.ReadFrom(p)
}

func (d *benchPlainDestination) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.destination.WriteTo(p, addr)
}

func (d *benchPlainDestination) Close() error { return nil }

func (d *benchPlainDestination) SetReadDeadline(t time.Time) error  { return os.ErrInvalid }
func (d *benchPlainDestination) SetWriteDeadline(t time.Time) error { return os.ErrInvalid }
func (d *benchPlainDestination) SetDeadline(t time.Time) error      { return os.ErrInvalid }

// benchName builds a stable sub-benchmark name.
func benchName(caseName string, payloadSize, batchSize int) string {
	return caseName + "/payload-" + itoaBench(payloadSize) + "B/batch-" + itoaBench(batchSize)
}

func itoaBench(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 6)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
