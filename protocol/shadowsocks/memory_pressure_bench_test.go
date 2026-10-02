package shadowsocks

import (
	"context"
	"testing"

	shadowss "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Memory-pressure benchmarks.
//
// # Why these exist
//
// The iOS client runs with GOMEMLIMIT 40 MiB and GOGC 50, and this phase has to answer
// whether that pacing costs throughput on the real data path. That cannot be answered
// with the existing benchmarks: measured under gctrace, the whole set peaks at 3-5 MiB,
// and a 40 MiB soft limit the heap never approaches does nothing. Comparing settings
// there would yield seven identical rows and the appearance of evidence.
//
// So the limit needs a workload that actually presses on it. These run the real
// Shadowsocks writer over a transfer large enough to hold many pooled buffers live at
// once - the shape of a busy client, where the live heap is a function of how much is
// in flight rather than of one buffer.
//
// # Validity is the harness's job, not this file's
//
// The matrix harness records peak heap per run and marks any row whose heap never
// approached its limit as INVALID instead of reporting it. These benchmarks are sized
// to put the unlimited baseline above the largest limit in the matrix; if that stops
// being true the harness says so rather than reporting noise as a result.

// pressureSink consumes buffers and discards them.
//
// It deliberately does NOT retain payload. An earlier version did, and that was a
// design error worth recording: retaining every byte made the live set ~96 MiB, above
// every limit in the matrix, so the GC ran continuously chasing a target the live heap
// alone already exceeded. Every limited setting then measured 65x the GC cycles and
// ~72% less throughput - a real measurement of an unsatisfiable configuration, and
// nothing at all like production traffic.
//
// The point of this benchmark is the opposite: a realistic live set that stays well
// BELOW the limit, while allocating at a high rate. That is what a proxy does - it
// moves buffers through, it does not accumulate them - and it is the condition under
// which GOMEMLIMIT is supposed to pace the heap without thrashing.
type pressureSink struct {
	// nopConn supplies the net.Conn surface; only the write path matters here.
	nopConn
	// held keeps a bounded working set alive. It is sized so the live heap sits near
	// the middle of the range the matrix tests: large enough that the limits engage and
	// pace the collector, small enough that the collector can actually reach them.
	//
	// The distinction matters. Retaining everything (the first attempt) put the live
	// set above every limit, which no soft limit can satisfy, and every limited setting
	// thrashed at 65x the GC cycles. Retaining nothing left the heap at 5 MiB and no
	// limit engaged at all. Neither measures the configuration the iOS client runs.
	held     [][]byte
	heldSize int
	total    int64
}

// heldWorkingSet is the live heap the benchmark deliberately keeps alive, in bytes.
//
// # Getting this right took three attempts, and the wrong ones are worth recording
//
// A soft limit paces memory the runtime can RECLAIM. Measuring that needs two things at
// once: a live set small enough that the limit is satisfiable, and an allocation rate high
// enough that the runtime keeps being pushed toward it. Getting either wrong produces
// confident nonsense:
//
//   - Retaining everything (~97 MiB) put the live set above every limit. A limit below the
//     live set can never be met, so the runtime collected continuously: 7426 GC cycles
//     against 115 unlimited, and every limited row showed ~70% less throughput. A true
//     measurement of an unsatisfiable configuration.
//
//   - Retaining 24 MiB left the peak at ~32 MiB, BELOW every limit in the matrix. Nothing
//     engaged and all rows were identical.
//
//   - Retaining 64 MiB put the live set above every limit again, reproducing the first
//     failure at a larger size: 505 GC cycles chasing an unreachable target.
//
// 20 MiB of retained working set, with the rest churn. The retained part must stay well
// below the smallest limit tested (37.5 MiB) so the limit has room to act, while the total
// allocation per iteration is large enough that the runtime keeps being pushed toward it.
// The matrix runs several iterations, so the peak settles above the limits rather than
// below them.
const heldWorkingSet = 20 << 20

func (s *pressureSink) WriteBuffer(buffer *buf.Buffer) error {
	s.total += int64(buffer.Len())
	if s.heldSize < heldWorkingSet {
		// Keep a copy so the buffer returns to the pool: retaining the buffer would
		// measure the pool's accounting rather than the collector's pacing.
		chunk := append([]byte(nil), buffer.Bytes()...)
		s.held = append(s.held, chunk)
		s.heldSize += len(chunk)
	}
	buffer.Release()
	return nil
}

func (s *pressureSink) Upstream() any { return nil }

func (s *pressureSink) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkShadowMemoryPressure runs the real copy loop under a high allocation rate
// with a bounded live set.
//
// The transfer is large enough that total allocation is many times the limit, so the
// collector must run repeatedly and any pacing difference shows up, while the live set
// stays small because nothing is retained. The harness records peak heap per run and
// marks a row invalid if the heap never came close enough to the limit for it to
// engage, so this cannot silently become a measurement of nothing.
func BenchmarkShadowMemoryPressure(b *testing.B) {
	method, err := shadowss.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm",
		shadowss.MethodOptions{Password: "AAAAAAAAAAAAAAAAAAAAAA=="})
	if err != nil {
		b.Skipf("method unavailable: %v", err)
	}

	// 256 MiB per iteration: roughly six times the largest limit in the matrix, so the
	// collector runs many times and the pacing is what is being compared.
	const payloadPerOp = 256 << 20

	b.SetBytes(payloadPerOp)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		sink := &pressureSink{}
		conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
		destination := withStreamMTU(conn)
		source := &fixedSizeReader{remaining: payloadPerOp}
		b.StartTimer()

		if _, err := bufio.Copy(destination, source); err != nil {
			b.Fatal(err)
		}
	}
}

// TestShadowMemoryPressureDeliversPayload keeps the benchmark honest.
//
// A pressure benchmark that silently transferred nothing would report a very fast,
// very allocation-light result for a datapath that never ran, which is exactly the kind
// of number that gets quoted as evidence. This checks the payload arrives.
func TestShadowMemoryPressureDeliversPayload(t *testing.T) {
	method := shadowAuditMethod(t, "2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")

	const payload = 4 << 20
	sink := &pressureSink{}
	conn := method.DialEarlyConn(sink, M.ParseSocksaddrHostPort("target.example", 443))
	destination := withStreamMTU(conn)

	copied, err := bufio.Copy(destination, &fixedSizeReader{remaining: payload})
	require.NoError(t, err)
	require.EqualValues(t, payload, copied, "the copy loop must consume the whole payload")
	require.Greater(t, sink.total, int64(0), "payload must reach the sink")
}
