package shadowsocks

import (
	"context"
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/internal/memmetrics"
	shadowss "github.com/sagernet/sing-shadowsocks2"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// BenchmarkShadowMemoryPressureMeasured runs the pressure workload and reports the runtime
// memory figures from INSIDE the process being measured.
//
// # Why this replaces the gctrace approach
//
// The previous harness set GODEBUG=gctrace=1 on `go test` and parsed its output. That had
// three problems, all of which produced numbers that looked like evidence:
//
//   - the gctrace heap field is the heap at a cycle, not the runtime-managed memory the
//     GOMEMLIMIT contract governs, so "did the limit engage" was decided from the wrong
//     quantity;
//   - the three "ms clock" phases were summed and reported as GC pause, when only part of
//     one of them is stop-the-world;
//   - GODEBUG is inherited by the whole process tree, so the compiler's and the go
//     command's own GC was mixed into the workload's measurement.
//
// runtime/metrics has none of those problems: the metrics are read in-process, they are
// the runtime's supported interface, and the pause figure comes from the STW histogram
// rather than from phase timings.
//
// The figures are emitted as a single line the matrix harness parses, so the harness does
// not need to understand gctrace at all.
func BenchmarkShadowMemoryPressureMeasured(b *testing.B) {
	method, err := shadowss.CreateMethod(context.Background(), "2022-blake3-aes-128-gcm",
		shadowss.MethodOptions{Password: "AAAAAAAAAAAAAAAAAAAAAA=="})
	if err != nil {
		b.Skipf("method unavailable: %v", err)
	}

	recorder, err := memmetrics.NewRecorder()
	if err != nil {
		// Fail rather than skip: a benchmark that cannot measure the thing it exists to
		// measure must not report a number.
		b.Fatalf("runtime metrics unavailable, refusing to measure: %v", err)
	}
	start, err := memmetrics.Read()
	if err != nil {
		b.Fatalf("read runtime state: %v", err)
	}

	const payloadPerOp = 256 << 20

	// A continuous sampler runs for the WHOLE measured section, on a fixed cadence.
	//
	// The previous code called recorder.Sample() once per completed 256 MiB copy - that is,
	// only at workload BOUNDARIES. A soft limit does not hold the runtime at the limit; it
	// allows an overshoot between collections and then brings it back, so the peak is a
	// transient in the MIDDLE of a copy. Sampling at the edges measured the peak of the
	// boundary readings, not the peak.
	//
	// The same sampler and cadence are used for every configuration in the matrix, so the
	// overhead is shared and cannot favour one side.
	sampler, err := memmetrics.NewContinuousSampler(memmetrics.SamplerOptions{})
	if err != nil {
		b.Fatalf("start continuous sampler: %v", err)
	}

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
	b.StopTimer()

	// Stop waits for the sampling goroutine, so nothing outlives the measurement.
	sampler.Stop()
	continuousPeak := sampler.Peak()
	continuousTicks := sampler.Ticks()

	delta, end, err := recorder.Finish()
	if err != nil {
		b.Fatalf("finish metrics: %v", err)
	}

	// One machine-readable line. The harness parses this and nothing else.
	// pause_total_ns is the EXACT cumulative STW pause for this run, from the runtime's own
	// nanosecond counter. pause_max_upper_bound_ns is the largest histogram bucket upper bound
	// among this run's pauses and is named as a bound, because a pause in bucket [a,b) could be
	// anywhere in that range. The previous output reported the histogram estimate as
	// pause_total_ns, which claimed an exactness it did not have.
	fmt.Printf("MEMMETRICS gogc=%d gomemlimit=%d managed_start=%d managed_peak=%d managed_end=%d "+
		"gc_cycles=%d pause_total_ns=%d pause_count=%d pause_max_upper_bound_ns=%d "+
		"pause_upper_bound_total_ns=%d heap_live=%d continuous_peak=%d continuous_ticks=%d\n",
		end.GOGCPercent,
		end.GOMEMLIMITBytes,
		delta.RuntimeManagedAtStart,
		delta.RuntimeManagedPeak,
		delta.RuntimeManagedAtEnd,
		delta.GCCycles,
		delta.PauseTotalNs,
		delta.PauseCount,
		int64(delta.PauseMaxUpperBound*1e9),
		int64(delta.PauseUpperBoundTotal*1e9),
		end.HeapLiveBytes,
		continuousPeak,
		continuousTicks,
	)
	_ = start
}

// TestMemoryPressureMetricsAreEmitted keeps the benchmark's contract honest.
//
// If the metrics line stopped being emitted, the harness would see missing data and could
// silently fall back to reporting nothing, or worse, to a default. This asserts the
// benchmark can read the runtime's figures at all.
func TestMemoryPressureMetricsAreEmitted(t *testing.T) {
	if !memmetrics.Supported() {
		t.Fatal("the runtime must publish the metrics the pressure benchmark reports")
	}
	recorder, err := memmetrics.NewRecorder()
	if err != nil {
		t.Fatal(err)
	}
	delta, state, err := recorder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if state.GOMEMLIMITBytes == 0 {
		t.Error("the memory limit must be reported even for an empty workload")
	}
	if delta.RuntimeManagedPeak == 0 {
		t.Error("the runtime-managed figure must be non-zero")
	}
}
