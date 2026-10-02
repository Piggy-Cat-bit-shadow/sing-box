package memmetrics

import (
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestReadMatchesTheRuntimeConfiguration(t *testing.T) {
	const limit = 40 * 1024 * 1024
	previousLimit := debug.SetMemoryLimit(limit)
	defer debug.SetMemoryLimit(previousLimit)
	previousGC := debug.SetGCPercent(80)
	defer debug.SetGCPercent(previousGC)

	state, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if state.GOMEMLIMITBytes != limit {
		t.Errorf("GOMEMLIMIT %d, want %d", state.GOMEMLIMITBytes, limit)
	}
	if state.GOGCPercent != 80 {
		t.Errorf("GOGC %d, want 80", state.GOGCPercent)
	}
}

func TestRuntimeManagedIsTotalMinusReleased(t *testing.T) {
	// This is the GOMEMLIMIT contract. Reading total alone overstates what the limit
	// governs, because released memory is no longer charged to the runtime - and the
	// benchmark this replaced was reading an unrelated quantity entirely.
	state, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if state.RuntimeTotalBytes == 0 {
		t.Fatal("the runtime must report total memory")
	}
	if state.RuntimeManagedBytes > state.RuntimeTotalBytes {
		t.Errorf("managed (%d) exceeds total (%d)", state.RuntimeManagedBytes, state.RuntimeTotalBytes)
	}
	expected := state.RuntimeTotalBytes - state.HeapReleasedBytes
	if state.RuntimeManagedBytes != expected {
		t.Errorf("managed %d, want total-minus-released %d", state.RuntimeManagedBytes, expected)
	}
}

func TestSupportedReportsTrueOnThisRuntime(t *testing.T) {
	if !Supported() {
		t.Fatal("every metric this package needs must exist on a current Go runtime")
	}
}

func TestRecorderMeasuresGCDelta(t *testing.T) {
	recorder, err := NewRecorder()
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	// Force enough allocation to guarantee at least one collection.
	debug.SetGCPercent(10)
	defer debug.SetGCPercent(100)
	for i := 0; i < 64; i++ {
		chunk := make([]byte, 512*1024)
		_ = chunk[0]
		recorder.Sample()
	}

	delta, end, err := recorder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if delta.GCCycles == 0 {
		t.Error("a workload this size must have run at least one GC cycle")
	}
	if delta.RuntimeManagedPeak < delta.RuntimeManagedAtStart {
		t.Error("the peak must be at least the starting value")
	}
	if end.GOMEMLIMITBytes == 0 {
		t.Error("the ending state must report the memory limit")
	}
	t.Logf("gcCycles=%d managedStart=%d managedPeak=%d managedEnd=%d pauseTotalNs=%d pauseCount=%d",
		delta.GCCycles, delta.RuntimeManagedAtStart, delta.RuntimeManagedPeak,
		delta.RuntimeManagedAtEnd, delta.PauseTotalNs, delta.PauseCount)
}

func TestRecorderPauseIsNotAnOvercountedSum(t *testing.T) {
	// The old benchmark summed three gctrace phase timings and called the result "pause".
	// The real figure comes from the runtime's STW histogram, so it must be small relative
	// to the workload rather than the sum of every GC phase.
	recorder, err := NewRecorder()
	if err != nil {
		t.Fatal(err)
	}
	debug.SetGCPercent(10)
	defer debug.SetGCPercent(100)
	for i := 0; i < 32; i++ {
		chunk := make([]byte, 1<<20)
		_ = chunk[0]
	}
	delta, _, err := recorder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if delta.GCCycles > 0 && delta.PauseCount == 0 {
		t.Error("GC cycles were observed but no pauses were recorded; the histogram is not being read")
	}
	// Sanity bound: total STW pause for a short workload cannot plausibly reach a second.
	if delta.PauseTotalNs > uint64(time.Second) {
		t.Errorf("total STW pause %dns is implausible for this workload", delta.PauseTotalNs)
	}
	// The exact nanosecond counter and the histogram estimate should agree in magnitude. A
	// large divergence would mean one of them is being misread.
	if delta.PauseUpperBoundTotal > 0 {
		estimateNs := delta.PauseUpperBoundTotal * 1e9
		exactNs := float64(delta.PauseTotalNs)
		if exactNs > 0 && estimateNs > exactNs*4 {
			t.Errorf("histogram upper-bound total %.0fns is more than 4x the exact total %dns; "+
				"the estimate is not tracking the measurement", estimateNs, delta.PauseTotalNs)
		}
	}
	t.Logf("pauseTotalNs=%d pauseCount=%d pauseMaxUpperBound=%.6fs pauseUpperBoundTotal=%.6fs gcCycles=%d",
		delta.PauseTotalNs, delta.PauseCount, delta.PauseMaxUpperBound,
		delta.PauseUpperBoundTotal, delta.GCCycles)
}

// TestPauseTotalIsAnExactRuntimeDelta pins §6's first requirement.
//
// The total must come from runtime.MemStats.PauseTotalNs - an integer nanosecond counter the
// runtime maintains - and not from summing histogram bucket upper bounds, which can only
// overstate by up to one bucket width per pause.
func TestPauseTotalIsAnExactRuntimeDelta(t *testing.T) {
	recorder, err := NewRecorder()
	if err != nil {
		t.Fatal(err)
	}

	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Force several collections so the counter definitely moves.
	debug.SetGCPercent(10)
	for i := 0; i < 64; i++ {
		chunk := make([]byte, 1<<20)
		_ = chunk[0]
	}
	debug.SetGCPercent(100)
	runtime.GC()

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta, _, err := recorder.Finish()
	if err != nil {
		t.Fatal(err)
	}

	// The recorder's interval is bounded by the two readings taken around it.
	lower := before.PauseTotalNs
	upper := after.PauseTotalNs
	// The recorder started before `before` and finished after `after`, so its interval must be
	// at least as large as the span between these two readings.
	if delta.PauseTotalNs < upper-lower {
		t.Errorf("PauseTotalNs = %d, but the runtime counter advanced by at least %d over the "+
			"same collections; the total is not coming from runtime.MemStats",
			delta.PauseTotalNs, upper-lower)
	}

	// And it must be a nanosecond count, not a seconds-as-float estimate. A workload that
	// forced collections cannot have paused for less than a microsecond in total.
	if delta.GCCycles > 0 && delta.PauseTotalNs == 0 {
		t.Error("GC cycles occurred but PauseTotalNs is zero; the exact counter is not being read")
	}

	t.Logf("exact pause delta = %dns over %d cycles", delta.PauseTotalNs, delta.GCCycles)
}

// TestPauseMaxDescribesTheIntervalNotTheProcess pins §6's second requirement.
//
// A cumulative histogram describes the whole process, so its largest bucket says nothing about
// this run. A benchmark starting after a large collection would inherit that collection's
// slowest pause as its own maximum, making every run look alike and hiding the regression being
// measured.
//
// This is tested on the interval arithmetic directly, because manufacturing a specific
// process-history pause distribution is not something a test can control.
func TestPauseMaxDescribesTheIntervalNotTheProcess(t *testing.T) {
	// Buckets: (-inf, 1ms], (1ms, 10ms], (10ms, 100ms]
	buckets := []float64{0, 0.001, 0.010, 0.100}

	// The process already contains a 100ms pause from before the benchmark.
	start := pauseSnapshot{
		counts:  []uint64{5, 3, 1},
		buckets: buckets,
	}
	// This run added only fast pauses.
	end := pauseSnapshot{
		counts:  []uint64{105, 3, 1},
		buckets: buckets,
	}

	interval := end.interval(start)

	if interval.Count != 100 {
		t.Fatalf("interval count = %d, want 100", interval.Count)
	}
	// The interval's largest pause is in the 1ms bucket. Using the process maximum would
	// report 100ms, misattributing a pre-existing pause to this run.
	if interval.MaxUpperBound != 0.001 {
		t.Fatalf("interval max upper bound = %v, want 0.001; "+
			"a pre-existing 100ms pause must not be attributed to this interval",
			interval.MaxUpperBound)
	}

	// The mirror: a run that DOES add a slow pause must report it.
	slowEnd := pauseSnapshot{
		counts:  []uint64{105, 3, 2},
		buckets: buckets,
	}
	slowInterval := slowEnd.interval(start)
	if slowInterval.MaxUpperBound != 0.100 {
		t.Fatalf("interval max upper bound = %v, want 0.100 for a run that added a slow pause",
			slowInterval.MaxUpperBound)
	}
	if slowInterval.Count != 101 {
		t.Fatalf("interval count = %d, want 101", slowInterval.Count)
	}
}

// TestPauseIntervalIgnoresUnchangedBuckets guards the subtraction itself.
func TestPauseIntervalIgnoresUnchangedBuckets(t *testing.T) {
	buckets := []float64{0, 0.001, 0.010}
	start := pauseSnapshot{counts: []uint64{10, 5}, buckets: buckets}
	end := pauseSnapshot{counts: []uint64{10, 5}, buckets: buckets}

	interval := end.interval(start)
	if interval.Count != 0 || interval.MaxUpperBound != 0 || interval.UpperBoundTotal != 0 {
		t.Fatalf("an unchanged histogram must yield an empty interval, got %+v", interval)
	}
}

// TestPauseIntervalHandlesAShortPreviousSnapshot guards against a panic when the runtime's
// bucket layout differs between reads, which would otherwise index out of range.
func TestPauseIntervalHandlesAShortPreviousSnapshot(t *testing.T) {
	end := pauseSnapshot{
		counts:  []uint64{1, 2, 3},
		buckets: []float64{0, 0.001, 0.010, 0.100},
	}
	start := pauseSnapshot{counts: []uint64{0}, buckets: []float64{0, 0.001}}

	interval := end.interval(start)
	if interval.Count != 6 {
		t.Fatalf("interval count = %d, want 6", interval.Count)
	}
}
