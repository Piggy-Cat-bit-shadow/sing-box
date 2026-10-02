package memmetrics

import (
	"runtime/debug"
	"testing"
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
	t.Logf("gcCycles=%d managedStart=%d managedPeak=%d managedEnd=%d pauseTotal=%.6fs pauseCount=%d",
		delta.GCCycles, delta.RuntimeManagedAtStart, delta.RuntimeManagedPeak,
		delta.RuntimeManagedAtEnd, delta.PauseTotalSeconds, delta.PauseCount)
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
	if delta.PauseTotalSeconds > 1.0 {
		t.Errorf("total STW pause %.3fs is implausible for this workload; the histogram is probably being misread",
			delta.PauseTotalSeconds)
	}
	t.Logf("pauseTotal=%.6fs pauseCount=%d pauseMax=%.6fs gcCycles=%d",
		delta.PauseTotalSeconds, delta.PauseCount, delta.PauseMaxSeconds, delta.GCCycles)
}
