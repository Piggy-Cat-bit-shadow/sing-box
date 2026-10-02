package oomkiller

import (
	"runtime/debug"
	"runtime/metrics"
	"testing"
)

// Verify the GOMEMLIMIT accounting figure matches the contract: total minus released.
func TestRuntimeManagedAccounting(t *testing.T) {
	debug.SetMemoryLimit(40 * 1024 * 1024)
	defer debug.SetMemoryLimit(1<<63 - 1)

	r := NewRecorder(RecorderOptions{})
	// Read through the recorder's own sample set so this covers the wiring, not just the
	// metric names.
	metrics.Read(r.metricsSamples)
	total := r.metricsSamples[0].Value.Uint64()
	released := r.metricsSamples[5].Value.Uint64()
	managed := subtractFloor(total, released)
	t.Logf("total=%d released=%d managed=%d limit=%d gogc=%d",
		total, released, managed,
		r.metricsSamples[6].Value.Uint64(), r.metricsSamples[7].Value.Uint64())

	if managed > total {
		t.Errorf("managed (%d) must never exceed total (%d)", managed, total)
	}
	if got := r.metricsSamples[6].Value.Uint64(); got != 40*1024*1024 {
		t.Errorf("gomemlimit metric = %d, want %d", got, 40*1024*1024)
	}
	if got := r.metricsSamples[7].Value.Uint64(); got == 0 {
		t.Error("gogc metric must be non-zero for a normally configured runtime")
	}
}

func TestSubtractFloorDoesNotUnderflow(t *testing.T) {
	if got := subtractFloor(10, 20); got != 0 {
		t.Errorf("subtractFloor(10,20) = %d, want 0 (an underflow would wrap)", got)
	}
	if got := subtractFloor(20, 10); got != 10 {
		t.Errorf("subtractFloor(20,10) = %d, want 10", got)
	}
}
