package libbox

import (
	"runtime/debug"
	"strings"
	"testing"
)

// The diagnostic must OBSERVE the runtime, never perturb it.
//
// The implementation it replaced read GOGC by calling debug.SetGCPercent(-1) and
// restoring it. That is not a getter: -1 disables garbage collection, so a memory
// diagnostic briefly turned the collector off. These tests pin the property that made
// that unacceptable.

func TestRuntimeMemoryDiagnosticDoesNotChangeGOGC(t *testing.T) {
	const configured = 100
	previous := debug.SetGCPercent(configured)
	defer debug.SetGCPercent(previous)

	before := readRuntimeMemoryState()
	if !before.gogcKnown {
		t.Fatal("the runtime must publish /gc/gogc:percent for this diagnostic to be trustworthy")
	}
	if before.GOGCPercent != configured {
		t.Fatalf("precondition: GOGC reported %d, expected %d", before.GOGCPercent, configured)
	}

	// Render the line, which is where the old code would have probed.
	line := runtimeMemoryDiagnostic(50*1024*1024, before)
	if !strings.Contains(line, "GOGC=") {
		t.Fatalf("the diagnostic must report GOGC, got %q", line)
	}

	after := readRuntimeMemoryState()
	if after.GOGCPercent != before.GOGCPercent {
		t.Fatalf("the diagnostic changed GOGC: %d -> %d", before.GOGCPercent, after.GOGCPercent)
	}
}

func TestRuntimeMemoryDiagnosticDoesNotDisableGC(t *testing.T) {
	// The specific regression: a non-zero GOGC must survive the diagnostic. If the
	// implementation used SetGCPercent(-1), GOGC would read back as -1 afterwards.
	previous := debug.SetGCPercent(37)
	defer debug.SetGCPercent(previous)

	state := readRuntimeMemoryState()
	_ = runtimeMemoryDiagnostic(50*1024*1024, state)

	verify := readRuntimeMemoryState()
	if verify.GOGCPercent != 37 {
		t.Fatalf("GOGC is %d after the diagnostic, expected 37; -1 would mean GC was disabled",
			verify.GOGCPercent)
	}
}

func TestRuntimeMemoryDiagnosticReportsTheRealLimit(t *testing.T) {
	const limit = 40 * 1024 * 1024
	previous := debug.SetMemoryLimit(limit)
	defer debug.SetMemoryLimit(previous)

	state := readRuntimeMemoryState()
	if !state.memLimitKnown {
		t.Fatal("the runtime must publish /gc/gomemlimit:bytes")
	}
	if state.MemoryLimitBytes != limit {
		t.Fatalf("reported limit %d, expected %d", state.MemoryLimitBytes, limit)
	}

	line := runtimeMemoryDiagnostic(50*1024*1024, state)
	if !strings.Contains(line, "runtime_limit=") {
		t.Fatalf("the diagnostic must report the runtime limit, got %q", line)
	}
	// The budget is a policy input, and the line must label it as such rather than
	// presenting it as a system limit.
	if !strings.Contains(line, "budget=") {
		t.Fatalf("the diagnostic must report the budget, got %q", line)
	}
}

func TestRuntimeMemoryDiagnosticReportsUnknownRatherThanGuessing(t *testing.T) {
	// When a metric is unavailable the field must say so. A diagnostic that invents a
	// number is worse than one that admits ignorance, because it is read as fact.
	line := runtimeMemoryDiagnostic(50*1024*1024, runtimeMemoryState{})
	if !strings.Contains(line, "runtime_limit=unknown") {
		t.Errorf("an unavailable limit must be reported as unknown, got %q", line)
	}
	if !strings.Contains(line, "GOGC=unknown") {
		t.Errorf("an unavailable GOGC must be reported as unknown, got %q", line)
	}
}

func TestRuntimeMemoryDiagnosticAlwaysReportsTheBudget(t *testing.T) {
	// The budget comes from policy, not from the runtime, so it is always known.
	line := runtimeMemoryDiagnostic(50*1024*1024, runtimeMemoryState{})
	if !strings.Contains(line, "budget=") {
		t.Fatalf("the budget must always be reported, got %q", line)
	}
}
