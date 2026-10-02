package libbox

import (
	"runtime/metrics"

	"github.com/sagernet/sing/common/byteformats"
)

// Runtime memory diagnostics.
//
// # Why runtime/metrics rather than setting and restoring a knob
//
// There is no exported getter for GOGC. The previous approach called
// debug.SetGCPercent(-1) to make it return the current value and then restored it - but
// -1 does not mean "read"; it means "disable garbage collection". Reading a diagnostic
// briefly turned the collector off, which is the opposite of what a memory diagnostic
// should do, and it did so on a startup path in a process whose whole problem is memory.
//
// runtime/metrics reads the runtime's own published statistics with no side effects.
// Every value below is read that way, so the diagnostic observes the process instead of
// perturbing it.
//
// # Failing closed
//
// A metric can be absent on a runtime that does not publish it. When that happens the
// field is left unset and reported as unknown; it is never filled with a guess. A
// diagnostic that invents a number is worse than one that admits it does not know,
// because the whole point is to be trusted when reading a device log.

// runtimeMemoryState is the runtime's own view of its memory configuration.
type runtimeMemoryState struct {
	// GOGCPercent is /gc/gogc:percent, or 0 with gogcKnown false.
	GOGCPercent uint64
	gogcKnown   bool

	// MemoryLimitBytes is /gc/gomemlimit:bytes, or 0 with memLimitKnown false.
	MemoryLimitBytes uint64
	memLimitKnown    bool
}

// readRuntimeMemoryState reads the runtime memory configuration without changing it.
func readRuntimeMemoryState() runtimeMemoryState {
	samples := []metrics.Sample{
		{Name: "/gc/gogc:percent"},
		{Name: "/gc/gomemlimit:bytes"},
	}
	metrics.Read(samples)

	var state runtimeMemoryState
	if value := samples[0].Value; value.Kind() == metrics.KindUint64 {
		state.GOGCPercent = value.Uint64()
		state.gogcKnown = true
	}
	if value := samples[1].Value; value.Kind() == metrics.KindUint64 {
		state.MemoryLimitBytes = value.Uint64()
		state.memLimitKnown = true
	}
	return state
}

// runtimeMemoryDiagnostic renders the state for the startup log.
//
// Each field is reported from what the runtime actually says, and an unavailable metric
// is printed as "unknown" rather than as a number. The budget is passed in because it is
// a policy input rather than a runtime value, and it is labelled as what it is: a
// fallback budget, not a system limit.
func runtimeMemoryDiagnostic(budget uint64, state runtimeMemoryState) string {
	line := "[Memory] NetworkExtension budget=" + byteformats.FormatMemoryBytes(budget)

	if state.memLimitKnown {
		line += " runtime_limit=" + byteformats.FormatMemoryBytes(state.MemoryLimitBytes)
	} else {
		line += " runtime_limit=unknown"
	}

	if state.gogcKnown {
		line += " GOGC=" + formatUint(state.GOGCPercent)
	} else {
		line += " GOGC=unknown"
	}
	return line
}

func formatUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}
