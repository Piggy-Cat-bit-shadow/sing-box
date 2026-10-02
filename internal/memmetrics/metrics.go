// Package memmetrics reads the Go runtime's own memory and GC statistics for benchmarks
// and diagnostics.
//
// # Why not gctrace
//
// The obvious way to observe GC is GODEBUG=gctrace=1 and parsing its output. That approach
// was used in the memory benchmark and produced three distinct errors:
//
//  1. The heap field in a gctrace line ("12->14->7 MB") was treated as the memory the
//     GOMEMLIMIT contract accounts against. It is not: that is the heap at the cycle,
//     while GOMEMLIMIT governs runtime-managed memory. The two differ, and the benchmark
//     was deciding whether a limit "engaged" from the wrong quantity.
//
//  2. The "0.006+1.7+0.015 ms clock" triplet was summed and reported as GC pause. Those
//     are the sweep termination, concurrent mark and mark termination phases; only part of
//     one of them is stop-the-world. Summing them overstates pause by an order of
//     magnitude and calling it "pause" is simply a different number.
//
//  3. GODEBUG is inherited by every process in the tree, so enabling it for `go test`
//     also traced the compiler and the go command. The GC activity of the toolchain was
//     mixed into the measurement of the workload.
//
// runtime/metrics reads the runtime's published statistics directly, in-process, with no
// environment variable and no parsing. It is the supported interface for exactly this.
package memmetrics

import (
	"errors"
	"runtime/metrics"
)

// Sample names.
const (
	metricGCCycles         = "/gc/cycles/total:gc-cycles"
	metricGOGC             = "/gc/gogc:percent"
	metricGOMEMLIMIT       = "/gc/gomemlimit:bytes"
	metricRuntimeTotal     = "/memory/classes/total:bytes"
	metricHeapReleased     = "/memory/classes/heap/released:bytes"
	metricHeapLive         = "/gc/heap/live:bytes"
	metricPauseTotalGCDist = "/sched/pauses/total/gc:seconds"
)

// ErrMetricUnavailable is returned when the runtime does not publish a metric this package
// needs. Callers must treat it as a failure rather than substituting a default: a benchmark
// that silently measures nothing is worse than one that refuses to run.
var ErrMetricUnavailable = errors.New("runtime metric unavailable")

// State is a point-in-time reading of the runtime memory configuration and counters.
type State struct {
	// GCCycles is the total number of completed GC cycles.
	GCCycles uint64
	// GOGCPercent is the collector target.
	GOGCPercent uint64
	// GOMEMLIMITBytes is the soft memory limit.
	GOMEMLIMITBytes uint64
	// RuntimeManagedBytes is the quantity GOMEMLIMIT accounts against:
	// /memory/classes/total:bytes minus /memory/classes/heap/released:bytes.
	RuntimeManagedBytes uint64
	// RuntimeTotalBytes is /memory/classes/total:bytes. It is NOT the GOMEMLIMIT figure;
	// it is recorded so the two can be compared and so the subtraction is auditable.
	RuntimeTotalBytes uint64
	// HeapReleasedBytes is memory returned to the OS and no longer charged to the runtime.
	HeapReleasedBytes uint64
	// HeapLiveBytes is live heap at the last cycle.
	HeapLiveBytes uint64
}

// Delta is the change between two States, plus derived rates.
type Delta struct {
	GCCycles              uint64
	RuntimeManagedPeak    uint64
	RuntimeManagedAtStart uint64
	RuntimeManagedAtEnd   uint64
	PauseTotalSeconds     float64
	PauseCount            uint64
	PauseMaxSeconds       float64
}

// reader holds reusable sample slices so repeated reads do not allocate.
type reader struct {
	samples []metrics.Sample
}

func newReader() *reader {
	return &reader{samples: []metrics.Sample{
		{Name: metricGCCycles},
		{Name: metricGOGC},
		{Name: metricGOMEMLIMIT},
		{Name: metricRuntimeTotal},
		{Name: metricHeapReleased},
		{Name: metricHeapLive},
		{Name: metricPauseTotalGCDist},
	}}
}

// Read returns the current runtime state.
//
// It fails rather than guessing when the runtime does not publish a metric, because every
// number here is used to decide whether a configuration was measured at all.
func Read() (State, error) {
	return newReader().read()
}

func (r *reader) read() (State, error) {
	metrics.Read(r.samples)

	var state State
	for i, sample := range r.samples {
		switch sample.Name {
		case metricPauseTotalGCDist:
			// A histogram; handled by the caller through PauseDelta.
			continue
		}
		if sample.Value.Kind() != metrics.KindUint64 {
			return State{}, ErrMetricUnavailable
		}
		value := sample.Value.Uint64()
		switch i {
		case 0:
			state.GCCycles = value
		case 1:
			state.GOGCPercent = value
		case 2:
			state.GOMEMLIMITBytes = value
		case 3:
			state.RuntimeTotalBytes = value
		case 4:
			state.HeapReleasedBytes = value
		case 5:
			state.HeapLiveBytes = value
		}
	}
	// GOMEMLIMIT accounting is total minus released. An unsigned underflow would wrap to a
	// near-2^64 value that reads as a catastrophic event, so it saturates.
	if state.HeapReleasedBytes > state.RuntimeTotalBytes {
		state.RuntimeManagedBytes = 0
	} else {
		state.RuntimeManagedBytes = state.RuntimeTotalBytes - state.HeapReleasedBytes
	}
	return state, nil
}

// pauseSnapshot captures the GC pause histogram.
type pauseSnapshot struct {
	count   uint64
	total   float64
	maxSeen float64
}

func (r *reader) pauses() (pauseSnapshot, error) {
	for _, sample := range r.samples {
		if sample.Name != metricPauseTotalGCDist {
			continue
		}
		if sample.Value.Kind() != metrics.KindFloat64Histogram {
			return pauseSnapshot{}, ErrMetricUnavailable
		}
		histogram := sample.Value.Float64Histogram()
		var snapshot pauseSnapshot
		for i, count := range histogram.Counts {
			if count == 0 {
				continue
			}
			snapshot.count += count
			// Use the upper bound of the bucket as the representative pause.
			if i+1 < len(histogram.Buckets) {
				upper := histogram.Buckets[i+1]
				snapshot.total += upper * float64(count)
				if upper > snapshot.maxSeen {
					snapshot.maxSeen = upper
				}
			}
		}
		return snapshot, nil
	}
	return pauseSnapshot{}, ErrMetricUnavailable
}

// Recorder samples runtime memory repeatedly during a workload and reports the peak
// runtime-managed memory observed.
//
// # Why sample rather than read once
//
// A soft limit keeps the runtime near a target between collections, so a single reading
// before or after a workload says nothing about what happened during it. Peak matters
// because that is what approaches jetsam. Sampling in-process - rather than inferring a
// peak from toolchain log output - is the only way to observe it from inside the process
// being measured.
type Recorder struct {
	reader   *reader
	start    State
	startPau pauseSnapshot
	peak     uint64
	samples  int
}

// NewRecorder reads the starting state.
func NewRecorder() (*Recorder, error) {
	reader := newReader()
	start, err := reader.read()
	if err != nil {
		return nil, err
	}
	pauses, err := reader.pauses()
	if err != nil {
		return nil, err
	}
	return &Recorder{reader: reader, start: start, startPau: pauses, peak: start.RuntimeManagedBytes}, nil
}

// Sample records the current runtime-managed memory into the peak.
func (r *Recorder) Sample() {
	state, err := r.reader.read()
	if err != nil {
		return
	}
	r.samples++
	if state.RuntimeManagedBytes > r.peak {
		r.peak = state.RuntimeManagedBytes
	}
}

// Finish reads the ending state and returns the delta.
func (r *Recorder) Finish() (Delta, State, error) {
	end, err := r.reader.read()
	if err != nil {
		return Delta{}, State{}, err
	}
	endPauses, err := r.reader.pauses()
	if err != nil {
		return Delta{}, State{}, err
	}
	if end.RuntimeManagedBytes > r.peak {
		r.peak = end.RuntimeManagedBytes
	}

	delta := Delta{
		RuntimeManagedAtStart: r.start.RuntimeManagedBytes,
		RuntimeManagedAtEnd:   end.RuntimeManagedBytes,
		RuntimeManagedPeak:    r.peak,
		PauseCount:            endPauses.count - r.startPau.count,
		PauseMaxSeconds:       endPauses.maxSeen,
	}
	if end.GCCycles >= r.start.GCCycles {
		delta.GCCycles = end.GCCycles - r.start.GCCycles
	}
	if endPauses.total >= r.startPau.total {
		delta.PauseTotalSeconds = endPauses.total - r.startPau.total
	}
	return delta, end, nil
}

// Supported reports whether every metric this package needs is available on this runtime.
func Supported() bool {
	_, err := Read()
	return err == nil
}
