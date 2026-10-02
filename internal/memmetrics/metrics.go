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
	"runtime"
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
	// PauseTotalNs is the EXACT cumulative stop-the-world pause time for this interval, from
	// runtime.MemStats.PauseTotalNs - an integer nanosecond counter the runtime maintains.
	//
	// It replaces a histogram-based estimate. Summing bucket upper bounds times counts can only
	// overstate, by up to one bucket width per pause, and reporting that as a total conflated a
	// measurement with a bound.
	PauseTotalNs uint64
	// PauseCount is how many pauses this interval produced, from the histogram delta.
	PauseCount uint64
	// PauseMaxUpperBound is the largest bucket UPPER BOUND among this interval's pauses.
	//
	// It is an upper bound, not a measured maximum. The runtime publishes pauses as a
	// histogram and does not expose a true maximum, so this is the tightest honest statement
	// available - and the name says so rather than calling it "max pause".
	PauseMaxUpperBound float64
	// PauseUpperBoundTotal is the histogram estimate for this interval. Advisory, and strictly
	// less trustworthy than PauseTotalNs.
	PauseUpperBoundTotal float64
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
//
// # Why the per-bucket counts are kept
//
// A cumulative histogram describes the whole process, so its largest bucket says nothing about
// THIS benchmark: the worst pause may belong to a collection that finished before the run
// started. Keeping the counts lets Finish subtract the starting histogram and describe only the
// pauses this run produced.
//
// # What the total means
//
// histogramUpperBoundTotal sums bucket UPPER BOUNDS times counts. It is an approximation, named
// accordingly, and can only overstate a pause by at most one bucket width per sample. It is
// recorded for the distribution and must never be reported as an exact pause total.
type pauseSnapshot struct {
	counts  []uint64
	buckets []float64
	count   uint64
	// histogramUpperBoundTotal is an approximation, not a measured total.
	histogramUpperBoundTotal float64
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

		snapshot := pauseSnapshot{
			counts:  make([]uint64, len(histogram.Counts)),
			buckets: make([]float64, len(histogram.Buckets)),
		}
		copy(snapshot.counts, histogram.Counts)
		copy(snapshot.buckets, histogram.Buckets)

		for i, count := range histogram.Counts {
			if count == 0 {
				continue
			}
			snapshot.count += count
			// The bucket's UPPER bound, used only as a representative value. This is an
			// approximation and the field name says so.
			if i+1 < len(histogram.Buckets) {
				snapshot.histogramUpperBoundTotal += histogram.Buckets[i+1] * float64(count)
			}
		}
		return snapshot, nil
	}
	return pauseSnapshot{}, ErrMetricUnavailable
}

// intervalPauseStats describes ONLY the pauses that happened between two snapshots.
type intervalPauseStats struct {
	// Count is how many pauses this interval produced.
	Count uint64
	// MaxUpperBound is the largest bucket UPPER BOUND among the interval's pauses.
	//
	// It is an upper bound, not a measured maximum: a pause recorded in the bucket [a,b) could
	// be anywhere in that range. The name says so, because reporting it as "max pause" would
	// overstate it by up to one bucket width.
	MaxUpperBound float64
	// UpperBoundTotal is the sum of bucket upper bounds times counts, for this interval only.
	UpperBoundTotal float64
}

// interval computes the pauses attributable to the span between two snapshots.
//
// # Why not use the end histogram's largest bucket
//
// The end histogram describes the PROCESS, not the run. A benchmark starting after a large
// collection inherits that collection's slowest pause as its own maximum, which makes every run
// look alike and hides the very regression being measured.
//
// Subtracting bucket counts isolates the interval: a bucket contributes only if its count GREW,
// and the interval maximum is the largest bucket that grew.
func (s pauseSnapshot) interval(previous pauseSnapshot) intervalPauseStats {
	var stats intervalPauseStats
	for i, count := range s.counts {
		var previousCount uint64
		if i < len(previous.counts) {
			previousCount = previous.counts[i]
		}
		if count <= previousCount {
			continue
		}
		added := count - previousCount
		stats.Count += added

		if i+1 < len(s.buckets) {
			upper := s.buckets[i+1]
			stats.UpperBoundTotal += upper * float64(added)
			if upper > stats.MaxUpperBound {
				stats.MaxUpperBound = upper
			}
		}
	}
	return stats
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
	// startPauseTotalNs is the exact cumulative pause counter at the start, so the interval
	// total can be computed by subtraction.
	startPauseTotalNs uint64
	peak              uint64
	samples           int
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
	var memoryStats runtime.MemStats
	runtime.ReadMemStats(&memoryStats)
	return &Recorder{
		reader:            reader,
		start:             start,
		startPau:          pauses,
		startPauseTotalNs: memoryStats.PauseTotalNs,
		peak:              start.RuntimeManagedBytes,
	}, nil
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

	interval := endPauses.interval(r.startPau)

	delta := Delta{
		RuntimeManagedAtStart: r.start.RuntimeManagedBytes,
		RuntimeManagedAtEnd:   end.RuntimeManagedBytes,
		RuntimeManagedPeak:    r.peak,
		PauseCount:            interval.Count,
		// The interval's largest bucket UPPER BOUND. Named as an upper bound because that is
		// what it is: a pause in bucket [a,b) could be anywhere in that range, so this
		// overstates by up to one bucket width.
		PauseMaxUpperBound: interval.MaxUpperBound,
		// An approximation, kept for the distribution only.
		PauseUpperBoundTotal: interval.UpperBoundTotal,
	}
	if end.GCCycles >= r.start.GCCycles {
		delta.GCCycles = end.GCCycles - r.start.GCCycles
	}

	// The EXACT cumulative stop-the-world pause total comes from runtime.MemStats, which
	// reports it as an integer nanosecond counter maintained by the runtime itself.
	//
	// The histogram cannot supply this. Summing bucket upper bounds times counts is an
	// estimate that can only overstate, and the previous code reported that estimate under a
	// name - PauseTotalSeconds - that claimed exactness. A benchmark comparing two
	// configurations on an inflated, quantised figure is comparing bucket widths as much as
	// pause behaviour.
	var memoryStats runtime.MemStats
	runtime.ReadMemStats(&memoryStats)
	endPauseTotalNs := memoryStats.PauseTotalNs
	if endPauseTotalNs >= r.startPauseTotalNs {
		delta.PauseTotalNs = endPauseTotalNs - r.startPauseTotalNs
	}
	return delta, end, nil
}

// Supported reports whether every metric this package needs is available on this runtime.
func Supported() bool {
	_, err := Read()
	return err == nil
}
