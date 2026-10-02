package memmetrics

import (
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// ContinuousSampler observes runtime-managed memory repeatedly while a workload runs.
//
// # Why a ticker rather than sampling at workload boundaries
//
// A soft memory limit does not hold the runtime AT the limit; the runtime is allowed to
// overshoot between collections and then bring itself back. That means the peak is a
// transient, and a reading taken before or after a transfer cannot see it.
//
// The previous benchmark sampled once per completed 256 MiB copy - that is, only at workload
// BOUNDARIES. A spike in the middle of a copy, which is exactly where an overshoot happens,
// was invisible. The measured "peak" was really the peak of the boundary readings, and it
// understated the true peak by however much the workload rose and fell within a copy.
//
// A ticker samples on a fixed cadence for as long as the workload runs, so the peak reflects
// the whole interval rather than its edges.
//
// # Cost
//
// Each tick reads one runtime metric through metrics.Read, which is cheap but not free. The
// cadence is a parameter so its cost can be measured rather than assumed; see
// SamplerOverhead. The sampler is the SAME on both sides of an A/B comparison, so any overhead
// is shared - but it still has to be small enough not to change what it measures.
type ContinuousSampler struct {
	reader   *reader
	interval time.Duration

	stopOnce sync.Once
	stopped  chan struct{}
	done     chan struct{}

	peak uint64
	// ticks counts completed observations, so a caller can confirm sampling actually happened
	// rather than trusting that the goroutine was scheduled.
	ticks atomic.Uint64
	// startManaged is the first observed value, used to seed the peak so a workload that never
	// rises still reports its true level.
	startManaged uint64
}

// SamplerOptions configures a ContinuousSampler.
type SamplerOptions struct {
	// Interval is the sampling cadence. Zero selects DefaultSampleInterval.
	Interval time.Duration
}

// DefaultSampleInterval is the default cadence.
//
// 1ms is chosen to be far shorter than any allocation burst that could matter - a 256 MiB copy
// completes in tens of milliseconds even on a slow path - while remaining cheap enough that
// measuring it does not perturb the measurement. See SamplerOverhead.
const DefaultSampleInterval = time.Millisecond

// NewContinuousSampler starts sampling immediately and returns the running sampler.
//
// The caller MUST call Stop. Start and Stop are paired, and Stop waits for the sampling
// goroutine to exit, so no goroutine outlives the workload it was measuring.
func NewContinuousSampler(options SamplerOptions) (*ContinuousSampler, error) {
	interval := options.Interval
	if interval <= 0 {
		interval = DefaultSampleInterval
	}

	reader := newReader()
	initial, err := reader.readRuntimeManaged()
	if err != nil {
		return nil, err
	}

	sampler := &ContinuousSampler{
		reader:       reader,
		interval:     interval,
		stopped:      make(chan struct{}),
		done:         make(chan struct{}),
		peak:         initial,
		startManaged: initial,
	}

	go sampler.run()
	return sampler, nil
}

func (s *ContinuousSampler) run() {
	defer close(s.done)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopped:
			// One final observation, so a rise that happened between the last tick and the
			// stop is not lost.
			s.observe()
			return
		case <-ticker.C:
			s.observe()
		}
	}
}

func (s *ContinuousSampler) observe() {
	managed, err := s.reader.readRuntimeManaged()
	if err != nil {
		return
	}
	s.ticks.Add(1)
	if managed > s.peak {
		s.peak = managed
	}
}

// Stop halts sampling and waits for the goroutine to exit.
//
// It is safe to call more than once.
func (s *ContinuousSampler) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopped)
		<-s.done
	})
}

// Peak returns the highest runtime-managed value observed.
func (s *ContinuousSampler) Peak() uint64 {
	return s.peak
}

// Start returns the first observed value.
func (s *ContinuousSampler) Start() uint64 {
	return s.startManaged
}

// Ticks returns how many observations completed.
//
// A caller can use this to distinguish "the workload never rose" from "the sampler never ran",
// which otherwise look identical in the peak alone.
func (s *ContinuousSampler) Ticks() uint64 {
	return s.ticks.Load()
}

// readRuntimeManaged reads only the quantity GOMEMLIMIT accounts against.
//
// It uses a dedicated sample slice so it does not race a Recorder reading through its own.
func (r *reader) readRuntimeManaged() (uint64, error) {
	if r.managedSamples == nil {
		r.managedSamples = []metrics.Sample{
			{Name: metricRuntimeTotal},
			{Name: metricHeapReleased},
		}
	}
	metrics.Read(r.managedSamples)
	total := r.managedSamples[0]
	released := r.managedSamples[1]
	if total.Value.Kind() != metrics.KindUint64 || released.Value.Kind() != metrics.KindUint64 {
		return 0, ErrMetricUnavailable
	}
	return subtractManagingFloor(total.Value.Uint64(), released.Value.Uint64()), nil
}

// subtractManagingFloor subtracts without wrapping.
//
// The two metrics are read at slightly different instants, so released can momentarily exceed
// total. An unsigned subtraction would wrap to a value near 2^64 and be recorded as an
// enormous peak, which would look like a catastrophic overshoot.
func subtractManagingFloor(total uint64, released uint64) uint64 {
	if released >= total {
		return 0
	}
	return total - released
}

// SamplerOverhead measures the cost of the sampler itself.
//
// # Why this exists
//
// A sampler that changes what it measures is worse than no sampler, and "1ms ticks are
// probably cheap" is an assumption rather than a measurement. This reports how much a tick
// costs so the choice of cadence is defensible and so a report can state the overhead instead
// of asserting it is negligible.
//
// It returns the cost of a single observation. Callers comparing two configurations should
// note that the SAME cadence is used on both sides, so the overhead largely cancels - but it
// still has to be small relative to the workload.
func SamplerOverhead(iterations int) (time.Duration, error) {
	if iterations <= 0 {
		iterations = 1000
	}
	reader := newReader()
	if _, err := reader.readRuntimeManaged(); err != nil {
		return 0, err
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if _, err := reader.readRuntimeManaged(); err != nil {
			return 0, err
		}
	}
	return time.Since(start) / time.Duration(iterations), nil
}
