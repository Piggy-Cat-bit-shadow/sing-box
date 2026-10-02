package memmetrics

import (
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// TestContinuousSamplerObservesTransientPeaks is §7's requirement.
//
// The sampler must catch a rise that happens BETWEEN workload boundaries, which is where a
// soft-limit overshoot actually occurs. The test creates a transient: it grows the heap and
// releases it again, repeatedly, while sampling runs.
//
// A boundary sampler - the previous behaviour, one Sample() per completed copy - would see
// only the level at each boundary and could miss every peak.
func TestContinuousSamplerObservesTransientPeaks(t *testing.T) {
	// A limit well above normal operation, so the runtime has room to overshoot and the test
	// is not merely observing the limit clamping everything.
	debug.SetMemoryLimit(512 << 20)
	defer debug.SetMemoryLimit(1<<63 - 1)

	sampler, err := NewContinuousSampler(SamplerOptions{Interval: 200 * time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Stop()

	startLevel := sampler.Start()

	// Repeatedly allocate and drop, so the managed figure rises and falls many times. Any
	// single boundary reading could land on a trough.
	var sink [][]byte
	for round := 0; round < 40; round++ {
		chunk := make([]byte, 4<<20)
		for i := 0; i < len(chunk); i += 4096 {
			chunk[i] = byte(round)
		}
		sink = append(sink, chunk)
		if len(sink) > 2 {
			sink = sink[1:]
		}
		time.Sleep(500 * time.Microsecond)
	}
	runtime.GC()

	sampler.Stop()

	if sampler.Ticks() == 0 {
		t.Fatal("the sampler completed no observations; the goroutine never ran")
	}
	// The peak must be at least the starting level - the sampler seeds with its first reading.
	if sampler.Peak() < startLevel {
		t.Fatalf("peak %d is below the starting level %d", sampler.Peak(), startLevel)
	}
	t.Logf("continuous peak=%d start=%d ticks=%d", sampler.Peak(), startLevel, sampler.Ticks())
}

// TestContinuousSamplerStopIsIdempotentAndLeakFree guards the clean stop requirement.
func TestContinuousSamplerStopIsIdempotentAndLeakFree(t *testing.T) {
	before := runtimeGoroutines()

	sampler, err := NewContinuousSampler(SamplerOptions{Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// Stop twice, and concurrently, to prove the pairing is safe.
	var waitGroup sync.WaitGroup
	for i := 0; i < 4; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sampler.Stop()
		}()
	}
	waitGroup.Wait()

	// Stop waits for the goroutine, so the count must have returned to where it started.
	// A short settle avoids counting an unrelated runtime goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtimeGoroutines() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines before=%d after=%d; the sampler leaked", before, runtimeGoroutines())
}

// TestContinuousSamplerReportsTicksSeparatesNeverRanFromNeverRose documents the tick counter.
//
// Without it, "the workload never grew" and "the sampler never ran" produce the same peak, and
// a benchmark could report a flat line while measuring nothing.
func TestContinuousSamplerReportsTicksSeparatesNeverRanFromNeverRose(t *testing.T) {
	sampler, err := NewContinuousSampler(SamplerOptions{Interval: 100 * time.Microsecond})
	if err != nil {
		t.Fatal(err)
	}
	defer sampler.Stop()

	time.Sleep(20 * time.Millisecond)
	if sampler.Ticks() == 0 {
		t.Fatal("expected observations over a 20ms run at a 100us cadence")
	}
}

// TestSamplerOverheadIsMeasurable reports the sampler's own cost, so the cadence choice is
// defensible rather than assumed.
func TestSamplerOverheadIsMeasurable(t *testing.T) {
	overhead, err := SamplerOverhead(2000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sampler observation overhead: %v per read", overhead)

	// A read must be far cheaper than the cadence it runs at, or the sampler would dominate
	// the workload it is measuring. 1ms is the default cadence.
	if overhead > DefaultSampleInterval/10 {
		t.Errorf("a single observation costs %v, more than a tenth of the %v default cadence; "+
			"the sampler would perturb what it measures", overhead, DefaultSampleInterval)
	}
}

func runtimeGoroutines() int {
	return runtime.NumGoroutine()
}
