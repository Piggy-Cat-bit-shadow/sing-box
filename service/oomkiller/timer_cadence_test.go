package oomkiller

import (
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the fresh-start polling cadence (§11).
//
// # The window being closed
//
// A fresh timer polled at minInterval once and then jumped straight to maxInterval, because the
// first normal sample hit `if currentInterval == 0 { currentInterval = maxInterval }` and skipped
// the whole ladder. With the canonical policy - a 50 MiB budget, a 5 MiB margin, a 45 MiB
// trigger - that left ten seconds in which a native allocation burst of more than 5 MiB would
// never be observed by the only component that watches this process's phys_footprint.

// TestFreshStartRampsInsteadOfJumpingToMax is the §11 regression.
//
// It drives the REAL timer rather than a helper that mirrors it. An earlier version asserted on
// intervalScheduleForDiagnostics, which duplicated the logic under test - so it kept passing
// when the timer's own ladder was replaced with the old jump-to-ceiling behaviour, which is
// exactly the failure a regression test exists to catch.
func TestFreshStartRampsInsteadOfJumpingToMax(t *testing.T) {
	pressure := &atomic.Uint32{}
	timer := newPressureTestTimer(pressure)

	// Observe the interval the timer actually chooses, sample after sample, in the normal state.
	var schedule []time.Duration
	timer.access.Lock()
	for i := 0; i < 12; i++ {
		schedule = append(schedule, timer.intervalForState())
	}
	timer.access.Unlock()

	if len(schedule) < 2 {
		t.Fatal("expected a schedule")
	}
	if schedule[0] != timer.minInterval {
		t.Fatalf("the first interval = %v, want minInterval %v", schedule[0], timer.minInterval)
	}

	for i := 1; i < len(schedule); i++ {
		previous := schedule[i-1]
		current := schedule[i]
		if current > previous*2 {
			t.Fatalf("step %d jumps from %v to %v, more than a doubling; the ladder was skipped",
				i, previous, current)
		}
		if current < previous {
			t.Fatalf("step %d decreases from %v to %v", i, previous, current)
		}
		if current > timer.maxInterval {
			t.Fatalf("step %d = %v exceeds maxInterval %v", i, current, timer.maxInterval)
		}
	}

	// The specific defect: the second observation must not already be at the ceiling.
	if schedule[1] == timer.maxInterval {
		t.Fatalf("the second interval is already maxInterval %v; the ladder is being skipped",
			timer.maxInterval)
	}

	// And it must still reach the ceiling rather than polling fast forever.
	var reached bool
	for _, interval := range schedule {
		if interval == timer.maxInterval {
			reached = true
		}
	}
	if !reached {
		t.Fatalf("the ramp never reaches maxInterval: %v", schedule)
	}
	t.Logf("fresh-start schedule: %v", schedule)
}

// TestPressureReturnsToMinInterval confirms the ramp is not the only path back to fast polling.
//
// A growing process must leave the normal state and be observed at minInterval regardless of
// where the ramp currently is.
func TestPressureReturnsToMinInterval(t *testing.T) {
	pressure := &atomic.Uint32{}
	timer := newPressureTestTimer(pressure)

	// Walk the ramp up. The test timer's ceiling is its own maxInterval, which is what the
	// ramp must reach - not the package default, which this timer does not use.
	ceiling := timer.maxInterval
	for i := 0; i < 12; i++ {
		timer.access.Lock()
		timer.intervalForState()
		timer.access.Unlock()
	}
	timer.access.Lock()
	ramped := timer.currentInterval
	timer.access.Unlock()
	if ramped != ceiling {
		t.Fatalf("expected the ramp to reach the timer's own ceiling %v, got %v", ceiling, ramped)
	}

	// A pressure state must snap it back to the minimum.
	timer.access.Lock()
	timer.state = pressureStateArmed
	interval := timer.intervalForState()
	timer.access.Unlock()

	if interval != timer.minInterval {
		t.Fatalf("under pressure the interval = %v, want the timer's minInterval %v",
			interval, timer.minInterval)
	}
}

// TestRampCostIsBounded reports the wakeup cost of the ramp.
//
// The ramp must be cheap: it adds a bounded number of wakeups shortly after start, not a
// permanent fast poll. This measures that bound rather than asserting it.
func TestRampCostIsBounded(t *testing.T) {
	schedule := intervalScheduleForDiagnostics(defaultMinInterval, defaultMaxInterval, 64)

	var total time.Duration
	for _, interval := range schedule {
		total += interval
		if interval == defaultMaxInterval {
			break
		}
	}

	// Polling at minInterval for the same wall-clock span is the naive alternative.
	naivePolls := int(total / defaultMinInterval)
	rampPolls := 0
	var elapsed time.Duration
	for _, interval := range schedule {
		rampPolls++
		elapsed += interval
		if elapsed >= total {
			break
		}
	}

	if rampPolls > 16 {
		t.Fatalf("the ramp costs %d wakeups to reach the ceiling; expected a small bounded number",
			rampPolls)
	}
	t.Logf("reaching %v from start takes %d wakeups and %v; "+
		"polling at %v for the same span would take ~%d wakeups",
		defaultMaxInterval, rampPolls, total, defaultMinInterval, naivePolls)
}
