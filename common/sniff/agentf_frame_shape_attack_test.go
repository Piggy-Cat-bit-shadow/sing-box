package sniff_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Agent F, round 4: attack the `-1` in `sniffGoroutinesFromCallback`.
//
// # The claim under attack
//
//	sniffGoroutinesFromCallback() > before
//
// where `sniffGoroutinesFromCallback` is `sniffGoroutines() - 1` and `before` is read on the TEST
// goroutine. The subtraction is documented as "the callback's own frame". If it is not exactly one in
// every frame shape a condition can run in, the predicate is either blind by that difference (a false
// green) or fires on a clean product (a false red).
//
// # Why each shape is measured in its own test
//
// A goroutine is counted once per STACK BLOCK, not once per matching frame, so a single callback
// goroutine should contribute exactly 1 whatever created it. My first version of this file measured
// all three shapes in one function and read `never = baseline + 2`, which contradicts the production
// predicates passing in the same binary - i.e. the reading was polluted by the shape measured before
// it, not by a defect. Each shape therefore gets its own test, its own baseline, and a settle, so a
// cross-shape artefact cannot be mistaken for a finding.
//
// The three shapes are require.Eventually's condition, require.Never's condition, and a plain
// `go func()`. The firing direction is sampled with a plain goroutine rather than with
// `require.Never`, because `require.Never` FAILS when its condition becomes true - using it to detect
// firing inverts the meaning and was the second bug in my first version.

// agentFLeak starts one goroutine whose stack names this package and returns its release.
func agentFShapeLeak(t *testing.T) func() {
	t.Helper()
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	go func() {
		entered <- struct{}{}
		<-gate
	}()
	<-entered
	return func() { close(gate) }
}

// agentFFires samples the production predicate on a plain goroutine.
func agentFShapeFires(before int) bool {
	done := make(chan bool, 1)
	go func() { done <- sniffGoroutinesFromCallback() > before }()
	return <-done
}

// agentFShapeSettle waits for the PRODUCTION corrected reading to reach an exact value, so each phase
// starts from a known state.
//
// It compares through `sniffGoroutinesFromCallback`, not `sniffGoroutines`: the comparison runs inside
// an Eventually closure, whose own frame the raw census would count. That is the same frame-arithmetic
// trap this file exists to measure, and my first version of this helper fell into it - the settle
// expectation was one goroutine short in every phase.
func agentFShapeSettle(t *testing.T, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return sniffGoroutinesFromCallback() == want },
		5*time.Second, 5*time.Millisecond,
		"the corrected census never settled at %d, so the next measurement would carry the last one", want)
}

func TestAgentFFrameShapeEventually(t *testing.T) {
	before := sniffGoroutines()

	// # Why these two are ATOMIC, and it is not defensive style
	//
	// The condition runs on a goroutine testify starts, and testify can have the PREVIOUS tick's
	// condition goroutine still exiting while the next one runs - that overlap is the whole subject of
	// this file. A plain `var inside int` written there and read on the test goroutine is therefore
	// written by two different goroutines and read by a third, and `-race -count=3` reports it:
	// MEASURED, `WARNING: DATA RACE ... Previous write at ... TestAgentFFrameShapeNever` from exactly
	// this pattern. The same instrument that found the instability found its own author's mistake.
	var insideReading, correctedReading atomic.Int64

	require.Eventually(t, func() bool {
		insideReading.Store(int64(sniffGoroutines()))
		return true
	}, 2*time.Second, time.Millisecond, "the condition must run")

	require.Eventually(t, func() bool {
		correctedReading.Store(int64(sniffGoroutinesFromCallback()))
		return true
	}, 2*time.Second, time.Millisecond)

	inside := int(insideReading.Load())
	corrected := int(correctedReading.Load())

	t.Logf("MEASURED shape=require.Eventually with nothing leaked: before=%d inside=%d corrected=%d fires=%v",
		before, inside, corrected, agentFShapeFires(before))
	require.Equal(t, before+1, inside,
		"in require.Eventually the callback's own frame must be worth exactly one goroutine")
	require.Equal(t, before, corrected, "the corrected reading must land on the baseline")
	require.False(t, agentFShapeFires(before), "nothing is leaked, so the predicate must not fire")

	release := agentFShapeLeak(t)
	defer release()
	agentFShapeSettle(t, before+1)
	require.True(t, agentFShapeFires(before), "one leaked goroutine must make the predicate fire")
}

func TestAgentFFrameShapeNever(t *testing.T) {
	before := sniffGoroutines()

	// Atomic for the reason spelled out in TestAgentFFrameShapeEventually: this is the shape where the
	// overlapping condition goroutines actually occur, so a plain variable here IS a data race.
	var insideReading atomic.Int64
	require.Never(t, func() bool {
		insideReading.Store(int64(sniffGoroutines()))
		return false
	}, 60*time.Millisecond, 10*time.Millisecond)

	inside := int(insideReading.Load())

	t.Logf("MEASURED shape=require.Never with nothing leaked: before=%d inside=%d post-return probe fires=%v",
		before, inside, agentFShapeFires(before))

	// THE INSTABILITY, measured with two different outcomes on two runs: this reading is before+1 on
	// one run and before+2 on the next (MEASURED: `inside=2 fires=true`, then `inside=3 fires=false`).
	// The callback's own frame is still worth exactly one; the extra goroutine is the PREVIOUS tick's
	// condition goroutine, which testify does not join before starting the next tick's. The old `+4`
	// allowance absorbed that, and an exact predicate cannot - so this asserts the BOUND rather than a
	// number, and the post-return probe is logged rather than asserted: the two readings are taken at
	// different instants, so no relationship between them can be pinned.
	require.GreaterOrEqual(t, inside, before+1,
		"the callback's own frame must be worth at least one goroutine; a reading at the baseline or "+
			"below would mean the `-1` over-corrects and the census is blind")
	require.LessOrEqual(t, inside, before+2,
		"at most ONE previous condition goroutine can linger in this shape; a larger reading would "+
			"mean something else is being counted and this file's attribution is wrong")

	release := agentFShapeLeak(t)
	defer release()
	agentFShapeSettle(t, before+1)
	require.True(t, agentFShapeFires(before),
		"a real one-goroutine leak must fire the predicate in this frame shape too")
}

func TestAgentFFrameShapePlainGoroutine(t *testing.T) {
	before := sniffGoroutines()

	done := make(chan int, 1)
	go func() { done <- sniffGoroutines() }()
	inside := <-done

	t.Logf("MEASURED shape=plain goroutine with nothing leaked: before=%d inside=%d fires=%v",
		before, inside, agentFShapeFires(before))
	require.Equal(t, before+1, inside,
		"a plain goroutine must be worth exactly one goroutine, the same as a callback frame")
	require.False(t, agentFShapeFires(before), "nothing is leaked, so the predicate must not fire")

	release := agentFShapeLeak(t)
	defer release()
	agentFShapeSettle(t, before+1)
	require.True(t, agentFShapeFires(before), "one leaked goroutine must make the predicate fire")
}

// TestAgentFNestedHelperOverCorrects pins the authoring hazard the `-1` creates, so a future test
// cannot fall into it silently: a helper that reads the census through a goroutine of its own adds a
// SECOND frame on top of testify's, and the correction is then one short.
func TestAgentFNestedHelperOverCorrects(t *testing.T) {
	before := sniffGoroutines()

	// Atomic, same reason: the inner helper already makes this the busiest shape in the file.
	var nestedReading atomic.Int64
	require.Eventually(t, func() bool {
		// The helper spawns its own goroutine, so this frame shape costs two goroutines, not one.
		done := make(chan int, 1)
		go func() { done <- sniffGoroutines() }()
		nestedReading.Store(int64(<-done))
		return true
	}, 2*time.Second, time.Millisecond)

	nested := int(nestedReading.Load())

	t.Logf("MEASURED shape=require.Eventually wrapping a helper that spawns a goroutine: before=%d "+
		"inside=%d, so `sniffGoroutinesFromCallback()` reads %d (a false read of one goroutine over "+
		"the baseline)", before, nested, nested-1)
	require.Equal(t, before+2, nested,
		"a nested helper costs two frames; if this ever reads before+1 the hazard described here is "+
			"gone and this test should be deleted rather than adjusted")
	require.Greater(t, nested-1, before,
		"and the documented correction is therefore one short in this shape, which is why the "+
			"production predicates must read the census DIRECTLY in the condition")
}
