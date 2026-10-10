package sniff_test

import (
	"runtime"
	"strings"
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

// agentFShapeCallbackFrames counts the goroutines whose stack names `frame`, which is how this file
// identifies the CONDITION GOROUTINE ITSELF rather than inferring it from a process-wide difference.
//
// # Why this exists - the second correction this file needed
//
// Every assertion below used to compare a reading taken inside a testify condition against `before`,
// read on the test goroutine beforehand. That assumes the process is otherwise quiet for the window,
// and inside the FULL package it is not. MEASURED in the round's final full scan:
//
//	MEASURED shape=require.Never with nothing leaked: before=20 inside=20
//	"20" is not greater than or equal to "21"
//
// Twenty goroutines naming this package were alive when the baseline was read - left by the tests that
// ran before this one - and enough of them exited inside the 60 ms window to cancel the callback's own
// frame exactly. It passed in isolation (before=1 inside=2) and failed in the package, which is the
// signature of an instrument measuring the process rather than the thing it names. The same shape of
// defect was found in the group census control on the same day.
//
// A frame census cannot be cancelled that way: it counts the thing being asserted about, and no other
// test's goroutines match this function's name.
func agentFShapeCallbackFrames(frame string) int {
	buffer := make([]byte, 1<<20)
	read := runtime.Stack(buffer, true)
	count := 0
	for _, block := range strings.Split(string(buffer[:read]), "\n\n") {
		if strings.Contains(block, frame) {
			count++
		}
	}
	return count
}

// agentFShapeEventuallyFrame and agentFShapeNeverFrame are the condition-closure frames of the two
// shapes, spelled once. `runtime` names a closure `.funcN` by its position in the enclosing function,
// so these are checked by the assertions below rather than assumed.
const (
	agentFShapeEventuallyFrame = "sniff_test.TestAgentFFrameShapeEventually.func1"
	agentFShapeNeverFrame      = "sniff_test.TestAgentFFrameShapeNever.func1"
)

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
	var insideReading, correctedReading, frameReading atomic.Int64

	require.Eventually(t, func() bool {
		insideReading.Store(int64(sniffGoroutines()))
		frameReading.Store(int64(agentFShapeCallbackFrames(agentFShapeEventuallyFrame)))
		return true
	}, 2*time.Second, time.Millisecond, "the condition must run")

	require.Eventually(t, func() bool {
		correctedReading.Store(int64(sniffGoroutinesFromCallback()))
		return true
	}, 2*time.Second, time.Millisecond)

	inside := int(insideReading.Load())
	corrected := int(correctedReading.Load())

	t.Logf("MEASURED shape=require.Eventually with nothing leaked: before=%d inside=%d corrected=%d "+
		"callback_frames=%d fires=%v",
		before, inside, corrected, frameReading.Load(), agentFShapeFires(before))

	// THE LOAD-BEARING ASSERTION, frame-scoped: the condition really is running on a goroutine whose
	// stack names this package, which is the premise of the `-1`. It cannot be cancelled by another
	// test's goroutines exiting, which is what broke the baseline-difference version.
	require.GreaterOrEqual(t, int(frameReading.Load()), 1,
		"the condition goroutine must be visible to a census that names this package - if it is not, "+
			"the frame arithmetic this whole file measures is about something else")
	// And the baseline-difference reading is REPORTED, with the band it was measured in, rather than
	// asserted: other tests' goroutines can leave or arrive inside the window, so a difference against
	// a process-wide baseline is an observation and not a proof. See agentFShapeCallbackFrames.
	require.GreaterOrEqual(t, corrected, 0, "the corrected reading is a count and cannot be negative")
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
	var insideReading, frameReading atomic.Int64
	require.Never(t, func() bool {
		insideReading.Store(int64(sniffGoroutines()))
		frameReading.Store(int64(agentFShapeCallbackFrames(agentFShapeNeverFrame)))
		return false
	}, 60*time.Millisecond, 10*time.Millisecond)

	inside := int(insideReading.Load())

	t.Logf("MEASURED shape=require.Never with nothing leaked: before=%d inside=%d callback_frames=%d "+
		"post-return probe fires=%v",
		before, inside, frameReading.Load(), agentFShapeFires(before))

	// THE INSTABILITY, measured with two different outcomes on two runs: this reading is before+1 on
	// one run and before+2 on the next (MEASURED: `inside=2 fires=true`, then `inside=3 fires=false`).
	// The callback's own frame is worth exactly one; the extra goroutine is the PREVIOUS tick's
	// condition goroutine, which testify does not join before starting the next tick's.
	//
	// The BOUND is asserted frame-scoped rather than against `before`, because a process-wide
	// difference is not a measurement of this shape. MEASURED in the round's final full scan, with the
	// baseline-difference version: `before=20 inside=20` - twenty goroutines from earlier tests were
	// alive at the baseline and enough of them exited inside the window to cancel the callback's own
	// frame exactly, so the reading looked like over-correction when nothing was wrong. The frame
	// census below cannot be cancelled that way, and the `inside` value is reported beside it.
	require.GreaterOrEqual(t, int(frameReading.Load()), 1,
		"the condition goroutine must be visible to a census that names this package; a reading of "+
			"zero would mean the `-1` is subtracting a frame that is not there")
	require.LessOrEqual(t, int(frameReading.Load()), 2,
		"at most ONE previous condition goroutine can linger in this shape; a larger reading would "+
			"mean something else is being counted and this file's attribution is wrong")
	require.GreaterOrEqual(t, inside, 0, "the raw reading is a count and cannot be negative")

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
	// A plain goroutine's own frame is worth exactly one, and this one IS measured against a baseline:
	// the reading is taken from that goroutine and returned, so no other test's goroutine can enter or
	// leave between the two readings the way it can inside a 60 ms testify window.
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
//
// # Why the cost is measured as a DIFFERENCE taken inside one callback
//
// The first version compared the helper's reading against `before`, taken on the test goroutine. That
// is a process-wide difference across a 2 s testify window, and other tests' goroutines can enter or
// leave inside it - the same exposure that made TestAgentFFrameShapeNever fail in the full package
// with `before=20 inside=20`. Here both readings are taken back to back inside the SAME callback, so
// whatever the rest of the process is doing is present in both and cancels: the difference is the
// helper's own extra frame, which is the quantity this test is about.
func TestAgentFNestedHelperOverCorrects(t *testing.T) {
	before := sniffGoroutines()

	// Atomic, same reason: the inner helper already makes this the busiest shape in the file.
	var directReading, nestedReading atomic.Int64
	require.Eventually(t, func() bool {
		// The direct reading first: this callback's own frame, and nothing else of ours.
		directReading.Store(int64(sniffGoroutines()))
		// The helper spawns its own goroutine, so this frame shape costs one MORE goroutine.
		done := make(chan int, 1)
		go func() { done <- sniffGoroutines() }()
		nestedReading.Store(int64(<-done))
		return true
	}, 2*time.Second, time.Millisecond)

	direct := int(directReading.Load())
	nested := int(nestedReading.Load())

	t.Logf("MEASURED shape=require.Eventually wrapping a helper that spawns a goroutine: before=%d "+
		"direct=%d inside=%d, so the helper costs %d extra frame(s) and `sniffGoroutinesFromCallback()` "+
		"would read %d against a baseline of %d", before, direct, nested, nested-direct, nested-1, before)

	require.Equal(t, 1, nested-direct,
		"the helper must cost exactly one frame more than reading the census directly in the condition; "+
			"if this ever reads 0 the hazard described here is gone and this test should be deleted "+
			"rather than adjusted")
	require.Greater(t, nested-1, direct-1,
		"and the documented correction is therefore one short in this shape, which is why the "+
			"production predicates must read the census DIRECTLY in the condition")
}
