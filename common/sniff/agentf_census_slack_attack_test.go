package sniff_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Agent F, round 2: convert the bounded-sensitivity claim about the sniff leak check into a
// MEASUREMENT.
//
// # The claim under attack
//
// sniff_stream_test.go:261 and :324 both assert:
//
//	require.Never(t, func() bool { return sniffGoroutines() > before+4 }, 200*time.Millisecond, 20*time.Millisecond)
//
// under the comment at :34-36 that counting this package's stacks "keeps the property the tests exist
// for - PeekStream must not leave a goroutine behind". The tolerance is +4, and the comment justifies
// the SCOPING of the count but never the SIZE of the tolerance.
//
// # The two frames, measured rather than argued
//
// `before` is read from the test goroutine (:248, :305), whose own stack names this package. testify
// evaluates the condition on a goroutine it creates, whose stack ALSO names this package. The first
// test below measures that difference instead of assuming it, because every conclusion about the
// tolerance depends on it: the predicate compares two readings taken from different frames.
//
// # Why a leak is injected rather than reasoned about
//
// "The tolerance hides up to three goroutines" is a claim about an instrument, and a counter that
// cannot be made to fail is not an instrument. A fixed, controllable leak is held open here and the
// production predicate is evaluated against it once per leak size, so the answer is the number of
// goroutines the check actually catches.
//
// The sampling below mirrors testify's own shape - a fresh goroutine per evaluation, the same 200ms
// window and 20ms tick - because that callback frame is part of what is being measured.

// agentFLeakGate holds every injected worker open until the test closes it.
var agentFLeakGate = make(chan struct{})

// agentFLeak starts exactly n goroutines blocked on gate, whose stacks name this test package, and
// returns once all of them are alive.
func agentFLeak(t *testing.T, n int, gate <-chan struct{}) {
	t.Helper()
	entered := make(chan struct{}, n)
	for range n {
		go func() {
			entered <- struct{}{}
			<-gate
		}()
	}
	for range n {
		<-entered
	}
}

// agentFCensusFromCallback reads the census from a goroutine created here, which is the frame testify's
// condition runs on.
func agentFCensusFromCallback() int {
	done := make(chan int, 1)
	go func() { done <- sniffGoroutines() }()
	return <-done
}

// agentFPredicateWouldFire evaluates the production predicate the way testify does - on a goroutine it
// creates, at the test's own 200ms window and 20ms tick - and reports whether it ever fired.
func agentFPredicateWouldFire(before int, window, tick time.Duration) bool {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		done := make(chan bool, 1)
		go func() { done <- sniffGoroutines() > before+4 }()
		if <-done {
			return true
		}
		time.Sleep(tick)
	}
	return false
}

// TestAgentFSniffCensusFramesDifferByOne measures the mismatch the tolerance has to absorb, with
// nothing injected: the same census, read from the test goroutine and from a callback goroutine.
func TestAgentFSniffCensusFramesDifferByOne(t *testing.T) {
	fromTest := sniffGoroutines()
	fromCallback := agentFCensusFromCallback()
	t.Logf("MEASURED with nothing injected: census from the test goroutine=%d, from a callback "+
		"goroutine=%d, delta=%d", fromTest, fromCallback, fromCallback-fromTest)
	require.Equal(t, fromTest+1, fromCallback,
		"the callback's own frame must account for exactly one goroutine; if it does not, the "+
			"arithmetic below is wrong and this file's conclusion is retracted")
}

// TestAgentFSniffCensusSlackIsMeasured reports, for a fixed leak of one, two, three and four
// goroutines, whether the production leak predicate catches it.
func TestAgentFSniffCensusSlackIsMeasured(t *testing.T) {
	// Exactly what the production tests do: the baseline is read from the test goroutine.
	before := sniffGoroutines()
	t.Logf("MEASURED baseline from the test goroutine: %d; the predicate is `> %d`, evaluated on a "+
		"callback goroutine that counts itself", before, before+4)

	defer close(agentFLeakGate)

	for _, n := range []int{1, 2, 3, 4} {
		// One gate per leak size, released before the next, so each measurement is of exactly n
		// workers rather than of the running total.
		gate := make(chan struct{})
		agentFLeak(t, n, gate)

		// The leak must be real and visible, or this attack proves nothing. Read from a callback
		// frame, so the expected value carries that frame: before (test goroutine) + n + 1.
		var raw int
		require.Eventually(t, func() bool {
			raw = sniffGoroutines()
			return raw == before+n+1
		}, 5*time.Second, 5*time.Millisecond,
			"the injected leak of %d never became visible to the raw census", n)

		fired := agentFPredicateWouldFire(before, 200*time.Millisecond, 20*time.Millisecond)

		t.Logf("MEASURED fixed leak of %d: census %d against a baseline of %d (the callback frame is "+
			"the +1), predicate `> %d` %s",
			n, raw, before, before+4, map[bool]string{true: "FIRED (caught)", false: "did NOT fire (hidden)"}[fired])

		if n <= 3 {
			require.False(t, fired,
				"a fixed leak of %d goroutines is supposed to be hidden by the +4 tolerance; if this "+
					"fires, the slack is narrower than measured and the finding is retracted", n)
		} else {
			require.True(t, fired,
				"a leak of %d must be caught: this predicate is the only leak check these two tests "+
					"have", n)
		}

		close(gate)
		require.Eventually(t, func() bool { return sniffGoroutines() == before+1 },
			5*time.Second, 5*time.Millisecond,
			"the workers of size %d were not released, so the next measurement would carry them", n)
	}
}

// TestAgentFSniffCensusReturnsToBaseline is the control for the control: the injected workers must be
// releasable, so "the census caught it" cannot be confused with "the census never comes back down".
func TestAgentFSniffCensusReturnsToBaseline(t *testing.T) {
	before := sniffGoroutines()
	leak := make(chan struct{})
	entered := make(chan struct{}, 3)
	for range 3 {
		go func() {
			entered <- struct{}{}
			<-leak
		}()
	}
	for range 3 {
		<-entered
	}
	require.Eventually(t, func() bool { return sniffGoroutines() == before+3+1 },
		5*time.Second, 5*time.Millisecond,
		"three workers must be visible to a callback-frame census")
	marker := agentFCensusFromCallback()
	t.Logf("MEASURED three workers injected: test-goroutine baseline %d, callback-frame census %d",
		before, marker)
	close(leak)
	// Read directly inside the closure, not through the helper: the helper would add a SECOND frame
	// on top of the callback testify already runs the condition on, and the expectation would be
	// wrong by one. That is the same trap this file exists to measure.
	require.Eventually(t, func() bool { return sniffGoroutines() == before+1 },
		5*time.Second, 5*time.Millisecond,
		"the census must return to its baseline once the workers are released, or it is not measuring "+
			"workers at all")
	t.Logf("MEASURED after release: census back to %d from the test goroutine (baseline %d)",
		sniffGoroutines(), before)
}
