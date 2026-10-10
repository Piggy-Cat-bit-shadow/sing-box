package route

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Agent F, round 1: attack on the goroutine census instrument in interface_churn_cost_test.go.
//
// # The claim under attack
//
// interface_churn_cost_test.go:125-131 asserts, inside `require.Eventually`:
//
//	routeGoroutinesFromClosure() <= goroutinesBefore
//
// where goroutinesBefore was taken OUTSIDE the closure (line 75) and routeGoroutinesFromClosure is
// routeGoroutines() - 1. The comment at :183-197 says the -1 corrects for the closure counting itself,
// and that before the correction the assertion was unsatisfiable by construction.
//
// The reverse hypothesis is that the correction is either wrong in the other direction, leaving a
// tolerance that hides a leak, or that it is right and the instrument is calibrated. Neither can be
// settled by reading: the caller's own frame is ALSO in the package, so whether the two numbers are on
// the same scale depends on what runtime.Stack reports for a goroutine blocked inside
// require.Eventually. This file measures it.
//
// # Why a leak is injected rather than argued about
//
// A counter that cannot be made to fail is not an instrument. A worker whose stack belongs to this
// package is held open here, so the census has a known, controllable amount of load to report.
//
// # The gate is per INVOCATION, and that is a correction
//
// It was a package-level channel closed by a `defer`, which is not re-runnable. Under `-count=2` the
// second repetition found the gate already closed, so its injected worker exited immediately, the
// baseline no longer moved, and the assertion below failed on a state the test itself had created -
// and the deferred close then PANICKED with `close of closed channel` on the way out, taking the rest
// of the package's repetitions with it. MEASURED: `go test -count=3 -run TestAgentF ./route` passed
// repetition 1, failed repetition 2, and panicked; `-count=1` was green. Since this round's own gate
// runs the whole suite under `-race -count=3`, a test that cannot survive repetition is a defect
// rather than a nuisance, and it is fixed here instead of being excluded from the gate.

// agentFStartOneRouteStackWorker starts exactly one goroutine whose stack names this package, and
// returns once that goroutine is alive and blocked. The returned function releases it and is
// idempotent, so no repetition can close a channel another one already closed.
func agentFStartOneRouteStackWorker(t *testing.T) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	entered := make(chan struct{})
	go func() {
		close(entered)
		<-gate
	}()
	<-entered
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}

// agentFStableBaseline reads the census until two consecutive readings agree, so a worker released by
// a PREVIOUS repetition cannot be counted as this one's baseline.
func agentFStableBaseline() int {
	previous := routeGoroutines()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		current := routeGoroutines()
		if current == previous {
			return current
		}
		previous = current
	}
	return previous
}

// agentFCensusFromClosure mirrors require.Eventually: the condition runs on a goroutine testify
// creates, which is what routeGoroutinesFromClosure's -1 exists to cancel out.
func agentFCensusFromClosure() int {
	done := make(chan int, 1)
	go func() { done <- routeGoroutinesFromClosure() }()
	return <-done
}

// TestAgentFChurnCensusIsCalibratedAndSeesOneLeakedWorker measures both directions of the instrument.
func TestAgentFChurnCensusIsCalibratedAndSeesOneLeakedWorker(t *testing.T) {
	// The churn test's baseline: taken from the test goroutine, outside any closure (line 75).
	baseline := agentFStableBaseline()

	// --- direction 1: with nothing leaked, is the two-scale comparison exact? ---
	insideClean := agentFCensusFromClosure()
	t.Logf("MEASURED baseline(outside a closure)=%d, census(inside a closure)=%d, delta=%d",
		baseline, insideClean, baseline-insideClean)
	require.Equal(t, baseline, insideClean,
		"the corrected census must be on the same scale as the baseline, or the churn bound is off "+
			"by the difference in either direction")

	// --- direction 2: does one leaked worker move it, and does the churn bound catch that? ---
	release := agentFStartOneRouteStackWorker(t)
	defer release()

	raw, insideLeaked := 0, 0
	require.Eventually(t, func() bool {
		raw = routeGoroutines()
		insideLeaked = routeGoroutinesFromClosure()
		return raw >= baseline+1
	}, 5*time.Second, 5*time.Millisecond,
		"the injected worker never became visible to the raw census, so this attack proves nothing")

	t.Logf("MEASURED with one injected route-stack worker: raw census=%d (baseline %d), "+
		"census(inside a closure)=%d, churn bound is `<= %d`", raw, baseline, insideLeaked, baseline)

	require.Equal(t, raw-1, insideLeaked,
		"the closure correction must be exactly one goroutine, or the two numbers are on different scales")

	// The churn test's own condition, evaluated the way the churn test evaluates it. If this is
	// satisfied with one worker leaked, the reversibility assertion cannot see a one-worker leak.
	satisfied := agentFCensusConditionHolds(baseline)
	require.False(t, satisfied,
		"the churn test's reversibility condition (`census <= baseline`) was satisfied while one "+
			"package worker was still running, so a single leaked worker per run is invisible to it")

	// And the raw count, uncorrected, is what would have caught it -- which is the measurement the
	// message argument takes, from the test goroutine rather than from the polling closure.
	require.Greater(t, raw, baseline,
		"the uncorrected census does move by one; only the corrected comparison has to be exact")
}

// agentFCensusConditionHolds runs the churn test's condition (interface_churn_cost_test.go:126)
// verbatim, on its own goroutine, and reports whether it was ever satisfied.
func agentFCensusConditionHolds(baseline int) bool {
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		done := make(chan bool, 1)
		go func() { done <- routeGoroutinesFromClosure() <= baseline }()
		if <-done {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// DELETED: TestAgentFCensusCountsTheRouteRuleSubpackage.
//
// That test pinned a real flaw - `routeGoroutines` matched the bare substring "sing-box/route", which
// is also a prefix of the `route/rule` subpackage's import path, so a goroutine owned by another
// package could move this package's leak assertion. The flaw is FIXED: `routeGoroutines` now matches
// `routePackageFrame` = "github.com/sagernet/sing-box/route.", whose trailing dot is the frame
// boundary.
//
// The old test's body asserted `require.Contains(rulePath, "sing-box/route")` - a statement about two
// string constants, not about the census - so once the predicate changed it kept passing while its
// logged claim ("the census predicate ... also matches ..., so a goroutine in the route/rule subpackage
// is counted as this package's") had become FALSE. A test whose message no longer describes the code
// is the exact defect this round exists to remove, and the adversary who wrote it authorised deletion
// over adjustment for precisely this case.
//
// The property is not lost: `route/census_scope_test.go` pins it against the REAL predicate
// (`routeStackBlockCounts`) on the frame shapes `runtime.Stack` produces, keeps the old predicate
// in-file as the discriminating control that shows what it used to accept, and adds a sensitivity
// control proving the narrowed census still moves by exactly one for a goroutine this package starts.
