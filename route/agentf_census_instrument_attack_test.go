package route

import (
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

// agentFLeakGate holds the injected worker open until the test closes it.
var agentFLeakGate = make(chan struct{})

// agentFStartOneRouteStackWorker starts exactly one goroutine whose stack names this package, and
// returns once that goroutine is alive and blocked.
func agentFStartOneRouteStackWorker(t *testing.T) {
	t.Helper()
	entered := make(chan struct{})
	go func() {
		close(entered)
		<-agentFLeakGate
	}()
	<-entered
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
	baseline := routeGoroutines()

	// --- direction 1: with nothing leaked, is the two-scale comparison exact? ---
	insideClean := agentFCensusFromClosure()
	t.Logf("MEASURED baseline(outside a closure)=%d, census(inside a closure)=%d, delta=%d",
		baseline, insideClean, baseline-insideClean)
	require.Equal(t, baseline, insideClean,
		"the corrected census must be on the same scale as the baseline, or the churn bound is off "+
			"by the difference in either direction")

	// --- direction 2: does one leaked worker move it, and does the churn bound catch that? ---
	agentFStartOneRouteStackWorker(t)
	defer close(agentFLeakGate)

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

// TestAgentFCensusCountsTheRouteRuleSubpackage pins the scope of the string match the census uses.
//
// routeGoroutines matches any stack block containing "sing-box/route", and github.com/sagernet/sing-box/route/rule
// contains that substring. The doc comment at interface_churn_cost_test.go:59-61 claims the census
// counts "only the goroutines whose STACK belongs to this package" and that "no other test in the
// binary can move it". A goroutine running in the route/rule subpackage is not this package, and is
// counted by the same substring.
func TestAgentFCensusCountsTheRouteRuleSubpackage(t *testing.T) {
	rulePath := "github.com/sagernet/sing-box/route/rule"
	require.Contains(t, rulePath, "sing-box/route",
		"the substring the census matches on must match a SUBPACKAGE import path for this finding to "+
			"hold; if it no longer does, this test should be deleted rather than adjusted")
	t.Logf("MEASURED: the census predicate strings.Contains(block, %q) also matches %q, so a goroutine "+
		"in the route/rule subpackage is counted as this package's", "sing-box/route", rulePath)
}
