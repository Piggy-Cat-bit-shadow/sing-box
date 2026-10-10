package group

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Agent F, round 2: the counter TestRecheckSingleFlightCollapsesABurst says it is, but is not.
//
// # The claim
//
// urltest_recheck_test.go:89-91: "Many concurrent traffic failures must not create many recheck
// goroutines." And :119-123, defending the choice of instrument: "Counting probes would pass either
// way: the health function's own `checking` guard already collapses concurrent measurements, so a
// per-failure goroutine also produces one probe. What that design produces is one short-lived
// goroutine per failure, which is what this pins."
//
// # What the assertion actually is
//
//	require.LessOrEqual(t, group.recheckRuns.Load(), int32(2), ...)     // :128
//
// `recheckRuns` counts ROUNDS THAT RAN. MEASURED: with the single-flight guard in
// requestHealthRecheck defeated - so that every request in a burst sets the worker flag and spawns its
// own `drainHealthRechecks`, i.e. the per-failure goroutine the comment names - TestRecheckSingleFlight
// CollapsesABurst and TestTrafficFailureQueuesForcedRecheckBehindRunningCheck both still PASS. A
// SECOND guard downstream (the round's own `checking` flag) collapses the rounds, so the round counter
// cannot see a per-failure goroutine: the comment rejects one insensitive instrument and adopts
// another one.
//
// There is a second, smaller insensitivity: :128 reads the round count as soon as ONE probe has been
// observed (:116), not after the worker has drained. MEASURED, the final count under that mutation is
// 12 - above the bound of 2 - so the bound is discriminating in value but is read before the value
// exists. The handoff test already does this correctly (:197-201 waits for the worker to go idle).
//
// # What this file measures
//
// The instrument the comment describes: a package-scoped goroutine census, sampled at the peak of the
// burst while the probe is held open, so the per-failure workers are alive and countable. The correct
// product runs ONE worker for the whole burst; the defeat runs one per request.
//
// The control comes first so the census is proved sensitive before it is used to make a claim.

// agentFGroupGoroutines counts goroutines whose stacks name this package.
//
// The technique common/sniff and route adopted, with the caveat measured in
// common/sniff/agentf_census_slack_attack_test.go: a census read from a callback goroutine counts that
// callback's own frame, so readings are compared as peaks over a window rather than by exact equality.
func agentFGroupGoroutines() int {
	buffer := make([]byte, 1<<20)
	read := runtime.Stack(buffer, true)
	count := 0
	for _, block := range strings.Split(string(buffer[:read]), "\n\n") {
		if strings.Contains(block, "sing-box/protocol/group") {
			count++
		}
	}
	return count
}

// agentFPeakGoroutines samples the census for a window and returns the highest reading.
func agentFPeakGoroutines(window time.Duration) int {
	peak := 0
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if current := agentFGroupGoroutines(); current > peak {
			peak = current
		}
		time.Sleep(2 * time.Millisecond)
	}
	return peak
}

// agentFCountFrames counts goroutines whose stack names `frame`, which is how this file identifies the
// workers IT injected rather than inferring them from a difference.
func agentFCountFrames(frame string) int {
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

// agentFInjectedWorker is the body of the goroutines this control starts, as a NAMED function rather
// than a function literal.
//
// The frame has to be unambiguous: `group.TestAgentFGroupCensusIsSensitive` also matches the TEST
// goroutine, and a literal's suffix (`.func1`) depends on how many closures precede it in the function,
// which a later edit can silently renumber. MEASURED: with the test-function name as the pattern the
// count was 5 - the four workers plus the reader - and the superset assertion below then demanded a
// peak of 6 from a process that had 5.
func agentFInjectedWorker(entered chan<- struct{}, gate <-chan struct{}) {
	entered <- struct{}{}
	<-gate
}

// agentFInjectedWorkerFrame is the frame agentFInjectedWorker produces.
const agentFInjectedWorkerFrame = "group.agentFInjectedWorker"

// TestAgentFGroupCensusIsSensitive is the control: the census must move for workers it is supposed to
// see, or the bound it supports means nothing.
//
// # Why this does NOT compare against a baseline, which is a correction
//
// The first version took `baseline := agentFGroupGoroutines()` before injecting and required
// `peak >= baseline+4`. That assumes the process is otherwise quiet for the whole window, and inside
// the FULL package it is not: MEASURED, the same assertion read `baseline=4, peak=5` in a full-package
// `-race -count=3` run - three goroutines from earlier tests were still alive when the baseline was
// taken and exited while the four injected workers were being held, so the difference cancelled. It
// passed in isolation (baseline 1, peak 5) and failed in the package, which is the signature of an
// instrument measuring the process rather than the thing it names.
//
// The control now identifies its OWN workers by frame and asserts that the PACKAGE predicate is a
// superset of that count plus the reading goroutine. Leftover goroutines can only make the package
// count larger, so this direction cannot be cancelled by them - and the release assertion is stated as
// a DROP of four rather than a return to an absolute number, for the same reason.
func TestAgentFGroupCensusIsSensitive(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 4)
	for range 4 {
		go agentFInjectedWorker(entered, gate)
	}
	for range 4 {
		<-entered
	}

	peak := agentFPeakGoroutines(100 * time.Millisecond)
	injected := agentFCountFrames(agentFInjectedWorkerFrame)
	t.Logf("MEASURED injected 4 group-stack workers: identified by their own frame %d, package census "+
		"peak over the window %d", injected, peak)

	require.Equal(t, 4, injected,
		"the four injected workers must be alive and identifiable by their own frame, or this control "+
			"measures nothing at all")
	require.GreaterOrEqual(t, peak, injected+1,
		"the package census (peak %d) must count every goroutine the frame census counts (%d), plus "+
			"the goroutine that reads it; if it does not, the census cannot support any bound. Leftover "+
			"goroutines from other tests can only make this LARGER, so this direction is the one that "+
			"cannot be cancelled", peak, injected)

	// The release assertion is relative to a reading taken the SAME way while the workers are held, for
	// the same reason the entry assertion is not a baseline difference: an absolute number here would be
	// a claim about the whole process.
	//
	// It is polled from a PLAIN LOOP rather than from `require.Eventually`, and that is the second
	// correction this control needed: `agentFPeakGoroutines` counts every goroutine whose stack names
	// this package, and testify runs an `Eventually` condition on a goroutine of its own - so a reading
	// taken inside one is one HIGHER than the same reading taken on the test goroutine. MEASURED, the
	// release check compared a callback-frame reading (2) against a test-goroutine reading minus four
	// (1) and could never be satisfied. Both readings are now taken on the test goroutine.
	held := agentFPeakGoroutines(20 * time.Millisecond)
	close(gate)

	settled := 0
	deadline := time.Now().Add(5 * time.Second)
	for {
		settled = agentFPeakGoroutines(20 * time.Millisecond)
		if settled <= held-4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.LessOrEqual(t, settled, held-4,
		"the census must fall by at least the four released workers; it read %d with the workers held "+
			"(peak %d) and %d after releasing them", held, peak, settled)
}

// TestAgentFBurstMustNotCreateAWorkerPerFailure is the property, measured with a counter that moves.
func TestAgentFBurstMustNotCreateAWorkerPerFailure(t *testing.T) {
	release := make(chan struct{})
	node := &blockingRecheckOutbound{tag: "node-a", release: release}

	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	baseline := agentFGroupGoroutines()

	const burst = 100
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < burst; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			group.requestHealthRecheck()
		}()
	}
	close(start)
	waitGroup.Wait()

	// The probe is still held, so every worker the burst created is alive and countable.
	peak := agentFPeakGoroutines(300 * time.Millisecond)

	// The instrument must be armed, or the bound below is vacuous.
	require.Eventually(t, func() bool { return node.probes.Load() >= 1 },
		3*time.Second, 5*time.Millisecond,
		"the burst must actually cause a probe, or nothing is in flight to be counted")

	close(release)
	require.Eventually(t, func() bool {
		group.recheckAccess.Lock()
		defer group.recheckAccess.Unlock()
		return !group.recheckWorker
	}, 3*time.Second, 5*time.Millisecond, "the worker must finish so the count is final")

	// The bound: one coalesced worker for the whole burst, plus the tolerance the census needs for the
	// harness's own frames. One worker per failure would be ~100.
	const tolerance = 3
	t.Logf("MEASURED %d concurrent recheck requests: package goroutines %d -> peak %d (tolerance %d), "+
		"rounds that ran %d", burst, baseline, peak, tolerance, group.recheckRuns.Load())

	require.LessOrEqual(t, peak, baseline+tolerance,
		"%d concurrent traffic failures produced %d goroutines over a baseline of %d: the property is "+
			"that the burst coalesces into ONE worker, and a per-failure goroutine is exactly the storm "+
			"a health check exists to avoid", burst, peak, baseline)

	// Leave the package as it was found: a census test that walks away from 100 workers would poison
	// every later test in this package that counts anything.
	require.Eventually(t, func() bool { return agentFPeakGoroutines(20*time.Millisecond) <= baseline+1 },
		5*time.Second, 5*time.Millisecond,
		"the drain workers must have exited, or this test leaks into the rest of the package")
}
