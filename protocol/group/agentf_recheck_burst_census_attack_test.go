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

// TestAgentFGroupCensusIsSensitive is the control: the census must move for workers it is supposed to
// see, or the bound it supports means nothing.
func TestAgentFGroupCensusIsSensitive(t *testing.T) {
	baseline := agentFGroupGoroutines()

	gate := make(chan struct{})
	entered := make(chan struct{}, 4)
	for range 4 {
		go func() {
			entered <- struct{}{}
			<-gate
		}()
	}
	for range 4 {
		<-entered
	}

	peak := agentFPeakGoroutines(100 * time.Millisecond)
	t.Logf("MEASURED injected 4 group-stack workers: census from this frame %d, peak over the window %d",
		baseline, peak)
	require.GreaterOrEqual(t, peak, baseline+4,
		"four injected workers whose stacks name this package must be visible to the census; if they "+
			"are not, the census cannot support any bound")

	close(gate)
	require.Eventually(t, func() bool { return agentFPeakGoroutines(20*time.Millisecond) <= baseline+1 },
		5*time.Second, 5*time.Millisecond,
		"and the census must come back down once they are released")
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
