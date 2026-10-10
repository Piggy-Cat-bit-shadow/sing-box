package route

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

// Repeated interface changes must cost bounded work and must be REVERSIBLE, and this is the detector
// for the half of D7 that was not walked (section 13.7 recorded it as NOT RUN).
//
// # Why a churn test is not the same as the coalescing test
//
// `interface_transition_coalescing_test.go` proves that ONE physical transition carrying both reasons
// resets ONCE. It says nothing about what a SEQUENCE of transitions costs, which is the shape a device
// actually sees: a laptop moving between access points, a phone handing over between cells. The failure
// that shape produces is accumulation - a timer per event, a worker that outlives its transition, a
// reset body running in parallel with the next one - and none of those is visible in a single
// transition.
//
// # The three things asserted, and why each is separate
//
//  1. BOUNDED. Each transition is churned only after the previous one settled, so the expected number
//     of resets is exact rather than a bound. A drop below it means a transition was LOST; a rise above
//     it means one physical change cost more than one teardown.
//
//  2. SERIALISED. `countingRouter` records the maximum number of reset bodies inside the router's own
//     reset at one time. Anything above 1 is two transitions tearing the network down concurrently.
//
//     MEASURED while writing this, and it is why the claim is stated narrowly: removing the settle-wait
//     from the loop below - so that transitions overlap - leaves this test GREEN. Together with the
//     supersede test, the reason is visible: a newer notification CANCELS the in-flight update's
//     context, so only one transition ever reaches the reset at all. The serialisation observed here is
//     therefore guaranteed twice, by cancellation first and by the reset lock behind it, and this
//     assertion is meaningful only against the second - which `TestConcurrentResetNetworkIsSerialized`
//     exercises directly, with two resets dispatched from independent goroutines.
//
//     What this churn adds is that the guarantee still HOLDS once the path is driven end to end 25 times
//     through the real notifier and the real dispatcher, not that it is the only thing enforcing it.
//
//  3. REVERSIBLE. Once the churn stops the manager must report a settled network and the process must
//     hold no more goroutines than it started with. This is the half a "does it reset correctly" test
//     cannot see: work that accumulates and is never released still passes every count above.
//
// # The instrument, and why the global count is not it
//
// `runtime.NumGoroutine` is process-global: it moves with every other test in this binary, and it was
// caught doing exactly that while this test was being written - it reported "goroutines went from 2 to
// 2 ... and did not come back", a sentence that contradicts itself. That is the same weakness recorded
// in section 13.5, where an investigator's first probes "proved" safety from three green no-ops because they
// counted a number that had nothing to do with the code under test.
//
// So the census below counts only the goroutines whose STACK belongs to this package. A leak of one
// worker per transition is then one goroutine per transition in the number that is asserted, and no
// other test in the binary can move it. The bounded/serialised assertions above are the primary
// evidence and do not depend on this at all.
func TestRepeatedInterfaceChangesCostBoundedWorkAndAreReversible(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)

	// Establish the first fingerprint: publishing it is not a transition.
	harness.setSSID("churn-0")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	require.True(t, waitForTransitionStable(harness.manager, 5*time.Second),
		"the manager did not settle after establishing the first fingerprint, so no churn measurement "+
			"below would mean anything")

	// Settled before the churn starts, and remembered so the reversibility assertion compares like
	// with like.
	goroutinesBefore := routeGoroutines()
	resetsBefore := harness.resetCount()
	generationBefore := harness.manager.NetworkResetGeneration()
	require.True(t, harness.manager.NetworkTransitionStable(),
		"precondition: the network must be settled before the churn begins")

	const transitions = 25
	churnStarted := time.Now()
	for i := 1; i <= transitions; i++ {
		harness.setSSID(fmt.Sprintf("churn-%d", i))
		// The production entry: the platform's notification, which CLAIMS the transition and
		// dispatches the update goroutine.
		harness.markInterfaceResetPending()

		require.True(t, harness.router.waitForCount(resetsBefore+i, 10*time.Second),
			"transition %d of %d never completed: the reset count reached %d, expected %d",
			i, transitions, harness.router.count(), resetsBefore+i)

		// Wait for the transition to SETTLE before starting the next one, so the expected count is
		// exact: overlapping transitions legitimately coalesce, and this test is about cost rather
		// than about coalescing (which its own test pins).
		require.True(t, waitForTransitionStable(harness.manager, 10*time.Second),
			"transition %d settled the reset but left the network unstable, so the next transition "+
				"would be measured against a state the product does not consider settled", i)
	}

	// 1. BOUNDED: exactly one reset per transition, no more and no fewer.
	require.Equal(t, resetsBefore+transitions, harness.resetCount(),
		"%d sequential transitions produced %d resets: one physical change must cost exactly one "+
			"teardown, and a count above it means a burst of interface callbacks became a reset storm",
		transitions, harness.resetCount()-resetsBefore)
	t.Logf("MEASURED %d sequential transitions -> %d resets, %d serialised at a time at most, in %s",
		transitions, harness.resetCount()-resetsBefore, harness.router.maxSeen.Load(),
		time.Since(churnStarted).Round(time.Millisecond))

	// 2. SERIALISED: never two reset bodies at once across the whole churn.
	require.Equal(t, int32(1), harness.router.maxSeen.Load(),
		"two reset bodies were inside the router's reset at the same time during the churn; "+
			"concurrent teardown of the same network state is the interleaving the transition protocol "+
			"exists to prevent")

	// The epoch is a monotone reset epoch, not a count: it must have advanced, and it must not have
	// advanced once per notification rather than once per transition.
	require.Greater(t, harness.manager.NetworkResetGeneration(), generationBefore,
		"the reset epoch did not advance across %d real transitions", transitions)

	// 3. REVERSIBLE. Nothing accumulated and nothing is still running.
	require.True(t, harness.manager.NetworkTransitionStable(),
		"the network did not return to a settled state after the churn stopped")

	require.Eventually(t, func() bool {
		return routeGoroutinesFromClosure() <= goroutinesBefore
	}, 10*time.Second, 10*time.Millisecond,
		"goroutines whose stack belongs to this package did not return to their settled baseline of "+
			"%d across %d interface transitions (currently %d): one worker or timer per transition is "+
			"exactly the accumulation this test exists to catch",
		goroutinesBefore, transitions, routeGoroutines())

	// And the manager is still USABLE after the churn rather than merely quiet: one more transition
	// must still be performed.
	harness.setSSID("churn-after")
	harness.markInterfaceResetPending()
	require.True(t, harness.router.waitForCount(resetsBefore+transitions+1, 10*time.Second),
		"a transition after the churn was not performed: the manager stopped responding rather than "+
			"settling")
}

// waitForTransitionStable waits for the manager to report a settled network, polling rather than
// sleeping a fixed interval so a fast machine does not pay for a slow one. It is the join the churn
// loop needs: the reset count rises when the reset BODY runs, while the settled flag is restored by
// commitTransition afterwards, and the two are different moments.
func waitForTransitionStable(manager *NetworkManager, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if manager.NetworkTransitionStable() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return manager.NetworkTransitionStable()
}

// routeGoroutines counts the goroutines whose STACK names this package, rather than every goroutine in
// the process.
//
// # Why the scoped count is the only one worth asserting on
//
// A process-global count cannot distinguish "the code under test leaked a worker" from "another test in
// this binary started one", and in a full-package run the second is constant. The scoping is the same
// technique `common/sniff` adopted after a process-global leak check reported a leak in a test that had
// not leaked (section 10.10), and the one the D7 investigator used to answer the same question for
// transport/wireguard (section 13.5).
//
// A goroutine started BY this package but currently executing inside a dependency would not match, and
// that is the conservative direction: it under-counts, so it cannot invent an accumulation that is not
// there. The counts it does see are exact.
func routeGoroutines() int {
	buffer := make([]byte, 1<<20)
	read := runtime.Stack(buffer, true)
	count := 0
	for _, block := range strings.Split(string(buffer[:read]), "\n\n") {
		if strings.Contains(block, "sing-box/route") {
			count++
		}
	}
	return count
}

// routeGoroutinesFromClosure is routeGoroutines for a census taken from INSIDE a closure, and the
// subtraction is not cosmetic - it was found the hard way.
//
// A closure defined in this test file has this package in its own stack, so a census taken while it
// runs counts ITSELF and reports one more goroutine than the package really holds. The first version of
// this test polled from inside `require.Eventually` and was therefore unsatisfiable by construction: it
// read 2 against a baseline of 1 forever, and the failure message printed "did not return to their
// settled baseline of 1 ... (currently 1)", because the message's own argument was evaluated outside
// the closure where the true count is visible. The instrument was wrong, not the code under test.
//
// A goroutine is measured relative to what is running it, which is the general hazard of counting
// stacks rather than being told a number.
func routeGoroutinesFromClosure() int {
	return routeGoroutines() - 1
}
