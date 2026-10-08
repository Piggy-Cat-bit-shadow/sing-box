package route

import (
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
)

// resetWaitTimeout bounds the wait for a dispatched reset body. It is generous because the body runs
// behind a lock the test itself holds, and the failure it guards is "the transition was dropped", not
// "the transition was slow".
const (
	resetWaitTimeout  = 10 * time.Second
	resetPollInterval = 5 * time.Millisecond
)

// # Android handover: the generation must move once per real transition, and never less than once
//
// The Android adapter deduplicates the callbacks for one ConnectivityManager transition before they
// reach this layer (see experimental/libbox/handover_coalescing_test.go). What is left to prove here
// is the second half of the contract, at the layer that owns the epoch: a burst of notifications that
// DOES reach the manager must claim one generation, and a genuine network change must never be
// swallowed by that coalescing.
//
// # Why the burst is delivered while the reset lock is held
//
// notifyInterfaceUpdate claims the transition when it is DELIVERED and arms networkResetPending; the
// dispatched update consumes the flag when it reaches the reset lock. If the lock is free, a burst of
// platform callbacks can each be consumed before the next arrives, and the coalescing under test
// would not be exercised at all. Holding the lock is therefore not a trick: it is the situation the
// coalescing exists for - a reset body that is slow because the previous network's teardown is still
// running - and it makes the assertion deterministic instead of timing-dependent.

// TestHandoverNotificationBurstClaimsOneGeneration pins the coalescing.
func TestHandoverNotificationBurstClaimsOneGeneration(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	// Settle the fingerprint on a real interface and a known SSID. The first observation is itself a
	// transition (no environment -> a fingerprint), so it is taken as the baseline rather than
	// asserted about.
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	baselineGeneration := harness.manager.NetworkResetGeneration()
	baselineResets := harness.resetCount()

	// The previous reset body is still running, which is exactly when several platform callbacks for
	// one transition arrive together.
	harness.holdResetLock(t)

	for index := range 8 {
		harness.manager.notifyInterfaceUpdate(&control.Interface{Index: 1, Name: "en0"}, 0)
		require.GreaterOrEqual(t, harness.manager.NetworkResetGeneration(), baselineGeneration,
			"the epoch is monotonic; callback %d must not take it backwards", index)
	}

	require.Equal(t, baselineGeneration+1, harness.manager.NetworkResetGeneration(),
		"eight deliveries of one transition must claim exactly one generation: each additional claim "+
			"would be a reset storm for a single physical event")
	require.Equal(t, baselineResets, harness.resetCount(),
		"the reset body is running behind the lock; nothing may have reset yet")

	// Release the lock: the owning update performs the transition, once.
	close(harness.release)
	require.Eventually(t, func() bool {
		return harness.resetCount() == baselineResets+1
	}, resetWaitTimeout, resetPollInterval,
		"the coalesced transition must still run exactly one reset body")
	require.Equal(t, baselineGeneration+1, harness.manager.NetworkResetGeneration(),
		"consuming the pending transition must not claim a second generation")
}

// TestHandoverGenuineChangeAfterABurstIsNotSwallowed is the complementary invariant: coalescing may
// only drop REPEATS, never a real network change.
func TestHandoverGenuineChangeAfterABurstIsNotSwallowed(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	resetsBefore := harness.resetCount()

	// A burst that claims, then a real move behind the same interface: the device changed networks
	// (a different gateway, a different SSID) without the interface index changing, which is the
	// common Wi-Fi-to-Wi-Fi case. It must claim its own generation and run its own reset.
	harness.holdResetLock(t)
	harness.manager.notifyInterfaceUpdate(&control.Interface{Index: 1, Name: "en0"}, 0)
	generationAfterBurst := harness.manager.NetworkResetGeneration()

	close(harness.release)
	require.Eventually(t, func() bool {
		return harness.resetCount() == resetsBefore+1
	}, resetWaitTimeout, resetPollInterval, "the burst's transition must run")

	harness.setSSID("B")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, resetsBefore+2, harness.resetCount(),
		"a genuine environment change after a coalesced burst must still reset: coalescing may only "+
			"drop repeats, and dropping a real transition is the failure it must never have")
	require.Equal(t, generationAfterBurst+1, harness.manager.NetworkResetGeneration(),
		"the genuine change must claim exactly one later generation: the burst claimed the transition "+
			"it represented, and the new network is a second transition, not a repeat of the first")
}

// TestHandoverRepeatedGenuineChangesEachClaimOnce is the anti-swallow control: two real transitions
// are two generations and two resets, not one.
func TestHandoverRepeatedGenuineChangesEachClaimOnce(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	harness.setSSID("A")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	resetsBefore := harness.resetCount()
	generationBefore := harness.manager.NetworkResetGeneration()

	harness.setSSID("B")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})
	harness.setSSID("C")
	harness.manager.updateInterface(harness.manager.startedCtx, &control.Interface{Index: 1, Name: "en0"})

	require.Equal(t, resetsBefore+2, harness.resetCount())
	require.Equal(t, generationBefore+2, harness.manager.NetworkResetGeneration(),
		"two real transitions must claim exactly two generations: coalescing may only drop repeats")
}
