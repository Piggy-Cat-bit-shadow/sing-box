package dns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Tests for the network-reset half of the reverse-mapping invalidation protocol.
//
// # The window these pin, and what is different about it
//
// reverse_mapping_atomicity_test.go pins the DNS-only source by stopping the recording side before it
// takes dnsEnvironmentAccess. That is not enough here, and the difference is the point.
//
// The commit's comparison and its writes were already one critical section, so no second lock
// acquisition could get between them. The gap this file is about was INSIDE the counter:
// ResetNetwork advanced networkGeneration with a plain atomic add that took no lock, and the purge
// that belongs to that advance happened at the END of the same function - after the transport resets
// and after the environment re-pin. So a commit could read the NEW counter value while the purge had
// not run yet:
//
//	commit:          takes dnsEnvironmentAccess, reads generation -> the NEW value (the bump is
//	                 lock-free, so the bump already happened even though ResetNetwork is not done)
//	commit:          captured == current, so the answer is accepted
//	commit:          writes the address-to-name pair
//	ResetNetwork:    ... reaches its purge and removes it
//
// Taken alone that ordering is harmless, and that is exactly why it survived: the purge does remove
// the entry. The damage is to a commit that runs BETWEEN two resets, or against a purge the commit
// cannot see - what the ordering actually breaks is the claim that "the advance and the purge are one
// barrier", which the function's own comment makes. With the purge separated from the advance, the
// barrier has a hole whose width is the whole transport-reset and re-pin body.
//
// # How the window is held open
//
// testReverseMappingComparisonHook fires after the comparison has been evaluated and while
// dnsEnvironmentAccess is held, so a test can stop the commit at precisely the state this ordering
// produced and run a REAL ResetNetwork from the other side. It is the same shape as the DNS-only file
// and it is the only seam that can observe a lock-free write to the counter.

// resetBoundaryTimeout bounds every wait in this file, so a broken seam fails with a reason instead of
// hanging until the package timeout.
const resetBoundaryTimeout = 10 * time.Second

// awaitSignal waits for a channel with a bounded timeout.
func awaitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(resetBoundaryTimeout):
		t.Fatal(message)
	}
}

// TestNetworkResetCannotLeaveARetiredAnswerBehind is the window, forced deterministically: the commit
// has passed its comparison and is about to write, and a real ResetNetwork runs to completion.
//
// The commit is stopped while it holds the lock, so the reset's purge has to wait for it - which is the
// property under test. Whichever order the two end up in, the retired answer must not survive.
func TestNetworkResetCannotLeaveARetiredAnswerBehind(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.41")
	transport := newMutableEnvironmentTransport("reset-window", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, transport)

	// Pin the environment so the reset below is a genuine transition rather than the first observation.
	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("retired.example", address)

	comparisonReached := make(chan struct{})
	comparisonRelease := make(chan struct{})
	router.testReverseMappingComparisonHook = func(captured, current uint64) {
		require.Equal(t, capturedGeneration, captured,
			"the seam must observe the commit's own captured epoch")
		require.Equal(t, capturedGeneration, current,
			"the premise of this test: the comparison matched, so only the ordering of the purge "+
				"stands between this answer and the cache")
		close(comparisonReached)
		<-comparisonRelease
	}

	commitDone := make(chan struct{})
	go func() {
		defer close(commitDone)
		router.recordReverseMappingFrom(message, response, transport, capturedGeneration)
	}()

	awaitSignal(t, comparisonReached,
		"the commit never reached its comparison, so the window this test is about was not entered")

	// A real network transition, from the other side, while the commit holds the lock.
	resetDone := make(chan struct{})
	go func() {
		defer close(resetDone)
		router.ResetNetwork()
	}()

	// The reset's purge must not be able to complete while the commit is inside its critical section:
	// that mutual exclusion is what makes "the advance and the purge are one barrier" true. Releasing
	// the commit and then letting the reset finish is the ordering that has to hold.
	select {
	case <-resetDone:
		t.Fatal("ResetNetwork completed while the commit held dnsEnvironmentAccess: the purging half " +
			"of the barrier is not serialised against the commit at all")
	case <-time.After(50 * time.Millisecond):
		// Expected: the reset is blocked on the lock. This is not a timing assertion about the product;
		// it is the observation that the commit's critical section and the reset's purge are mutually
		// exclusive, which is what the released code changed.
	}

	close(comparisonRelease)
	awaitSignal(t, commitDone, "the commit never finished")
	awaitSignal(t, resetDone, "the reset never finished")

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded,
		"an answer asked for on the network being left survived the transition that retired it: the "+
			"epoch advance and the purge are not one barrier, so a commit that reads the advanced "+
			"counter waits for nothing and writes an answer the purge was supposed to remove")
}

// TestReverseMappingLookupSeesAResetThatCompletesBeforeItReads pins the read side of the same rule: a
// lookup must never return a name that a completed reset has already retired.
func TestReverseMappingLookupSeesAResetThatCompletesBeforeItReads(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.42")
	transport := newMutableEnvironmentTransport("reset-read", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "before-reset.example")
	domain, loaded := router.LookupReverseMapping(address)
	require.True(t, loaded, "the premise: the answer was recorded")
	require.Equal(t, "before-reset.example", domain)

	router.ResetNetwork()

	domain, loaded = router.LookupReverseMapping(address)
	require.False(t, loaded,
		"route policy read %q after a completed network transition: the mapping describes a name "+
			"learned on the network the device has left", domain)
}

// TestResetNetworkStillAdvancesTheEpochFirstAndResetsTransportsAfter pins the parts of the reset the
// reordering was NOT allowed to change: the epoch is a barrier from its first instruction, the
// transports are still reset, and a DNS-only change still does none of it.
func TestResetNetworkStillAdvancesTheEpochFirstAndResetsTransportsAfter(t *testing.T) {
	transport := newMutableEnvironmentTransport("reset-order", "1.1.1.1:53")
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	generationBefore := router.dnsGeneration()
	environmentBefore := router.observeDNSEnvironment()

	router.ResetNetwork()

	require.Equal(t, generationBefore+1, router.dnsGeneration(),
		"a network transition must advance the network epoch exactly once")
	require.Equal(t, environmentBefore, router.observeDNSEnvironment(),
		"a network transition must not advance the DNS environment epoch: that counter belongs to a "+
			"resolver or search-domain change, which is a different event")
	require.EqualValues(t, 1, transport.resetCount.Load(),
		"a network transition must still reset the transports; that is what re-binds them to the new "+
			"network")
}

// TestClearCacheAlsoSerialisesWithTheCommit pins the third invalidation source. ClearCache purges the
// reverse mapping without advancing any epoch, so the only thing that can keep a concurrent commit out
// of the cache it just cleared is the same mutual exclusion - and that is what the commit now holds.
func TestClearCacheAlsoSerialisesWithTheCommit(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.43")
	transport := newMutableEnvironmentTransport("clear-cache", "1.1.1.1:53")
	transport.address = address
	router := newRouterForEnvironmentTest(t, transport)

	exchangeForEnvironmentTest(t, router, transport, "pin.example")
	capturedGeneration := router.dnsGeneration()
	message, response := answerWithAddresses("cleared.example", address)

	comparisonReached := make(chan struct{})
	comparisonRelease := make(chan struct{})
	router.testReverseMappingComparisonHook = func(captured, current uint64) {
		close(comparisonReached)
		<-comparisonRelease
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.recordReverseMappingFrom(message, response, transport, capturedGeneration)
	}()
	awaitSignal(t, comparisonReached, "the commit never reached its comparison")

	// ClearCache from the other side: it does not advance the generation, so if it were not
	// serialised against the commit's critical section the write below would land in the cache it
	// just cleared with nothing to remove it.
	clearDone := make(chan struct{})
	go func() {
		defer close(clearDone)
		router.ClearCache()
	}()
	select {
	case <-clearDone:
		t.Fatal("ClearCache completed while the commit held dnsEnvironmentAccess: a purge that does " +
			"not advance the generation has nothing else to order it against the write it must not " +
			"race")
	case <-time.After(50 * time.Millisecond):
	}

	close(comparisonRelease)
	awaitSignal(t, done, "the commit never finished")
	awaitSignal(t, clearDone, "ClearCache never finished")

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded, "an entry survived a completed ClearCache")
}
