package http

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// These tests cover the full-map behaviour of the unauthenticated limiter.
//
// The hazard being pinned: when the tracked-IP map is full, a flood of random
// source addresses must not turn every request into an O(tracked IPs) eviction
// scan under the mutex. The limiter fails closed for NEW sources instead, while
// leaving already-tracked sources and authenticated traffic untouched.

func newFullMapLimiter(t *testing.T, maxTracked int) *unauthenticatedLimiter {
	t.Helper()
	limiter := newUnauthenticatedLimiter(option.UnauthenticatedLimits{
		Enabled:            true,
		MaxConcurrentPerIP: 8,
		RequestsPerSecond:  10,
		Burst:              20,
		IdleTimeout:        10 * time.Minute,
		MaxTrackedIPs:      maxTracked,
	})
	require.NotNil(t, limiter)
	return limiter
}

func sourceAddress(i int) string {
	return fmt.Sprintf("10.%d.%d.%d:12345", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
}

func newSourceAddress(i int) string {
	return fmt.Sprintf("172.16.%d.%d:12345", (i>>8)&0xff, i&0xff)
}

// TestLimiterFullMapRejectsNewSourcesAndStaysBounded fills the map exactly, then
// floods it with new sources and asserts the tracked count never grows past the
// cap.
func TestLimiterFullMapRejectsNewSourcesAndStaysBounded(t *testing.T) {
	const maxTracked = 64
	limiter := newFullMapLimiter(t, maxTracked)
	now := time.Now()

	for i := range maxTracked {
		_, allowed := limiter.acquire(sourceAddress(i), now)
		require.True(t, allowed, "filling to the cap must admit source %d", i)
	}
	require.Equal(t, maxTracked, limiter.trackedCount())

	for i := range 10000 {
		_, allowed := limiter.acquire(newSourceAddress(i), now)
		require.False(t, allowed,
			"a new source must be refused while the map is full; source %d", i)
	}
	require.Equal(t, maxTracked, limiter.trackedCount(),
		"the tracked count must stay at the cap")
	require.Equal(t, 10000, limiter.capRejectionCount(),
		"every refused new source must be accounted as a cap rejection")
}

// TestLimiterFullMapDoesNotScanPerRequest proves each refused new source costs
// constant work: the sweep must not walk the whole map once per request.
//
// With maxTracked entries and N refused requests, an O(n)-per-request path would
// visit about n*N entries. The amortized design must stay far below that.
func TestLimiterFullMapDoesNotScanPerRequest(t *testing.T) {
	const maxTracked = 64
	const flood = 10000
	limiter := newFullMapLimiter(t, maxTracked)
	now := time.Now()

	for i := range maxTracked {
		limiter.acquire(sourceAddress(i), now)
	}
	// Reset the counter so only the flood is measured.
	baseline := limiter.visitedCount()

	for i := range flood {
		limiter.acquire(newSourceAddress(i), now)
	}

	visited := limiter.visitedCount() - baseline
	quadratic := maxTracked * flood
	require.Less(t, visited, quadratic/10,
		"the full-map path must not scan the map per request: visited %d, "+
			"an O(n)-per-request path would visit about %d", visited, quadratic)

	// The legitimate work is the amortized sweep, which may run at most about
	// flood/cleanupInterval times. Allowing a generous multiple of that pins the
	// ORDER of the work -- amortized rather than per-request -- without becoming
	// brittle about the exact counter value.
	amortizedAllowance := (flood/cleanupInterval + 2) * maxTracked * 2
	require.LessOrEqual(t, visited, amortizedAllowance,
		"expected only the amortized sweep to walk entries: visited %d, "+
			"allowance %d", visited, amortizedAllowance)
}

// TestLimiterFullMapPreservesTrackedSources proves a full map does not reset or
// displace the budget of a source that is already tracked. Otherwise an attacker
// could clear its own concurrency state by filling the map.
func TestLimiterFullMapPreservesTrackedSources(t *testing.T) {
	const maxTracked = 64
	limiter := newFullMapLimiter(t, maxTracked)
	now := time.Now()

	// Track a source and hold a concurrency slot on it.
	victim := sourceAddress(0)
	release, allowed := limiter.acquire(victim, now)
	require.True(t, allowed)
	require.Equal(t, 1, limiter.states[mustNormalize(t, victim)].concurrent)

	for i := range maxTracked - 1 {
		limiter.acquire(sourceAddress(i+1), now)
	}
	require.Equal(t, maxTracked, limiter.trackedCount())

	// Flood with new sources; the tracked source keeps its in-flight slot.
	for i := range 5000 {
		limiter.acquire(newSourceAddress(i), now)
	}
	require.Equal(t, 1, limiter.states[mustNormalize(t, victim)].concurrent,
		"a full map must not disturb an existing source's in-flight state")

	release()
	require.Equal(t, 0, limiter.states[mustNormalize(t, victim)].concurrent,
		"releasing must still work for a source that stayed tracked")

	// The victim is still tracked and still gets its own budget.
	_, allowed = limiter.acquire(victim, now)
	require.True(t, allowed, "an established source must keep working")
}

// TestLimiterFullMapDoesNotResetTokenBudget proves the token budget of a tracked
// source is not refreshed by an attacker filling the map.
func TestLimiterFullMapDoesNotResetTokenBudget(t *testing.T) {
	const maxTracked = 64
	limiter := newFullMapLimiter(t, maxTracked)
	now := time.Now()

	victim := sourceAddress(0)
	// Drain the victim's bucket.
	for range 20 {
		release, allowed := limiter.acquire(victim, now)
		if allowed {
			release()
		}
	}
	address := mustNormalize(t, victim)
	drained := limiter.states[address].tokens
	require.Less(t, drained, 1.0, "the bucket should be drained")

	for i := range maxTracked - 1 {
		limiter.acquire(sourceAddress(i+1), now)
	}
	for i := range 5000 {
		limiter.acquire(newSourceAddress(i), now)
	}

	require.Equal(t, drained, limiter.states[address].tokens,
		"filling the map must not refill an existing source's bucket")
}

// TestLimiterDisabledAccountsNothing is the authenticated-path guarantee: when
// the limiter is not enabled, no accounting happens at all.
func TestLimiterDisabledAccountsNothing(t *testing.T) {
	limiter := newUnauthenticatedLimiter(option.UnauthenticatedLimits{
		Enabled: false,
	})
	require.Nil(t, limiter, "a disabled limiter must not be constructed")
	require.Zero(t, limiter.accountedCount())
	require.Zero(t, limiter.trackedCount())
	release, allowed := limiter.acquire("203.0.113.9:5555", time.Now())
	require.True(t, allowed, "a nil limiter must admit everything")
	require.NotNil(t, release)
	release()
}

// TestLimiterFullMapConcurrentFloodStaysBounded exercises the full-map path from
// many goroutines so the bound and the counters hold under -race.
func TestLimiterFullMapConcurrentFloodStaysBounded(t *testing.T) {
	const maxTracked = 32
	limiter := newFullMapLimiter(t, maxTracked)
	now := time.Now()

	for i := range maxTracked {
		limiter.acquire(sourceAddress(i), now)
	}

	done := make(chan struct{})
	for worker := range 8 {
		go func(worker int) {
			defer func() { done <- struct{}{} }()
			for i := range 2000 {
				limiter.acquire(newSourceAddress(worker*100000+i), now)
			}
		}(worker)
	}
	for range 8 {
		<-done
	}

	require.LessOrEqual(t, limiter.trackedCount(), maxTracked,
		"the tracked count must never exceed the cap under concurrency")
}

func mustNormalize(t *testing.T, source string) netip.Addr {
	t.Helper()
	parsed, ok := normalizedIP(source)
	require.True(t, ok, "test source %q must normalize", source)
	return parsed
}
