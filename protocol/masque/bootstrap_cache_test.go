package masque

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// Tests for bootstrap resolution and the last-known-good cache.
//
// The behaviour being pinned is recovery, and every case is about the difference between
// "the resolver answered" and "the resolver could not be reached this time":
//
//	cold start, fresh fails        -> FAIL (never invent an address)
//	recovery, fresh succeeds       -> fresh first, cache merged behind it
//	recovery, fresh fails/times out/empty -> cached fallback
//	a candidate that connected     -> promoted, but still only for fallback
//
// The cold-start case is the one that matters for correctness rather than availability:
// falling back to a guess when nothing has ever worked would turn a configuration error
// into a confusing connection to the wrong host.

func staticResolve(addresses ...string) bootstrapResolution {
	return func(context.Context) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			out = append(out, netip.MustParseAddr(address))
		}
		return out, nil
	}
}

func failingResolve(err error) bootstrapResolution {
	return func(context.Context) ([]netip.Addr, error) { return nil, err }
}

func emptyResolve() bootstrapResolution {
	return func(context.Context) ([]netip.Addr, error) { return nil, nil }
}

// testResolver adapts the resolution helpers above to the bootstrapResolver the dialer
// takes, so these tests keep exercising the cache through the real wrapper.
type testResolver struct {
	resolve bootstrapResolution
}

func newTestResolver(resolve bootstrapResolution) *bootstrapResolver {
	return &bootstrapResolver{fqdnResolve: func(string) bootstrapResolution { return resolve }}
}

// TestBootstrapColdStartRequiresFreshResolution is the correctness case.
func TestBootstrapColdStartRequiresFreshResolution(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), failingResolve(errTestDialFailed))
	require.Error(t, err, "a cold start must fail when the resolver fails")
	require.Contains(t, err.Error(), "test: dial failed",
		"the real resolver error must reach the caller, not a synthesised one")

	_, err = cache.resolve(context.Background(), emptyResolve())
	require.Error(t, err, "an empty answer on a cold start must fail")
}

// TestBootstrapColdStartSucceeds proves the happy path, so the test above cannot pass by
// failing unconditionally.
func TestBootstrapColdStartSucceeds(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	addresses, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses)
}

// TestBootstrapFallsBackToCacheOnResolverFailure is the primary recovery test.
func TestBootstrapFallsBackToCacheOnResolverFailure(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	// A successful resolution first, establishing the cache.
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)

	// Now the resolver fails. The cached address must carry the reconnect.
	addresses, err := cache.resolve(context.Background(), failingResolve(errTestDialFailed))
	require.NoError(t, err, "a resolver failure during recovery must fall back to the cache")
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses)
}

func TestBootstrapFallsBackToCacheOnEmptyAnswer(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)

	addresses, err := cache.resolve(context.Background(), emptyResolve())
	require.NoError(t, err, "an empty fresh answer during recovery must fall back")
	require.Len(t, addresses, 1)
}

// TestBootstrapFreshTimeoutIsBounded proves a hanging resolver cannot stall a reconnect.
//
// Without the bound, a resolver that accepts the query and never answers would block the
// reconnect for as long as the system resolver allows, which is the 20-30 second stall
// this exists to avoid.
func TestBootstrapFreshTimeoutIsBounded(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)

	// A resolver that hangs until its context is cancelled.
	var observedDeadline bool
	hanging := func(ctx context.Context) ([]netip.Addr, error) {
		deadline, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline, "the fresh lookup must be given a deadline")
		remaining := time.Until(deadline)
		require.LessOrEqual(t, remaining, bootstrapFreshTimeout,
			"the deadline must not exceed the bound")
		observedDeadline = true
		<-ctx.Done()
		return nil, ctx.Err()
	}

	start := time.Now()
	addresses, err := cache.resolve(context.Background(), hanging)
	elapsed := time.Since(start)

	require.True(t, observedDeadline)
	require.NoError(t, err, "a timed-out fresh lookup must fall back to the cache")
	require.Len(t, addresses, 1)
	require.Less(t, elapsed, bootstrapFreshTimeout+2*time.Second,
		"the fallback must happen promptly after the bound, not after the system "+
			"resolver's own timeout")
}

// TestBootstrapFreshAnswerLeadsTheCache is the fresh-first ordering test.
//
// After a network change the previously working address may be unreachable, so a fresh
// answer must lead. An implementation that promoted the cached winner would keep
// retrying an address that no longer works.
func TestBootstrapFreshAnswerLeadsTheCache(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)
	// Record that the first address actually connected, making it the winner.
	cache.promote(netip.MustParseAddr("192.0.2.1"))

	// A later resolution returns a different address first.
	addresses, err := cache.resolve(context.Background(), staticResolve("198.51.100.1"))
	require.NoError(t, err)

	require.Equal(t, netip.MustParseAddr("198.51.100.1"), addresses[0],
		"a fresh answer must lead even when a cached winner exists; the network may "+
			"have changed since the winner was recorded")
	require.Contains(t, addresses, netip.MustParseAddr("192.0.2.1"),
		"the cached address must still be offered behind the fresh answer")
}

// TestBootstrapMergesAndDeduplicates proves the fresh and cached sets are merged without
// duplicates, which matters because a duplicate costs an extra connection attempt.
func TestBootstrapMergesAndDeduplicates(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1", "192.0.2.2"))
	require.NoError(t, err)

	// A second resolution repeats one address and adds another.
	addresses, err := cache.resolve(context.Background(), staticResolve("192.0.2.2", "192.0.2.3"))
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.1"),
	}, addresses, "fresh answers lead, cached ones follow, no duplicates")

	seen := make(map[netip.Addr]int)
	for _, address := range addresses {
		seen[address]++
	}
	for address, count := range seen {
		require.Equal(t, 1, count, "address %s appeared %d times", address, count)
	}
}

// TestBootstrapCacheIsBounded proves a hostile or misconfigured resolver cannot make the
// list grow without limit.
func TestBootstrapCacheIsBounded(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	for round := range 20 {
		addresses := make([]string, 0, 4)
		for offset := range 4 {
			addresses = append(addresses, "203.0.113."+strconv.Itoa(round*4+offset+1))
		}
		_, err := cache.resolve(context.Background(), staticResolve(addresses...))
		require.NoError(t, err)
	}
	require.LessOrEqual(t, cache.cachedCount(), defaultMaxBootstrapCandidates,
		"the cache must stay within its bound")
	require.Positive(t, cache.cachedCount())
}

// TestBootstrapPromoteMovesWinnerToTheFrontOfFallback covers winner promotion, and
// asserts the limit that matters: promotion affects FALLBACK order only.
func TestBootstrapPromoteMovesWinnerToTheFrontOfFallback(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1", "192.0.2.2", "192.0.2.3"))
	require.NoError(t, err)

	// The third address is the one that actually connected.
	cache.promote(netip.MustParseAddr("192.0.2.3"))

	// With the resolver unavailable, the winner leads the fallback.
	fallback, err := cache.resolve(context.Background(), failingResolve(errTestDialFailed))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("192.0.2.3"), fallback[0],
		"the address that connected must lead the fallback")

	// But a fresh answer still leads the winner.
	fresh, err := cache.resolve(context.Background(), staticResolve("198.51.100.9"))
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("198.51.100.9"), fresh[0],
		"promotion must not outrank a fresh resolution")
}

// TestBootstrapCacheSurvivesRepeatedRecovery proves the cache is not consumed by use,
// which is what makes a reconnect storm recoverable rather than merely the first retry.
func TestBootstrapCacheSurvivesRepeatedRecovery(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	_, err := cache.resolve(context.Background(), staticResolve("192.0.2.1"))
	require.NoError(t, err)

	for attempt := range 5 {
		addresses, resolveErr := cache.resolve(context.Background(), failingResolve(errTestDialFailed))
		require.NoError(t, resolveErr, "recovery attempt %d must succeed", attempt)
		require.Len(t, addresses, 1, "recovery attempt %d must still have the address", attempt)
	}
	require.True(t, cache.hasCache())
}

// TestBootstrapDialerPassesThroughIPDestinations proves the wrapper only changes
// behaviour for domain destinations.
//
// A dial to a literal address has nothing to resolve, and routing it through the cache
// would be both pointless and wrong: the cache is keyed to the server hostname.
func TestBootstrapDialerPassesThroughIPDestinations(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	cache := newBootstrapCache()
	wrapped := newBootstrapDialer(dialer, cache, newTestResolver(failingResolve(errTestDialFailed)))

	_, err := wrapped.DialContext(context.Background(), "tcp", M.ParseSocksaddr("192.0.2.7:443"))
	require.NoError(t, err)
	require.Equal(t, 1, dialer.dials)
	require.Equal(t, "192.0.2.7", dialer.last.Addr.String())
	require.Equal(t, 0, cache.cachedCount(),
		"an IP destination must not populate the bootstrap cache")
}

// TestBootstrapDialerResolvesAndPromotes proves the wrapper resolves a domain through the
// cache and records the address that connected.
func TestBootstrapDialerResolvesAndPromotes(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	cache := newBootstrapCache()
	wrapped := newBootstrapDialer(dialer, cache, newTestResolver(staticResolve("192.0.2.1")))

	_, err := wrapped.DialContext(context.Background(), "tcp", M.ParseSocksaddr("masque.example:443"))
	require.NoError(t, err)
	require.Equal(t, 1, dialer.dials)
	require.Equal(t, "192.0.2.1", dialer.last.Addr.String(),
		"the domain must have been resolved before dialling")
	require.Equal(t, 1, cache.cachedCount())
}

// TestBootstrapDialerForwardsResolutionErrors proves a hard resolution failure is
// reported rather than silently becoming something else.
func TestBootstrapDialerForwardsResolutionErrors(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{}
	cache := newBootstrapCache()
	wrapped := newBootstrapDialer(dialer, cache, newTestResolver(failingResolve(errTestDialFailed)))

	_, err := wrapped.DialContext(context.Background(), "tcp", M.ParseSocksaddr("masque.example:443"))
	require.Error(t, err)
	require.Equal(t, 0, dialer.dials,
		"a failed resolution must not produce a dial")
}

// TestBootstrapCacheIsRaceFree exercises resolve, record and promote concurrently.
//
// The cache is written on every successful resolution and read on every reconnect, and
// with on-demand or a network change those can overlap.
func TestBootstrapCacheIsRaceFree(t *testing.T) {
	t.Parallel()

	cache := newBootstrapCache()
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := range 500 {
			_, _ = cache.resolve(context.Background(), staticResolve(
				"203.0.113."+strconv.Itoa(round%250+1)))
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := range 500 {
			cache.promote(netip.MustParseAddr("203.0.113." + strconv.Itoa(round%250+1)))
		}
	}()
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			for range 500 {
				_, _ = cache.resolve(context.Background(), failingResolve(errTestDialFailed))
				_ = cache.hasCache()
				_ = cache.cachedCount()
			}
		}()
	}
	wg.Wait()
}
