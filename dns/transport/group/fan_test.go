package group

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Tests for the fastest election, the fan's single-flight lock, and the record
// cap. They assert on observed member calls, so a broken flag that still happens
// to be "released" cannot pass.

func TestFastestColdStartElectsOnceUnderConcurrency(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b", "c"))
	release := make(chan struct{})
	// Only each member's FIRST call parks: that call is the election fan, which is what the burst
	// has to overlap with. Every later call - the concurrents' single attempts - answers at once.
	//
	// # Why the parking has to be per-member and not global
	//
	// An earlier version parked EVERY call until the release, which made the test's exact call count
	// depend on how quickly all the concurrents reached selection: a query that arrived after the
	// election had already been decided takes the sticky path, and while it still makes exactly one
	// call, the barrier ("at least expectedCalls have dispatched") could be satisfied before every
	// query had entered. The assertion then compared an exact count against a burst that had not
	// fully formed, and the test failed under load - in a full-suite run, never in isolation.
	//
	// Parking only the first call removes the timing dependence entirely: the fan is still
	// concurrent with the burst (it cannot finish until the release), every query makes exactly one
	// call, and a second election fan would still show up as three extra calls and fail.
	for _, fake := range harness.fakes {
		fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			return successResponse(message), nil
		})
		fake.setFirstCallBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case <-release:
				return successResponse(message), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}

	const queries = 8
	// One election fan of three members, then exactly one attempt for each of
	// the other queries: the window's concurrents go to a random clean member
	// instead of starting a fan of their own.
	const expectedCalls = 3 + queries - 1

	var waitGroup sync.WaitGroup
	errs := make(chan error, queries)
	for index := 0; index < queries; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			_, err := harness.transport.Exchange(ctx, queryMessage())
			errs <- err
		}()
	}

	// Barrier: every query has dispatched its calls and is parked on release, so
	// the election really is concurrent with the rest of the burst.
	waitFor(t, "the whole burst to dispatch", func() bool {
		return harness.totalCalls() >= expectedCalls
	})
	close(release)
	waitGroup.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, int64(expectedCalls), harness.totalCalls(),
		"a burst must run exactly ONE election fan: three calls for the fan plus one for each other query")
	require.False(t, harness.electionInFlight(), "the election flag must be released")
	require.NotEmpty(t, harness.current(), "the election winner must become current")
}

func TestFastestWinExpiryTriggersReelection(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b", "c"))
	harness.allSucceed()
	ctx := testContext(t)

	_, err := harness.exchange(ctx)
	require.NoError(t, err)
	winner := harness.current()
	require.NotEmpty(t, winner)
	harness.awaitTotalCalls(t, 3, "the cold-start election fan")
	require.Equal(t, 1, harness.liveWins(winner))

	// Age the win past win_ttl. No timer runs anywhere: the next selection simply
	// finds no live win and must measure again.
	harness.transport.access.Lock()
	harness.transport.records[winner].wins = []time.Time{time.Now().Add(-24 * time.Hour)}
	harness.transport.access.Unlock()
	require.Zero(t, harness.liveWins(winner))

	_, err = harness.exchange(ctx)
	require.NoError(t, err)
	harness.awaitTotalCalls(t, 6, "an expired win must force a fresh election fan")
}

func TestFastestWinnerFailureErasesWinsAndReelects(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b", "c"))
	harness.allSucceed()
	ctx := testContext(t)

	_, err := harness.exchange(ctx)
	require.NoError(t, err)
	winner := harness.current()
	require.Equal(t, 1, harness.liveWins(winner))

	harness.byTag[winner].fail()
	response, err := harness.exchange(ctx)
	require.NoError(t, err, "the rescue fan must answer after the winner failed")
	require.NotNil(t, response)
	require.Zero(t, harness.liveWins(winner), "a failure must erase the member's wins")
	require.Greater(t, harness.liveErrors(winner), 0)
	require.NotEqual(t, winner, harness.current(), "a new winner must be elected")
	require.Equal(t, 1, harness.liveWins(harness.current()))
	harness.awaitTotalCalls(t, 6,
		"the second query is one attempt against the failed winner plus a rescue fan of two")
}

func TestInterruptedElectionDoesNotLeakItsFlagOrPoisonFreshTables(t *testing.T) {
	t.Run("reset mid-fan", func(t *testing.T) {
		harness := newGroupHarness(t, fastestOptions("a", "b"))
		release := make(chan struct{})
		for _, fake := range harness.fakes {
			fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				select {
				case <-release:
					// A genuine failure observed after the amnesty: the fan's
					// own gen guard must drop it, not the cancellation guard.
					return nil, errFake
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			_, err := harness.transport.Exchange(ctx, queryMessage())
			result <- err
		}()
		waitFor(t, "both election probes to dispatch", func() bool {
			return harness.totalCalls() == 2
		})

		harness.transport.Reset()
		close(release)
		require.Error(t, <-result)
		waitFor(t, "the election flag to be released", func() bool {
			return !harness.electionInFlight()
		})
		require.Zero(t, harness.recordCount(),
			"a fan that began before Reset must not write into the amnestied tables")

		// The flag must really be reusable: a fresh query runs a new fan, which
		// it could not do if the abandoned election had leaked `election`.
		harness.allSucceed()
		_, err := harness.exchange(testContext(t))
		require.NoError(t, err)
		harness.awaitTotalCalls(t, 4,
			"the fresh query must fan again, so the interrupted election did not leak its flag")
	})

	t.Run("caller cancels", func(t *testing.T) {
		harness := newGroupHarness(t, fastestOptions("a", "b"))
		entered := make(chan struct{}, 2)
		for _, fake := range harness.fakes {
			fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
		}

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := harness.transport.Exchange(ctx, queryMessage())
			result <- err
		}()
		<-entered
		<-entered
		cancel()
		require.Error(t, <-result)
		waitFor(t, "the election flag to be released after caller cancellation", func() bool {
			return !harness.electionInFlight()
		})
		require.Zero(t, harness.recordCount(),
			"a cancellation the group itself caused must not be recorded as a member failure")

		harness.allSucceed()
		_, err := harness.exchange(testContext(t))
		require.NoError(t, err)
		harness.awaitTotalCalls(t, 4, "the flag must be reusable after a cancelled election")
	})
}

func TestDeadMemberRecordsAreCapped(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a"))
	harness.byTag["a"].fail()
	ctx := testContext(t)

	for index := 0; index < maxRecords*3; index++ {
		_, err := harness.exchange(ctx)
		require.Error(t, err)
	}
	require.Equal(t, maxRecords, harness.errorCount("a"),
		"hammering a dead member must keep its record list at the cap; counts above it change no decision "+
			"and an uncapped list grows without bound exactly where the network is already broken")
}
