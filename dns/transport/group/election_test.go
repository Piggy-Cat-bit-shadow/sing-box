package group

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Tests for the generation-owned fastest election.
//
// The election is a single-flight lock, and the tests below are about WHO owns
// that lock across a Reset. A bare bool is reset-or-not; a token carries the
// generation that minted it, so a fan from the old network can unwind without
// blocking the new network's election and without being able to release it.

// parkFirstCall installs behaviour that parks each member's FIRST call - which
// is exactly the election fan - on the returned channel, while later calls
// answer at once via succeed.
func parkFirstCall(harness *groupHarness, release <-chan struct{}) {
	for _, fake := range harness.fakes {
		fake.setFirstCallBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case <-release:
				return successResponse(message), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}
	harness.allSucceed()
}

// TestResetLetsNewGenerationElectWhileOldFanUnwinds is the lockout this task
// exists to remove.
//
// The old election is parked mid-fan, so its token is still set when Reset
// amnesties the network. The token's generation is now stale, which must be
// enough for the next query to start its OWN election immediately instead of
// being forced onto the provisional-random path until the old fan happens to
// unwind. electionCount makes that deterministic: it is bumped synchronously
// when a query takes the lock, so a second fan is provable without racing the
// old fan's goroutines.
func TestResetLetsNewGenerationElectWhileOldFanUnwinds(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	release := make(chan struct{})
	parkFirstCall(harness, release)

	oldResult := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		oldResult <- err
	}()
	waitFor(t, "the old election fan to dispatch", func() bool {
		return harness.totalCalls() == 2
	})
	require.True(t, harness.electionOwned(), "the cold-start query must own the election")
	require.Equal(t, uint64(1), harness.electionCount())

	harness.transport.Reset()

	// The old token is STILL SET here: the parked collector has not returned.
	// That is the point - the new generation must not need it to be cleared.
	require.True(t, harness.electionInFlight(), "the old collector must still own its token")
	require.False(t, harness.electionOwned(), "the old token must be stale after Reset")

	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	require.Equal(t, uint64(2), harness.electionCount(),
		"the new generation must mint its own election while the old fan is still unwinding")
	harness.awaitTotalCalls(t, 4,
		"two parked old probes plus the new generation's own two-probe fan; a provisional single attempt would leave the total at three")

	close(release)
	require.NoError(t, <-oldResult, "the old fan's participants succeed, so its own query still answers")
}

// TestStaleElectionReleaseCannotClearNewGeneration covers the other direction of
// ownership: a collector that finishes late may release its own token and
// nothing else. The stale release is invoked exactly as collectFan invokes it on
// its way out, after a fresh token has already been minted, and the new
// election must still be owned. Ownership is then checked functionally: a
// concurrent query must take the provisional single attempt, proving the lock
// is still held, rather than starting a second fan.
func TestStaleElectionReleaseCannotClearNewGeneration(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	release := make(chan struct{})
	for _, fake := range harness.fakes {
		fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case <-release:
				return successResponse(message), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}

	current := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		current <- err
	}()
	waitFor(t, "the new election fan to dispatch", func() bool {
		return harness.totalCalls() == 2
	})
	newToken := harness.electionToken()
	require.True(t, newToken.held())

	// The old collector's return, simulated at its exact release point.
	stale := electionToken{generation: newToken.generation - 1, id: newToken.id}
	harness.transport.releaseElection(stale)
	require.Equal(t, newToken, harness.electionToken(),
		"a collector may only release its own token; a stale one must leave the new election owned")

	// Ownership has to be functional, not just a field value: while the new
	// election is owned, a concurrent query is provisional - one attempt - and
	// must not start a second fan.
	harness.allSucceed()
	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	harness.awaitTotalCalls(t, 3,
		"an owned election must force a concurrent query onto the provisional single attempt")

	close(release)
	require.NoError(t, <-current)
}

// TestRepeatedResetKeepsElectionStartable is the sustained form of the lockout
// test: no number of Resets may leave the transport unable to elect, even with
// an old fan still parked across all of them.
func TestRepeatedResetKeepsElectionStartable(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	release := make(chan struct{})
	parkFirstCall(harness, release)

	oldResult := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		oldResult <- err
	}()
	waitFor(t, "the old election fan to dispatch", func() bool {
		return harness.totalCalls() == 2
	})

	for index := 0; index < 3; index++ {
		harness.transport.Reset()
	}
	require.False(t, harness.electionOwned(), "no Reset may leave a stale token owned")

	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	require.Equal(t, uint64(2), harness.electionCount(),
		"whatever the Reset count, the new generation must still be able to elect")

	close(release)
	require.NoError(t, <-oldResult)
}

// TestCallerCancelDuringElectionReleasesToken covers the abandoned election: the
// caller hung up while the fan was still running, so no winner was ever minted.
// The collector must still release the token on its way out, or one cancelled
// election would disable elections for the life of the transport.
func TestCallerCancelDuringElectionReleasesToken(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	entered := make(chan struct{}, 2)
	for _, fake := range harness.fakes {
		fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			return parkUntilDone(ctx, message)
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

	waitFor(t, "the election token to be released after caller cancellation", func() bool {
		return !harness.electionInFlight()
	})
	require.Zero(t, harness.electionToken(), "a cancelled election must not leak its token")
	require.Zero(t, harness.recordCount(), "the cancellation is local and must not be recorded")

	// Functional proof of release: a fresh query must be able to run a new fan.
	harness.allSucceed()
	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	require.Equal(t, uint64(2), harness.electionCount(), "the released token must be reusable")
	require.Positive(t, harness.liveWins(harness.current()), "the fresh election must mint a win")
}

// TestCloseDuringElectionReleasesToken is the shutdown form of the same
// property: the run context ends under the fan, the fan is abandoned, and the
// token must still be released - and nothing may be recorded as a member
// failure, because Close is a local lifetime, not an upstream one.
func TestCloseDuringElectionReleasesToken(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	entered := make(chan struct{}, 2)
	for _, fake := range harness.fakes {
		fake.setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			return parkUntilDone(ctx, message)
		})
	}

	result := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		result <- err
	}()
	<-entered
	<-entered
	require.NoError(t, harness.transport.Close())
	require.Error(t, <-result)

	waitFor(t, "the election token to be released after Close", func() bool {
		return !harness.electionInFlight()
	})
	require.Zero(t, harness.electionToken())
	require.Zero(t, harness.recordCount(), "Close is not a member failure")
}

// TestElectionOneFanPerGenerationUnderConcurrency is the -race stress: 8, 32 and
// 128 queries released together must still mint exactly ONE election per
// generation. electionCount is the deterministic witness - it is bumped under
// access at selection time, so a second fan cannot hide behind goroutine
// scheduling - and the total call count independently pins the fan's size.
func TestElectionOneFanPerGenerationUnderConcurrency(t *testing.T) {
	for _, queries := range []int{8, 32, 128} {
		t.Run(strconv.Itoa(queries), func(t *testing.T) {
			harness := newGroupHarness(t, fastestOptions("a", "b", "c"))
			harness.allSucceed()

			const members = 3
			expected := int64(members + queries - 1)

			runBurst := func() {
				var waitGroup sync.WaitGroup
				errs := make(chan error, queries)
				start := make(chan struct{})
				for index := 0; index < queries; index++ {
					waitGroup.Add(1)
					go func() {
						defer waitGroup.Done()
						<-start
						ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
						defer cancel()
						_, err := harness.transport.Exchange(ctx, queryMessage())
						errs <- err
					}()
				}
				close(start)
				waitGroup.Wait()
				close(errs)
				for err := range errs {
					require.NoError(t, err, "a burst query must be served, not starved by a lockout")
				}
			}

			runBurst()
			require.Equal(t, uint64(1), harness.electionCount(),
				"a cold-start burst must mint exactly one election")
			harness.awaitTotalCalls(t, expected,
				"one fan of three plus one attempt for each other query")
			waitFor(t, "the first generation's election to be released", func() bool {
				return !harness.electionInFlight()
			})

			// A network change drops the wins, so the next burst cold-starts
			// again and must mint exactly one election of its own.
			harness.transport.Reset()
			runBurst()
			require.Equal(t, uint64(2), harness.electionCount(),
				"the new generation must mint exactly one election, no more and no fewer")
			harness.awaitTotalCalls(t, 2*expected,
				"the second generation's single fan plus one attempt for each other query")
			waitFor(t, "the second generation's election to be released", func() bool {
				return !harness.electionInFlight()
			})
		})
	}
}
