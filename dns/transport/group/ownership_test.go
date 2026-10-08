package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"

	mDNS "github.com/miekg/dns"
)

// Tests for the ownership split between the lifetimes that can end an exchange.
//
// The property under test is not "cancellation is ignored". It is that the
// group records a member failure only for a failure it may attribute to the
// member, and that the group's OWN sub-deadline - the blackhole detector - is
// attributed to the member every time. A blanket exemption for
// context.DeadlineExceeded would pass the first kind of test and silently break
// the second, which is why the two appear side by side here.

// parkUntilDone blocks the exchange until its context ends and then reports the
// context error, mirroring a blackholed upstream: the only thing that ends the
// call is the context, and it is the caller's or the group's own deadline that
// has to be told apart.
func parkUntilDone(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCallerCancellationDoesNotRecordMemberFailure covers the first LOCAL
// lifetime: the client gave up. The target never answered because nobody was
// waiting any more, so an error record would let one cancelled client shrink the
// clean set and mark a healthy server dirty.
func TestCallerCancellationDoesNotRecordMemberFailure(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a"))
	entered := make(chan struct{}, 1)
	harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		return parkUntilDone(ctx, message)
	})

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(ctx, queryMessage())
		result <- err
	}()
	<-entered
	cancel()
	require.Error(t, <-result)
	require.Zero(t, harness.recordCount(),
		"a caller cancellation is a LOCAL lifetime ending and must write no error record")
	require.Zero(t, harness.errorCount("a"))
}

// TestCloseDoesNotRecordMemberFailure covers the other LOCAL lifetime: the
// transport's own run context, cancelled by Close. The member did not fail; the
// box is being torn down.
func TestCloseDoesNotRecordMemberFailure(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a"))
	entered := make(chan struct{}, 1)
	harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		return parkUntilDone(ctx, message)
	})

	// No caller deadline at all: Close is the only thing that can end this
	// exchange, so a record appearing here cannot be blamed on the caller.
	result := make(chan error, 1)
	go func() {
		_, err := harness.transport.Exchange(context.Background(), queryMessage())
		result <- err
	}()
	<-entered
	require.NoError(t, harness.transport.Close())
	require.Error(t, <-result)
	require.Zero(t, harness.recordCount(),
		"Close is a LOCAL lifetime ending and must write no error record")
	require.Zero(t, harness.errorCount("a"))
}

// TestSingleTargetSubDeadlineDoesNotGetExempted is the trap the ownership split
// exists to avoid. The exchange ends with context.DeadlineExceeded exactly like
// the caller-cancellation case, but the context that expired is the group's own
// sub-deadline while the caller is still alive and waiting. That expiry is how
// the group decides a target is a blackhole, so it MUST be recorded. A blanket
// "DeadlineExceeded is neutral" rule would erase the detection entirely.
func TestSingleTargetSubDeadlineDoesNotGetExempted(t *testing.T) {
	harness := newGroupHarness(t, stableOptions("a"))
	harness.byTag["a"].setBehavior(parkUntilDone)

	// The group spends half the remaining budget on the single target, so the
	// target expires well before the caller's own deadline. The margin is what
	// keeps the two deadlines distinguishable: by the time the exchange returns,
	// the caller still has half its budget left.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := harness.exchange(ctx)
	require.Error(t, err)
	require.NoError(t, ctx.Err(),
		"the caller's own deadline must still be alive when the group classifies the failure")
	require.Positive(t, harness.liveErrors("a"),
		"the group's own sub-deadline expiring IS the blackhole detector and must be recorded")
}

// TestRemoteOutcomesOwnership pins the two remaining classifications: a
// transport-level failure (SERVFAIL) is REMOTE and dirties the target, while a
// valid answer - NXDOMAIN or an empty NOERROR - is a success and must not. The
// distinction is what keeps an NXDOMAIN-only zone from being read as a broken
// server.
func TestRemoteOutcomesOwnership(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		response func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)
		dirty    bool
		rcode    int
	}{
		{
			name: "servfail",
			response: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				return servfailResponse(message), nil
			},
			dirty: true,
			rcode: mDNS.RcodeSuccess,
		},
		{
			name: "nxdomain",
			response: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				return nxdomainResponse(message), nil
			},
			dirty: false,
			rcode: mDNS.RcodeNameError,
		},
		{
			name: "empty noerror",
			response: func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				return successResponse(message), nil
			},
			dirty: false,
			rcode: mDNS.RcodeSuccess,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newGroupHarness(t, stableOptions("a", "b"))
			harness.byTag["a"].setBehavior(testCase.response)
			harness.byTag["b"].succeed()
			harness.setCurrent("a")

			response, err := harness.exchange(testContext(t))
			require.NoError(t, err)
			require.Equal(t, testCase.rcode, response.Rcode,
				"a valid answer must be returned exactly as the member produced it")
			if testCase.dirty {
				require.Positive(t, harness.liveErrors("a"),
					"SERVFAIL is a REMOTE failure and must be recorded")
			} else {
				require.Zero(t, harness.liveErrors("a"),
					"a valid answer must never be recorded as a member failure")
			}
		})
	}
}

// TestCancelledFanLoserIsNotRecorded covers the third LOCAL lifetime: the group
// cancelled its own fan loser once another member had won. The loser's error is
// an artifact of that cancellation, not evidence about the member, and recording
// it would let one blackholed target dirty every other member.
func TestCancelledFanLoserIsNotRecorded(t *testing.T) {
	harness := newGroupHarness(t, fastestOptions("a", "b"))
	// "a" answers at once and wins the election fan; "b" is still parked when
	// the fan cancels it, so its context error is the group's own doing.
	harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		return successResponse(message), nil
	})
	harness.byTag["b"].setBehavior(parkUntilDone)

	_, err := harness.exchange(testContext(t))
	require.NoError(t, err)
	// The election token is released only after collectFan has drained every
	// participant, so waiting for the release is the barrier that guarantees the
	// cancelled loser has actually been classified.
	waitFor(t, "the election token to be released after the winner", func() bool {
		return !harness.electionInFlight()
	})
	require.Zero(t, harness.errorCount("b"), "a fan loser cancelled by the group must not be recorded")
	require.Zero(t, harness.liveErrors("b"))
}

// TestResetDropsInFlightExchangeResults verifies that the generation guard is
// not a fan-only property. Both the single-target path and the survival path
// carry the generation they selected under into noteError/noteSuccess, so a
// result that lands after Reset must write nothing into the amnestied tables.
func TestResetDropsInFlightExchangeResults(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		prepare func(harness *groupHarness)
	}{
		{
			name:    "single target",
			prepare: func(harness *groupHarness) {},
		},
		{
			name: "survival",
			prepare: func(harness *groupHarness) {
				// Make the only member dirty so selection takes the survival
				// path instead of the single-target one.
				harness.markDirty("a")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := stableOptions("a")
			options.ErrorTTL = badoption.Duration(time.Hour)
			harness := newGroupHarness(t, options)
			testCase.prepare(harness)

			release := make(chan struct{})
			entered := make(chan struct{}, 1)
			harness.byTag["a"].setBehavior(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-release
				// A genuine failure, not a context error: only the generation
				// guard can be responsible for dropping it.
				return nil, errFake
			})

			result := make(chan error, 1)
			go func() {
				_, err := harness.transport.Exchange(context.Background(), queryMessage())
				result <- err
			}()
			<-entered

			harness.transport.Reset()
			close(release)
			require.Error(t, <-result)
			require.Zero(t, harness.recordCount(),
				"an in-flight result from the old generation must not write into the amnestied tables")
		})
	}
}
