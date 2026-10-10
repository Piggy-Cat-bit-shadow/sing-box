package wireguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/wireguard-go/device"

	"github.com/stretchr/testify/require"
)

// D7-02, part two: the instruments and the error contract.
//
// This file is separate from rebind_lease_test.go on purpose. That file has to COMPILE against the base
// commit, because it is the one run against the unfixed revision to show the defect is real - and the reason
// it compiles is that it touches nothing the fix adds. Everything that touches what the fix adds lives here:
// the revocation sentinel and the census sensitivity control.
//
// The split is not cosmetic. A single file that referenced anything the fix adds would fail to build on the
// base commit, and the old-code probe would have to be reported as a compile error - which is not acceptable
// as evidence.

// The goroutine census must be able to go RED, must not count itself, and must be scoped to the endpoint under
// test.
//
// # Why the residents are parked through rebindHook and not through a new seam
//
// `rebindHook` is fetched and invoked SYNCHRONOUSLY on the recovery goroutine, from inside `RebindStale`,
// which the loop calls. So a hook that blocks parks the recovery worker exactly where a frame named
// `(*Endpoint).recoveryLoop` is live on its stack - which is what the census counts. It is the seam the
// package already has, with a documented meaning, and it is enough. A second seam beside it would mean two
// places a future fixture could arm, only one of which does anything.
//
// # How 60 workers are made resident through a seam that runs once per lease
//
// Two coalescing rules stand between a burst of 60 loops and 60 residents, and both are production policy
// rather than test scaffolding:
//
//   - `BeginRebind` grants one lease per generation, and the loop RETURNS when it is refused;
//   - it also refuses inside the recovery window of the previous grant.
//
// So the hook releases the lease it is running under (`CompleteRebind`) before it parks, the window is
// shortened with the existing `Registration.SetRecoveryWindow` - which is what the registration provides for
// exactly this - and a worker that loses the race is REPLACED rather than counted. Each resident then holds a
// lease that is genuinely its own, and the number below is the number of resident recovery goroutines, not of
// attempts. Reaching the population by replacement instead of by hoping 60 goroutines arrive together is what
// makes the count exact under `-race`, where arrival times spread out widely.
func TestCensusInstrumentIsSensitiveAndDoesNotCountItself(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	require.Zero(t, goroutineCensus(t, endpoint),
		"an idle endpoint must have no resident recovery worker")

	// A stale session is what earns the workers their leases. It is set BEFORE any loop starts, so every
	// resident below has passed the loop's own stale predicate rather than a test's view of it.
	endpoint.recovery.settle = time.Millisecond
	endpoint.recovery.poll = time.Millisecond
	endpoint.registration.SetRecoveryWindow(time.Millisecond)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	require.True(t, endpoint.hasStaleSession())

	const parked = 60
	entered := make(chan struct{}, parked*4)
	granted := make(chan struct{}, parked*4)
	release := make(chan struct{})
	// The hook is installed under the recovery lock, which is the lock RebindStale reads it under.
	endpoint.recovery.access.Lock()
	endpoint.recovery.rebindHook = func(ctx context.Context) error {
		// Reporting the grant before parking is what makes the population deterministic: a worker refused by
		// the coalescing rules never reaches here, and the loop below starts another one in its place.
		granted <- struct{}{}
		endpoint.registration.CompleteRebind()
		entered <- struct{}{}
		<-release
		return nil
	}
	endpoint.recovery.access.Unlock()
	t.Cleanup(func() {
		endpoint.recovery.access.Lock()
		endpoint.recovery.rebindHook = nil
		endpoint.recovery.access.Unlock()
	})

	var waitGroup sync.WaitGroup
	for started := 0; started < parked; {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			endpoint.recoveryLoop()
		}()
		select {
		case <-granted:
			started++
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d recovery workers earned a lease; the coalescing rules did not let "+
				"the population reach the size this control needs", started, parked)
		}
	}
	for index := 0; index < parked; index++ {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d recovery workers became resident", index, parked)
		}
	}

	// The control: 0 -> 60. A census that cannot make this move cannot detect a leak either.
	require.Equal(t, parked, goroutineCensus(t, endpoint),
		"the census must move with the number of residents in the frame it counts: 0 -> %d is the "+
			"sensitivity control, and a census that stays at 0 here proves nothing", parked)

	// The census called from a closure - the shape inside a `require.Eventually`, which is where the previous
	// round's self-counting happened - must report the same number, not one more.
	require.Eventually(t, func() bool {
		return goroutineCensus(t, endpoint) == parked
	}, 2*time.Second, 5*time.Millisecond,
		"a census taken from inside a closure must see the residents and must not add itself to them")

	// Scoped to the instance: another endpoint's census must not see these residents. The other endpoint is
	// live and has its own receive goroutines, so this is a check against a live false positive rather than
	// against a string.
	other := newRebindFixture(t, 0)
	other.proveStandardBindBranch(t)
	require.Zero(t, goroutineCensus(t, other.endpoint),
		"a second endpoint's census must not see the first endpoint's workers: the instrument must be "+
			"scoped to the instance under test, not to the type")
	require.Greater(t, socketCensus(t, other.endpoint), 0,
		"the second endpoint must be live, or its zero above proves nothing")

	// The control, other direction: 60 -> 0.
	close(release)
	waitGroup.Wait()
	require.Eventually(t, func() bool {
		return goroutineCensus(t, endpoint) == 0
	}, 5*time.Second, 2*time.Millisecond,
		"the census must return to zero when the residents leave, or it is measuring something else")
}

// The negative control for the census's receiver-address scoping: a resident of one endpoint must not be
// counted by another endpoint's census. It is why the census reads the address off the frame instead of
// matching the function name.
func TestCensusDoesNotCountAnotherEndpointsWorkers(t *testing.T) {
	first := newRebindFixture(t, 0)
	first.proveStandardBindBranch(t)
	second := newRebindFixture(t, 0)
	second.proveStandardBindBranch(t)

	entered := make(chan struct{}, 2)
	release := make(chan struct{})

	// A failed assertion must not leave a worker parked inside the hook, so the release is
	// guarded and runs even when the test fails early.
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }
	defer doRelease()

	endpoints := []*Endpoint{first.endpoint, second.endpoint}

	for _, endpoint := range endpoints {
		// ORDER MATTERS, and getting it wrong is why this test measured 2 workers per endpoint.
		//
		// `sessionStateChanged(PeerSessionExpired)` does not merely record the session: it calls
		// pokeRecovery(), which starts the production recovery worker. Doing that BEFORE installing
		// the hook left a worker running that had no seam to block in, so the test then started a
		// SECOND one by hand with `go endpoint.recoveryLoop()` - bypassing pokeRecovery's residency
		// guard entirely, since that guard is what the manual call skipped. The census then observed
		// two, correctly: the fixture had really created two.
		//
		// So: settle/poll, then the hook, and only then the trigger. The worker that starts is the
		// production one, started by the production path, with nowhere to go but the hook.
		endpoint.recovery.settle = time.Millisecond
		endpoint.recovery.poll = time.Millisecond
		endpoint.recovery.access.Lock()
		endpoint.recovery.rebindHook = func(ctx context.Context) error {
			entered <- struct{}{}
			<-release
			return nil
		}
		endpoint.recovery.access.Unlock()
		endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	}

	// No manual `go recoveryLoop()` calls: the workers under test are the two the production path
	// started, one per endpoint, and the census must see exactly those.
	for index := 0; index < 2; index++ {
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of 2 recovery workers became resident", index)
		}
	}

	require.Equal(t, 1, goroutineCensus(t, first.endpoint),
		"the first endpoint's census must count exactly its own resident worker")
	require.Equal(t, 1, goroutineCensus(t, second.endpoint),
		"and the second endpoint's census must count exactly its own, not the first one's")

	// Release, then wait for the residents to actually leave, so the goroutines this test created
	// cannot leak into whatever runs next.
	doRelease()
	for index, endpoint := range endpoints {
		require.Eventually(t, func() bool {
			return !endpoint.WorkerResident()
		}, 10*time.Second, 2*time.Millisecond,
			"endpoint %d: the worker must exit once the hook is released", index)
	}
}

// A revoked rebind must not leave the endpoint unable to recover: the worker flag the loop clears on its way
// out is what lets the next trigger start a fresh worker. This is the mechanism the recovery code's comment
// relies on, asserted rather than described.
//
// Both halves are checked, because either alone would pass on a broken implementation: the flag is clear after
// the loop returns, AND a fresh failure really does start a new worker.
func TestAFinishedWorkerLeavesTheResidencyFlagClear(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)

	endpoint := fixture.endpoint
	endpoint.recovery.settle = time.Millisecond
	endpoint.recovery.poll = time.Millisecond

	// The seam runs the decision path and returns immediately, so the worker completes.
	endpoint.recovery.access.Lock()
	endpoint.recovery.rebindHook = func(ctx context.Context) error { return nil }
	endpoint.recovery.access.Unlock()

	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)

	require.Eventually(t, func() bool {
		return !endpoint.WorkerResident()
	}, 5*time.Second, 2*time.Millisecond,
		"the residency flag must be clear once the worker is done, or pokeRecovery will refuse to start "+
			"the next one and the endpoint will never recover again")

	// And the next trigger really does start a new worker, which is the half that matters: a clear flag plus a
	// refusing pokeRecovery would look identical in the assertion above.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	require.Eventually(t, func() bool {
		return endpoint.WorkerResident()
	}, 5*time.Second, time.Millisecond,
		"a fresh failure must be able to start a worker again after a completed one")
}

// The revocation predicate must be a statement about the lease, not about the error's shape.
//
// # The case that matters
//
// `errRevokedRebind` is produced by exactly one function, `rebindOutcome`, and only when the context the
// rebind ran under is already cancelled. So "revoked" means a live lease stopped being live, and nothing else.
// An unrelated failure cannot be reclassified as "revoked, socket reopened, nothing to see": it carries no
// sentinel, and the impostor below is an error that READS exactly like one while being nothing of the kind -
// which the message-based predicate in the other file WOULD be fooled by.
func TestRevokedRebindPredicateIsAboutTheLease(t *testing.T) {
	// A genuine revocation - a generation advance cancels the lease - is identified, and so is its cause.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	genuine := rebindOutcome(ctx, nil)
	require.True(t, rebindWasRevoked(genuine))
	require.ErrorIs(t, revokedRebindCause(genuine), context.Canceled,
		"a lease revocation must be attributable to the cancellation the lease carried")

	// This layer's OWN bound expiring is a different cause carried through the same mechanism, so a caller can
	// tell a handover from a slow socket rather than having to treat every revocation alike.
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer deadlineCancel()
	<-deadlineCtx.Done()
	boundExpired := rebindOutcome(deadlineCtx, nil)
	require.True(t, rebindWasRevoked(boundExpired))
	require.ErrorIs(t, revokedRebindCause(boundExpired), context.DeadlineExceeded,
		"the rebind's own timeout must be distinguishable from a revocation by the runtime")

	// An unrelated error is NOT a revocation, whatever it says.
	impostor := errors.New("rebind lease was revoked while the socket was being reopened: socket exploded")
	require.False(t, rebindWasRevoked(impostor),
		"an error with no sentinel must never be classified as a revoked rebind")
	require.Nil(t, revokedRebindCause(impostor))
	require.True(t, revokedRebindClaimed(impostor),
		"the message-based predicate used by the file that must compile against the base commit WOULD be "+
			"fooled by that error; that is why the two predicates are not the same function")

	// The two agree on everything genuinely revoked, so the weaker one is not producing false negatives that
	// would have made the old-code probe vacuous.
	for _, err := range []error{genuine, boundExpired} {
		require.True(t, rebindWasRevoked(err))
		require.True(t, revokedRebindClaimed(err),
			"a genuinely revoked rebind must also satisfy the message predicate")
	}
}

// An ordinary failure must not be reported as a revocation: the reclassification the predicate above guards
// against, asserted through the path that produces the outcome.
func TestOrdinaryRebindFailuresAreNotRevocations(t *testing.T) {
	sentinel := errors.New("rebind socket")
	require.False(t, rebindWasRevoked(rebindOutcome(context.Background(), sentinel)))
	require.False(t, rebindWasRevoked(rebindOutcome(context.Background(), errRebindNotPossible)))
	require.False(t, rebindWasRevoked(errRebindNotPossible))
	require.False(t, rebindWasRevoked(nil))
	require.Nil(t, revokedRebindCause(nil))
}

// The revocation sentinel has to satisfy two readers at once, and this is where that is pinned.
//
// # Why both facts, and why neither may be dropped
//
//   - `errors.Is(err, errRevokedRebind)` is how a caller withholds a recovery claim. Without it a superseded
//     generation is recorded as healthy - the D7-02 wrong answer.
//   - `errors.Is(err, context.Canceled)` is what the existing filters in this package use
//     (`exceptions.IsClosedOrCanceled`). Without it the same event is reported as a rebind FAILURE, which is a
//     second, noisier wrong answer.
//
// A single wrapper cannot carry both unless it is built to: wrapping the sentinel around the cancellation
// reason leaves the sentinel as the only leaf, and wrapping the reason around the sentinel loses the sentinel.
// This asserts the two coexist, each through its own reader.
func TestRevokedRebindSentinelCarriesBothFacts(t *testing.T) {
	revoked := &revokedRebindError{reason: context.Canceled}

	require.ErrorIs(t, revoked, errRevokedRebind,
		"a revoked rebind must be identifiable, or a caller cannot withhold the recovery claim")
	require.ErrorIs(t, revoked, context.Canceled,
		"and it must stay recognisable as a cancellation, or the existing filters report it as a failure")
	require.True(t, rebindWasRevoked(revoked))
	require.True(t, exceptions.IsClosedOrCanceled(revoked),
		"the package's own cancellation filter must classify a revoked rebind as a cancellation: if it does "+
			"not, every generation change during a reopen logs a warning about a socket that was reopened "+
			"correctly")
	require.Contains(t, revoked.Error(), "revoked")

	// The two facts are independent.
	require.False(t, rebindWasRevoked(context.Canceled),
		"a bare cancellation must not be reported as a revoked rebind")
	require.True(t, rebindWasRevoked(&revokedRebindError{reason: context.DeadlineExceeded}))
	require.ErrorIs(t, &revokedRebindError{reason: context.DeadlineExceeded}, context.DeadlineExceeded)
}

// The classification must keep a revoked rebind out of the warning path without silencing a real failure.
// The filter is spelled the way both branches of the recovery code spell it.
func TestRevokedRebindIsNotClassifiedAsAFailure(t *testing.T) {
	revoked := &revokedRebindError{reason: context.Canceled}
	require.True(t, rebindWasRevoked(revoked))
	require.True(t, exceptions.IsClosedOrCanceled(revoked))
	require.False(t, errors.Is(revoked, errRebindNotPossible))

	// The worker loop's branch.
	loopWouldWarn := func(err error) bool {
		return err != nil && !rebindWasRevoked(err) && !exceptions.IsClosedOrCanceled(err) &&
			!errors.Is(err, errRebindNotPossible)
	}
	require.False(t, loopWouldWarn(revoked),
		"a revoked rebind must not reach the warning path: nothing failed and the socket was reopened")
	require.False(t, loopWouldWarn(errRebindNotPossible),
		"and a lifecycle refusal is not a failure either")
	require.True(t, loopWouldWarn(errors.New("real failure")),
		"a real failure must still reach it, or the filter has been widened into silence")

	// The wake path's branch.
	wakeWouldDebug := func(err error) bool {
		return err != nil && !rebindWasRevoked(err) && !errors.Is(err, errRebindNotPossible) &&
			!exceptions.IsClosedOrCanceled(err)
	}
	require.False(t, wakeWouldDebug(revoked))
	require.True(t, wakeWouldDebug(errors.New("real failure")))
}
