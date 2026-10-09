package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The window this file closes
// ---------------------------------------------------------------------------
//
// dns/client.go already refuses to RECORD an answer that was captured under a policy epoch which no
// longer holds: `stateMutationAllowed` consults `policyStillCurrent`. What that check cannot do is make
// itself and the write one step. The invalidation does not have to be inside the exchange to be
// harmful - it only has to land between the two:
//
//	old exchange captures policy epoch E
//	old response returns and passes the E check              <- authorised, and the guard says yes
//	                                                         <- [THE WINDOW]
//	ClearCache() runs to completion: E -> E+1, cache purged
//	old response writes its answer                           <- live under E+1
//
// The next query under E+1 reads that entry and is answered by the server the switch moved away from,
// which is exactly what the epoch exists to prevent. Re-checking the epoch immediately before the write
// does not close it either: the re-check and the write are still two steps, and the purge can land
// between them.
//
// # How the window is held open deterministically
//
// `ClientOptions.TestStorePreCommitHook` runs at exactly one place: after a response has passed every
// ownership and policy guard, immediately before the cache commit takes the store guard. The test parks
// a real commit there, runs a real `Router.ClearCache` to completion, and then releases it. Every step
// is a real product path - the round trip, the guards, the epoch, the purge, the commit - and the only
// thing the seam supplies is the freeze.
//
// # What the fix has to be
//
// A re-check is not enough, so the commit runs inside `StoreUnderPolicy`, which `ClearCache` takes
// exclusively for the whole of "advance the epoch and purge". Then the commit is either entirely before
// the clear - and the purge removes what it wrote - or entirely after it, in which case the epoch read
// INSIDE the guard fails and nothing is written.
//
// Because the hook runs before the guard is taken, this test is red on the check-then-write version for
// the right reason: the clear completes while the commit is frozen, and the frozen commit then writes
// an answer whose epoch has been retired.

// TestAnAnswerAuthorisedBeforeTheClearIsNotRecordedAfterIt is the reproduction for the cache-commit
// window.
//
// The interleaving, in events rather than sleeps:
//
//  1. a query is issued under mode Rule and its transport answers immediately, so the response is a
//     complete, authorised result;
//  2. that response is frozen at the last reversible point of its commit - every guard has been
//     evaluated, nothing has been written;
//  3. the mode switches to Global, which advances the epoch and purges the cache. The switch is
//     required to COMPLETE while the commit is frozen: the window is only real if the invalidation can
//     run to the end inside it;
//  4. the response is released, so it performs the write it was authorised to perform;
//  5. the state left behind is inspected, and then the same question is asked under Global.
//
// Step 5 must not find the old answer. If it does, the switch did not take effect for that name - for
// the rest of the entry's TTL.
func TestAnAnswerAuthorisedBeforeTheClearIsNotRecordedAfterIt(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", false)

	// The seam. `frozen` says a commit has passed every guard and has not written; `release` lets it
	// write; `finished` says the whole exchange has returned, so the cache can be inspected without a
	// timing question.
	//
	// The harness builds the router's client as a plain Client, so the concrete type is available here.
	// A harness that left it nil would fail loudly rather than silently installing nothing.
	concreteClient, isConcrete := harness.router.client.(*Client)
	require.True(t, isConcrete, "the harness must expose the concrete client, got %T", harness.router.client)
	frozen := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var frozeOnce bool
	concreteClient.storePreCommitHook = func() {
		if frozeOnce {
			return
		}
		frozeOnce = true
		close(frozen)
		<-release
		// Closed while the hook is still on the stack, so this orders every step the exchange takes
		// after it - the write included.
		defer close(finished)
	}

	const name = "commit-window.example.org."
	message, metadata := modeTestMessage(name)

	// --- 1. a complete, authorised answer, produced under mode Rule ---------------------------------
	require.Equal(t, "Rule", harness.manager.Mode())
	require.EqualValues(t, 0, harness.router.policyEpoch(),
		"the epoch must start where the fixture assumes it does, or the capture below is meaningless")
	firstCtx := adapter.WithContext(context.Background(), metadata)
	firstResult := make(chan netip.Addr, 1)
	firstError := make(chan error, 1)
	go func() {
		response, err := harness.router.Exchange(firstCtx, message, adapter.DNSQueryOptions{})
		if err != nil {
			firstError <- err
			return
		}
		firstResult <- modeTestAddress(t, response, nil)
	}()

	// --- 2. frozen inside the commit, past every guard ----------------------------------------------
	select {
	case <-frozen:
	case err := <-firstError:
		t.Fatalf("the first query failed before reaching its commit: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the first query never reached the pre-commit seam, so the window was never opened")
	}

	// --- 3. the clear runs against a commit that is frozen mid-write ---------------------------------
	//
	// This is where the two builds differ, and the difference is the whole ordering question:
	//
	//	check-then-write   the commit holds nothing, so the clear runs to completion inside the window -
	//	                   epoch advanced, cache purged - and the commit then performs its write
	//	store guard        the commit holds the guard's read side, so the clear cannot even start until
	//	                   the commit has finished
	//
	// So "did the clear finish while the commit was frozen" is not a timing measurement, it is the
	// ordering fact itself, and it is read from a closed channel rather than from a duration: the clear
	// closes `clearDone` only after `SetMode` - epoch advance, cache purge, reverse purge - has returned.
	clearStarted := make(chan struct{})
	clearDone := make(chan struct{})
	go func() {
		close(clearStarted)
		harness.manager.SetMode("Global")
		close(clearDone)
	}()
	<-clearStarted
	clearFinishedInsideTheWindow := false
	select {
	case <-clearDone:
		clearFinishedInsideTheWindow = true
	case <-time.After(200 * time.Millisecond):
		// The clear is waiting on the commit. That is the expected shape: the commit is inside the
		// guarded section, and the clear takes that section exclusively.
	}

	// --- 4. release the frozen commit, and let the exchange return ----------------------------------
	close(release)
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the frozen exchange never finished after its release")
	}
	select {
	case address := <-firstResult:
		require.Equal(t, netip.MustParseAddr("192.0.2.10"), address,
			"the caller that asked must still receive its answer: the policy declines the RECORDING, "+
				"not the delivery")
	case err := <-firstError:
		t.Fatalf("the frozen query failed after its release: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the frozen query never returned after its release")
	}
	select {
	case <-clearDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the mode switch never completed even after the commit it was waiting on finished")
	}
	require.Equal(t, "Global", harness.manager.Mode())
	require.EqualValues(t, 1, harness.router.policyEpoch(),
		"the clear must have advanced the epoch, or the store below is authorised for the wrong reason")

	require.False(t, clearFinishedInsideTheWindow,
		"the clear ran to completion between a commit's epoch check and its cache write. There was "+
			"nothing ordering the two, so the answer the switch moved away from was written into the "+
			"cache the clear had just emptied, and the new policy reads it for the rest of its TTL")

	// A write barrier before the inspection: everything the exchange did is ordered before this read,
	// so "the entry is not there" is a fact about the commit and not about timing.
	harness.router.policyStoreGuard.access.Lock()
	harness.router.policyStoreGuard.access.Unlock()
	_, loaded := concreteClient.cache.Get(concreteClient.newCacheKey(
		harness.transport, message.Question[0], message, adapter.DNSQueryOptions{}))
	require.False(t, loaded,
		"a stale answer is live in the cache after the clear that purged it")

	// The new mode's server answers differently, so which server answered is observable.
	harness.setAddress(netip.MustParseAddr("192.0.2.20"))

	// --- 5. the same question under the new policy --------------------------------------------------
	//
	// The transport is HELD before it answers this second query, for the same reason as in
	// TestAnInFlightAnswerFromTheOldModeIsNotServedUnderTheNewMode: without the hold, this query's own
	// commit could repair the cache and the assertion below would pass even though the new policy had
	// been served the OLD answer.
	harness.transport.entered = make(chan struct{})
	harness.transport.release = make(chan struct{})
	harness.transport.once = sync.Once{}

	secondCtx := adapter.WithContext(context.Background(), metadata)
	before := harness.transport.queryCount.Load()
	secondResult := make(chan netip.Addr, 1)
	secondError := make(chan error, 1)
	go func() {
		response, err := harness.router.Exchange(secondCtx, message, adapter.DNSQueryOptions{})
		if err != nil {
			secondError <- err
			return
		}
		secondResult <- modeTestAddress(t, response, nil)
	}()

	select {
	case <-harness.transport.entered:
	case err := <-secondError:
		t.Fatalf("the second query failed: %v", err)
	case address := <-secondResult:
		t.Fatalf("the new policy was served %v from the cache without asking its own server: an answer "+
			"produced by the server the switch moved away from was recorded after the clear that "+
			"purged it", address)
	case <-time.After(10 * time.Second):
		t.Fatal("the second query neither reached its transport nor returned: it is stuck somewhere " +
			"other than the cache path this test is about")
	}
	require.Greater(t, harness.transport.queryCount.Load(), before,
		"the new policy must ask its own server rather than read an entry written after its clear")

	close(harness.transport.release)
	select {
	case served := <-secondResult:
		require.Equal(t, netip.MustParseAddr("192.0.2.20"), served,
			"the new policy asked its own server but was handed the old one's value")
	case err := <-secondError:
		t.Fatalf("the second query failed after its release: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the second query never completed after its release")
	}

	// --- positive control: the guard rejects stale commits, it does not disable caching -------------
	//
	// The answer above belongs to the CURRENT epoch, so it IS recorded, and the next identical query is
	// served from it. Without this the fix could be "never store anything", which would pass every
	// assertion above for the wrong reason.
	thirdCtx := adapter.WithContext(context.Background(), metadata)
	beforeThird := harness.transport.queryCount.Load()
	thirdResponse, thirdErr := harness.router.Exchange(thirdCtx, message, adapter.DNSQueryOptions{})
	require.Equal(t, netip.MustParseAddr("192.0.2.20"), modeTestAddress(t, thirdResponse, thirdErr))
	require.Equal(t, beforeThird, harness.transport.queryCount.Load(),
		"an answer stored under the current policy must still be served from the cache")
}

// TestThePolicyEpochIsStillCurrentInsideTheCommitGuard pins the mechanism rather than its consequence,
// so a future change that moves the epoch read out of the guarded section fails here with a message
// that names the reason instead of an unexplained cache hit.
//
// `StoreUnderPolicy` must be the section in which the epoch is read: if the epoch is read outside it,
// the value can be withdrawn between the read and the write, which is the defect.
func TestThePolicyEpochIsStillCurrentInsideTheCommitGuard(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", false)
	guard := &harness.router.policyStoreGuard

	before := guard.PolicyStoreEpoch()
	var observedInside uint64
	var observedAfter uint64
	guard.StoreUnderPolicy(func() {
		observedInside = guard.PolicyStoreEpoch()
	})
	observedAfter = guard.PolicyStoreEpoch()

	require.Equal(t, before, observedInside,
		"the epoch read inside the guard must be the live one")
	require.Equal(t, before, observedAfter,
		"and reading it must not itself advance it")

	// The counter, not only the accessor: advancing it is ClearCache's job alone.
	harness.router.ClearCache()
	require.Equal(t, before+1, guard.PolicyStoreEpoch(),
		"a clear advances the policy epoch by exactly one")
}

// ---------------------------------------------------------------------------
// The same window on the reverse-mapping cache
// ---------------------------------------------------------------------------

// TestAReverseMappingLearnedUnderTheOldPolicyIsNotPublishedAfterTheClear pins the policy half of the
// reverse-mapping commit, at the level the guard actually works at.
//
// That cache is guarded by `dnsEnvironmentAccess`, and the commit already compares the NETWORK
// generation inside it. `ClearCache` purges it too - but it advances the POLICY epoch, not the network
// generation, so without a policy comparison an answer that was already authorised under the retired
// policy could be published after the purge had completed. Route matching would then read a name learned
// from the resolver set the switch moved away from, which is the one thing that cache feeds.
//
// # Two epochs, two sources
//
// The NETWORK generation is captured by the exchange and carried to the commit, because a response
// describes the network its request was issued on. The POLICY epoch is read from the router at commit
// time, because the answer being recorded is the one about to be written and the policy that matters is
// the one in force for the write. The comparison inside the guarded section is what makes that read
// trustworthy: ClearCache advances the epoch and purges under the same lock, so the read cannot be
// withdrawn between itself and the writes it authorises. This test drives the commit function directly
// to hold both halves of the comparison still.
func TestAReverseMappingLearnedUnderTheOldPolicyIsNotPublishedAfterTheClear(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", false)

	address := netip.MustParseAddr("203.0.113.10")
	message, _ := modeTestMessage("reverse-policy.example.org.")
	response := FixedResponse(message.Id, message.Question[0], []netip.Addr{address}, 300)

	answers := reverseMappingAnswersFrom(response, harness.transport)
	require.NotEmpty(t, answers, "the fixture must produce an answer for the commit to publish")

	capturedGeneration := harness.router.dnsGeneration()
	// The policy epoch the exchange was authorised under, captured before the switch.
	stalePolicy := harness.router.policyEpoch()

	// The switch completes: the epoch advances and this cache is purged.
	harness.router.ClearCache()
	_, loaded := harness.router.LookupReverseMapping(address)
	require.False(t, loaded, "the clear must have purged the reverse mapping")
	require.NotEqual(t, stalePolicy, harness.router.policyEpoch(),
		"the clear must advance the policy epoch, or the comparison below is inert")

	// The in-flight answer is published with the epochs it captured.
	harness.router.commitReverseMappingAnswers(answers, capturedGeneration, stalePolicy)
	_, loaded = harness.router.LookupReverseMapping(address)
	require.False(t, loaded,
		"an answer authorised under the retired policy was published into the mapping after the clear "+
			"that purged it: route matching would read a name learned from the resolver set the switch "+
			"moved away from")

	// Positive control: the same publish with the CURRENT policy epoch lands, so the policy comparison
	// rejects stale answers rather than disabling this cache.
	harness.router.commitReverseMappingAnswers(answers, capturedGeneration, harness.router.policyEpoch())
	domain, loaded := harness.router.LookupReverseMapping(address)
	require.True(t, loaded, "an answer under the current policy must still be published")
	require.Equal(t, "reverse-policy.example.org", domain)
}

// TestAnAnswerFromAnotherResolverSetIsStillRefused keeps the network-generation half of the commit
// intact: the policy comparison must not have replaced it.
func TestAnAnswerFromAnotherResolverSetIsStillRefused(t *testing.T) {
	harness := newModeSwitchHarness(t, "shared", false)

	address := netip.MustParseAddr("203.0.113.11")
	message, _ := modeTestMessage("reverse-generation.example.org.")
	response := FixedResponse(message.Id, message.Question[0], []netip.Addr{address}, 300)

	capturedGeneration := harness.router.dnsGeneration()
	harness.router.ResetNetwork()

	harness.router.recordReverseMappingFrom(message, response, harness.transport, capturedGeneration)
	_, loaded := harness.router.LookupReverseMapping(address)
	require.False(t, loaded,
		"an answer captured before a network reset must not be published after it")
}
