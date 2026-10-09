package tun

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// Tests that assert the SHAPE of the reference release, not only its effect.
//
// These reference the release helpers directly, so they only compile against the fixed tree. The
// end-to-end pairing tests live in ruleset_refs_test.go and are the ones that run red against the
// previous implementation; this file is the reverse-break control that fails if the release is
// wired up in a way that satisfies the counts for the wrong reason.

// TestCallbacksAloneDoNotReleaseTheReference is the counterfactual control for the fix.
//
// The reference release is a separate responsibility from the callback release, and the defect was
// exactly that the two were conflated: the release that existed only unregistered callbacks. This
// drives only the callback half and requires the reference to survive it, so a future change that
// made the callback half release the reference as a side effect - or that dropped
// releaseRouteSetRefs out of releaseRouteSets - fails here rather than quietly passing the counts.
func TestCallbacksAloneDoNotReleaseTheReference(t *testing.T) {
	inbound, routeRuleSet, _ := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
	require.Equal(t, 1, routeRuleSet.refCount())

	inbound.releaseRouteSetCallbacks()

	require.Zero(t, routeRuleSet.callbackCount(), "the callback half is released")
	require.Equal(t, 1, routeRuleSet.refCount(),
		"and the reference is still held: unregistering a callback is not the same resource as the "+
			"reference Start took, and a release that only does this half leaves the rules pinned")

	inbound.releaseRouteSetRefs()
	require.Zero(t, routeRuleSet.refCount())
}

// TestRefReleaseIsIdempotentAtTheReferenceLayer pins the clearing behaviour directly.
//
// Releasing the same reference twice would drive a real rule-set's counter negative, which is a
// panic in LocalRuleSet and RemoteRuleSet. Clearing the record is what makes the second call a
// no-op; if the clearing were removed, this test panics instead of passing.
func TestRefReleaseIsIdempotentAtTheReferenceLayer(t *testing.T) {
	inbound, routeRuleSet, excludeRuleSet := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
	require.Equal(t, 1, routeRuleSet.refCount())

	inbound.releaseRouteSetRefs()
	require.Zero(t, routeRuleSet.refCount())

	require.NotPanics(t, func() {
		inbound.releaseRouteSetRefs()
		inbound.releaseRouteSetsCleanup()
	}, "the record must be cleared on release, or a second release drives the counter negative")
	require.Zero(t, routeRuleSet.refCount())
	require.Zero(t, excludeRuleSet.refCount())

	// The stored record itself must be empty, not merely balanced: a non-empty record after a release
	// is what a later double release would act on.
	require.Empty(t, inbound.routeRuleSetRefs,
		"the acquisition record must be cleared so the pairing stays exactly-once")
}

// TestReleaseWithoutAcquisitionIsANoOp covers the failure that happens BEFORE the acquisition.
//
// Start can return before it reaches the reference block - the platform interface can be absent on a
// platform that does not need it, or an earlier stage can fail - and the Scope cleanup must then find
// nothing to release rather than decrementing counters it never incremented.
func TestReleaseWithoutAcquisitionIsANoOp(t *testing.T) {
	inbound, routeRuleSet, excludeRuleSet := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	require.NotPanics(t, func() {
		require.NoError(t, inbound.releaseRouteSetsCleanup())
		require.NoError(t, inbound.Close())
	})

	require.Zero(t, routeRuleSet.refCount(), "nothing was acquired, so nothing may be released")
	require.Zero(t, excludeRuleSet.refCount())
}
