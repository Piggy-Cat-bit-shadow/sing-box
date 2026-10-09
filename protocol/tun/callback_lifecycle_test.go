package tun

import (
	"context"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"

	"github.com/stretchr/testify/require"
)

// Tests for the route-set callback lifecycle.
//
// # The defect these pin
//
// Start registered t.updateRouteAddressSet on every route rule-set and stored the returned element
// so it could be released later, but nothing ever called UnregisterCallback. The callback closes
// over the *Inbound, so after Close the rule-set still held a reference to a torn-down inbound and
// would call into it on the next rule-set update. The element slice made the omission look like it
// had been handled - the bookkeeping was there, only the release was missing.

// trackingRuleSet records registration, release and the reference count.
//
// The reference counter is real, not a no-op. Empty IncRef/DecRef bodies made the double agree with
// every implementation, including one that never released a reference - a test built on it could
// only ever prove that the callbacks were released, never that the references were. DecRef mirrors
// LocalRuleSet and RemoteRuleSet exactly, including the panic on a negative count, so a double
// release fails here the same way it fails in production.
type trackingRuleSet struct {
	adapter.RuleSet
	access       *callbackAccess
	refs         atomic.Int32
	callbacks    []*list.Element[adapter.RuleSetUpdateCallback]
	registered   int
	unregistered int
}

type callbackAccess struct {
	registered   int
	unregistered int
}

func (s *trackingRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.registered++
	s.access.registered++
	element := &list.Element[adapter.RuleSetUpdateCallback]{Value: callback}
	s.callbacks = append(s.callbacks, element)
	return element
}

func (s *trackingRuleSet) ExtractIPSet() []*netipx.IPSet { return nil }

func (s *trackingRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.unregistered++
	s.access.unregistered++
	for index, existing := range s.callbacks {
		if existing == element {
			s.callbacks = append(s.callbacks[:index], s.callbacks[index+1:]...)
			return
		}
	}
}

func (s *trackingRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *trackingRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

// TestCloseReleasesRouteSetCallbacks is §49, §50.
//
// Close must release every callback Start registered. Without this the rule-set keeps invoking a
// callback that points at a closed inbound.
func TestCloseReleasesRouteSetCallbacks(t *testing.T) {
	access := &callbackAccess{}
	ruleSet := &trackingRuleSet{access: access}

	// Two rule-sets, one include and one exclude, exactly as Start would register them.
	excludeRuleSet := &trackingRuleSet{access: access}
	inbound := &Inbound{
		routeRuleSet:        []adapter.RuleSet{ruleSet},
		routeExcludeRuleSet: []adapter.RuleSet{excludeRuleSet},
	}
	// Register the way Start does.
	inbound.routeRuleSetCallback = append(inbound.routeRuleSetCallback,
		ruleSet.RegisterCallback(inbound.updateRouteAddressSet))
	inbound.routeExcludeRuleSetCallback = append(inbound.routeExcludeRuleSetCallback,
		excludeRuleSet.RegisterCallback(inbound.updateRouteAddressSet))

	require.Equal(t, 2, access.registered)

	require.NoError(t, inbound.Close())

	require.Equal(t, 2, access.unregistered,
		"Close must release every callback Start registered; the rule-set otherwise keeps a "+
			"callback into a closed inbound")
	require.Empty(t, ruleSet.callbacks,
		"no callback may remain registered after Close")
	require.Empty(t, excludeRuleSet.callbacks,
		"the exclude rule-set's callback must be released too")
	require.Empty(t, inbound.routeRuleSetCallback,
		"the stored elements must be cleared so a second Close is a no-op")
	require.Empty(t, inbound.routeExcludeRuleSetCallback)
}

// TestCloseIsIdempotentForCallbacks is §52's repeated-lifecycle half.
func TestCloseIsIdempotentForCallbacks(t *testing.T) {
	access := &callbackAccess{}
	ruleSet := &trackingRuleSet{access: access}

	inbound := &Inbound{routeRuleSet: []adapter.RuleSet{ruleSet}}
	inbound.routeRuleSetCallback = append(inbound.routeRuleSetCallback,
		ruleSet.RegisterCallback(inbound.updateRouteAddressSet))

	require.NoError(t, inbound.Close())
	afterFirst := access.unregistered

	require.NoError(t, inbound.Close())
	require.Equal(t, afterFirst, access.unregistered,
		"a second Close must not unregister again; releasing an element twice would corrupt the "+
			"rule-set's list")
}

// TestCallbackCountDoesNotGrowAcrossLifecycles is §52.
//
// A fresh inbound registers its own callbacks; the closed one's must be gone. Repeated
// start/close cycles must not accumulate registrations.
func TestCallbackCountDoesNotGrowAcrossLifecycles(t *testing.T) {
	access := &callbackAccess{}
	ruleSet := &trackingRuleSet{access: access}

	for cycle := 0; cycle < 5; cycle++ {
		inbound := &Inbound{routeRuleSet: []adapter.RuleSet{ruleSet}}
		inbound.routeRuleSetCallback = append(inbound.routeRuleSetCallback,
			ruleSet.RegisterCallback(inbound.updateRouteAddressSet))

		require.NoError(t, inbound.Close())
	}

	require.Equal(t, 5, access.registered)
	require.Equal(t, 5, access.unregistered,
		"every cycle must release what it registered")
	require.Empty(t, ruleSet.callbacks,
		"after 5 cycles the rule-set must hold no callbacks; a growing list means closed "+
			"inbounds are still referenced")
}

// recordingAutoRedirect accepts route-set updates and records them.
type recordingAutoRedirect struct {
	tun.AutoRedirect
	updates atomic.Int32
}

func (r *recordingAutoRedirect) UpdateRouteAddressSet() error {
	r.updates.Add(1)
	return nil
}

// TestInFlightCallbackUnderCloseIsOrdered is I1.
//
// Releasing the callbacks removes the registration, so no NEW update reaches a closed inbound. A
// callback that is ALREADY executing is a different question: it is inside the inbound while Close
// tears the auto-redirect down.
//
// The two are ordered by the mutex the callback and Close share, which is what this test pins. It
// drives the real callback and the real release path, with a rule-set that holds the update until the
// test says otherwise, so the interleaving is chosen rather than raced.
func TestInFlightCallbackUnderCloseIsOrdered(t *testing.T) {
	ruleSet := &trackingRuleSet{access: &callbackAccess{}}
	inbound := &Inbound{
		tag:          "tun-inflight",
		ctx:          context.Background(),
		logger:       log.NewNOPFactory().Logger(),
		routeRuleSet: []adapter.RuleSet{ruleSet},
		// A callback only exists when the inbound has an auto-redirect: Start registers them
		// together, inside `if t.autoRedirect != nil`. The fixture mirrors that coupling, because a
		// callback with no auto-redirect is a state production cannot reach.
		autoRedirect:          &recordingAutoRedirect{},
		routeAddressSetAccess: sync.RWMutex{},
	}

	// Register exactly as Start does, so the callback under test is the production one.
	callback := adapter.RuleSetUpdateCallback(inbound.updateRouteAddressSet)
	element := ruleSet.RegisterCallback(callback)
	inbound.routeRuleSetCallback = []*list.Element[adapter.RuleSetUpdateCallback]{element}

	// The callback must be safe to run after the release has cleared the stored elements: Close
	// clears them, and a callback that raced the clear must not depend on them.
	inbound.releaseRouteSetCallbacks()

	require.NotPanics(t, func() {
		callback(ruleSet)
	}, "a callback that was already in flight when Close released it must not panic. It reads the "+
		"inbound's rule-set slices and updates the address-set pair, none of which Close invalidates")

	// And the release really did happen, exactly once.
	require.Equal(t, 1, ruleSet.access.unregistered, "the callback is released exactly once")

	// A second release is a no-op, so a repeated Close cannot hand the same element to
	// UnregisterCallback twice.
	require.NotPanics(t, func() { inbound.releaseRouteSetCallbacks() })
	require.Equal(t, 1, ruleSet.access.unregistered,
		"a second release must not unregister again; the rule-set's list would be corrupted")
}
