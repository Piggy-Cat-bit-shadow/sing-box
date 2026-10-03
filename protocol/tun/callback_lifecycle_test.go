package tun

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/x/list"

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

// trackingRuleSet records registration and release.
type trackingRuleSet struct {
	adapter.RuleSet
	access       *callbackAccess
	refCount     int
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

func (s *trackingRuleSet) IncRef() {}
func (s *trackingRuleSet) DecRef() {}

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
