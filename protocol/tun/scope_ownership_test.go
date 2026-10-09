package tun

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// Tests for the route-set callback OWNERSHIP transfer, as opposed to the release itself.
//
// # Why this file exists next to callback_lifecycle_test.go
//
// callback_lifecycle_test.go pins that Inbound.Close() releases the callbacks. That is true, and it
// stayed true - but it was never the question that mattered. The product close path is
//
//	Box.Close() -> Scope.Close() -> the cleanups handed to the Scope
//
// and Scope.Close() runs scope.Add entries only; it never calls a component's Close() method. The
// TUN inbound never handed its release to that Scope, so on a real Box.Close() the callbacks were
// never unregistered. The rule-set kept a callback into a torn-down *Inbound for the lifetime of
// the process, and the stored element slice made it look handled.
//
// A test that calls inbound.Close() directly therefore proves the release WORKS, not that it
// HAPPENS. These tests drive the real Scope through the real Start entry point, which is the path
// the product uses, so a regression in the OWNERSHIP wiring fails here.

// Name completes the trackingRuleSet double for the Start path, which logs the rule-set's name when
// it extracts no destination CIDR. The embedded adapter.RuleSet is nil, so without this the call
// panics before any assertion is reached.
func (s *trackingRuleSet) Name() string { return "tracking-rule-set" }

// Close completes recordingAutoRedirect for the teardown paths. The embedded tun.AutoRedirect is nil,
// so the auto-redirect's own Close would otherwise panic before the ordering assertion is reached.
func (r *recordingAutoRedirect) Close() error { return nil }

// failingPlatformInterface is a platform integration whose interface cannot be opened.
//
// Start reaches OpenInterface only after it has registered the route-set callbacks, so this is a
// failure injected exactly inside the window where the callbacks are live but nothing owns them.
type failingPlatformInterface struct {
	adapter.PlatformInterface
}

func (f *failingPlatformInterface) UsePlatformInterface() bool { return true }

func (f *failingPlatformInterface) OpenInterface(*tun.Options, option.TunPlatformOptions) (tun.Tun, error) {
	return nil, E.New("injected platform interface failure")
}

// newScopeOwnedInbound builds the real *Inbound in the state Start(StartStateStart) expects, with
// the smallest amount of the platform faked out. Everything the assertion is about - the Scope, the
// inbound and its route-set bookkeeping - is the production object.
func newScopeOwnedInbound(access *callbackAccess, platformInterface adapter.PlatformInterface) (*Inbound, *trackingRuleSet, *trackingRuleSet) {
	routeRuleSet := &trackingRuleSet{access: access}
	routeExcludeRuleSet := &trackingRuleSet{access: access}
	return &Inbound{
		tag:            "tun-scope-owned",
		ctx:            context.Background(),
		router:         nil,
		networkManager: &stackNetworkManagerStub{},
		logger:         log.NewNOPFactory().Logger(),
		// EXP_MultiPendingPackets keeps StartStateStart out of the outbound/endpoint probe, which
		// is not what is under test here and would need a router this fixture does not have.
		tunOptions: tun.Options{
			EXP_MultiPendingPackets: true,
		},
		// The callbacks are only registered when an auto-redirect exists: Start registers them
		// together inside `if t.autoRedirect != nil`, so a fixture without one would take a branch
		// production cannot reach.
		autoRedirect:        &recordingAutoRedirect{},
		platformInterface:   platformInterface,
		routeRuleSet:        []adapter.RuleSet{routeRuleSet},
		routeExcludeRuleSet: []adapter.RuleSet{routeExcludeRuleSet},
	}, routeRuleSet, routeExcludeRuleSet
}

// TestScopeOwnsRouteSetCallbacks is P0-L01.
//
// The invariant: once the Scope that started the inbound is closed, every callback Start registered
// is released - whether or not anything ever calls Inbound.Close(). The product only ever closes
// the Scope.
//
// The failure is injected after registration so the assertion is about ownership, not about the
// release function: on the unfixed tree Start registers two callbacks, the injected failure returns
// from Start, Scope.Close() finds nothing to run, and both callbacks are still held by their
// rule-sets.
func TestScopeOwnsRouteSetCallbacks(t *testing.T) {
	access := &callbackAccess{}
	inbound, routeRuleSet, routeExcludeRuleSet := newScopeOwnedInbound(access, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())

	// The real manager path: adapter/inbound/manager.go calls exactly this.
	err := scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart)
	require.Error(t, err, "the injected platform failure must surface from Start")
	require.Equal(t, 2, access.registered,
		"Start must have reached the registration block before the injected failure; otherwise this "+
			"test is asserting nothing")

	require.NoError(t, scope.Close())

	require.Equal(t, access.registered, access.unregistered,
		"every callback Start registered must be released by Scope.Close() alone: Box.Close() closes "+
			"the Scope and never calls Inbound.Close(), so a release that is not handed to the Scope "+
			"never runs")
	require.Empty(t, routeRuleSet.callbacks,
		"the route rule-set still holds a callback into a torn-down inbound after the owning Scope closed")
	require.Empty(t, routeExcludeRuleSet.callbacks,
		"the exclude rule-set's callback must be released by the owning Scope too")
	require.Empty(t, inbound.routeRuleSetCallback,
		"the stored elements must be cleared so a later explicit Close() cannot release them twice")
	require.Empty(t, inbound.routeExcludeRuleSetCallback)
}

// TestScopeOwnedCallbacksCannotFireAfterClose is the behavioural half of P0-L01.
//
// The count above is bookkeeping; this asks the question the user actually cares about. After the
// owning Scope closes, the rule-set must have no live observer left, so a later rule-set update
// cannot reach the closed inbound at all.
func TestScopeOwnedCallbacksCannotFireAfterClose(t *testing.T) {
	access := &callbackAccess{}
	inbound, routeRuleSet, _ := newScopeOwnedInbound(access, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
	require.NoError(t, scope.Close())

	// A rule-set update after teardown: the rule-set delivers to whatever is still registered.
	for _, element := range routeRuleSet.callbacks {
		element.Value(routeRuleSet)
	}
	require.Empty(t, routeRuleSet.callbacks,
		"no observer may survive the Scope that owned it, so a post-close rule-set update has "+
			"nothing to deliver to")

	// And the release stays exactly-once when an explicit Close() follows the Scope teardown, which
	// is the duplicate-tag path in adapter/inbound/manager.go.
	before := access.unregistered
	require.NoError(t, inbound.Close())
	require.Equal(t, before, access.unregistered,
		"a second release must not hand the same element to UnregisterCallback twice")
}

// observingAutoRedirect records whether the route-set callbacks were already gone at the moment the
// auto-redirect was closed.
//
// It is a double only because the real auto-redirect programs nftables/pf; the object whose ordering
// is under test is the *Inbound, and every piece of bookkeeping it consults here is production
// state.
type observingAutoRedirect struct {
	tun.AutoRedirect
	ruleSet              *trackingRuleSet
	started              bool
	closedWithCallbacks  bool
	closedAtAll          bool
	updateAfterCloseSeen atomic.Int32
}

func (r *observingAutoRedirect) Start() error {
	r.started = true
	return nil
}

func (r *observingAutoRedirect) Close() error {
	r.closedAtAll = true
	r.closedWithCallbacks = len(r.ruleSet.callbacks) > 0
	return nil
}

func (r *observingAutoRedirect) UpdateRouteAddressSet() error {
	if r.closedAtAll {
		r.updateAfterCloseSeen.Add(1)
	}
	return nil
}

// startOnlyStack and startOnlyInterface stand in for the device layer so the POST-START stage can be
// driven without a real interface. They are the only doubles in this test, and the assertion is not
// about them: it is about which cleanup Start registers and in what order the Scope runs them.
type startOnlyStack struct{ tun.Stack }

func (s *startOnlyStack) Start() error { return nil }
func (s *startOnlyStack) Close() error { return nil }

type startOnlyInterface struct{ tun.Tun }

func (t *startOnlyInterface) Start() error { return nil }
func (t *startOnlyInterface) Close() error { return nil }

// TestStartRegistersReleaseBeforeAutoRedirectTeardown pins which cleanup the REAL Start registers,
// not merely what closeAutoRedirect does when it is called by hand.
//
// Scope.Close() runs cleanups in reverse registration order. The callbacks are acquired in
// StartStateStart and the auto-redirect is closed in StartStatePostStart, so on registration order
// alone the release runs LAST - after the auto-redirect it protects is already gone. A rule-set
// notification landing in that window reaches updateRouteAddressSet, which calls
// UpdateRouteAddressSet on a closed auto-redirect.
//
// This drives both stages through a real Scope and the real Start entry point, so it fails if
// production ever goes back to registering the bare auto-redirect Close.
func TestStartRegistersReleaseBeforeAutoRedirectTeardown(t *testing.T) {
	access := &callbackAccess{}
	inbound, routeRuleSet, _ := newScopeOwnedInbound(access, &failingPlatformInterface{})
	observer := &observingAutoRedirect{ruleSet: routeRuleSet}
	inbound.autoRedirect = observer
	// Injected so StartStatePostStart can run. StartStateStart still fails at the platform interface,
	// which is what leaves PostStart as the stage that registers the teardown.
	inbound.tunStack = &startOnlyStack{}
	inbound.tunIf = &startOnlyInterface{}

	// The real manager path: a parent Scope that creates the child and passes it to Start.
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "inbound/tun[" + inbound.tag + "]"
	require.Error(t, scope.Start(name, inbound, adapter.StartStateStart),
		"the injected platform failure must surface from Start")
	require.Equal(t, 2, access.registered,
		"the callbacks must exist before their teardown is registered")

	// The second stage runs on the SAME child scope, exactly as the Box start sequence does it.
	require.NoError(t, scope.Start(name, inbound, adapter.StartStatePostStart))
	require.True(t, observer.started, "PostStart must have started the auto-redirect")

	require.NoError(t, scope.Close())

	require.True(t, observer.closedAtAll, "the auto-redirect must still be closed")
	require.False(t, observer.closedWithCallbacks,
		"Start must register a teardown that releases the route-set callbacks before it closes the "+
			"auto-redirect they are delivered to; registering the bare auto-redirect Close leaves a "+
			"window where a rule-set update reaches a closed auto-redirect")
	require.Equal(t, 2, access.unregistered, "released exactly once each")
	require.Empty(t, routeRuleSet.callbacks)
}

// TestRouteSetReleaseOrderInversedIsDetected is the reverse-break companion: it drives the same
// objects through the WRONG order and requires the assertion above to notice.
//
// Without this, a closeAutoRedirect that closed the auto-redirect first would still satisfy every
// count-based check - the callbacks are released either way - and the ordering contract would be
// pinned by nothing.
func TestRouteSetReleaseOrderInversedIsDetected(t *testing.T) {
	access := &callbackAccess{}
	inbound, routeRuleSet, routeExcludeRuleSet := newScopeOwnedInbound(access, nil)
	observer := &observingAutoRedirect{ruleSet: routeRuleSet}
	inbound.autoRedirect = observer

	inbound.routeRuleSetCallback = append(inbound.routeRuleSetCallback,
		routeRuleSet.RegisterCallback(inbound.updateRouteAddressSet))
	inbound.routeExcludeRuleSetCallback = append(inbound.routeExcludeRuleSetCallback,
		routeExcludeRuleSet.RegisterCallback(inbound.updateRouteAddressSet))

	// The inverse of closeAutoRedirect: tear down first, release afterwards.
	require.NoError(t, observer.Close())
	inbound.releaseRouteSetCallbacks()

	require.True(t, observer.closedAtAll)
	require.True(t, observer.closedWithCallbacks,
		"closing the auto-redirect before releasing the callbacks must be observable - if it is not, "+
			"the ordering assertion above proves nothing")
	require.Equal(t, 2, access.unregistered)
}
