package tun

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"

	"github.com/stretchr/testify/require"
)

// Tests for the route rule-set REFERENCE lifecycle, which is a different resource from the callback
// registration that callback_lifecycle_test.go and scope_ownership_test.go pin.
//
// # The defect these pin
//
// Start calls IncRef on every route and route-exclude rule-set before it reads their destination
// CIDRs, and nothing ever called DecRef. A rule-set counts references by hand: IncRef keeps its
// parsed rules alive across an update, and RemoteRuleSet.Cleanup / LocalRuleSet.Cleanup only drop
// them once the count is back to zero. So every TUN inbound that started permanently pinned the
// rules of every rule-set it referenced, and a TUN that failed to start leaked the same reference
// again on the next attempt.
//
// # Why the existing tests could not see it
//
// They asserted on the callback bookkeeping, and the double's IncRef/DecRef were empty methods - a
// double that agrees with any implementation, including one that never releases. The double in
// callback_lifecycle_test.go now counts for real, and this file drives the real Start through a real
// Scope so the OWNERSHIP of the reference is what fails, not just the existence of a release call.
//
// # What is asserted
//
//   - one DecRef per IncRef, including two acquisitions of the same rule-set object
//   - the release happens on the Scope.Close() path, which is the only close path the product uses
//   - the branch WITHOUT an auto-redirect releases too: that branch takes the reference on a plain
//     desktop TUN and used to register nothing at all
//   - repeated release, repeated Close and repeated Box lifecycles never drive the count negative
//     and never accumulate

// countingRuleSet is the strict double these tests assert against: a rule-set whose reference
// counter is real and whose counter, like every production implementation, panics when driven
// negative.
type countingRuleSet struct {
	adapter.RuleSet
	name string

	access    sync.Mutex
	callbacks []*list.Element[adapter.RuleSetUpdateCallback]
	refs      atomic.Int32
	delivered atomic.Int32
	// onDecRef, when set, runs at the top of DecRef - before the count moves - so a test can observe
	// the state the release path was in when it decided to drop the reference.
	onDecRef func()
}

func (s *countingRuleSet) Name() string { return s.name }

func (s *countingRuleSet) ExtractIPSet() []*netipx.IPSet { return nil }

func (s *countingRuleSet) IncRef() { s.refs.Add(1) }

// DecRef mirrors LocalRuleSet.DecRef and RemoteRuleSet.DecRef, panic included: a negative count is a
// programming error, not a value a release path is allowed to swallow.
func (s *countingRuleSet) DecRef() {
	if s.onDecRef != nil {
		s.onDecRef()
	}
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *countingRuleSet) refCount() int { return int(s.refs.Load()) }

func (s *countingRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	element := &list.Element[adapter.RuleSetUpdateCallback]{Value: callback}
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks = append(s.callbacks, element)
	return element
}

// UnregisterCallback is deliberately stricter than the production one: releasing an element that is
// not registered is a bug in the caller, and a double that silently tolerated it would hide exactly
// the double release this file exists to catch.
func (s *countingRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	for index, existing := range s.callbacks {
		if existing == element {
			s.callbacks = append(s.callbacks[:index], s.callbacks[index+1:]...)
			return
		}
	}
	panic("rule-set: UnregisterCallback with an element that is not registered")
}

func (s *countingRuleSet) callbackCount() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.callbacks)
}

// deliver models a rule-set update: the production implementations snapshot the callback list under
// their lock and invoke the callbacks OUTSIDE it, which is what makes an in-flight delivery overlap a
// release.
func (s *countingRuleSet) deliver() {
	s.access.Lock()
	snapshot := make([]*list.Element[adapter.RuleSetUpdateCallback], len(s.callbacks))
	copy(snapshot, s.callbacks)
	s.access.Unlock()
	for _, element := range snapshot {
		element.Value(s)
		s.delivered.Add(1)
	}
}

// refPairingInterfaceName is not a name sing-tun can accept, so the interface step fails
// deterministically without creating anything on the host: darwin rejects it in fmt.Sscanf before it
// opens a socket, and Linux rejects it at TUNSETIFF because it is longer than IFNAMSIZ. The point of
// the fixture is that Start reaches the reference acquisition and then returns - whether the machine
// running the test is privileged or not.
const refPairingInterfaceName = "route-rule-set-reference-pairing-invalid-name"

// newRefCountingInbound builds the real *Inbound in the state Start(StartStateStart) expects. Only
// the platform integration and the auto-redirect are faked; the Scope, the inbound and every piece of
// reference bookkeeping under test are production objects.
func newRefCountingInbound(autoRedirect tun.AutoRedirect, platformInterface adapter.PlatformInterface) (*Inbound, *countingRuleSet, *countingRuleSet) {
	routeRuleSet := &countingRuleSet{name: "route-rule-set"}
	excludeRuleSet := &countingRuleSet{name: "route-exclude-rule-set"}
	return newRefCountingInboundWith(routeRuleSet, excludeRuleSet, autoRedirect, platformInterface),
		routeRuleSet, excludeRuleSet
}

func newRefCountingInboundWith(routeRuleSet, excludeRuleSet *countingRuleSet, autoRedirect tun.AutoRedirect, platformInterface adapter.PlatformInterface) *Inbound {
	return &Inbound{
		tag:            "tun-refs",
		ctx:            context.Background(),
		networkManager: &stackNetworkManagerStub{},
		logger:         log.NewNOPFactory().Logger(),
		tunOptions: tun.Options{
			// Keeps StartStateStart out of the outbound/endpoint probe, which needs a router this
			// fixture does not have and is not what is under test.
			EXP_MultiPendingPackets: true,
			Name:                    refPairingInterfaceName,
			MTU:                     1500,
		},
		autoRedirect:        autoRedirect,
		platformInterface:   platformInterface,
		routeRuleSet:        []adapter.RuleSet{routeRuleSet},
		routeExcludeRuleSet: []adapter.RuleSet{excludeRuleSet},
	}
}

// TestScopeCloseReleasesRouteSetRefs is the primary red test for S01.
//
// Start acquires one reference per route and route-exclude rule-set and then fails at the injected
// platform interface. The Scope that started the inbound is the only owner the product ever closes,
// so closing it must return both counters to zero.
func TestScopeCloseReleasesRouteSetRefs(t *testing.T) {
	inbound, routeRuleSet, excludeRuleSet := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart),
		"the injected platform failure must surface from Start")

	require.Equal(t, 1, routeRuleSet.refCount(),
		"Start must have taken the route rule-set's reference before the injected failure; otherwise "+
			"this test is asserting nothing")
	require.Equal(t, 1, excludeRuleSet.refCount(),
		"Start must have taken the exclude rule-set's reference too")
	require.Equal(t, 1, routeRuleSet.callbackCount(), "the callback registration is the other acquisition")

	require.NoError(t, scope.Close())

	require.Zero(t, routeRuleSet.refCount(),
		"the owning Scope must release the reference Start took; a rule-set only drops its parsed "+
			"rules once its count is back to zero, so a leaked reference pins them for the lifetime "+
			"of the process")
	require.Zero(t, excludeRuleSet.refCount(),
		"the exclude rule-set's reference must be released by the owning Scope too")
	require.Zero(t, routeRuleSet.callbackCount(), "and the callback must still be released")
}

// TestScopeCloseReleasesRouteSetRefsWithoutAutoRedirect covers the branch that had no owner at all.
//
// Start takes the reference when an auto-redirect exists OR the inbound runs on a plain interface OR
// the platform is Windows. The release used to be registered inside `if t.autoRedirect != nil`, so a
// desktop TUN with route_address_set and no auto-redirect took references that nothing ever handed
// back.
//
// The fixture has no auto-redirect and no platform interface, which is what puts Start on that
// branch; the interface step then fails on the unusable name above, so the rollback is exercised
// through the same Scope.Close() the Box uses.
func TestScopeCloseReleasesRouteSetRefsWithoutAutoRedirect(t *testing.T) {
	inbound, routeRuleSet, excludeRuleSet := newRefCountingInbound(nil, nil)

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	err := scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart)

	require.Equal(t, 1, routeRuleSet.refCount(),
		"the no-auto-redirect branch still takes the route rule-set's reference")
	require.Equal(t, 1, excludeRuleSet.refCount(),
		"the no-auto-redirect branch still takes the exclude rule-set's reference")
	require.Zero(t, routeRuleSet.callbackCount(),
		"and registers no callback: there is no auto-redirect to notify, which is exactly why the "+
			"release cannot be tied to the callbacks")
	if err != nil {
		t.Logf("Start returned as expected without an auto-redirect: %v", err)
	}

	require.NoError(t, scope.Close())

	require.Zero(t, routeRuleSet.refCount(),
		"the reference must be released even though no callback was ever registered; this is the "+
			"branch that had no owner at all")
	require.Zero(t, excludeRuleSet.refCount())
}

// TestRouteSetRefPairingSurvivesRepeatedRelease drives every release entry point that exists on the
// public surface, in every order.
//
// The three callers that can release - the Scope cleanup, closeAutoRedirect and an explicit
// Inbound.Close() - must be individually idempotent, because the duplicate-tag loser path in
// adapter/inbound/manager.go calls Close() on an inbound whose Scope has already run.
func TestRouteSetRefPairingSurvivesRepeatedRelease(t *testing.T) {
	inbound, routeRuleSet, excludeRuleSet := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
	require.Equal(t, 1, routeRuleSet.refCount())

	require.NoError(t, scope.Close())
	require.Zero(t, routeRuleSet.refCount())

	require.NotPanics(t, func() {
		require.NoError(t, inbound.Close())
		require.NoError(t, inbound.closeAutoRedirect())
		require.NoError(t, scope.Close())
	}, "a release that runs after the Scope already released must be a no-op, not a second DecRef: "+
		"every real rule-set panics on a negative count")

	require.Zero(t, routeRuleSet.refCount(), "and the count stays at zero")
	require.Zero(t, excludeRuleSet.refCount())
}

// TestSharedRuleSetIsReleasedOncePerAcquisition pins the deliberate absence of de-duplication.
//
// One rule-set object configured as both a route and a route-exclude set is acquired twice, so it
// must be released twice. A release that treated the acquisition list as a set would under-count and
// leak the rules of exactly the rule-sets that are referenced from two places.
func TestSharedRuleSetIsReleasedOncePerAcquisition(t *testing.T) {
	shared := &countingRuleSet{name: "shared-rule-set"}
	inbound := newRefCountingInboundWith(shared, shared, &recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))

	require.Equal(t, 2, shared.refCount(),
		"the same rule-set in both lists is two acquisitions, and needs two releases")
	require.Equal(t, 2, shared.callbackCount(),
		"and two callback registrations, one per list")

	require.NoError(t, scope.Close())

	require.Zero(t, shared.refCount(),
		"de-duplicating the acquisition list would release only one of the two references")
	require.Zero(t, shared.callbackCount())
}

// TestRepeatedBoxLifecyclesDoNotAccumulateRefs is the multi-round half: references must be exactly
// balanced over many start/close cycles, neither leaking nor drifting negative.
func TestRepeatedBoxLifecyclesDoNotAccumulateRefs(t *testing.T) {
	ruleSet := &countingRuleSet{name: "reused-rule-set"}
	for round := range 25 {
		inbound := newRefCountingInboundWith(ruleSet, &countingRuleSet{name: "exclude"}, &recordingAutoRedirect{}, &failingPlatformInterface{})
		scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
		require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
		require.Equal(t, 1, ruleSet.refCount(), "round %d acquired exactly once", round)
		require.NoError(t, scope.Close())
		require.Zero(t, ruleSet.refCount(), "round %d released exactly once", round)
	}
}

// TestRefReleasePrecedesRuleSetTeardown is the ordering half.
//
// Dropping the reference is not the same responsibility as unregistering the callback, and the order
// between them is not free: a callback that is still registered can be delivered on the next
// rule-set update and reads the rule-sets' rules through ExtractIPSet. Releasing the reference first
// would let a concurrent update drop those rules underneath a callback that is still wired in.
//
// The release must therefore unregister first and only then decrement.
func TestRefReleasePrecedesRuleSetTeardown(t *testing.T) {
	ruleSet := &countingRuleSet{name: "ordering-rule-set"}
	inbound := newRefCountingInboundWith(ruleSet, &countingRuleSet{name: "exclude"}, &recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))

	// Observe the ordering from inside the release: at the moment DecRef is about to run, the callback
	// list must already be empty.
	observed := make(chan int, 4)
	ruleSet.onDecRef = func() {
		select {
		case observed <- ruleSet.callbackCount():
		default:
		}
	}
	require.NoError(t, scope.Close())
	require.Len(t, observed, 1, "the reference must be released exactly once")

	require.Zero(t, <-observed,
		"DecRef must run only after every callback is unregistered: a registered callback reads the "+
			"rules that DecRef is about to let the rule-set drop")
	require.Zero(t, ruleSet.refCount())
}

// TestRouteSetRefsUnderConcurrentCallbackDelivery runs a rule-set update against a Scope close.
//
// Releasing a callback does not wait for a delivery that is already executing, so the update and the
// release genuinely overlap. The invariants that must survive: no data race (-race), no negative
// reference, and a count of zero once the Scope has closed.
func TestRouteSetRefsUnderConcurrentCallbackDelivery(t *testing.T) {
	inbound, routeRuleSet, _ := newRefCountingInbound(&recordingAutoRedirect{}, &failingPlatformInterface{})

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	require.Error(t, scope.Start("inbound/tun["+inbound.tag+"]", inbound, adapter.StartStateStart))
	require.Equal(t, 1, routeRuleSet.refCount())

	var waitGroup sync.WaitGroup
	delivering := make(chan struct{})
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for index := range 200 {
			routeRuleSet.deliver()
			if index == 0 {
				close(delivering)
			}
		}
	}()

	// Wait until the update is genuinely in flight, so the close below overlaps it rather than
	// winning the race against the goroutine's start-up.
	<-delivering
	require.NoError(t, scope.Close())
	waitGroup.Wait()

	require.Zero(t, routeRuleSet.refCount(),
		"a rule-set update racing the teardown must not change how many references were released")
	require.Zero(t, routeRuleSet.callbackCount())
	require.NotZero(t, routeRuleSet.delivered.Load(),
		"the update must actually have been delivered; otherwise the race was never exercised")
}
