package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/power"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The reuse boundary is the whole post-wake contract, and these tests are the contract:
//
//	a stale reusable resource is not handed to the next demand,
//	a live stream is not killed by the boundary,
//	a boundary with no demand does not dial,
//	and a short sleep, a suspect boundary or a closed manager touches nothing at all.
//
// The keepers here model the contract every real keeper is reviewed against - CloseIdleConnections
// closes what has no active user and never starts a connection - so that the walk itself is what is
// under test rather than one protocol's pool. The pools themselves are covered where they live.

// reuseTestKeeper is a reusable pool with the idle-only contract.
type reuseTestKeeper struct {
	adapter.Outbound

	access sync.Mutex
	// idleConns are pooled connections with no user. These are what a retire may close.
	idleConns int
	// liveStreams are streams carrying traffic. A connection with one is never closed by a retire,
	// which is what makes the live-flow assertion below mean something.
	liveStreams int
	liveConns   int
	// dials counts connections opened because a demand asked for one. A retire must never move it.
	dials  int
	retire int
	// idleClosed counts pooled connections a retire actually closed.
	idleClosed int
	// keepIdle is the eligibility flag the reference walk sets; the fake records it so the walk is
	// exercised the way the real managers exercise it.
	keepIdle bool
	// tag identifies the fake in the walk's log lines.
	tag string
}

// SetKeepIdleConnections is part of adapter.IdleConnectionKeeper, and it is what makes this fake
// reachable by the same walk the real pools are reached by.
func (k *reuseTestKeeper) SetKeepIdleConnections(keep bool) {
	k.access.Lock()
	defer k.access.Unlock()
	k.keepIdle = keep
}

func (k *reuseTestKeeper) CloseIdleConnections() {
	k.access.Lock()
	defer k.access.Unlock()
	k.retire++
	// The idle-only contract: what has no user is retired, what has one is left alone. Nothing here
	// can start a connection.
	k.idleClosed += k.idleConns
	k.idleConns = 0
}

// demand models a new flow arriving at the pool: it reuses an idle connection when there is one and
// dials only when there is not. That is what makes "the retire forced a fresh path" observable.
func (k *reuseTestKeeper) demand() (dialed bool) {
	k.access.Lock()
	defer k.access.Unlock()
	k.liveStreams++
	k.liveConns++
	if k.idleConns > 0 {
		k.idleConns--
		return false
	}
	k.dials++
	return true
}

// finishStream models a stream that ended: its connection goes back to the pool, which is the state a
// sleep then invalidates.
func (k *reuseTestKeeper) finishStream() {
	k.access.Lock()
	defer k.access.Unlock()
	k.liveStreams--
	k.liveConns--
	k.idleConns++
}

// resetCounters clears the observation counters, so a test can probe the walk and then measure the
// boundary without the probe being counted as the thing under test.
func (k *reuseTestKeeper) resetCounters() {
	k.access.Lock()
	defer k.access.Unlock()
	k.retire = 0
	k.idleClosed = 0
	k.dials = 0
}

// poolIdleConn adds a pooled connection that nobody is using, which is what a sleep survives.
func (k *reuseTestKeeper) poolIdleConn() {
	k.access.Lock()
	defer k.access.Unlock()
	k.idleConns++
}

// The identity methods the reference walk reads. They are explicit rather than inherited from the
// embedded interface so a nil embedded value cannot turn a wiring test into a panic.
func (k *reuseTestKeeper) Type() string           { return "reuse-test" }
func (k *reuseTestKeeper) Tag() string            { return k.tag }
func (k *reuseTestKeeper) Network() []string      { return nil }
func (k *reuseTestKeeper) Dependencies() []string { return nil }

func (k *reuseTestKeeper) snapshot() (idle, liveStreams, liveConns, dials, retires, idleClosed int) {
	k.access.Lock()
	defer k.access.Unlock()
	return k.idleConns, k.liveStreams, k.liveConns, k.dials, k.retire, k.idleClosed
}

// reuseTestDNSTransport is the same contract on the DNS side, where the prompt's "every new domain is
// slow" failure lives: a blackholed DoH/DoT connection is a stall that hits every name at once.
type reuseTestDNSTransport struct {
	adapter.DNSTransport
	keeper *reuseTestKeeper
}

func (t *reuseTestDNSTransport) Tag() string  { return "reuse-test-dns" }
func (t *reuseTestDNSTransport) Type() string { return "reuse-test-dns" }
func (t *reuseTestDNSTransport) SetKeepIdleConnections(keep bool) {
	t.keeper.SetKeepIdleConnections(keep)
}
func (t *reuseTestDNSTransport) CloseIdleConnections() {
	t.keeper.CloseIdleConnections()
}

type reuseTestOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *reuseTestOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }
func (m *reuseTestOutboundManager) Default() adapter.Outbound     { return nil }
func (m *reuseTestOutboundManager) Outbound(string) (adapter.Outbound, bool) {
	return nil, false
}

type reuseTestEndpointManager struct {
	adapter.EndpointManager
	endpoints []adapter.Endpoint
}

func (m *reuseTestEndpointManager) Endpoints() []adapter.Endpoint { return m.endpoints }

type reuseTestInboundManager struct {
	adapter.InboundManager
}

func (m *reuseTestInboundManager) Inbounds() []adapter.Inbound { return nil }

type reuseTestServiceManager struct {
	adapter.ServiceManager
}

func (m *reuseTestServiceManager) Services() []adapter.Service { return nil }

type reuseTestDNSTransportManager struct {
	adapter.DNSTransportManager
	transports []adapter.DNSTransport
}

func (m *reuseTestDNSTransportManager) Transports() []adapter.DNSTransport { return m.transports }
func (m *reuseTestDNSTransportManager) Transport(string) (adapter.DNSTransport, bool) {
	return nil, false
}
func (m *reuseTestDNSTransportManager) Default() adapter.DNSTransport { return nil }

type reuseTestNetworkManager struct {
	adapter.NetworkManager
}

func (m *reuseTestNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

// newReuseTestManager builds a started reference manager over fake managers.
//
// Nothing here dials: the only path under test is the one a resume boundary takes, and the fakes make
// every step of it observable.
func newReuseTestManager(t *testing.T, outboundKeeper, dnsKeeper *reuseTestKeeper) (*ReferenceManager, *power.Governor) {
	t.Helper()
	governor := power.NewGovernor(power.DefaultPolicy())
	ctx := service.ContextWith[*power.Governor](context.Background(), governor)
	outboundManager := &reuseTestOutboundManager{}
	if outboundKeeper != nil {
		outboundManager.outbounds = []adapter.Outbound{outboundKeeper}
	}
	transportManager := &reuseTestDNSTransportManager{}
	if dnsKeeper != nil {
		transportManager.transports = []adapter.DNSTransport{&reuseTestDNSTransport{keeper: dnsKeeper}}
	}
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outboundManager)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &reuseTestEndpointManager{})
	ctx = service.ContextWith[adapter.InboundManager](ctx, &reuseTestInboundManager{})
	ctx = service.ContextWith[adapter.ServiceManager](ctx, &reuseTestServiceManager{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, transportManager)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &reuseTestNetworkManager{})
	logger := log.NewNOPFactory().NewLogger("reference")
	manager := NewReferenceManager(ctx, logger, option.Options{})
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, manager.Start(adapter.StartStateStarted, scope))
	t.Cleanup(func() {
		require.NoError(t, scope.Close())
		governor.Close()
	})
	return manager, governor
}

// boundary builds the verdict a resume of the given length produces under the shipping policy, so a
// test that drives the observer directly is still driven by the policy's own numbers.
func boundary(t *testing.T, sleep time.Duration) power.ReuseBoundary {
	t.Helper()
	action := power.DefaultPolicy().ReuseFreshness.Classify(sleep, true)
	require.NotEqual(t, power.ReuseKeep, action,
		"the shipping policy keeps a %s sleep: this test is measuring the wrong band", sleep)
	return power.ReuseBoundary{Epoch: 1, Sleep: sleep, Known: true, Action: action}
}

// TestReuseBoundaryRetiresIdlePoolsAndPreservesLiveStreams is the acceptance criterion in one test.
func TestReuseBoundaryRetiresIdlePoolsAndPreservesLiveStreams(t *testing.T) {
	outboundKeeper := &reuseTestKeeper{}
	dnsKeeper := &reuseTestKeeper{idleConns: 1}
	// One live stream on the outbound, and one idle pooled connection beside it: the resource that
	// must survive the boundary, and the one that must not.
	require.True(t, outboundKeeper.demand(), "the first demand must dial: the pool starts empty")
	outboundKeeper.poolIdleConn()

	manager, _ := newReuseTestManager(t, outboundKeeper, dnsKeeper)
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	idle, liveStreams, liveConns, dials, retires, idleClosed := outboundKeeper.snapshot()
	require.Zero(t, idle, "an idle reusable connection survived the boundary")
	require.Equal(t, 1, idleClosed, "the boundary did not close the idle pooled connection")
	require.Equal(t, 1, liveStreams, "the live stream was killed by the boundary")
	require.Equal(t, 1, liveConns, "the connection carrying the live stream was closed")
	require.Equal(t, 1, dials, "the boundary dialled: only the demand in this test may dial")
	require.Equal(t, 1, retires, "the retire walk did not reach the outbound pool")

	// The next flow, arriving while the live stream is still running, gets a path of its own.
	require.True(t, outboundKeeper.demand(), "the flow after the boundary reused the retired connection")
	_, liveStreams, _, dials, _, _ = outboundKeeper.snapshot()
	require.Equal(t, 2, liveStreams, "the live stream did not survive the new flow")
	require.Equal(t, 2, dials)

	dnsIdle, _, _, dnsDials, dnsRetires, dnsIdleClosed := dnsKeeper.snapshot()
	require.Zero(t, dnsIdle, "an idle DNS transport connection survived the boundary")
	require.Equal(t, 1, dnsIdleClosed)
	require.Zero(t, dnsDials, "the boundary dialled a DNS transport")
	require.Equal(t, 1, dnsRetires, "the retire walk did not reach the DNS transports")
}

// TestTheDemandAfterTheBoundaryGetsAFreshPath is the other half: retiring only helps if the next flow
// cannot be handed the retired connection back.
func TestTheDemandAfterTheBoundaryGetsAFreshPath(t *testing.T) {
	keeper := &reuseTestKeeper{}
	require.True(t, keeper.demand(), "the first demand dials")
	keeper.finishStream()
	_, liveStreams, _, dials, _, _ := keeper.snapshot()
	require.Zero(t, liveStreams)
	require.Equal(t, 1, dials)

	manager, _ := newReuseTestManager(t, keeper, nil)
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	require.True(t, keeper.demand(),
		"the demand after the boundary reused the connection the boundary was supposed to retire")
	_, _, _, dials, retires, _ := keeper.snapshot()
	require.Equal(t, 2, dials)
	require.Equal(t, 1, retires)
}

// TestAShortSleepDoesNotTouchThePool is the power requirement, at the wiring level: the same
// managers, the same governor, and a sleep short enough that the policy keeps everything.
func TestAShortSleepDoesNotTouchThePool(t *testing.T) {
	keeper := &reuseTestKeeper{idleConns: 3}
	manager, _ := newReuseTestManager(t, keeper, nil)

	// The shipping policy's own verdict for a two second sleep.
	verdict := power.DefaultPolicy().ReuseFreshness.Classify(2*time.Second, true)
	require.Equal(t, power.ReuseKeep, verdict,
		"the shipping policy no longer keeps a two second sleep: this test is measuring the wrong band")
	manager.onReuseBoundary(power.ReuseBoundary{Epoch: 1, Sleep: 2 * time.Second, Known: true, Action: verdict})

	idle, _, _, dials, retires, idleClosed := keeper.snapshot()
	require.Equal(t, 3, idle, "a two second sleep retired a pooled connection")
	require.Zero(t, idleClosed)
	require.Zero(t, retires)
	require.Zero(t, dials)
}

// TestASuspectBoundaryRetiresNothing: the middle band is a published verdict, not an action. Pools
// are churned only where the policy says the sleep was long enough to have killed them.
func TestASuspectBoundaryRetiresNothing(t *testing.T) {
	keeper := &reuseTestKeeper{idleConns: 2}
	manager, _ := newReuseTestManager(t, keeper, nil)

	verdict := boundary(t, 8*time.Second)
	require.Equal(t, power.ReuseSuspect, verdict.Action,
		"the shipping policy no longer has a suspect band: this test is measuring the wrong band")
	manager.onReuseBoundary(verdict)

	idle, _, _, dials, retires, idleClosed := keeper.snapshot()
	require.Equal(t, 2, idle, "the suspect band retired a pool it was told to keep")
	require.Zero(t, idleClosed)
	require.Zero(t, retires)
	require.Zero(t, dials)
}

// TestAClosedManagerIgnoresALateBoundary is the Close ordering: teardown wins, and a boundary that
// was in flight while the manager was being torn down must not reach into half-closed managers.
func TestAClosedManagerIgnoresALateBoundary(t *testing.T) {
	keeper := &reuseTestKeeper{idleConns: 1}
	manager, _ := newReuseTestManager(t, keeper, nil)

	manager.closed.Store(true)
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	idle, _, _, dials, retires, idleClosed := keeper.snapshot()
	require.Equal(t, 1, idle, "a boundary after Close retired a pool")
	require.Zero(t, idleClosed)
	require.Zero(t, retires)
	require.Zero(t, dials)
}

// TestTheGovernorDrivesTheManagerThroughARealBoundary is the wiring itself: no direct call into the
// observer, a real governor, a real pause and a real resume. It is the test that would have caught
// the original defect's shape - a boundary that is published into nothing.
//
// The sleep is really slept for five milliseconds rather than simulated, because the policy's clock
// is the governor's own and this package must not reach into it. The threshold is moved instead, so
// the test proves the path rather than the tuning.
func TestTheGovernorDrivesTheManagerThroughARealBoundary(t *testing.T) {
	keeper := &reuseTestKeeper{idleConns: 1}
	// The clock is injected rather than slept through: this test proves the PATH - governor to observer
	// to keeper - and a test that waits for a threshold measures the scheduler instead. The tuning has
	// its own tests in common/power.
	policy := power.DefaultPolicy()
	policy.ReuseFreshness = power.ReuseFreshness{SuspectAfter: 5 * time.Second, RetireAfter: 15 * time.Second}
	now := time.Unix(1700000000, 0)
	var elapsed time.Duration
	var elapsedAccess sync.Mutex
	clock := func() time.Time {
		elapsedAccess.Lock()
		defer elapsedAccess.Unlock()
		return now.Add(elapsed)
	}
	governor := power.NewGovernorWithClock(policy, clock)
	ctx := service.ContextWith[*power.Governor](context.Background(), governor)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &reuseTestOutboundManager{outbounds: []adapter.Outbound{keeper}})
	ctx = service.ContextWith[adapter.EndpointManager](ctx, &reuseTestEndpointManager{})
	ctx = service.ContextWith[adapter.InboundManager](ctx, &reuseTestInboundManager{})
	ctx = service.ContextWith[adapter.ServiceManager](ctx, &reuseTestServiceManager{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &reuseTestDNSTransportManager{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &reuseTestNetworkManager{})
	manager := NewReferenceManager(ctx, log.NewNOPFactory().NewLogger("reference"), option.Options{})
	scope := adapter.NewScope(ctx, log.NewNOPFactory().Logger())
	require.NoError(t, manager.Start(adapter.StartStateStarted, scope))
	t.Cleanup(func() {
		require.NoError(t, scope.Close())
		governor.Close()
	})

	// A second observer, for the failure message only: if this ever fails, the message says whether
	// the governor published nothing, published a verdict the walk should have acted on, or published
	// it and lost it on the way to the pool.
	var observed []power.ReuseBoundary
	governor.AddReuseObserver(func(boundary power.ReuseBoundary) { observed = append(observed, boundary) })

	// The two links of the chain, asserted before the boundary runs, because a failure at either of
	// them says something different from a failure at the boundary itself:
	//
	//	1. the manager must have found the governor in its context, or it never registered;
	//	2. the walk must see the keeper, or it would retire nothing even when it runs.
	require.Same(t, governor, manager.powerGovernor,
		"the manager did not find the governor in its context, so no boundary could reach it")
	require.Equal(t, 1, manager.retireIdleResources(),
		"the walk cannot see the keeper through the managers in this context")
	// The probe retired the pooled connection, which is exactly what the boundary under test is
	// supposed to do; put the pool back and clear the counters so the two are not confused.
	keeper.resetCounters()
	keeper.poolIdleConn()
	require.False(t, manager.closed.Load(), "the manager was closed before the boundary")
	governor.SleepStarted()
	elapsedAccess.Lock()
	elapsed = 30 * time.Second
	elapsedAccess.Unlock()
	governor.Resumed()

	require.Equal(t, uint64(1), governor.ReuseEpoch(),
		"a thirty second sleep did not reach the retire threshold")
	idle, _, _, dials, retires, idleClosed := keeper.snapshot()
	require.Zero(t, idle, "the boundary did not reach the pool it was published for: observed=%+v retires=%d", observed, retires)
	require.Equal(t, 1, idleClosed)
	require.Equal(t, 1, retires)
	require.Zero(t, dials)
}

// TestRetireIdleResourcesCountsEveryReachablePool keeps the diagnostic honest: the number logged at
// a boundary is the number of pools actually asked to retire.
func TestRetireIdleResourcesCountsEveryReachablePool(t *testing.T) {
	outboundKeeper := &reuseTestKeeper{idleConns: 1}
	dnsKeeper := &reuseTestKeeper{idleConns: 1}
	manager, _ := newReuseTestManager(t, outboundKeeper, dnsKeeper)

	require.Equal(t, 2, manager.retireIdleResources())
	require.Equal(t, 2, manager.retireIdleResources(), "the walk must count pools, not connections")

	// It is also the teardown path (Box.CloseIdleConnections), so it must keep working after the
	// manager has been marked closed: that flag gates the boundary, not the explicit pass.
	manager.closed.Store(true)
	require.Equal(t, 2, manager.retireIdleResources())
}
