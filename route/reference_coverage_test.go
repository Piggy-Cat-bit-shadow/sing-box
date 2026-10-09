package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Runtime resource coverage, at the wiring level.
//
// # What went wrong, and why these tests exist
//
// The walk reached the HTTP client manager through an assertion on adapter.IdleConnectionKeeper, an
// interface with TWO methods: SetKeepIdleConnections (the eligibility axis) and CloseIdleConnections
// (the retire action). The production owner has only the second one:
//
//	common/httpclient/manager.go   (*Manager) CloseIdleConnections()   yes
//	                               (*Manager) SetKeepIdleConnections   absent
//
// so the assertion was false in every real build and the fourth owner of reusable state - the pool
// behind provider refresh, remote rule sets, the dashboard and the API - stayed unreachable from
// every pass: the reuse boundary, the memory trim and the DEEP_IDLE release. The regression test that
// was supposed to prove otherwise stayed green because its double implemented BOTH methods, which is
// precisely the failure mode of testing the pool instead of the capability the walk asserts.
//
// The fix names the capability the walk actually uses, so a pool that can only drop what is idle is
// reachable without also having to claim an eligibility axis it does not have. These tests pin both
// halves: the type the fix depends on, and the enumeration that must stay single-source.

// TestTheWalkCanReachTheProductionHTTPClientManager is the red-check that was missing.
//
// It asserts on the PRODUCTION concrete type, not on a double. A double that implements more than the
// real owner is exactly how this gap survived: if a future change widens the walk's requirement
// again, this test fails on the real type rather than passing on a fake.
func TestTheWalkCanReachTheProductionHTTPClientManager(t *testing.T) {
	var manager *httpclient.Manager
	require.Implements(t, (*adapter.IdleConnectionRetirer)(nil), manager,
		"the walk's retire action is unreachable for the production HTTP client manager: "+
			"the pool behind provider refresh, remote rule sets, the dashboard and the API is "+
			"not reached by the reuse boundary, the trim or the DEEP_IDLE release")
}

// coverageTestEndpoint is the endpoint owner class. Like the HTTP client manager it implements ONLY
// the retire action and no eligibility axis, because that is the shape the walk has to be able to
// reach.
type coverageTestEndpoint struct {
	adapter.Endpoint
	keeper *reuseTestKeeper
}

func (e *coverageTestEndpoint) Tag() string  { return "coverage-endpoint" }
func (e *coverageTestEndpoint) Type() string { return "coverage-endpoint" }
func (e *coverageTestEndpoint) CloseIdleConnections() {
	e.keeper.CloseIdleConnections()
}

// coverageManagers registers one distinguishable owner in every owner class the walk must discover.
func coverageManagers(outboundKeeper, dnsKeeper, endpointKeeper, httpKeeper *reuseTestKeeper) func(context.Context) context.Context {
	return func(ctx context.Context) context.Context {
		ctx = service.ContextWith[adapter.EndpointManager](ctx, &reuseTestEndpointManager{
			endpoints: []adapter.Endpoint{&coverageTestEndpoint{keeper: endpointKeeper}},
		})
		return service.ContextWith[adapter.HTTPClientManager](ctx, &reuseTestHTTPClient{keeper: httpKeeper})
	}
}

// TestEveryOwnerClassIsWalkedExactlyOnce pins the coverage contract per owner class: every owner of
// reusable state is discovered, acted on, acted on once, and not skipped.
//
// The four classes are asserted independently rather than in aggregate so that a failure names the
// class that was dropped. The endpoint class is included on purpose: it is inert for every endpoint
// kind that ships today (they implement the suspend axis, not the retire action), so without a test
// like this the arm could be deleted and nothing would notice until an endpoint grew a pool.
func TestEveryOwnerClassIsWalkedExactlyOnce(t *testing.T) {
	outboundKeeper := &reuseTestKeeper{idleConns: 1}
	endpointKeeper := &reuseTestKeeper{idleConns: 1}
	dnsKeeper := &reuseTestKeeper{idleConns: 1}
	httpKeeper := &reuseTestKeeper{idleConns: 1}

	manager, _ := newReuseTestManager(t, outboundKeeper, dnsKeeper,
		coverageManagers(outboundKeeper, dnsKeeper, endpointKeeper, httpKeeper))

	manager.TrimIdleResources()

	for name, keeper := range map[string]*reuseTestKeeper{
		"outbound": outboundKeeper,
		"endpoint": endpointKeeper,
		"dns":      dnsKeeper,
		"http":     httpKeeper,
	} {
		idle, _, _, dials, retires, idleClosed := keeper.snapshot()
		require.Zero(t, idle, "%s: an idle reusable connection survived the trim", name)
		require.Equal(t, 1, retires, "%s: the trim did not reach this owner exactly once", name)
		require.Equal(t, 1, idleClosed, "%s: the trim did not close the idle connection", name)
		require.Zero(t, dials, "%s: the trim dialled", name)
	}
}

// TestTheTrimAndTheBoundaryWalkTheSameOwnerSet is the single-source requirement made observable.
//
// The two walks have different actions - the trim only drops what is idle, the boundary also refuses
// new work on what a pool already holds - but they must discover the SAME owners. Before the walks
// shared one enumeration they were two hand-written lists of managers, and adding an owner to one was
// silently not adding it to the other.
func TestTheTrimAndTheBoundaryWalkTheSameOwnerSet(t *testing.T) {
	outboundKeeper := &reuseTestKeeper{idleConns: 1}
	endpointKeeper := &reuseTestKeeper{idleConns: 1}
	dnsKeeper := &reuseTestKeeper{idleConns: 1}
	httpKeeper := &reuseTestKeeper{idleConns: 1}

	manager, _ := newReuseTestManager(t, outboundKeeper, dnsKeeper,
		coverageManagers(outboundKeeper, dnsKeeper, endpointKeeper, httpKeeper))

	require.Equal(t, 4, manager.retireSuspectResources(),
		"the boundary did not discover every owner of reusable state")
	manager.TrimIdleResources()

	for name, keeper := range map[string]*reuseTestKeeper{
		"outbound": outboundKeeper,
		"endpoint": endpointKeeper,
		"dns":      dnsKeeper,
		"http":     httpKeeper,
	} {
		_, _, _, dials, retires, _ := keeper.snapshot()
		require.Equal(t, 2, retires,
			"%s: the boundary and the trim did not both reach this owner", name)
		require.Zero(t, dials, "%s: a walk dialled", name)
	}
}

// TestTheBoundaryIsReachedThroughTheCapabilityNotThePool is the §9 warning made a test: the boundary
// must reach an owner through the interface assertion the walk uses, so a pool that is wired but not
// capability-visible is caught here rather than in production.
func TestTheBoundaryIsReachedThroughTheCapabilityNotThePool(t *testing.T) {
	// A pool with the full capability: it must be asked to drain AND to retire.
	full := &reuseTestDrainer{}
	full.poolIdleConn()
	// A pool with only the retire action: it must be retired and must not be asked to drain.
	retireOnly := &reuseTestKeeper{idleConns: 1}

	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		ctx = service.ContextWith[adapter.OutboundManager](ctx, &reuseTestOutboundManager{
			outbounds: []adapter.Outbound{full},
		})
		return service.ContextWith[adapter.HTTPClientManager](ctx, &reuseTestHTTPClient{keeper: retireOnly})
	})

	manager.onReuseBoundary(boundary(t, 20*time.Second))

	drained, drainCalls, idleCalls, liveStreams, dials := full.snapshot()
	require.True(t, drained, "the boundary did not use the stronger action where it exists")
	require.Equal(t, 1, drainCalls)
	require.Equal(t, 1, idleCalls)
	require.Zero(t, liveStreams)
	require.Zero(t, dials)

	_, _, _, retireOnlyDials, retireOnlyRetires, retireOnlyIdleClosed := retireOnly.snapshot()
	require.Equal(t, 1, retireOnlyRetires,
		"the boundary did not reach a retire-capable owner that cannot drain")
	require.Equal(t, 1, retireOnlyIdleClosed)
	require.Zero(t, retireOnlyDials, "retiring a pool dialled")
}
