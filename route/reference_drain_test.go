package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The reuse boundary's walk has two capabilities now, not one, and these tests pin which action each
// owner gets:
//
//	a pool that can refuse new work on what it holds  -> draining, AND its idle resources retired
//	a pool that can only drop what is idle            -> its idle resources retired (unchanged)
//	the HTTP client service                           -> reached at all (it was not, before)
//
// The distinction matters because the two actions are not interchangeable. A multiplexed session with
// a live stream cannot be closed - the stream would lose its transport - and must not be left able to
// take new work, because an open stream is not evidence that the path survived the sleep. Draining is
// the only action that is neither of those two wrong things, and the walk has to prefer it where it
// exists without silently dropping the idle release where it does not.

// reuseTestDrainer is a pool with both capabilities, modelled on the XHTTP XMUX session pool: it holds
// idle connections, connections with a stream on them, and it can refuse new work on the latter.
type reuseTestDrainer struct {
	adapter.Outbound

	access sync.Mutex
	// idleConns are pooled connections with no user; a boundary closes them.
	idleConns int
	// liveStreams are streams carrying traffic; a boundary must not disturb them.
	liveStreams int
	// drained reports whether new work is currently being refused.
	drained bool
	// drainCalls and idleCalls count the two entry points separately, which is what makes "the walk
	// preferred draining" observable rather than inferred.
	drainCalls int
	idleCalls  int
	// dials counts connections opened because a demand asked for one.
	dials int
}

func (d *reuseTestDrainer) SetKeepIdleConnections(keep bool) {}

func (d *reuseTestDrainer) CloseIdleConnections() {
	d.access.Lock()
	defer d.access.Unlock()
	d.idleCalls++
	d.idleConns = 0
}

func (d *reuseTestDrainer) RetireSuspect() {
	d.access.Lock()
	defer d.access.Unlock()
	d.drainCalls++
	d.drained = true
	d.idleConns = 0
}

// demand models a new stream: it takes an idle connection when the pool still offers one and this pool
// is not refusing new work, and dials otherwise. That is what makes "the boundary refused the session"
// observable.
func (d *reuseTestDrainer) demand() (dialed bool) {
	d.access.Lock()
	defer d.access.Unlock()
	d.liveStreams++
	if d.drained || d.idleConns == 0 {
		d.dials++
		return true
	}
	d.idleConns--
	return false
}

// poolIdleConn adds a pooled connection nobody is using, which is what a sleep survives.
func (d *reuseTestDrainer) poolIdleConn() {
	d.access.Lock()
	defer d.access.Unlock()
	d.idleConns++
}

func (d *reuseTestDrainer) idleCount() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.idleConns
}

func (d *reuseTestDrainer) Type() string           { return "reuse-test-drainer" }
func (d *reuseTestDrainer) Tag() string            { return "drainer" }
func (d *reuseTestDrainer) Network() []string      { return nil }
func (d *reuseTestDrainer) Dependencies() []string { return nil }

func (d *reuseTestDrainer) snapshot() (drained bool, drainCalls, idleCalls, liveStreams, dials int) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.drained, d.drainCalls, d.idleCalls, d.liveStreams, d.dials
}

// reuseTestHTTPClient is the fourth owner of reusable state: the pool behind provider refresh, remote
// rule sets, the dashboard and the API. It is an adapter.HTTPClientManager and an
// adapter.IdleConnectionKeeper, and it is registered in the service context rather than reached
// through a manager list.
type reuseTestHTTPClient struct {
	adapter.HTTPClientManager
	keeper *reuseTestKeeper
}

func (c *reuseTestHTTPClient) ResetNetwork() {}
func (c *reuseTestHTTPClient) SetKeepIdleConnections(keep bool) {
	c.keeper.SetKeepIdleConnections(keep)
}
func (c *reuseTestHTTPClient) CloseIdleConnections() { c.keeper.CloseIdleConnections() }

// TestTheBoundaryDrainsAPoolThatCanRefuseNewWork is the P0-C acceptance criterion at the wiring level:
// the walk asks for the stronger action where it exists.
func TestTheBoundaryDrainsAPoolThatCanRefuseNewWork(t *testing.T) {
	drainer := &reuseTestDrainer{}
	// One live stream on the pool, and one idle connection beside it: the resource that must survive
	// and the one that must not.
	require.True(t, drainer.demand(), "the first demand must dial: the pool starts empty")
	drainer.poolIdleConn()

	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.OutboundManager](ctx, &reuseTestOutboundManager{outbounds: []adapter.Outbound{drainer}})
	})
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	drained, drainCalls, idleCalls, liveStreams, dials := drainer.snapshot()
	require.True(t, drained, "the boundary did not refuse new work on a pool that can express it")
	require.Equal(t, 1, drainCalls, "the boundary did not call the draining entry point")
	require.Equal(t, 1, idleCalls,
		"the boundary skipped the idle release: a pool that drains must still have its idle resources retired")
	require.Equal(t, 1, liveStreams, "the boundary killed the live stream")
	require.Equal(t, 1, dials, "the boundary dialled: only the demand in this test may dial")

	// The next flow must NOT be placed on what the boundary refused.
	require.True(t, drainer.demand(), "the flow after the boundary reused a connection the boundary refused")
	_, _, _, liveStreams, dials = drainer.snapshot()
	require.Equal(t, 2, liveStreams, "the live stream did not survive the new flow")
	require.Equal(t, 2, dials)
}

// TestTheBoundaryStillRetiresAPoolThatCannotDrain is the no-regression half. Every pool except the
// XHTTP session pool is in this class, and for those the boundary must do exactly what it did before
// the draining capability existed.
func TestTheBoundaryStillRetiresAPoolThatCannotDrain(t *testing.T) {
	keeper := &reuseTestKeeper{idleConns: 2}
	keeper.resetCounters()
	manager, _ := newReuseTestManager(t, keeper, nil)
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	idle, _, _, dials, retires, idleClosed := keeper.snapshot()
	require.Zero(t, idle, "an idle reusable connection survived the boundary")
	require.Equal(t, 1, retires, "the boundary did not reach the outbound pool")
	require.Equal(t, 2, idleClosed, "the boundary did not close every idle pooled connection")
	require.Zero(t, dials, "the boundary dialled")
	require.Implements(t, (*adapter.IdleConnectionKeeper)(nil), adapter.Outbound(keeper))
}

// TestTheBoundaryReachesTheHTTPClientService closes the P0-C item that was recorded as unreachable.
//
// The HTTP client manager owns the pooled connections behind provider refresh, remote rule sets, the
// dashboard and the API. It is not an outbound, an endpoint or a DNS transport, so the walk needed a
// step of its own for it - and before that step existed, a resume boundary retired every pool except
// these.
func TestTheBoundaryReachesTheHTTPClientService(t *testing.T) {
	httpClient := &reuseTestHTTPClient{keeper: &reuseTestKeeper{idleConns: 3}}
	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.HTTPClientManager](ctx, httpClient)
	})
	manager.onReuseBoundary(boundary(t, 20*time.Second))

	idle, _, _, dials, retires, idleClosed := httpClient.keeper.snapshot()
	require.Zero(t, idle, "an idle pooled HTTP client connection survived the boundary")
	require.Equal(t, 1, retires, "the walk did not reach the HTTP client service")
	require.Equal(t, 3, idleClosed, "the walk did not close the HTTP client service's idle connections")
	require.Zero(t, dials, "retiring the HTTP client pools dialled")

	// And the other two passes reach it as well, because it is the same walk: a memory trim and the
	// DEEP_IDLE release must not have been left with the old, narrower reach.
	httpClient.keeper.poolIdleConn()
	manager.TrimIdleResources()
	_, _, _, _, retires, _ = httpClient.keeper.snapshot()
	require.Equal(t, 2, retires, "the trim pass did not reach the HTTP client service")

	httpClient.keeper.poolIdleConn()
	manager.CloseIdleConnections()
	_, _, _, _, retires, _ = httpClient.keeper.snapshot()
	require.Equal(t, 3, retires, "the DEEP_IDLE/teardown pass did not reach the HTTP client service")
}

// TestTheSuspectBandDrainsNothing is the band policy at the walk: a suspect boundary advances the
// epoch and touches no pool, which is what keeps a mid-length sleep from costing a handshake for no
// correctness gain.
func TestTheSuspectBandDrainsNothing(t *testing.T) {
	drainer := &reuseTestDrainer{}
	require.True(t, drainer.demand(), "the first demand must dial: the pool starts empty")
	drainer.poolIdleConn()
	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.OutboundManager](ctx, &reuseTestOutboundManager{outbounds: []adapter.Outbound{drainer}})
	})

	manager.onReuseBoundary(boundary(t, 7*time.Second))

	drained, drainCalls, idleCalls, liveStreams, dials := drainer.snapshot()
	require.False(t, drained, "the suspect band refused new work: it is a published state, not an action")
	require.Zero(t, drainCalls)
	require.Zero(t, idleCalls)
	require.Equal(t, 1, liveStreams)
	require.Equal(t, 1, dials)
	require.Equal(t, 1, drainer.idleCount(), "the suspect band retired an idle pooled connection")
	// And the idle connection is still usable, which is what "kept by policy" means: the next demand
	// reuses it rather than dialling.
	require.False(t, drainer.demand(), "the suspect band made the next flow dial")
}

// TestAClosedBoundaryManagerDrainsNothing is the Close-wins rule on the new entry point: the governor
// is closed before the scope that owns this manager, so a boundary can be in flight while the pools it
// would reach are being torn down.
func TestAClosedBoundaryManagerDrainsNothing(t *testing.T) {
	drainer := &reuseTestDrainer{idleConns: 1}
	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.OutboundManager](ctx, &reuseTestOutboundManager{outbounds: []adapter.Outbound{drainer}})
	})
	manager.closed.Store(true)

	manager.onReuseBoundary(boundary(t, 20*time.Second))

	drained, drainCalls, idleCalls, _, _ := drainer.snapshot()
	require.False(t, drained, "a closed manager drained a pool")
	require.Zero(t, drainCalls)
	require.Zero(t, idleCalls)
}
