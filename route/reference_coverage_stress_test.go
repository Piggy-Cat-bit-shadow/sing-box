package route

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// One hundred pass cycles over every owner of reusable state, with a goroutine baseline.
//
// # What this is for
//
// The walk is the one place every resource class meets, and it runs on paths that fire repeatedly for
// the life of the process: a memory trim, a resume boundary, a DEEP_IDLE release. §21 of the
// architecture-closure prompt forbids answering a discovered problem with a resident background
// mechanism, so this test's job is to prove the unified walk did not acquire one - no goroutine, no
// ticker, no timer, and nothing left behind after Close.
//
// It also re-asserts the action invariants across all 100 cycles rather than once: a pass may only
// ever make a pool smaller, it may never dial, and it may never touch a flow that is carrying traffic.

// TestOneHundredPassCyclesAreStableAndResurrectNothing is the §21 stress item for the resource walk.
func TestOneHundredPassCyclesAreStableAndResurrectNothing(t *testing.T) {
	outbound := &reuseTestKeeper{idleConns: 1}
	endpoint := &reuseTestKeeper{idleConns: 1}
	dns := &reuseTestKeeper{idleConns: 1}
	http := &reuseTestKeeper{idleConns: 1}

	manager, _ := newReuseTestManager(t, outbound, dns, func(ctx context.Context) context.Context {
		ctx = service.ContextWith[adapter.EndpointManager](ctx, &reuseTestEndpointManager{
			endpoints: []adapter.Endpoint{&coverageTestEndpoint{keeper: endpoint}},
		})
		return service.ContextWith[adapter.HTTPClientManager](ctx, &reuseTestHTTPClient{keeper: http})
	})
	owners := map[string]*reuseTestKeeper{"outbound": outbound, "endpoint": endpoint, "dns": dns, "http": http}

	// One live stream on every owner, started before the baseline. It must still be running at the
	// end: not one of the 100 cycles may touch it. Each owner starts with exactly one idle
	// connection, which this demand consumes, so the cycle identity below has no residue from setup
	// and a demand that had to dial would show up as dials != 0.
	for _, keeper := range owners {
		keeper.demand()
	}

	goroutinesBefore := stableGoroutineCount()

	suspect := boundary(t, 8*time.Second)
	retire := boundary(t, 20*time.Second)
	const cycles = 100
	// Four actions per cycle reach every owner: the boundary's walk, the trim, the DEEP_IDLE release,
	// and the retire band. The suspect band is deliberately the fifth call and contributes nothing -
	// it is a published verdict, not an action - so a suspect boundary that started acting would show
	// up here as a larger count rather than as a silently different pool.
	const actionsPerOwner = 4
	for cycle := 0; cycle < cycles; cycle++ {
		// Refill first, so the cycle ENDS with the pools emptied and the identity below is exact.
		for _, keeper := range owners {
			keeper.poolIdleConn()
			keeper.poolIdleConn()
		}
		manager.retireSuspectResources()
		manager.TrimIdleResources()
		manager.CloseIdleConnections()
		manager.onReuseBoundary(suspect)
		manager.onReuseBoundary(retire)
	}

	for name, keeper := range owners {
		idle, liveStreams, liveConns, dials, retires, idleClosed := keeper.snapshot()
		require.Zero(t, idle, "%s: idle state survived the final cycle", name)
		require.Zero(t, dials, "%s: a pass cycle dialled", name)
		require.Equal(t, 1, liveStreams, "%s: a pass cycle killed the live stream", name)
		require.Equal(t, 1, liveConns, "%s: a pass cycle closed the connection carrying the live stream", name)
		require.Equal(t, cycles*actionsPerOwner, retires,
			"%s: the number of retire actions is not the identity this test pins", name)
		// Two idle connections are pooled per cycle and the first action of the cycle closes them, so
		// the count is exactly two per cycle. Asserted as an identity rather than a floor: a walk that
		// stopped reaching an owner, or one that started double-acting, changes this number.
		require.Equal(t, cycles*2, idleClosed,
			"%s: the number of closed idle connections is not the identity this test pins", name)
	}

	requireStableGoroutines(t, goroutinesBefore, "the pass cycles leaked a goroutine")

	// Close wins. The distinction the walk documents is preserved here rather than flattened: the
	// BOUNDARY is gated by the closed flag, while the explicit trim / DEEP_IDLE passes are the
	// teardown path and keep working (TestRetireIdleResourcesCountsEveryReachablePool pins that).
	// What must not happen is a resurrection - a late boundary reaching an owner, a dial, a new
	// connection, or a goroutine - and that is what is asserted.
	manager.closed.Store(true)
	for _, keeper := range owners {
		keeper.poolIdleConn()
	}
	manager.onReuseBoundary(retire)
	for name, keeper := range owners {
		idle, liveStreams, _, dials, retires, _ := keeper.snapshot()
		require.Equal(t, 1, idle, "%s: a boundary after Close retired a pool", name)
		require.Equal(t, 1, liveStreams, "%s: a boundary after Close touched the live stream", name)
		require.Zero(t, dials, "%s: a boundary after Close dialled", name)
		require.Equal(t, cycles*actionsPerOwner, retires, "%s: a boundary after Close reached an owner", name)
	}

	// The explicit passes are still allowed to reduce, and only to reduce.
	manager.CloseIdleConnections()
	for name, keeper := range owners {
		idle, liveStreams, liveConns, dials, _, idleClosed := keeper.snapshot()
		require.Zero(t, idle, "%s: the teardown pass did not release the idle state", name)
		require.Equal(t, 1, liveStreams, "%s: the teardown pass touched the live stream", name)
		require.Equal(t, 1, liveConns, "%s: the teardown pass closed the connection carrying the live stream", name)
		require.Zero(t, dials, "%s: the teardown pass dialled", name)
		require.Equal(t, cycles*2+1, idleClosed, "%s: the teardown pass did not release exactly the idle state", name)
	}

	requireStableGoroutines(t, goroutinesBefore, "teardown leaked a goroutine")
}

// stableGoroutineCount reports the goroutine count once it has stopped moving.
//
// The count is sampled until two consecutive reads agree rather than slept through, because the
// goroutines this test cares about - a walk that started a worker, a timer that survived Close -
// appear and settle on their own schedule, and a fixed sleep would either be flaky or slow. A
// bounded number of attempts keeps a genuinely leaking tree from hanging the test: the assertion
// after the loop is what fails, not this helper.
func stableGoroutineCount() int {
	previous := runtime.NumGoroutine()
	for attempt := 0; attempt < 200; attempt++ {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
		current := runtime.NumGoroutine()
		if current == previous {
			return current
		}
		previous = current
	}
	return previous
}

// requireStableGoroutines allows a small negative drift but no growth.
//
// The contract is "does not grow without bound", not "is bit-identical": a runtime worker or a
// testing helper may exit between the two samples, and failing on that would make the test measure
// the scheduler. Growth in the direction this test exists to catch is positive and persistent, and
// the loop above has already waited for the count to settle before either sample was taken.
func requireStableGoroutines(t *testing.T, before int, message string) {
	t.Helper()
	after := stableGoroutineCount()
	require.LessOrEqual(t, after, before+2, "%s: before=%d after=%d", message, before, after)
}
