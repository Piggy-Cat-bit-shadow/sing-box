package group

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the health recheck a traffic failure requests.
//
// # The two defects these pin
//
// A failed business connection cleared the selection and asked for a health recheck with force =
// false. Because the node's measurement was still fresh, the batch SKIPPED it - so no probe ran at
// all, and the following selection simply re-evaluated the same history. The node that had just
// failed to carry traffic was eligible to be chosen again on the strength of the measurement that
// had already been contradicted.
//
// The recheck also had no worker-level single-flight. Every failing connection started its own
// goroutine, so a burst produced a burst of goroutines even though the measurement itself collapsed
// to one. On a mobile device that is the traffic pattern a health check exists to avoid.

// recheckCountingOutbound counts how many times it is actually probed.
type recheckCountingOutbound struct {
	adapter.Outbound
	tag     string
	probes  atomic.Int32
	dialErr error
}

func (o *recheckCountingOutbound) Type() string      { return "stub" }
func (o *recheckCountingOutbound) Tag() string       { return o.tag }
func (o *recheckCountingOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *recheckCountingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.probes.Add(1)
	if o.dialErr != nil {
		return nil, o.dialErr
	}
	return &stubConn{}, nil
}

func (o *recheckCountingOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.probes.Add(1)
	if o.dialErr != nil {
		return nil, o.dialErr
	}
	return &stubPacketConn{}, nil
}

// TestTrafficFailureForcesAHealthRecheck is §4.
//
// The node's measurement is fresh. A traffic failure must still cause a real probe; otherwise the
// recheck is a no-op and selection re-reads the very evidence the failure just contradicted.
func TestTrafficFailureForcesAHealthRecheck(t *testing.T) {
	node := &recheckCountingOutbound{tag: "node-a"}

	group, storage := newGroupFixture(t, "https://probe.example/generate_204", node)

	// A FRESH measurement: the batch would normally skip this node.
	storage.StoreURLTestHistoryFor("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	require.Equal(t, int32(0), node.probes.Load())

	group.selected.Store(&selectedState{tcp: node, udp: node})

	// A business connection fails through this node.
	group.clearSelectionFor(N.NetworkTCP, node)

	// The recheck runs in the background; wait for it to actually probe.
	require.Eventually(t, func() bool { return node.probes.Load() > 0 },
		3*time.Second, 5*time.Millisecond,
		"a traffic failure must force a real health probe; with force=false the fresh measurement "+
			"is skipped, so nothing is re-measured and selection re-reads the evidence the failure "+
			"just contradicted")
}

// TestRecheckSingleFlightCollapsesABurst is §5.
//
// Many concurrent traffic failures must not create many recheck goroutines.
//
// # What this test used to count, and why it could not fail
//
// It asserted on `recheckRuns`, the number of forced ROUNDS, and its own comment said that counting
// probes "would pass either way: the health function's own `checking` guard already collapses
// concurrent measurements, so a per-failure goroutine also produces one probe. What that design
// produces is one short-lived goroutine per failure, which is what this pins."
//
// The comment rejected one insensitive instrument and adopted another of the same kind. MEASURED by an
// independent adversary with the single-flight guard deleted from `requestHealthRecheck`
// (`if g.recheckWorker` -> `if false && g.recheckWorker`; `go vet` exit 0 first): this test and its
// handoff sibling BOTH PASSED, because a SECOND, downstream guard - the round's own `checking` flag -
// still collapses the rounds. The property in the name was the goroutine count, and the assertion
// could not see it.
//
// The census below counts the thing the name is about: the goroutines actually executing
// `(*URLTestGroup).drainHealthRechecks`, which is the worker the guard exists to single-flight. It is
// exact rather than sampled, because `requestHealthRecheck` starts its worker and RETURNS - there is
// no inline path - so with the guard at most one such goroutine exists, and without it one exists per
// request.
func TestRecheckSingleFlightCollapsesABurst(t *testing.T) {
	// The probe blocks, so the recheck stays in flight while the burst arrives.
	release := make(chan struct{})
	node := &blockingRecheckOutbound{tag: "node-a", release: release}

	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	const burst = 100
	var waitGroup sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < burst; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			group.requestHealthRecheck()
		}()
	}
	close(start)
	waitGroup.Wait()

	// THE DETERMINISTIC WINDOW. Every requester has returned and the probe is still blocking, so every
	// worker that was started is parked inside `drainHealthRechecks` right now - no sampling, no peak
	// tracking, and no dependence on how fast the machine is.
	require.Eventually(t, func() bool { return recheckWorkers() >= 1 },
		3*time.Second, 5*time.Millisecond,
		"no drain worker was started at all, so there is nothing here under test")

	// 2 and not 1: a worker that finds new debt retired while it ran hands the tail to a REPLACEMENT it
	// starts from inside its own frame, so the retiring and the replacement worker coexist for an
	// instant. The number that indicates the defect is `burst`, so the gap between 2 and 100 is the
	// whole margin this assertion needs.
	require.LessOrEqual(t, recheckWorkers(), 2,
		"%d concurrent traffic failures started %d recheck workers; the single-flight guard must "+
			"collapse them into at most one worker (plus an instant of handoff). A worker per failure is "+
			"the goroutine storm the guard exists to prevent", burst, recheckWorkers())

	// Let the in-flight round finish, then wait for the worker to go IDLE before reading the round
	// count: the previous version read it as soon as one probe had been observed, so it compared a
	// mid-drain snapshot against a final bound. Its own handoff sibling already waits for the worker,
	// and the adversary measured the mutated product reporting 12 and then 3 against a bound of 2 -
	// discriminating in value, read before the value existed.
	close(release)
	require.Eventually(t, func() bool { return node.probes.Load() >= 1 },
		3*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool {
		group.recheckAccess.Lock()
		defer group.recheckAccess.Unlock()
		return !group.recheckWorker
	}, 3*time.Second, 5*time.Millisecond, "the recheck worker must finish before its count is read")

	// The round count is kept as a SECOND, weaker signal: it is what the coalescing contract is about,
	// and it would catch a design that served the burst sequentially. It is not the load-bearing
	// assertion any more - the census above is.
	//
	// The bound is 2, not 1, and that is the coalescing contract working: one round was already
	// running when the burst arrived, and the burst is owed exactly ONE further forced round. The
	// number that would indicate a bug is %d.
	require.LessOrEqual(t, group.recheckRuns.Load(), int32(2),
		"%d concurrent traffic failures must coalesce into at most one extra forced round; a "+
			"goroutine per failure would run a round per failure, which is the storm a health check "+
			"exists to avoid", burst)

	require.GreaterOrEqual(t, node.probes.Load(), int32(1),
		"and the burst must actually cause a probe")
}

// recheckWorkers counts the goroutines currently executing this package's recheck worker.
//
// # Why the frame and not a counter
//
// A counter would have to live in production and be incremented on a goroutine start - test-visible
// state added to the thing under test, which is the shape this repository avoids. The stack already
// carries the fact, and it carries it for exactly the function the single-flight guard protects.
//
// It is called from `require.Eventually`, so it runs on testify's goroutine; that goroutine's frames
// belong to testify, not to this package, so unlike the churn census in `route` this predicate cannot
// count its own caller. It also cannot see a worker currently executing inside a dependency - an
// under-count, the conservative direction, and one that cannot invent a storm that is not there.
func recheckWorkers() int {
	buffer := make([]byte, 1<<20)
	read := runtime.Stack(buffer, true)
	count := 0
	for _, block := range strings.Split(string(buffer[:read]), "\n\n") {
		if strings.Contains(block, "(*URLTestGroup).drainHealthRechecks") {
			count++
		}
	}
	return count
}

// blockingRecheckOutbound blocks its probe until released, so a recheck stays in flight.
type blockingRecheckOutbound struct {
	adapter.Outbound
	tag     string
	probes  atomic.Int32
	release chan struct{}
}

func (o *blockingRecheckOutbound) Type() string      { return "stub" }
func (o *blockingRecheckOutbound) Tag() string       { return o.tag }
func (o *blockingRecheckOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *blockingRecheckOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.probes.Add(1)
	select {
	case <-o.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &stubConn{}, nil
}

func (o *blockingRecheckOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not used")
}

var _ = urltest.MeasurementScope{}

// TestToleranceDoesNotOverflow is §47, §64(P).
//
// Both the delay and the tolerance are uint16. Their sum therefore wraps, and a node comfortably
// inside the tolerance could be rejected while a far slower one was accepted - the exact inverse of
// what a tolerance means.
func TestToleranceDoesNotOverflow(t *testing.T) {
	// A current best of 30000 with a tolerance of 50000 accepts anything up to 80000, which is
	// every possible delay. A candidate of 100 is therefore comfortably better and must win.
	//
	// Wrapped: 30000 + 50000 = 14464, so the comparison `30000 > 14464` is TRUE and the current
	// best is REPLACED. The result is the opposite of the tolerance's intent.
	current := uint16(30000)
	candidate := uint16(100)
	tolerance := uint16(50000)

	wrapped := current + tolerance
	require.Equal(t, uint16(14464), wrapped,
		"the naive sum wraps, which is the defect being pinned")

	require.False(t, uint32(current) > uint32(candidate)+uint32(tolerance),
		"with the arithmetic widened, a candidate of 100 is inside the tolerance of a 30000 best "+
			"and must not replace it")
	require.True(t, current+tolerance > candidate,
		"while the wrapped uint16 arithmetic says the opposite - which is why the widening is "+
			"required rather than cosmetic")
}
