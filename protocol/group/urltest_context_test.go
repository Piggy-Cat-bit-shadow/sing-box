package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Tests for the context a group health operation runs under.
//
// # The defect these pin
//
// The group owns g.ctx, which carries the Box's services and the group's lifetime. The public
// entries passed the CALLER's context straight through to Measure:
//
//	URLTest.URLTest(ctx) -> URLTestGroup.urlTest(ctx, ...) -> URLTestOutboundsWithTarget(ctx, ...)
//
// A caller that supplies its own context - the Clash API supplies the HTTP request's, the native
// command client supplies a gRPC one - therefore replaced the Box context entirely. Three
// invariants broke at once:
//
//   - the per-Box Coordinator was not reachable, so the measurement concurrency limit did not apply
//   - the certificate roots and time service were not reachable, so a private-root endpoint failed
//     here while the identical native measurement succeeded
//   - Close canceled g.ctx, which the measurement was not using, so an in-flight measurement
//     survived the group being closed

// contextProbeDialer records the context values a measurement actually observed.
type contextProbeDialer struct {
	adapter.Outbound
	tag string

	coordinator atomic.Pointer[urltest.Coordinator]
	dials       atomic.Int32
}

func (d *contextProbeDialer) Type() string      { return "context-probe" }
func (d *contextProbeDialer) Tag() string       { return d.tag }
func (d *contextProbeDialer) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (d *contextProbeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	d.coordinator.Store(urltest.CoordinatorFromContext(ctx))
	return nil, net.ErrClosed
}

func (d *contextProbeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.dials.Add(1)
	d.coordinator.Store(urltest.CoordinatorFromContext(ctx))
	return nil, net.ErrClosed
}

// TestGroupMeasurementUsesBoxCoordinatorWithForeignCallerContext is §7.4.
//
// A caller supplying its own context must not be able to bypass the Box's measurement budget.
func TestGroupMeasurementUsesBoxCoordinatorWithForeignCallerContext(t *testing.T) {
	coordinator := urltest.NewCoordinator(10)

	node := &observingOutbound{tag: "node-a"}

	// The group context carries the Box services; the caller context carries nothing.
	baseCtx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	baseCtx = urltest.ContextWithCoordinator(baseCtx, coordinator)

	group, err := NewURLTestGroup(
		baseCtx, &stubOutboundManager{}, log.NewNOPFactory().NewLogger("group"),
		[]adapter.Outbound{node}, "https://probe.example/generate_204", 0, 0, 0, false)
	require.NoError(t, err)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	probe := &contextProbeDialer{tag: "probe"}
	group.outbounds = []adapter.Outbound{probe}

	// A FOREIGN caller context: this is what the Clash and native APIs supply.
	group.URLTest(context.Background())

	require.Eventually(t, func() bool { return probe.dials.Load() > 0 },
		5*time.Second, 5*time.Millisecond, "the measurement never ran")

	require.Same(t, coordinator, probe.coordinator.Load(),
		"the measurement did not see the Box coordinator, so a caller supplying its own context "+
			"bypasses the per-Box concurrency limit entirely - several groups can then run "+
			"unbounded measurements at once, which is exactly the budget the coordinator exists to "+
			"enforce")
}

// TestGroupCloseCancelsForeignCallerMeasurement is §7.4.
//
// Close cancels g.ctx. A measurement started with a foreign caller context must still be canceled.
func TestGroupCloseCancelsForeignCallerMeasurement(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})

	blocking := &blockingContextOutbound{tag: "blocking", entered: entered, release: release}

	group, _ := newGroupFixture(t, "https://probe.example/generate_204", blocking)
	group.selected.Store(&selectedState{tcp: blocking, udp: blocking})

	// A caller context with no cancellation of its own, as Background would be.
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	defer cancelCaller()

	done := make(chan struct{})
	go func() {
		defer close(done)
		group.URLTest(callerCtx)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the measurement never started")
	}

	require.NoError(t, group.Close())

	require.Eventually(t, func() bool { return blocking.canceled.Load() },
		5*time.Second, 5*time.Millisecond,
		"Close did not cancel a measurement started with a foreign caller context. Close cancels "+
			"g.ctx, and the measurement was not using it, so the group can be torn down while its "+
			"health work keeps running against services that no longer exist")

	close(release)
	<-done
}

// blockingContextOutbound blocks until its context ends.
type blockingContextOutbound struct {
	adapter.Outbound
	tag      string
	entered  chan struct{}
	release  chan struct{}
	canceled atomic.Bool
}

func (o *blockingContextOutbound) Type() string      { return "blocking-context" }
func (o *blockingContextOutbound) Tag() string       { return o.tag }
func (o *blockingContextOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *blockingContextOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	select {
	case o.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		o.canceled.Store(true)
		return nil, ctx.Err()
	case <-o.release:
		return nil, net.ErrClosed
	}
}

func (o *blockingContextOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// TestClosedGroupCannotStartAnotherHealthRound is §7.4.
func TestClosedGroupCannotStartAnotherHealthRound(t *testing.T) {
	probe := &contextProbeDialer{tag: "probe"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", probe)

	require.NoError(t, group.Close())

	group.URLTest(context.Background())
	group.CheckOutbounds(context.Background(), true)

	require.Never(t, func() bool { return probe.dials.Load() > 0 },
		200*time.Millisecond, 20*time.Millisecond,
		"a closed group must not start a health measurement; its services are gone and any result "+
			"would be written for a group that no longer exists")
}

var _ = http.StatusOK
var _ = httptest.NewServer

// TestPostStartAfterCloseDoesNotReviveGroup is §15.
//
// A closed group is terminal. PostStart must not leave it reporting itself started, nor queue
// background work for services that are gone.
func TestPostStartAfterCloseDoesNotReviveGroup(t *testing.T) {
	probe := &contextProbeDialer{tag: "probe"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", probe)

	require.NoError(t, group.Close())

	group.PostStart()

	group.access.Lock()
	started := group.started
	closed := group.closed
	group.access.Unlock()

	require.True(t, closed, "the group stays closed")
	require.False(t, started,
		"PostStart set started=true on a closed group, so the group reports itself running while "+
			"every other entry point refuses to work. A group cannot be both")

	require.Never(t, func() bool { return probe.dials.Load() > 0 },
		200*time.Millisecond, 20*time.Millisecond,
		"and no health work may reach the network")
}

// TestInterfaceUpdatedAfterCloseStartsNothing is §4.11.
func TestInterfaceUpdatedAfterCloseStartsNothing(t *testing.T) {
	probe := &contextProbeDialer{tag: "probe"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", probe)
	require.NoError(t, group.Close())

	group.CheckOutbounds(context.Background(), true)
	group.URLTest(context.Background())

	require.Never(t, func() bool { return probe.dials.Load() > 0 },
		200*time.Millisecond, 20*time.Millisecond,
		"a closed group must not dial")
}

// TestCoordinatorWaitDoesNotDeleteHealthWithoutDial is §8.5.
//
// A node that never got a measurement slot must not lose its health evidence. Deleting it would
// record a node as unhealthy on the strength of a queue wait, which is evidence changed without a
// measurement.
//
// # What this test does and does not prove
//
// It is a CONTRACT GUARD, not a discriminator. The reordering inside Measure is what makes the
// queue safe, and that is discriminated by TestCoordinatorWaitDoesNotConsumeProbeTimeout. The
// group's own outer per-member timeout was a second, compounding cause: with the old ordering the
// two charged the same wait twice. Demonstrating that in isolation would require holding a slot
// longer than C.TCPTimeout, i.e. a real 15-second wait, which is not an acceptable unit test and
// would rely on timing rather than a barrier.
//
// So this asserts the invariant that must hold end to end - no dial means no health deletion -
// rather than claiming to reproduce the timeout interaction.
func TestCoordinatorWaitDoesNotDeleteHealthWithoutDial(t *testing.T) {
	coordinator := urltest.NewCoordinator(1)

	// One node, with valid health evidence already recorded.
	node := &observingOutbound{tag: "node-a"}

	baseCtx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	baseCtx = urltest.ContextWithCoordinator(baseCtx, coordinator)

	group, err := NewURLTestGroup(
		baseCtx, &stubOutboundManager{}, log.NewNOPFactory().NewLogger("group"),
		[]adapter.Outbound{node}, "https://probe.example/generate_204", 0, 0, 0, false)
	require.NoError(t, err)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	storage := service.PtrFromContext[urltest.HistoryStorage](baseCtx)
	storage.StoreHealthHistory("node-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: 25})

	// Hold the Box's only slot so the group cannot measure.
	releaseSlot, err := coordinator.Acquire(baseCtx)
	require.NoError(t, err)

	// Ask for a forced round: it will queue for the slot.
	group.requestHealthRecheck()

	// Give it time to attempt measurement and be refused admission.
	time.Sleep(150 * time.Millisecond)

	releaseSlot()

	// The evidence must still be there, whether or not the round has completed by now.
	require.NotNil(t, storage.LoadURLTestHistoryFor("node-a", group.scope),
		"the node's health evidence was deleted while it was waiting for a measurement slot. The "+
			"node was never tested, so nothing was learned about it - and a queue wait is not "+
			"health evidence")
}

// TestBusyForcedRoundReportsFailureRatherThanAnEmptySuccess is grey zone A.
//
// The Clash API assigns the returned map and serialises it as the response body, so an empty map
// with a nil error tells the client "the test succeeded and every node is unreachable". A busy
// group cannot serve the request now, which is a failure to answer - not an answer of "nothing".
func TestBusyForcedRoundReportsFailureRatherThanAnEmptySuccess(t *testing.T) {
	node := &observingOutbound{tag: "node-a"}
	group, _ := newGroupFixture(t, "https://probe.example/generate_204", node)
	group.selected.Store(&selectedState{tcp: node, udp: node})

	// A round is already running, so a forced round cannot proceed.
	require.False(t, group.checking.Swap(true))

	result, err := group.URLTest(context.Background())

	require.Error(t, err,
		"a forced round that could not run reported success with an empty result. The Clash API "+
			"serialises that map as the response body, so the client is told the test succeeded and "+
			"every node is unreachable, when in fact nothing was measured at all")

	group.checking.Store(false)
	_ = result
}

// TestStartCloseInterfaceUpdatedGroupPointerIsRaceFree is grey zone B.
//
// Start replaces s.group, and the assignment happened OUTSIDE checkAccess - the lock was released
// before it - while readers such as Selected, DialContext and InterfaceUpdated take that lock. The
// pointer was therefore read and written concurrently.
//
// The readers are on the traffic path, so this is not a diagnostic-only window: a dial could observe
// a group pointer that was mid-replacement.
func TestStartCloseInterfaceUpdatedGroupPointerIsRaceFree(t *testing.T) {
	node := &observingOutbound{tag: "node-a"}

	// Built through the real constructor, so the wrapper is configured the way production does.
	manager := &singleOutboundManager{outbound: node}
	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(10))
	// NewURLTest reads the outbound manager from the context, which is how production supplies it.
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	constructed, err := NewURLTest(ctx, nil,
		log.NewNOPFactory().NewLogger("group"), "auto", option.URLTestOutboundOptions{
			Outbounds: []string{"node-a"},
			URL:       "https://probe.example/generate_204",
		})
	require.NoError(t, err)

	urlTest := constructed.(*URLTest)

	require.NoError(t, urlTest.Start())

	var waitGroup sync.WaitGroup
	stop := make(chan struct{})

	// A reader on the traffic path, exactly as production does it.
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = urlTest.Selected(N.NetworkTCP)
		}
	}()
	go func() {
		defer waitGroup.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = urlTest.Tag()
		}
	}()

	// The writer: repeated Start, each of which replaces the pointer.
	for attempt := 0; attempt < 50; attempt++ {
		_ = urlTest.Start()
	}

	close(stop)
	waitGroup.Wait()

	require.NoError(t, urlTest.Close())
}

// singleOutboundManager serves one outbound by tag.
type singleOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *singleOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	if m.outbound != nil && m.outbound.Tag() == tag {
		return m.outbound, true
	}
	return nil, false
}

func (m *singleOutboundManager) Outbounds() []adapter.Outbound {
	if m.outbound == nil {
		return nil
	}
	return []adapter.Outbound{m.outbound}
}

// TestWrapperCloseWinsAgainstConcurrentStart is §22/§23.
//
// Start constructs a group and then publishes it, with nothing checking whether Close already ran.
// A Close landing during construction therefore returns success and is then undone: the wrapper owns
// a live group again, with background work, after it has been closed.
//
// The window is widened deterministically by holding the outbound manager's lookup, which Start
// calls during construction, so Close completes while Start is provably between its detach and its
// publish.
func TestWrapperCloseWinsAgainstConcurrentStart(t *testing.T) {
	node := &observingOutbound{tag: "node-a"}
	manager := &blockingOutboundManager{
		outbound: node,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}

	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(10))
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	constructed, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("group"), "auto",
		option.URLTestOutboundOptions{
			Outbounds: []string{"node-a"},
			URL:       "https://probe.example/generate_204",
		})
	require.NoError(t, err)
	urlTest := constructed.(*URLTest)

	// Start, parked inside construction.
	startDone := make(chan error, 1)
	go func() {
		startDone <- urlTest.Start()
	}()

	select {
	case <-manager.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Start never reached construction")
	}

	// Close while Start is provably mid-construction.
	require.NoError(t, urlTest.Close())

	// Let Start finish publishing.
	close(manager.release)

	select {
	case <-startDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Start never returned")
	}

	require.Nil(t, urlTest.currentGroup(),
		"Close returned and was then undone by a late Start publication: the wrapper owns a live "+
			"group, with its own ticker and background context, after it has been closed. A closed "+
			"wrapper must stay closed")
}

// blockingOutboundManager parks its first lookup so a test can hold Start mid-construction.
type blockingOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (m *blockingOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	m.once.Do(func() {
		close(m.entered)
		<-m.release
	})
	if m.outbound != nil && m.outbound.Tag() == tag {
		return m.outbound, true
	}
	return nil, false
}

func (m *blockingOutboundManager) Outbounds() []adapter.Outbound {
	if m.outbound == nil {
		return nil
	}
	return []adapter.Outbound{m.outbound}
}

// TestWrapperMethodsDoNotPanicAfterClose is §26/§27.
//
// A closed wrapper has no group, and every entry point dereferenced it. These are API calls a
// control plane can make at any time, so a panic here is a crash of the management surface.
func TestWrapperMethodsDoNotPanicAfterClose(t *testing.T) {
	node := &observingOutbound{tag: "node-a"}
	manager := &singleOutboundManager{outbound: node}

	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(10))
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	constructed, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("group"), "auto",
		option.URLTestOutboundOptions{
			Outbounds: []string{"node-a"},
			URL:       "https://probe.example/generate_204",
		})
	require.NoError(t, err)
	urlTest := constructed.(*URLTest)
	require.NoError(t, urlTest.Start())
	require.NoError(t, urlTest.Close())

	require.NotPanics(t, func() {
		_ = urlTest.PostStart()
		_, _ = urlTest.URLTest(context.Background())
		urlTest.CheckOutbounds()
		urlTest.PerformUpdateCheck()
		_ = urlTest.MeasurementScope()
		_ = urlTest.Selected(N.NetworkTCP)
		_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.Socksaddr{})
		_, _ = urlTest.ListenPacket(context.Background(), M.Socksaddr{})
		urlTest.InterfaceUpdated(context.Background())
	}, "a closed wrapper must be safe to call from a control plane")
}

// TestWrapperFailedStartLeavesNoGroup is §28.
func TestWrapperFailedStartLeavesNoGroup(t *testing.T) {
	manager := &singleOutboundManager{} // resolves nothing

	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(10))
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	constructed, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("group"), "auto",
		option.URLTestOutboundOptions{
			Outbounds: []string{"missing"},
			URL:       "https://probe.example/generate_204",
		})
	require.NoError(t, err)
	urlTest := constructed.(*URLTest)

	require.Error(t, urlTest.Start(), "an unresolvable member fails the start")
	require.Nil(t, urlTest.currentGroup(),
		"a failed Start must leave no group: a partially constructed wrapper would report itself "+
			"usable while nothing owns the members")
}

// TestWrapperRepeatedStartDoesNotLeakPreviousGroup is §28.
//
// A second Start must dispose of the first group rather than stranding its ticker and background
// context, which nothing could then reach.
func TestWrapperRepeatedStartDoesNotLeakPreviousGroup(t *testing.T) {
	node := &observingOutbound{tag: "node-a"}
	manager := &singleOutboundManager{outbound: node}

	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	ctx = urltest.ContextWithCoordinator(ctx, urltest.NewCoordinator(10))
	ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)

	constructed, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("group"), "auto",
		option.URLTestOutboundOptions{
			Outbounds: []string{"node-a"},
			URL:       "https://probe.example/generate_204",
		})
	require.NoError(t, err)
	urlTest := constructed.(*URLTest)

	require.NoError(t, urlTest.Start())
	first := urlTest.currentGroup()
	require.NotNil(t, first)

	require.NoError(t, urlTest.Start())
	second := urlTest.currentGroup()
	require.NotNil(t, second)
	require.NotSame(t, first, second, "the second Start installs a new group")

	// The first group must have been disposed: its background context is cancelled.
	select {
	case <-first.backgroundContext().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the replaced group's background context was never cancelled, so its ticker and " +
			"health work keep running for a group nothing can reach")
	}

	require.NoError(t, urlTest.Close())
}
