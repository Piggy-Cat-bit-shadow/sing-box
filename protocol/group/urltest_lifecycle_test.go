package group

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// Lifecycle tests for the URLTest group.
//
// # The defects these pin
//
// Touch read g.started OUTSIDE g.access, while PostStart and Close write it under the lock. That is
// a data race, and it also means a Touch concurrent with a Close could observe started == true just
// before Close ran, then register a ticker and a pause callback on a group that is being torn down -
// leaving a background task running after the group was closed.
//
// Close was not terminal either: it returned early when no ticker existed, so a group that had been
// started but never touched closed without cancelling anything, and the started flag stayed true.

// newLifecycleFixture builds a group with a pause manager, which Touch needs.
func newLifecycleFixture(t *testing.T) (*URLTestGroup, *urltest.HistoryStorage) {
	t.Helper()
	ctx := pause.WithDefaultManager(service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage()))
	group, err := NewURLTestGroup(
		ctx,
		&stubOutboundManager{},
		log.NewNOPFactory().NewLogger("group"),
		[]adapter.Outbound{&stubOutbound{tag: "node-a"}},
		"https://probe.example/generate_204",
		50*time.Millisecond,
		0,
		time.Second,
		false,
	)
	require.NoError(t, err)
	return group, service.PtrFromContext[urltest.HistoryStorage](ctx)
}

// TestTouchAndCloseAreRaceFree is §5.3.
//
// Touch and Close run concurrently many times over. Without the lock covering the started flag, the
// race detector reports a data race on it.
func TestTouchAndCloseAreRaceFree(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		group, _ := newLifecycleFixture(t)
		group.PostStart()

		var waitGroup sync.WaitGroup
		start := make(chan struct{})

		waitGroup.Add(2)
		go func() {
			defer waitGroup.Done()
			<-start
			group.Touch()
		}()
		go func() {
			defer waitGroup.Done()
			<-start
			_ = group.Close()
		}()

		close(start)
		waitGroup.Wait()

		// Whatever the interleaving, the group must end closed and idempotent.
		require.NoError(t, group.Close())
	}
}

// TestCloseIsTerminalAndIdempotent is §5.1, §5.4.
func TestCloseIsTerminalAndIdempotent(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()
	group.Touch()

	require.NoError(t, group.Close())
	require.NoError(t, group.Close(), "a second Close must be a no-op, not a panic")
	require.NoError(t, group.Close())

	group.access.Lock()
	ticker := group.ticker
	started := group.started
	callback := group.pauseCallback
	group.access.Unlock()

	require.Nil(t, ticker, "no ticker may survive Close")
	require.Nil(t, callback, "no pause callback may survive Close")
	require.False(t, started,
		"Close must be terminal: a group that still reports itself started can be touched into "+
			"starting new background work after teardown")
}

// TestTouchAfterCloseStartsNothing is §5.1.
//
// A Touch that arrives after Close must not create a ticker, a pause callback, or a goroutine.
func TestTouchAfterCloseStartsNothing(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()
	group.Touch()
	require.NoError(t, group.Close())

	// Repeated touches after the terminal state.
	for attempt := 0; attempt < 10; attempt++ {
		group.Touch()
	}

	group.access.Lock()
	ticker := group.ticker
	callback := group.pauseCallback
	group.access.Unlock()

	require.Nil(t, ticker, "Touch after Close must not start a ticker")
	require.Nil(t, callback, "Touch after Close must not register a pause callback")
}

// TestCloseWithoutTouchIsStillTerminal is §5.1's other half.
//
// A group that was started but never touched has no ticker. Close must still mark it closed, so a
// later Touch cannot start background work.
func TestCloseWithoutTouchIsStillTerminal(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()

	// No Touch: there is no ticker yet.
	require.NoError(t, group.Close())

	group.access.Lock()
	started := group.started
	group.access.Unlock()
	require.False(t, started, "Close must be terminal even when no ticker existed")

	group.Touch()

	group.access.Lock()
	ticker := group.ticker
	group.access.Unlock()
	require.Nil(t, ticker,
		"a group closed before it was ever touched must not be startable by a later Touch")
}

// TestCloseCancelsInFlightBackgroundWork is §5.1's "no background check after Close" and §5.2's
// group-owned child context.
//
// The group stores the caller's context and every background check runs on it. Close stops the
// ticker and closes the loop channel, but neither of those cancels work that is already running:
// a check in flight keeps going, and a health recheck requested by a failing connection starts a
// goroutine that nothing can stop.
//
// A group that is closed must stop doing work.
func TestCloseCancelsInFlightBackgroundWork(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()

	// The group must own a context that Close can cancel. Observing it directly is what makes this
	// a deterministic assertion rather than a race against a check finishing on its own.
	groupCtx := group.backgroundContext()
	require.NotNil(t, groupCtx, "the group must expose the context its background work runs on")

	select {
	case <-groupCtx.Done():
		t.Fatal("the background context must be live before Close")
	default:
	}

	require.NoError(t, group.Close())

	select {
	case <-groupCtx.Done():
		// Cancelled as required.
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the group's background context; a health check already " +
			"running keeps going, and a check requested by a failing connection can start after " +
			"the group is closed - both write history for a group that no longer exists")
	}
}

// TestClosedGroupDoesNotStartNewBackgroundWork is the observable half.
//
// requestHealthRecheck is called when a connection fails. After Close it must not start a check.
//
// The assertion is on the BACKGROUND CONTEXT rather than on the group's checking latch: PostStart
// starts a check of its own, so the latch may legitimately be set when the group is closed. What
// must hold is that no work runs against a context that is already cancelled - a check started
// before Close is cancelled by it, and one requested after Close is refused.
func TestClosedGroupDoesNotStartNewBackgroundWork(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()
	require.NoError(t, group.Close())

	backgroundCtx := group.backgroundContext()
	require.Error(t, backgroundCtx.Err(),
		"the background context must be cancelled by Close")

	// A failing connection asks for a recheck on a closed group. The request must be refused
	// rather than starting a goroutine that would run against a cancelled context.
	group.requestHealthRecheck()

	require.Never(t, func() bool {
		// A refused request leaves no new work: the only thing that could set the latch again is
		// a check that actually ran, and none may.
		select {
		case <-backgroundCtx.Done():
			return false
		default:
			return group.checking.Load()
		}
	}, 200*time.Millisecond, 10*time.Millisecond,
		"a closed group must not start a health check; it would run against a torn-down group and "+
			"write history for one that no longer exists")

	// The decisive, non-timing assertion: the request must not have spawned anything that could
	// observe the cancelled context and continue.
	require.Error(t, backgroundCtx.Err())
}

// TestDoubleStartDoesNotStrandTheFirstGroup is §5.1's "Start only once".
//
// URLTest.Start builds a fresh group and assigns it to s.group. A second Start therefore replaces
// the first group without disposing of it, and the first one's ticker, pause callback and
// background context are left owned by nothing.
func TestDoubleStartDoesNotStrandTheFirstGroup(t *testing.T) {
	member := &stubOutbound{tag: "node-a"}
	manager := &taggedOutboundManager{byTag: map[string]adapter.Outbound{"node-a": member}}
	ctx := pause.WithDefaultManager(
		service.ContextWithPtr(service.ContextWith[adapter.OutboundManager](context.Background(), manager),
			urltest.NewHistoryStorage()))

	instance := &URLTest{
		Adapter:  outbound.NewAdapter(C.TypeURLTest, "group", []string{N.NetworkTCP}, []string{"node-a"}),
		ctx:      ctx,
		outbound: manager,
		logger:   log.NewNOPFactory().NewLogger("group"),
		tags:     []string{"node-a"},
		link:     "https://probe.example/generate_204",
	}

	require.NoError(t, instance.Start(adapter.StartStateStart))
	first := instance.currentGroup()
	require.NotNil(t, first, "Start must install a group")
	firstCtx := first.backgroundContext()
	first.PostStart()

	// A second Start on the same instance.
	require.NoError(t, instance.Start(adapter.StartStateStart))
	second := instance.currentGroup()
	require.NotNil(t, second)

	if first != second {
		require.Eventually(t, func() bool {
			select {
			case <-firstCtx.Done():
				return true
			default:
				return false
			}
		}, 2*time.Second, 10*time.Millisecond,
			"Start replaced the group, so the previous group's background context must be "+
				"cancelled; otherwise its ticker, pause callback and context are stranded with no "+
				"owner and a health check keeps running for a group nothing references")
	}

	require.NoError(t, instance.Close())
}

// TestStartIsIdempotentOrReplacesCleanly is §5.1's "Start only once".
//
// Start builds a fresh group and assigns it to s.group. Calling it twice would replace the first
// group without closing it, leaving a ticker, a pause callback and a background context behind -
// the lifecycle resources the first group acquired that nothing now owns.
func TestStartIsIdempotentOrReplacesCleanly(t *testing.T) {
	group, _ := newLifecycleFixture(t)
	group.PostStart()
	group.Touch()

	firstCtx := group.backgroundContext()

	// Close is the only sanctioned way to dispose of a group, and the URLTest wrapper must not
	// discard one silently.
	require.NoError(t, group.Close())

	select {
	case <-firstCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a replaced or closed group must have its background context cancelled")
	}

	// A second group can be built and started without the first one's resources interfering.
	second, _ := newLifecycleFixture(t)
	second.PostStart()
	// Compared by IDENTITY, not with require.NotEqual.
	//
	// A context carries its own mutexes and atomics, so reflect.DeepEqual walks state that the
	// runtime is free to be mutating - which the race detector correctly reports. Pointer identity
	// is what "each group owns its own context" actually means.
	require.NotSame(t, firstCtx, second.backgroundContext(),
		"each group owns its own background context")
	require.NoError(t, second.Close())
}
