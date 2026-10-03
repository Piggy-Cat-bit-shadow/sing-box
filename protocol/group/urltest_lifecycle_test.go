package group

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
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
