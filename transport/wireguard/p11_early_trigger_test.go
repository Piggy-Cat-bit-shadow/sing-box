package wireguard

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/wireguard-go/device"

	"github.com/stretchr/testify/require"
)

// P1-1: the early stale-handshake trigger must actually fire.
//
// # The defect
//
// The callback that observes session transitions started the recovery worker only when a session
// was already STALE. A handshake entering its series is not stale - it becomes stale only when the
// settle window expires, and the code that makes that decision lives INSIDE the worker. So with no
// worker nobody ever made the decision, and the early trigger could only fire if some OTHER peer
// happened to have given up first and started the worker as a side effect.
//
// The visible consequence is the one the trigger exists to prevent: a node wakes, its handshake
// retries into the dead 5-tuple, and the user waits for the full give-up cycle (~90s) instead of
// the early window.

// A handshake that never establishes and never gives up must still produce exactly one rebind once
// the settle window expires.
func TestP11EarlyTriggerFiresWithoutAGiveUpEvent(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	// Only ever a Handshake. No Established, no Expired, no None - the whole point is that the
	// early trigger must not depend on the device ever telling us the series failed.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)

	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 3*time.Second, 5*time.Millisecond,
		"a handshake still running at the settle window must produce a rebind without any give-up event")
	time.Sleep(120 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(), "and exactly one, not one per poll")
}

// A handshake that completes before the settle window must cost nothing.
func TestP11HandshakeEstablishedBeforeSettleDoesNotRebind(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionEstablished)
	time.Sleep(200 * time.Millisecond)
	require.Zero(t, rebinds.Load())
}

// Repeated Handshake events are one series: one worker, one rebind, and the settle window is not
// re-armed by a retry (otherwise a node that retries forever would never reach the window).
func TestP11RepeatedHandshakeEventsAreOneSeries(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)
	for index := 0; index < 5; index++ {
		endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
		time.Sleep(4 * time.Millisecond)
	}
	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 3*time.Second, 5*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(), "five retries of one series are still one logical recovery")
	endpoint.recovery.access.Lock()
	workers := endpoint.recovery.worker
	endpoint.recovery.access.Unlock()
	require.False(t, workers, "the worker must have exited once it acted")
}

// Close during the settle window cancels the pending early trigger.
func TestP11CloseDuringSettleCancelsTheEarlyTrigger(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	require.NoError(t, endpoint.Close())
	time.Sleep(200 * time.Millisecond)
	require.Zero(t, rebinds.Load(), "a rebind scheduled before Close must not run after it")
}

// Suspend during the settle window must not wake the endpoint or rebind its socket.
func TestP11SuspendDuringSettleDoesNotRebind(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.suspended.Store(true)
	time.Sleep(250 * time.Millisecond)
	require.Zero(t, rebinds.Load(), "a suspended endpoint must be marked stale, not woken")
	require.True(t, endpoint.suspended.Load())
}

// A generation advance while the early window is open must not let the old generation's trigger
// spend the new generation's recovery.
func TestP11GenerationChangeDuringSettleDoesNotPolluteTheNewGeneration(t *testing.T) {
	endpoint, coordinator, rebinds := newRecoveryEndpoint(t, true)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)

	coro := coordinator
	coro.Advance(1)

	// The new generation must be able to recover immediately: the window described the OLD network,
	// so a failure on the new one is a new fact and must not wait out the old window.
	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 3*time.Second, 5*time.Millisecond,
		"the generation published while the early window was open must be able to recover")
	time.Sleep(150 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load())

	// And that new window is consumed exactly once: a second failure in the SAME generation
	// coalesces rather than producing a second rebind. This is the property that keeps a burst from
	// becoming a burst of socket rebuilds.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	time.Sleep(150 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(),
		"a second failure in the same generation and window must coalesce")

	// A further generation is a further recovery.
	coro.Advance(2)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	require.Eventually(t, func() bool { return rebinds.Load() == 2 }, 3*time.Second, 5*time.Millisecond,
		"each new generation earns its own recovery")
}

var _ = adapter.RebindHandshakeGiveUp
