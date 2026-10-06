package route

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// countingInterfaceUpdateListener records how many times it was told the interface changed.
type countingInterfaceUpdateListener struct {
	adapter.Outbound
	calls atomic.Int32
}

func (l *countingInterfaceUpdateListener) InterfaceUpdated(context.Context) {
	l.calls.Add(1)
}

// listenerOutboundManager hands the manager one listener to notify.
type listenerOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *listenerOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }

// TestListenersAreNotNotifiedWhilePaused is the §5 redesign.
//
// Almost every outbound reads InterfaceUpdated as "tear the session down" - the inventory is in
// docs/fork/interface-update-lifecycle.md - and while the device is paused there is no new network to
// hand them. The teardown cannot lead to a working connection; it can only produce a dial certain to
// fail, and it discards a session that may still have been carrying traffic over a path the
// notification did not necessarily break.
//
// It is DEFERRED, not dropped: the wake notification runs the same body with the pause lifted, which
// is the third assertion here.
func TestListenersAreNotNotifiedWhilePaused(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	harness.manager.pauseManager = paused

	listener := &countingInterfaceUpdateListener{}
	harness.manager.outbound = &listenerOutboundManager{outbounds: []adapter.Outbound{listener}}

	// Online: the notification lands.
	harness.manager.ResetNetwork(context.Background())
	require.EqualValues(t, 1, listener.calls.Load(), "an online transition must reach the outbounds")

	// Paused, which is also the Wi-Fi to Cellular gap: the sessions are left alone.
	paused.NetworkPause()
	harness.manager.ResetNetwork(context.Background())
	require.EqualValues(t, 1, listener.calls.Load(),
		"an outbound was told to tear its session down while the device was offline, so the teardown "+
			"could only produce a dial certain to fail")

	// Wake: the deferred work happens, once.
	paused.NetworkWake()
	harness.manager.ResetNetwork(context.Background())
	require.EqualValues(t, 2, listener.calls.Load(),
		"the deferred notification did not happen when the network came back")
}

// TestRouterResetIsUnconditional pins the deliberate exception.
//
// router.ResetNetwork is where the DNS transports and their environment pins move TOGETHER. Gating
// it on the pause would let the pin and the socket disagree, which is the inconsistency the pin
// exists to prevent - so it must run whether or not the listeners were skipped.
func TestRouterResetIsUnconditional(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	harness.manager.pauseManager = paused

	harness.manager.ResetNetwork(context.Background())
	before := harness.router.entered

	paused.NetworkPause()
	harness.manager.ResetNetwork(context.Background())

	require.Equal(t, before+1, harness.router.entered,
		"the router's own reset was skipped while paused; the DNS pin and its socket would have "+
			"been left disagreeing")
}
