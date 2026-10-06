package route

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// trackingPauseManager is a pause manager that remembers, which noopPauseManager does not.
//
// The classification reads IsNetworkPaused(), so a double that always answers false cannot exercise
// it at all.
type trackingPauseManager struct {
	networkPaused atomic.Bool
	devicePaused  atomic.Bool
}

func (m *trackingPauseManager) DevicePause()          { m.devicePaused.Store(true) }
func (m *trackingPauseManager) DeviceWake()           { m.devicePaused.Store(false) }
func (m *trackingPauseManager) NetworkPause()         { m.networkPaused.Store(true) }
func (m *trackingPauseManager) NetworkWake()          { m.networkPaused.Store(false) }
func (m *trackingPauseManager) IsDevicePaused() bool  { return m.devicePaused.Load() }
func (m *trackingPauseManager) IsNetworkPaused() bool { return m.networkPaused.Load() }
func (m *trackingPauseManager) IsPaused() bool {
	return m.devicePaused.Load() || m.networkPaused.Load()
}
func (m *trackingPauseManager) WaitActive() {}
func (m *trackingPauseManager) RegisterCallback(pause.Callback) *list.Element[pause.Callback] {
	return nil
}
func (m *trackingPauseManager) UnregisterCallback(*list.Element[pause.Callback]) {}

var _ pause.Manager = (*trackingPauseManager)(nil)

// TestTransientGapIsNotConfirmedOffline is §15, driven through the REAL entrypoint.
//
// A Wi-Fi to Cellular handover passes through a moment with no default interface. Classifying on
// that instant would reclaim destructively on a device that is about to have a perfectly good
// network - the drain undone by its own special case. The state has to have held.
func TestTransientGapIsNotConfirmedOffline(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	harness.manager.pauseManager = paused
	monitor, isStatic := harness.manager.interfaceMonitor.(*staticInterfaceMonitor)
	require.True(t, isStatic)

	require.False(t, harness.manager.networkIsConfirmedOffline(), "online to start with")

	// The platform reports no default interface. This is the callback the network monitor invokes.
	monitor.current = nil
	harness.manager.notifyInterfaceUpdate(nil, 0)
	require.True(t, paused.IsNetworkPaused(), "the gap must pause the network")

	require.False(t, harness.manager.networkIsConfirmedOffline(),
		"a just-started gap was confirmed offline, so a handover would close every connection of a "+
			"device that is about to have a network")

	// Cellular arrives.
	monitor.current = &control.Interface{Index: 2, Name: "pdp_ip0"}
	harness.manager.notifyInterfaceUpdate(nil, 0)
	require.False(t, paused.IsNetworkPaused(), "the handover must wake the network")
	require.False(t, harness.manager.networkIsConfirmedOffline())
}

// TestSustainedPauseIsConfirmedOffline is the other direction: a device that really is offline must
// still be reclaimable aggressively, or the special case would disable the hard path entirely.
func TestSustainedPauseIsConfirmedOffline(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	paused.NetworkPause()
	harness.manager.pauseManager = paused
	harness.manager.networkPausedSince.Store(time.Now().Add(-HardTransitionConfirm - time.Second).UnixNano())

	require.True(t, harness.manager.networkIsConfirmedOffline(),
		"a device that has been offline past the confirmation window must still be confirmed")

	// Recovery clears it.
	paused.NetworkWake()
	require.False(t, harness.manager.networkIsConfirmedOffline(), "recovery must forget the outage")
}

// TestGapOnsetSurvivesABurstOfNotifications matters because the confirmation window is a deadline:
// if each notification restarted the clock, a flapping interface would never reach it and the hard
// path would never run, however long the device was actually offline.
func TestGapOnsetSurvivesABurstOfNotifications(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	harness.manager.pauseManager = paused
	monitor := harness.manager.interfaceMonitor.(*staticInterfaceMonitor)
	monitor.current = nil

	harness.manager.notifyInterfaceUpdate(nil, 0)
	first := harness.manager.networkPausedSince.Load()
	require.NotZero(t, first)

	time.Sleep(5 * time.Millisecond)
	for range 5 {
		harness.manager.notifyInterfaceUpdate(nil, 0)
	}
	require.Equal(t, first, harness.manager.networkPausedSince.Load(),
		"a burst of notifications pushed the deadline out, so a flapping interface would never be "+
			"confirmed offline")
}

// TestTransitionDuringAGapDrains is the end-to-end property, and the one the brief actually asks
// for: a transition that lands while the handover gap is in effect must DRAIN, not destroy.
//
// The gap is reachable by a reset even though the nil branch returns early, because the environment
// fingerprint goes to zero during it and an environment transition then runs the reset body.
func TestTransitionDuringAGapDrains(t *testing.T) {
	harness := newInterfaceTransitionHarness(t)
	paused := &trackingPauseManager{}
	harness.manager.pauseManager = paused

	connections := newDrainHarness(t)
	active, peer := connections.dial(t)
	go func() { _, _ = peer.Write([]byte("payload")) }()
	buffer := make([]byte, 16)
	if _, err := active.Read(buffer); err != nil {
		t.Fatal("the fixture could not move a byte: ", err)
	}
	connections.idleFor(active, time.Second)
	harness.manager.connectionManager = connections.manager

	// The handover gap.
	harness.manager.interfaceMonitor.(*staticInterfaceMonitor).current = nil
	harness.manager.notifyInterfaceUpdate(nil, 0)

	// A reset lands while the gap is in effect.
	harness.manager.ResetNetwork(context.Background())

	require.Equal(t, 1, connections.manager.Count(),
		"a transition during a transient gap reclaimed an active connection; the handover would "+
			"close every stream the device was running")
}
