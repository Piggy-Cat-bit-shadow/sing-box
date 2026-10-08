package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/common/urltest"

	"github.com/stretchr/testify/require"
)

// # The Android lifecycle must not be able to mark, or unmark, a measurement
//
// The Phase 1.5 invariant is that background work does not wake an idle resource, and the mechanism
// is the background-probe marker the entry point puts on the operation context. The Android work adds
// a new source of platform facts - memory trims, screen state, app foreground - and the risk it
// introduces is a new one: if those facts reached the measurement path, a screen-off could mark a
// manual test as background (the user's own test would be refused), or a foreground fact could mark a
// periodic round as demand (a timer would wake the tunnel engine).
//
// The tests below drive the real URLTestGroup with the real lifecycle policy in each state and assert
// the marker follows the ENTRY POINT and nothing else.

// TestScreenOffAutomaticRoundCannotWakeASuspendedEndpoint is the screen-off case.
func TestScreenOffAutomaticRoundCannotWakeASuspendedEndpoint(t *testing.T) {
	// The Android lifecycle reports the common idle combination.
	lifecycle := runtimecoord.NewPlatformEvents(nil)
	lifecycle.SetScreenOn(false)
	lifecycle.SetAppForeground(false)

	member := &probeMarkingOutbound{tag: "idle-wg", suspendedErr: adapter.ErrResourceSuspended}
	urlTestGroup, storage := newGroupFixture(t, "https://probe.example/generate_204", member)
	scope, err := urltest.NewMeasurementScope("https://probe.example/generate_204", nil)
	require.NoError(t, err)
	previous := &adapter.URLTestHistory{Time: time.Now(), Delay: 37}
	storage.StoreHealthHistory("idle-wg", scope, previous)

	// The automatic health round, on a context that declares nothing - which is the group's own
	// periodic path. The lifecycle state must not change that.
	urlTestGroup.CheckOutbounds(context.Background(), true)

	dials, background := member.counts()
	require.Greater(t, dials, 0)
	require.Equal(t, dials, background,
		"a screen-off automatic round must stay background work, or the timer that fires while the "+
			"phone is in a pocket wakes the tunnel engine it exists to leave asleep")
	after := storage.LoadURLTestHistoryFor("idle-wg", scope)
	require.NotNil(t, after)
	require.EqualValues(t, previous.Delay, after.Delay, "not measured is not unhealthy")
}

// TestForegroundRoundAfterScreenOnMayWakeASuspendedEndpoint is the other direction: coming back to
// the app must not leave a manual measurement classified as background.
func TestForegroundRoundAfterScreenOnMayWakeASuspendedEndpoint(t *testing.T) {
	lifecycle := runtimecoord.NewPlatformEvents(nil)
	lifecycle.SetScreenOn(false)
	lifecycle.SetAppForeground(false)

	// The user picks the phone up and opens the app: the two facts land, in the order a real device
	// delivers them.
	lifecycle.SetScreenOn(true)
	lifecycle.SetAppForeground(true)

	member := &probeMarkingOutbound{tag: "node", suspendedErr: adapter.ErrResourceSuspended}
	urlTestGroup, _ := newGroupFixture(t, "https://probe.example/generate_204", member)

	// "Test All" declares the origin at the API entry point - see daemon.StartedService.URLTest, which
	// builds exactly this context.
	foreground := runtimecoord.ContextWithProbeOrigin(context.Background(), runtimecoord.ProbeForeground)
	urlTestGroup.CheckOutbounds(foreground, true)

	dials, background := member.counts()
	require.Greater(t, dials, 0)
	require.Zero(t, background,
		"a measurement a person asked for is demand; the lifecycle state must not have re-marked it")
}

// TestRealTrafficIsNotBackgroundWork pins the third leg: a flow the device asked for is not marked,
// so a suspended endpoint serves it. The endpoint's own demand path is exercised by
// transport/wireguard's resumeForCaller tests; this is the marker half of the same contract.
func TestRealTrafficIsNotBackgroundWork(t *testing.T) {
	require.False(t, adapter.IsBackgroundProbe(context.Background()),
		"a context that declares nothing is demand for the traffic path; only the periodic health path "+
			"sets the marker")
	require.False(t, adapter.IsBackgroundProbe(
		runtimecoord.ContextWithProbeOrigin(context.Background(), runtimecoord.ProbeForeground)))
	require.True(t, adapter.IsBackgroundProbe(
		runtimecoord.MeasurementContext(context.Background(), runtimecoord.ProbeAutomatic)),
		"the automatic path is what the group's timer uses, and it must be marked")
}
