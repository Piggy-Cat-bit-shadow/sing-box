package wireguard

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/runtimecoord"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/device"

	"github.com/stretchr/testify/require"
)

// WireGuard recovery (LX 041) against the failure matrix of
// docs/fork/runtime-lifecycle-phase1.5.md.
//
// The tests drive the session-state callback and the rebind seam directly, so they need no peer, no
// socket and no network, and they are deterministic rather than timing-dependent.

var testPeer = device.NoisePublicKey{1, 2, 3}

// newRecoveryEndpoint builds an endpoint whose recovery state is ready to drive. The device is not
// started: every path under test decides before touching it, and the rebind itself is stubbed.
func newRecoveryEndpoint(t *testing.T, withCoordinator bool) (*Endpoint, *runtimecoord.Coordinator, *atomic.Int64) {
	t.Helper()
	ctx := context.Background()
	coordinator := runtimecoord.New()
	if withCoordinator {
		ctx = service.ContextWith[*runtimecoord.Coordinator](ctx, coordinator)
	}
	endpoint, err := NewEndpoint(EndpointOptions{
		Context:    ctx,
		Logger:     log.NewNOPFactory().Logger(),
		Tag:        "wg-test",
		PrivateKey: testPrivateKey,
	})
	require.NoError(t, err)
	require.NoError(t, endpoint.Initialize(nil))

	// The real device exists but is never started; a rebind is observed through the seam.
	var rebinds atomic.Int64
	endpoint.recovery.settle = 20 * time.Millisecond
	endpoint.recovery.poll = 5 * time.Millisecond
	endpoint.recovery.rebindHook = func(ctx context.Context) error {
		rebinds.Add(1)
		return nil
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint, coordinator, &rebinds
}

const testPrivateKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// Invariant 7: a burst of give-ups is one rebind, and the rebind happens off the callback.
func TestGiveUpBurstProducesOneRebind(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	// Four give-ups, as four peers failing at the same moment would produce.
	for index := 0; index < 4; index++ {
		peer := testPeer
		peer[2] = byte(index)
		endpoint.sessionStateChanged(peer, device.PeerSessionHandshake)
		endpoint.sessionStateChanged(peer, device.PeerSessionExpired)
	}

	require.Eventually(t, func() bool { return rebinds.Load() >= 1 }, 2*time.Second, 5*time.Millisecond,
		"a give-up must eventually produce a rebind")
	// Give the window a chance to be violated if it is not honoured: the endpoint's window is the
	// production 90 seconds, so a second rebind here would be a real defect.
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(),
		"four give-ups in one window must be one logical rebind")
}

// A healthy session is not stale: the early trigger must not fire, and no worker should act.
func TestEstablishedSessionIsNotStale(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionEstablished)

	time.Sleep(120 * time.Millisecond)
	require.Zero(t, rebinds.Load(),
		"a session that completed its handshake must never be treated as stale")
	require.False(t, endpoint.hasStaleSession())
}

// Invariant 4: a suspended endpoint is not woken by recovery, and does not rebind its socket while
// the device is deliberately down.
func TestSuspendedEndpointIsNotReboundByRecovery(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)
	endpoint.suspended.Store(true)

	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)

	time.Sleep(120 * time.Millisecond)
	require.Zero(t, rebinds.Load(),
		"a suspended endpoint must not be rebound: the device is deliberately down")

	// A wake nudge skips it too.
	endpoint.rebindOnWake()
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, rebinds.Load(), "a wake nudge must not wake a suspended endpoint")

	// The direct API reports a refusal rather than acting, so a caller cannot force it either.
	err := endpoint.RebindStale(context.Background(), adapter.RebindHandshakeGiveUp)
	require.ErrorIs(t, err, errRebindNotPossible)
	require.Zero(t, rebinds.Load())
}

// Invariant 1: Close wins. A rebind scheduled before Close must not run after it.
func TestCloseCancelsAScheduledRebind(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	require.NoError(t, endpoint.Close())

	time.Sleep(150 * time.Millisecond)
	require.Zero(t, rebinds.Load(),
		"a rebind scheduled before Close must not run after it")
	require.True(t, endpoint.recovery.closed)
}

// The wake nudge applies the stale predicate: healthy costs nothing, provably dead acts.
func TestWakeNudgeOnlyRebindsAStaleSession(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	endpoint.sessionStateChanged(testPeer, device.PeerSessionEstablished)
	endpoint.rebindOnWake()
	time.Sleep(80 * time.Millisecond)
	require.Zero(t, rebinds.Load(), "a wake with a healthy session must cost nothing")

	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	endpoint.rebindOnWake()
	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 2*time.Second, 5*time.Millisecond,
		"a wake with a provably dead session must rebind")
}

// A network generation change re-arms the window, so a real failure after a handover is not
// swallowed by a window that described the previous network.
func TestNetworkChangeReArmsTheRecoveryWindow(t *testing.T) {
	endpoint, coordinator, rebinds := newRecoveryEndpoint(t, true)

	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 2*time.Second, 5*time.Millisecond)

	// Same generation, second failure: inside the 90-second window, so it coalesces.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	time.Sleep(80 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load())

	// A new generation makes the previous window irrelevant.
	coordinator.Advance(1)
	require.Eventually(t, func() bool { return endpoint.registration.Stale() }, time.Second, 5*time.Millisecond,
		"a published generation must make the resource stale until it acts")

	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	require.Eventually(t, func() bool { return rebinds.Load() == 2 }, 2*time.Second, 5*time.Millisecond,
		"a failure on a new generation must be able to recover")
}

// An idle endpoint refuses a background probe, and an active one serves it. Nothing about the probe
// may wake a suspended device.
func TestBackgroundProbeDoesNotWakeASuspendedEndpoint(t *testing.T) {
	endpoint, _, _ := newRecoveryEndpoint(t, false)

	// Not suspended: the probe proceeds to the device, which is not started, so it fails - but not
	// with the suspended sentinel, which is the distinction under test.
	_, err := endpoint.DialContext(context.Background(), "tcp", M.SocksaddrFromNetIP(netip.MustParseAddrPort("10.0.0.1:80")))
	require.NotErrorIs(t, err, adapter.ErrResourceSuspended)

	endpoint.suspended.Store(true)
	_, err = endpoint.DialContext(adapter.ContextWithBackgroundProbe(context.Background()), "tcp", M.SocksaddrFromNetIP(netip.MustParseAddrPort("10.0.0.1:80")))
	require.ErrorIs(t, err, adapter.ErrResourceSuspended,
		"a background probe must be refused rather than wake a suspended endpoint")
	require.True(t, endpoint.suspended.Load(), "the probe must not have resumed the endpoint")

	// A demand dial is not marked, so it passes the probe gate: it is not refused with the sentinel,
	// which is what makes the refusal a probe-specific decision rather than a blanket one. (The
	// device is not started in this test, so the dial itself cannot succeed; what is under test is
	// the gate, and the sentinel is its observable outcome.)
	_, err = endpoint.DialContext(context.Background(), "tcp", M.SocksaddrFromNetIP(netip.MustParseAddrPort("10.0.0.1:80")))
	require.NotErrorIs(t, err, adapter.ErrResourceSuspended,
		"a demand dial must not be refused by the background-probe gate")
}

// The gate itself: a background probe is refused before anything else happens, and a demand caller
// is let through to the resume path.
//
// The gate is tested directly rather than through DialContext because a resume needs a published
// device, which needs a started endpoint; the gate is where the policy lives and it is the whole
// difference between the two callers.
func TestResumeGateRefusesOnlyBackgroundWork(t *testing.T) {
	endpoint, _, _ := newRecoveryEndpoint(t, false)

	endpoint.suspended.Store(true)
	require.ErrorIs(t,
		endpoint.resumeForCaller(adapter.ContextWithBackgroundProbe(context.Background())),
		adapter.ErrResourceSuspended)
	require.True(t, endpoint.suspended.Load(), "the refused probe must not have resumed anything")

	// A demand caller passes the gate. The device is not published in this test, so the resume
	// itself cannot complete, but the gate is what is under test and it did not refuse.
	require.NoError(t, endpoint.resumeForCaller(context.Background()))

	// And an endpoint that is not suspended serves both callers.
	endpoint.suspended.Store(false)
	require.NoError(t, endpoint.resumeForCaller(adapter.ContextWithBackgroundProbe(context.Background())))
}

func TestBackgroundProbeMarker(t *testing.T) {
	require.False(t, adapter.IsBackgroundProbe(context.Background()))
	require.True(t, adapter.IsBackgroundProbe(adapter.ContextWithBackgroundProbe(context.Background())))

	// The runtime helper marks an undeclared measurement as background, and leaves a declared
	// foreground measurement alone.
	require.True(t, adapter.IsBackgroundProbe(runtimecoord.MeasurementContext(context.Background(), runtimecoord.ProbeAutomatic)))
	require.False(t, adapter.IsBackgroundProbe(runtimecoord.MeasurementContext(context.Background(), runtimecoord.ProbeForeground)))
}

// Restart stress: repeated Start/Stop must not accumulate recovery workers, and the endpoint must
// remain usable afterwards. Counted goroutines make an accumulation a failure rather than a
// suspicion.
func TestRecoveryDoesNotAccumulateWorkers(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for cycle := 0; cycle < 25; cycle++ {
		func() {
			endpoint, _, _ := newRecoveryEndpoint(t, true)
			endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
			endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
			require.NoError(t, endpoint.Close())
		}()
	}
	// A worker per cycle would be 25 goroutines. Allow the runtime's own noise a generous margin.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+8 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), baseline+8,
		"repeated endpoint cycles leaked recovery workers")
}

// A peer's session-state transitions are deduplicated by the device, and the callback itself must
// be safe under the race detector with concurrent readers of the stale predicate.
func TestSessionStateCallbackIsRaceFree(t *testing.T) {
	endpoint, _, _ := newRecoveryEndpoint(t, true)

	var waitGroup sync.WaitGroup
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
			endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			_ = endpoint.hasStaleSession()
			_ = endpoint.anyHandshaking()
			_ = endpoint.staleFromGiveUp()
		}
	}()
	go func() {
		defer waitGroup.Done()
		for index := 0; index < 100; index++ {
			endpoint.rebindOnWake()
		}
	}()
	waitGroup.Wait()
}

// The device-wake nudge is a different event from the network-wake callback, and it must be wired:
// a tunnel that slept through a device wake is the field case this recovery exists for.
func TestDeviceWakeNudgeIsWiredAndSkipsIdleEndpoints(t *testing.T) {
	endpoint, _, rebinds := newRecoveryEndpoint(t, true)

	// A dead session plus a device wake: one rebind.
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	endpoint.onDeviceWake(pause.EventDeviceWake)
	require.Eventually(t, func() bool { return rebinds.Load() == 1 }, 2*time.Second, 5*time.Millisecond,
		"a device wake with a provably dead session must rebind")

	// Other events are not the nudge.
	endpoint.onDeviceWake(pause.EventDevicePaused)
	endpoint.onDeviceWake(pause.EventNetworkPause)
	endpoint.onDeviceWake(pause.EventNetworkWake)
	time.Sleep(60 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(),
		"only a device wake is the nudge; the other pause events are not")

	// A suspended endpoint is skipped, so a device wake cannot spin up a tunnel the idle policy
	// released.
	endpoint.suspended.Store(true)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionHandshake)
	endpoint.sessionStateChanged(testPeer, device.PeerSessionExpired)
	endpoint.onDeviceWake(pause.EventDeviceWake)
	time.Sleep(80 * time.Millisecond)
	require.EqualValues(t, 1, rebinds.Load(),
		"a suspended endpoint must not be woken by the nudge")
	endpoint.suspended.Store(false)
}
