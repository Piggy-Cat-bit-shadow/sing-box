package masque

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// MASQUE runtime lifecycle.
//
// The MASQUE client in this fork already owns its own state (one loop, exponential backoff, a
// suspend gate), and Phase 1.5 deliberately does not replace it. What these tests pin is the part
// that interacts with the network-generation model:
//
//   - exactly one event loop exists, whatever combination of Suspend/Resume/RestartSession arrives
//     (a duplicate loop would be a duplicate reconnect engine, i.e. a reconnect storm);
//   - Close stops it, and nothing restarts it afterwards (invariant 1);
//   - the transport epoch, which is what carries the H3/H2 verdict, is replaced after a network
//     change rather than carried over (invariant 2; the mechanism is pinned in
//     common/httpclient/managed_transport_reset_test.go).
//
// The endpoint dials 127.0.0.1 with TLS, so every attempt fails immediately and locally: the loop
// runs its real failure path with no network and no timeout.

func newLifecycleEndpoint(t *testing.T) *ClientEndpoint {
	t.Helper()
	router := &fakeBootstrapRouter{answer: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	built, err := buildTestEndpoint(t, router, "127.0.0.1", newBootstrapTLSOptions())
	require.NoError(t, err)
	endpoint, isEndpoint := built.(*ClientEndpoint)
	require.True(t, isEndpoint)
	require.NotNil(t, endpoint.client)
	return endpoint
}

// Invariant 7: there is exactly one recovery engine, however the caller drives the lifecycle.
func TestMasqueLifecycleKeepsOneLoop(t *testing.T) {
	endpoint := newLifecycleEndpoint(t)
	client := endpoint.client

	client.Start()
	require.Eventually(t, func() bool { return client.ActiveLoops() == 1 },
		2*time.Second, 5*time.Millisecond, "Start must run exactly one loop")

	// A network change is a session restart, not a new engine. Suspend/Resume is the idle policy.
	for index := 0; index < 20; index++ {
		client.RestartSession()
		client.Suspend()
		client.Resume()
		require.LessOrEqual(t, client.ActiveLoops(), int64(1),
			"Suspend/Resume/RestartSession must never spawn a second reconnect engine")
	}

	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { return client.ActiveLoops() == 0 },
		2*time.Second, 5*time.Millisecond, "Close must stop the loop")
}

// Invariant 1: after Close, nothing may restart the session, however the caller asks.
func TestMasqueCloseRefusesLaterRecovery(t *testing.T) {
	endpoint := newLifecycleEndpoint(t)
	client := endpoint.client
	client.Start()
	require.Eventually(t, func() bool { return client.ActiveLoops() == 1 }, 2*time.Second, 5*time.Millisecond)

	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { return client.ActiveLoops() == 0 }, 2*time.Second, 5*time.Millisecond)

	// These are the post-Close calls a racing interface update or pause callback would make.
	client.RestartSession()
	client.Resume()
	time.Sleep(100 * time.Millisecond)
	require.Zero(t, client.ActiveLoops(),
		"a restarted session after Close would be a resurrected resource")
	require.False(t, client.Ready())
}

// A suspended client is not dialling, which is what keeps a paused device from reconnecting in the
// background.
func TestMasqueSuspendStopsReconnectAttempts(t *testing.T) {
	endpoint := newLifecycleEndpoint(t)
	client := endpoint.client
	client.Start()
	require.Eventually(t, func() bool { return client.ActiveLoops() == 1 }, 2*time.Second, 5*time.Millisecond)

	client.Suspend()
	time.Sleep(150 * time.Millisecond)
	require.False(t, client.Ready(), "a suspended client must not report ready")
	require.EqualValues(t, 1, client.ActiveLoops(),
		"suspending parks the loop rather than replacing it")

	client.Resume()
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool { return client.ActiveLoops() == 0 }, 2*time.Second, 5*time.Millisecond)
}

// Start/Close cycles must not accumulate loops or goroutines: the loop is the only worker here, so a
// leak in it would be a leak per pause/wake cycle on a device.
func TestMasqueRestartCyclesDoNotLeakLoops(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for cycle := 0; cycle < 15; cycle++ {
		endpoint := newLifecycleEndpoint(t)
		client := endpoint.client
		client.Start()
		require.Eventually(t, func() bool { return client.ActiveLoops() == 1 }, 2*time.Second, 5*time.Millisecond)
		client.RestartSession()
		require.NoError(t, client.Close())
		require.Eventually(t, func() bool { return client.ActiveLoops() == 0 }, 2*time.Second, 5*time.Millisecond)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+6 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), baseline+6,
		"repeated MASQUE lifecycles leaked goroutines")
}
