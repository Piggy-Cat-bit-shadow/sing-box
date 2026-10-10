package wireguard

// Adversary G: item 7 (the socket-release witness) and the wireguard half of the reverse questions.
//
// # Item 7, stated as the claim being attacked
//
// `rebind_lease_test.go` asserts, immediately after a network pause, that
// `socketCensus(t, endpoint) == 0`, and its own comment states the inference that licenses it:
//
//	`closeBindLocked` closes the bind and then waits `netc.stopping.Wait()` for the receive
//	goroutines before `Down()` returns, so an endpoint that released its socket has no receiver of
//	that socket left.
//
// The claim is therefore "census 0 => no socket". In the pinned dependency that inference has a hole,
// and the hole is in `BindUpdate`'s own order (`device/device.go`):
//
//	closeBindLocked(device)        <- Close + stopping.Wait: the previous generation's receivers exit
//	bind.Open(netc.port)           <- both sockets are created AND bound inside this call. `Open` binds
//	                                  udp4 with `syscall.Bind` (net/sock_posix.go:217) and then binds
//	                                  udp6, and it assigns StdNetBind's `ipv4`/`ipv6` fields only
//	                                  AFTER both listens have returned (conn/bind_std.go:239,262)
//	startRouteListener(bind)
//	bind.SetMark(fwmark)           <- only when fwmark != 0, which this endpoint never sets
//	peers loop: markEndpointSrcForClearing()
//	stopping.Add(len(recvFns))
//	go RoutineReceiveIncoming(..)  <- the census only starts counting HERE
//
// So between the udp4 bind and the receive-goroutine spawn the endpoint holds a BOUND socket, while
// BOTH device-owned witnesses read zero: the census counts goroutines and none has been started, and
// the bind's own socket fields are still nil because `Open` has not returned. The only witness that can
// see the socket is the OS port table - which `requirePortReleasedByTheEndpoint` excuses for exactly
// that reading (`socketCensus <= socketsPerStandardBind`, and 0 satisfies it).
//
// # How the window is pinned rather than sampled
//
// A full goroutine dump (what the census costs) takes about a millisecond, and the window is a few
// microseconds, so sampling cannot resolve it. The fixture's own socket gate can pin it instead. The
// gate's control hook runs BEFORE `syscall.Bind`, so blocking at it is pre-bind; but `enter()` reads
// `armed` before it runs the registered probe, so a probe that ARMS the gate from inside the udp4 entry
// lets that entry proceed and blocks the NEXT one - the udp6 entry - which is strictly after the udp4
// socket has been bound and strictly before `Open` has returned.
//
// What that state means for the two assertions under attack is measured directly below: the port the
// endpoint is reopening on is occupied, the census reads 0, and the helper's own arithmetic
// (`held <= socketsPerStandardBind`) therefore passes.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// TestAdvGItem7OccupiedPortIsInvisibleWhileTheReopenIsInFlight pins the window described above and
// measures both halves of the release witness in it. No reflection and no -race hazard: the witnesses
// are the goroutine census and the OS port table, which is what the assertions under attack use.
func TestAdvGItem7OccupiedPortIsInvisibleWhileTheReopenIsInFlight(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)
	endpoint := fixture.endpoint

	held := fixture.livePort(t)
	require.False(t, udpPortIsFree(t, held), "precondition: the endpoint holds its port before the pause")

	endpoint.onPauseUpdated(pause.EventNetworkPause)
	require.Zero(t, socketCensus(t, endpoint),
		"precondition: a settled pause really does release the socket, which is why the assertion "+
			"under attack is sound at that point")
	require.True(t, udpPortIsFree(t, held), "precondition: and the port really is free then")

	// Arm the gate from INSIDE the reopen's first control hook (the udp4 listen), so the udp4 socket is
	// bound by the time the udp6 listen blocks: see the file header for why that is the post-bind state.
	fixture.gate.probeAtSocketOpen(func() { fixture.gate.arm() })

	wakeDone := make(chan struct{})
	go func() {
		defer close(wakeDone)
		endpoint.onPauseUpdated(pause.EventNetworkWake)
	}()
	fixture.gate.awaitEntry(t, 15*time.Second)

	// The pinned state. `t.Logf` first, so the numbers are in the record even when an assertion fires.
	census := socketCensus(t, endpoint)
	portOccupied := !udpPortIsFree(t, held)
	t.Logf("ADVG_ITEM7_PINNED port=%d census=%d port_occupied=%v", held, census, portOccupied)

	// Release before asserting, so a failure cannot leave the fixture blocked.
	fixture.gate.release()
	select {
	case <-wakeDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the wake never finished after the gate was released")
	}
	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 15*time.Second, time.Millisecond, "the released wake must settle on one bind's worth of receivers")
	require.Equal(t, held, fixture.livePort(t),
		"the endpoint must end up holding the same port, which is what makes the holder observed in "+
			"the pinned state the endpoint's OWN socket rather than another process's")

	require.True(t, portOccupied,
		"the gate did not land between the two family listens, so this probe did not reach the state "+
			"it describes and its other assertion proves nothing (census=%d)", census)

	// THE FINDING, pinned as the property it turned out to be rather than as a failure.
	//
	// This assertion used to be `require.NotZero(t, census)` and was RED BY DESIGN: the counterexample
	// is that the census reads 0 while the endpoint holds a bound socket, and a test cannot prove a
	// limit by asserting the limit away. The limit is real - a socket `bind.Open` has bound but whose
	// receive goroutines have not started is invisible to a census of receivers - and no assertion in
	// this file can remove it. What the round DID do is stop the release helper from reading that
	// state as a release, so the finding is now pinned on both sides:
	//
	//   1. the witness really cannot see it (here), and
	//   2. the helper refuses to answer in it (the second subtest below).
	require.Zero(t, census,
		"the census reads %d in a state where the endpoint demonstrably holds a bound socket on port "+
			"%d, so `socketCensus == 0` does NOT imply `no socket`. This is the measured limit of the "+
			"receive-goroutine census; if it ever reads non-zero here the limit has been closed and "+
			"this pin - not the product - should be revisited", census, held)

	t.Run("the release helper now checks this precondition", func(t *testing.T) {
		// Re-enter the same state and check the PRECONDITION the helper now asserts first.
		//
		// The helper itself is not called here: it ends in `require`, which calls `FailNow`, which is
		// only valid from a real test's own goroutine - so "call it and expect a failure" cannot be
		// written this way, and a probe that pretended otherwise would be measuring testify rather
		// than the product. The property is asserted directly instead, and the helper's dependence on
		// it was established by a reverse-break run against the helper's own first statement.
		fixture.gate.probeAtSocketOpen(func() { fixture.gate.arm() })
		wakeAgain := make(chan struct{})
		go func() {
			defer close(wakeAgain)
			endpoint.onPauseUpdated(pause.EventNetworkPause)
			endpoint.onPauseUpdated(pause.EventNetworkWake)
		}()
		fixture.gate.awaitEntry(t, 15*time.Second)

		censusAgain := socketCensus(t, endpoint)
		require.NotZero(t, fixture.gate.socketOperationsInFlight(),
			"`socketOperationsInFlight` must be non-zero in this state, which is the whole point: it "+
				"is the only reading here that distinguishes a released socket from one being reopened, "+
				"and `requirePortReleasedByTheEndpoint` now fails on it before it looks at either witness")
		require.Zero(t, censusAgain,
			"and the census still reads %d while the endpoint holds a bound socket", censusAgain)

		fixture.gate.release()
		select {
		case <-wakeAgain:
		case <-time.After(30 * time.Second):
			t.Fatal("the second wake never finished after the gate was released")
		}
	})
}

// TestAdvGItem7TheTwoWitnessesAgreeWheneverNothingIsReopening is the discriminating control: the census
// and the port table agree in every settled state, so a disagreement in the test above is about the
// reopen window and not about the census being broken.
func TestAdvGItem7TheTwoWitnessesAgreeWheneverNothingIsReopening(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)
	endpoint := fixture.endpoint

	for cycle := 0; cycle < 3; cycle++ {
		held := fixture.livePort(t)
		require.Equal(t, socketsPerStandardBind, socketCensus(t, endpoint),
			"cycle %d: settled, one bind's worth of receivers", cycle)
		require.False(t, udpPortIsFree(t, held), "cycle %d: settled, the port is held", cycle)

		endpoint.onPauseUpdated(pause.EventNetworkPause)
		require.Zero(t, socketCensus(t, endpoint), "cycle %d: settled pause", cycle)
		require.True(t, udpPortIsFree(t, held), "cycle %d: settled pause releases the port", cycle)

		endpoint.onPauseUpdated(pause.EventNetworkWake)
		require.Eventually(t, func() bool {
			return socketCensus(t, endpoint) == socketsPerStandardBind
		}, 15*time.Second, time.Millisecond, "cycle %d: settled wake", cycle)
		require.Eventually(t, func() bool {
			return !udpPortIsFree(t, held)
		}, 15*time.Second, time.Millisecond, "cycle %d: the wake reopens on the same port", cycle)
	}
}

// The reverse question, wireguard half: several pause/wake cycles inside one second must leave one
// bind's worth of sockets and no resident recovery worker.
func TestAdvGReverseWGManyFastPauseWakeCyclesLeaveOneSocket(t *testing.T) {
	fixture := newRebindFixture(t, 0)
	fixture.proveStandardBindBranch(t)
	endpoint := fixture.endpoint

	require.Equal(t, socketsPerStandardBind, socketCensus(t, endpoint),
		"a freshly started endpoint must hold exactly one bind's worth of receivers")

	var workerHigh int64
	start := time.Now()
	cycles := 0
	for time.Since(start) < time.Second && cycles < 64 {
		endpoint.onPauseUpdated(pause.EventNetworkPause)
		require.Zero(t, socketCensus(t, endpoint),
			"cycle %d: the pause handler must return with the socket released", cycles)
		endpoint.onPauseUpdated(pause.EventNetworkWake)
		cycle := cycles
		require.Eventually(t, func() bool {
			return socketCensus(t, endpoint) == socketsPerStandardBind
		}, 15*time.Second, time.Millisecond,
			"cycle %d: a wake must leave exactly one bind's worth of receivers", cycle)
		require.LessOrEqual(t, socketCensus(t, endpoint), socketsPerStandardBind,
			"cycle %d: more than one bind's worth of receivers is a leaked socket", cycle)
		if workers := int64(goroutineCensus(t, endpoint)); workers > atomic.LoadInt64(&workerHigh) {
			atomic.StoreInt64(&workerHigh, workers)
		}
		cycles++
	}
	elapsed := time.Since(start)
	require.Greater(t, cycles, 3, "the burst must contain several cycles for the question to be asked")

	require.Eventually(t, func() bool {
		return socketCensus(t, endpoint) == socketsPerStandardBind
	}, 15*time.Second, time.Millisecond, "the burst must settle on exactly one socket")
	require.Eventually(t, func() bool {
		return goroutineCensus(t, endpoint) == 0
	}, 15*time.Second, time.Millisecond,
		"a recovery worker outlived the burst, so generations accumulated workers")

	t.Logf("ADVG_REVERSE_WG cycles=%d elapsed=%s sockets=%d workers_now=%d workers_high=%d",
		cycles, elapsed, socketCensus(t, endpoint), goroutineCensus(t, endpoint),
		atomic.LoadInt64(&workerHigh))
	require.LessOrEqual(t, atomic.LoadInt64(&workerHigh), int64(1),
		"more than one recovery worker of this endpoint existed at the same time during the burst")
}

// unused import guard: sync is used by the fixture's gate, kept explicit so this file's dependencies
// are visible.
var _ = sync.Mutex{}
