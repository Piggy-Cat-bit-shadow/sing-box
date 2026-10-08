package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// lifecycleConfig is deliberately minimal: the lifecycle questions are about the box's own
// resources, and a simple chain makes "did this flow survive" unambiguous.
const lifecycleConfig = `{
  "log": {"level": "%s"},
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "remote", "server": "127.0.0.1", "server_port": %d, "version": "5"}
  ],
  "route": {
    "rules": [
      {"ip_cidr": ["10.9.9.9/32"], "port": [%d], "action": "route", "outbound": "remote"}
    ],
    "final": "direct"
  }
}`

// TestLifecycleUnderLoad drives the lifecycle operations the mobile clients perform against a live
// chain: a network reset while traffic is flowing, a memory trim while a flow is active, and a
// close while connections are busy.
//
// The assertions are about boundedness, survival and non-resurrection rather than about timing:
// a reset that takes an unbounded time is a hang, a trim that kills an active flow is a
// regression, and a box that still accepts connections after Close has been resurrected.
func TestLifecycleUnderLoad(t *testing.T) {
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sink := startSocksSink(t, "127.0.0.1:0")
	proxyPort := freePort(t)
	config := fmt.Sprintf(lifecycleConfig, chainLogLevel, proxyPort,
		uint16(sink.listener.Addr().(*net.TCPAddr).Port), echoPort)
	running := startChain(t, config)
	proxyAddress := fmt.Sprintf("127.0.0.1:%d", proxyPort)

	t.Run("network_reset_during_traffic", func(t *testing.T) {
		// Four long-lived connections, all mid-conversation.
		connections := make([]net.Conn, 4)
		for index := range connections {
			conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
			requireEcho(t, conn, fmt.Sprintf("before-reset-%d", index))
			connections[index] = conn
			defer conn.Close()
		}
		resetDone := make(chan time.Duration, 1)
		go func() {
			started := time.Now()
			running.instance.Network().ResetNetwork(context.Background())
			resetDone <- time.Since(started)
		}()
		select {
		case elapsed := <-resetDone:
			t.Logf("network reset returned after %s", elapsed)
			require.Less(t, elapsed, 10*time.Second, "a network reset must be bounded")
		case <-time.After(15 * time.Second):
			t.Fatal("network reset did not return within 15s: it is a hang, not a slow reset")
		}
		// Every in-flight connection must reach a conclusion - either it still carries data, or it
		// fails - within a bound. What it must not do is hang forever.
		for index, conn := range connections {
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
			payload := fmt.Sprintf("after-reset-%d", index)
			_, writeErr := conn.Write([]byte(payload))
			if writeErr != nil {
				require.NotErrorIs(t, writeErr, context.DeadlineExceeded)
				t.Logf("connection %d failed after the reset, as allowed: %v", index, writeErr)
				continue
			}
			reply := make([]byte, len(payload))
			_, readErr := io.ReadFull(conn, reply)
			if readErr != nil {
				t.Logf("connection %d read failed after the reset, as allowed: %v", index, readErr)
				continue
			}
			require.Equal(t, payload, string(reply))
		}
		// New traffic must work immediately: a reset that leaves the box unable to dial is worse
		// than one that drops the old flows.
		for round := 0; round < 4; round++ {
			conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
			requireEcho(t, conn, fmt.Sprintf("post-reset-%d", round))
			require.NoError(t, conn.Close())
		}
	})

	t.Run("repeated_resets_do_not_accumulate", func(t *testing.T) {
		for round := 0; round < 5; round++ {
			conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
			requireEcho(t, conn, "during-resets")
			require.NoError(t, conn.Close())
			done := make(chan struct{})
			go func() {
				running.instance.Network().ResetNetwork(context.Background())
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("reset %d did not return within 10s", round)
			}
		}
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "after-repeated-resets")
	})

	t.Run("trim_idle_resources_keeps_active_flow", func(t *testing.T) {
		conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
		defer conn.Close()
		requireEcho(t, conn, "before-trim")
		running.sessionTrim(t)
		// The SAME connection must still work: trimming may release reusable pools, never an
		// active flow.
		requireEcho(t, conn, "after-trim-same-connection")
		// And a new flow must be creatable without a stall.
		fresh := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
		defer fresh.Close()
		requireEcho(t, fresh, "after-trim-new-connection")
	})

	t.Run("close_under_load", func(t *testing.T) {
		const workers = 32
		var (
			started   sync.WaitGroup
			stop      atomic.Bool
			completed atomic.Int64
		)
		connections := make([]net.Conn, 0, workers)
		var connectionsLock sync.Mutex
		for index := 0; index < workers; index++ {
			conn := dialSocks5(t, proxyAddress, 0x01, "127.0.0.1", echoPort)
			connectionsLock.Lock()
			connections = append(connections, conn)
			connectionsLock.Unlock()
			started.Add(1)
			go func(index int, conn net.Conn) {
				defer started.Done()
				for !stop.Load() {
					payload := fmt.Sprintf("load-%02d", index)
					if _, err := conn.Write([]byte(payload)); err != nil {
						return
					}
					reply := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, reply); err != nil {
						return
					}
					completed.Add(1)
				}
			}(index, conn)
		}
		// Let the load actually start before closing.
		deadline := time.Now().Add(5 * time.Second)
		for completed.Load() < int64(workers) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		require.GreaterOrEqual(t, completed.Load(), int64(workers), "the load never started")

		closeDone := make(chan error, 1)
		go func() { closeDone <- running.closeNow() }()
		select {
		case err := <-closeDone:
			require.NoError(t, err, "Close under load must not report an error")
		case <-time.After(20 * time.Second):
			t.Fatal("Close under load did not return within 20s")
		}
		stop.Store(true)

		// Every busy connection must fail rather than hang.
		connectionsLock.Lock()
		openConnections := append([]net.Conn(nil), connections...)
		connectionsLock.Unlock()
		for index, conn := range openConnections {
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
			_, err := conn.Write([]byte("after-close"))
			if err == nil {
				reply := make([]byte, len("after-close"))
				_, err = io.ReadFull(conn, reply)
			}
			require.Error(t, err, "connection %d survived Close", index)
			require.NoError(t, conn.Close())
		}
		started.Wait()

		// A closed box must not be resurrected: the listener is gone.
		_, dialErr := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
		require.Error(t, dialErr, "the inbound listener must be closed with the box")

		// Close is idempotent and safe to repeat.
		require.NoError(t, running.closeNow())
	})

	t.Run("repeated_start_stop_leaves_no_goroutines", func(t *testing.T) {
		// The box under test is already closed by the subtest above, so this measures a clean
		// slate plus N full start/close cycles.
		running.closeNow()
		settle()
		baseline := runtime.NumGoroutine()
		var counts []int
		for round := 0; round < 5; round++ {
			port := freePort(t)
			single := startChain(t, fmt.Sprintf(lifecycleConfig, chainLogLevel, port,
				uint16(sink.listener.Addr().(*net.TCPAddr).Port), echoPort))
			conn := dialSocks5(t, fmt.Sprintf("127.0.0.1:%d", port), 0x01, "127.0.0.1", echoPort)
			requireEcho(t, conn, fmt.Sprintf("cycle-%d", round))
			require.NoError(t, conn.Close())
			require.NoError(t, single.closeNow())
			settle()
			counts = append(counts, runtime.NumGoroutine())
		}
		t.Logf("goroutines: baseline=%d after each cycle=%v", baseline, counts)
		require.LessOrEqual(t, counts[len(counts)-1], baseline+8,
			"goroutines after five start/close cycles: %v (baseline %d)", counts, baseline)
		require.LessOrEqual(t, counts[len(counts)-1], counts[0]+4,
			"goroutine count grew across identical cycles, which is what a leak looks like: %v", counts)
	})
}

// TestFirstDialAfterStartIsNotCancelled is the intermittent-outcome half of the regression for a
// failure this suite found. Its deterministic half is
// TestFirstDialAfterStartIsNotCancelledByTheStartupObservation, which holds the same window open
// instead of racing it; this one races it, with nothing between Start and the dial, and is the gate
// that fails whenever the window opens on its own.
//
// # The symptom, measured
//
// A connection made through a freshly started box is sometimes cancelled before it is routed. The
// client sees a SOCKS5 failure (0x01), and the box's own log says either
//
//	connection: open connection to 127.0.0.1:PORT using outbound/direct[direct]:
//	  dial 127.0.0.1: network changed while dialling
//
// or, when the dial had not finished connecting yet,
//
//	connection: open connection to 127.0.0.1:PORT using outbound/direct[direct]:
//	  dial 127.0.0.1: dial tcp 127.0.0.1:PORT: operation was canceled
//
// Observed in this suite's full-package run: 2 of 20 iterations without -race, and both -race
// -count=20 runs, once failing four subtests at once. It has never reproduced when the same
// assertions are run in isolation (240 box starts in a row passed).
//
// # The sequence, established
//
// Both errors are produced by ONE transition, and it is the box's first environment observation:
//
//	NetworkManager.Start(StartStatePostStart)        route/network.go
//	  dispatchInterfaceUpdateLocked                  spawns `go updateInterface(...)`
//	updateInterface                                  route/network.go
//	  recomputeNetworkEnvironment                    route/network_environment.go
//	    fingerprint 0 -> the real one, epoch claimed, network marked unsettled
//	  resetNetworkLocked                             route/network.go
//	    connectionManager.Reclaim -> dialSetupGate.advance
//	                                                 route/dial_setup.go, cancels every
//	                                                 not-yet-established dial: "operation was
//	                                                 canceled"
//	    router.ResetNetwork, InterfaceUpdated
//	  commitTransition
//
// That goroutine is spawned before Start returns and can reach its claim after it - measured at
// 3.6 ms from the start of recomputeNetworkEnvironment to the claim in the one round of 300 that
// failed, which is long enough for a caller's first connection to begin. Such a connection
// captured the pre-transition epoch, so the dialer's epoch guard refused it at hand-over
// ("network changed while dialling"); if it was still connecting, the setup gate cancelled it
// first. Either way the box refused a connection over a network that had not changed: it was
// still learning which network it was on.
//
// A probe on a just-started box reads epoch 1, settled true when the observation wins the race and
// epoch 0, settled true when the caller's dial begins first - both are "the box has not finished
// its own first observation", and the second is the failing one.
//
// # The fix
//
// The first observation is established before Start returns
// (Box.start -> NetworkManager.EstablishInitialNetworkEnvironment, route/network_environment.go),
// and a manager that has not started does not observe its environment at all. The guard, the reset
// body and the claim are untouched: a genuine transition still moves the epoch, cancels in-flight
// dials and re-pins the transports.
//
// # Why the test is strict
//
// It dials immediately after Start with nothing in between, and asserts success with no retry: a
// retry would hide exactly the thing being measured.
func TestFirstDialAfterStartIsNotCancelled(t *testing.T) {
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sink := startSocksSink(t, "127.0.0.1:0")
	sinkPort := uint16(sink.listener.Addr().(*net.TCPAddr).Port)
	for round := 0; round < 6; round++ {
		port := freePort(t)
		single := startChain(t, fmt.Sprintf(lifecycleConfig, chainLogLevel, port, sinkPort, echoPort))
		// The dial happens immediately: no probe, no log, nothing that would give the startup
		// transition time to finish. That immediacy IS the test.
		conn, code := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", port), 0x01, "127.0.0.1", echoPort)
		if conn != nil {
			conn.Close()
		}
		require.Equal(t, byte(0x00), code,
			"round %d: the first connection through a freshly started box was cancelled "+
				"(see the box's own log line: dial ...: network changed while dialling)", round)
		require.NoError(t, single.closeNow())
	}
}

// environmentObservationGate is a log.PlatformWriter that holds the goroutine reporting a new
// network environment, so a test can decide what the box does while that report is in flight.
//
// The platform writer is a production interface: it is how the mobile clients forward the box's log,
// and the box calls it for every message, at every level, from the goroutine that logged it. That
// makes it an observation point on the box's own transition path rather than a test hook - and the
// message it waits for is the one the transition emits after it has published the new fingerprint
// and claimed the epoch, which is the state the defect is about.
type environmentObservationGate struct {
	marker   string
	parked   chan struct{}
	released chan struct{}
	once     sync.Once
}

func newEnvironmentObservationGate() *environmentObservationGate {
	return &environmentObservationGate{
		marker:   "updated network environment",
		parked:   make(chan struct{}),
		released: make(chan struct{}),
	}
}

// WriteMessage blocks the first matching report until release is called. Every other message - and
// every later environment report - passes straight through, so the box keeps logging and a held
// report cannot stall anything but the goroutine that made it.
func (g *environmentObservationGate) WriteMessage(_ log.Level, message string) {
	if !strings.Contains(message, g.marker) {
		return
	}
	g.once.Do(func() {
		close(g.parked)
		<-g.released
	})
}

// release lets the held report through. Idempotent, and safe to call when nothing is parked.
func (g *environmentObservationGate) release() {
	select {
	case <-g.released:
	default:
		close(g.released)
	}
}

// TestFirstDialAfterStartIsNotCancelledByTheStartupObservation is the deterministic half of the
// regression TestFirstDialAfterStartIsNotCancelled describes.
//
// # What makes it deterministic
//
// The defect is a race: the box's first environment observation runs on a goroutine that can reach
// its claim after Start has returned, so the first dial begins before the transition and is handed
// over after it. Racing it directly makes the failure 1-in-300 (see the other test's comment for the
// measurement), which is not a usable red check.
//
// This test does not race it. The box is given a platform log writer that holds the observation open
// at the report it emits immediately after claiming the epoch - the transition is then in flight and
// cannot commit - and the dial is made against that state. A box that returned from Start with its
// observation still owed fails, deterministically; a box that establishes it before returning passes,
// because there is nothing left to land mid-dial.
//
// # The two orderings
//
//	Start returns while the report is still owed    the defect: the observation is a background
//	                                               update, and it can land mid-dial
//	Start does not return because of the report     the fix: the observation is part of starting
//
// The second is stated the only way "nothing happened" can be: a bounded wait. Start takes
// milliseconds, and a box that has not returned after two seconds is a box whose start is waiting
// for its own network observation, because the report it makes is held and cannot complete.
func TestFirstDialAfterStartIsNotCancelledByTheStartupObservation(t *testing.T) {
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sink := startSocksSink(t, "127.0.0.1:0")
	sinkPort := uint16(sink.listener.Addr().(*net.TCPAddr).Port)
	port := freePort(t)
	gate := newEnvironmentObservationGate()
	defer gate.release()
	running := buildChain(t, fmt.Sprintf(lifecycleConfig, chainLogLevel, port, sinkPort, echoPort), gate)

	started := make(chan error, 1)
	go func() { started <- running.instance.Start() }()

	const observationBound = 10 * time.Second
	select {
	case <-gate.parked:
	case <-time.After(observationBound):
		t.Fatal("the box never reported a network environment: this host has no default interface " +
			"for the first observation to describe, so it cannot exercise this defect")
	}

	// The precondition that keeps the assertion below from being vacuous: there really was an
	// environment to observe, and the box has published it. (The report this gate holds is emitted
	// after the fingerprint is published, so it holds in both orderings.)
	require.NotZero(t, running.instance.Network().NetworkEnvironment(),
		"the box never published a network environment; this host has no default interface for the "+
			"first observation to describe")

	const startBound = 2 * time.Second
	var startErr error
	select {
	case startErr = <-started:
		require.NoError(t, startErr, "box.Start failed")
		// The defect, exactly: the box is up, and the transition that learns which network it is on
		// is in flight and uncommitted. Dial now, which is what a caller does, and it must not be
		// refused - there was no network change for it to cross.
	case <-time.After(startBound):
		// Start is blocked making the report itself. Let it finish: the box it returns is one whose
		// network it has already observed.
		gate.release()
		select {
		case startErr = <-started:
		case <-time.After(observationBound):
			t.Fatal("Start did not return after its first environment observation was released")
		}
	}
	require.NoError(t, startErr, "box.Start failed")

	conn, code := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", port), 0x01, "127.0.0.1", echoPort)
	if conn != nil {
		conn.Close()
	}
	gate.release()
	require.Equal(t, byte(0x00), code,
		"the first connection through a freshly started box was cancelled by the box's own first "+
			"environment observation: the box reported itself started before it knew which network "+
			"it was on, and the transition that learns it refused the dial (the box's log says "+
			"either \"network changed while dialling\" or \"operation was canceled\")")
}

// TestRepeatedStartDialCycles is the same first-dial assertion repeated past the point where the
// defect's 1-in-300 rate could hide, with box lifetime churn in between.
//
// Each cycle is a complete start and close of a real box, and the dial is made with nothing in
// between: no probe, no wait, no retry. A retry would hide exactly what this measures, so a single
// non-zero reply code fails the cycle that produced it - and the round number says which start it
// was, because "it failed once in 120" is a different report from "it failed on the first".
//
// The goroutine count is taken before the cycles and after them, with the same tolerance the
// lifecycle churn test uses: a start/close cycle that leaks is a second defect, and it would also
// make the next cycle's timing unlike the first.
func TestRepeatedStartDialCycles(t *testing.T) {
	echo := startEchoServer(t, "tcp", "127.0.0.1:0")
	echoPort := uint16(echo.listener.Addr().(*net.TCPAddr).Port)
	sink := startSocksSink(t, "127.0.0.1:0")
	sinkPort := uint16(sink.listener.Addr().(*net.TCPAddr).Port)
	settle()
	baseline := runtime.NumGoroutine()
	const cycles = 120
	for round := 0; round < cycles; round++ {
		port := freePort(t)
		single := startChain(t, fmt.Sprintf(lifecycleConfig, chainLogLevel, port, sinkPort, echoPort))
		conn, code := socks5Request(t, fmt.Sprintf("127.0.0.1:%d", port), 0x01, "127.0.0.1", echoPort)
		if conn != nil {
			conn.Close()
		}
		require.Equal(t, byte(0x00), code,
			"cycle %d of %d: the first connection through a freshly started box was cancelled",
			round, cycles)
		require.NoError(t, single.closeNow())
	}
	settle()
	after := runtime.NumGoroutine()
	t.Logf("goroutines: baseline=%d after %d start/close cycles=%d", baseline, cycles, after)
	require.LessOrEqual(t, after, baseline+8,
		"goroutines after %d start/close cycles: %d (baseline %d)", cycles, after, baseline)
}

// sessionTrim calls the production memory-trim entry point the mobile clients call.
func (c *chain) sessionTrim(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		c.instance.Network().TrimMemory(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("TrimMemory did not return within 10s")
	}
}

// settle gives the runtime a bounded chance to reap goroutines. It waits for the count to stop
// decreasing rather than sleeping a fixed amount, so it is a convergence check, not a delay.
func settle() {
	previous := runtime.NumGoroutine()
	for attempt := 0; attempt < 100; attempt++ {
		time.Sleep(20 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current >= previous {
			if current == previous {
				return
			}
		}
		previous = current
	}
}

// goroutineReport is the diagnostic printed when a lifecycle assertion fails: the stacks of every
// goroutine, so "it leaked" comes with what leaked.
func goroutineReport() string {
	buffer := make([]byte, 1<<20)
	length := runtime.Stack(buffer, true)
	return string(buffer[:length])
}
