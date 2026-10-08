package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// TestFirstDialAfterStartIsNotCancelled is the regression test for an intermittent failure this
// suite found.
//
// # The symptom, measured
//
// A connection made through a freshly started box is sometimes cancelled before it is routed. The
// client sees a SOCKS5 failure (0x01), and the box's own log says:
//
//	connection: open connection to 127.0.0.1:PORT using outbound/direct[direct]:
//	  dial 127.0.0.1: network changed while dialling
//
// Observed in this suite's full-package run: 2 of 20 iterations without -race, and both
// -race -count=20 runs, once failing four subtests at once. It has never reproduced when the same
// assertions are run in isolation (240 box starts in a row passed).
//
// # The layer is certain, the trigger is not
//
// The error string has exactly one source: common/dialer's epoch guard, which captures
// (epoch, settled) when a dial STARTS and refuses the connection when the network was unsettled at
// that moment or the epoch moved while the dial was in flight. That contract is deliberate and
// correct - it is what stops a dial begun on the old network from being handed over on the new one.
//
// What is NOT established is what advances the epoch or clears the settled flag in this window.
// The leading hypothesis, with one supporting measurement, is the box's own startup:
//
//   - route/network_environment.go publishes the first network-environment fingerprint
//     asynchronously (updateEnvironment -> beginTransition), so that transition can land after
//     Box.Start has returned;
//   - a probe on a box whose Start has just returned reads the transition snapshot and sees
//     epoch 1, settled true - the epoch is 1, not 0, because the startup transition already claimed
//     one. Under load that transition can complete late enough to catch the first dial.
//
// That hypothesis is not proven, and the fix is not this package's to make: it belongs with the
// startup transition (route/network*.go) or with the guard's treatment of the first transition
// (common/dialer) - there was no previous network to leave.
//
// # Why the test is strict
//
// It dials immediately after Start with nothing in between, and asserts success with no retry: a
// retry would hide exactly the thing being measured. It is a gate for the fix, and it also fails
// whenever the window opens.
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
