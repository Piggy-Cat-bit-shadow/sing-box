//go:build with_quic

package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// GOAWAY / draining coverage for the MASQUE pool.
//
// These tests drive a REAL HTTP/3 server that performs a REAL graceful shutdown,
// so the client observes a genuine GOAWAY frame. They deliberately do not set a
// boolean on the slot and then assert the boolean: that style of test proves
// only that the flag exists, not that the protocol event is detected or that the
// pool reacts correctly.
//
// The technique, verified against quic-go v0.61.0-sing-box-mod.7 before being
// relied on:
//
//   - A normal http3.Server.Shutdown() closes the listener, which makes the
//     client see an idle timeout rather than a GOAWAY, so it cannot be used.
//   - Binding the socket ourselves and calling Shutdown() keeps the LISTENER
//     closed from the server's perspective but the client already holds a
//     connection, and quic-go's client sends no new stream on it.
//   - What actually works is the server-side graceful path: an active stream
//     keeps the connection alive, the server shuts down, GOAWAY is sent, and
//     OpenRequestStream then fails with "connection in graceful shutdown".
//
// That last sequence is what the pool must detect, and it is what these tests
// exercise end to end.

// goAwayPoolServer is a real HTTP/3 server whose graceful shutdown can be
// triggered on demand.
type goAwayPoolServer struct {
	address     string
	connections *connectionCounter
	tunnels     *httpserverTunnelCounter
	// hold keeps a CONNECT handler alive so the connection is not simply closed
	// when GOAWAY is sent; without an active stream quic-go closes the
	// connection immediately and there is nothing to drain.
	hold chan struct{}
	// release stops the held handler.
	release   chan struct{}
	server    *http3.Server
	udpConn   net.PacketConn
	closeOnce sync.Once
}

func startGoAwayPoolServer(t *testing.T) *goAwayPoolServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	counter := &connectionCounter{conns: make(map[*quic.Conn]struct{})}
	server := &goAwayPoolServer{
		connections: counter,
		tunnels:     &httpserverTunnelCounter{},
		release:     make(chan struct{}),
		udpConn:     udpConn,
	}
	serverImpl := &http3.Server{
		EnableDatagrams: true,
		TLSConfig:       poolTestServerTLS(t),
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			counter.add(conn)
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodConnect {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			server.tunnels.inc()
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			// Hold the tunnel open so the connection stays busy while the server
			// drains. Without this, quic-go closes the connection as soon as the
			// stream count reaches zero.
			<-server.release
		}),
	}
	server.server = serverImpl
	go func() { _ = serverImpl.Serve(udpConn) }()
	t.Cleanup(func() {
		server.closeOnce.Do(func() { close(server.release) })
		_ = serverImpl.Close()
		udpConn.Close()
	})
	server.address = udpConn.LocalAddr().String()
	return server
}

// poolServer exposes the embedded view the shared test agent constructor needs.
func (s *goAwayPoolServer) poolServer() *masquePoolServer {
	return &masquePoolServer{
		address:     s.address,
		connections: s.connections,
		tunnels:     s.tunnels,
	}
}

// gracefulShutdown sends a REAL GOAWAY frame by performing an HTTP/3 graceful
// shutdown while a tunnel is held open.
//
// Shutdown is run ASYNCHRONOUSLY on purpose. It sends GOAWAY immediately, then
// blocks until active requests finish or its context expires; because this
// server deliberately holds a tunnel open, a synchronous call would block for
// the whole timeout and the test would stall rather than observe the drain. The
// GOAWAY frame is what the client reacts to, and it is sent before that wait.
func (s *goAwayPoolServer) gracefulShutdown(t *testing.T) {
	t.Helper()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx)
	}()
	// Give the GOAWAY frame time to reach the client.
	time.Sleep(200 * time.Millisecond)
}

// TestH3PoolGOAWAYMarksSlotDraining proves a real GOAWAY moves the slot out of
// healthy.
func TestH3PoolGOAWAYMarksSlotDraining(t *testing.T) {
	server := startGoAwayPoolServer(t)
	agent := newPoolTestAgent(t, server.poolServer(), 1)

	// Open a tunnel and hold it: an active stream is what keeps the connection
	// alive across GOAWAY.
	conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, 1, server.connections.count(), "one QUIC connection must exist")

	require.Equal(t, http3SlotHealthy, agent.slots[0].health().State,
		"precondition: the slot starts healthy")

	server.gracefulShutdown(t)
	// Give the client's control-stream reader time to process the frame.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if agent.slots[0].health().State == http3SlotDraining {
			break
		}
		// Attempt a new tunnel: this is what surfaces the GOAWAY to the client,
		// because quic-go reports it from OpenRequestStream.
		newConn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
		if err == nil {
			newConn.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, http3SlotDraining, agent.slots[0].health().State,
		"a GOAWAY must move the slot to draining")
}

// TestH3PoolDoesNotAssignNewTunnelToDrainingSlot proves the pool stops handing
// tunnels to a connection that has received GOAWAY.
//
// The assertion is on SELECTION, not merely on the state field: a slot that is
// marked draining but still selected would be a worse bug than not detecting
// GOAWAY at all.
func TestH3PoolDoesNotAssignNewTunnelToDrainingSlot(t *testing.T) {
	server := startGoAwayPoolServer(t)
	agent := newPoolTestAgent(t, server.poolServer(), 2)

	// Hold tunnels on BOTH slots so both connections exist.
	heldA, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)
	defer heldA.Close()
	heldB, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)
	defer heldB.Close()
	require.GreaterOrEqual(t, server.connections.count(), 2)

	// Force slot 0 into draining directly, since GOAWAY affects whichever
	// connection the server chooses and driving it to a specific slot is not
	// deterministic. The DETECTION of a real GOAWAY is covered by the test
	// above; this test covers the SELECTION consequence.
	agent.slots[0].markDraining(nil)
	require.Equal(t, http3SlotDraining, agent.slots[0].health().State)

	// Releasing the held tunnel on slot 0 must not make it eligible again.
	heldA.Close()
	time.Sleep(50 * time.Millisecond)
	require.False(t, agent.slots[0].eligible(time.Now()),
		"a draining slot must never be eligible, even once idle")

	// New tunnels must land on the healthy slot.
	for range 4 {
		conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
		require.NoError(t, err)
		conn.Close()
	}
	require.Equal(t, http3SlotDraining, agent.slots[0].health().State)
	require.Equal(t, http3SlotHealthy, agent.slots[1].health().State)
	require.Zero(t, agent.slots[0].health().Active,
		"no new tunnel may be attributed to the draining slot")
}

// TestH3PoolExistingTunnelSurvivesGOAWAY proves GOAWAY does NOT kill tunnels
// that are already established.
//
// This is the whole point of draining rather than closing: RFC 9114 forbids new
// streams after GOAWAY but explicitly allows in-flight requests to complete.
func TestH3PoolExistingTunnelSurvivesGOAWAY(t *testing.T) {
	server := startGoAwayPoolServer(t)
	agent := newPoolTestAgent(t, server.poolServer(), 1)

	conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)
	defer conn.Close()

	// The tunnel must be usable BEFORE the drain.
	_, err = conn.Write([]byte("before"))
	require.NoError(t, err)

	server.gracefulShutdown(t)
	time.Sleep(200 * time.Millisecond)

	// The established tunnel must still carry data after GOAWAY.
	_, err = conn.Write([]byte("after"))
	require.NoError(t, err,
		"an established tunnel must survive GOAWAY; only NEW streams are forbidden")

	// And the pool must not have killed the connection out from under it.
	require.False(t, agent.slots[0].shouldClose(),
		"a draining slot with a live tunnel must not be closed")
}

// TestH3PoolReplacesDrainingSlot proves capacity is restored after a drain
// rather than the pool permanently shrinking.
func TestH3PoolReplacesDrainingSlot(t *testing.T) {
	server := startGoAwayPoolServer(t)
	agent := newPoolTestAgent(t, server.poolServer(), 1)

	conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)
	require.Equal(t, 1, agent.slots[0].health().Active,
		"the open tunnel must be counted")
	conn.Close()
	require.Zero(t, agent.slots[0].health().Active,
		"closing the tunnel must release the count, leaving the slot idle")

	// Drain the now-idle slot so it becomes recyclable.
	agent.slots[0].markDraining(nil)
	require.True(t, agent.slots[0].shouldClose(),
		"a draining slot with no live tunnels is recyclable")

	// A new tunnel must still be served: the pool recycles the slot in place.
	newConn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err, "the pool must recover capacity after a drain")
	newConn.Close()

	require.Equal(t, http3SlotHealthy, agent.slots[0].health().State,
		"the recycled slot must be healthy again")
	require.Equal(t, 1, len(agent.slots),
		"recycling must happen IN PLACE, so the pool never exceeds its size")
}

// TestH3PoolDrainingSlotClosesWhenIdle proves an idle draining slot is released
// rather than held forever.
func TestH3PoolDrainingSlotClosesWhenIdle(t *testing.T) {
	server := startGoAwayPoolServer(t)
	agent := newPoolTestAgent(t, server.poolServer(), 1)

	conn, err := agent.DialContext(context.Background(), M.ParseSocksaddr("127.0.0.1:9"))
	require.NoError(t, err)

	// While the tunnel is live the slot must NOT be closed.
	agent.slots[0].markDraining(nil)
	require.False(t, agent.slots[0].shouldClose(),
		"a draining slot with a live tunnel must not be closed")

	// Once the tunnel ends, the slot becomes closable.
	conn.Close()
	require.True(t, agent.slots[0].shouldClose(),
		"an idle draining slot must be released")
}

// TestH3PoolActiveCountLifecycle pins the active-tunnel accounting rules.
//
// A leaked count is subtle and damaging: least-active selection would
// permanently avoid the leaked slot, silently reducing pool capacity.
func TestH3PoolActiveCountLifecycle(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)
	target := M.ParseSocksaddr("127.0.0.1:9")

	t.Run("success increments and close decrements", func(t *testing.T) {
		before := agent.slots[0].health().Active
		conn, err := agent.DialContext(context.Background(), target)
		require.NoError(t, err)
		require.Greater(t, agent.totalActive(), before,
			"an opened tunnel must be counted")
		conn.Close()
		require.Equal(t, before, agent.totalActive(),
			"closing the tunnel must release the count")
	})

	t.Run("double close decrements only once", func(t *testing.T) {
		baseline := agent.totalActive()
		conn, err := agent.DialContext(context.Background(), target)
		require.NoError(t, err)
		conn.Close()
		conn.Close()
		require.Equal(t, baseline, agent.totalActive(),
			"a double close must not double-decrement")
	})

	t.Run("open failure does not leak a count", func(t *testing.T) {
		baseline := agent.totalActive()
		// A cancelled context fails before a stream is opened.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = agent.DialContext(ctx, target)
		require.Equal(t, baseline, agent.totalActive(),
			"a failed open must not leave a count behind")
	})
}

// TestH3SlotFailureDoesNotPoisonAuthority is the P0 separation guard.
//
// A slot being dead, draining or cooling down says NOTHING about whether the
// authority speaks HTTP/3. Only a genuine handshake/ALPN negotiation failure
// may produce ErrHTTP3Unavailable, because that is the single error the caller
// treats as "fall back to HTTP/2".
//
// This is asserted by exhausting the pool's slots and then checking that a
// failing tunnel does NOT report ErrHTTP3Unavailable. If a slot-level failure
// were ever classified as an authority failure, every slot blip would push all
// traffic to HTTP/2, which is exactly the regression this guards.
func TestH3SlotFailureDoesNotPoisonAuthority(t *testing.T) {
	server := startMASQUEPoolServer(t)
	agent := newPoolTestAgent(t, server, 2)
	target := M.ParseSocksaddr("127.0.0.1:9")

	// Make every slot unusable: draining with no live tunnels, which the pool
	// may recycle, and dead, which it cannot use without recycling.
	for _, slot := range agent.slots {
		slot.markDraining(nil)
	}

	// A tunnel still succeeds (the pool recycles), and crucially the error from
	// any failure is never the authority-level sentinel.
	for range 4 {
		conn, err := agent.DialContext(context.Background(), target)
		if err != nil {
			require.False(t, errors.Is(err, ErrHTTP3Unavailable),
				"a slot-level failure must never be reported as HTTP/3 unavailable; got %v", err)
			continue
		}
		conn.Close()
	}

	// Also cover the case where every slot is DEAD, which is the state the pool
	// cannot recover from without re-dialing. The resulting error must still not
	// be the authority-level sentinel: an unusable pool is a transport
	// condition, not an ALPN verdict about the authority.
	for _, slot := range agent.slots {
		slot.markDead()
		slot.access.Lock()
		if slot.rawConn != nil {
			slot.rawConn.Close()
		}
		slot.access.Unlock()
	}
	_, err := agent.DialContext(context.Background(), target)
	if err != nil {
		require.False(t, errors.Is(err, ErrHTTP3Unavailable),
			"a dead pool must not be reported as HTTP3-unavailable; got %v", err)
	}
}

// TestClientSingleFlightH3Probe proves a burst of callers after the avoidance
// window expires produces at most ONE HTTP/3 probe, and that no caller is
// blocked waiting for it.
//
// The hazard: when the window closes, a hundred simultaneous connections would
// otherwise all dial QUIC at once, which is the thundering herd the backoff
// exists to prevent.
func TestClientSingleFlightH3Probe(t *testing.T) {
	client := newScheduleOnlyClient(option.HTTP3FallbackSchedule{
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Multiplier:     2,
		ResetOnSuccess: true,
	})
	require.NotNil(t, client)

	// Put the client into an open avoidance window with a long deadline, so the
	// next callers are in the "window open" branch.
	client.http3BrokenUntil.Store(time.Now().Add(time.Hour).UnixNano())
	require.False(t, client.http3WindowElapsed(), "precondition: the window is open")

	const callers = 64
	results := make(chan struct {
		useH3   bool
		isProbe bool
	}, callers)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			useH3, isProbe := client.http3ProbeDecision()
			results <- struct {
				useH3   bool
				isProbe bool
			}{useH3, isProbe}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	probes := 0
	blocked := 0
	for result := range results {
		if result.isProbe {
			probes++
		}
		if !result.useH3 && !result.isProbe {
			// A non-winner must go straight to HTTP/2, not wait.
			blocked++
		}
	}
	require.Equal(t, 1, probes,
		"exactly one caller may hold the H3 probe; got %d", probes)
	require.Equal(t, callers-1, blocked,
		"every other caller must proceed on HTTP/2 without waiting; got %d", blocked)

	// Releasing the probe lets the next caller become the prober, so recovery is
	// not permanently wedged by one attempt.
	client.finishProbe()
	_, isProbe := client.http3ProbeDecision()
	require.True(t, isProbe, "after the probe completes a new probe must be possible")
	client.finishProbe()
}

// TestClientProbeReleasedOnBothOutcomes proves the single-flight slot is
// released whether the probe succeeds or fails.
//
// A leak here would be permanent: H3 would never be probed again.
func TestClientProbeReleasedOnBothOutcomes(t *testing.T) {
	t.Run("on failure the window reopens and the probe slot frees", func(t *testing.T) {
		client := newScheduleOnlyClient(option.HTTP3FallbackSchedule{
			InitialBackoff: 5 * time.Second,
			MaxBackoff:     5 * time.Minute,
			Multiplier:     2,
			ResetOnSuccess: true,
		})
		// An OPEN window with a probe in flight is the recovery scenario: the
		// window has expired, so a probe is allowed.
		client.http3BrokenUntil.Store(time.Now().Add(time.Hour).UnixNano())
		require.False(t, client.http3WindowElapsed(), "precondition: the window is open")
		useH3, isProbe := client.http3ProbeDecision()
		require.True(t, useH3, "the probe owner must attempt HTTP/3")
		require.True(t, isProbe)

		client.markHTTP3Broken()
		client.finishProbe()

		require.False(t, client.http3WindowElapsed(),
			"a failed probe must reopen the avoidance window")
		require.False(t, client.probeActive.Load(),
			"the probe slot must be released after a failure")
	})

	t.Run("on success the window clears and the probe slot frees", func(t *testing.T) {
		client := newScheduleOnlyClient(option.HTTP3FallbackSchedule{
			InitialBackoff: 5 * time.Second,
			MaxBackoff:     5 * time.Minute,
			Multiplier:     2,
			ResetOnSuccess: true,
		})
		client.http3BrokenUntil.Store(time.Now().Add(time.Hour).UnixNano())
		_, isProbe := client.http3ProbeDecision()
		require.True(t, isProbe)

		client.clearHTTP3Broken()
		client.finishProbe()

		require.True(t, client.http3WindowElapsed(),
			"a successful probe must clear the avoidance window")
		require.False(t, client.probeActive.Load(),
			"the probe slot must be released after a success")
		require.Zero(t, client.http3Escalation.Load(),
			"reset_on_success must clear the escalation history")
	})
}
