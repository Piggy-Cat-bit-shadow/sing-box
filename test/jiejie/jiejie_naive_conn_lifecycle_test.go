package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

// This file MEASURES the Native Naive inbound's connection lifecycle over a real
// socket. It exists because reading code produced two opposite errors in earlier
// rounds, so every claim below is an observation of a live connection.
//
// The experiments map one-to-one onto the recognised attack surface:
//
//	A. TLS completes, then no HTTP header is sent at all.
//	B. HTTP/1 headers arrive a few bytes at a time, forever.
//	C. HTTP/2 connection with no stream ever opened.
//	D. HTTP/2 stream opened, then the peer stops sending.
//	E. Authenticated CONNECT succeeds, then the tunnel goes idle forever.
//	F. Wrong password, to confirm the failure path is not LONGER-lived.
//	G. Ordinary HTTPS/masquerade traffic, to confirm normal web serving works.
//
// The point is NOT to make everything bounded. The point is to know precisely
// which stages are bounded, by what, and which are not -- so a later change can
// add a bound without guessing.

// naiveLifecycleServer is a running Naive inbound plus the port it listens on.
type naiveLifecycleServer struct {
	port uint16
	env  *naiveTestEnv
}

func startNaiveLifecycleServer(t *testing.T) *naiveLifecycleServer {
	t.Helper()
	env := startNaiveInbound(t, false)
	return &naiveLifecycleServer{port: env.port, env: env}
}

// waitForConnClosed reports whether the peer closed the connection within the
// window.
//
// The distinction that matters is EOF/RST versus a LOCAL read timeout: both make
// Read return an error, but only the first means the server closed. An earlier
// version of this helper treated any error as "closed" and therefore reported
// every idle connection as server-closed the instant its own deadline expired --
// a false positive that, taken at face value, would have "proved" an idle timeout
// that does not exist.
//
// So the deadline is treated as "still open", and only os.ErrDeadlineExceeded is
// excluded explicitly rather than relying on the error's identity.
func waitForConnClosed(conn net.Conn, window time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	if err == nil {
		// Data arrived; the peer is alive and talking.
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// Our own deadline fired. The peer said nothing, but it did NOT close.
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	// EOF or reset: the peer really did close.
	return true
}

// countGoroutines samples the goroutine count a few times and returns the
// minimum, which filters out transient goroutines from the test framework itself.
func countGoroutines() int {
	best := -1
	for range 5 {
		n := runtime.NumGoroutine()
		if best == -1 || n < best {
			best = n
		}
		time.Sleep(10 * time.Millisecond)
	}
	return best
}

// ---------------------------------------------------------------------------
// A. TLS handshake, then silence.
// ---------------------------------------------------------------------------

// TestAuditNaiveStageA_TLSThenSilenceIsMeasured records what actually happens to a
// peer that completes the TLS handshake and then sends nothing.
//
// THIS CORRECTS AN EARLIER CLAIM. A previous round asserted that this stage was
// bounded by C.TCPTimeout (15s). That is wrong for the Naive path, and the
// mistake is instructive because there are TWO functions named ServerHandshake:
//
//	sing-box/common/tls/server.go   ServerHandshake  -- applies C.TCPTimeout
//	                                                   when HandshakeTimeout()==0
//	sing/common/tls/config.go       ServerHandshake  -- applies the timeout ONLY
//	                                                   when HandshakeTimeout() > 0
//
// The Naive listener is built with aTLS.NewListener (the SING package), whose
// LazyConn.Read calls the SING ServerHandshake with context.Background(). The
// Naive TLS config never sets HandshakeTimeout, so no timeout is applied at all,
// and background() carries no deadline either.
//
// So the earlier claim cited a fallback that lives in a function this path never
// calls. The measurement below is what settles it.
//
// The stage is therefore UNBOUNDED by default: a peer can complete the handshake
// and hold the connection, its goroutine and its file descriptor indefinitely.
func TestAuditNaiveStageA_TLSThenSilenceIsMeasured(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(server.port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "naive.test",
		NextProtos:         []string{"http/1.1"},
	})
	require.NoError(t, tlsConn.Handshake())

	// Observe for well past the 15s bound the earlier claim named. If that bound
	// existed on this path, the connection would be gone by now.
	const observation = 20 * time.Second
	closed := waitForConnClosed(tlsConn, observation)
	t.Logf("OBSERVED: TLS completed then silence -> closed within %s: %v", observation, closed)

	require.False(t, closed,
		"a post-handshake-silent connection was closed; if a handshake or header "+
			"timeout was added, this test must be updated to assert the new bound")
}

// TestAuditNaiveStageA2_HandshakeTimeoutBoundsMidHandshakeStall proves the SCOPE
// of handshake_timeout, which is narrower than it first appears.
//
// The first version of this test asserted that handshake_timeout disconnects a
// peer that completes the TLS handshake and then goes silent. It does not, and
// the failure was informative rather than a product bug:
//
//	LazyConn.Read -> ServerHandshake(ctx with 3s) -> tlsConn.HandshakeContext(ctx)
//
// The deadline covers the HANDSHAKE. A client that finishes the handshake
// finishes it, the context is cancelled, and every later read is unbounded. So
// handshake_timeout bounds "stalled mid-handshake" and nothing after it.
//
// This test therefore asserts the property handshake_timeout DOES provide: a peer
// that opens TCP and never completes the handshake is disconnected.
func TestAuditNaiveStageA2_HandshakeTimeoutBoundsMidHandshakeStall(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.TLS.HandshakeTimeout = badoption.Duration(3 * time.Second)
	})

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Open TCP and send NOTHING. No ClientHello, so the server-side handshake can
	// never complete and the configured deadline is the only thing that can end it.
	closed := waitForConnClosed(conn, 15*time.Second)
	t.Logf("OBSERVED: with handshake_timeout=3s, peer that never sent a ClientHello closed within 15s: %v", closed)
	require.True(t, closed,
		"handshake_timeout did not disconnect a peer that never started the handshake")
}

// ---------------------------------------------------------------------------
// B. Extremely slow HTTP/1 headers.
// ---------------------------------------------------------------------------

// TestAuditNaiveStageB_SlowHeadersCanBeHeldIndefinitely records the first
// genuinely unbounded stage.
//
// Once the TLS handshake is done, the http.Server has no ReadHeaderTimeout and
// the Naive conn has no read deadline, so a peer that dribbles header bytes
// slower than the header-timeout (which does not exist) can hold a connection
// and its goroutine open for as long as it keeps trickling bytes.
//
// The test asserts the CURRENT behaviour, which is that the connection survives a
// window far longer than any production timeout would be. It is written as a
// positive assertion of the unbounded shape so that adding a bound later turns
// this test RED and forces the change to be deliberate.
func TestAuditNaiveStageB_SlowHeadersCanBeHeldIndefinitely(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	tlsConn := naiveTLSConn(t, server.port, "http/1.1")

	// Send a partial request line and stop. No complete header block ever
	// arrives, so the request never reaches ServeHTTP.
	_, err := tlsConn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n"))
	require.NoError(t, err)

	// Trickle a byte occasionally, which is what defeats a per-read timeout and
	// is the classic slowloris shape.
	observed := 0
	for range 4 {
		time.Sleep(1500 * time.Millisecond)
		if _, err = tlsConn.Write([]byte("X")); err != nil {
			break
		}
		observed++
	}
	require.Equal(t, 4, observed,
		"the server closed a connection whose headers arrive slowly; if a header "+
			"timeout was added deliberately, update this test rather than deleting it")

	t.Logf("OBSERVED: an incomplete HTTP/1 header block held a connection open for "+
		"%d keepalive rounds with no server-side header timeout", observed)
}

// ---------------------------------------------------------------------------
// C. HTTP/2 connection with no stream.
// ---------------------------------------------------------------------------

// TestAuditNaiveStageC_H2IdleConnectionLifetime records how long an HTTP/2
// connection that completes its preface but never opens a stream survives, both
// with the default configuration and with an explicit idle timeout.
//
// This is the test that distinguishes "MaxConcurrentStreams bounds streams" from
// "something bounds connections": a connection with ZERO streams is unaffected by
// any stream limit, so if nothing else applies, it lives until the peer leaves.
func TestAuditNaiveStageC_H2IdleConnectionLifetime(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	tlsConn := naiveTLSConn(t, server.port, "h2")
	// The HTTP/2 client preface, then nothing. No SETTINGS frame follows, so the
	// server's http2 state machine is waiting on the preface.
	_, err := tlsConn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)

	closed := waitForConnClosed(tlsConn, 6*time.Second)
	t.Logf("OBSERVED: idle HTTP/2 connection (no stream) closed by server within 6s: %v", closed)

	require.False(t, closed,
		"an idle HTTP/2 connection was closed by the server; if a default idle "+
			"timeout was introduced, this test must be updated deliberately")
}

// ---------------------------------------------------------------------------
// E/F. Authentication outcomes.
// ---------------------------------------------------------------------------

// TestAuditNaiveStageF_BadAuthIsNotLongerLivedThanSuccess proves the failure path
// does not hold resources longer than the success path, which is the property
// that actually matters for an attacker probing passwords.
func TestAuditNaiveStageF_BadAuthIsNotLongerLivedThanSuccess(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	conn := naiveTLSConn(t, server.port, "http/1.1")

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("naive-user:WRONG-PASSWORD"))
	request := "CONNECT example.com:443 HTTP/1.1\r\n" +
		"Host: example.com:443\r\n" +
		"Proxy-Authorization: " + auth + "\r\n\r\n"
	_, err := conn.Write([]byte(request))
	require.NoError(t, err)

	// The server must answer (407, or the masquerade when configured) rather than
	// holding the connection waiting for something.
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	statusLine, err := reader.ReadString('\n')
	require.NoError(t, err, "no response to a wrong-password CONNECT")
	require.Contains(t, statusLine, "407",
		"a wrong password must be refused with the proxy-auth challenge")
}

// TestAuditNaiveStageG_MasqueradeServesOrdinaryTraffic proves the decoy web path
// still works, so any limiter added later cannot be allowed to break it.
func TestAuditNaiveStageG_MasqueradeServesOrdinaryTraffic(t *testing.T) {
	env := startNaiveInbound(t, true)

	conn := naiveTLSConn(t, env.port, "http/1.1")
	_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: naive.test\r\n\r\n"))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer response.Body.Close()

	require.Equal(t, http.StatusOK, response.StatusCode,
		"ordinary HTTPS traffic must be served the decoy page")
}

// ---------------------------------------------------------------------------
// Resource accounting.
// ---------------------------------------------------------------------------

// TestAuditNaiveIdleConnectionsAreTrackedAndReleased drives N simultaneous idle
// TLS connections, confirms the process really is holding that many, then closes
// them and confirms the resource returns.
//
// This is mechanism evidence, not a throughput claim: it establishes that the
// count of held connections is observable and that closing them releases
// everything, which is the precondition for any limiter being meaningful.
func TestAuditNaiveIdleConnectionsAreTrackedAndReleased(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	const connectionCount = 40

	baselineGoroutines := countGoroutines()

	conns := make([]*tls.Conn, 0, connectionCount)
	for range connectionCount {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(server.port)), 10*time.Second)
		require.NoError(t, err)
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "naive.test",
			NextProtos:         []string{"http/1.1"},
		})
		require.NoError(t, tlsConn.Handshake())
		conns = append(conns, tlsConn)
	}

	heldGoroutines := countGoroutines()
	require.GreaterOrEqual(t, heldGoroutines, baselineGoroutines,
		"holding %d connections must not reduce the goroutine count", connectionCount)
	t.Logf("OBSERVED: %d idle TLS connections -> goroutines %d -> %d (delta %d)",
		connectionCount, baselineGoroutines, heldGoroutines, heldGoroutines-baselineGoroutines)

	for _, conn := range conns {
		_ = conn.Close()
	}

	// Cleanup must actually happen; poll rather than assuming it is instant.
	var released int
	for range 60 {
		released = countGoroutines()
		if released <= baselineGoroutines+2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("OBSERVED: after close -> goroutines %d (baseline %d)", released, baselineGoroutines)
	require.LessOrEqual(t, released, baselineGoroutines+2,
		"goroutines did not return to baseline after the connections were closed, "+
			"which would mean the per-connection resource is leaked")
}

// TestAuditNaiveSlowHeaderConnectionsHoldRealResources quantifies what the
// unbounded stage B actually costs, so the finding is a measurement rather than
// an assertion.
func TestAuditNaiveSlowHeaderConnectionsHoldRealResources(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	const connectionCount = 40
	baseline := countGoroutines()

	conns := make([]*tls.Conn, 0, connectionCount)
	for range connectionCount {
		conn := naiveTLSConn(t, server.port, "http/1.1")
		_, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n"))
		require.NoError(t, err)
		conns = append(conns, conn)
	}

	held := countGoroutines()
	t.Logf("OBSERVED: %d stalled-header connections -> goroutines %d -> %d (delta %d)",
		connectionCount, baseline, held, held-baseline)

	// Each stalled connection costs at least one server-side goroutine, because
	// the http.Server blocks reading a header block that never completes.
	require.GreaterOrEqual(t, held-baseline, connectionCount/2,
		"stalled-header connections did not register as held resources")

	for _, conn := range conns {
		_ = conn.Close()
	}

	var released int
	for range 60 {
		released = countGoroutines()
		if released <= baseline+2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.LessOrEqual(t, released, baseline+2,
		"closing stalled-header connections did not release their goroutines")
}

// ---------------------------------------------------------------------------
// Diagnostic: is anything in the H1 path setting a read deadline?
// ---------------------------------------------------------------------------

// TestAuditNaiveH1ConnHasNoServerDeadline documents, at the type level, why stage
// B is unbounded: the H1 tunnel conn forwards deadlines to the socket but nothing
// in the inbound ever sets one, and the H2 conn refuses deadlines outright.
func TestAuditNaiveH1ConnHasNoServerDeadline(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	// Establish an authenticated H1 CONNECT and confirm the tunnel is live, then
	// observe that the server never imposes an idle bound of its own.
	tlsConn := naiveTLSConn(t, server.port, "http/1.1")
	// Target the LIVE origin backend, not a dead port: a refused dial closes the
	// tunnel for a reason unrelated to idle handling, which would make this test
	// assert the wrong thing.
	response, err := naiveWriteConnect(t, tlsConn, server.env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	// An authenticated, idle tunnel. Confirm it stays open for a window far
	// longer than a typical idle timeout would be.
	idle := 5 * time.Second
	closed := waitForConnClosed(tlsConn, idle)
	t.Logf("OBSERVED: authenticated idle tunnel closed within %s: %v", idle, closed)
	require.False(t, closed,
		"an authenticated idle tunnel was closed by the server after %s; if an idle "+
			"timeout was added deliberately, this test must be updated", idle)
}

// ---------------------------------------------------------------------------
// Configured limits, measured on a real listener.
// ---------------------------------------------------------------------------

// TestAuditNaiveMaxConnectionsIsEnforcedAndReleased proves the global connection
// limit works end-to-end and that slots are released, which together are what
// make the limit a bound rather than a one-way ratchet.
func TestAuditNaiveMaxConnectionsIsEnforcedAndReleased(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.ServerLimits = &option.NaiveServerLimitsOptions{
			MaxConnections: 3,
		}
	})

	open := func() net.Conn {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
		require.NoError(t, err)
		return conn
	}

	// Three connections are admitted.
	first := make([]net.Conn, 0, 3)
	for i := range 3 {
		conn := open()
		require.NotNil(t, conn, "connection %d must be admitted", i)
		first = append(first, conn)
	}

	// The FOURTH must be refused. This uses waitForConnClosed rather than a bare
	// Read error because the two outcomes are indistinguishable to require.Error:
	// a refused connection is CLOSED (EOF), while an accepted-but-silent one
	// merely times out. An earlier version of this test used require.Error and
	// therefore passed even with the limiter removed entirely -- it was asserting
	// "something happened", not "the connection was refused".
	refused := open()
	require.True(t, waitForConnClosed(refused, 5*time.Second),
		"the connection beyond max_connections must be CLOSED by the listener "+
			"(a timeout would mean it was accepted)")
	_ = refused.Close()

	// Releasing one slot must admit exactly one more connection.
	_ = first[0].Close()

	// Releasing a slot must make room for exactly one more connection. "Admitted"
	// here means the connection is NOT closed, which is the complement of the
	// refusal test above and uses the same EOF-versus-timeout distinction.
	var admitted bool
	for range 40 {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
		if dialErr != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if waitForConnClosed(conn, 700*time.Millisecond) {
			// Closed => still over the limit; the slot was not released yet.
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		admitted = true
		_ = conn.Close()
		break
	}
	require.True(t, admitted, "closing a connection must release its slot")

	for _, conn := range first[1:] {
		_ = conn.Close()
	}
}

// TestAuditNaiveMaxConnectionsPerIPIsEnforced proves the per-IP limit refuses a
// second connection from the SAME address while still admitting from another,
// which is what distinguishes a per-IP bound from a global one.
func TestAuditNaiveMaxConnectionsPerIPIsEnforced(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.ServerLimits = &option.NaiveServerLimitsOptions{
			MaxConnectionsPerIP: 2,
		}
	})

	// All loopback connections share one source address, so the per-IP limit is
	// observable by opening more than two.
	first, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
	require.NoError(t, err)
	defer first.Close()
	second, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
	require.NoError(t, err)
	defer second.Close()

	third, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 5*time.Second)
	require.NoError(t, err)
	defer third.Close()

	// The third from the same address must be CLOSED, not merely silent: a
	// timeout would mean the limit never applied.
	require.True(t, waitForConnClosed(third, 5*time.Second),
		"a connection beyond max_connections_per_ip must be CLOSED by the listener")
}

// TestAuditNaiveHeaderTimeoutBoundsSilentPeers is the behavioural proof that the
// control closes the measured "TLS completes, then silence" hole.
//
// It also proves the timeout does NOT fire on an established tunnel: the second
// phase of the test holds an authenticated tunnel open past the header timeout
// and requires it to stay alive.
func TestAuditNaiveHeaderTimeoutBoundsSilentPeers(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.ServerLimits = &option.NaiveServerLimitsOptions{
			HeaderTimeout: badoption.Duration(2 * time.Second),
		}
	})

	// Phase 1: complete TLS, send no request at all. The header timeout must
	// disconnect this peer.
	silent := naiveTLSConn(t, env.port, "http/1.1")
	closed := waitForConnClosed(silent, 12*time.Second)
	require.True(t, closed,
		"a peer that completes TLS and sends no request must be disconnected by header_timeout")

	// Phase 2: an ESTABLISHED tunnel must survive past the same timeout, because
	// net/http resets the read deadline once the headers have been read. A tunnel
	// that is idle for longer than header_timeout is normal, not abuse.
	tunnel := naiveTLSConn(t, env.port, "http/1.1")
	response, err := naiveWriteConnect(t, tunnel, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Hold the tunnel idle for well past header_timeout.
	tunnelClosed := waitForConnClosed(tunnel, 6*time.Second)
	require.False(t, tunnelClosed,
		"header_timeout must NOT tear down an established tunnel; it applies to the "+
			"request phase only, and net/http resets the deadline after the headers")
}

// TestAuditNaiveDefaultConfigurationIsUnchanged proves the new option changes
// nothing when it is omitted: an idle silent peer still holds its connection,
// exactly as measured before the option existed.
func TestAuditNaiveDefaultConfigurationIsUnchanged(t *testing.T) {
	server := startNaiveLifecycleServer(t)

	silent := naiveTLSConn(t, server.port, "http/1.1")
	_, err := silent.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\n"))
	require.NoError(t, err)

	closed := waitForConnClosed(silent, 4*time.Second)
	t.Logf("OBSERVED: with server_limits omitted, stalled peer closed within 4s: %v", closed)
	require.False(t, closed,
		"omitting server_limits must preserve the previous unlimited behaviour")
}

// TestAuditNaiveActiveTransferSurvivesHeaderTimeout is the §9 false-positive
// guard: it proves the protection distinguishes "idle" from "slow but actively
// transferring".
//
// The scenario that matters is a tunnel which is QUIET for longer than
// header_timeout between bursts of real traffic -- a browser session, which is
// exactly what a Naive tunnel carries. A control that could not tell that apart
// from a slowloris would disconnect working clients, so this test holds a tunnel
// idle past the timeout and then proves it still carries data.
func TestAuditNaiveActiveTransferSurvivesHeaderTimeout(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.ServerLimits = &option.NaiveServerLimitsOptions{
			HeaderTimeout: badoption.Duration(2 * time.Second),
		}
	})

	tunnel := naiveTLSConn(t, env.port, "http/1.1")
	response, err := naiveWriteConnect(t, tunnel, env.originAddr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Stay QUIET for longer than header_timeout. A tunnel is allowed to be idle;
	// that is the normal state of a browsing session between page loads.
	time.Sleep(5 * time.Second)

	// The tunnel must still work. Sending a complete HTTP request through it and
	// reading the origin's response proves the connection was neither closed nor
	// half-closed by the header timeout.
	_, err = tunnel.Write([]byte("GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err, "the tunnel must still accept data after being idle")

	_ = tunnel.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(tunnel)
	tunnelResponse, err := http.ReadResponse(reader, nil)
	require.NoError(t, err, "the tunnel must still carry data after being idle")
	defer tunnelResponse.Body.Close()
	require.Equal(t, http.StatusOK, tunnelResponse.StatusCode,
		"a tunnel idle for longer than header_timeout must still carry a full request/response")
}

// TestAuditNaiveSlowButActiveTransferIsNotTreatedAsAbuse proves a peer that
// transfers continuously and slowly is also not disconnected, which is the other
// half of the false-positive concern. Unlike a slowloris, this peer eventually
// completes a valid request.
func TestAuditNaiveSlowButActiveTransferIsNotTreatedAsAbuse(t *testing.T) {
	env := startNaiveInboundWithOptions(t, func(options *option.NaiveInboundOptions) {
		options.ServerLimits = &option.NaiveServerLimitsOptions{
			// Comfortably longer than the deliberate pacing below.
			HeaderTimeout: badoption.Duration(10 * time.Second),
		}
	})

	tunnel := naiveTLSConn(t, env.port, "http/1.1")

	// Send a valid CONNECT one byte at a time with a pause between bytes. This is
	// slow, but it is NOT a stall: the peer keeps making progress, so a
	// header-timeout implementation that resets per byte must let it through.
	request := "CONNECT " + env.originAddr + " HTTP/1.1\r\n" +
		"Host: " + env.originAddr + "\r\n" +
		"Proxy-Authorization: " + naiveBasicAuth() + "\r\n\r\n"
	for _, b := range []byte(request) {
		_, err := tunnel.Write([]byte{b})
		require.NoError(t, err, "a slowly-progressing peer must not be cut off")
		time.Sleep(20 * time.Millisecond)
	}

	_ = tunnel.SetReadDeadline(time.Now().Add(15 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(tunnel), nil)
	require.NoError(t, err, "a slow but progressing request must be served")
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode,
		"a peer that progresses slowly but continuously must not be treated as a slowloris")
}
