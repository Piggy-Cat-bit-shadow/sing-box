package jiejie_test

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// These tests are about RESOURCE LIFECYCLE, not protocol correctness.
//
// The failure they exist to prevent is the one seen in production with the Caddy
// forwardproxy fork: UDP sockets accumulating over a day of use until hundreds
// of high-numbered ports were held open, worked around by adding explicit
// close handling. The acceptance criterion is not "zero sockets" -- an active
// UDP session legitimately needs one -- but "a FINISHED session must not keep
// accumulating resources".
//
// Socket counting is done by reading /proc/self/fd on Linux, where the CI runs.
// On other platforms the count is unavailable and the test says so rather than
// passing vacuously.

// countOpenUDPFDs counts this process's open UDP socket file descriptors.
//
// It returns ok=false when the platform does not expose /proc/self/fd, so a
// caller can distinguish "no leak" from "could not tell".
func countOpenUDPFDs(t *testing.T) (int, bool) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	count := 0
	for _, entry := range entries {
		target, readErr := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if readErr != nil {
			continue
		}
		// A UDP socket shows up as "socket:[NNNN]" and can be classified by
		// reading /proc/self/net/udp, but that is racy. Instead compare the
		// total socket count around the workload: TCP tunnels are closed too, so
		// a UDP-specific leak still shows up as growth.
		if strings.HasPrefix(target, "socket:[") {
			count++
		}
	}
	return count, true
}

// skipIfNoFDCounting skips on platforms without /proc.
func skipIfNoFDCounting(t *testing.T) {
	t.Helper()
	if _, ok := countOpenUDPFDs(t); !ok {
		t.Skip("cannot count file descriptors on this platform (no /proc/self/fd); " +
			"the leak assertions are not verified here")
	}
}

// shortLivedUoTSession opens one UoT session, exchanges one datagram and closes.
func shortLivedUoTSession(port uint16, echoAddr string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	if err = tlsConn.Handshake(); err != nil {
		return err
	}
	if err = tlsConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}

	magic := uot.RequestDestination(uot.Version).String()
	tunnelReader, err := writeConnectWithoutT(tlsConn, magic)
	if err != nil {
		return err
	}

	addressBytes, err := encodeV2RequestAddrForGoroutine(metadata.ParseSocksaddr(echoAddr))
	if err != nil {
		return err
	}
	if _, err = tlsConn.Write(naivePaddingFrame(append([]byte{1}, addressBytes...), 0)); err != nil {
		return err
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	if _, err = tlsConn.Write(naivePaddingFrame(append(length, payload...), 0)); err != nil {
		return err
	}

	frameHeader := make([]byte, 3)
	if _, err = io.ReadFull(tunnelReader, frameHeader); err != nil {
		return err
	}
	frameData := make([]byte, int(frameHeader[0])<<8|int(frameHeader[1]))
	if _, err = io.ReadFull(tunnelReader, frameData); err != nil {
		return err
	}
	if framePaddingSize := int(frameHeader[2]); framePaddingSize > 0 {
		if _, err = io.ReadFull(tunnelReader, make([]byte, framePaddingSize)); err != nil {
			return err
		}
	}
	if len(frameData) < 2 || string(frameData[2:]) != string(payload) {
		return errors.New("echo mismatch")
	}
	return nil
}

// TestJiejieNaiveUoTSocketsDoNotAccumulate is the direct regression test for the
// production socket leak.
//
// It runs many SHORT-LIVED UoT sessions and then checks that the process's open
// socket count returned to roughly where it started. A finished session must not
// leave a socket behind.
func TestJiejieNaiveUoTSocketsDoNotAccumulate(t *testing.T) {
	skipIfNoFDCounting(t)

	env := startNaiveInboundForUoT(t)

	// Warm up so one-time allocations (listeners, TLS state, DNS) do not count
	// as growth.
	const warmup = 5
	for index := range warmup {
		require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr,
			[]byte("warmup-"+strconv.Itoa(index))))
	}
	waitForFDStabilisation(t)

	before, _ := countOpenUDPFDs(t)

	const sessions = 60
	for index := range sessions {
		require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr,
			[]byte("session-"+strconv.Itoa(index))),
			"short-lived UoT session %d must complete", index)
	}

	// Sockets are closed asynchronously by the runtime and the peer, so allow a
	// bounded settling period before asserting.
	waitForFDStabilisation(t)
	after, _ := countOpenUDPFDs(t)

	growth := after - before
	t.Logf("open sockets before=%d after=%d growth=%d over %d short-lived sessions",
		before, after, growth, sessions)

	// Every session is finished by the time this runs, so the socket count must
	// not have grown with the number of sessions. A small slack covers runtime
	// bookkeeping and a few lingering TIME_WAIT-adjacent descriptors.
	const allowedSlack = 10
	require.LessOrEqual(t, growth, allowedSlack,
		"finished UoT sessions must not accumulate sockets: %d sessions left %d extra "+
			"descriptors open", sessions, growth)
}

// TestJiejieNaiveUoTGoroutinesDoNotAccumulate proves finished sessions do not
// leak goroutines, which is the other half of the production symptom.
func TestJiejieNaiveUoTGoroutinesDoNotAccumulate(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	for index := range 5 {
		require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr,
			[]byte("warm-"+strconv.Itoa(index))))
	}
	waitForGoroutineStabilisation(t)
	before := runtime.NumGoroutine()

	const sessions = 40
	for index := range sessions {
		require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr,
			[]byte("g-"+strconv.Itoa(index))))
	}
	waitForGoroutineStabilisation(t)
	after := runtime.NumGoroutine()

	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d sessions",
		before, after, growth, sessions)

	// Two goroutines per session would be 80; anything close to that means the
	// relay loops are not exiting.
	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"finished UoT sessions must not accumulate goroutines: %d sessions left %d "+
			"extra goroutines", sessions, growth)
}

// TestJiejieNaiveClientDisconnectReleasesSession proves an abrupt client
// disconnect (no orderly close) still releases the session.
func TestJiejieNaiveClientDisconnectReleasesSession(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	for index := range 5 {
		require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr,
			[]byte("warm-"+strconv.Itoa(index))))
	}
	waitForGoroutineStabilisation(t)
	before := runtime.NumGoroutine()

	// Open sessions and drop them hard: set linger 0 so the peer sees a reset
	// rather than a FIN, which is the harsher of the two disconnect shapes.
	const abrupt = 30
	for range abrupt {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
		require.NoError(t, err)
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
		if err = tlsConn.Handshake(); err != nil {
			conn.Close()
			continue
		}
		_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err = writeConnectWithoutT(tlsConn, uot.RequestDestination(uot.Version).String()); err != nil {
			if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
				_ = tcpConn.SetLinger(0)
			}
			conn.Close()
			continue
		}
		if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
	}

	waitForGoroutineStabilisation(t)
	after := runtime.NumGoroutine()
	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d abrupt disconnects",
		before, after, growth, abrupt)

	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"abrupt client disconnects must not accumulate goroutines: %d disconnects left "+
			"%d extra goroutines", abrupt, growth)
}

// TestJiejieNaiveUoTFailedAuthDoesNotLeak proves failed authentication does not
// consume resources.
func TestJiejieNaiveUoTFailedAuthDoesNotLeak(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	waitForGoroutineStabilisation(t)
	before := runtime.NumGoroutine()

	const attempts = 40
	for range attempts {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
		require.NoError(t, err)
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
		if err = tlsConn.Handshake(); err != nil {
			conn.Close()
			continue
		}
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		request := "CONNECT " + uot.RequestDestination(uot.Version).String() + " HTTP/1.1\r\n" +
			"Host: example.test\r\n" +
			"Proxy-Authorization: Basic " + wrongBasicAuth() + "\r\n\r\n"
		_, _ = io.WriteString(tlsConn, request)
		_, _ = io.ReadAll(tlsConn)
		conn.Close()
	}

	waitForGoroutineStabilisation(t)
	after := runtime.NumGoroutine()
	growth := after - before
	t.Logf("goroutines before=%d after=%d growth=%d over %d failed auths",
		before, after, growth, attempts)

	const allowedSlack = 20
	require.LessOrEqual(t, growth, allowedSlack,
		"failed authentication must not accumulate goroutines: %d attempts left %d extra",
		attempts, growth)
}

// wrongBasicAuth is a well-formed but incorrect credential.
func wrongBasicAuth() string {
	return "Basic " + "bmFpdmUtdXNlcjp3cm9uZy1wYXNzd29yZA==" // naive-user:wrong-password
}

// waitForFDStabilisation waits until the open-descriptor count stops falling.
func waitForFDStabilisation(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	previous := -1
	stable := 0
	for time.Now().Before(deadline) {
		current, ok := countOpenUDPFDs(t)
		if !ok {
			return
		}
		if current == previous {
			stable++
			if stable >= 3 {
				return
			}
		} else {
			stable = 0
			previous = current
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForGoroutineStabilisation waits until the goroutine count stops falling.
func waitForGoroutineStabilisation(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	previous := -1
	stable := 0
	for time.Now().Before(deadline) {
		current := runtime.NumGoroutine()
		if current == previous {
			stable++
			if stable >= 5 {
				return
			}
		} else {
			stable = 0
			previous = current
		}
		time.Sleep(100 * time.Millisecond)
	}
}
