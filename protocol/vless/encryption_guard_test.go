package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/vless/encryption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The encryption handshake ends in a blocking io.ReadFull for the server's
// reply. A node that accepts the connection and then says nothing parks that
// read forever, and nothing above can intervene: the conn has not been handed
// up yet, the caller is still inside DialContext. guardHandshake closes the
// conn when the dial context dies, which is the only lever that reaches a
// parked read; these tests drive that path with a fake conn, no network.

// testDeadline fails the test if it is still running after d, so a regression
// that reintroduces an unbounded wait fails in seconds instead of hanging
// until the go test timeout.
func testDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	timer := time.AfterFunc(d, func() {
		panic(fmt.Sprintf("%s exceeded its %v deadline: an unbounded wait is back", t.Name(), d))
	})
	t.Cleanup(func() { timer.Stop() })
}

// newTestEncryption builds a real, initialized ClientInstance. An uninitialized
// one is useless here: its Handshake returns "uninitialized" immediately, so the
// handshake never reaches the blocking read these tests are about, and every
// assertion would pass for the wrong reason.
func newTestEncryption(t *testing.T) *encryption.ClientInstance {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	instance := &encryption.ClientInstance{}
	require.NoError(t, instance.Init([][]byte{key.PublicKey().Bytes()}, xorModeNative, 0, ""))
	return instance
}

// silentConn accepts every write and blocks every read until closed, which is
// what a half-alive node looks like from the client: the TCP handshake
// succeeded, so the dial completed, and the peer then produces nothing.
type silentConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	closes    atomic.Int32
}

func newSilentConn() *silentConn {
	return &silentConn{closed: make(chan struct{})}
}

func (c *silentConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *silentConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *silentConn) Close() error {
	c.closes.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *silentConn) SetDeadline(t time.Time) error      { return nil }
func (c *silentConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *silentConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *silentConn) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (c *silentConn) RemoteAddr() net.Addr               { return M.Socksaddr{} }

// A cancelled dial context must end the handshake instead of leaving the
// goroutine parked in the read — the zombie that outlived a full box
// restart, because the dial context was the only handle on the conn and
// nobody was listening to it once the dial had returned.
func TestWrapEncryptionAbortsHandshakeOnContextCancel(t *testing.T) {
	testDeadline(t, 10*time.Second)

	dialer := &vlessDialer{encryption: newTestEncryption(t)}
	conn := newSilentConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	returned := make(chan error, 1)
	go func() {
		_, err := dialer.wrapEncryption(ctx, conn)
		returned <- err
	}()

	// Let the handshake write its padding and reach the read it cannot escape.
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-returned:
		t.Fatalf("handshake returned before the context was cancelled: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-returned:
		require.Error(t, err, "wrapEncryption reported success although the guard aborted the handshake")
	case <-time.After(5 * time.Second):
		t.Fatal("wrapEncryption stayed parked in the handshake read after the dial context was cancelled — " +
			"this is the zombie that outlives box.Close")
	}
	require.NotZero(t, conn.closes.Load(),
		"the guard did not close the conn; closing it is the only lever that reaches a parked read")
}

// The guard must not outlive the handshake. A pooled consumer (the DNS
// transport pool) cancels the dial context the moment DialContext returns, by
// the net.Dialer contract — a guard still listening then would close a healthy
// conn, which is the regression the XHTTP dial-context contract removed the
// transport-level watchdog for (transport/v2rayxhttp/dial_ctx_contract_test.go).
func TestWrapEncryptionGuardStopsBeforeReturn(t *testing.T) {
	testDeadline(t, 10*time.Second)

	dialer := &vlessDialer{encryption: newTestEncryption(t)}
	conn := newSilentConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The handshake fails on its own: closing the conn up front makes the read
	// return immediately, so wrapEncryption returns while the context is still live.
	conn.Close()
	closesAfterSetup := conn.closes.Load()
	_, err := dialer.wrapEncryption(ctx, conn)
	require.Error(t, err, "expected the handshake to fail on a closed conn")

	cancel()
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, closesAfterSetup+1, conn.closes.Load(),
		"the conn was closed again after wrapEncryption returned: the guard outlived the handshake "+
			"and would break every pooled consumer")
}

// A context that can never be cancelled needs no guard goroutine, and the
// handshake must still work.
func TestWrapEncryptionWithoutCancellableContextRunsNoGuard(t *testing.T) {
	testDeadline(t, 10*time.Second)

	dialer := &vlessDialer{encryption: newTestEncryption(t)}
	conn := newSilentConn()
	conn.Close()

	before := runtime.NumGoroutine()
	_, err := dialer.wrapEncryption(context.Background(), conn)
	require.Error(t, err, "expected the handshake to fail on a closed conn")

	// NumGoroutine is noisy (GC workers), so let it settle before failing; a
	// guard goroutine blocked on a nil Done channel would never settle.
	settle := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(settle) {
		time.Sleep(10 * time.Millisecond)
	}
	require.LessOrEqual(t, runtime.NumGoroutine(), before,
		"guard goroutine started for an uncancellable context")
}
