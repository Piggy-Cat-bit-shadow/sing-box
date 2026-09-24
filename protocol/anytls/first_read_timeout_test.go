package anytls

import (
	"context"
	stdTLS "crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

// These tests pin the one-shot pre-authentication read timeout that closes the
// "TLS handshake complete, then silence" resource hold.
//
// Every test uses a real net.Pipe, wrapped in a minimal tls.Conn stand-in, so the
// behaviour under test is genuine socket deadline behaviour rather than a mock's
// bookkeeping. The timeout is deliberately short here; production uses
// C.TCPTimeout (15s).

// plainTLSConn is a minimal tls.Conn over a real net.Conn. The TLS methods are
// inert: these tests exercise the read-deadline path, not the handshake.
type plainTLSConn struct {
	net.Conn
}

func (c *plainTLSConn) NetConn() net.Conn                      { return c.Conn }
func (c *plainTLSConn) HandshakeContext(context.Context) error { return nil }
func (c *plainTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

var _ stdTLS.ConnectionState = tls.ConnectionState{}

// newWrappedPipe returns a connected pair with the server end wrapped by the
// one-shot timeout, plus the wrapper itself for state assertions.
func newWrappedPipe(t *testing.T, timeout time.Duration) (net.Conn, net.Conn, *firstReadTimeoutConn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	wrapped := newFirstReadTimeoutConn(&plainTLSConn{Conn: server}, timeout)
	underlying, ok := wrapped.(*firstReadTimeoutConn)
	require.True(t, ok, "with a positive timeout the connection must be wrapped")
	return client, wrapped, underlying
}

// TestFirstReadTimeoutWrapperKeepsTLSInterface is the regression guard for a real
// bug found while writing this fix: hiding the tls.Conn behind a bare net.Conn
// broke fallback_for_alpn routing, because protocol/anytls type-asserts the
// connection to tls.Conn to read NegotiatedProtocol. Every client silently
// landed on the default backend instead of its ALPN-specific one.
func TestFirstReadTimeoutWrapperKeepsTLSInterface(t *testing.T) {
	_, wrapped, _ := newWrappedPipe(t, time.Second)

	_, isTLSConn := wrapped.(tls.Conn)
	require.True(t, isTLSConn,
		"the wrapper must keep the tls.Conn interface, or fallback_for_alpn "+
			"routing breaks and every client goes to the default backend")
}

// TestFirstReadTimeoutClosesSilentPeer is case A at unit level: the peer sends
// nothing, so the first read must time out rather than block forever.
func TestFirstReadTimeoutClosesSilentPeer(t *testing.T) {
	_, wrapped, _ := newWrappedPipe(t, 200*time.Millisecond)

	readErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 16)
		_, err := wrapped.Read(buffer)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		require.Error(t, err, "a silent peer must hit the pre-auth read deadline")
		var netErr net.Error
		require.True(t, errors.As(err, &netErr), "expected a net.Error, got %T", err)
		require.True(t, netErr.Timeout(), "the error must be a timeout, got %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the first read never timed out; a silent peer would hold the connection forever")
	}
}

// TestFirstReadTimeoutClearedAfterFirstByte is case B: once any application data
// arrives the deadline is cleared, so a subsequently silent-but-legitimate
// session is no longer governed by the pre-authentication budget.
func TestFirstReadTimeoutClearedAfterFirstByte(t *testing.T) {
	client, wrapped, underlying := newWrappedPipe(t, 150*time.Millisecond)
	require.True(t, underlying.firstReadDeadlineArmed(), "the deadline must start armed")

	go func() {
		_, _ = client.Write([]byte("first application bytes"))
	}()

	buffer := make([]byte, 64)
	n, err := wrapped.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, len("first application bytes"), n)
	require.False(t, underlying.firstReadDeadlineArmed(),
		"the one-shot deadline must be retired after the first read")

	// Observable proof: a second read that stays silent well past the original
	// timeout must now block instead of returning a timeout error.
	blocked := make(chan error, 1)
	go func() {
		late := make([]byte, 8)
		_, readErr := wrapped.Read(late)
		blocked <- readErr
	}()
	select {
	case err := <-blocked:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("a read after the first byte must not be governed by the pre-auth "+
				"timeout, but it timed out: %v", err)
		}
	case <-time.After(3 * 150 * time.Millisecond):
		// Still blocked, as intended: the one-shot deadline is gone.
	}
}

// TestFirstReadTimeoutClearedOnPartialReadWithError is the n>0 && err!=nil case:
// a partial read with an error still proves the peer sent application data, so
// that peer must not then be punished with the pre-authentication timeout.
func TestFirstReadTimeoutClearedOnPartialReadWithError(t *testing.T) {
	client, wrapped, underlying := newWrappedPipe(t, 2*time.Second)

	go func() {
		_, _ = client.Write([]byte("hi"))
		_ = client.Close()
	}()

	buffer := make([]byte, 64)
	n, _ := wrapped.Read(buffer)
	require.Equal(t, 2, n, "data written before the close must be observed")

	require.False(t, underlying.firstReadDeadlineArmed(),
		"a partial read with an error still proves the peer sent data, so the "+
			"pre-auth deadline must be cleared")
}

// TestFirstReadTimeoutDisabledWhenZero proves a non-positive timeout leaves the
// connection untouched, so the wrapper can never impose an unconfigured timeout.
func TestFirstReadTimeoutDisabledWhenZero(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	inner := &plainTLSConn{Conn: server}
	wrapped := newFirstReadTimeoutConn(inner, 0)
	require.Same(t, inner, wrapped, "a zero timeout must return the raw connection")
}

// TestFirstReadTimeoutIsTransparent checks the wrapper does not perturb the
// addresses or the write path, since it is handed to sing-anytls and then to the
// fallback router.
func TestFirstReadTimeoutIsTransparent(t *testing.T) {
	client, wrapped, _ := newWrappedPipe(t, time.Second)

	require.NotNil(t, wrapped.LocalAddr())
	require.NotNil(t, wrapped.RemoteAddr())

	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 4)
		_, _ = client.Read(buffer)
		received <- string(buffer)
	}()
	written, err := wrapped.Write([]byte("ping"))
	require.NoError(t, err)
	require.Equal(t, 4, written)
	require.Equal(t, "ping", <-received)

	require.NoError(t, wrapped.SetWriteDeadline(time.Now().Add(time.Second)))
	require.NoError(t, wrapped.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, wrapped.SetReadDeadline(time.Time{}))
	require.NoError(t, wrapped.Close())
}

// TestFirstReadTimeoutConcurrentClearAndRead is the race guard: the one-shot
// clear and the read path must not race on the wrapper state.
func TestFirstReadTimeoutConcurrentClearAndRead(t *testing.T) {
	client, wrapped, underlying := newWrappedPipe(t, 2*time.Second)

	go func() {
		for range 64 {
			_, _ = client.Write([]byte("x"))
			time.Sleep(time.Millisecond)
		}
		_ = client.Close()
	}()

	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			buffer := make([]byte, 8)
			for range 16 {
				if _, err := wrapped.Read(buffer); err != nil {
					return
				}
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		for range 64 {
			underlying.clearDeadlineOnce()
		}
	}()
	group.Wait()
	require.False(t, underlying.firstReadDeadlineArmed())
}

// TestFirstReadTimeoutUsesTCPTimeoutBudget documents that the production budget
// is the existing pre-authentication constant rather than a new option.
func TestFirstReadTimeoutUsesTCPTimeoutBudget(t *testing.T) {
	require.Equal(t, 15*time.Second, defaultPreAuthTimeout(),
		"the pre-auth read budget must be the existing C.TCPTimeout, not a new knob")
}
