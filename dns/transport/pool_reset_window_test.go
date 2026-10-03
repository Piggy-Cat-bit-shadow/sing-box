package transport

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Tests for what a query started DURING a Reset observes.
//
// # The window being tested
//
// ResetNetwork advances the network generation and then resets the transports, so there is a real
// interval in which the generation is already the new one while a pool still holds state belonging to
// the previous network. A query issued inside that interval must not come away with a connection
// from the old network.
//
// The pool guards this in three independent places - the per-state cancel context that aborts an
// in-flight dial, the `closed` recheck, and the `state != current` check that discards a connection
// dialled against a state the reset has replaced. The second and third are reachable by a caller and
// are driven here.

// dialingPool is a pool whose dial blocks until the test releases it.
type dialingPool struct {
	pool    *ConnPool[*net.TCPConn]
	dialed  atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func newDialingPool(t *testing.T) *dialingPool {
	t.Helper()
	harness := &dialingPool{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	harness.pool = NewConnPool(ConnPoolOptions[*net.TCPConn]{
		Mode: ConnPoolOrdered,
		IsAlive: func(conn *net.TCPConn) bool {
			return conn != nil
		},
		Close: func(conn *net.TCPConn, cause error) {
			if conn != nil {
				conn.Close()
			}
		},
	})
	return harness
}

// dial is the dial function handed to Acquire. It parks until released.
func (h *dialingPool) dial(ctx context.Context) (*net.TCPConn, error) {
	h.dialed.Add(1)
	select {
	case h.entered <- struct{}{}:
	default:
	}
	select {
	case <-h.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return h.pair()
}

// pair returns a connected client socket over a throwaway listener.
//
// It takes no *testing.T: the dial function has no access to one. The listener is closed on return
// and the accepted socket is closed alongside its peer.
func (h *dialingPool) pair() (*net.TCPConn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	select {
	case server := <-accepted:
		go func() {
			// Mirror the client's lifetime without holding the test open.
			<-time.After(30 * time.Second)
			server.Close()
		}()
	case <-time.After(5 * time.Second):
		conn.Close()
		return nil, errDialTimeout
	}
	return conn.(*net.TCPConn), nil
}

// errDialTimeout reports that the loopback helper could not complete.
var errDialTimeout = errors.New("loopback pair was never accepted")

// TestDialStartedBeforeResetIsNotHandedOut is item 2.
//
// A dial is held in flight, the pool is reset, and only then is the dial allowed to finish. The
// connection it produced was dialled against the state the reset replaced, so it belongs to the old
// network and must not be handed to the caller as a usable connection for the new one.
//
// # Why two guards are needed to reproduce a failure
//
// The pool refuses this connection twice over, independently:
//
//	Reset cancels the replaced state's context, and the dial runs under that context, so an
//	in-flight dial is aborted before it can even produce a connection;
//
//	and if it produces one anyway - a dial that ignores its context, or one that completed in the
//	instant before cancellation - the install path compares the captured state against the live
//	one and discards the result.
//
// Disabling either alone still holds, which is the point: the guarantee does not depend on the
// context being honoured. Both have to be removed before the stale connection is handed out.
func TestDialStartedBeforeResetIsNotHandedOut(t *testing.T) {
	harness := newDialingPool(t)

	type acquireResult struct {
		conn *net.TCPConn
		err  error
	}
	result := make(chan acquireResult, 1)
	go func() {
		conn, _, err := harness.pool.Acquire(context.Background(), harness.dial)
		result <- acquireResult{conn, err}
	}()

	// Barrier: the dial is genuinely in flight against the pre-reset state.
	select {
	case <-harness.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never started")
	}

	// The network change, as ResetNetwork performs it.
	harness.pool.Reset()

	// Now let the dial complete.
	close(harness.release)

	select {
	case acquired := <-result:
		if acquired.err == nil && acquired.conn != nil {
			t.Fatal("a connection dialled against the pre-reset pool state was handed to the caller " +
				"after the reset. The new network would send its first query down the old network's " +
				"socket, which is exactly the reuse a reset must prevent")
		}
		require.Error(t, acquired.err,
			"the acquire must fail rather than succeed on a connection from a replaced state")
	case <-time.After(10 * time.Second):
		t.Fatal("the acquire never returned after the dial was released")
	}
}

// TestIdleConnectionIsNotReusedAfterReset is the idle half of item 2.
//
// A reset must make previously pooled connections unusable, so the next query dials instead of
// reusing a socket the old network owns.
func TestIdleConnectionIsNotReusedAfterReset(t *testing.T) {
	var dials atomic.Int32

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	// Accepted sockets are closed when the listener closes, which the cleanup above performs, so the
	// accept loop only has to drain until Accept fails.
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	pool := NewConnPool(ConnPoolOptions[*net.TCPConn]{
		Mode: ConnPoolOrdered,
		IsAlive: func(conn *net.TCPConn) bool {
			return conn != nil
		},
		Close: func(conn *net.TCPConn, cause error) {
			if conn != nil {
				conn.Close()
			}
		},
	})

	dial := func(ctx context.Context) (*net.TCPConn, error) {
		dials.Add(1)
		var dialer net.Dialer
		conn, dialErr := dialer.DialContext(ctx, "tcp", listener.Addr().String())
		if dialErr != nil {
			return nil, dialErr
		}
		return conn.(*net.TCPConn), nil
	}

	// One query, released back for reuse, so a connection is parked as idle.
	first, _, err := pool.Acquire(context.Background(), dial)
	require.NoError(t, err)
	require.NotNil(t, first)
	pool.Release(first, true)
	require.EqualValues(t, 1, dials.Load(), "the first acquire dialled")

	// The network changes.
	pool.Reset()

	second, _, err := pool.Acquire(context.Background(), dial)
	require.NoError(t, err)
	require.NotNil(t, second)
	require.NotSame(t, first, second,
		"the reset handed back the connection that was parked before it. That socket belongs to the "+
			"previous network, so the new network's query would travel over it")
	require.EqualValues(t, 2, dials.Load(),
		"the post-reset acquire must dial rather than reuse the pre-reset idle connection")

	pool.Release(second, true)
}

// TestReleaseOfAConnectionFromAReplacedStateIsNotPooled is the release half.
//
// A query that was in flight across a reset finishes holding a connection from the replaced state.
// Returning it to the pool would reintroduce exactly what the reset removed.
func TestReleaseOfAConnectionFromAReplacedStateIsNotPooled(t *testing.T) {
	var dials atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	pool := NewConnPool(ConnPoolOptions[*net.TCPConn]{
		Mode: ConnPoolOrdered,
		IsAlive: func(conn *net.TCPConn) bool {
			return conn != nil
		},
		Close: func(conn *net.TCPConn, cause error) {
			if conn != nil {
				conn.Close()
			}
		},
	})

	dial := func(ctx context.Context) (*net.TCPConn, error) {
		dials.Add(1)
		var dialer net.Dialer
		conn, dialErr := dialer.DialContext(ctx, "tcp", listener.Addr().String())
		if dialErr != nil {
			return nil, dialErr
		}
		return conn.(*net.TCPConn), nil
	}

	// A query that started before the reset.
	conn, _, err := pool.Acquire(context.Background(), dial)
	require.NoError(t, err)

	// The network changes while that query is still using its connection.
	pool.Reset()

	// The query finishes and tries to return the connection for reuse.
	pool.Release(conn, true)

	// The next query must dial, because the released connection belonged to the replaced state and
	// was therefore dropped rather than pooled.
	dialsBefore := dials.Load()
	next, _, err := pool.Acquire(context.Background(), dial)
	require.NoError(t, err)
	require.NotNil(t, next)
	require.Greater(t, dials.Load(), dialsBefore,
		"a connection from the replaced state was retained and handed to the next query, so the new "+
			"network reused the old network's socket")
	pool.Release(next, true)
}
