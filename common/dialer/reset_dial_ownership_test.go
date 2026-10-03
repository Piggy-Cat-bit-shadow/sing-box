package dialer

import (
	"context"
	"github.com/sagernet/sing/common/control"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Whether a dial that was already in flight when the network reset can still become the connection
// the caller uses.
//
// # The timing this turns on
//
// DefaultDialer registers a finished connection with the connection manager only AFTER the dial
// returns:
//
//	conn, err := dial(...)
//	return d.trackConn(ctx, address, conn, err)     // TrackConn happens here
//
// and the reset closes only what is already registered:
//
//	func (m *ConnectionManager) CloseAll() {
//	    // walks m.connections, which holds only TRACKED connections
//	}
//
// A dial that started before the reset and has not yet returned is therefore invisible to CloseAll.
// Nothing else stops it either: the dialer consults no network epoch, and the candidate scheduler is
// not told that the network moved.
//
// # What that means
//
// The connection it produces belongs to the network that has been left. If it is handed to the
// caller, the caller's traffic travels over the old network's socket - which is precisely the
// ownership the reset exists to revoke. This test establishes whether that can happen, so the answer
// is a measurement rather than an assumption.

// countingConnectionManager records tracked connections and can close them, counting how many it
// actually closed.
type countingConnectionManager struct {
	adapter.ConnectionManager

	access  sync.Mutex
	tracked []net.Conn
	closed  atomic.Int32
}

func (m *countingConnectionManager) TrackConn(conn net.Conn) net.Conn {
	m.access.Lock()
	m.tracked = append(m.tracked, conn)
	m.access.Unlock()
	return conn
}

func (m *countingConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	return conn
}

// CloseAll mirrors the production implementation: it closes what has been TRACKED, and nothing else.
func (m *countingConnectionManager) CloseAll() {
	m.access.Lock()
	closers := m.tracked
	m.tracked = nil
	m.access.Unlock()
	for _, conn := range closers {
		conn.Close()
		m.closed.Add(1)
	}
}

func (m *countingConnectionManager) trackedCount() int {
	m.access.Lock()
	defer m.access.Unlock()
	return len(m.tracked)
}

// loopbackTarget returns a listener address that accepts and immediately closes, so a dial to it
// succeeds and yields a real connection.
func loopbackTarget(t *testing.T) string {
	t.Helper()
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
	return listener.Addr().String()
}

// newTrackedDialer builds a production DefaultDialer wired to the given connection manager.
//
// NewDefault reads the manager out of the context, so the test injects it there rather than passing
// it as an option - the test drives the real construction path, and trackConn is the production one.
func newTrackedDialer(t *testing.T, manager adapter.ConnectionManager, control control.Func) *DefaultDialer {
	t.Helper()
	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)
	dialer, err := NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)
	dialer.dialer4.Control = control
	dialer.dialer6.Control = control
	return dialer
}

// gatedTarget is a listener that accepts normally, plus a gate the dial passes through first.
//
// The gate is the dialer's own Control hook, which production uses for socket options and which runs
// immediately before connect. Blocking there holds the dial in flight with the entire production
// dial path intact - nothing about trackConn, the connection manager or the candidate logic is
// replaced.
type gatedTarget struct {
	listener net.Listener
	address  string
	gate     chan struct{}
	entered  chan struct{}
	once     sync.Once
}

func newGatedTarget(t *testing.T) *gatedTarget {
	t.Helper()
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
	return &gatedTarget{
		listener: listener,
		address:  listener.Addr().String(),
		gate:     make(chan struct{}),
		entered:  make(chan struct{}, 1),
	}
}

// control is installed as the dialer's Control hook.
func (t *gatedTarget) control(network, address string, conn syscall.RawConn) error {
	t.once.Do(func() {
		select {
		case t.entered <- struct{}{}:
		default:
		}
		<-t.gate
	})
	return nil
}

// TestInFlightDialStartedBeforeResetIsNotClosedByReset is C2.
//
// A dial is held in flight, the reset runs, and only then is the dial allowed to complete. The
// question is whether the resulting connection is subject to the reset.
func TestInFlightDialStartedBeforeResetIsNotClosedByReset(t *testing.T) {
	manager := &countingConnectionManager{}

	target := newGatedTarget(t)
	dialer := newTrackedDialer(t, manager, target.control)

	type dialResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan dialResult, 1)
	go func() {
		conn, err := dialer.DialContext(context.Background(), "tcp",
			M.ParseSocksaddr(target.address))
		result <- dialResult{conn, err}
	}()

	// Barrier: the dial is genuinely in flight, before the reset.
	// Barrier: the dial has entered the production Control hook and is held there, so it is
	// genuinely in flight and has definitely not returned.
	select {
	case <-target.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never reached the gate")
	}

	// At this instant the reset sees nothing to close, because the connection does not exist yet.
	require.Equal(t, 0, manager.trackedCount(),
		"the in-flight dial must not be tracked before it returns, which is what makes it invisible "+
			"to the reset")

	// The network change.
	manager.CloseAll()
	require.EqualValues(t, 0, manager.closed.Load(),
		"the reset closed nothing, which is the point: the connection had not been created")

	// Now the dial is allowed to proceed.
	close(target.gate)

	select {
	case outcome := <-result:
		require.NoError(t, outcome.err,
			"the dial completed after the reset. Nothing cancelled it: the reset closes tracked "+
				"connections only, and the dialer consults no network epoch")
		require.NotNil(t, outcome.conn)

		// The connection the caller now holds was dialled for the previous network, and the reset
		// did not touch it.
		require.EqualValues(t, 0, manager.closed.Load(),
			"the reset did not close the connection, because it was created after CloseAll ran")

		// It is tracked now, so a LATER reset would close it - but the ownership the caller already
		// holds was granted across the network change.
		require.Equal(t, 1, manager.trackedCount(),
			"the connection was registered with the manager only after the reset")

		outcome.conn.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the dial never returned after being released")
	}
}

// TestTrackedConnectionIsClosedByReset is the control.
//
// A connection that WAS registered before the reset is closed by it, so the guarantee the manager
// does provide is real and is not being misread as covering the in-flight case.
func TestTrackedConnectionIsClosedByReset(t *testing.T) {
	manager := &countingConnectionManager{}

	// A dial that returns immediately, so the connection is tracked before the reset.
	target := loopbackTarget(t)
	dialer := newTrackedDialer(t, manager, nil)

	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target))
	require.NoError(t, err)
	require.Equal(t, 1, manager.trackedCount(), "the completed dial is tracked")

	manager.CloseAll()
	require.EqualValues(t, 1, manager.closed.Load(),
		"a tracked connection IS closed by the reset - so the manager's guarantee is real, it simply "+
			"does not extend to a dial that has not returned yet")
	_ = conn
}
