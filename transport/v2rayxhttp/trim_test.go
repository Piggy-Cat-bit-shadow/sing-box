//go:build with_xhttp

package v2rayxhttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The memory-trim contract for the XHTTP pool.
//
// The runtime lifecycle model (docs/fork/runtime-lifecycle-phase1.5.md) splits the two ways a
// network-bound resource can be told to let go:
//
//	network change  -> retire EVERYTHING (every pooled connection belongs to the network being left)
//	memory pressure -> retire only what is IDLE (a trim must not disturb a live stream)
//
// and it forbids one outcome for the second: a trim must not be able to cause a dial for work that is
// already in flight. For a pool of one connection per session, retiring a connection with a live
// stream on it would not break that stream - the teardown is deferred - but it WOULD make the next
// request dial. Both paths end with fewer pooled connections, so only a test can tell them apart.

// The fake connection is the package's own (xmux_test.go), so the assertion is "was it torn down"
// rather than a second model of the pool.

func newTrimTestManager() (*xmuxManager, *fakeXmuxConn, *fakeXmuxConn) {
	idleConn := &fakeXmuxConn{}
	busyConn := &fakeXmuxConn{}
	manager := &xmuxManager{newConn: func() xmuxConn { return &fakeXmuxConn{} }}
	idle := &xmuxClient{conn: idleConn, leftUsage: -1}
	busy := &xmuxClient{conn: busyConn, leftUsage: -1}
	// openUsage is the live-stream count.
	busy.addOpenUsage(1)
	manager.clients = []*xmuxClient{idle, busy}
	return manager, idleConn, busyConn
}

func TestCloseIdleConnectionsLeavesLiveStreamsPooled(t *testing.T) {
	t.Parallel()
	manager, idleConn, busyConn := newTrimTestManager()

	manager.CloseIdleConnections()

	require.Equal(t, 1, idleConn.closes(), "an idle pooled connection must be released by a trim")
	require.Zero(t, busyConn.closes(),
		"a connection carrying a live stream must survive a trim: retiring it would make the next request dial")
	require.Len(t, manager.clients, 1, "only the busy connection stays pooled")
	require.Same(t, busyConn, manager.clients[0].conn)
}

func TestCloseIdleConnectionsEmptyPoolIsSafe(t *testing.T) {
	t.Parallel()
	manager := &xmuxManager{}
	manager.CloseIdleConnections()
	require.Empty(t, manager.clients)
	// Idempotent: a second trim on an empty pool is a no-op, not a panic.
	manager.CloseIdleConnections()
}

func TestCloseRetiresEverythingIncludingBusyConnections(t *testing.T) {
	t.Parallel()
	manager, _, busyConn := newTrimTestManager()
	busy := manager.clients[1]

	manager.Close()

	require.Zero(t, busyConn.closes(),
		"the teardown of a busy connection is deferred to its last stream")
	require.Empty(t, manager.clients, "but it is retired: no new stream may be placed on it")

	// The deferred teardown runs when the last stream leaves that connection.
	busy.addOpenUsage(-1)
	require.Equal(t, 1, busyConn.closes(),
		"a retired connection is torn down once its last stream finishes")
}

func TestSetKeepIdleConnectionsFalseTrims(t *testing.T) {
	t.Parallel()
	client := &Client{xmux: &xmuxManager{}}
	idleConn := &fakeXmuxConn{}
	client.xmux.clients = []*xmuxClient{{conn: idleConn, leftUsage: -1}}

	client.SetKeepIdleConnections(true)
	require.Zero(t, idleConn.closes(),
		"keep=true has nothing to pre-warm and must not release anything")

	client.SetKeepIdleConnections(false)
	require.Equal(t, 1, idleConn.closes(), "keep=false releases what is not in use")
}

// The transport must satisfy the capability the trim path asserts, or the memory-pressure pass
// silently stops at the outbound and never reaches this pool.
func TestClientImplementsIdleConnectionKeeper(t *testing.T) {
	t.Parallel()
	var client any = &Client{}
	if _, ok := client.(interface {
		SetKeepIdleConnections(bool)
		CloseIdleConnections()
	}); !ok {
		t.Fatal("the XHTTP client must implement adapter.IdleConnectionKeeper, or the memory-trim path cannot reach its pool")
	}
}
