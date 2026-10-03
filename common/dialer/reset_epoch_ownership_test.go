package dialer

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The network-epoch ownership invariant, across every ordering a reset can take.
//
// # The sequence
//
//	epoch := capture                   before any raw work
//	conn  := raw dial                  <- a reset may land anywhere in here
//	track(conn)                        ownership moves to the connection manager
//	verify(epoch)                      and only then is it handed to the caller
//
// Tracking BEFORE verifying is what closes the window in both directions: a reset that lands before
// the track is caught by the verification, and one that lands after it is visible to CloseAll. The
// reverse order - verify then track - leaves an interval no check can see, which is why the ordering
// itself is what these tests pin rather than the check alone.

// epochNetworkManager supplies the reset counter and the interface finder the dialer asks for.
//
// The finder is the one part of the manager a DefaultDialer needs at construction; everything else
// stays embedded and nil, which is deliberate - the point of the capability being optional is that a
// manager which provides nothing else still works.
type epochNetworkManager struct {
	adapter.NetworkManager
	epoch  *atomic.Uint64
	finder control.InterfaceFinder
}

func (m *epochNetworkManager) NetworkResetGeneration() uint64 { return m.epoch.Load() }

func (m *epochNetworkManager) InterfaceFinder() control.InterfaceFinder { return m.finder }

// DefaultOptions returns zero options, so the dialer binds nothing by default. The dialer consults
// it during construction, and a manager that provides no options is a manager with nothing to bind -
// which keeps the harness on the plain dial path this test is about.
func (m *epochNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (m *epochNetworkManager) AutoDetectInterface() bool { return false }

// AutoRedirectOutputMarkFunc returns a no-op. The dialer installs it on every dial's control chain,
// and this harness is not about the auto-redirect mark.
func (m *epochNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network, address string, conn syscall.RawConn) error { return nil }
}

// epochManager tracks connections and closes exactly those on CloseAll.
type epochManager struct {
	adapter.ConnectionManager

	access  sync.Mutex
	tracked []io.Closer
	closed  atomic.Int32
}

func (m *epochManager) TrackConn(conn net.Conn) net.Conn {
	m.access.Lock()
	m.tracked = append(m.tracked, conn)
	m.access.Unlock()
	return conn
}

func (m *epochManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	m.access.Lock()
	m.tracked = append(m.tracked, conn)
	m.access.Unlock()
	return conn
}

// CloseAll mirrors production: it closes what has been TRACKED and nothing else.
func (m *epochManager) CloseAll() {
	m.access.Lock()
	closers := m.tracked
	m.tracked = nil
	m.access.Unlock()
	for _, closer := range closers {
		_ = closer.Close()
		m.closed.Add(1)
	}
}

func (m *epochManager) trackedCount() int {
	m.access.Lock()
	defer m.access.Unlock()
	return len(m.tracked)
}

// epochHarness is a production DefaultDialer wired to an epoch counter and a tracking manager.
type epochHarness struct {
	dialer  *DefaultDialer
	epoch   *atomic.Uint64
	manager *epochManager
	target  string
}

// newEpochHarness builds the harness against a listener that accepts and closes immediately.
func newEpochHarness(t *testing.T) *epochHarness {
	t.Helper()
	target := loopbackTarget(t)

	epoch := &atomic.Uint64{}
	manager := &epochManager{}

	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)
	ctx = service.ContextWith[adapter.NetworkManager](ctx,
		&epochNetworkManager{epoch: epoch, finder: control.NewDefaultInterfaceFinder()})
	dialer, err := NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)

	return &epochHarness{dialer: dialer, epoch: epoch, manager: manager, target: target}
}

// reset performs what NetworkManager.ResetNetwork does to these two collaborators: the epoch
// advances, then the tracked connections are closed.
func (h *epochHarness) reset() {
	h.epoch.Add(1)
	h.manager.CloseAll()
}

type dialOutcome struct {
	conn net.Conn
	err  error
}

// gateDial installs a Control hook that signals entry and then blocks until release.
//
// The hook is the production Control function, which runs immediately before connect, so the dial is
// genuinely in flight inside the real dial path while the test holds it.
func (h *epochHarness) gateDial() (entered chan struct{}, release chan struct{}) {
	entered = make(chan struct{})
	release = make(chan struct{})
	var once sync.Once
	gate := func(network, address string, conn syscall.RawConn) error {
		once.Do(func() {
			close(entered)
			<-release
		})
		return nil
	}
	h.dialer.dialer4.Control = gate
	h.dialer.dialer6.Control = gate
	return entered, release
}

// dial starts a dial in the background.
func (h *epochHarness) dial(ctx context.Context) chan dialOutcome {
	outcome := make(chan dialOutcome, 1)
	go func() {
		conn, err := h.dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(h.target))
		outcome <- dialOutcome{conn, err}
	}()
	return outcome
}

// TestCase1ResetBeforeTheDialReturns is case 1.
//
// The reset completes while the raw dial is still in flight. The connection it then produces belongs
// to the network that has been left, so the caller must not receive it as usable.
func TestCase1ResetBeforeTheDialReturns(t *testing.T) {
	harness := newEpochHarness(t)
	entered, release := harness.gateDial()
	outcome := harness.dial(context.Background())

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never entered the dial path")
	}

	// The entire reset runs before the dial returns.
	harness.reset()
	require.EqualValues(t, 0, harness.manager.trackedCount(),
		"the reset sees nothing to close, because the connection does not exist yet")

	close(release)

	received := <-outcome
	if received.err == nil {
		// If it succeeded, the epoch check must have caught it - and the connection must be closed.
		require.Nil(t, received.conn,
			"the caller received a connection dialled for the network that was reset")
	}
	require.Error(t, received.err,
		"a dial that spanned a network reset must fail rather than succeed with a stale connection")
	require.Contains(t, received.err.Error(), "network changed")
}

// TestCase3TrackedConnectionIsVisibleToTheReset is case 3.
//
// The narrower, mechanical half of the ordering: a connection that has been tracked must be visible
// to CloseAll, so a reset that lands after the handover closes it. This is what tracking before
// verifying buys, and it is asserted directly rather than through a racing timeline - the racing
// version would depend on which goroutine wins, and the property being pinned is that the connection
// is REACHABLE, not that a particular interleaving occurs.
func TestCase3TrackedConnectionIsVisibleToTheReset(t *testing.T) {
	harness := newEpochHarness(t)

	// A plain dial: it completes, is tracked, and the epoch is unchanged so it is returned.
	conn, err := harness.dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(harness.target))
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.Equal(t, 1, harness.manager.trackedCount(),
		"the connection must be registered with the manager BEFORE the caller receives it. If it "+
			"were verified first and tracked afterwards, a reset landing in between would find "+
			"nothing to close and the connection would escape")

	// The reset now sees it and closes it - which is only possible because the handover happened
	// before this point.
	harness.reset()
	require.EqualValues(t, 1, harness.manager.closed.Load(),
		"the reset closed the tracked connection")

	// The caller still holds the handle; the point is that the socket is closed underneath it, so it
	// cannot be used to reach the network that has been left.
	buffer := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := conn.Read(buffer)
	require.Error(t, readErr,
		"the connection the caller holds must be closed after the reset, not merely untracked")
}

// TestCase5NoResetIsUnchanged is case 5: the normal dial must be completely unaffected.
func TestCase5NoResetIsUnchanged(t *testing.T) {
	harness := newEpochHarness(t)

	conn, err := harness.dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(harness.target))
	require.NoError(t, err, "a dial with no network change must succeed exactly as before")
	require.NotNil(t, conn)
	require.Equal(t, 1, harness.manager.trackedCount(), "and it is tracked")
	require.EqualValues(t, 0, harness.manager.closed.Load())

	conn.Close()
}

// TestDialerWithoutAnEpochDegradesToPreviousBehaviour pins the optional-capability contract.
//
// A network manager that cannot report an epoch is one where the check does not apply, so the dialer
// must behave exactly as it did before rather than rejecting every dial.
func TestDialerWithoutAnEpochDegradesToPreviousBehaviour(t *testing.T) {
	target := loopbackTarget(t)
	manager := &epochManager{}

	ctx := service.ContextWith[adapter.ConnectionManager](context.Background(), manager)
	dialer, err := NewDefault(ctx, option.DialerOptions{})
	require.NoError(t, err)

	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target))
	require.NoError(t, err,
		"a manager with no reset counter must not cause dials to fail; the capability is optional")
	require.NotNil(t, conn)
	conn.Close()
}
