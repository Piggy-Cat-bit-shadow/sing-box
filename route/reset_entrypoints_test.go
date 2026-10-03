package route

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"time"

	"github.com/stretchr/testify/require"
)

// The four reset entry points, exercised together.
//
// # Why all four
//
// The interface path and the power paths already hold resetRunAccess across a wider critical section,
// so they call the inner function; the control plane calls the exported one, which takes the lock
// itself. That split is required - the lock is not reentrant, so having a lock holder call the
// exported function would deadlock every interface change - but it means two entry points must be
// exercised rather than one, and the paths that do NOT reset must be shown not to take the lock.
//
//	interface update   resetRunAccess held -> inner
//	power resume       resetRunAccess held -> inner
//	control plane      no lock            -> exported (takes it)
//	ReleaseMemory      no lock            -> exported, then CloseIdleConnections

// TestAllResetEntryPointsCoexist drives the two entry forms concurrently against one manager.
//
// Serialisation must not drop work, and neither form may deadlock against the other.
func TestAllResetEntryPointsCoexist(t *testing.T) {
	router := newCountingRouter()
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	const perForm = 4
	var (
		waitGroup sync.WaitGroup
		start     = make(chan struct{})
	)

	// The control-plane form: the exported entry, which takes the lock.
	for index := 0; index < perForm; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.ResetNetwork(context.Background())
		}()
	}

	// The interface / power form: hold the lock, then call the inner function.
	for index := 0; index < perForm; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			manager.resetRunAccess.Lock()
			defer manager.resetRunAccess.Unlock()
			manager.resetNetworkLocked(context.Background())
		}()
	}

	close(start)

	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the reset entry points deadlocked. The lock is not reentrant, so a path that " +
			"already holds resetRunAccess must reach the inner function rather than the exported one")
	}

	require.EqualValues(t, perForm*2, router.entered,
		"every reset must have run; serialising must not drop one form in favour of the other")
	require.EqualValues(t, 1, router.maxSeen.Load(),
		"two resets were inside the router's reset simultaneously")
}

// TestReleaseMemoryResetsThenClosesIdle is the ReleaseMemory ordering.
//
// It calls the exported entry and then releases idle connections, so the exported path must return
// with the lock free - otherwise the CloseIdleConnections loop runs while holding it, or deadlocks.
func TestReleaseMemoryResetsThenClosesIdle(t *testing.T) {
	router := newCountingRouter()
	keeper := &recordingIdleKeeper{}
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &recordingOutboundManager{keepers: []*recordingIdleKeeper{keeper}},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.ReleaseMemory(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ReleaseMemory deadlocked. It calls the exported reset and then releases idle " +
			"connections; if the reset did not return with the lock free, the second half never runs")
	}

	require.EqualValues(t, 1, router.entered, "ReleaseMemory resets the network")
	require.EqualValues(t, 1, keeper.closed.Load(), "and then releases idle connections")
}

// recordingIdleKeeper counts CloseIdleConnections calls.
type recordingIdleKeeper struct {
	closed atomic.Int32
}

func (k *recordingIdleKeeper) CloseIdleConnections() { k.closed.Add(1) }

// recordingOutboundManager lists outbounds that implement IdleConnectionKeeper.
type recordingOutboundManager struct {
	adapter.OutboundManager
	keepers []*recordingIdleKeeper
}

func (m *recordingOutboundManager) Outbounds() []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(m.keepers))
	for _, keeper := range m.keepers {
		outbounds = append(outbounds, &keeperOutbound{keeper: keeper})
	}
	return outbounds
}

// keeperOutbound exposes a keeper through the Outbound interface.
type keeperOutbound struct {
	adapter.Outbound
	keeper *recordingIdleKeeper
}

func (o *keeperOutbound) SetKeepIdleConnections(keep bool) {}

func (o *keeperOutbound) CloseIdleConnections() { o.keeper.CloseIdleConnections() }
