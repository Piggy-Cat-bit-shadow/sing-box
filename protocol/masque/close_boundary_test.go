package masque

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/device"

	"github.com/stretchr/testify/require"
)

// Tests for the acquisition window that Scope.Close does NOT cover.
//
// # The window
//
// Scope.Close joins the cleanup drain and returns; it does not wait for a Start that is already
// running. StartStateInitialize registers the endpoint's teardown with the Scope at the moment it
// acquires the device, so a drain that happens while StartStateStart is running releases the device
// and closes a listener that has not been started yet - which is a no-op.
//
// StartStateStart then carries on and binds the listening socket. The device is protected from this
// by its own Start-after-Close contract (both in-tree devices refuse), but common/listener has no
// such contract: Listener.Start binds unconditionally and its Close has already been and gone. The
// result would be a listening TCP/UDP port that outlives the endpoint, the Scope and Box.Close(),
// with no owner left to close it: Scope.Close only ever walks the queue it already drained.
//
// # The fix these pin
//
// ServerEndpoint publishes `closed` before its teardown releases anything and re-checks it after the
// bind. Either the check sees the endpoint still open - and the release that follows the critical
// section is ordered after the bind and finds the socket - or it sees it closed and Start releases
// what it just bound itself. Neither branch can leave the port behind.

// blockingDevice is a device.Device whose Start can be held at the exact point where StartStateStart
// sits between the device and the listener. Everything else delegates to the embedded interface,
// which the test never reaches.
type blockingDevice struct {
	device.Device
	startEntered chan struct{}
	startRelease chan struct{}
	startCalls   atomic.Int32
	closeCalls   atomic.Int32
}

func (d *blockingDevice) Start() error {
	d.startCalls.Add(1)
	close(d.startEntered)
	<-d.startRelease
	return nil
}

func (d *blockingDevice) Close() error {
	d.closeCalls.Add(1)
	return nil
}

// TestServerEndpointReleasesAListenerBoundAfterClose is the window, forced deterministically.
//
// Ordering is enforced by the test rather than by timing: the Start goroutine cannot reach the bind
// until `startRelease` is closed, and that happens only after Scope.Close has returned.
func TestServerEndpointReleasesAListenerBoundAfterClose(t *testing.T) {
	endpoint, _ := newOwnershipEndpoint(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NotNil(t, endpoint.device, "StartStateInitialize must have acquired the device")

	// Stand in for the device so the window can be held open. The real one is released by the test
	// instead of by the drain, which is the only thing this substitution changes.
	realDevice := endpoint.device
	t.Cleanup(func() { _ = realDevice.Close() })
	blocked := &blockingDevice{
		Device:       realDevice,
		startEntered: make(chan struct{}),
		startRelease: make(chan struct{}),
	}
	endpoint.device = blocked

	startDone := make(chan error, 1)
	go func() { startDone <- scope.Start(name, endpoint, adapter.StartStateStart) }()

	<-blocked.startEntered
	require.False(t, endpoint.started.Load(), "the endpoint is still starting")

	// The drain runs the teardown that StartStateInitialize registered, and returns.
	require.NoError(t, scope.Close())
	require.Equal(t, int32(1), blocked.closeCalls.Load(),
		"closing the Scope must have run the endpoint teardown")

	// Only now may Start bind.
	close(blocked.startRelease)
	startErr := <-startDone

	require.Error(t, startErr,
		"Start must not report success for an endpoint that was closed while it was starting: the "+
			"caller would treat a released endpoint as a live one")

	bound := endpoint.listener.TCPListener()
	require.NotNil(t, bound,
		"the premise of this test: the listener DID bind after Close returned - that is the window")
	rebind, err := net.Listen("tcp", bound.Addr().String())
	require.NoError(t, err,
		"the port bound after Scope.Close returned must have been released again; it is still "+
			"listening on %v, so the socket outlives the endpoint, the Scope and Box.Close()", bound.Addr())
	require.NoError(t, rebind.Close())

	require.False(t, endpoint.started.Load(),
		"the endpoint must not advertise itself as started after the Scope closed it")
	require.Equal(t, int32(1), blocked.closeCalls.Load(),
		"the endpoint teardown must still have run exactly once")
}

// TestServerEndpointStartAfterCloseDoesNotBind is the same rule for a Start that begins after the
// teardown is complete: it must not reach the bind at all.
//
// Here the device's own Start-after-Close contract refuses first; the assertion is on the observable
// outcome, so a future reordering that binds the listener before starting the device cannot pass.
func TestServerEndpointStartAfterCloseDoesNotBind(t *testing.T) {
	endpoint, _ := newOwnershipEndpoint(t)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NoError(t, scope.Close())

	// A Start that reaches the component anyway: the Scope refuses new starts, but the component
	// must not be the second line of defence that fails.
	require.Error(t, endpoint.Start(adapter.StartStateStart, adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())))
	require.Nil(t, endpoint.listener.TCPListener(),
		"an endpoint that is already closed must not bind a listening socket")
	require.False(t, endpoint.started.Load())
}
