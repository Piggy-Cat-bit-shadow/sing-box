package masque

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the Scope ownership of a MASQUE server endpoint's teardown.
//
// # The defect these pin
//
// ServerEndpoint.Start acquires the endpoint's running resources - a device, a TLS config, a
// listener and the HTTP/3 server - and Close releases all of them. Nothing ever handed Close to the
// Scope. The product closes a Box by closing its Scope, and Scope.Close() runs the entries handed to
// it through scope.Add; it never calls a component's Close() method. So on a real Box.Close() the
// device and the listening socket stayed open: the Scope owned no part of this endpoint.
//
// The endpoint manager's Start skips StartStateStart, so the device is acquired by the stage that
// always runs - StartStateInitialize - and it is the acquisition that has to be owned.

// recordingCloser stands in for the HTTP/3 server, which is the one part of the teardown that is an
// io.Closer the test can hand in without a QUIC stack. The assertion is not about this object; it is
// a witness for whether Close ran at all.
type recordingCloser struct {
	closed atomic.Int32
}

func (c *recordingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

// newOwnershipEndpoint builds the real *ServerEndpoint with the smallest amount of the OS-facing
// layer substituted: the device is the production userspace stack, and the listener is a real socket
// on an ephemeral port.
func newOwnershipEndpoint(t *testing.T) (*ServerEndpoint, *recordingCloser) {
	t.Helper()
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()
	witness := &recordingCloser{}
	endpoint := &ServerEndpoint{
		endpointBase: endpointBase{
			logger: logger,
		},
		ctx:   ctx,
		http3: false,
		// Left as the witness on purpose: StartStateStart must not be able to replace it, and with
		// http3 false the field is not touched.
		http3Server: witness,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.AddrFrom4([4]byte{127, 0, 0, 1}))),
				ListenPort: 0,
			},
		}),
		deviceOptions: &device.Options{
			Context: ctx,
			Logger:  logger,
			MTU:     1500,
		},
	}
	// A real server: Close tears it down, so a fixture without one would not be able to drive the
	// production teardown at all.
	server, err := masque.NewServer(masque.ServerOptions{
		Context: ctx,
		Logger:  logger,
		Path:    "/",
		Address: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		Handler: endpoint,
	})
	require.NoError(t, err)
	endpoint.server = server
	return endpoint, witness
}

// TestScopeOwnsServerEndpointTeardown is P0-L01b.
//
// The invariant: closing the Scope that started the endpoint releases every resource Start acquired,
// whether or not anything ever calls Close() by hand. The product only ever closes the Scope.
func TestScopeOwnsServerEndpointTeardown(t *testing.T) {
	endpoint, witness := newOwnershipEndpoint(t)

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"

	// The stage the endpoint manager always runs: this is where the device is acquired.
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NotNil(t, endpoint.device, "StartStateInitialize must have acquired the device")

	// The stage adapter/endpoint.Manager.StartEndpoint runs for an endpoint-outbound.
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateStart))
	require.True(t, endpoint.started.Load(), "StartStateStart must have started the endpoint")

	require.NoError(t, scope.Close())

	require.Equal(t, int32(1), witness.closed.Load(),
		"closing the Scope must run the endpoint's teardown: Box.Close() closes the Scope and never "+
			"calls Close(), so a teardown that is not handed to the Scope leaves the device and the "+
			"listening socket open")
}

// TestServerEndpointCloseIsExactlyOnce is invariant #2 for this object.
//
// Both the Scope and the explicit loser path in adapter/endpoint/manager.go can reach the teardown.
// Releasing twice would close the same listener and device twice, so Close has to be idempotent
// regardless of which path gets there first.
func TestServerEndpointCloseIsExactlyOnce(t *testing.T) {
	endpoint, witness := newOwnershipEndpoint(t)

	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateInitialize))
	require.NoError(t, scope.Start(name, endpoint, adapter.StartStateStart))
	require.NoError(t, scope.Close())

	require.NoError(t, endpoint.Close())

	require.Equal(t, int32(1), witness.closed.Load(),
		"a second Close must not release the same resource again")
}
