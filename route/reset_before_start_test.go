package route

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// A network reset that arrives before the manager has a router is a no-op, not a crash.
//
// # The failure this pins
//
// NetworkManager.router is assigned on the initialize stage, but the daemon publishes the core
// instance before it calls Start. A command-protocol RPC in that window - the classic trigger is
// a Wi-Fi to cellular handover landing while the tunnel is still starting - reaches
// resetNetworkLocked with a nil router, and the reset walks its managers and then dereferences
// it. The result is a nil-interface method call in a core goroutine and the whole process dies.
//
// The window is not narrow: the initialize stage starts the cache file, the Clash API and the
// v2ray API before the network manager is started, so a slow cache open widens it.
//
// The other three managers are assigned by the constructor, which is why the router is the one
// that has to be guarded.
func TestResetNetworkBeforeStartIsANoOp(t *testing.T) {
	t.Parallel()

	manager := &NetworkManager{
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	require.NotPanics(t, func() {
		manager.ResetNetwork(context.Background())
	}, "a reset before the router is assigned must not dereference it")
}

// The guard must not disable resets once the router is there.
func TestResetNetworkStillResetsOnceRouterIsAssigned(t *testing.T) {
	t.Parallel()

	router := newCountingRouter()
	manager := &NetworkManager{
		router:   router,
		endpoint: &emptyEndpointManager{},
		inbound:  &emptyInboundManager{},
		outbound: &emptyOutboundManager{},
	}

	manager.ResetNetwork(context.Background())

	require.EqualValues(t, 1, router.entered, "an initialised manager must still reset its router")
}
