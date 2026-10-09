package route

import (
	"context"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/masque"
	"github.com/sagernet/sing-box/protocol/openconnect"
	"github.com/sagernet/sing-box/protocol/openvpn"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// This file turns the reusable-owner inventory that `route/reference.go` and
// `docs/fork/post-wake-reuse.md` state in prose into an assertion about the real types.
//
// # Why the inventory needs a test at all
//
// Every claim the boundary and the trim make about safety rests on one sentence: a keeper can only
// ever close a resource that has no active user traffic, and it can never dial. That sentence is a
// property of the KEEPERS, not of `retireIdleResources`, and `retireIdleResources` says so at
// length - "it is what every review of a new keeper has to establish". A review is a moment; this
// file is the part that survives it.
//
// The shape it guards is the dangerous one, and it is dangerous precisely because it looks like an
// improvement: adding `CloseIdleConnections` to an on-demand tunnel would make it reachable from
// the DEEP_IDLE, memory-pressure and reuse-boundary walks, and those walks would then suspend a
// WireGuard, MASQUE, OpenVPN, OpenConnect or Tailscale tunnel that is carrying traffic. On Apple
// that is the hotspot case: the phone's own tunnel keeps looking alive while the tethered client
// loses its path. The tunnels implement `SetKeepIdleConnections` - a suspend/resume of the tunnel
// itself, which is NOT an idle-only action - and deliberately not `CloseIdleConnections`, so the
// walk cannot reach them.
//
// So the assertion is two-sided on purpose. `Implements(OnDemandEndpoint)` pins that the endpoint
// is still reached by the eligibility pass at all; `Not(Implements(IdleConnectionKeeper))` is the
// one that fails the day somebody gives a tunnel an idle-close method, which is exactly the day
// the paragraph above has to be re-argued rather than inherited.

var (
	idleConnectionReleaser = reflect.TypeFor[adapter.IdleConnectionReleaser]()
	idleConnectionKeeper   = reflect.TypeFor[adapter.IdleConnectionKeeper]()
	reuseSuspect           = reflect.TypeFor[adapter.ReuseSuspect]()
	onDemandEndpoint       = reflect.TypeFor[adapter.OnDemandEndpoint]()
)

// TestTheOnDemandTunnelsAreReachableOnlyFromTheEligibilityPass is the first half of the inventory:
// the tunnels are suspended and resumed by the device level, and are invisible to the walks that
// release reusable state.
func TestTheOnDemandTunnelsAreReachableOnlyFromTheEligibilityPass(t *testing.T) {
	tunnels := []struct {
		name string
		typ  reflect.Type
	}{
		{"protocol/wireguard.Endpoint", reflect.TypeFor[*wireguard.Endpoint]()},
		{"protocol/masque.ClientEndpoint", reflect.TypeFor[*masque.ClientEndpoint]()},
		{"protocol/openvpn.ClientEndpoint", reflect.TypeFor[*openvpn.ClientEndpoint]()},
		{"protocol/openconnect.Endpoint", reflect.TypeFor[*openconnect.Endpoint]()},
	}
	for _, tunnel := range tunnels {
		tunnel := tunnel
		t.Run(tunnel.name, func(t *testing.T) {
			require.True(t, tunnel.typ.Implements(onDemandEndpoint),
				"%s is no longer an adapter.OnDemandEndpoint, so the eligibility pass at "+
					"route/reference.go's update() no longer suspends it on a device pause", tunnel.name)
			require.False(t, tunnel.typ.Implements(idleConnectionKeeper),
				"%s now implements adapter.IdleConnectionKeeper, so retireIdleResources and "+
					"retireSuspectResources can reach it. Those walks run on DEEP_IDLE, on memory "+
					"pressure and on every reuse boundary, and its CloseIdleConnections is a "+
					"suspend of the tunnel itself, not a release of idle sockets. Re-argue the "+
					"contract documented at route/reference.go's retireIdleResources before "+
					"changing this assertion.", tunnel.name)
		})
	}
}

// TestTheReusableOwnersTheWalkIsDocumentedToReachKeepTheirCapabilities is the second half, and it is
// the direction that must not silently disappear: the two capabilities that CLOSED residual risks
// 2 and 4 of docs/fork/post-wake-reuse.md.
//
//   - common/httpclient.Manager is the fourth owner of reusable state and was the one pool the walk
//     could not reach. It is reached through an interface assertion on adapter.HTTPClientManager, so
//     losing adapter.IdleConnectionReleaser here would silently re-open that gap with no compile
//     error and no other test - which is exactly what happened: the walk asserted the BUNDLED
//     adapter.IdleConnectionKeeper, Manager has never implemented SetKeepIdleConnections, and the
//     assertion failed at run time on every boundary while `TestTheBoundaryReachesTheHTTPClientService`
//     passed against a fake that implemented both. The first assertion below is therefore stated
//     twice on purpose: Manager must be reachable (Releaser), and it must NOT be quietly turned into
//     a keeper to make an over-broad assertion succeed.
//   - transport/v2rayxhttp is the one pool that can express adapter.ReuseSuspect - refuse new work on
//     what it holds while the work already on it finishes. Losing it would fall every multiplexed
//     session back to the idle-only action, which is the case the capability exists for.
func TestTheReusableOwnersTheWalkIsDocumentedToReachKeepTheirCapabilities(t *testing.T) {
	manager := reflect.TypeFor[*httpclient.Manager]()
	require.True(t, manager.Implements(idleConnectionReleaser),
		"common/httpclient.Manager no longer implements adapter.IdleConnectionReleaser, so the "+
			"reference manager's walk cannot reach the pools behind provider refresh, remote rule "+
			"sets, the dashboard and the API - the gap docs/fork/post-wake-reuse.md records as "+
			"closed, and the gap this test was written to catch")
	require.False(t, manager.Implements(idleConnectionKeeper),
		"common/httpclient.Manager now implements the full adapter.IdleConnectionKeeper. Its "+
			"transports are shared and refcounted and nothing has an eligibility answer to ask it, "+
			"so the retire walks must keep asserting adapter.IdleConnectionReleaser - the capability "+
			"they actually call - rather than the bundled interface that silently excluded it")

	xmux := reflect.TypeFor[*v2rayxhttp.Client]()
	require.True(t, xmux.Implements(idleConnectionReleaser),
		"transport/v2rayxhttp.Client no longer implements adapter.IdleConnectionReleaser, so the "+
			"reuse boundary cannot retire its idle pooled connections")
	require.True(t, xmux.Implements(reuseSuspect),
		"transport/v2rayxhttp.Client no longer implements adapter.ReuseSuspect, so a multiplexed "+
			"session with a live stream is neither closed nor refused new work. That is the "+
			"capability the boundary walk prefers over the idle-only action and the reason it "+
			"applies both.")
}

// TestTheWalkReachesTheRealHTTPClientManager is the same claim as the assertion above, made through
// the walk instead of through reflection, and it is the test that would have caught the defect.
//
// The reflection assertion can only say the TYPE has the method. The defect was that the WALK asked
// for a different, larger interface and the type assertion failed at run time - so the walk is what
// has to be driven, with the REAL manager registered where box.go registers it. The fake in
// TestTheBoundaryReachesTheHTTPClientService could not catch it by construction: it implemented both
// halves of the bundled interface, so it satisfied the over-broad assertion that the real manager
// does not.
//
// Both walks are checked because they assert separately, and both were wrong.
func TestTheWalkReachesTheRealHTTPClientManager(t *testing.T) {
	realManager := httpclient.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("httpclient"),
		nil,
		"",
	)
	manager, _ := newReuseTestManager(t, nil, nil, func(ctx context.Context) context.Context {
		return service.ContextWith[adapter.HTTPClientManager](ctx, realManager)
	})

	require.Equal(t, 1, manager.retireIdleResources(),
		"the trim walk did not reach the real *httpclient.Manager, so Box.CloseIdleConnections, the "+
			"DEEP_IDLE release and the memory pass all left the pools behind provider refresh, "+
			"remote rule sets, the dashboard and the API untouched")
	require.Equal(t, 1, manager.retireSuspectResources(),
		"the reuse-boundary walk did not reach the real *httpclient.Manager, so the first provider "+
			"refresh after a sleep could still be handed a connection the sleep killed")
}
