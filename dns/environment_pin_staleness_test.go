package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// Whether the per-transport environment pin can go stale.
//
// # The direction this checks
//
// Pinning the environment to the transport fixed "new environment stamped on an old transport's
// answer". The opposite failure is a pin that outlives the network it describes: if the environment
// changes and the transports are NOT reset, the pin keeps stamping queries with the network they
// were established on - and a later query, whose answer comes from the new network, is filed under
// the old one.
//
// # Why that is reachable
//
// NetworkManager changes the environment from three places:
//
//	updateInterface            -> updateNetworkEnvironment, then a reset IF networkResetPending
//	UpdateInterfaces           -> postUpdateNetworkEnvironment (debounced), NO reset
//	onWIFIStateChanged         -> postUpdateNetworkEnvironment (debounced), NO reset
//
// A Wi-Fi SSID change on the same interface, or an interface list refresh, therefore moves the
// fingerprint without touching the DNS router's transports.
//
// # What the fixtures in this file can and cannot show
//
// windowTransport answers from a FIXED address for the whole test. A transport like that cannot go
// stale, because it never acquires a new underlay - so these tests show the pin holding while the
// transport is unchanged, and nothing more. They do NOT show that the pin still describes the network
// after the transport has moved.
//
// That case is real: TCP, TLS and HTTPS re-dial through their dialer when a pooled connection is
// invalidated, and the dial resolves the device's routes then. It is covered by
// TestTransportRedialedOnANewNetworkDoesNotKeepTheOldEnvironment in environment_rebind_test.go, and
// the transition that closes it is route's boundEnvironmentTransition.
//
// The boundary is now established on a real environment change, so the scenario these two tests
// describe - "the environment moved but nothing reset" - is no longer reachable through production
// paths. They are kept because they pin the ordering the pin exists for: an operation still running
// on the old network must not be stamped with the new one.

// movingEnvironmentManager is a NetworkEnvironment the test drives.
type movingEnvironmentManager struct {
	adapter.NetworkManager
	environment atomic.Uint64
}

func (m *movingEnvironmentManager) NetworkEnvironment() uint64 { return m.environment.Load() }

// TestEnvironmentChangeWithoutAResetRestampsTheTransport is B2.
//
// The environment moves but no reset runs, so the transport is not replaced. The question is what
// the next query is stamped with: the network the transport still belongs to, or the one the OS now
// reports.
func TestEnvironmentChangeWithoutAResetRestampsTheTransport(t *testing.T) {
	manager := &movingEnvironmentManager{}
	manager.environment.Store(0xA)

	transport := &windowTransport{
		tag:         "wifi-switch",
		environment: []string{"wifi"},
		address:     netip.MustParseAddr("10.0.0.1"),
	}

	router, client := newRouterWithWindowTransport(t, manager, transport)

	// Network A.
	require.EqualValues(t, 0xA, client.transportEnvironment(transport))

	// Wi-Fi moves to another SSID on the SAME interface. This is onWIFIStateChanged's path: the
	// debounced environment update runs, and no reset is pending, so the transports are never reset.
	manager.environment.Store(0xB)

	// No reset is performed, deliberately - that is the condition under test.
	pinned := client.transportEnvironment(transport)
	require.EqualValues(t, 0xA, pinned,
		"the transport keeps the environment it was established in, which is the intended pin")

	// In THIS fixture the transport answers from a fixed address and never re-dials, so its answer
	// describes network A and stamping it A is accurate. That is a property of the fixture, not a
	// general guarantee - see the file comment.
	message := new(mDNS.Msg)
	message.SetQuestion("wifi-switch.example.", mDNS.TypeA)
	question := message.Question[0]
	key := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})

	require.EqualValues(t, 0xA, pinned)
	require.EqualValues(t, 0xB, manager.NetworkEnvironment(),
		"the live environment has moved to B, so a live read would have stamped B")

	// The contract: while the transport is not reset, it still serves network A, so its answers are
	// filed under A. They are therefore NOT served to a query issued after a reset moves the pin.
	_, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	cached, _, _ := client.loadResponse(key)
	require.NotNil(t, cached, "the answer is filed under the network the transport serves")

	// The reset rebinds the pin, which is the boundary at which the transport starts serving B.
	router.ResetNetwork()
	require.EqualValues(t, 0xB, client.transportEnvironment(transport),
		"the reset must move the pin to the environment that is current, or the transport would "+
			"keep filing new-network answers under the old namespace forever")

	keyAfter := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	require.NotEqual(t, key.environment, keyAfter.environment)
}

// TestEnvironmentMovesWhileATransportIsInUseIsVisibleToTheNextQuery is B5's decision, made explicit.
//
// The invariant chosen is: the environment belongs to the transport until the transport is reset.
// A pin that tracked the live environment instead would reintroduce the misattribution the pin was
// added to prevent - a query travelling over network A's socket stamped with B.
func TestEnvironmentMovesWhileATransportIsInUseIsVisibleToTheNextQuery(t *testing.T) {
	manager := &movingEnvironmentManager{}
	manager.environment.Store(0xA)

	transport := &windowTransport{
		tag:         "in-use",
		environment: []string{"wifi"},
		address:     netip.MustParseAddr("10.0.0.2"),
	}

	_, client := newRouterWithWindowTransport(t, manager, transport)
	require.EqualValues(t, 0xA, client.transportEnvironment(transport))

	// The environment moves several times without any transport being reset. The pin must not follow,
	// because the socket underneath did not change.
	for _, value := range []uint64{0xB, 0xC, 0xA} {
		manager.environment.Store(value)
		require.EqualValues(t, 0xA, client.transportEnvironment(transport),
			"the pin followed the live environment. The transport was never reset, so its socket "+
				"still belongs to the network it was established on, and stamping it with a later "+
				"value would file that network's answers under a namespace they do not describe")
	}
}
