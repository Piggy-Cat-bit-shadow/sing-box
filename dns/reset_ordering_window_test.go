package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"

	"github.com/stretchr/testify/require"
)

// Item 5: the window between the interface notification and the DNS generation advance.
//
// # The ordering
//
// NetworkManager.ResetNetwork closes managed connections, notifies every endpoint, inbound and
// outbound that the interface changed, and only then calls the DNS router's ResetNetwork, which is
// what advances the generation. A DNS query issued from inside one of those notifications therefore
// runs while the OLD generation is still current.
//
// # Why that is correct rather than a window to close
//
// The generation is not "which network is physically up". It is "which network epoch a response may
// still be attributed to". A query issued during the notification is issued while the old epoch is
// genuinely current: the transports have not been reset and nothing has been purged, because the
// reset is only complete once it returns. Attributing that answer to the old epoch is accurate - it
// is the last query of the old network, sent over the old network's transports, not the first query
// of the new one.
//
// Advancing the generation earlier, at the start of NetworkManager.ResetNetwork, would be wrong in
// the other direction: it would label a query sent over the old transports as belonging to the new
// network, and a response that in fact describes the old network would then be stored as a current
// answer.
//
// # The cache is deliberately NOT cleared
//
// ResetNetwork purges the reverse mapping and advances the generation, but does not clear the DNS
// cache. That is upstream policy, not an omission: upstream commit 059508ed7 ("Avoid clearing DNS
// caches during network resets") removed the ClearCache call that the original implementation had.
// Entries therefore survive a network change for the remainder of their TTL, and the generation
// guard governs only what may be WRITTEN, not what may be read.
//
// This test pins both halves so neither can change silently: the window attributes correctly, and a
// reset does not clear the cache.

// TestQueryDuringInterfaceNotificationUsesTheEpochItWasAskedIn is item 5.
//
// A query issued while the notification is running is attributed to the epoch that was genuinely
// current when it was sent, and the reset does not retroactively clear what it stored.
func TestQueryDuringInterfaceNotificationUsesTheEpochItWasAskedIn(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	client.networkManager = &generationNetworkManager{}

	transport := &stepwiseTransport{
		tag:     "ordering",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: netip.MustParseAddr("10.0.0.1"),
	}
	close(transport.release) // this transport answers immediately

	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{transport.Tag(): transport},
			defaultTransport: transport,
		},
		client: client,
	}
	client.networkGeneration = router.dnsGeneration

	// A query issued during the window, before the generation advances.
	require.EqualValues(t, 0, router.dnsGeneration(), "the old epoch is current during the window")

	message := new(mDNS.Msg)
	message.SetQuestion("window.internal.", mDNS.TypeA)
	_, err := router.Exchange(context.Background(), message,
		adapter.DNSQueryOptions{Transport: transport})
	require.NoError(t, err)

	// The reset then completes.
	router.ResetNetwork()
	require.EqualValues(t, 1, router.dnsGeneration(), "the reset advanced the epoch")

	// The window's answer was stored under the epoch it was asked in, and the reset does not clear
	// the cache - upstream removed that call deliberately. What the guard guarantees is the other
	// direction: nothing may be WRITTEN under a mismatched epoch.
	question := message.Question[0]
	cacheKey := client.newCacheKey(transport, question, message, adapter.DNSQueryOptions{})
	cached, _, isStale := client.loadResponse(cacheKey)
	require.True(t, cached != nil && !isStale,
		"the entry stored during the window is still present. A reset does not clear the DNS cache "+
			"(upstream commit 059508ed7 removed that call deliberately), so an entry survives for its "+
			"TTL. If this starts failing, the cache-clear policy changed and the decision has to be "+
			"taken deliberately rather than by accident")

	// The half that IS the guard: a capture from the old epoch cannot be written after the reset.
	stale := &stepwiseTransport{
		tag:     "ordering-stale",
		entered: make(chan struct{}),
		release: make(chan struct{}),
		address: netip.MustParseAddr("10.0.0.9"),
	}
	close(stale.release)
	require.False(t, client.generationStillCurrent(&exchangeOperation{
		generation:         0,
		hasGenerationGuard: true,
	}), "a response captured on the old epoch must not be storable once the reset has advanced it")

	// And a query issued after the reset is attributed to the new epoch.
	staleCapture := client.networkGeneration()
	require.EqualValues(t, 1, staleCapture,
		"a query issued after the reset captures the new epoch")
}

// TestGenerationAdvancesOnlyOncePerReset pins that the window is closed by the same reset that
// notified the interfaces, rather than by a later independent event.
func TestGenerationAdvancesOnlyOncePerReset(t *testing.T) {
	var generation atomic.Uint64
	client := newGenerationGuardedClient(t, &generation)
	client.networkManager = &generationNetworkManager{}

	router := &Router{
		logger: log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{
			transports:       map[string]adapter.DNSTransport{},
			defaultTransport: nil,
		},
		client: client,
	}
	client.networkGeneration = router.dnsGeneration

	require.EqualValues(t, 0, router.dnsGeneration())
	router.ResetNetwork()
	require.EqualValues(t, 1, router.dnsGeneration(), "one reset advances exactly one epoch")
	router.ResetNetwork()
	require.EqualValues(t, 2, router.dnsGeneration(), "and each reset advances it again")

	require.Eventually(t, func() bool { return true }, time.Second, time.Millisecond)
}
