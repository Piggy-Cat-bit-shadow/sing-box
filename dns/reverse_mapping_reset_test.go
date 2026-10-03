package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/stretchr/testify/require"
)

// Tests for the reverse mapping's lifecycle across a network change.
//
// # What the mapping is
//
// A cache of "what name did this address last mean", learned from DNS answers and used by rule
// matching when a flow arrives for a literal address. It is a cache: every entry is re-learned from
// the next answer, and nothing depends on one surviving anything.
//
// # Why a network change invalidates it
//
// With split-horizon or captive-portal DNS the same address can mean a different name on a
// different network. An entry left behind would let a stale name participate in route rule matching
// until its DNS TTL expired.

func newRouterWithReverseMapping(t *testing.T) *Router {
	t.Helper()
	client := NewClient(ClientOptions{Context: context.Background(), Logger: log.NewNOPFactory().Logger()})
	client.Start()
	router := &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{}},
		client:    client,
	}
	router.dnsReverseMapping = common.Must1(freelru.New[netip.Addr, string](
		1024, maphash.NewHasher[netip.Addr]().Hash32, true))
	return router
}

// TestResetNetworkPurgesTheReverseMapping is §54.
func TestResetNetworkPurgesTheReverseMapping(t *testing.T) {
	router := newRouterWithReverseMapping(t)
	address := netip.MustParseAddr("192.0.2.7")

	router.dnsReverseMapping.Add(address, "old.example")

	domain, loaded := router.LookupReverseMapping(address)
	require.True(t, loaded)
	require.Equal(t, "old.example", domain)

	router.ResetNetwork()

	_, loaded = router.LookupReverseMapping(address)
	require.False(t, loaded,
		"a network change must discard the reverse mapping: on the new network the same address "+
			"can mean a different name, and a stale one would feed route rule matching until its "+
			"TTL expired")
}

// TestClearCacheStillPurgesTheReverseMapping is the existing contract, kept.
func TestClearCacheStillPurgesTheReverseMapping(t *testing.T) {
	router := newRouterWithReverseMapping(t)
	address := netip.MustParseAddr("192.0.2.8")

	router.dnsReverseMapping.Add(address, "cached.example")
	router.ClearCache()

	_, loaded := router.LookupReverseMapping(address)
	require.False(t, loaded, "an explicit cache clear must discard the mapping")
}

// TestResetNetworkDoesNotPanicWithoutAMapping covers the nil guard.
func TestResetNetworkDoesNotPanicWithoutAMapping(t *testing.T) {
	router := &Router{
		logger:    log.NewNOPFactory().Logger(),
		transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{}},
	}
	require.NotPanics(t, func() { router.ResetNetwork() },
		"ResetNetwork must tolerate a router built without a reverse mapping")

	require.NotEqual(t, C.DNSTypeTCP, C.DNSTypeUDP)
}
