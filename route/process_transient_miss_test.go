package route

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/stretchr/testify/require"
)

// Tests for a transient process-lookup failure at the fast-path boundary.
//
// # The defect these pin
//
// canFastBypass decides whether a flow may leave userspace irreversibly. PreMatch walks the FULL
// rule set, so a process rule is evaluated against metadata.ProcessInfo. When the process lookup
// fails transiently - which it can, and which the cache is there to smooth over - ProcessInfo stays
// nil, the process rule does not match, and the flow falls through to the default outbound.
//
// If that default is direct, the flow takes a native bypass and never re-enters userspace. The
// route decision was then made on the absence of metadata rather than on its content: "unknown"
// was read as "does not match a process rule".
//
// The rule is that metadata whose absence prevents PROVING a bypass is safe must fail closed.

// flakyProcessSearcher fails its first calls and succeeds afterwards.
type flakyProcessSearcher struct {
	calls   atomic.Int32
	failFor int32
	result  *adapter.ConnectionOwner
}

func (s *flakyProcessSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	if s.calls.Add(1) <= s.failFor {
		return nil, errProcessLookupUnavailable
	}
	return s.result, nil
}

func (s *flakyProcessSearcher) Close() error { return nil }
func (s *flakyProcessSearcher) ResetCache()  {}

var errProcessLookupUnavailable = errors.New("process lookup temporarily unavailable")

// TestTransientProcessMissDoesNotBecomeADirectBypass is §41, §42.
//
// A process rule selects the proxy outbound. The lookup fails on the first attempt. The flow must
// NOT be handed to the platform as a direct bypass on that basis.
func TestTransientProcessMissDoesNotBecomeADirectBypass(t *testing.T) {
	searcher := &flakyProcessSearcher{
		failFor: 1,
		result: &adapter.ConnectionOwner{
			ProcessPaths: []string{"/usr/bin/curl"},
		},
	}

	router := newProcessTestRouter(searcher)

	metadata := adapter.InboundContext{
		InboundType: C.TypeTun,
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFrom(netip.MustParseAddr("192.168.1.2"), 40000),
		Destination: M.SocksaddrFrom(netip.MustParseAddr("93.184.216.34"), 443),
	}

	// First attempt: the lookup fails, so ProcessInfo stays nil.
	router.searchProcessInfo(context.Background(), &metadata)

	require.Nil(t, metadata.ProcessInfo,
		"the first lookup fails, so there is no process info - this is the transient miss")

	// The decision that actually matters is canFastBypass, which is what lets a flow leave
	// userspace irreversibly. It must refuse.
	outbound := &plainDirectOutbound{}
	outbound.canBypass.Store(1)
	packetDestination := metadata.Destination

	require.False(t, router.canFastBypass(&metadata, packetDestination,
		[]adapter.Outbound{outbound}, outbound).BypassAllowed(),
		"a process lookup that could not be completed must not become a native bypass; the "+
			"decision would then be made by missing metadata rather than by the configuration, "+
			"and a process rule selecting a proxy would be silently skipped")

	// The same call with process metadata available DOES bypass, which is what makes the
	// assertion above about the missing metadata rather than about the fixture.
	metadata.ProcessInfo = &adapter.ConnectionOwner{ProcessPaths: []string{"/usr/bin/curl"}}
	require.True(t, router.canFastBypass(&metadata, packetDestination,
		[]adapter.Outbound{outbound}, outbound).BypassAllowed(),
		"with the process metadata obtained the bypass is provable and must be allowed")
	metadata.ProcessInfo = nil

	// The second attempt succeeds, showing the miss really was transient. The negative result is
	// cached for a short window - which is exactly why a transient failure can persist long enough
	// to matter - so the cache is cleared to model the next window.
	metadata.ProcessInfo = nil
	router.processCache.Purge()
	router.searchProcessInfo(context.Background(), &metadata)
	require.NotNil(t, metadata.ProcessInfo,
		"the second lookup succeeds, which is what makes the first miss transient rather than "+
			"a permanent condition")
}

// TestFailedProcessLookupIsDistinguishable is the underlying property.
//
// "The lookup failed" and "the lookup found nothing" must not be the same value, or a caller cannot
// tell an unprovable bypass from a proven absence.
func TestFailedProcessLookupIsDistinguishable(t *testing.T) {
	searcher := &flakyProcessSearcher{failFor: 1, result: &adapter.ConnectionOwner{ProcessPaths: []string{"/usr/bin/curl"}}}
	router := newProcessTestRouter(searcher)

	metadata := adapter.InboundContext{
		InboundType: C.TypeTun,
		Network:     N.NetworkTCP,
		Source:      M.SocksaddrFrom(netip.MustParseAddr("192.168.1.2"), 40000),
		Destination: M.SocksaddrFrom(netip.MustParseAddr("93.184.216.34"), 443),
	}

	router.searchProcessInfo(context.Background(), &metadata)
	require.False(t, router.processMetadataIsProven(&metadata),
		"a failed lookup must leave the metadata UNPROVEN")

	// With no searcher at all there is nothing to prove and nothing to lose: a configuration with
	// no process rules cannot be affected by a missing lookup.
	noSearcher := newProcessTestRouter(nil)
	require.True(t, noSearcher.processMetadataIsProven(&metadata),
		"without a searcher no process rule can exist, so the bypass is not unproven")
}

// localSourcePlatform reports one address as belonging to this host, so the process search
// considers the test's source local without needing a real network manager.
type localSourcePlatform struct {
	adapter.PlatformInterface
	address netip.Addr
}

func (p *localSourcePlatform) MyInterfaceAddress() []netip.Addr { return []netip.Addr{p.address} }

// newProcessTestRouter builds a router with the process cache the real constructor installs.
func newProcessTestRouter(searcher process.Searcher) *Router {
	router := &Router{
		logger:            log.NewNOPFactory().Logger(),
		processSearcher:   searcher,
		platformInterface: &localSourcePlatform{address: netip.MustParseAddr("192.168.1.2")},
	}
	if searcher != nil {
		router.processCache = common.Must1(freelru.New[processCacheKey, processCacheEntry](
			256, maphash.NewHasher[processCacheKey]().Hash32, true))
		router.processCache.SetLifetime(200 * time.Millisecond)
	}
	return router
}
