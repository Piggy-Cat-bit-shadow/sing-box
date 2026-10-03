package route

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for the Direct Fast Path eligibility predicate.
//
// # Why a matrix rather than a few cases
//
// This predicate is an allow-list guarding four correctness boundaries: DNS hijack, Fake-IP,
// dynamic-destination UDP, and anything needing sniff/resolve/override semantics. Every one of
// those fails CLOSED here, so the risk is not that a wrong connection is bypassed by a missing
// condition - it is that a later change relaxes a condition without anyone noticing. The matrix
// pins each condition individually.

// --- fakes ---------------------------------------------------------------------------

// plainDirectOutbound models an outbound with no dial configuration at all.
type plainDirectOutbound struct {
	adapter.Outbound
	canBypass atomic.Int32
	calls     atomic.Int32
}

func (o *plainDirectOutbound) Type() string      { return C.TypeDirect }
func (o *plainDirectOutbound) Tag() string       { return "direct" }
func (o *plainDirectOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *plainDirectOutbound) CanBypass(network string, destination netip.Addr) bool {
	o.calls.Add(1)
	if o.canBypass.Load() == 1 {
		return true
	}
	return false
}

// configuredDirectOutbound models a direct outbound that DOES carry dial configuration, so it
// must never be bypassed.
type configuredDirectOutbound struct {
	adapter.Outbound
	calls atomic.Int32
}

func (o *configuredDirectOutbound) Type() string      { return C.TypeDirect }
func (o *configuredDirectOutbound) Tag() string       { return "direct-configured" }
func (o *configuredDirectOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *configuredDirectOutbound) CanBypass(string, netip.Addr) bool {
	o.calls.Add(1)
	return false
}

// nonBypassableOutbound models a proxy: it does not implement the capability at all.
type nonBypassableOutbound struct {
	adapter.Outbound
}

func (o *nonBypassableOutbound) Type() string      { return "socks" }
func (o *nonBypassableOutbound) Tag() string       { return "proxy" }
func (o *nonBypassableOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

// stubOutboundManager serves outbounds by tag and provides a default.
type stubOutboundManager struct {
	byTag map[string]adapter.Outbound
	def   adapter.Outbound
}

func (m *stubOutboundManager) Start(stage adapter.StartStage) error { return nil }
func (m *stubOutboundManager) Close() error                         { return nil }
func (m *stubOutboundManager) Outbounds() []adapter.Outbound        { return nil }
func (m *stubOutboundManager) Remove(tag string) error              { return nil }
func (m *stubOutboundManager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

func (m *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.byTag[tag]
	return o, ok
}

func (m *stubOutboundManager) Default() adapter.Outbound { return m.def }

// eligibleRouter builds a Router whose default outbound can bypass.
func eligibleRouter(t *testing.T) (*Router, *plainDirectOutbound) {
	t.Helper()
	outbound := &plainDirectOutbound{}
	outbound.canBypass.Store(1)
	return &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: outbound},
	}, outbound
}

// fastBypassMetadata is the minimal context that may be bypassed: a TUN TCP flow to a literal
// address with nothing else set.
func fastBypassMetadata(network string, destination M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound:     "tun-in",
		InboundType: C.TypeTun,
		Network:     network,
		Source:      M.ParseSocksaddr("192.168.1.2:12345"),
		Destination: destination,
	}
}

// --- TCP matrix (§41) -----------------------------------------------------------------

func TestFastBypassPlainDirectTCPEligible(t *testing.T) {
	router, outbound := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.Equal(t, adapter.PreMatchBypass, result.Action,
		"a plain direct TUN TCP flow to a literal address must take the fast path")
	require.EqualValues(t, 1, outbound.calls.Load(),
		"the outbound capability must have been consulted")
}

func TestFastBypassPlainDirectIPv6Eligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("[2606:2800:220:1:248:1893:25c8:1946]:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.Equal(t, adapter.PreMatchBypass, result.Action,
		"IPv6 literals must be eligible exactly like IPv4")
}

func TestFastBypassConfiguredDirectIsIneligible(t *testing.T) {
	// A direct outbound with bind addresses, routing marks, TFO or any other dial option is not
	// equivalent to a plain connect.
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: &configuredDirectOutbound{}},
	}

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a direct outbound carrying dial configuration must not be bypassed")
}

func TestFastBypassProxyIsIneligible(t *testing.T) {
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: &nonBypassableOutbound{}},
	}

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a proxy outbound must never be bypassed")
}

func TestFastBypassFakeIPIsIneligible(t *testing.T) {
	// A FakeIP address is a placeholder owned by the virtual range. Sending it to the OS routing
	// table would route it somewhere meaningless, and translating it back is the userspace
	// path's job.
	router, outbound := eligibleRouter(t)

	destination := M.ParseSocksaddr("198.18.0.1:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.FakeIP = true

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a Fake-IP destination must never be bypassed")
	require.EqualValues(t, 0, outbound.calls.Load(),
		"the Fake-IP check must short-circuit before consulting the outbound")
}

func TestFastBypassDomainDestinationIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("example.com:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a domain destination still needs resolution and must not be bypassed")
}

func TestFastBypassSniffedDomainIsIneligible(t *testing.T) {
	// This is the dual-stack recovery boundary. A literal destination with a recovered domain
	// may use literal recovery, which lives in the dialer; bypassing would skip it entirely.
	router, outbound := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.Domain = "example.com"

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a literal destination with a sniffed domain must stay on the slow path so dual-stack "+
			"recovery is preserved")
	require.EqualValues(t, 0, outbound.calls.Load())
}

func TestFastBypassResolvedCandidatesAreIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a populated candidate list means resolve/recovery already took part")
}

func TestFastBypassDestinationOverrideIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	packetDestination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, packetDestination)
	// A rule rewrote the destination to something else.
	metadata.Destination = M.ParseSocksaddr("93.184.216.99:443")

	result := router.preMatchFlow(context.Background(), &metadata, packetDestination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a rewritten destination must be dialled by the userspace path, not bypassed")
}

func TestFastBypassRouteOriginalDestinationIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.RouteOriginalDestination = M.ParseSocksaddr("93.184.216.34:443")

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a tracked original destination means routing already rewrote something")
}

func TestFastBypassTrackerIsIneligible(t *testing.T) {
	// A bypassed flow never reaches a tracker, so traffic statistics and the connections API
	// would silently lose it.
	router, _ := eligibleRouter(t)
	router.trackers = []adapter.ConnectionTracker{&noopTracker{}}

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"an active tracker must disable the fast path rather than silently lose accounting")
}

func TestFastBypassNonTunInboundIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.InboundType = C.TypeMixed

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"v1 targets TUN only; other inbounds keep their existing path")
}

func TestFastBypassICMPIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34")
	metadata := fastBypassMetadata(N.NetworkICMP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"ICMP keeps its existing Flow semantics")
}

// --- UDP matrix (§42) -----------------------------------------------------------------

func TestFastBypassPlainUDPEligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("8.8.4.4:12345")
	metadata := fastBypassMetadata(N.NetworkUDP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.Equal(t, adapter.PreMatchBypass, result.Action,
		"a plain direct TUN UDP flow to a literal address must take the fast path")
}

func TestFastBypassUDPConnectIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("8.8.4.4:12345")
	metadata := fastBypassMetadata(N.NetworkUDP, destination)
	metadata.UDPConnect = true

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"connected UDP has socket and NAT semantics this optimisation does not reproduce")
}

func TestFastBypassUoTDynamicDestinationIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("8.8.4.4:12345")
	metadata := fastBypassMetadata(N.NetworkUDP, destination)
	metadata.UoTDatagramDestinations = true

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a per-datagram UoT session has no single fixed destination and must not be bypassed")
}

func TestFastBypassCustomUDPTimeoutIsIneligible(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("8.8.4.4:12345")
	metadata := fastBypassMetadata(N.NetworkUDP, destination)
	metadata.UDPTimeout = 30 * time.Second

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a custom UDP timeout is applied by the userspace path and has no native equivalent here")
}

func TestFastBypassNetworkOptionsAreIneligible(t *testing.T) {
	strategy := C.NetworkStrategy(C.NetworkStrategyDefault)
	cases := map[string]func(*adapter.InboundContext){
		"network strategy":      func(m *adapter.InboundContext) { m.NetworkStrategy = &strategy },
		"network type":          func(m *adapter.InboundContext) { m.NetworkType = []C.InterfaceType{C.InterfaceTypeWIFI} },
		"fallback network type": func(m *adapter.InboundContext) { m.FallbackNetworkType = []C.InterfaceType{C.InterfaceTypeCellular} },
		"fallback delay":        func(m *adapter.InboundContext) { m.FallbackDelay = time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := eligibleRouter(t)
			destination := M.ParseSocksaddr("93.184.216.34:443")
			metadata := fastBypassMetadata(N.NetworkTCP, destination)
			mutate(&metadata)

			result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
			require.NotEqual(t, adapter.PreMatchBypass, result.Action,
				"network selection and fallback are dialer behaviour a bypass does not perform")
		})
	}
}

func TestFastBypassTLSOptionsAreIneligible(t *testing.T) {
	cases := map[string]func(*adapter.InboundContext){
		"tls fragment":        func(m *adapter.InboundContext) { m.TLSFragment = true },
		"tls record fragment": func(m *adapter.InboundContext) { m.TLSRecordFragment = true },
		"tls spoof":           func(m *adapter.InboundContext) { m.TLSSpoof = "example.com" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := eligibleRouter(t)
			destination := M.ParseSocksaddr("93.184.216.34:443")
			metadata := fastBypassMetadata(N.NetworkTCP, destination)
			mutate(&metadata)

			result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
			require.NotEqual(t, adapter.PreMatchBypass, result.Action,
				"TLS rewriting happens in the userspace path; bypassing would disable it silently")
		})
	}
}

// --- chain length (§24) ---------------------------------------------------------------

func TestFastBypassGroupChainIsIneligible(t *testing.T) {
	// A group introduces selection, lifecycle and accounting of its own. Bypassing it would skip
	// all of that even though the selected outbound is direct.
	direct := &plainDirectOutbound{}
	direct.canBypass.Store(1)
	group := &stubGroup{selected: direct}

	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: group},
	}

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
	require.NotEqual(t, adapter.PreMatchBypass, result.Action,
		"a connection through a group must not be bypassed, even when it selects direct")
}

// stubGroup is an outbound group selecting a fixed member.
type stubGroup struct {
	adapter.Outbound
	selected adapter.Outbound
}

func (g *stubGroup) Type() string      { return C.TypeSelector }
func (g *stubGroup) Tag() string       { return "group" }
func (g *stubGroup) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
func (g *stubGroup) Selected(network string) adapter.Outbound {
	return g.selected
}

// noopTracker satisfies the tracker interface without observing anything.
type noopTracker struct{}

func (noopTracker) Start(stage adapter.StartStage) error { return nil }
func (noopTracker) Close() error                         { return nil }
func (noopTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	return conn
}
func (noopTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	return conn
}
func (noopTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}

// --- benchmarks and allocation guarantees (§39, §47, §79) -----------------------------

// TestFastBypassPredicateDoesNotAllocate is the hard allocation requirement.
//
// This predicate runs on every pre-match for every rule that routes to an outbound, and the
// overwhelmingly common outcome is a miss. A miss that allocated would add cost to exactly the
// traffic that gains nothing from the optimisation.
func TestFastBypassPredicateDoesNotAllocate(t *testing.T) {
	router, _ := eligibleRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	chain := []adapter.Outbound{router.outbound.Default()}
	outbound := chain[0]

	// The eligible path must not allocate either: a hit that allocated would still hand the
	// saving to a manual GC.
	allocs := testing.AllocsPerRun(1000, func() {
		_ = router.canFastBypass(&metadata, destination, chain, outbound)
	})
	require.Zero(t, allocs,
		"the fast-path predicate must not allocate; measured %.2f allocs/op", allocs)

	// And the common miss, which runs far more often.
	missMetadata := fastBypassMetadata(N.NetworkTCP, destination)
	missMetadata.Domain = "example.com"
	missAllocs := testing.AllocsPerRun(1000, func() {
		_ = router.canFastBypass(&missMetadata, destination, chain, outbound)
	})
	require.Zero(t, missAllocs,
		"the ineligible path must not allocate; measured %.2f allocs/op", missAllocs)
}

// BenchmarkCanFastBypassEligible measures the hit path.
func BenchmarkCanFastBypassEligible(b *testing.B) {
	router, _ := eligibleRouter(&testing.T{})
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	chain := []adapter.Outbound{router.outbound.Default()}
	outbound := chain[0]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !router.canFastBypass(&metadata, destination, chain, outbound) {
			b.Fatal("expected eligible")
		}
	}
}

// BenchmarkCanFastBypassIneligibleEarlyExit measures the cheapest miss: a condition that fails
// before any real work, which is the case for most proxied traffic.
func BenchmarkCanFastBypassIneligibleEarlyExit(b *testing.B) {
	router, _ := eligibleRouter(&testing.T{})
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.InboundType = C.TypeMixed
	chain := []adapter.Outbound{router.outbound.Default()}
	outbound := chain[0]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if router.canFastBypass(&metadata, destination, chain, outbound) {
			b.Fatal("expected ineligible")
		}
	}
}

// BenchmarkCanFastBypassIneligibleLateExit measures the most expensive miss: every cheap
// condition passes and the outbound is consulted before the connection is rejected on a
// metadata condition. This is the worst case a fast-path miss can cost.
func BenchmarkCanFastBypassIneligibleLateExit(b *testing.B) {
	router, _ := eligibleRouter(&testing.T{})
	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	metadata.FakeIP = true
	chain := []adapter.Outbound{router.outbound.Default()}
	outbound := chain[0]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if router.canFastBypass(&metadata, destination, chain, outbound) {
			b.Fatal("expected ineligible")
		}
	}
}

// BenchmarkDirectCanBypass measures the outbound-level check on its own, which the router calls
// once per eligible-looking connection.
func BenchmarkDirectCanBypass(b *testing.B) {
	outbound := &plainDirectOutbound{}
	outbound.canBypass.Store(1)
	destination := netip.MustParseAddr("93.184.216.34")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !outbound.CanBypass(N.NetworkTCP, destination) {
			b.Fatal("expected bypassable")
		}
	}
}

// TestFastPathHitSimulation is the flow-scale proof (§48, §80).
//
// A microbenchmark says the predicate is cheap. It does not say the userspace stages are
// actually skipped. This drives many eligible flows through the predicate and counts the
// outcomes, so the claim "N eligible flows produce zero slow-path decisions" is measured rather
// than asserted from a single case.
func TestFastPathHitSimulation(t *testing.T) {
	router, outbound := eligibleRouter(t)

	const flows = 10000

	destinations := []string{
		"93.184.216.34:443",
		"1.1.1.1:53",
		"8.8.4.4:12345",
		"[2606:4700:4700::1111]:443",
	}

	var bypass, slow int
	networks := []string{N.NetworkTCP, N.NetworkUDP}
	for i := 0; i < flows; i++ {
		network := networks[i%len(networks)]
		destination := M.ParseSocksaddr(destinations[i%len(destinations)])
		metadata := fastBypassMetadata(network, destination)

		result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
		if result.Action == adapter.PreMatchBypass {
			bypass++
		} else {
			slow++
		}
	}

	require.Equal(t, flows, bypass,
		"every eligible flow must take the fast path")
	require.Zero(t, slow,
		"an eligible flow must never fall to the slow path")
	require.EqualValues(t, flows, outbound.calls.Load(),
		"the outbound capability must be consulted once per flow")

	t.Logf("hit simulation: %d flows, %d bypass, %d slow", flows, bypass, slow)
}

// TestFastPathMissSimulation counts the negative case, so the hit simulation above cannot be
// satisfied by a predicate that bypasses everything.
func TestFastPathMissSimulation(t *testing.T) {
	router, _ := eligibleRouter(t)

	const flows = 10000

	// Every flow here carries a condition that disqualifies it.
	ineligible := []func(*adapter.InboundContext){
		func(m *adapter.InboundContext) { m.FakeIP = true },
		func(m *adapter.InboundContext) { m.Domain = "example.com" },
		func(m *adapter.InboundContext) { m.UDPConnect = true },
		func(m *adapter.InboundContext) { m.UoTDatagramDestinations = true },
		func(m *adapter.InboundContext) { m.UDPTimeout = time.Minute },
		func(m *adapter.InboundContext) {
			m.DestinationAddresses = []netip.Addr{netip.MustParseAddr("93.184.216.34")}
		},
	}

	var bypass, slow int
	for i := 0; i < flows; i++ {
		destination := M.ParseSocksaddr("93.184.216.34:443")
		metadata := fastBypassMetadata(N.NetworkTCP, destination)
		ineligible[i%len(ineligible)](&metadata)

		result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "")
		if result.Action == adapter.PreMatchBypass {
			bypass++
		} else {
			slow++
		}
	}

	require.Zero(t, bypass,
		"an ineligible flow must never take the fast path; a bypass here would mean the "+
			"correctness boundary leaked")
	require.Equal(t, flows, slow)

	t.Logf("miss simulation: %d flows, %d bypass, %d slow", flows, bypass, slow)
}
