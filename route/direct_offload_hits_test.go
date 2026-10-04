package route

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Direct Offload hit reporting.
//
// # What is measured, and against what
//
// Two configurations, because the answer differs and only one of them is realistic:
//
//	minimal     a direct outbound carrying domain_resolver, which is what the shipped topology
//	            declares, and no traffic-control API
//	dashboard   the same, with a connection tracker attached as the Clash API and the dashboard do
//
// The point of the second is that a dashboard is the common case and the tracker guard is absolute:
// the fast path is refused for every flow, not only for the flows a dashboard would want to see.
// That is the correct first-round behaviour - silently losing connection statistics is not an
// acceptable optimisation - but it means the L1 gain is real only for setups without an API, and
// reporting a hit rate from the minimal configuration alone would be misleading.
//
// # What the numbers are not
//
// The flow mix below is a MODEL, not a measurement of anyone's traffic. It is a desktop proxy's
// plausible shape: mostly literal-IP TCP, some literal UDP, and a minority that needs DNS or
// unmapping. The per-shape verdicts are exact; the weighted total is only as good as the weights,
// which is why both are printed.

// productionDirectOutbound models the shipped topology's direct outbound: the real profile built
// from the real option value, behind the router's own capability check.
//
// It wraps the profile rather than the protocol/direct outbound so this file stays in the route
// package; protocol/direct has its own test that the outbound is wired to the same profile.
type productionDirectOutbound struct {
	adapter.Outbound
	semantics dialer.SocketSemantics
}

func newProductionDirectOutbound() *productionDirectOutbound {
	return &productionDirectOutbound{
		semantics: dialer.NativeBypassSemantics(option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				DomainResolver: &option.DomainResolveOptions{Server: "local-agh"},
			},
		}),
	}
}

func (o *productionDirectOutbound) Type() string      { return C.TypeDirect }
func (o *productionDirectOutbound) Tag() string       { return "direct" }
func (o *productionDirectOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *productionDirectOutbound) CanBypass(network string, destination netip.Addr) bool {
	return o.semantics.CanNativeBypass(dialer.NativeBypassFacts{
		Network:              network,
		DestinationIsLiteral: true,
		Destination:          destination,
	})
}

func (o *productionDirectOutbound) BypassBlockers(network string, destination netip.Addr) dialer.NativeBypassBlocker {
	return o.semantics.Blockers(dialer.NativeBypassFacts{
		Network:              network,
		DestinationIsLiteral: true,
		Destination:          destination,
	})
}

// trackerStub is a connection tracker that does nothing but pass connections through. Its presence
// is the whole point: the router refuses the fast path on the existence of a tracker, not on what
// it does with the connection.
type trackerStub struct {
	adapter.ConnectionTracker
}

func (t *trackerStub) RoutedConnection(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	return conn
}

func (t *trackerStub) RoutedPacketConnection(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return conn
}

func (t *trackerStub) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

// offloadFlow is one shape of traffic, with the weight the model gives it.
type offloadFlow struct {
	name          string
	weight        int
	network       string
	destination   M.Socksaddr
	sniffedDomain string
	fakeIP        bool
	udpConnect    bool
}

func offloadFlowMix() []offloadFlow {
	return []offloadFlow{
		{
			name: "literal IPv4 TCP", weight: 55, network: N.NetworkTCP,
			destination: M.ParseSocksaddr("93.184.216.34:443"),
		},
		{
			name: "literal IPv6 TCP", weight: 15, network: N.NetworkTCP,
			destination: M.ParseSocksaddr("[2606:2800:220:1:248:1893:25c8:1946]:443"),
		},
		{
			name: "literal IPv4 UDP", weight: 15, network: N.NetworkUDP,
			destination: M.ParseSocksaddr("8.8.8.8:443"),
		},
		{
			name: "sniffed domain TCP", weight: 8, network: N.NetworkTCP,
			destination: M.ParseSocksaddr("93.184.216.34:443"),
			// The destination is a literal, but a domain was recovered for it, which is what makes
			// dual-stack recovery reachable. It must not be bypassed.
			sniffedDomain: "example.com",
		},
		{
			name: "FakeIP TCP", weight: 5, network: N.NetworkTCP,
			destination: M.ParseSocksaddr("198.18.0.5:443"),
			fakeIP:      true,
		},
		{
			name: "connected UDP", weight: 2, network: N.NetworkUDP,
			destination: M.ParseSocksaddr("8.8.8.8:443"),
			udpConnect:  true,
		},
	}
}

// offloadRouter builds a router whose default outbound is the production-shaped direct outbound.
//
// It takes no *testing.T so that tests and benchmarks share one construction path: a benchmark built
// from a slightly different router would report a slightly different number for a slightly different
// code path.
func offloadRouter(withDashboard bool) (*Router, *productionDirectOutbound) {
	outbound := newProductionDirectOutbound()
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: outbound},
	}
	if withDashboard {
		router.AppendTracker(&trackerStub{})
	}
	return router, outbound
}

// TestDirectOffloadHitReport is the report the round is measured by.
//
// It runs the real pre-match entry point for each flow shape and records the verdict, so the number
// is produced by production code rather than by a description of it.
func TestDirectOffloadHitReport(t *testing.T) {
	for _, configuration := range []struct {
		name          string
		withDashboard bool
	}{
		{"minimal", false},
		{"dashboard-enabled", true},
	} {
		t.Run(configuration.name, func(t *testing.T) {
			router, outbound := offloadRouter(configuration.withDashboard)
			chain := []adapter.Outbound{outbound}

			results := make(map[string]offloadResult)
			weightedHits := 0
			totalWeight := 0
			for _, flow := range offloadFlowMix() {
				metadata := fastBypassMetadata(flow.network, flow.destination)
				metadata.Domain = flow.sniffedDomain
				metadata.FakeIP = flow.fakeIP
				metadata.UDPConnect = flow.udpConnect

				verdict := router.canFastBypass(&metadata, flow.destination, chain, outbound)
				entry := offloadResult{verdict: verdict}
				if verdict == BypassRefusedOutboundSemantics {
					entry.detail = bypassBlockerDetail(outbound, flow.network, flow.destination.Addr).String()
				}
				results[flow.name] = entry
				totalWeight += flow.weight
				if verdict.BypassAllowed() {
					weightedHits += flow.weight
				}
				t.Logf("%-22s %-9s %s", flow.name, verdict, entry.detail)
			}

			t.Logf("L1 hit by flow count:   %d/%d shapes", countHits(results), len(results))
			t.Logf("L1 hit by model weight: %d%%", weightedHits*100/totalWeight)

			if !configuration.withDashboard {
				// The literal flows are the ones this round exists for. Every one of them must be
				// bypassable, or the profile did not do its job.
				require.True(t, results["literal IPv4 TCP"].verdict.BypassAllowed())
				require.True(t, results["literal IPv6 TCP"].verdict.BypassAllowed())
				require.True(t, results["literal IPv4 UDP"].verdict.BypassAllowed())

				// And the policy boundaries are unmoved: each of these is refused for its own
				// reason, not by accident.
				require.Equal(t, BypassRefusedSniffedDomain, results["sniffed domain TCP"].verdict)
				require.Equal(t, BypassRefusedFakeIP, results["FakeIP TCP"].verdict)
				require.Equal(t, BypassRefusedUDPConnect, results["connected UDP"].verdict)
			} else {
				// With a dashboard attached nothing is bypassed. The three literal flows - the ones
				// the profile change made eligible - now report the tracker, which is the finding
				// worth stating plainly: the guard is not selective, it refuses shapes that a
				// dashboard has no particular interest in.
				require.Equal(t, BypassRefusedTracker, results["literal IPv4 TCP"].verdict)
				require.Equal(t, BypassRefusedTracker, results["literal IPv6 TCP"].verdict)
				require.Equal(t, BypassRefusedTracker, results["literal IPv4 UDP"].verdict)

				// The shapes refused earlier in the allow-list keep their own reason. Reporting the
				// tracker for them would be misleading: removing the API would not make them
				// eligible.
				require.Equal(t, BypassRefusedSniffedDomain, results["sniffed domain TCP"].verdict)
				require.Equal(t, BypassRefusedFakeIP, results["FakeIP TCP"].verdict)
				require.Equal(t, BypassRefusedUDPConnect, results["connected UDP"].verdict)
			}
		})
	}
}

// offloadResult is one shape's verdict, with the outbound-level detail when there is any.
type offloadResult struct {
	verdict BypassVerdict
	detail  string
}

func countHits(results map[string]offloadResult) int {
	hits := 0
	for _, entry := range results {
		if entry.verdict.BypassAllowed() {
			hits++
		}
	}
	return hits
}

// TestDirectOffloadRefusalIsAttributed pins that a refusal names its cause.
//
// The alternative - a boolean - would leave "why is my direct traffic not bypassed?" unanswerable,
// and the answer differs per cause: an unclassified option is a bug, a routing mark is a
// configuration choice, and a tracker is a missing feature.
func TestDirectOffloadRefusalIsAttributed(t *testing.T) {
	destination := M.ParseSocksaddr("93.184.216.34:443")

	// An outbound whose options set a bind interface cannot say anything but "not equivalent", and
	// the detail names the option rather than the outbound.
	bound := &productionDirectOutbound{
		semantics: dialer.NativeBypassSemantics(option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "en0"},
		}),
	}
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &stubOutboundManager{def: bound},
	}
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	verdict := router.canFastBypass(&metadata, destination, []adapter.Outbound{bound}, bound)
	require.Equal(t, BypassRefusedOutboundSemantics, verdict)
	require.Contains(t, bypassBlockerDetail(bound, N.NetworkTCP, destination.Addr).String(), "bind_interface")

	// A condition the router owns reports itself instead.
	metadata.FakeIP = true
	require.Equal(t,
		BypassRefusedFakeIP,
		router.canFastBypass(&metadata, destination, []adapter.Outbound{bound}, bound),
		"the earlier condition in the allow-list is the one reported")
}

// boundDirectSemantics is a profile that refuses: the outbound in the attribution tests carries a
// bind interface, which no native connect can reproduce.
func boundDirectSemantics() dialer.SocketSemantics {
	return dialer.NativeBypassSemantics(option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: "en0"},
	})
}
