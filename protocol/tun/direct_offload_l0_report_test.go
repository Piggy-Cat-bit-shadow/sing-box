package tun

import (
	"net/netip"
	"testing"

	tun "github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// L0 hit reporting.
//
// # Where L0 sits, and why it is not "the router, then a bypass"
//
// JudgeFlow decides in this order: DNS hijack, then the route sets, then the router. The route sets
// therefore take a flow the router never sees, and the correct description of the layer is
// "authoritative IP-only policy that is already encoded in the TUN's own routing configuration" -
// not "policy that ran first". Saying the latter would suggest L0 can express rules it cannot: it
// knows an address and nothing else, so a domain, a process or a protocol condition cannot be
// honoured there at all.
//
// What L0 can do is cheap, and what it costs is nothing per byte. What it cannot do is be trusted
// with a synthetic address, which is the boundary the FakeIP guard in JudgeFlow draws.

// offloadL0Flow is one shape of traffic for the L0 report.
type offloadL0Flow struct {
	name        string
	destination netip.AddrPort
	fakeIP      bool
}

func offloadL0Mix() []offloadL0Flow {
	return []offloadL0Flow{
		{name: "inside the include set", destination: netip.MustParseAddrPort("10.1.2.3:443")},
		{name: "outside the include set", destination: netip.MustParseAddrPort("93.184.216.34:443")},
		{name: "in the exclude set", destination: netip.MustParseAddrPort("198.20.0.5:443")},
		{name: "FakeIP in the exclude set", destination: netip.MustParseAddrPort("198.18.0.5:443"), fakeIP: true},
	}
}

// TestL0HitReport measures what the route sets carry, for the two ways a TUN can be configured with
// them, and reports the layer's hit rate.
//
// The router is deliberately made non-bypassing so that "reached the router" and "was bypassed" are
// distinguishable: the layer being measured is the one that answers without asking the router at all.
func TestL0HitReport(t *testing.T) {
	includeSet := []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}
	excludeSet := []*netipx.IPSet{ipSetFrom(t, "198.16.0.0/12")}

	for _, configuration := range []struct {
		name        string
		routeSet    []*netipx.IPSet
		excludeSet  []*netipx.IPSet
		expectBypas map[string]bool
	}{
		{
			name:        "no route sets",
			expectBypas: map[string]bool{},
		},
		{
			name:        "route_address_set 10/8",
			routeSet:    includeSet,
			expectBypas: map[string]bool{"outside the include set": true},
		},
		{
			name:        "route_exclude_address_set 198.16/12",
			excludeSet:  excludeSet,
			expectBypas: map[string]bool{"in the exclude set": true},
		},
	} {
		t.Run(configuration.name, func(t *testing.T) {
			bypassed := 0
			for _, flow := range offloadL0Mix() {
				inbound, router := hijackTestInbound(t, nil, false)
				router.bypassable.Store(false)
				inbound.fakeIPStore = &fakeIPStoreStub{inet4: netip.MustParsePrefix("198.18.0.0/15")}
				inbound.routeAddressSet = configuration.routeSet
				inbound.routeExcludeAddressSet = configuration.excludeSet

				verdict := inbound.JudgeFlow(
					uint8(headerTCP),
					netip.MustParseAddrPort("192.168.1.2:40000"),
					flow.destination,
					nil,
				)
				l0Bypass := verdict.Action == tun.ActionBypass
				if l0Bypass {
					bypassed++
				}
				expected, hasExpectation := configuration.expectBypas[flow.name]
				if hasExpectation {
					require.Equal(t, expected, l0Bypass,
						"%s: the route sets are the layer under test", flow.name)
				}
				if flow.fakeIP {
					require.False(t, l0Bypass,
						"a FakeIP placeholder is never carried by the platform's routing table, "+
							"whatever the sets say")
				}
				t.Logf("%-28s L0 bypass: %v (router reached: %v)", flow.name, l0Bypass,
					router.preMatchCalls.Load() == 1)
			}
			t.Logf("L0 hits: %d/%d shapes", bypassed, len(offloadL0Mix()))
		})
	}
}

// TestL0CannotExpressAnythingButAddresses pins what the layer is not.
//
// It is the reason the fast path's eligibility is not "compile the DIRECT rules into a route set".
// A rule with a domain, a process or a protocol condition has no representation here, so a flow that
// such a rule would have matched is bypassed by an ADDRESS-MATCHING set that never saw the rule.
func TestL0CannotExpressAnythingButAddresses(t *testing.T) {
	inbound, router := hijackTestInbound(t, nil, false)
	router.bypassable.Store(false)
	// An include set that does not contain the destination. The destination is a plain public
	// address whose real routing belongs to a rule the router would have matched.
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict := inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		nil,
	)
	require.Equal(t, tun.ActionBypass, verdict.Action)
	require.EqualValues(t, 0, router.preMatchCalls.Load(),
		"the router - and therefore every domain, process and protocol rule in it - was never "+
			"consulted. This is exactly why a DIRECT rule must not be compiled into a route set "+
			"unless it is an authoritative IP-only rule.")
}
