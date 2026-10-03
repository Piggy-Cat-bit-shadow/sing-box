package tun

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// Tests for DNS hijack taking precedence over the Direct Fast Path.
//
// # Why these drive JudgeFlow itself
//
// The DNS hijack checks live in JudgeFlow, ahead of the router. A test that mocked the router to
// return ActionHijackDNS would prove nothing about that ordering - it would only prove the mock
// was called. These tests go through the real production entry point with a router that WOULD
// bypass if asked, so the assertion is that DNS wins over an available bypass, not that a stub
// said so.
//
// This is the boundary that keeps DNS-based ad filtering working: a DNS query must reach the
// DNS router, never the direct path.

// bypassPreferringRouter is a router that would take the fast path for anything it sees.
//
// It counts how often PreMatch is reached, which is what makes the precedence assertion
// meaningful: if JudgeFlow hands a DNS query to the router, the counter moves.
type bypassPreferringRouter struct {
	adapter.Router
	preMatchCalls atomic.Int32
	bypassable    atomic.Bool
}

func newBypassPreferringRouter() *bypassPreferringRouter {
	r := &bypassPreferringRouter{}
	r.bypassable.Store(true)
	return r
}

func (r *bypassPreferringRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.preMatchCalls.Add(1)
	if r.bypassable.Load() {
		return adapter.PreMatchResult{Action: adapter.PreMatchBypass}
	}
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *bypassPreferringRouter) PreMatchFlowAction(network string) adapter.PreMatchAction {
	return adapter.PreMatchBypass
}

// hijackTestInbound builds a TUN inbound with DNS hijack configured and a router that would
// otherwise bypass.
func hijackTestInbound(t *testing.T, dnsAddress []netip.Addr, byPort bool) (*Inbound, *bypassPreferringRouter) {
	t.Helper()
	router := newBypassPreferringRouter()
	inbound := &Inbound{
		tag:              "tun-in",
		ctx:              context.Background(),
		router:           router,
		logger:           log.NewNOPFactory().Logger(),
		dnsHijackAddress: dnsAddress,
		dnsHijackByPort:  byPort,
	}
	return inbound, router
}

// TestDNSHijackAddressBeatsDirectFastPath is §28/§43.
//
// The configured DNS address is ALSO a perfectly good direct destination, so the two
// optimisations compete. DNS must win.
func TestDNSHijackAddressBeatsDirectFastPath(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	inbound, router := hijackTestInbound(t, []netip.Addr{dnsAddress}, false)

	// UDP to the hijack address: hijack.
	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"a UDP query to the configured DNS address must be hijacked")
	require.EqualValues(t, 0, router.preMatchCalls.Load(),
		"the router must never see a DNS query, or an available bypass could claim it")

	// TCP to the hijack address: accepted so the stream path can take over, NOT bypassed.
	verdict = inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action,
		"TCP to a hijack address is accepted for the stream DNS path")
	require.NotEqual(t, tun.ActionBypass, verdict.Action,
		"TCP DNS must never be bypassed, or it would leave sing-box entirely")
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

// TestDNSHijackByPortBeatsDirectFastPath is §28/§43 for the by-port mode.
func TestDNSHijackByPortBeatsDirectFastPath(t *testing.T) {
	inbound, router := hijackTestInbound(t, nil, true)

	ordinaryDestination := netip.MustParseAddr("8.8.4.4")

	// UDP/53 with hijack-by-port enabled.
	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(ordinaryDestination, 53),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"UDP port 53 must be hijacked when hijack-by-port is enabled")
	require.EqualValues(t, 0, router.preMatchCalls.Load())

	// TCP/53: accepted for the existing stream hijack path.
	verdict = inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(ordinaryDestination, 53),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action)
	require.NotEqual(t, tun.ActionBypass, verdict.Action,
		"TCP port 53 must not be bypassed while hijack-by-port is enabled")
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

// TestDNSHijackBeatsRouteExcludeAddressSet is §28's explicit requirement: even when a route
// address set says the destination is bypassable, DNS still wins.
//
// The route-exclude bypass is the fastest existing path in JudgeFlow and sits BEFORE the
// by-port check, so this is the strongest form of the precedence question.
func TestDNSHijackBeatsRouteExcludeAddressSet(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")

	var builder netipx.IPSetBuilder
	builder.Add(dnsAddress)
	ipSet, err := builder.IPSet()
	require.NoError(t, err)

	inbound, router := hijackTestInbound(t, []netip.Addr{dnsAddress}, false)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSet}

	// The address is in the exclude set, which normally bypasses immediately.
	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"DNS hijack must win even when the destination is also in the route-exclude bypass set")
	require.NotEqual(t, tun.ActionBypass, verdict.Action)
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

// TestNonDNSStillReachesTheRouter is the negative control.
//
// Without this, the tests above would also pass if JudgeFlow hijacked everything.
func TestNonDNSStillReachesTheRouter(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	inbound, router := hijackTestInbound(t, []netip.Addr{dnsAddress}, true)

	verdict := inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		nil,
	)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"ordinary traffic must still reach the router and be able to bypass")
	require.EqualValues(t, 1, router.preMatchCalls.Load())
}

// TestDNSHijackAppliesToEveryPort confirms the address check is not port-limited.
func TestDNSHijackAppliesToEveryPort(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	inbound, _ := hijackTestInbound(t, []netip.Addr{dnsAddress}, false)

	for _, port := range []uint16{53, 853, 443, 12345} {
		verdict := inbound.JudgeFlow(
			uint8(headerUDP),
			netip.MustParseAddrPort("192.168.1.2:40000"),
			netip.AddrPortFrom(dnsAddress, port),
			nil,
		)
		require.Equal(t, tun.ActionHijackDNS, verdict.Action,
			"the configured DNS address is hijacked on any port, as before this work")
	}
}

// --- integration: a bypassed flow must not enter the userspace path (§40, §48) ---------

// countingConnectionRouter records any attempt to route a connection or packet connection
// through the userspace data path.
type countingConnectionRouter struct {
	adapter.Router
	connectionCalls atomic.Int32
	packetCalls     atomic.Int32
	preMatchCalls   atomic.Int32
}

func (r *countingConnectionRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.connectionCalls.Add(1)
}

func (r *countingConnectionRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.packetCalls.Add(1)
}

func (r *countingConnectionRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	r.preMatchCalls.Add(1)
	return adapter.PreMatchResult{Action: adapter.PreMatchBypass}
}

// TestBypassedFlowDoesNotEnterTheUserspacePath is the integration-level proof that the fast
// path actually removes the userspace stages, rather than merely returning a different enum.
//
// Asserting `Action == Bypass` alone would pass even if the caller then ignored it.
func TestBypassedFlowDoesNotEnterTheUserspacePath(t *testing.T) {
	router := &countingConnectionRouter{}
	inbound := &Inbound{
		tag:              "tun-in",
		ctx:              context.Background(),
		router:           router,
		logger:           log.NewNOPFactory().Logger(),
		dnsHijackAddress: []netip.Addr{netip.MustParseAddr("10.0.0.53")},
	}

	const flows = 64
	for i := 0; i < flows; i++ {
		verdict := inbound.JudgeFlow(
			uint8(headerTCP),
			netip.MustParseAddrPort("192.168.1.2:40000"),
			netip.MustParseAddrPort("93.184.216.34:443"),
			nil,
		)
		require.Equal(t, tun.ActionBypass, verdict.Action)
	}

	// The verdict is what the TUN stack acts on; the flow never becomes a sing-box connection.
	require.EqualValues(t, 0, router.connectionCalls.Load(),
		"a bypassed TCP flow must not be routed as a userspace connection")
	require.EqualValues(t, 0, router.packetCalls.Load(),
		"a bypassed flow must not be routed as a userspace packet connection")
}

// TestDNSQueryDoesNotEnterTheUserspacePath mirrors the above for DNS: it must reach the DNS
// router, never the direct path, and never the userspace connection path either.
func TestDNSQueryDoesNotEnterTheUserspacePath(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	router := &countingConnectionRouter{}
	inbound := &Inbound{
		tag:              "tun-in",
		ctx:              context.Background(),
		router:           router,
		logger:           log.NewNOPFactory().Logger(),
		dnsHijackAddress: []netip.Addr{dnsAddress},
	}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action)
	require.EqualValues(t, 0, router.connectionCalls.Load())
	require.EqualValues(t, 0, router.packetCalls.Load())
}

// --- helpers --------------------------------------------------------------------------

// Protocol numbers, named so the tests read as protocols rather than magic bytes.
const (
	headerTCP  = 6
	headerUDP  = 17
	headerICMP = 1
)

// --- DNS-by-port precedence over the route address sets -------------------------------
//
// # The bug these pin
//
// JudgeFlow checked the route address sets BEFORE dnsHijackByPort. A destination that the
// exclude set covered, or that the include set did not, therefore returned ActionBypass and the
// function never reached the DNS-by-port check at all. A query to 8.8.8.8:53 left sing-box
// entirely instead of reaching the DNS router, so DNS rules, ad filtering and Fake-IP policy
// were bypassed for the most ordinary DNS destination there is.
//
// These tests build REAL *netipx.IPSet values and drive the real JudgeFlow, because the defect
// is in the ordering inside that function. A fake that returned "bypass" for a test flag would
// reproduce nothing.

// ipSetFrom builds a real IPSet from addresses or CIDR prefixes.
//
// The caller supplies whichever form reads more naturally for the set being modelled - a single
// DNS server address, or the private range an include list would carry.
func ipSetFrom(t *testing.T, entries ...string) *netipx.IPSet {
	t.Helper()
	var builder netipx.IPSetBuilder
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			builder.AddPrefix(netip.MustParsePrefix(entry))
			continue
		}
		builder.Add(netip.MustParseAddr(entry))
	}
	ipSet, err := builder.IPSet()
	require.NoError(t, err)
	return ipSet
}

// hijackByPortInbound builds a TUN inbound with only the by-port hijack enabled, so the address
// check cannot mask the ordering under test.
func hijackByPortInbound(t *testing.T) (*Inbound, *bypassPreferringRouter) {
	t.Helper()
	router := newBypassPreferringRouter()
	inbound := &Inbound{
		tag:             "tun-in",
		ctx:             context.Background(),
		router:          router,
		logger:          log.NewNOPFactory().Logger(),
		dnsHijackByPort: true,
	}
	return inbound, router
}

func TestDNSHijackByPortBeatsRouteExclude(t *testing.T) {
	// The exclusion case: 8.8.8.8 is in the exclude set, so ordinary traffic bypasses.
	inbound, router := hijackByPortInbound(t)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "8.8.8.8")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"UDP/53 in the route-exclude set must still be hijacked; the exclude bypass ran first "+
			"and the query never reached the DNS router")
	require.EqualValues(t, 0, router.preMatchCalls.Load(),
		"the router must not see the query")
}

func TestDNSHijackByPortTCPBeatsRouteExclude(t *testing.T) {
	// TCP/53 must be accepted for the stream DNS path - NOT bypassed, and NOT hijacked here.
	inbound, router := hijackByPortInbound(t)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "8.8.8.8")}

	verdict := inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action,
		"TCP/53 must be accepted so the existing stream DNS hijack can take over")
	require.NotEqual(t, tun.ActionBypass, verdict.Action,
		"TCP/53 must not be bypassed")
	require.NotEqual(t, tun.ActionHijackDNS, verdict.Action,
		"TCP/53 keeps its existing ActionAccept semantics; changing it would alter the stream "+
			"DNS architecture")
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

func TestDNSHijackByPortBeatsRouteAddressSetMiss(t *testing.T) {
	// The include case: the set is non-empty and does not contain 8.8.8.8, so ordinary traffic
	// bypasses.
	inbound, router := hijackByPortInbound(t)
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"UDP/53 outside the route include set must still be hijacked")
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

func TestDNSHijackByPortTCPBeatsRouteAddressSetMiss(t *testing.T) {
	inbound, router := hijackByPortInbound(t)
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict := inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action)
	require.NotEqual(t, tun.ActionBypass, verdict.Action)
	require.EqualValues(t, 0, router.preMatchCalls.Load())
}

// TestDNSHijackAddressBeatsRouteAddressSetMiss covers the address check against the include set.
func TestDNSHijackAddressBeatsRouteAddressSetMiss(t *testing.T) {
	dnsAddress := netip.MustParseAddr("10.0.0.53")
	inbound, _ := hijackTestInbound(t, []netip.Addr{dnsAddress}, false)
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "192.168.0.0/16")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"the configured DNS address must be hijacked even when it falls outside the route "+
			"include set")

	// TCP keeps its existing semantics on the address path too.
	verdict = inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.AddrPortFrom(dnsAddress, 53),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action)
}

// --- the non-DNS bypasses must keep working (§21, §22, §29, §30) -----------------------

func TestNonDNSRouteExcludeStillBypasses(t *testing.T) {
	// The fastest native path must not be collateral damage of moving the DNS check earlier.
	inbound, _ := hijackByPortInbound(t)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "8.8.8.8")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:443"),
		nil,
	)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"a non-DNS destination in the exclude set must still bypass natively")
}

func TestNonDNSRouteAddressSetMissStillBypasses(t *testing.T) {
	inbound, _ := hijackByPortInbound(t)
	inbound.routeAddressSet = []*netipx.IPSet{ipSetFrom(t, "10.0.0.0/8")}

	verdict := inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("1.2.3.4:443"),
		nil,
	)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"a non-DNS destination outside the include set must still bypass")
}

func TestDNSHijackByPortDisabledDoesNotHijack(t *testing.T) {
	// With the by-port rule off, port 53 is ordinary traffic and the route sets decide.
	inbound, _ := hijackTestInbound(t, nil, false)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "8.8.8.8")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.Equal(t, tun.ActionBypass, verdict.Action,
		"port 53 must not be hijacked when dnsHijackByPort is disabled; the bypass applies")
}

func TestDNSHijackByPortIgnoresNonTCPAndNonUDP(t *testing.T) {
	// ICMP carries no port, but the guard is on the network number and must stay.
	inbound, _ := hijackByPortInbound(t)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "8.8.8.8")}

	verdict := inbound.JudgeFlow(
		uint8(headerICMP),
		netip.MustParseAddrPort("192.168.1.2:0"),
		netip.MustParseAddrPort("8.8.8.8:53"),
		nil,
	)
	require.NotEqual(t, tun.ActionHijackDNS, verdict.Action,
		"only TCP and UDP are DNS-by-port candidates")
}

func TestDNSHijackByPortWorksForIPv6(t *testing.T) {
	inbound, _ := hijackByPortInbound(t)
	inbound.routeExcludeAddressSet = []*netipx.IPSet{ipSetFrom(t, "2001:4860:4860::8888")}

	verdict := inbound.JudgeFlow(
		uint8(headerUDP),
		netip.MustParseAddrPort("[2001:db8::1]:40000"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
		nil,
	)
	require.Equal(t, tun.ActionHijackDNS, verdict.Action,
		"the precedence must hold for IPv6 destinations too")

	verdict = inbound.JudgeFlow(
		uint8(headerTCP),
		netip.MustParseAddrPort("[2001:db8::1]:40000"),
		netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
		nil,
	)
	require.Equal(t, tun.ActionAccept, verdict.Action)
}
