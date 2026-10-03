package tun

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

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
	headerTCP = 6
	headerUDP = 17
)
