package route

import (
	"context"
	"net/netip"
	"testing"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// End-to-end contract test for the verdict the Direct Fast Path produces.
//
// # Why this lives here and not only in the tun package
//
// The defect is a cross-module one: it appears when a PreMatchBypass verdict whose outbound
// implements tun.Port is converted by adapter.JudgeFlow into the verdict sing-tun actually
// consumes. Testing either half alone cannot see it, so this test drives the real Router.PreMatch
// through the real adapter.JudgeFlow and inspects the resulting FlowVerdict.
//
// # The pinned sing-tun conversion
//
// sing-tun v0.9.7-0.20260929152201-837976228ca2, flow_dispatch.go:
//
//	if verdict.Action == ActionBypass && verdict.Port != nil {
//	    verdict.Action = ActionFlow
//	}
//
// A bypass carrying a Port is therefore rewritten into a userspace flow - the optimisation does
// not happen, and the flow is given the direct outbound's ICMP ping Port.

// portDirectOutbound is a bypassable direct outbound that ALSO implements tun.Port, which is what
// the real direct outbound does because it serves ICMP. Reproducing that is the point: an outbound
// without the interface would never trigger the conversion.
type portDirectOutbound struct {
	adapter.Outbound
}

func (o *portDirectOutbound) Type() string { return C.TypeDirect }
func (o *portDirectOutbound) Tag() string  { return "direct" }

// The real direct outbound serves ICMP as well - that is why it implements tun.Port - so the
// fake must declare it, or the router would refuse to route ICMP to it.
func (o *portDirectOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}
}

func (o *portDirectOutbound) CanBypass(network string, destination netip.Addr) bool { return true }

// PreMatchFlow mirrors the real direct outbound: ICMP is served by a ping Port and therefore takes
// the flow path, while TCP and UDP do not.
func (o *portDirectOutbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if network == N.NetworkICMP {
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (o *portDirectOutbound) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
}
func (o *portDirectOutbound) PortMTU() uint32                          { return 1500 }
func (o *portDirectOutbound) AttachReturn(returnPath tun.Return) error { return nil }
func (o *portDirectOutbound) DetachReturn(returnPath tun.Return) error { return nil }
func (o *portDirectOutbound) WritePackets(packets [][]byte) error      { return nil }

var _ tun.Port = (*portDirectOutbound)(nil)

// verdictDNSRouter reports no reverse mapping, which is the production state when the destination
// is not a FakeIP or reverse-mapped address.
type verdictDNSRouter struct{ adapter.DNSRouter }

func (r *verdictDNSRouter) Start(stage adapter.StartStage) error { return nil }
func (r *verdictDNSRouter) Close() error                         { return nil }
func (r *verdictDNSRouter) ClearCache()                          {}
func (r *verdictDNSRouter) ResetNetwork()                        {}
func (r *verdictDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}
func (r *verdictDNSRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, nil
}
func (r *verdictDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	return nil, nil
}

// verdictDNSTransport has no FakeIP configured, so prepareMatchMetadata's FakeIP branch is
// skipped exactly as in a deployment without FakeIP.
type verdictDNSTransport struct{ adapter.DNSTransportManager }

func (m *verdictDNSTransport) Start(stage adapter.StartStage) error { return nil }
func (m *verdictDNSTransport) Close() error                         { return nil }
func (m *verdictDNSTransport) Transports() []adapter.DNSTransport   { return nil }
func (m *verdictDNSTransport) Transport(tag string) (adapter.DNSTransport, bool) {
	return nil, false
}
func (m *verdictDNSTransport) Default() adapter.DNSTransport   { return nil }
func (m *verdictDNSTransport) FakeIP() adapter.FakeIPTransport { return nil }
func (m *verdictDNSTransport) Remove(tag string) error         { return nil }
func (m *verdictDNSTransport) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return nil
}

// portRouter builds a Router whose default outbound can bypass and implements tun.Port.
func portRouter(t *testing.T) (*Router, *portDirectOutbound) {
	t.Helper()
	outbound := &portDirectOutbound{}
	return &Router{
		ctx:          context.Background(),
		logger:       log.NewNOPFactory().Logger(),
		outbound:     &stubOutboundManager{byTag: map[string]adapter.Outbound{"direct": outbound}, def: outbound},
		dns:          &verdictDNSRouter{},
		dnsTransport: &verdictDNSTransport{},
	}, outbound
}

// TestDirectFastBypassVerdictHasNoPort is the P0 contract for TCP.
func TestDirectFastBypassVerdictHasNoPort(t *testing.T) {
	router, _ := portRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)

	result := router.PreMatch(metadata, nil)
	require.Equal(t, adapter.PreMatchBypass, result.Action,
		"the connection is eligible, so the router must report a bypass")

	verdict := adapter.JudgeFlow(router, metadata, 6, /* TCP */
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		nil)

	require.Equal(t, tun.ActionBypass, verdict.Action,
		"a direct fast bypass must remain a bypass after the adapter converts it")
	require.Nil(t, verdict.Port,
		"a bypass verdict must NOT carry a tun.Port: the pinned sing-tun rewrites "+
			"ActionBypass+Port into ActionFlow, so a Port here silently disables the fast path "+
			"and builds a userspace flow with the direct outbound's ICMP ping Port")
}

// TestDirectFastBypassVerdictHasNoPortUDP is the same contract for UDP.
func TestDirectFastBypassVerdictHasNoPortUDP(t *testing.T) {
	router, _ := portRouter(t)

	destination := M.ParseSocksaddr("8.8.4.4:12345")
	metadata := fastBypassMetadata(N.NetworkUDP, destination)

	result := router.PreMatch(metadata, nil)
	require.Equal(t, adapter.PreMatchBypass, result.Action)

	verdict := adapter.JudgeFlow(router, metadata, 17, /* UDP */
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("8.8.4.4:12345"),
		nil)

	require.Equal(t, tun.ActionBypass, verdict.Action)
	require.Nil(t, verdict.Port,
		"a UDP direct fast bypass must not carry a Port either")
}

// TestICMPFlowVerdictKeepsItsPort is the regression guard for the other direction.
//
// The ping Port exists for ICMP and ICMP must keep it; stripping the Port from every verdict would
// fix TCP and UDP by breaking ICMP.
//
// # Why this drives preMatchFlow rather than PreMatch
//
// PreMatch's rule loop type-asserts the concrete *option.RuleActionRoute, which only the
// route/rule package can construct - a test in this package cannot build one without an import
// cycle. The Port semantics live in the outbound's PreMatchFlow and in adapter.JudgeFlow, both of
// which are reached from here, so this exercises the code that can actually be wrong.
func TestICMPFlowVerdictKeepsItsPort(t *testing.T) {
	router, outbound := portRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34")
	metadata := fastBypassMetadata(N.NetworkICMP, destination)

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "direct")
	require.Equal(t, adapter.PreMatchFlow, result.Action,
		"ICMP must take the flow path, not the bypass path")
	require.Same(t, adapter.Outbound(outbound), result.Outbound)

	verdict := adapter.JudgeFlow(router, metadata, 1, /* ICMP */
		netip.MustParseAddrPort("192.168.1.2:0"),
		netip.MustParseAddrPort("93.184.216.34:0"),
		nil)

	require.Equal(t, tun.ActionFlow, verdict.Action)
	require.NotNil(t, verdict.Port,
		"an ICMP flow verdict must keep the outbound's ping Port")
	require.Same(t, tun.Port(outbound), verdict.Port,
		"the Port must be the outbound's own")
}

// TestTCPFlowVerdictKeepsItsPortWhenNotBypassed documents which verdict TCP takes.
//
// The real direct outbound serves ICMP through its ping Port and NOTHING else: TCP and UDP go
// through the ordinary dial path, so PreMatchFlow returns PreMatchContinue for them. That is why
// a TCP bypass verdict must be Port-free - there is no Port that would be meaningful for it.
//
// This test fixes that shape so a future change cannot start attaching the ICMP Port to TCP flows
// on the theory that "the outbound has a Port".
func TestTCPFlowVerdictKeepsItsPortWhenNotBypassed(t *testing.T) {
	router, outbound := portRouter(t)

	destination := M.ParseSocksaddr("93.184.216.34:443")
	metadata := fastBypassMetadata(N.NetworkTCP, destination)
	// A sniffed domain makes the connection ineligible for the fast path, so it takes the
	// ordinary path.
	metadata.Domain = "example.com"

	result := router.preMatchFlow(context.Background(), &metadata, destination, nil, "direct")
	require.Equal(t, adapter.PreMatchContinue, result.Action,
		"TCP is not a flow-path network for the direct outbound")

	verdict := adapter.JudgeFlow(router, metadata, 6, /* TCP */
		netip.MustParseAddrPort("192.168.1.2:40000"),
		netip.MustParseAddrPort("93.184.216.34:443"),
		nil)

	require.Equal(t, tun.ActionAccept, verdict.Action,
		"an ineligible TCP connection falls back to the ordinary stack path")
	require.Nil(t, verdict.Port,
		"the ICMP ping Port must never be attached to a TCP verdict")
	require.NotNil(t, outbound)
}
