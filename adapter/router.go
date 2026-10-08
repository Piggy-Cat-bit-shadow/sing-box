package adapter

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
)

type Router interface {
	Lifecycle
	ConnectionRouter
	PreMatch(metadata InboundContext, firstPacket []byte) PreMatchResult
	HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata InboundContext)
	ConnectionRouterEx
	RuleSet(tag string) (RuleSet, bool)
	Rules() []Rule
	NeedFindProcess() bool
	NeedFindNeighbor() bool
	NeighborResolver() NeighborResolver
	AppendTracker(tracker ConnectionTracker)
	ResetNetwork()
	// TrimIdleResources is the progressive memory pass: release reusable pools without a network
	// reset. It must only reduce memory - see NetworkManager.TrimMemory for why the distinction
	// matters.
	TrimIdleResources()
}

type PreMatchAction uint8

const (
	PreMatchContinue PreMatchAction = iota
	PreMatchFlow
	PreMatchReject
	PreMatchDrop
	PreMatchBypass
	PreMatchHijackDNS
)

type PreMatchResult struct {
	Action      PreMatchAction
	Outbound    Outbound
	Destination netip.AddrPort
	UDPTimeout  time.Duration
	NewTracker  func() tun.FlowTracker
}

// canonicalAddrPort rewrites a v4-mapped IPv6 address to its four-byte form, and is a no-op for
// every other address. It is duplicated from protocol/tun rather than shared because the adapter
// package is a leaf: the alternative would be a dependency between two packages that both describe
// the boundary rather than one implementing it.
func canonicalAddrPort(address netip.AddrPort) netip.AddrPort {
	addr := address.Addr()
	if !addr.Is4In6() {
		return address
	}
	return netip.AddrPortFrom(addr.Unmap(), address.Port())
}

func JudgeFlow(router Router, metadata InboundContext, network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	var networkName string
	switch network {
	case uint8(header.TCPProtocolNumber):
		networkName = N.NetworkTCP
	case uint8(header.UDPProtocolNumber):
		networkName = N.NetworkUDP
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		networkName = N.NetworkICMP
	default:
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	metadata.Network = networkName
	// Canonicalised here because this is the boundary EVERY JudgeFlow caller goes through, including
	// the Linux nfqueue one, whose packets are parsed from the wire just like a TUN's. A v4-mapped
	// destination is an IPv4 address in sixteen bytes, and every policy comparison downstream -
	// route rules by CIDR, FakeIP ranges, DNS addresses - is written against the four-byte form.
	source = canonicalAddrPort(source)
	destination = canonicalAddrPort(destination)
	metadata.Source = M.SocksaddrFromNetIP(source)
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	if networkName == N.NetworkICMP {
		metadata.Source.Port = 0
		metadata.Destination.Port = 0
	}
	result := router.PreMatch(metadata, firstPacket)
	switch result.Action {
	case PreMatchFlow:
		port, isPort := result.Outbound.(tun.Port)
		if !isPort {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
		verdict := tun.FlowVerdict{Action: tun.ActionFlow, Port: port, UDPTimeout: result.UDPTimeout, NewTracker: result.NewTracker}
		if result.Destination.IsValid() {
			destinationPort := result.Destination.Port()
			if networkName == N.NetworkICMP {
				destinationPort = destination.Port()
			}
			verdict.Destination = netip.AddrPortFrom(result.Destination.Addr(), destinationPort)
		}
		return verdict
	case PreMatchReject:
		return tun.FlowVerdict{Action: tun.ActionReject}
	case PreMatchDrop:
		return tun.FlowVerdict{Action: tun.ActionDrop}
	case PreMatchBypass:
		// A bypass verdict carries NO Port, deliberately.
		//
		// The direct outbound implements tun.Port because it serves ICMP through a ping Port, so
		// attaching that Port here made a bypass arrive at sing-tun as ActionBypass + Port. The
		// pinned sing-tun rewrites exactly that combination (flow_dispatch.go, judgeAndInstall):
		//
		//	if verdict.Action == ActionBypass && verdict.Port != nil {
		//	    verdict.Action = ActionFlow
		//	}
		//
		// so the bypass was silently converted into a userspace flow carrying the ICMP ping Port -
		// the fast path did not happen, and the flow was built with a Port describing a ping
		// rather than the TCP or UDP connection being judged.
		//
		// A bypass means "let the platform route this itself"; there is no flow, so there is
		// nothing for a Port to describe. ICMP keeps its Port through the PreMatchFlow branch
		// above, which is the only verdict that builds a flow here.
		return tun.FlowVerdict{Action: tun.ActionBypass}
	case PreMatchHijackDNS:
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	default:
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
}

type ConnectionTracker interface {
	RoutedConnection(ctx context.Context, conn net.Conn, metadata InboundContext, matchedRule Rule, matchOutbound Outbound) net.Conn
	RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext, matchedRule Rule, matchOutbound Outbound) N.PacketConn
	RoutedFlow(ctx context.Context, metadata InboundContext, matchedRule Rule, matchOutbound Outbound) tun.FlowTracker
}

// Deprecated: Use ConnectionRouterEx instead.
type ConnectionRouter interface {
	RouteConnection(ctx context.Context, conn net.Conn, metadata InboundContext) error
	RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext) error
}

type ConnectionRouterEx interface {
	ConnectionRouter
	RouteConnectionEx(ctx context.Context, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}

type RuleSet interface {
	Name() string
	StartContext(ctx context.Context, startContext *HTTPStartContext) error
	Metadata() RuleSetMetadata
	ExtractIPSet() []*netipx.IPSet
	IncRef()
	DecRef()
	Cleanup()
	RegisterCallback(callback RuleSetUpdateCallback) *list.Element[RuleSetUpdateCallback]
	UnregisterCallback(element *list.Element[RuleSetUpdateCallback])
	Close() error
	HeadlessRule
}

type RuleSetUpdateCallback func(it RuleSet)

type DNSRuleSetUpdateValidator interface {
	ValidateRuleSetMetadataUpdate(tag string, metadata RuleSetMetadata) error
}

// ip_version is not a headless-rule item, so ContainsIPVersionRule is intentionally absent.
type RuleSetMetadata struct {
	ContainsProcessRule      bool
	ContainsWIFIRule         bool
	ContainsIPCIDRRule       bool
	ContainsDNSQueryTypeRule bool
	// ContainsNonIPCIDRRule signals that the rule-set carries at least one sub-rule
	// with a predicate other than destination ip_cidr / ip_set, so it can contribute
	// to DNS pre-response matching. A rule-set where this is false and
	// ContainsIPCIDRRule is true is "pure-IP" and matches nothing before a DNS
	// response is available.
	ContainsNonIPCIDRRule bool
}
