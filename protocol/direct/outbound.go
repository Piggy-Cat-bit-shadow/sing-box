package direct

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, NewOutbound)
}

var (
	_ N.ParallelDialer                = (*Outbound)(nil)
	_ dialer.ParallelNetworkDialer    = (*Outbound)(nil)
	_ dialer.DirectDialer             = (*Outbound)(nil)
	_ adapter.FlowOutbound            = (*Outbound)(nil)
	_ adapter.BypassableOutbound      = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	logger         logger.ContextLogger
	network        adapter.NetworkManager
	dialer         dialer.ParallelInterfaceDialer
	domainStrategy C.DomainStrategy
	fallbackDelay  time.Duration
	// semantics is the precomputed native-bypass profile of this outbound's dial options. It is
	// built once, here, from the same options the dialer was built from, and it is the only thing
	// that answers "would the userspace dial path do anything special for this flow?".
	semantics dialer.SocketSemantics
	// familyStrategy reports the effective address-family policy of the resolver this outbound was
	// given, or nil when it has none. It is a function rather than a value because the effective
	// policy can come from the resolver's own configuration and is only known once the router can
	// be asked.
	familyStrategy func() C.DomainStrategy
	myAddresses    common.TypedValue[[]netip.Prefix]
	icmpPort       *ping.Port
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("`detour` is not supported in direct context")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
	})
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		network: service.FromContext[adapter.NetworkManager](ctx),
		//nolint:staticcheck
		domainStrategy: C.DomainStrategy(options.DomainStrategy),
		fallbackDelay:  time.Duration(options.FallbackDelay),
		dialer:         outboundDialer.(dialer.ParallelInterfaceDialer),
		semantics:      dialer.NativeBypassSemantics(options.DialerOptions),
	}
	if reporter, isReporter := outboundDialer.(dialer.ResolveDialer); isReporter {
		outbound.familyStrategy = reporter.EffectiveFamilyStrategy
	}
	//nolint:staticcheck
	if options.ProxyProtocol != 0 {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	if defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer); isDefaultDialer {
		outbound.icmpPort = ping.NewPort(ctx, logger, func(destination netip.Addr) control.Func {
			return defaultDialer.DialerForICMPDestination(destination).Control
		}, 0)
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.icmpPort != nil {
			scope.Add(h.icmpPort.Close)
		}
	case adapter.StartStatePostStart, adapter.StartStateStarted:
		if len(h.myAddresses.Load()) == 0 {
			h.fetchMyAddresses()
		}
	}
	return nil
}

func (h *Outbound) fetchMyAddresses() {
	interfaceMonitor := h.network.InterfaceMonitor()
	if interfaceMonitor == nil {
		return
	}
	myInterfaceNames := interfaceMonitor.MyInterfaces()
	if len(myInterfaceNames) == 0 {
		return
	}
	var (
		myAddresses []netip.Prefix
		found       bool
	)
	for _, myInterfaceName := range myInterfaceNames {
		myInterface, err := h.network.InterfaceFinder().ByName(myInterfaceName)
		if err != nil {
			continue
		}
		found = true
		myAddresses = append(myAddresses, myInterface.Addresses...)
	}
	if !found {
		return
	}
	h.myAddresses.Store(myAddresses)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.fetchMyAddresses()
	if h.icmpPort != nil {
		h.icmpPort.Close()
	}
}

func (h *Outbound) isMyLoopbackAddress(addresses ...netip.Addr) bool {
	for _, prefix := range h.myAddresses.Load() {
		for _, address := range addresses {
			if !C.IsDarwin && prefix.Addr() == address {
				continue
			}
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return h.dialer.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if network == N.NetworkICMP && h.icmpPort != nil {
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	return h.icmpPort.PortAddresses()
}

func (h *Outbound) PortMTU() uint32 {
	return h.icmpPort.PortMTU()
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	return h.icmpPort.AttachReturn(returnPath)
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	return h.icmpPort.DetachReturn(returnPath)
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	return h.icmpPort.WritePackets(packets)
}

func (h *Outbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), nil, nil, nil, h.fallbackDelay)
}

func (h *Outbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
}

func (h *Outbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, newDestination, err := dialer.ListenSerialNetworkPacket(ctx, h.dialer, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return conn, newDestination, nil
}

// IsEmpty reports whether this outbound asks the socket layer for nothing at all.
//
// It is NOT the bypass question, and the difference is the point of the profile: a direct outbound
// configured only with a domain_resolver is not empty, because it resolves names for the flows that
// need it, while a literal-IP flow through the same outbound still needs no resolution and is
// reproducible by the platform's own connect.
func (h *Outbound) IsEmpty() bool {
	return h.semantics.IsPlain()
}

// CanBypass reports whether a connection over this network to this literal destination may skip the
// userspace data path.
//
// # What it answers, and how
//
// It is a conjunction of three things the userspace path would otherwise do:
//
//	the dial options        the profile built once from the same options the dialer was built from
//	the ambient policy      the network manager's default bind, mark, strategy and fallback
//	the self-address guard  the check that keeps a TUN from routing a connection into itself
//
// # Why the options are no longer compared wholesale
//
// The previous implementation asked whether the outbound's options were literally empty. That is
// safe but it answers the wrong question: a configured option only disqualifies a flow if it would
// AFFECT that flow. The production topology is the case in point - its direct outbound carries
// domain_resolver and nothing else - and a literal-IP flow through it never reaches the resolver.
// Comparing the configuration refused the bypass; comparing the semantics does not.
//
// The conservative direction is preserved where it matters. Every option that changes a socket, a
// bind, a mark, a timeout, TCP behaviour, interface selection or the resolution of a name still
// refuses, an option nobody has classified refuses, and the ambient-policy and self-address guards
// are unchanged.
func (h *Outbound) CanBypass(network string, destination netip.Addr) bool {
	return h.BypassBlockers(network, destination) == dialer.BlockerNone
}

// BypassBlockers reports every reason this outbound cannot be reproduced by the platform's own
// connect for this flow. The empty set means it can.
//
// It exists beside CanBypass so a refusal can be attributed rather than merely observed: knowing
// that the fast path is off is not actionable, and knowing it is off because of a routing mark is.
// The cost is one profile lookup and two comparisons on a path that runs once per flow.
func (h *Outbound) BypassBlockers(network string, destination netip.Addr) dialer.NativeBypassBlocker {
	facts := dialer.NativeBypassFacts{
		Network: network,
		// Always true here, and not by assumption: the router only consults a bypassable outbound
		// after establishing that the destination is a literal with no candidate list, no sniffed
		// domain and no rewrite. A flow that needs a name resolved never reaches this method.
		DestinationIsLiteral: true,
		Destination:          destination,
	}
	if h.familyStrategy != nil {
		facts.FamilyStrategy = h.familyStrategy()
	}
	blockers := h.semantics.Blockers(facts)
	blockers |= dialer.NetworkPolicyBlockers(h.network)
	if h.isMyLoopbackAddress(destination) {
		// The userspace path refuses to dial this host's own addresses so a TUN cannot route a
		// connection back into itself. A bypass is a connect performed by the platform, which has no
		// such guard, so this check is the only thing standing between the fast path and that loop.
		blockers |= dialer.BlockerSelfAddress
	}
	return blockers
}
