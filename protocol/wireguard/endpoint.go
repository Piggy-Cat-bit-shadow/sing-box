package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-box/transport/wireguard"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*Endpoint)(nil)
	_ adapter.OnDemandEndpoint            = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.WireGuardEndpointOptions](registry, C.TypeWireGuard, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx            context.Context
	router         adapter.Router
	dnsRouter      adapter.DNSRouter
	logger         logger.ContextLogger
	localAddresses []netip.Prefix
	endpoint       *wireguard.Endpoint
	onDemand       bool
	bindAccess     sync.Mutex
	started        atomic.Bool
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardEndpointOptions) (adapter.Endpoint, error) {
	ep := &Endpoint{
		Adapter:        endpoint.NewAdapterWithDialerOptions(C.TypeWireGuard, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:            ctx,
		router:         router,
		dnsRouter:      service.FromContext[adapter.DNSRouter](ctx),
		logger:         logger,
		localAddresses: options.Address,
		onDemand:       options.OnDemand,
	}
	if options.Detour != "" && options.ListenPort != 0 {
		return nil, E.New("`listen_port` is conflict with `detour`")
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: options.DialerOptions,
		RemoteIsDomain: common.Any(options.Peers, func(it option.WireGuardPeer) bool {
			return !M.ParseAddr(it.Address).IsValid()
		}),
		ResolverOnDetour: true,
	})
	if err != nil {
		return nil, err
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	// A WireGuard endpoint reached through a `detour` is a NESTED tunnel: its own transport messages
	// travel as UDP payloads inside the lower tunnel's inner IP packets. A lower tunnel that can prove
	// its capacity therefore bounds this endpoint's inner MTU, and the bound is the same number every
	// other protocol stacked on a tunnel uses - see nestedTunnelMTU for the arithmetic and for why an
	// unknown detour leaves the configured value exactly as it was.
	tunnelMTU := nestedTunnelMTU(ctx, logger, tag, options.Detour, options.MTU)
	wgEndpoint, err := wireguard.NewEndpoint(wireguard.EndpointOptions{
		Context:         ctx,
		Logger:          logger,
		System:          options.System,
		Handler:         ep,
		UDPTimeout:      udpTimeout,
		ICMPTimeout:     C.ICMPTimeout,
		UDPMapping:      tun.NATMapping(options.UDPMapping),
		UDPFiltering:    tun.NATFiltering(options.UDPFiltering),
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: networkManager.InterfaceFinder(),
		EgressPoolOptions: tun.UDPEgressPoolOptions{
			Logger:           logger,
			InterfaceFinder:  networkManager.InterfaceFinder(),
			InterfaceMonitor: networkManager.InterfaceMonitor(),
			IsExempt: func() bool {
				return networkManager.AutoRedirectOutputMark() != 0
			},
		},
		Dialer: outboundDialer,
		CreateDialer: func(interfaceName string) N.Dialer {
			return common.Must1(dialer.NewDefault(ctx, option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					BindInterface: interfaceName,
				},
			}))
		},
		Tag:        tag,
		Name:       options.Name,
		MTU:        tunnelMTU,
		Address:    options.Address,
		PrivateKey: options.PrivateKey,
		ListenPort: options.ListenPort,
		// ResolvePeer resolves a PEER ENDPOINT hostname, which is an address OUTSIDE the tunnel:
		// the client has to reach it before any tunnel exists. It therefore uses the resolver this
		// outbound was configured with, exactly like any other external server address.
		//
		// This is deliberately NOT the same authority as the inner targets resolved in
		// DialContextWithDestination below. Those are addresses INSIDE the tunnel, and the tunnel's
		// own routing decides how to reach them, so they follow the global DNS rules -- the same
		// reading that OpenVPN, OpenConnect, Tailscale and MASQUE apply to their inner traffic.
		//
		// The two must not be silently unified: an operator points domain_resolver at a resolver
		// reachable BEFORE the tunnel, and using it for inner names would send those queries to an
		// address the tunnel may not route.
		ResolvePeer: func(domain string) ([]netip.Addr, error) {
			return ep.dnsRouter.Lookup(ctx, domain, outboundDialer.(dialer.ResolveDialer).QueryOptions())
		},
		Peers: common.Map(options.Peers, func(it option.WireGuardPeer) wireguard.PeerOptions {
			return wireguard.PeerOptions{
				Endpoint:                    M.ParseSocksaddrHostPort(it.Address, it.Port),
				PublicKey:                   it.PublicKey,
				PreSharedKey:                it.PreSharedKey,
				AllowedIPs:                  it.AllowedIPs,
				PersistentKeepaliveInterval: it.PersistentKeepaliveInterval,
				Reserved:                    it.Reserved,
			}
		}),
		Workers: options.Workers,
	})
	if err != nil {
		return nil, err
	}
	ep.endpoint = wgEndpoint
	return ep, nil
}

func (w *Endpoint) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		err := w.endpoint.Initialize(oomkiller.MemoryPressure(w.ctx))
		if err != nil {
			return err
		}
		scope.Add(w.endpoint.Close)
	case adapter.StartStateStart:
		return w.endpoint.Start(false)
	case adapter.StartStatePostStart:
		err := w.endpoint.Start(true)
		if err != nil {
			return err
		}
		w.started.Store(true)
		scope.Add(func() error {
			w.bindAccess.Lock()
			w.started.Store(false)
			w.bindAccess.Unlock()
			return nil
		})
	}
	return nil
}

func (w *Endpoint) InterfaceUpdated(ctx context.Context) {
	if !w.started.Load() {
		return
	}
	go w.updateBind(ctx)
}

func (w *Endpoint) OnDemand() bool {
	return w.onDemand
}

func (w *Endpoint) SetKeepIdleConnections(keep bool) {
	w.endpoint.SetIdle(!keep)
}

func (w *Endpoint) updateBind(ctx context.Context) {
	w.bindAccess.Lock()
	defer w.bindAccess.Unlock()
	if ctx.Err() != nil || !w.started.Load() {
		return
	}
	err := w.endpoint.BindUpdate()
	if err != nil {
		w.logger.Error(E.Cause(err, "update bind"))
	}
}

func (w *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (w *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	return w.endpoint.PortAddresses()
}

func (w *Endpoint) PortMTU() uint32 {
	return w.endpoint.PortMTU()
}

// nestedTunnelMTU bounds a WireGuard endpoint's inner MTU by the capacity of the tunnel it is
// reached through, and returns the value unchanged when that capacity is not provable.
//
// # The arithmetic, in the units each layer actually uses
//
// A nested WireGuard's OUTER datagram is one transport message, and it travels as a UDP payload
// inside the detour's inner IP packet:
//
//	detour inner IP packet  48 + transport message  <=  detour inner MTU
//	transport message       inner MTU + 32          (measured; see
//	                                                 transport/wireguard/wg_framing_measurement_test.go)
//
// so
//
//	inner MTU  <=  detour inner MTU - 48 - 32
//
// which is exactly the ceiling the detour publishes for a UDP payload - `QuicPayloadCeiling`, the
// same number MASQUE, Hysteria2 and TUIC size their own QUIC packets with. Using the shared helper
// rather than a second derivation of the same arithmetic is the point: the 48 and the 32 are already
// there, and a fourth copy of them would be a fourth thing to keep in step.
//
// # Why the padding does not change the bound
//
// The transport message is capped at the tunnel MTU before the tag is added, so a full-size inner
// packet is not padded at all and no inner packet within the MTU produces a message above
// `MTU + 32`; a consumer of this bound sends an inner packet of at most `ceiling - 48 - 32`, which is
// one padding quantum below the cap. The measurement is in
// transport/wireguard/wg_framing_measurement_test.go.
//
// # Why an unknown detour changes nothing
//
// "We could not find out" and "we found out it is 1280" are different facts, and substituting a
// default for the first would silently resize every configuration whose detour this helper cannot
// see - a group, a selector, an unknown outbound, or no manager at all. An endpoint without a detour
// is not nested either, so it keeps exactly the value it had before this existed.
func nestedTunnelMTU(ctx context.Context, logger log.ContextLogger, tag string, detour string, configured uint32) uint32 {
	if detour == "" {
		return configured
	}
	capacity := dialer.DetourPathCapacity(ctx, detour)
	if !capacity.Known {
		return configured
	}
	ceiling, hasCeiling := capacity.QuicPayloadCeiling()
	if !hasCeiling {
		return configured
	}
	if configured != 0 && configured <= ceiling {
		return configured
	}
	logger.Info("wireguard[", tag, "] mtu ", configured, " is above what detour ", detour,
		" can carry; using ", ceiling)
	return ceiling
}

// WireGuard's transport-data framing, from the pinned module's own constants.
//
// # Where these numbers come from, in the pinned revision
//
// The module is github.com/sagernet/wireguard-go (go.mod), whose device package declares:
//
//	noise-protocol.go:67  MessageTransportHeaderSize = 16   // type+reserved(4), receiver index(4), counter(8)
//	noise-protocol.go:69  MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize
//	noise-protocol.go:26  PaddingMultiple            = 16
//	send.go:734-735       elem.packet = append(elem.packet, paddingZeros[:calculatePaddingSize(...)]...)
//	send.go:740-745       elem.packet = elem.keypair.send.Seal(header, nonce, elem.packet, nil)
//	send.go:817           scratch = append(scratch, elem.packet)   // -> peer.SendBuffers -> the UDP socket
//
// `poly1305.TagSize` is 16, so one transport-data message is
//
//	16 header + payload + 0..15 padding-to-16 + 16 tag
//
// and the packet handed to the socket is exactly that, with no additional framing: the 8-byte
// MessageEncapsulatingTransportSize is a writable PREFIX reserved in the buffer and re-sliced away
// (send.go:748), which is why it is not part of this budget.
//
// # Why the fixed part is the whole budget, and the padding is not
//
// The padding is 0..15 bytes and depends on the payload's remainder modulo 16, so it is not a fixed
// per-packet cost and cannot be added to a ceiling. The full reason it does not have to be is MEASURED
// rather than argued: the padded plaintext is capped at the tunnel MTU (`calculatePaddingSize` takes
// the padded size and clamps it to the MTU), so the transport message for any inner packet within the
// MTU is at most `MTU + 32`, and for a full-size packet it is exactly that. The measurement over every
// inner length from 28 to the tunnel MTU is in transport/wireguard/wg_framing_measurement_test.go; the
// honest fixed claim is D+32, which is what PortEncapOverhead returns.
const (
	// wireGuardTransportHeaderLength is device.MessageTransportHeaderSize: the transport-data header
	// that precedes the payload in every packet.
	wireGuardTransportHeaderLength = 16
	// wireGuardTransportTagLength is poly1305.TagSize: the AEAD tag appended after the payload.
	wireGuardTransportTagLength = 16
	// wireGuardEncapOverhead is what an inner IP packet costs BEFORE it is put into an outer IP and UDP
	// header: the transport header plus the AEAD tag. See the block comment above for the lines.
	wireGuardEncapOverhead = wireGuardTransportHeaderLength + wireGuardTransportTagLength
)

// PortEncapOverhead reports the WireGuard transport framing that sits INSIDE the inner IP packet this
// endpoint carries, so a protocol stacked on top of WireGuard as a `detour` sizes its own packets
// against the real budget rather than against the tunnel MTU.
//
// # The two numbers this keeps apart
//
//	inner IP MTU (PortMTU)          1408 default  what enters the tunnel, and what the operator set
//	encapsulation overhead            32          what WireGuard adds inside that 1408
//	inner UDP budget                 1360         what a UDP payload inside the tunnel really has
//	                                              over IPv4 (1408 - 20 - 8, or 1360 - 20 - 8 = 1332 for
//	                                              a UDP datagram: see QuicPayloadCeiling)
//
// # Why folding 32 into PortMTU would be wrong
//
// PortMTU is also what the tunnel device is configured with, and what the endpoint answers about its
// own inner capacity. Reporting 1376 there would mean the tunnel device refused packets between 1376
// and 1408 that it actually carries, and would report a tunnel MTU no operator configured. The
// overhead is a property of THIS transport, so it is published as its own fact and subtracted by the
// shared helper - common/dialer/path_mtu.go, PathCapacity.IPPacketCeiling and QuicPayloadCeiling -
// which is also where the IPv4/IPv6 header difference is applied once for every protocol.
//
// # What it does not claim
//
// It is a ceiling on the FIXED overhead, not a measurement of a particular packet: an individual
// message can be up to 15 bytes larger than its payload plus this figure, because of WireGuard's
// padding-to-16 (device.PaddingMultiple).
//
// The padding does NOT have to be added to the capacity, and that is a MEASURED result rather than an
// inference from the rule: the padded plaintext is capped at the tunnel MTU, so a full-size inner
// packet is not padded at all and no inner packet within the MTU can produce a transport message above
// `MTU + 32`. See transport/wireguard/wg_framing_measurement_test.go, which captures the framing on a
// real socket for every inner length from 28 to the tunnel MTU; the largest message measured over that
// whole range is exactly `MTU + 32`.
//
// A consumer of the ceiling published here stops one step short of even that: it sends an inner packet
// of at most `MTU - 48 - 32`, so its largest possible message is `ceil16(MTU-32) + 32`, which for a
// tunnel MTU that is a multiple of 16 is the MTU itself.
func (w *Endpoint) PortEncapOverhead() uint32 {
	return wireGuardEncapOverhead
}

func (w *Endpoint) UpstreamPort() any {
	return w.endpoint
}

func (w *Endpoint) AttachReturn(returnPath tun.Return) error {
	return w.endpoint.AttachReturn(returnPath)
}

func (w *Endpoint) DetachReturn(returnPath tun.Return) error {
	return w.endpoint.DetachReturn(returnPath)
}

func (w *Endpoint) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr()) {
			return tun.FlowVerdict{Action: tun.ActionAccept}
		}
	}
	return adapter.JudgeFlow(w.router, adapter.InboundContext{Inbound: w.Tag(), InboundType: w.Type()}, network, source, destination, firstPacket)
}

func (w *Endpoint) NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter) {
	ctx := log.ContextWithNewID(w.ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Network = N.NetworkUDP
	metadata.Source = source
	metadata.Destination = destination
	metadata.Protocol = C.ProtocolDNS
	w.logger.InfoContext(ctx, "inbound DNS packet from ", source)
	w.router.HijackDNSPacket(ctx, payload, writer, metadata)
}

func (w *Endpoint) WritePackets(packets [][]byte) error {
	if !w.started.Load() {
		return E.New("WireGuard is not ready yet")
	}
	return w.endpoint.WritePackets(packets)
}

func (w *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				destination.Addr = netip.IPv6Loopback()
			}
			break
		}
	}
	metadata.Destination = destination
	w.logger.InfoContext(ctx, "inbound connection from ", source)
	w.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	w.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = w.Tag()
	metadata.InboundType = w.Type()
	metadata.Source = source
	metadata.Destination = destination
	for _, localPrefix := range w.localAddresses {
		if localPrefix.Contains(destination.Addr) {
			metadata.OriginDestination = destination
			if destination.Addr.Is4() {
				metadata.Destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
			} else {
				metadata.Destination.Addr = netip.IPv6Loopback()
			}
			conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
		}
	}
	w.logger.InfoContext(ctx, "inbound packet connection from ", source)
	w.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	w.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (w *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if !w.started.Load() {
		return nil, E.New("WireGuard is not ready yet")
	}
	if destination.IsDomain() {
		// An INNER target: it is reached through the tunnel, so it is resolved under the global DNS
		// rules rather than by this outbound's domain_resolver. See ResolvePeer above for the
		// external counterpart and why the two differ.
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.endpoint, network, destination, destinationAddresses)
	} else if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return w.endpoint.DialContext(ctx, network, destination)
}

func (w *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if !w.started.Load() {
		return nil, netip.Addr{}, E.New("WireGuard is not ready yet")
	}
	if destination.IsDomain() {
		// The UDP counterpart of the inner-target lookup in DialContextWithDestination: global DNS
		// rules, not this outbound's domain_resolver.
		destinationAddresses, err := w.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, w.endpoint, destination, destinationAddresses)
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return iponly.NewPacketConn(w.logger, packetConn), destinationAddress, nil
	}
	packetConn, err := w.endpoint.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(w.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(w.logger, packetConn), netip.Addr{}, nil
}

func (w *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := w.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (w *Endpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	return false
}

func (w *Endpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if !w.started.Load() {
		return false
	}
	return w.endpoint.Lookup(address) != nil
}
