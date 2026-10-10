package socks

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
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

// clientDialer is the dialer the SOCKS client is built with.
//
// Version 5 is the only version with UDP ASSOCIATE, so it is the only one whose relay address
// can come back unspecified - and an unspecified address means the local system to Go, which
// sends every datagram to loopback with no error. The wrapper is scoped to that version so
// version 4 keeps its own path untouched.
func clientDialer(outboundDialer N.Dialer, version socks.Version, serverAddr M.Socksaddr) N.Dialer {
	if version != socks.Version5 {
		return outboundDialer
	}
	return newRelayDialer(outboundDialer, serverAddr)
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	client    *socks.Client
	// clientDialer is the dialer the SOCKS client was built with, kept so a caller can observe the
	// request-building seam: the dial the client makes with the target it DECIDED on is the only place
	// "what did the client actually send" is visible without a live peer. Production never reads it.
	clientDialer N.Dialer
	resolve      bool
	// destinationDNSOwnership is the declared downstream-hop position: this outbound is a proxy the
	// user's traffic reaches after leaving the device, so the destination domain must be resolved by
	// this fork's DNS policy plane rather than by the proxy.
	//
	// See option.DialerOptions.DestinationDNSOwnership for why it is a declaration and not the
	// default. `resolve` is the narrower, older reason to resolve locally (SOCKS4 cannot carry a
	// domain at all); this is the product reason.
	destinationDNSOwnership bool
	// targetQueryOptions is the resolver policy for a TARGET domain, as opposed to the proxy
	// server's hostname.
	//
	// SOCKS4 carries only an IPv4 address, so a domain target MUST be resolved locally before it
	// can be sent. That resolution is a workaround for the protocol's limit, not a tunnel policy,
	// so it has to follow the same resolver the operator configured for this outbound -- the one
	// the server hostname already uses. Querying with empty options instead would silently bypass
	// DialerOptions.DomainResolver and send the target through the default DNS path.
	//
	// Resolved once at construction: the options are fixed for the outbound's lifetime, and the
	// per-connection path must not re-derive them.
	targetQueryOptions adapter.DNSQueryOptions
	uotClient          *uot.Client
	// earlyBufferGrowth is reported through the copy-tuning capability so the route
	// layer can size its buffers for a chained hop. Off unless opted in.
	earlyBufferGrowth bool
}

// lookupDestinationAddresses resolves a destination domain for the wire.
//
// It is a package-level variable so a test can substitute a resolver without a DNS transport, the
// same seam TestSOCKS4LookupCarriesTheTargetPolicy uses through the router interface. Production
// always takes the default.
var lookupDestinationAddresses = func(ctx context.Context, router adapter.DNSRouter, options adapter.DNSQueryOptions, domain string) ([]netip.Addr, error) {
	return router.Lookup(ctx, domain, options)
}

// resolveDestinationForDownstream returns the addresses to dial when this outbound owns destination
// DNS, or ok=false when it must leave the destination as it is.
//
// The DECISION lives in common/dialer.DestinationOwnership, because protocol/http makes the same
// decision for the same option and a second copy of the rule is how one protocol ends up enforcing
// ownership on its stream path and not on its packet path. What stays here is the one thing the shared
// helper cannot supply: the `lookupDestinationAddresses` seam, which is the point these tests
// substitute so they can drive the real entry points without a DNS transport.
func (h *Outbound) resolveDestinationForDownstream(ctx context.Context, destination M.Socksaddr) ([]netip.Addr, bool, error) {
	if !h.destinationDNSOwnership || !destination.IsDomain() {
		return nil, false, nil
	}
	if h.dnsRouter == nil {
		return nil, false, E.New("socks: destination_dns_ownership is enabled but no DNS router is available to resolve ", destination.Fqdn)
	}
	addresses, err := lookupDestinationAddresses(ctx, h.dnsRouter, h.targetQueryOptions, destination.Fqdn)
	if err != nil {
		return nil, false, E.Cause(err, "socks: resolve destination ", destination.Fqdn,
			" locally, as destination_dns_ownership requires; the name is deliberately NOT sent to ",
			"the proxy")
	}
	if len(addresses) == 0 {
		return nil, false, E.New("socks: no address for destination ", destination.Fqdn,
			"; destination_dns_ownership forbids forwarding the unresolved name to the proxy")
	}
	return addresses, true, nil
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
	var version socks.Version
	var err error
	if options.Version != "" {
		version, err = socks.ParseVersion(options.Version)
	} else {
		version = socks.Version5
	}
	if err != nil {
		return nil, err
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	// The target policy is derived from DialerOptions DIRECTLY, not from the outbound dialer.
	//
	// # Why stealing it from the dialer was wrong
	//
	// dialer.New only builds a ResolveDialer when ServerIsDomain() is true, so when the proxy server
	// is an IP literal there is no dialer to read a policy from -- and the previous code left the
	// policy zero. An empty DNSQueryOptions is not "no preference": it bypasses
	// dialer_options.domain_resolver entirely and sends the target through the default DNS path, so
	// the SERVER name and the TARGET name would be resolved by different authorities with nothing in
	// the configuration explaining the difference.
	//
	// Both names come from the same DialerOptions, so both are derived from it. dialer.New derives
	// the server-side policy from these options; TargetQueryOptions derives the target-side policy
	// from the same options, which is what makes them agree by construction rather than by
	// coincidence.
	targetQueryOptions, err := dialer.TargetQueryOptions(ctx, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	dialClientDialer := clientDialer(outboundDialer, version, options.ServerOptions.Build())
	outbound := &Outbound{
		Adapter:                 outbound.NewAdapterWithDialerOptions(C.TypeSOCKS, tag, options.Network.Build(), options.DialerOptions),
		dnsRouter:               service.FromContext[adapter.DNSRouter](ctx),
		logger:                  logger,
		client:                  socks.NewClient(dialClientDialer, options.ServerOptions.Build(), version, options.Username, options.Password),
		clientDialer:            dialClientDialer,
		resolve:                 version == socks.Version4,
		destinationDNSOwnership: options.DialerOptions.DestinationDNSOwnership,
		targetQueryOptions:      targetQueryOptions,
	}

	if preconnect := options.TCPPreconnect; preconnect != nil && preconnect.Enabled {
		// The pool is SOCKS5 TCP CONNECT only. Enabling it for another version is a
		// configuration error rather than a silent no-op, so an operator cannot
		// believe a pool is active when it is not.
		if version != socks.Version5 {
			return nil, E.New("socks: tcp_preconnect requires version 5, got ", version)
		}
		preconnectOptions := socks.PreconnectOptions{
			MinIdle:     preconnect.MinIdle,
			MaxIdle:     preconnect.MaxIdle,
			IdleTimeout: time.Duration(preconnect.IdleTimeout),
		}
		// Defaults apply only to parameters the operator omitted, so a bare
		// `"enabled": true` yields a small bounded pool rather than zero or unbounded.
		if preconnectOptions.MinIdle == 0 {
			preconnectOptions.MinIdle = socks.DefaultPreconnectMinIdle
		}
		if preconnectOptions.MaxIdle == 0 {
			preconnectOptions.MaxIdle = socks.DefaultPreconnectMaxIdle
		}
		if preconnectOptions.IdleTimeout == 0 {
			preconnectOptions.IdleTimeout = socks.DefaultPreconnectIdleTimeout
		}
		if err = outbound.client.EnablePreconnect(preconnectOptions); err != nil {
			return nil, err
		}
	}

	if tuning := options.TCPTuning; tuning != nil {
		outbound.earlyBufferGrowth = tuning.EarlyBufferGrowth
	}

	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  outbound.client,
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

// EarlyConnectionBufferGrowth implements adapter.ConnectionCopyTuner.
//
// It reports whether the copy path may switch to a large buffer after the first
// transfer for connections through THIS outbound. Returning false keeps the
// framework default, so an ordinary SOCKS outbound is unaffected.
func (h *Outbound) EarlyConnectionBufferGrowth() bool {
	return h.earlyBufferGrowth
}

// Close releases the preconnect pool, so a reload or a removed outbound leaves no
// goroutine and no socket behind.
func (h *Outbound) Close() error {
	return h.client.Close()
}

// ownedDestinationContext records what was owned, so the metadata travels with the downstream dial.
//
// # Why the domain stays in the metadata
//
// The wire target is an address, because that is the contract: the proxy must not resolve the user's
// destination. The DOMAIN is still the thing the user asked for, and everything downstream of the
// dial that is not the wire - TLS SNI, an HTTP Host header, sniffing, the tracker, a log line - reads
// it from the context. Losing it here would turn "we resolved this locally" into "we forgot what the
// user asked for", and the second is a worse outcome than the first.
//
// `Destination` is left as the domain and `OriginDestination` records it, which is the same pairing the
// inbound side already uses for a destination that was rewritten: the domain is what the user meant,
// and the address actually dialled is whatever the dialer was handed. `DestinationAddresses` records
// WHICH local policy answer was chosen, so a diagnostic can tell the two apart afterwards.
//
// The extension is scoped to the downstream dial and its nested dials, so the caller's own metadata is
// untouched.
//
// It is one function rather than one per entry point because there are now four entry points that can
// reach the peer with a destination - SOCKS TCP CONNECT, SOCKS UDP ASSOCIATE, UoT through DialContext
// and UoT through ListenPacket - and four copies of a metadata rule is how one of them ends up
// differing from the other three.
func ownedDestinationContext(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr) context.Context {
	_, metadata := adapter.ExtendContext(ctx)
	metadata.OriginDestination = destination
	metadata.DestinationAddresses = addresses
	return adapter.WithContext(ctx, metadata)
}

// dialDownstreamOwnedDestination performs the dial when this outbound owns destination DNS.
func (h *Outbound) dialDownstreamOwnedDestination(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr) (net.Conn, error) {
	return N.DialSerial(ownedDestinationContext(ctx, destination, addresses), h.client, network, destination, addresses)
}

// listenDownstreamOwnedDestination is the packet-connection form of
// dialDownstreamOwnedDestination, with the same metadata rule.
func (h *Outbound) listenDownstreamOwnedDestination(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr) (net.PacketConn, error) {
	packetConn, _, err := N.ListenSerial(ownedDestinationContext(ctx, destination, addresses), h.client, destination, addresses)
	return packetConn, err
}

// dialUoTDownstreamOwnedDestination opens a UoT session to an address the local policy chose.
//
// UoT carries one destination per SESSION, so the session is opened to the first address the policy
// produced. That is the same "the candidate order decides, and the rest are fallbacks" rule the stream
// path applies through DialSerial: a UoT session cannot retry per address, so pretending otherwise
// would need a second resolution rather than a second attempt.
func (h *Outbound) dialUoTDownstreamOwnedDestination(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr) (net.Conn, error) {
	return h.uotClient.DialContext(
		ownedDestinationContext(ctx, destination, addresses),
		network,
		M.SocksaddrFrom(addresses[0], destination.Port),
	)
}

// listenUoTDownstreamOwnedDestination is the packet-connection form of
// dialUoTDownstreamOwnedDestination.
func (h *Outbound) listenUoTDownstreamOwnedDestination(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr) (net.PacketConn, error) {
	return h.uotClient.ListenPacket(
		ownedDestinationContext(ctx, destination, addresses),
		M.SocksaddrFrom(addresses[0], destination.Port),
	)
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	networkName := N.NetworkName(network)
	switch networkName {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
		} else {
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	// Destination DNS ownership is resolved ONCE, before every branch that can reach the peer.
	//
	// # The bypass this closes
	//
	// The ownership resolution used to sit AFTER the switch, while the UoT branch returned from
	// INSIDE it:
	//
	//	case N.NetworkUDP:
	//	    if h.uotClient != nil {
	//	        return h.uotClient.DialContext(ctx, network, destination)   <- the peer gets the NAME
	//	    }
	//	...
	//	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(...)   <- never reached
	//
	// So on a UoT-configured outbound - which is the common shape for a residential downstream hop,
	// because UDP through a SOCKS proxy needs UoT to be usable at all - `DialContext(UDP)` handed the
	// destination DOMAIN to the peer without ever consulting the declaration. The stream path was
	// covered and the packet path was not, and the asymmetry was invisible because the switch read as
	// presentation rather than as control flow.
	//
	// Resolving here, before the switch, means every UDP entry point - plain SOCKS UDP ASSOCIATE,
	// UoT through DialContext, and UoT through ListenPacket - takes the same decision from the same
	// place, and a name that must be owned cannot reach the peer through the one branch that used to
	// return early.
	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(ctx, destination)
	if ownErr != nil {
		return nil, ownErr
	}

	if networkName == N.NetworkUDP && h.uotClient != nil {
		if owned {
			return h.dialUoTDownstreamOwnedDestination(ctx, network, destination, downstreamAddresses)
		}
		return h.uotClient.DialContext(ctx, network, destination)
	}
	if owned {
		return h.dialDownstreamOwnedDestination(ctx, network, destination, downstreamAddresses)
	}
	// The SOCKS4 workaround: SOCKS4 cannot carry a domain at all, so it must be resolved locally
	// whatever the ownership declaration says.
	if h.resolve && destination.IsDomain() {
		destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, h.targetQueryOptions)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, h.client, network, destination, destinationAddresses)
	}
	return h.client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	// Resolved once, before the UoT split, for the same reason DialContext resolves it before its
	// switch. See the comment there for the bypass this shape closes.
	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(ctx, destination)
	if ownErr != nil {
		return nil, ownErr
	}
	if h.uotClient != nil {
		// UoT carries the target inside the tunnelled request, so the same ownership rule applies to
		// it as to a plain SOCKS UDP ASSOCIATE: what must not reach the peer is the NAME.
		if owned {
			h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination, " via ", downstreamAddresses)
			return h.listenUoTDownstreamOwnedDestination(ctx, destination, downstreamAddresses)
		}
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
	}
	if owned {
		return h.listenDownstreamOwnedDestination(ctx, destination, downstreamAddresses)
	}
	if h.resolve && destination.IsDomain() {
		destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, h.targetQueryOptions)
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, h.client, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}
