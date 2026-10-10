package http

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/http"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HTTPOutboundOptions](registry, C.TypeHTTP, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	client *http.Client
	// ownership decides whether the destination domain may be handed to the proxy as a NAME.
	//
	// See option.DialerOptions.DestinationDNSOwnership. On iOS/Windows/etc. an HTTP proxy is a common
	// residential downstream hop, and the authority it receives is the whole destination: a CONNECT
	// to `example.com:443` asks the PEER to resolve the name.
	// dnsRouter is the router the destination is resolved through. It is read by the seam below, so
	// the tests can substitute the seam instead of building a DNS transport.
	dnsRouter adapter.DNSRouter
	// ownership decides whether the destination domain may be handed to the proxy as a NAME.
	ownership dialer.DestinationOwnership
	// hostOverride is the configured `headers.Host`, which the CONNECT request uses as its authority
	// instead of the destination.
	//
	// It is recorded because it changes whether ownership can be honoured at all: with a Host override
	// the proxy resolves whatever the OPERATOR wrote, not the user's destination, so there is no name
	// of ours to own and no way to make one. See DialContext for the fail-closed rule that follows.
	hostOverride string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	// The target policy is derived from DialerOptions directly, exactly as the SOCKS outbound does it,
	// so both protocols ask the same authority for the same kind of name. It is derived even when the
	// proxy server is an IP literal, because an empty policy is not "no preference": it bypasses
	// dialer_options.domain_resolver and sends the target through the default DNS path.
	targetQueryOptions, err := dialer.TargetQueryOptions(ctx, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	headers := options.Headers.Build()
	client, err := http.NewClientWithTLS(ctx, logger, outboundDialer, options.ServerOptions, common.PtrValueOrDefault(options.TLS), http.ClientOptions{
		Username:               options.Username,
		Password:               options.Password,
		Path:                   options.Path,
		Headers:                headers,
		Version:                http.ResolveVersion(options.Version, options.Path, headers.Get("Host")),
		DisableVersionFallback: options.DisableVersionFallback,
		HTTP2Options:           options.HTTP2Options,
		HTTP3Options:           options.HTTP3Options,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:      outbound.NewAdapterWithDialerOptions(C.TypeHTTP, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:       logger,
		client:       client,
		dnsRouter:    service.FromContext[adapter.DNSRouter](ctx),
		ownership:    dialer.NewDestinationOwnership(ctx, options.DialerOptions, service.FromContext[adapter.DNSRouter](ctx), targetQueryOptions),
		hostOverride: headers.Get("Host"),
	}, nil
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.ResetConnections()
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(h.client.Close)
	return nil
}

// lookupDestinationAddresses resolves a destination domain for the CONNECT authority.
//
// It is a package-level variable so a test can substitute a resolver without a DNS transport - the same
// seam protocol/socks uses, so both protocols' wire tests observe the same decision through the same
// kind of substitution. Production always takes the default.
var lookupDestinationAddresses = func(ctx context.Context, router adapter.DNSRouter, options adapter.DNSQueryOptions, domain string) ([]netip.Addr, error) {
	return router.Lookup(ctx, domain, options)
}

// resolveDestinationForDownstream returns the addresses to put in the CONNECT authority, or ok=false
// when the destination must travel as it is.
//
// The DECISION lives in common/dialer.DestinationOwnership, because protocol/socks makes it for the same
// option on the same kind of destination; two copies of the rule is how one protocol ends up enforcing
// ownership and the other not. What stays here is the seam these tests substitute.
func (h *Outbound) resolveDestinationForDownstream(ctx context.Context, destination M.Socksaddr) ([]netip.Addr, bool, error) {
	if !h.ownership.Declared || !destination.IsDomain() {
		return nil, false, nil
	}
	if h.dnsRouter == nil {
		return nil, false, E.New("http: destination DNS ownership is enabled for this outbound but no ",
			"DNS router is available to resolve ", destination.Fqdn)
	}
	addresses, err := lookupDestinationAddresses(ctx, h.dnsRouter, h.ownership.QueryOptions, destination.Fqdn)
	if err != nil {
		return nil, false, E.Cause(err, "http: resolve destination ", destination.Fqdn,
			" locally, as destination DNS ownership requires; the name is deliberately NOT sent to ",
			"the proxy")
	}
	if len(addresses) == 0 {
		return nil, false, E.New("http: no address for destination ", destination.Fqdn,
			"; destination DNS ownership forbids forwarding the unresolved name to the proxy")
	}
	return addresses, true, nil
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
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(ctx, destination)
	if ownErr != nil {
		return nil, ownErr
	}
	if owned {
		// # Why a Host override cannot coexist with ownership
		//
		// With `headers.Host` configured, the CONNECT request's authority is the OPERATOR's value and
		// the destination travels nowhere: the proxy resolves what the operator wrote. Replacing the
		// authority with our address would not remove the peer's resolution, it would only move it,
		// while silently discarding a header the configuration asked for. So the combination is
		// refused rather than half-honoured.
		//
		// The alternative - keeping the override and resolving the destination anyway - would resolve
		// a name that never reaches the wire, which is work with no effect presented as a guarantee.
		if h.hostOverride != "" {
			return nil, E.New("http: destination DNS ownership cannot be honoured while a Host header ",
				"override is configured (host=", h.hostOverride, "): a CONNECT with an overridden ",
				"authority makes the PEER resolve that host, so the user destination ", destination.Fqdn,
				" would not be owned locally. Remove the Host override or disable destination DNS ",
				"ownership for this outbound")
		}
		ownedCtx := ownedDestinationContext(ctx, destination, downstreamAddresses)
		ownedDestination := M.SocksaddrFrom(downstreamAddresses[0], destination.Port)
		if networkName == N.NetworkUDP {
			h.logger.InfoContext(ctx, "outbound packet connection to ", ownedDestination, " (", destination, ")")
			packetConn, err := h.client.ListenPacket(ownedCtx, ownedDestination)
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetConn, ownedDestination), nil
		}
		h.logger.InfoContext(ctx, "outbound connection to ", ownedDestination, " (", destination, ")")
		return h.client.DialContext(ownedCtx, network, ownedDestination)
	}
	if networkName == N.NetworkTCP {
		return h.client.DialContext(ctx, network, destination)
	}
	packetConn, err := h.client.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return bufio.NewBindPacketConn(packetConn, destination), nil
}

// ownedDestinationContext records what was owned for the downstream request.
//
// # Why the domain stays in the metadata
//
// The authority on the wire is an address, because that is the contract. The DOMAIN is still what the
// user asked for, and everything that is not the CONNECT authority - the Host header an application
// set, SNI, sniffing, the tracker, a log line - reads it from the context. `Destination` keeps the
// domain and `OriginDestination` records it, which is the same pairing the inbound side uses for a
// rewritten destination.
func ownedDestinationContext(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr) context.Context {
	_, metadata := adapter.ExtendContext(ctx)
	metadata.OriginDestination = destination
	metadata.DestinationAddresses = addresses
	return adapter.WithContext(ctx, metadata)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(ctx, destination)
	if ownErr != nil {
		return nil, ownErr
	}
	if owned {
		if h.hostOverride != "" {
			return nil, E.New("http: destination DNS ownership cannot be honoured while a Host header ",
				"override is configured (host=", h.hostOverride, ")")
		}
		ownedDestination := M.SocksaddrFrom(downstreamAddresses[0], destination.Port)
		return h.client.ListenPacket(ownedDestinationContext(ctx, destination, downstreamAddresses), ownedDestination)
	}
	return h.client.ListenPacket(ctx, destination)
}
