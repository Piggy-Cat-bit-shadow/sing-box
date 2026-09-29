package socks

import (
	"context"
	"net"
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

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	client    *socks.Client
	resolve   bool
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
	// The outbound dialer is a ResolveDialer whenever the server is a domain, but it is built
	// unconditionally, so the type assertion is guarded rather than assumed.
	var targetQueryOptions adapter.DNSQueryOptions
	if resolveDialer, isResolveDialer := outboundDialer.(dialer.ResolveDialer); isResolveDialer {
		targetQueryOptions = resolveDialer.QueryOptions()
	}
	outbound := &Outbound{
		Adapter:            outbound.NewAdapterWithDialerOptions(C.TypeSOCKS, tag, options.Network.Build(), options.DialerOptions),
		dnsRouter:          service.FromContext[adapter.DNSRouter](ctx),
		logger:             logger,
		client:             socks.NewClient(outboundDialer, options.ServerOptions.Build(), version, options.Username, options.Password),
		resolve:            version == socks.Version4,
		targetQueryOptions: targetQueryOptions,
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

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			return h.uotClient.DialContext(ctx, network, destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
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
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.ListenPacket(ctx, destination)
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
