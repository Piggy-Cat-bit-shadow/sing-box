package vless

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.VLESSOutboundOptions](registry, C.TypeVLESS, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.ReuseSuspect            = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	client          *vless.Client
	serverAddr      M.Socksaddr
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	tlsDialer       tls.Dialer
	transport       adapter.V2RayClientTransport
	packetAddr      bool
	xudp            bool
	// encryption is the VLESS post-quantum layer, nil unless `encryption` is
	// configured. It wraps the dialed conn beneath the vless client.
	encryption *encryption.ClientInstance
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeVLESS, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: options.Server,
			Options:       common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				options.Flow == "",
		})
		if err != nil {
			return nil, err
		}
		// See the trojan outbound: tls.enabled=false yields a nil config by contract, and a dialer
		// built around it turns the first dial into a nil-config ClientHandshake and a process-wide
		// SIGSEGV. No config means the node is plain TCP, so no TLS dialer is built.
		if outbound.tlsConfig != nil {
			outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
		}
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outbound.dialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	if options.PacketEncoding == nil {
		outbound.xudp = true
	} else {
		switch *options.PacketEncoding {
		case "":
		case "packetaddr":
			outbound.packetAddr = true
		case "xudp":
			outbound.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", *options.PacketEncoding)
		}
	}
	// Set up the post-quantum encryption layer before the vless client, which
	// is unaware of it.
	if options.Encryption != "" && options.Encryption != "none" {
		encryptionConfig, err := parseClientEncryption(options.Encryption)
		if err != nil {
			return nil, E.Cause(err, "parse encryption")
		}
		outbound.encryption = &encryption.ClientInstance{}
		if err := outbound.encryption.Init(encryptionConfig.keys, encryptionConfig.xorMode, encryptionConfig.seconds, encryptionConfig.padding); err != nil {
			return nil, E.Cause(err, "initialize encryption")
		}
	}
	outbound.client, err = vless.NewClient(options.UUID, options.Flow, logger)
	if err != nil {
		return nil, err
	}
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vlessDialer)(outbound), logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		}
		return (*vlessDialer)(h).DialContext(ctx, network, destination)
	} else {
		switch N.NetworkName(network) {
		case N.NetworkTCP:
			h.logger.InfoContext(ctx, "outbound multiplex connection to ", destination)
		case N.NetworkUDP:
			h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		}
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return (*vlessDialer)(h).ListenPacket(ctx, destination)
	} else {
		h.logger.InfoContext(ctx, "outbound multiplex packet connection to ", destination)
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *Outbound) MultiplexEnabled() bool {
	if h.multiplexDialer != nil {
		return true
	}
	multiplexTransport, isMultiplexTransport := h.transport.(adapter.V2RayMultiplexClientTransport)
	return isMultiplexTransport && multiplexTransport.MultiplexEnabled()
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.SetKeepIdleConnections(keep)
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper)
	if isTransportKeeper {
		transportKeeper.CloseIdleConnections()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.CloseIdleConnections()
	}
}

// RetireSuspect forwards the reuse boundary to a transport that can refuse new work on the
// connections it already holds, and does nothing for one that cannot.
//
// # Why the outbound carries this and the boundary walk does not reach the transport
//
// The walk sees outbounds, endpoints, DNS transports and the HTTP client service, so an outbound that
// wants its transport's pool to participate has to forward. This is the same shape CloseIdleConnections
// already has, and for the same reason: the VLESS outbound owns the transport, and which transport it
// is - XHTTP, gRPC, HTTP, WebSocket - is a configuration detail the walk must not have to know.
//
// # Why the no-op for other transports is correct rather than a silent downgrade
//
// The walk applies BOTH actions and applies the idle one unconditionally, so an outbound whose
// transport cannot drain still has its idle connections retired at the boundary - exactly the
// behaviour it had before this method existed. What it does not get is the stronger action, because
// the transport cannot express it; the transport modules that can are the ones with a session pool
// (see transport/v2rayxhttp) and the ones that cannot are the ones whose CloseIdleConnections is
// already the whole story.
//
// The multiplex dialer is deliberately not forwarded to. Its pool is `sing-mux`, an external module
// with no no-new-stream state: the only operations it offers are CloseIdleConnections (streams == 0
// only) and Close, and the second would break live streams. Forwarding a no-op would claim a
// capability that does not exist; see docs/fork/post-wake-reuse.md for the recorded limitation.
func (h *Outbound) RetireSuspect() {
	transportDrainer, isTransportDrainer := h.transport.(adapter.ReuseSuspect)
	if isTransportDrainer {
		transportDrainer.RetireSuspect()
	}
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.transport != nil {
		scope.Add(h.transport.Close)
	}
	if h.multiplexDialer != nil {
		scope.Add(h.multiplexDialer.Close)
	}
	return nil
}

type vlessDialer Outbound

func (h *vlessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		return nil, err
	}
	conn, err = h.wrapEncryption(ctx, conn)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		if h.xudp {
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		} else if h.packetAddr {
			if destination.IsDomain() {
				return nil, E.New("packetaddr: domain destination is not supported")
			}
			packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(packetConn, destination), destination), nil
		} else {
			return h.client.DialEarlyPacketConn(conn, destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vlessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else if h.tlsDialer != nil {
		conn, err = h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	conn, err = h.wrapEncryption(ctx, conn)
	if err != nil {
		return nil, err
	}
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsDomain() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		conn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination)
	}
}
