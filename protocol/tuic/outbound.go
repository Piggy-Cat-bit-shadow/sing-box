package tuic

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/gofrs/uuid/v5"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TUICOutboundOptions](registry, C.TypeTUIC, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	logger    logger.ContextLogger
	client    *tuic.Client
	udpStream bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	userUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	var tuicUDPStream bool
	if options.UDPOverStream && options.UDPRelayMode != "" {
		return nil, E.New("udp_over_stream is conflict with udp_relay_mode")
	}
	// The empty value is the documented default, and it must be spelled out here: a value with a
	// typo used to fall through the switch and silently mean `native`, so a user who wrote
	// "qiuc" got a working relay in the wrong mode and no signal at all - while the neighbouring
	// `congestion_control` typo does produce an error. An unrecognised value is now a
	// configuration error.
	switch options.UDPRelayMode {
	case "", "native":
	case "quic":
		tuicUDPStream = true
	default:
		return nil, E.New("unknown udp_relay_mode: ", options.UDPRelayMode, " (expected native or quic)")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	// A proven lower tunnel caps what this QUIC connection may put on the wire.
	//
	// # TUIC goes through the same path as hysteria2, and the lines that say so
	//
	// TUIC does NOT build its own quic.Config. The pinned sing-quic TUIC client does it, and it calls
	// the SAME applier hysteria2's does - in the module pinned by go.mod
	// (github.com/sagernet/sing-quic v0.7.2-0.20260929152029-258509488380):
	//
	//	quic.go:54-78     func ApplyQUICOptions(quicConfig *quic.Config, options QUICOptions) {
	//	quic.go:72-74         if options.InitialPacketSize > 0 {
	//	quic.go:73                quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	//
	//	tuic/client.go:60-65  quicConfig := &quic.Config{
	//	                          DisablePathMTUDiscovery: !(GOOS == windows|linux|android|darwin),
	//	                          EnableDatagrams: true, MaxIncomingUniStreams: 1 << 60,
	//	                      }
	//	                      qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	//	tuic/client.go:170/172 qtls.DialEarly / qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	//
	// The field this outbound sets below (QUICOptions.InitialPacketSize) is the one read at
	// quic.go:72, so the ceiling reaches the same library field hysteria2's does.
	//
	// # And the difference that makes this clamp effective where hysteria2's is not
	//
	// Grep for ChromeParrot in this module: `tuic` never sets it, and nothing in sing-quic's TUIC path
	// can - quic-go's own guard says so, internal/handshake/tls_conn_utls.go:58
	// ("quic: tls.Config.VerifyConnection is not supported with ChromeParrot"). Only hysteria2's
	// outbound sets the field (protocol/hysteria2/outbound.go: `ChromeParrot: !options.DisableChromeParrot`),
	// and the pinned quic-go then REPLACES whatever the caller configured with
	// chromeInitialPacketSize = 1250 (quic-go config.go:109-121). TUIC never enters that branch, so for
	// TUIC the ceiling is what actually goes on the wire. MEASURED, not inferred:
	// `TestTheCeilingReachesTheTUICFirstDatagram` in this package reads len(p) of the first datagram the
	// real client config produces.
	//
	// An unknown path yields no ceiling and the configured value is used unchanged, so a direct dial
	// keeps exactly its previous behaviour.
	pathCapacity := dialer.DetourPathCapacity(ctx, options.DialerOptions.Detour)
	quicPayloadCeiling, hasCeiling := pathCapacity.QuicPayloadCeiling()
	effectiveInitialPacketSize := dialer.ClampToCeiling(options.InitialPacketSize, quicPayloadCeiling, hasCeiling)
	if hasCeiling && effectiveInitialPacketSize != options.InitialPacketSize {
		logger.Info("path capacity: inner MTU ", pathCapacity.InnerMTU,
			" caps the QUIC payload at ", quicPayloadCeiling,
			", so initial_packet_size ",
			options.InitialPacketSize, " becomes ", effectiveInitialPacketSize)
	}
	// A ceiling below the QUIC minimum is a configuration-level impossibility, not a value to clamp:
	// an Initial packet cannot be smaller than 1200 (RFC 9000 section 14.1), so there is no safe number
	// to send. The same refusal, with the same wording, is what hysteria2 already does - the two
	// protocols share the helper, so they must share the boundary too.
	if hasCeiling && effectiveInitialPacketSize < dialer.MinimumQUICInitialPacketSize {
		return nil, E.New("tuic: the lower tunnel (inner MTU ", pathCapacity.InnerMTU,
			", ", pathCapacity.Family.String(),
			") leaves ", quicPayloadCeiling, " bytes of UDP payload, which cannot carry a QUIC Initial ",
			"packet (minimum ", dialer.MinimumQUICInitialPacketSize,
			"). This path cannot carry a standard QUIC handshake; configure a larger tunnel MTU or ",
			"reach this server without this detour")
	}
	client, err := tuic.NewClient(tuic.ClientOptions{
		Context:       ctx,
		Dialer:        outboundDialer,
		ServerAddress: options.ServerOptions.Build(),
		TLSConfig:     tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       effectiveInitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		UUID:              userUUID,
		Password:          options.Password,
		CongestionControl: options.CongestionControl,
		UDPStream:         tuicUDPStream,
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTUIC, tag, options.Network.Build(), options.DialerOptions),
		logger:    logger,
		client:    client,
		udpStream: options.UDPOverStream,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		if h.udpStream {
			h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
			streamConn, err := h.client.DialConn(ctx, uot.RequestDestination(uot.Version))
			if err != nil {
				return nil, err
			}
			return uot.NewLazyConn(streamConn, uot.Request{
				IsConnect:   true,
				Destination: destination,
			}), nil
		} else {
			conn, err := h.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(conn, destination), nil
		}
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.udpStream {
		h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
		streamConn, err := h.client.DialConn(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return nil, err
		}
		return uot.NewLazyConn(streamConn, uot.Request{
			IsConnect:   false,
			Destination: destination,
		}), nil
	} else {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return h.client.ListenPacket(ctx)
	}
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	_ = h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	h.client.SetKeepIdleConnections(keep)
}

func (h *Outbound) CloseIdleConnections() {
	h.client.CloseIdleConnections()
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		return h.client.CloseWithError(os.ErrClosed)
	})
	return nil
}
