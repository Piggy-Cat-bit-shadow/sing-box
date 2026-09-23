//go:build with_quic && jiejie_server_minimal

package include

import (
	"context"
	"io"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	C "github.com/sagernet/sing-box/constant"
)

// This file is the QUIC registration surface for the minimal server build.
//
// MASQUE HTTP/3 is implemented by transport/http/server_h3.go, which is compiled
// whenever `with_quic` is set. It does NOT need any protocol registered here, so
// the minimal build deliberately does not register Hysteria, Hysteria2, TUIC,
// the Hysteria2 realm service, naive QUIC or the v2ray QUIC transport. Those
// packages are therefore absent from the import graph and never linked.
//
// The v2ray QUIC constructor and the naive HTTP/3 hook are still stubbed so that
// a configuration which references them fails with a clear message at config
// load rather than with an "unknown type" error.

func init() {
	v2ray.RegisterQUICConstructor(
		func(ctx context.Context, logger logger.ContextLogger, options option.V2RayQUICOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
			return nil, C.ErrQUICNotIncluded
		},
		func(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayQUICOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
			return nil, C.ErrQUICNotIncluded
		},
	)
}

func registerQUICInbounds(registry *inbound.Registry) {
	inbound.Register[option.HysteriaInboundOptions](registry, C.TypeHysteria, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaInboundOptions) (adapter.Inbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
	inbound.Register[option.TUICInboundOptions](registry, C.TypeTUIC, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICInboundOptions) (adapter.Inbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
	inbound.Register[option.Hysteria2InboundOptions](registry, C.TypeHysteria2, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2InboundOptions) (adapter.Inbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
	naive.ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error) {
		return nil, C.ErrQUICNotIncluded
	}
}

func registerQUICOutbounds(registry *outbound.Registry) {
	outbound.Register[option.HysteriaOutboundOptions](registry, C.TypeHysteria, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HysteriaOutboundOptions) (adapter.Outbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
	outbound.Register[option.TUICOutboundOptions](registry, C.TypeTUIC, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
	outbound.Register[option.Hysteria2OutboundOptions](registry, C.TypeHysteria2, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Hysteria2OutboundOptions) (adapter.Outbound, error) {
		return nil, C.ErrQUICNotIncluded
	})
}

// registerQUICTransports intentionally registers no DNS transport.
//
// QUIC and HTTP/3 DNS resolvers (DoQ / DoH3) are not used by this server: DNS is
// handled by the local AGH resolver and direct.domain_resolver, both of which use
// plain UDP/TCP/TLS/HTTPS transports registered unconditionally elsewhere.
//
// The types are still registered as stubs so that a config referencing them fails
// with a clear message instead of "unknown DNS type".
func registerQUICTransports(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTLSDNSServerOptions](registry, C.DNSTypeQUIC, func(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTLSDNSServerOptions) (adapter.DNSTransport, error) {
		return nil, C.ErrQUICNotIncluded
	})
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTP3, func(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
		return nil, C.ErrQUICNotIncluded
	})
}

// registerQUICServices registers no Hysteria2 realm service in the minimal build.
func registerQUICServices(registry *service.Registry) {
	service.Register[option.HysteriaRealmServiceOptions](registry, C.TypeHysteriaRealm, func(ctx context.Context, logger log.ContextLogger, tag string, options option.HysteriaRealmServiceOptions) (adapter.Service, error) {
		return nil, C.ErrQUICNotIncluded
	})
}
