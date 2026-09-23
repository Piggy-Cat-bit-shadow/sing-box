//go:build jiejie_server_minimal

package include

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/service/resolved"
	E "github.com/sagernet/sing/common/exceptions"
)

// Registry for the Jiejie Server Edition minimal build (`jiejie_server_minimal`).
//
// This is a protocol-registration-level trim for one specific production server.
// It does not delete or modify any upstream protocol source: it simply does not
// import the packages the server does not use, so they never enter the import
// graph and the Go linker drops them from the binary.
//
// Registered inbound:  http (MASQUE H2/H3), anytls, shadowtls, shadowsocks,
//                      socks, direct
// Registered outbound: direct, block, selector/urltest, socks, http,
//                      shadowsocks, shadowtls, anytls
// Registered endpoint: none (no WireGuard / OpenConnect / OpenVPN / Tailscale /
//                      MASQUE endpoint is used)
// Registered DNS:      tcp, udp, tls, https, hosts, local, plus QUIC stubs
// Registered service:  resolved
// Registered cert:     origin_ca only (no ACME, no Tailscale)
//
// Deliberately absent versus the default registry: tun, redirect/tproxy, mixed,
// snell, vmess, vless, trojan, naive, tor, ssh, bridge, the MASQUE endpoint,
// hysteria/hysteria2/tuic (also absent from the QUIC registration), WireGuard,
// OpenConnect, OpenVPN, Tailscale, cloudflared, DHCP, mdns, fakeip, the clash
// API, CCM/OCM, USBIP, DERP, sshd/SSM API and the OOM killer service.
//
// Note on tor/ssh/vmess/vless/trojan: they are omitted because the production
// routing table does not reference them. If any of them is ever needed, add the
// Register call here rather than abandoning this build.

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	// The server's public entry points.
	http.RegisterInbound(registry)        // MASQUE over HTTP/2 (behind Nginx Stream) and HTTP/3 (UDP/443)
	anytls.RegisterInbound(registry)      // AnyTLS with native fallback
	shadowtls.RegisterInbound(registry)   // ShadowTLS v3
	shadowsocks.RegisterInbound(registry) // Shadowsocks / SS2022
	socks.RegisterInbound(registry)       // loopback helpers
	direct.RegisterInbound(registry)      // direct inbound (used by TUN-less setups)

	registerQUICInbounds(registry)
	registerStubForRemovedInbounds(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry) // direct, used by DNS and fallback routing
	block.RegisterOutbound(registry)  // reject rules
	group.RegisterSelector(registry)  // selector
	group.RegisterURLTest(registry)   // urltest
	socks.RegisterOutbound(registry)  // residential SOCKS upstream
	http.RegisterOutbound(registry)   // MASQUE client (A/B testing the server from itself)
	shadowsocks.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)

	registerQUICOutbounds(registry)
	registerStubForRemovedOutbounds(registry)

	return registry
}

// EndpointRegistry registers no endpoint.
//
// The production server uses none of the endpoint types: no WireGuard, no
// OpenConnect, no OpenVPN, no Tailscale, and no MASQUE *endpoint* (the MASQUE
// server runs as an http inbound, not as an endpoint).
func EndpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	// Required by direct.domain_resolver and the local AGH setup.
	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	resolved.RegisterTransport(registry)

	// QUIC/HTTP3 DNS and mdns/fakeip are not used; only stubs are registered.
	registerQUICTransports(registry)

	return registry
}

func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	resolved.RegisterService(registry)

	registerQUICServices(registry)

	return registry
}

// CertificateProviderRegistry registers no certificate provider.
//
// Certificates on this server are provisioned by acme.sh outside sing-box, so
// neither the ACME provider nor the Cloudflare Origin CA provider is needed.
// Dropping origin_ca also drops the certmagic dependency, which it imports for
// its storage interface; certmagic would otherwise stay linked for nothing.
func CertificateProviderRegistry() *certificate.Registry {
	return certificate.NewRegistry()
}

func registerStubForRemovedInbounds(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}

func registerStubForRemovedOutbounds(registry *outbound.Registry) {
	outbound.Register[option.ShadowsocksROutboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
	outbound.Register[option.StubOptions](registry, C.TypeWireGuard, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.StubOptions) (adapter.Outbound, error) {
		return nil, E.New("WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead")
	})
}
