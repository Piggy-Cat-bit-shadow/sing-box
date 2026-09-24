//go:build jiejie_ios_slim

package include

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
)

// Registry for the Jiejie iOS slim build (`jiejie_ios_slim`).
//
// This is a CLIENT registry. Unlike the server-minimal registry, which serves one
// known server configuration, this one must cover whatever a user configures on
// their phone, so it is trimmed only where a protocol is genuinely not offered by
// this client.
//
// The trim target is the large optional components a mobile proxy client has no
// use for:
//
//   - hysteria / hysteria2 / tuic: not part of the Jiejie client feature set.
//   - vmess / trojan / ssh / tor / shadowsocksr: legacy or unused transports.
//   - tailscale: dropped by omitting the with_tailscale tag, which also removes
//     the tailscale dependency tree. This is the single largest saving.
//
// Everything the Jiejie iOS client advertises is retained, and each entry below
// is justified by test/jiejie/jiejie-ios-client-fixture.json, which is checked in
// CI with `sing-box check` against a build using exactly this tag set:
//
//	MASQUE over HTTP/3 and HTTP/2   -> http (also carries http3_connection_pool
//	                                   and http3_fallback)
//	AnyTLS                          -> anytls
//	VLESS + Reality/Vision          -> vless
//	Shadowsocks / 2022              -> shadowsocks
//	ShadowTLS                       -> shadowtls
//	NaiveProxy                      -> naive
//	TUN / mixed inbounds            -> tun, mixed
//	selector / urltest              -> group
//
// A protocol removed here that a user's config names will fail `sing-box check`
// with "unknown outbound type", which is the honest outcome: the build does not
// have it.
func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	http.RegisterInbound(registry)      // MASQUE: HTTP/3 and HTTP/2 proxy inbounds
	anytls.RegisterInbound(registry)    // AnyTLS, with native fallback
	shadowtls.RegisterInbound(registry) // ShadowTLS v3
	shadowsocks.RegisterInbound(registry)
	vless.RegisterInbound(registry) // VLESS, including Reality/Vision
	mixed.RegisterInbound(registry) // HTTP+SOCKS mixed inbound
	tun.RegisterInbound(registry)   // the VPN interface on iOS

	registerQUICInbounds(registry)

	return registry
}

func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)
	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	http.RegisterOutbound(registry) // MASQUE client, including the H3 pool
	anytls.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	shadowsocks.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	naive.RegisterOutbound(registry)
	socks.RegisterOutbound(registry)

	registerQUICOutbounds(registry)

	return registry
}

// EndpointRegistry registers no endpoint.
//
// The tailscale endpoint is absent by design; it is the component this profile
// exists to drop, and no client fixture references it.
func EndpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

// DNSTransportRegistry registers the transports the iOS client can configure.
//
// Unlike the server registry, which serves one UDP resolver, a mobile client
// legitimately uses every one of these, and the client fixture configures DoH,
// hosts and fakeip explicitly. `local` is registered for the same boot-dependency
// reason documented on the server registry: box.go unconditionally initialises
// the transport manager with a local fallback.
//
// `resolved` is deliberately absent: it is a Linux/systemd transport with no
// meaning on Darwin.
func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterUDP(registry)
	transport.RegisterTCP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	local.RegisterTransport(registry)
	hosts.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)

	registerQUICTransports(registry)

	return registry
}

// ServiceRegistry registers nothing beyond what QUIC support requires.
//
// The client fixture uses no sing-box service; cache_file is handled by the
// experimental section rather than a service registration.
func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	registerQUICServices(registry)

	return registry
}

// CertificateProviderRegistry registers no provider.
//
// The client consumes ordinary CA-signed certificates and never issues its own,
// so neither ACME nor the Cloudflare provider is needed.
func CertificateProviderRegistry() *certificate.Registry {
	return certificate.NewRegistry()
}
