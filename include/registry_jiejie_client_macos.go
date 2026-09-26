//go:build jiejie_client_macos

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
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
)

// Registry for the Jiejie Client Edition macOS build (`jiejie_client_macos`).
//
// This is a CLIENT registry. It is not the server registry and must not be
// confused with it: the server build serves one known VPS topology, so it can
// register almost nothing, whereas a macOS client core is loaded by a third-party
// GUI that runs whatever the user configured. The trim here is therefore limited
// to things no macOS desktop client can use.
//
// # Why this file exists at all
//
// include/registry.go is the upstream full registry. It registers 28 protocol
// packages, every endpoint including Tailscale/OpenVPN/OpenConnect, the systemd
// `resolved` DNS transport (meaningless on Darwin), and the CCM/OCM/USBIP
// services. None of that belongs in a client core whose whole job is to open a
// TUN device and speak proxy protocols outbound. This file registers the subset
// that a desktop proxy client actually uses.
//
// # The trim is registration-level only
//
// No upstream protocol source is edited or deleted. A package this file does not
// import never enters the import graph, so the Go linker drops it and its whole
// dependency tree with it. That is what keeps `include/registry.go` — and
// therefore upstream build capability — working unchanged.
//
// # What is deliberately NOT registered, and why
//
//   - redirect / tproxy: Linux netfilter only.
//   - ssh, tor: not part of the Jiejie client feature set; `tor` in particular
//     drags in a full Tor client.
//   - masque (endpoint), tailscale, openvpn, openconnect, wireguard: large
//     endpoint trees for transports the Jiejie client does not offer.
//   - resolved: a systemd D-Bus transport with no meaning on Darwin.
//   - acme / origin_ca: a client consumes CA-signed certificates and never
//     issues its own.
//   - ccm, ocm, usbip, ssmapi, derp: server-side or out-of-scope services.
//   - mdns, dhcp, tailscale DNS: not part of the client profile.
//
// # What IS registered, and the one thing that must never be dropped
//
// `local` is registered for the same boot-dependency reason documented on the
// server registry: box.go unconditionally initialises the DNS transport manager
// with a fallback that creates a C.DNSTypeLocal transport, so omitting it makes
// every start fail with "default DNS server fallback: transport type not found:
// local". It is not a feature choice, it is a boot dependency.
//
// See docs/JIEJIE-MACOS-CLIENT.md for the full rationale and the test matrix.
func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

// InboundRegistry registers the entry points a desktop client needs.
//
// `tun` is the primary one: a macOS GUI core exists to route system traffic
// through a TUN device. `mixed` is the single-port HTTP+SOCKS inbound GUIs use
// for local proxy mode, and `socks`/`http` are registered separately because the
// client feature fixtures and many GUI templates name them explicitly. `direct`
// is registered because the framework resolves it for `route.final` fallbacks in
// some templates and because a `direct` inbound is the supported way to expose an
// unproxied local listener.
func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	tun.RegisterInbound(registry)    // the VPN interface: the client's primary mode
	mixed.RegisterInbound(registry)  // single-port HTTP+SOCKS, the GUI default
	socks.RegisterInbound(registry)  // explicit SOCKS inbound
	http.RegisterInbound(registry)   // explicit HTTP inbound (and MASQUE HTTP/2+H3 client-side plumbing)
	direct.RegisterInbound(registry) // local passthrough listener

	registerQUICInbounds(registry)

	return registry
}

// OutboundRegistry registers the protocols a Jiejie macOS client connects with.
//
// `block` is registered here even though the server build drops it: on a client,
// `route.rules` with `action: reject` is only half the story — GUI templates
// routinely define a named `block` outbound and use it as a `route.final` or as a
// selector member, and that is a configuration error if the type is absent.
//
// The protocol list is the Jiejie client feature set:
//
//	direct, block          -> routing primitives
//	selector, urltest      -> group management, required by every GUI
//	socks, http            -> upstream proxies and the MASQUE client
//	shadowsocks, shadowtls -> SS / SS2022 and ShadowTLS v3
//	snell, trojan          -> Snell and Trojan
//	vless, vmess           -> VLESS (incl. Reality/Vision) and VMess
//	anytls                 -> AnyTLS
//	hysteria2, tuic        -> registered by registerQUICOutbounds
//
// `naive` is registered by registerNaiveOutbound, which is compiled only under
// `with_naive_outbound`. The macOS core deliberately does NOT enable that tag by
// default: see docs/JIEJIE-MACOS-CLIENT.md for the Cronet/CGO rationale.
func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	socks.RegisterOutbound(registry)
	http.RegisterOutbound(registry)

	shadowsocks.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	snell.RegisterOutbound(registry)
	trojan.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	vmess.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)

	registerQUICOutbounds(registry)
	registerNaiveOutbound(registry)

	return registry
}

// EndpointRegistry registers no endpoint.
//
// Every endpoint this build wants to offer is absent by design: the Jiejie macOS
// client connects through ordinary proxy protocols, not through Tailscale,
// WireGuard, OpenVPN or OpenConnect. Registering none of them is also the single
// largest dependency saving in the profile.
func EndpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

// DNSTransportRegistry registers every resolver a desktop client can configure.
//
// This is the part of the profile most likely to be trimmed too far, so each
// entry is deliberate:
//
//	udp    -> plain DNS, including the `local` fallback path
//	tcp    -> truncation fallback and explicit `type: tcp` servers
//	tls    -> DoT
//	https  -> DoH (and DoH3 when with_quic is on; see dns/transport/quic)
//	local  -> REQUIRED: box.go's unconditional fallback transport
//	hosts  -> static host entries
//	fakeip -> the FakeIP pool every GUI template uses for sniffed domains
//
// DoQ and DoH3 come from registerQUICTransports.
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

// ServiceRegistry registers nothing beyond what the client needs.
//
// The `api` (Clash API) service is registered by include/clashapi.go, which
// `with_clash_api` compiles in independently of this file — that is the service a
// third-party GUI talks to, and it is a hard requirement of the profile. No
// other sing-box service is registered: the client uses none of them, and
// dropping them is what keeps ssmapi/derp/usbip/oomkiller out of the binary.
func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	registerQUICServices(registry)

	return registry
}

// CertificateProviderRegistry registers no provider.
//
// A client consumes ordinary CA-signed certificates and never issues its own, so
// neither ACME nor the Cloudflare Origin CA provider is needed. Dropping the
// latter also drops the certmagic dependency it pulls in.
func CertificateProviderRegistry() *certificate.Registry {
	return certificate.NewRegistry()
}
