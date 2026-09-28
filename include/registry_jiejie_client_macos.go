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
	"github.com/sagernet/sing-box/protocol/masque"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/service/api"
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
//   - tailscale, openvpn, openconnect, wireguard: large endpoint trees for
//     transports the Jiejie client does not offer. MASQUE is NOT in this list:
//     the client role is registered (see EndpointRegistry), the server role is
//     not.
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

	// Exactly what the production configuration declares, and no more:
	//
	//   tun   -> the VPN interface
	//   mixed -> one port serving HTTP and SOCKS
	//
	// `mixed` provides BOTH HTTP and SOCKS on a single port, so the standalone
	// `socks` and `http` INBOUNDS are not needed and are not registered. Registering
	// them "because mixed contains them" would be a category error: mixed is a
	// distinct inbound type with its own handler, not a composition of the other two.
	//
	// `direct` as an inbound (a plain local listener with no proxy protocol) is also
	// absent: the production config does not use it.
	tun.RegisterInbound(registry)
	mixed.RegisterInbound(registry)

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
// `with_naive_outbound`. The macOS core DOES enable that tag - it is part of
// release/BUILD_TAGS_JIEJIE_CLIENT_MACOS - so the shipped client links the real
// Cronet-backed NaiveProxy outbound rather than the upstream not-included stub.
//
// The stub and the real implementation are indistinguishable at the TYPE level,
// because upstream registers the stub behind `!with_naive_outbound` so a user gets
// an actionable error instead of "unknown outbound type". That is why the shipped
// binary is checked for cronet-go.NewNaiveClient and for the stub's message string
// by scripts/ci/audit-macos-client-registry.sh, rather than trusting the tag.
// See docs/JIEJIE-MACOS-CLIENT.md for the Cronet/CGO rationale.
func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	// `http` is kept: it is the MASQUE client outbound, which the production
	// configuration uses for its 🇺🇸 美国｜MASQUE node. It is not here as a generic
	// HTTP proxy.
	http.RegisterOutbound(registry)

	shadowsocks.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	vless.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)

	registerNaiveOutbound(registry)

	// Deliberately NOT registered, because the production configuration does not use
	// them and nothing else in it depends on them: `socks` (as an upstream proxy),
	// `snell`, `trojan`, `vmess`, `hysteria2`, `tuic`. Their source stays in the tree
	// for the Linux server build and for upstream sync; the Go linker drops them from
	// this binary because nothing references them.
	//
	// registerQUICOutbounds (hysteria2, tuic) is intentionally not called. with_quic
	// REMAINS enabled: MASQUE needs HTTP/3, which is a different consumer of the same
	// tag.

	return registry
}

// EndpointRegistry registers exactly one endpoint: the MASQUE client.
//
// # Why MASQUE is registered here at all
//
// The Jiejie macOS client connects through ordinary proxy protocols AND through
// the `masque-client` endpoint (CONNECT-IP / CONNECT-UDP over HTTP/2 or HTTP/3).
// MASQUE is a first-class Jiejie transport, so the client role must resolve:
// without this registration a perfectly valid `type: masque-client` configuration
// fails with "unknown endpoint type", even though the complete implementation is
// compiled into the binary. That was the state this registration fixes, and it is
// why an empty EndpointRegistry was wrong rather than merely minimal.
//
// # Why the roles are split instead of calling masque.RegisterEndpoint
//
// masque.RegisterEndpoint registers BOTH `masque-client` and `masque-server`. The
// macOS client must get the first and not the second: `masque-server` binds a TUN
// device and serves a full CONNECT-IP endpoint, which is a Server Edition
// capability with no place in a desktop client core. Calling the combined helper
// would have silently shipped it.
//
// protocol/masque.RegisterClientEndpoint therefore registers only the client
// role. The protocol and transport source stays shared: this is one registry
// entry, not a second implementation, and every framing/capsule/H3 fix continues
// to benefit both roles.
//
// # What stays out, and why
//
//   - wireguard, tailscale, openvpn, openconnect: large endpoint trees for
//     transports the Jiejie client does not offer. Excluding them remains the
//     single largest dependency saving in the profile.
//   - masque-server: see above; the server role is not a client feature.
//
// See test/jiejie/macos_client_registry_audit_test.go, which asserts both
// directions: masque-client resolves, masque-server does not.
func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	masque.RegisterClientEndpoint(registry)

	return registry
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

// ServiceRegistry registers the two management-plane services a headless client
// needs, and nothing else.
//
// # Two different services, often confused
//
// sing-box has TWO independent management APIs, and this profile needs both:
//
//   - `api` (constant.TypeAPI, service/api) is the NATIVE management service. It
//     serves a gRPC API over gRPC-Web and WebSocket, and it is the only service
//     that can serve the sing-box Web Dashboard. Registering it is what makes
//     headless `browser -> localhost` operation possible at all. An earlier
//     revision of this registry did NOT register it — the comment here claimed
//     the Clash API covered it, which was wrong: they are separate services with
//     separate schemas, and the native dashboard was consequently unreachable
//     ("unknown inbound type: api").
//
// It is the ONLY management service in this product. The Clash API was removed
// from the fork entirely, so there is no compatibility service, no second
// management plane, and no `clash_api` configuration option.
//
// The service is not required for proxying. If it is misconfigured the core's
// data path — TUN, DNS, routing, outbounds — is unaffected; the control plane
// fails and the data plane keeps working. That separation is deliberate and is
// what makes a broken dashboard harmless.
//
// Everything else upstream registers (ssmapi, resolved, derp, ccm, ocm, usbip,
// oomkiller) stays out, which is what keeps their dependency trees out of the
// binary.
func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	api.RegisterService(registry)

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
