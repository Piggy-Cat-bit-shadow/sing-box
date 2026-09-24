//go:build jiejie_server_minimal

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
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
)

// Registry for the Jiejie Server Edition minimal build (`jiejie_server_minimal`).
//
// Every registration below is justified by the real production configuration of
// one specific server. Nothing is registered for test convenience: the test
// harness adapts to this registry, never the other way round.
//
// The trim is registration-level only. No upstream protocol source is edited or
// deleted; a package this file does not import never enters the import graph, so
// the Go linker drops it.
//
// Production topology this registry serves:
//
//	TCP/443  Nginx Stream -> 127.0.0.1:28436 anytls-in  (native fallback -> 28437)
//	                      -> 127.0.0.1:28440 masque-h2 (behind Nginx, HTTP/2)
//	                      -> 127.0.0.1:8554  shadowtls-in
//	                           detour -> ss2022-in -> route -> residential-socks / direct
//	UDP/443  masque-h3 (HTTP/3, MASQUE L4)
//	DNS      direct.domain_resolver and the ShadowTLS handshake resolver -> local-agh (UDP)
//
// The ports above are the ones release/jiejie-production-topology.json actually
// declares, which is the reference baseline. Keep the two in step: the fixture is
// what `sing-box check` and the integration tests exercise, so a comment that
// disagrees with it is simply wrong.
//
// See docs/JIEJIE-SERVER.md for the full rationale.

func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

// InboundRegistry registers the five public entry points, and nothing else.
//
// naive is the Native Naive server (klzgrad/naiveproxy-compatible CONNECT plus
// UoT v1/v2 and a Web masquerade). It adds NO UDP listener: UoT is carried inside
// the HTTP/2 CONNECT over TCP, so UDP/443 stays exclusively MASQUE.
//
// Registering this inbound deliberately does NOT pull in the Naive OUTBOUND or
// the Chromium/Cronet client stack: protocol/naive/outbound.go carries its own
// `with_naive_outbound` build tag, so a server build compiles only inbound.go and
// inbound_conn.go. `go list -deps ./include` confirms cronet is absent.
//
// The socks and direct inbounds are deliberately NOT registered. Both previously
// existed only so the integration tests could use an in-process client, which let
// the test harness dictate the production binary. The tests now use real protocol
// clients (HTTP/2, quic-go HTTP/3, sing-anytls, sing-shadowtls, sing-shadowsocks)
// or a separately built test client, so neither inbound is needed here.
func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	http.RegisterInbound(registry)        // MASQUE over HTTP/2 (behind Nginx Stream) and HTTP/3 (UDP/443)
	anytls.RegisterInbound(registry)      // AnyTLS, with native fallback to the Nginx web root
	naive.RegisterInbound(registry)       // Native Naive, incl. UoT v1/v2 and the Web masquerade
	shadowtls.RegisterInbound(registry)   // ShadowTLS v3; detour targets the ss2022-in inbound
	shadowsocks.RegisterInbound(registry) // Shadowsocks 2022, the ShadowTLS detour target

	registerQUICInbounds(registry)

	return registry
}

// OutboundRegistry registers exactly the two outbounds the production config
// uses: direct, and the residential SOCKS5 upstream.
//
// block, selector, urltest, http, shadowsocks, shadowtls and anytls outbounds are
// deliberately NOT registered:
//
//   - block is unnecessary. A route `reject` action returns a RejectedError from
//     route/rule/rule_action.go and never resolves an outbound, so reject rules
//     work without it. This was verified in source rather than assumed.
//   - selector and urltest are not in the production routing table.
//   - the http, shadowsocks, shadowtls and anytls outbounds exist on this server
//     only for debugging and for the fork's client-side feature tests. Those run
//     against the full/upstream build, so registering them here would enlarge the
//     production binary purely to satisfy tests.
func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry) // direct, used by the default route and by DNS
	socks.RegisterOutbound(registry)  // residential-socks, the SOCKS5 upstream

	registerQUICOutbounds(registry)

	return registry
}

// EndpointRegistry registers no endpoint: the production config uses none.
func EndpointRegistry() *endpoint.Registry {
	return endpoint.NewRegistry()
}

// DNSTransportRegistry registers the production resolver plus the transport
// sing-box itself requires to start.
//
// The production resolver is local-agh, a plain `type: udp` server pointing at
// 127.0.0.1:53 (AdGuard Home), so `udp` is the only one configured.
//
// `local` is ALSO required, and this was established by running the build rather
// than by reading the config: box.go unconditionally initialises the DNS
// transport manager with a fallback that creates a C.DNSTypeLocal transport, so
// omitting it makes every start fail with "default DNS server fallback:
// transport type not found: local". It is not a feature choice, it is a boot
// dependency.
//
// The tcp, tls, https, hosts and resolved transports are genuinely absent:
//
//   - tcp: not needed even for truncation fallback. dns/transport/udp.go
//     Exchange() inspects response.Truncated and calls its own exchangeTCP(),
//     which dials TCP through the same dialer and never consults the transport
//     registry. Covered by TestJiejieMinimalDNSTruncatedTCPFallback.
//   - tls/https: the server uses local-agh over UDP; no DoT or DoH is configured.
//   - hosts: no static host entries are configured.
//   - resolved: systemd-resolved is not this server's resolver, and dropping it
//     also keeps the D-Bus dependency out of the binary.
func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterUDP(registry)
	local.RegisterTransport(registry)

	registerQUICTransports(registry)

	return registry
}

// ServiceRegistry registers nothing.
//
// The production config uses no sing-box service. In particular systemd-resolved
// is not this server's resolver (local-agh is), so neither the resolved transport
// nor its service is present, which also keeps the D-Bus dependency out of the
// binary.
func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	registerQUICServices(registry)

	return registry
}

// CertificateProviderRegistry registers no provider.
//
// Certificates are provisioned by acme.sh outside sing-box, so neither the ACME
// provider nor the Cloudflare Origin CA provider is needed. Dropping the latter
// also drops the certmagic dependency it pulled in for its storage interface.
func CertificateProviderRegistry() *certificate.Registry {
	return certificate.NewRegistry()
}
