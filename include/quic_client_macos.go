//go:build with_quic && jiejie_client_macos

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/tuic"
	_ "github.com/sagernet/sing-box/transport/v2rayquic"
)

// QUIC registration surface for the Jiejie macOS client build.
//
// # What is kept
//
//   - Hysteria2 and TUIC outbounds: both are part of the Jiejie client feature
//     set and neither is reachable without `with_quic`.
//   - DoQ and DoH3 DNS transports (`quic.RegisterTransport` /
//     `RegisterHTTP3Transport`): a desktop client legitimately configures a QUIC
//     resolver, and FakeIP + DoH3 is a common GUI template.
//   - the v2ray QUIC transport, which VLESS needs for its QUIC-based packet
//     encoding.
//
// # Why protocol/naive/quic is NOT imported here
//
// This import used to be present, and removing it is a correction rather than a
// trim. protocol/naive/quic does exactly two things, both in init():
//
//	naive.ConfigureHTTP3ListenerFunc = ...   // qtls.ListenEarly + http3.Server
//	naive.WrapError = qtls.WrapError
//
// Both are SERVER-side. ConfigureHTTP3ListenerFunc is called only from
// protocol/naive/inbound.go, and WrapError only from protocol/naive/inbound_conn.go
// -- the Native Naive HTTP/3 LISTENER and its connection wrapper. The macOS client
// is outbound-only: it has no Naive inbound (the registry audit asserts `naive` is
// absent from the inbound registry), and its Naive outbound goes through
// `cronet.NewNaiveClient`, not through this package.
//
// So the import linked a complete HTTP/3 server listener stack -- qtls.ListenEarly,
// http3.Server, and the congestion_meta1/meta2 trees -- into a binary that could
// never call it. With `with_quic` set, the client profile was paying for a server
// it cannot run.
//
// Everything that actually matters for a Naive CLIENT is unaffected:
//
//   - Naive outbound over HTTP/2: protocol/naive/outbound.go, linked under
//     with_naive_outbound (the Naive flavor).
//   - Naive outbound over QUIC/HTTP/3: the same outbound with `"quic": true`,
//     which selects Cronet's QUIC stack, not this listener.
//   - Cronet: unchanged; it is the outbound implementation.
//
// The removal is verified by symbol audit rather than by reading this comment:
// scripts/ci/audit-macos-client-registry.sh asserts the native-Naive H3 listener
// symbols are absent while the Naive outbound still resolves.
//
// # What is deliberately NOT registered
//
//   - Hysteria v1 and its realm service: superseded by Hysteria2, which is what
//     the Jiejie client offers, and keeping it would pull the whole Hysteria v1
//     congestion-control and masquerade tree into the binary.
//   - the Hysteria2 realm service: a client consumes a realm, it does not serve
//     one. registerQUICServices is therefore empty.
//
// Like the server-minimal variant, these functions do NOT register friendly
// error stubs for the removed protocols. Importing a protocol purely to produce a
// nicer message would pull back the very package the trim exists to remove. A
// config naming a removed type fails `sing-box check` with "unknown outbound
// type", which is the honest outcome.
func registerQUICInbounds(registry *inbound.Registry) {
	// No QUIC *inbound* is registered.
	//
	// This is not a trim: the Jiejie macOS client is an outbound-only product.
	// It has no Hysteria2/TUIC server role, and the TUN inbound that matters is
	// registered in the base registry, not here.
}

func registerQUICOutbounds(registry *outbound.Registry) {
	tuic.RegisterOutbound(registry)
	hysteria2.RegisterOutbound(registry)
}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}

func registerQUICServices(registry *service.Registry) {}
