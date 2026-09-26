//go:build with_quic && jiejie_client_macos

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
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
//   - the naive QUIC import, which protocol/naive/quic implements for the
//     NaiveProxy client. This package carries no build tag of its own, so it is
//     pulled in by this import exactly as the server build does; when
//     `with_naive_outbound` is off, protocol/naive/outbound.go is not compiled
//     and the server-side half of that package is unused.
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
