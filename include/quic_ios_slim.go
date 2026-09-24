//go:build with_quic && jiejie_ios_slim

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
	_ "github.com/sagernet/sing-box/transport/v2rayquic"
)

// QUIC registration surface for the Jiejie iOS slim build.
//
// with_quic is required, but the QUIC *protocols* the default registry registers
// on top of it are not all wanted:
//
//   - Hysteria, Hysteria2 and TUIC are not part of the Jiejie client feature set.
//     Registering them also pulls their whole dependency trees (sing-quic's
//     hysteria congestion control, the Hysteria2 realm/STUN internals, sing-quic
//     tuic) into the binary, which is a large part of what this profile saves.
//   - the Hysteria2 realm service comes with Hysteria2 and goes with it.
//
// What is kept is what the client genuinely uses:
//
//   - the DoQ and DoH3 DNS transports, so a user can configure a QUIC resolver;
//   - the v2ray QUIC transport, which VLESS needs for its QUIC-based packet
//     encoding;
//   - the naive QUIC import, which the NaiveProxy inbound can use.
//
// Like the server-minimal version, these functions do NOT register friendly
// error stubs for the removed protocols: importing a protocol purely to produce a
// nicer message would pull back the package the trim exists to remove. A config
// naming a removed type fails `sing-box check` with "unknown outbound type",
// which is the honest outcome.

func registerQUICInbounds(registry *inbound.Registry) {}

func registerQUICOutbounds(registry *outbound.Registry) {}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}

func registerQUICServices(registry *service.Registry) {}
