//go:build with_quic && jiejie_server_minimal

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
)

// QUIC registration surface for the minimal server build.
//
// MASQUE HTTP/3 is implemented by transport/http/server_h3.go, which `with_quic`
// compiles on its own; it needs nothing registered here. Everything this file
// would otherwise register (Hysteria, Hysteria2, TUIC, naive QUIC, the v2ray
// QUIC transport, DoQ/DoH3 and the Hysteria2 realm service) is absent from this
// server's production config, so the functions are deliberately empty.
//
// They do NOT register error stubs. An earlier revision imported
// protocol/naive and transport/v2ray purely to return a friendlier error for a
// protocol this build removes. That defeats the purpose of a minimal build: the
// import pulls the very package the trim exists to remove back into the import
// graph. A config referencing a removed type now fails at `sing-box check` with
// "unknown inbound type" (or the equivalent), which is acceptable and keeps the
// binary honest.
//
// The one safety net that needs no import already exists upstream:
// transport/v2ray.NewQUICServer returns os.ErrInvalid when no constructor is
// registered, so leaving the constructor unset is a supported state.

func registerQUICInbounds(registry *inbound.Registry) {}

func registerQUICOutbounds(registry *outbound.Registry) {}

func registerQUICTransports(registry *dns.TransportRegistry) {}

func registerQUICServices(registry *service.Registry) {}
