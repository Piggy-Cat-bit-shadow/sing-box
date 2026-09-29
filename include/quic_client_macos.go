//go:build with_quic && jiejie_client_macos

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
)

// QUIC surface for the Jiejie macOS client build.
//
// # Why with_quic is set at all
//
// This tag is REQUIRED by this product, and its reason is MASQUE, not any of the
// protocols that happen to live behind the same tag:
//
//   - the MASQUE client endpoint and its HTTP/3 transport
//   - CONNECT-IP framing carried as HTTP Datagrams
//   - the same-connection DoH work that reuses the MASQUE HTTP/3 connection
//
// Removing `with_quic` would break the product's headline capability. Nothing below
// changes that: this file controls only which OTHER QUIC consumers are dragged in
// alongside it.
//
// # What is registered
//
//   - DoQ and DoH3 DNS transports. They are cheap here: the HTTP/3 client stack they
//     share is required by MASQUE regardless, so registering them adds registration
//     entries rather than a dependency tree.
//
// # What is NOT registered, and why
//
//   - Hysteria2 and TUIC outbounds. Neither appears in the production configuration,
//     and neither is a capability this product offers. An earlier revision registered
//     both and described them as "part of the Jiejie client feature set", which was
//     never true of this deployment. The production config is the authority.
//
//     Critically, this was not only a registration decision. The previous version
//     IMPORTED both packages in order to call their RegisterOutbound functions, and a
//     Go import forces the package into the link and runs its `init()` whether or not
//     the registration is ever called. So "not registered" was still paying for the
//     packages. The imports are gone, and the dependency graph is asserted to be free
//     of both rather than assumed to be.
//
//   - the v2ray QUIC transport. This one is worth stating carefully because it is easy
//     to defend by accident: VLESS uses it for QUIC-based packet encoding, and VLESS
//     IS a production protocol. But the production VLESS outbound uses Reality/Vision
//     over TCP and configures no `"transport": {"type": "quic"}`. A protocol being in
//     use does not mean every transport it could theoretically pair with is in use.
//
//     This is also emphatically NOT the same thing as MASQUE's HTTP/3. The two are
//     unrelated implementations that both happen to involve QUIC, and conflating them
//     is exactly how a MASQUE requirement gets used to justify keeping a V2Ray
//     transport alive. Removing this import does not touch MASQUE.
//
//   - Hysteria v1 and its realm service: superseded, and keeping either would pull in
//     the whole Hysteria v1 congestion-control and masquerade tree.
//
//   - the Hysteria2 realm service: a client consumes a realm, it does not serve one.
//     registerQUICServices is therefore empty.
//
// # Why protocol/naive/quic is not imported here
//
// Removing that import was a correction, not a trim, and the reasoning still holds:
// protocol/naive/quic does exactly two things, both in init(), and both SERVER-side:
//
//	naive.ConfigureHTTP3ListenerFunc = ...   // qtls.ListenEarly + http3.Server
//	naive.WrapError = qtls.WrapError
//
// ConfigureHTTP3ListenerFunc is called only from protocol/naive/inbound.go and
// WrapError only from protocol/naive/inbound_conn.go -- the native Naive HTTP/3
// LISTENER and its connection wrapper. This product is outbound-only: it has no Naive
// inbound (the registry audit asserts `naive` is absent from the inbound registry),
// and its Naive outbound goes through `cronet.NewNaiveClient`.
//
// So the import linked a complete HTTP/3 server listener -- qtls.ListenEarly,
// http3.Server, and the congestion_meta1/meta2 trees -- into a binary that could never
// call it. Everything a Naive CLIENT needs is unaffected: the outbound over HTTP/2,
// the same outbound over QUIC/HTTP/3 via `"quic": true` (which selects Cronet's stack,
// not this listener), and Cronet itself.
//
// The removal is verified by symbol audit rather than by this comment:
// scripts/ci/audit-macos-client-registry.sh asserts the native-Naive H3 listener
// symbols are absent while the Naive outbound still resolves.
//
// # No friendly stubs
//
// These functions deliberately do NOT register error stubs for the removed protocols.
// Importing a package purely to produce a nicer message would pull back the very code
// the trim exists to remove. A config naming a removed type fails `sing-box check`
// with "unknown outbound type", which is the honest outcome and is what the negative
// registry tests assert.
func registerQUICInbounds(registry *inbound.Registry) {
	// No QUIC *inbound* is registered: this is an outbound-only product with no
	// Hysteria2/TUIC server role. The TUN inbound that matters lives in the base
	// registry, not here.
}

func registerQUICOutbounds(registry *outbound.Registry) {
	// Intentionally empty. See the file comment: Hysteria2 and TUIC are not part of
	// this product, and keeping their imports alive would link them regardless of
	// whether this function registers them.
}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}

func registerQUICServices(registry *service.Registry) {}
