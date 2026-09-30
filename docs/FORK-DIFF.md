# Current fork diff manifest

`testing` is the sole long-term source branch. Linux amd64 server and macOS arm64 client binaries come from the same tree, with distinct build tags and registries. See [build profiles](BUILD-PROFILES.md).

| Area | Current fork behavior | Source |
| --- | --- | --- |
| MASQUE | HTTP inbound serves authenticated CONNECT over H2/H3 with masquerade; the client has a MASQUE endpoint and HTTP outbound. | `protocol/http`, `protocol/masque`, `transport/masque`, `transport/http` |
| AnyTLS | Inbound supports default and ALPN-specific fallback. | `option/anytls.go`, `protocol/anytls` |
| Native Naive | Server minimal registers the Native Naive inbound; the macOS client uses a separately tagged Cronet outbound. | `include/registry_jiejie_server.go`, `include/registry_jiejie_client_macos.go` |
| HTTP resources | Explicit per-inbound header, H2/H3, BBR and unauthenticated-request options. | `option/simple.go`, `option/http.go`, `transport/http` |
| Server registry | Inbounds: `http`, `anytls`, `naive`, `shadowtls`, `shadowsocks`; outbounds: `direct`, `socks`; DNS: `udp`, `local`; no endpoints or services. | `include/registry_jiejie_server.go` |
| macOS registry | `tun` and `mixed` inbounds, selected client outbounds, `masque-client`, client DNS transports and Native API service. | `include/registry_jiejie_client_macos.go`, `include/quic_client_macos.go` |
| Production topology | MASQUE H2/H3, AnyTLS, Native Naive, ShadowTLS v3 and SS2022; residential TCP uses a SOCKS5 outbound after IPv4 resolution. | `release/jiejie-production-topology.json` |

The default-tag upstream full registry remains available. Product build tags select capabilities, not separate copies of protocol implementations. The Linux and macOS workflows each have a routine artifact path and manually requested deep checks. Current source, registry and topology take precedence if this manifest drifts.
