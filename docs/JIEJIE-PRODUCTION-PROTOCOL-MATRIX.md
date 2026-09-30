# Production protocol capability matrix

This matrix describes the Linux server build selected by `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` and `include/registry_jiejie_server.go`. The deployment shape is in the [production topology](../release/jiejie-production-topology.json).

| Capability | Current implementation | Focused evidence |
| --- | --- | --- |
| MASQUE H2/H3 | `http` inbound, authenticated CONNECT, masquerade and QUIC/H3 transport | `transport/http` tests; `test/jiejie/jiejie_masque_connect_udp_ipv6_test.go`; reference module in manual deep checks |
| H3 stream limit | Bounded by quic-go default (currently 100) when unset; explicit `max_concurrent_streams` overrides it | `transport/http/server_h3.go`, `transport/http/server_h3_defaults_test.go` |
| H3 congestion control | Unset leaves quic-go default (currently CUBIC); explicit `bbr_profile` selects BBR | `transport/http/server_h3.go`, `transport/http/server_h3_defaults_test.go`, `transport/http/server_h3_options_runtime_test.go` |
| AnyTLS | Inbound with default and ALPN-specific fallback | `test/jiejie/jiejie_anytls_alpn_test.go`, `test/jiejie/jiejie_anytls_first_read_test.go` |
| Native Naive | Production inbound with TCP CONNECT, UoT and masquerade; no server Cronet outbound | `include/registry_jiejie_server.go`, `test/jiejie/jiejie_naive_connect_security_test.go` |
| ShadowTLS v3 / SS2022 | Registered inbounds; topology detours ShadowTLS into SS2022 | `include/registry_jiejie_server.go`, production topology |
| Residential SOCKS5 | Registered `socks` outbound; topology rejects residential UDP and resolves TCP destinations to IPv4 | `include/registry_jiejie_server.go`, production topology |
| DNS | `udp` serves local AdGuard Home; `local` remains for startup fallback | `include/registry_jiejie_server.go`, minimal DNS fallback test |

A registry entry does not prove wire interoperability. Unit and local integration tests cover their named paths. Linux manual deep checks add reference suites. Actual WAN conditions, live IPv6 H3 PTB and long-term VPS resource stability remain separate verification work. See [engineering notes](ENGINEERING-NOTES.md) and [server documentation](JIEJIE-SERVER.md).
