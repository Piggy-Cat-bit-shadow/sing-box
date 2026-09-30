# Jiejie Server Edition

The production server is a Linux amd64, CGO-disabled sing-box binary built from `testing` with the tags in `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`. Its configuration contract is the [production topology](../release/jiejie-production-topology.json); the TCP front-door rules are in [Nginx ALPN hardening](JIEJIE-NGINX-ALPN-HARDENING.md).

## Production topology and registry

| Component | Registered types or role |
| --- | --- |
| Inbounds | `http` (MASQUE H2/H3), `anytls`, `naive`, `shadowtls`, `shadowsocks` |
| Outbounds | `direct`, `socks` (residential exit) |
| Endpoints / services | None |
| DNS transports | `udp`, `local` (`local` is required for startup fallback) |

These entries come from `include/registry_jiejie_server.go`. Native Naive is a production inbound, not a compatibility layer. The server does not register a Naive outbound or link the client's Cronet stack.

The topology uses MASQUE H3 on UDP/443; loopback MASQUE H2, AnyTLS and Native Naive sit behind the TCP front door. ShadowTLS v3 detours to SS2022. Residential users' UDP is rejected; their TCP destination is resolved to IPv4 before `residential-socks` connects. The topology fixture has example credentials and certificate paths and is not a deployable secret-bearing configuration.

## HTTP inbound resource fields

Controls are explicit per inbound. The JSON shape follows `option/simple.go`, `option/http.go` and [`schema.json`](schema.json); HTTP version options are decoded for the inbound's selected `version`.

| Field | Current behavior |
| --- | --- |
| `max_header_bytes` | H2/H3 request-header limit; unset uses upstream's 1 MiB limit. |
| `max_concurrent_streams` | Applies to the selected H2/H3 option set. H3 unset retains quic-go's bounded default of 100 incoming streams; an explicit value overrides it. |
| `idle_timeout`, `keep_alive_period` | Per-version connection lifetime settings. H3 `idle_timeout` also reaches the HTTP/3 application server. |
| `stream_receive_window`, `connection_receive_window` | Per-version receive windows; invalid numeric bounds are rejected. |
| `initial_packet_size`, `disable_path_mtu_discovery` | QUIC options for H3. |
| `bbr_profile` | H3 server congestion-control choice: `conservative`, `standard` or `aggressive`. Unset leaves quic-go's default control unchanged (currently CUBIC). |
| `unauthenticated_limits` | Optional per-inbound pre-authentication limits; authenticated proxy traffic is unaffected. |

The production topology explicitly selects `bbr_profile: "standard"` on H3. This is a deployment choice, not the unset behavior. The H3 proxy listener disables 0-RTT because CONNECT is not replay-safe.

`unauthenticated_limits` provides per-source-IP concurrency and request-rate limits, burst capacity, idle expiry and a tracked-IP cap. Its source address is what the inbound sees: a loopback H2 listener behind Nginx sees Nginx unless the front door supplies a separately trusted identity. Exact field bounds are in the schema and `transport/http` limiter tests.

## Other inbound fields

| Inbound | Field | Contract |
| --- | --- | --- |
| AnyTLS | `fallback` | Default destination for traffic that is not an accepted AnyTLS session. |
| AnyTLS | `fallback_for_alpn` | Optional ALPN-specific destination; unmatched or absent ALPN uses the default fallback. |
| Native Naive | `server_limits` | Optional server resource controls; omission leaves these optional limits unset. |

AnyTLS fallback is exercised in `test/jiejie/jiejie_anytls_alpn_test.go`. Native Naive details are in [Native Naive server](JIEJIE-NAIVE-SERVER.md) and [Naive resource controls](JIEJIE-NAIVE-RESOURCE-CONTROLS.md).

## Build and verification

```sh
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
```

The build script reads the server tag file. The normal CI path builds and checks the production binary; manual deep checks add vet, reproducibility, race/fuzz work and reference interop. See [build profiles](BUILD-PROFILES.md) for the current CI contract.

The checked-in tests cover particular protocol paths and resource rules. They do not establish a VPS capacity limit, WAN throughput or long-running production stability. The evidence boundaries are in [engineering notes](ENGINEERING-NOTES.md) and the [protocol matrix](JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md).
