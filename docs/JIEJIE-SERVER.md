# Linux Server Minimal

The production server is a Linux amd64, CGO-disabled sing-box binary built from `testing` with the
tags in `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`. Its configuration contract is the
[production topology](../release/jiejie-production-topology.json); build and CI detail is in
[build profiles](BUILD-PROFILES.md).

## Product capabilities

| Capability | Current role |
| --- | --- |
| MASQUE H2/H3 | The authenticated proxy front door: HTTP CONNECT and CONNECT-UDP over HTTP/2 and HTTP/3. |
| AnyTLS | A TLS-camouflaged inbound with a fallback destination for traffic that is not an accepted session. |
| Native Naive | A NaiveProxy server inbound, including UoT, padding, masquerade and pre-authentication limits. |
| ShadowTLS v3 + SS2022 | The TLS-camouflage chain; ShadowTLS v3 detours to a Shadowsocks 2022 inbound. |
| Residential SOCKS | A SOCKS5 outbound that carries residential TCP after the target is resolved to IPv4 on this host. |
| DNS transports | `udp` and `local` only. `local` is required for startup fallback. |

The registry is `include/registry_jiejie_server.go`: inbounds `http`, `anytls`, `naive`,
`shadowtls`, `shadowsocks`; outbounds `direct`, `socks`; no endpoints and no services. Native Naive
is a production inbound, not a compatibility layer. The server does not register a Naive outbound
and does not link the client's Cronet stack.

## Production topology

| Plane | Owner | Notes |
| --- | --- | --- |
| TCP/443 | Nginx | The public front door. `ssl_preread` routes by SNI and ALPN before any TLS session reaches sing-box. |
| UDP/443 | sing-box | HTTP/3 MASQUE terminates directly. It does not pass through Nginx. |
| Loopback backends | sing-box | MASQUE H2, AnyTLS, Native Naive and ShadowTLS/SS2022 listen on loopback behind the front door. |

The topology fixture carries example credentials and certificate paths; it is a contract, not a
deployable secret-bearing configuration.

## AnyTLS fallback

Fallback happens after TLS termination: the backend receives the decrypted stream, so a plaintext
HTTP/1.1 backend is the simple deployment. `sing-anytls` caches the probe bytes it read while
checking authentication, so the backend receives the complete original stream.

- An authenticated AnyTLS session never falls back. The fallback backend is dialed only after
  authentication fails.
- Omitting both fields preserves the upstream authentication-failure behaviour.
- `fallback_for_alpn`, when present, **rejects** a negotiated ALPN that has no configured entry.
  The default `fallback` is used only when no ALPN was negotiated at all.
- Do not point a fallback at the AnyTLS listener itself; that configuration loops.
- The fork does not translate HTTP/2 to HTTP/1.1. An `h2`-negotiated backend receives the plaintext
  HTTP/2 preface and frames, so it must genuinely support h2c. The fork does not override TLS ALPN;
  set `tls.alpn` explicitly. Advertising only `http/1.1` with a plaintext HTTP/1.1 backend is the
  supported simple deployment.

Fields are documented in [AnyTLS inbound](configuration/inbound/anytls.md).

## MASQUE masquerade

Unauthenticated and wrong-password requests can be served by a masquerade handler, so the port
answers like an ordinary website. The authenticated data plane — CONNECT, extended CONNECT,
CONNECT-UDP, HTTP Datagram, QUIC and routing — is unmodified.

- **The resource limiter runs before the masquerade.** An over-limit request that also fails
  authentication receives a locally generated `429` and never reaches the masquerade backend.
  Serving the proxy masquerade over-limit would still issue one backend request per probe, which is
  what the limit exists to prevent. Accounting is released the moment authentication succeeds, so an
  authenticated client is never denied.
- Rejection requires **both** failing authentication and exceeding the budget.
- With masquerade configured, unauthenticated and wrong-password requests are the intended design
  path and are logged at DEBUG. Without it, a real 401/407 is returned and logged at ERROR.
- The masquerade schema reuses the Hysteria2 types (`proxy`, `file`, `string`). A reverse proxy
  preserves the backend's real status and body; it does not manufacture a fixed `200 OK`.

**Masquerade does not make the protocol undetectable.** The `429` decoy is not claimed to be
path-indistinguishable: it returns the same body for every over-limit request and does not forward
the request path.

Fields are documented in [HTTP inbound](configuration/inbound/http.md).

## Nginx ALPN front door

TCP/443 belongs to Nginx; sing-box owns UDP/443 and the loopback backends. The MASQUE HTTP/2
inbound is configured for HTTP/2 only.

Route the MASQUE SNI to the H2 backend **only** when the client negotiated `h2`. Everything else on
that SNI is ordinary web traffic and must reach the normal HTTPS web backend over HTTP/1.1. Without
that split, an `http/1.1`, no-ALPN or garbage-ALPN client reaches an H2-only listener where the TLS
handshake completes but the HTTP conversation then fails in a way an ordinary web server would not
produce — an active-probe signal visible before authentication is ever considered.

This is a deployment-layer concern, not a sing-box wire-protocol concern: Nginx already reads ALPN
during `ssl_preread`, so the decision is free and happens before any TLS session reaches sing-box.
No sing-box source file is involved, and no byte of any wire protocol changes.

Two illustrative fragments, showing the shape rather than a committed configuration:

```nginx
# $ssl_preread_alpn_protocols is a COMMA-SEPARATED list, so this is a membership
# test, not a substring test. The anchors stop a future "h2c"-like value matching.
map $ssl_preread_alpn_protocols $wants_h2 {
    default            0;
    "~*(^|,)h2(,|$)"   1;
}

# The compound key is consulted only for the MASQUE SNI. The default is the EMPTY
# STRING so a mistyped entry fails loudly in `nginx -t` instead of misrouting.
map "$masque_key $wants_h2" $masque_backend {
    default   "";
    "riri 1"  127.0.0.1:28440;
    "riri 0"  127.0.0.1:9443;
}
```

`ssl_preread on;` must stay on the `server` block: without it the `$ssl_preread_*` variables are
empty, both maps take their default, and every client goes to one backend.

**There is no production Nginx configuration in this repository.** None of this is applied by any
build, test or CI job; repository tests do not prove that a real VPS has deployed it. It is an
operator-facing step, applied and verified on the server with `nginx -t` and per-SNI checks.

## Residential chain

```text
Residential client
  -> Residential-AnyTLS   (UDP rejected)
  -> this VPS: resolve ipv4_only
  -> residential-socks    (SOCKS5)
  -> residential exit     (IPv4)
  -> IPv4 target
```

- DNS stays on this host by design. The residential SOCKS server does not resolve target domains, so
  the chain resolves here with `strategy: ipv4_only` and hands SOCKS5 an address, never a hostname.
  There is deliberately no remote-DNS mode: no SOCKS5h behaviour, no "residential DNS", no GeoDNS.
- `resolve` must be ordered **before** the routing rule. A resolve action needs the destination to
  still be a domain; if the route ran first, the proxy would receive a hostname and resolve it
  itself, moving DNS to the residential provider. The ordering is pinned by
  `TestProductionResidentialChainOrdering` against the topology fixture.
- Residential UDP is rejected. The residential exit is IPv4 TCP only, so a datagram path would
  either leak or fail silently.
- Ordinary AnyTLS is a different path: `AnyTLS -> direct -> local DNS -> IPv4 / IPv6`, dual stack.
  Do not confuse the two.
- The residential VLESS data plane (`Residential-VLESS-Reality -> Xray -> residential-socks`) belongs
  to Xray and is outside this repository.

Pool and tuning fields are documented in
[SOCKS outbound](configuration/outbound/socks.md).

## HTTP inbound resource fields

Controls are explicit per inbound and decoded for the inbound's selected `version`; the JSON shape
follows `option/simple.go`, `option/http.go` and [`schema.json`](schema.json).

| Field | Current behavior |
| --- | --- |
| `max_header_bytes` | H2/H3 request-header limit; unset uses upstream's 1 MiB limit. |
| `max_concurrent_streams` | Applies to the selected H2/H3 option set. H3 unset retains quic-go's bounded default of 100 incoming streams. |
| `idle_timeout`, `keep_alive_period` | Per-version connection lifetime. H3 `idle_timeout` also reaches the HTTP/3 application server. |
| `stream_receive_window`, `connection_receive_window` | Per-version receive windows; invalid numeric bounds are rejected. |
| `initial_packet_size`, `disable_path_mtu_discovery` | QUIC options for H3. |
| `quic_congestion_control` | H3 sender choice. Unset leaves quic-go's default unchanged. |
| `unauthenticated_limits` | Optional pre-authentication limits; authenticated proxy traffic is unaffected. |

The production topology explicitly selects a congestion-control profile on H3; that is a deployment
choice, not the unset behaviour. The H3 proxy listener disables 0-RTT because CONNECT is not
replay-safe.

`unauthenticated_limits` bounds per-source-IP concurrency, request rate, burst, idle expiry and the
number of tracked IPs. Its source address is what the inbound sees: a loopback H2 listener behind
Nginx sees Nginx unless the front door supplies a separately trusted identity. Field granularity is
in the schema and the `transport/http` limiter tests.

## Build and verification

```sh
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
```

The script reads the server tag file; the normal CI path builds and checks the production binary,
and manual deep checks add vet, reproducibility, race/fuzz work and reference interop.

| Capability | Evidence |
| --- | --- |
| MASQUE H2/H3 CONNECT data plane | `transport/http` lifecycle tests, including a real quic-go HTTP/3 server. |
| AnyTLS ALPN fallback | `test/jiejie/jiejie_anytls_alpn_test.go`. |
| Native Naive server behavior | See the verification section of [Native Naive](naive.md). |
| Residential chain ordering | `TestProductionResidentialChainOrdering` against the topology fixture. |
| Registry and topology | The production contract tests in the Linux workflow. |

These tests cover particular protocol paths and resource rules. They do not establish a VPS capacity
limit, WAN throughput or long-running production stability. Evidence boundaries are in
[engineering notes](ENGINEERING-NOTES.md).
