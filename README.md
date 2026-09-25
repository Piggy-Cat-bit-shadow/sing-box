# Jiejie Server Edition

Personal server-oriented fork of
[SagerNet/sing-box](https://github.com/SagerNet/sing-box).

- Upstream branch: `testing`
- Product scope: Linux amd64 server
- Production profile: `jiejie_server_minimal`
- Detailed design notes: [`docs/`](docs/)

## Upstream

| Item | Value |
| --- | --- |
| Repository | https://github.com/SagerNet/sing-box |
| Tracked branch | `testing` |
| Fork base | `b609f959f5` |
| Fork version | `1.15.0-jiejie-masquerade.5` |

This fork tracks the upstream `testing` branch and carries a set of server-side
changes. Protocol implementations, routing, DNS, TLS and transport layers come
from upstream; this repository adds deployment-specific server behaviour,
registry narrowing and validation.

## Build Scope

Server-oriented minimal build for Linux amd64. The trim is registration-level:
the minimal registry does not import unused packages, so the linker drops them.
The upstream full build remains available through
`include/registry.go` (`!jiejie_server_minimal`).

Production build tags:

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

**Retained inbound**

```text
HTTP       (MASQUE HTTP/2 and HTTP/3)
AnyTLS
Native Naive
ShadowTLS
Shadowsocks 2022
```

**Retained outbound**

```text
direct
SOCKS5
```

**Retained DNS transports**

```text
udp
local   (required at startup by box.go's DNS transport fallback)
```

**Excluded from the minimal production build**

| Category | Excluded |
| --- | --- |
| QUIC proxy protocols | Hysteria, Hysteria2, TUIC |
| Proxy protocols | VMess, VLESS, Trojan, Snell |
| Client runtime | Naive outbound, Cronet / Chromium client stack |
| Network endpoints | TUN, WireGuard, Tailscale, OpenVPN, OpenConnect |
| Outbounds | HTTP, Shadowsocks, ShadowTLS, AnyTLS, selector, urltest |
| DNS | DoT, DoH, DoQ, hosts, resolved |
| Services | Clash API and unused services |
| Certificate providers | unused certificate providers |

Note: the Naive **inbound** is retained; only the Naive outbound and client
runtime are excluded.

## Change Log

### Native Naive

- `45f6686a61` — Add the Native Naive inbound: authenticated CONNECT, optional
  Padding negotiation, and Web masquerade.
- `77607290f5` — Expose HTTP/2 server resource parameters
  (`max_concurrent_streams`, `idle_timeout`, receive windows).
- `ec1e7ab294` — Register the Native Naive inbound in the production registry.
- `bbcabc9a2e` — Add the UoT v1/v2 data path with end-to-end coverage.
- `c3de03ad48` — UoT sessions release their resources on completion.
- `568e93f140` — Web masquerade coverage for the non-proxy request path.
- `58985a3759` — Compatibility validation against the official NaiveProxy client.
- `c0ba174912` — Linux socket-level acceptance coverage; bounds a UDP loss finding.
- `ce0496a311` — Acceptance run against the production minimal registry build.
- `d0087e877e` — Independent coverage of the UoT exception paths.
- `4085c086dc` — HTTP/2 concurrency, Padding edge cases and destination control.
- `23af897bfd` — Stop honouring the non-standard `-connect-authority` header.
- `b24e294300` — TLS/ALPN, listener matrix and abnormal lifecycle audit.
- `6fd7135235` — UoT data plane beyond the v1/v2 round trips.
- `41bd528cb2` — What the masquerade backend actually receives.
- `fb90272a50` — Padding write path honours the standard `io.Writer`
  short-write contract.
- `eace39c3e6` — Deterministic Padding codec benchmarks.
- `0c83345a3f` — Per-stream authentication isolation and authority handling.
- `593f634a1a` — CONNECT retains tunnel payload already buffered by `net/http`.
- `3bbf179078` — UoT instrumentation; identifies the hijack interaction behind
  the observed loss.
- `10e1f2a957` — Deterministic loss regression and a real retry test.
- `d1f3798a63` — Churn acceptance at 2000 sessions.
- `d4ead1498a` — Per-datagram destination ACL for UoT sessions; ships the Naive
  ACL configuration template.
- `2ec06e451f` — UoT regression tests execute in CI rather than skipping.
- `1dc734f754` — Fault injection replaces the UoT skip; adds STUN and IPv6.
- `d2af551c40` — Tunnel lifecycle and Linux resource coverage.
- `3c6e0aad37` — Bounds the Padding size range so an oversized value cannot
  terminate the connection.
- `fe57895393` — Restores the full Padding range and corrects the buffer
  regression test.
- `e9d3293806` — CONNECT Padding negotiation aligned with the reference.
- `f2907e79a5` — HTTP CONNECT edge cases aligned with the reference.
- `cc9df81f07` — Caddy / forwardproxy differential compatibility harness.
- `83efc0bf00` — HTTP/3 audit against Caddy; pins the Cronet client version.
- `b32bb58f91` — HTTP/1 tunnel framing aligned with the reference.
- `1d66e934f3` — Source identity uses the transport peer by default.
- `7be29e4ba9` — HTTP/2 option bounds validated at decode time.
- `dccf70987e` — Returns the canonical capability error when the HTTP/3
  constructor is absent.
- `c630c9775c` — TCP and QUIC TLS ALPN lists isolated from each other.
- `9c6052b050` — HTTP/3 server policy disables 0-RTT.
- `34628b6daf` — Forwarded-header shapes covered against source spoofing.
- `ade5f465c6` — Canonical QUIC-absent error; widened bounds coverage.
- `ece998f21f` — HTTP/1 tunnel framing settled by byte comparison; removes a
  false divergence finding.
- `1be7647977` — TCP/QUIC ALPN isolation verified at runtime.
- `9885c45cf6` — Real HTTP/2 differential probes against the reference.
- `d480202829` — H3 stream limit measured; remaining H3 differences labelled.
- `0245deff82` — CONNECT response flush is checked as part of connection setup.
- `d921493382` — HTTP/3 incoming stream count returns to the quic-go bounded
  default (`MaxIncomingStreams` unset).
- `086aba2a45` — Padding codec and CONNECT authority fuzzing.
- `318dbee27d` — Differential verdicts and artifact made unambiguous.

### HTTP / MASQUE

- `d53c867b7d` — Inbound masquerade handler: non-proxy requests reach a Web
  backend.
- `f7e51ef60e` — Server resource profile and header limit option.
- `9771af9f49` — `server_profile` and `max_header_bytes` take effect on the
  running server.
- `38491df890` — Unauthenticated resource limits (per-IP concurrency, rate,
  burst, tracked-IP cap).
- `7e57fe8c77` — Over-limit requests do not reach the masquerade backend.
- `1276eb85a2` — Replay-safety invariant pinned across the H3 to H2 path.
- `747c62d263` — Request body bound enforced on the data path.
- `cce49f3877` — Limiter expiry behaviour measured rather than assumed.
- `80ad6df293` — Zero-code H3 closes normalised at the connection boundary.
- `27cd75af45` — HTTP/3 application idle timeout enforced.
- `cd8d702122` — Request header limits enforced on HTTP/3.
- `0eccef3c40` — Authentication precedes the missing-handler response.
- `127ae9c3b9` — Unauthenticated release is idempotent per acquisition.
- `a3cb8abf58` — HTTP/MASQUE source identity uses the transport peer by default;
  `X-Forwarded-For` / `Forwarded` / `X-Real-IP` no longer determine it.
- `2fb3ba6930` — Server resource option bounds validated.

### AnyTLS

- `e97ea9ce82` — Inbound fallback backend.
- `3570205356` — Fallback routed through the configured backend.
- `b1814cd660` — `fallback_for_alpn` routes by negotiated ALPN at runtime.
- `f30f63e0d6` — Bounds the first post-TLS application read with the existing
  TCP timeout budget.
- `5ef800316b` — ALPN behaviour pinned by measurement.
- `7a5212d8b7` — ALPN fallback semantics corrected (mapping hit, default
  fallback, TLS required).
- `93fa2708cb` — Pre-auth probe failures classified by error type.
- `1804358ab2` — Server-side faults remain visible in log classification while
  routine peer lifecycle events are not logged as errors.

### ShadowTLS / SS2022

- `20ce0a05ad` — ShadowTLS v3 probe fallback behaviour pinned.
- `1804358ab2` — Peer lifecycle and server-side fault classification separated
  (also applies to AnyTLS).
- `ec1e7ab294` — Shadowsocks 2022 registered as the production detour target.

### Routing / ACL

- `d4ead1498a` — Per-datagram destination ACL for UoT non-connect sessions.
  The guard performs allow/reject only; it does not re-select an outbound per
  datagram.
- `7029722bff` — Restricted self-target port exception for a local management
  service, without widening the general target ACL.
- `f45e465b83` — Self-hosted HTTPS targets are rewritten to an isolated loopback
  Web ingress, so they do not re-enter the public proxy front door. Proxy ingress
  hostnames are rejected before the suffix rewrite applies.
- `189bc6d0ed` — Documents the loopback Web ingress and the rewrite ordering.

### Minimal Build / Registry

- `bb5b56a460` — Add the Jiejie server build profile.
- `98d8ef0cb3` — Registry-level `jiejie_server_minimal` server build.
- `d8a3c8c222` — Fixture models the real production inbound detours.
- `9d63f155f2` — Remove test-only protocol registrations from the minimal
  registry.
- `918c1521d8` — Production runtime integration coverage for the minimal build.
- `61c05bb63d` — CI tests and publishes only the minimal production build.
- `5ce3c4d675` — Narrow the fork to the VPS-only server product; removes the
  iOS/client product lines.
- `0b27085f6a` — Registry audited against the production topology.

### CI / Validation

- `b21371720a` — Version, build-info, build and packaging scripts.
- `d71841fc6e` — Fast workflow with concurrency, caching and a build gate.
- `61c05bb63d` — Production build selection converged on the minimal artifact.
- `b49c78ca56` — CI gates aligned with the Naive server being production.
- `142df6d2db` — Race detector runs on `./route`.
- `75a32bcd7f` — Naive differential runs against the pinned reference.
- `4ed6dff200` — Naive HTTP/3 integration tests execute instead of skipping.
- `9cce35ec3b` — HTTP/2 differential actually runs in CI.
- `a4f22a5949` — Upstream `testing` sync merge.

### Documentation / Audit

- `5c620c33a4` — Initial Jiejie Server Edition documentation.
- `7c0267f2cc` — Native Naive server, UoT and masquerade.
- `8764f6ec61` — VPS probe-resistance boundaries.
- `427defcbf7` — Production protocol capability matrix.
- `5c5440577d` — Audit claims reconciled with measured coverage: stale H3 claims
  removed, over-broad PASS labels downgraded to PARTIAL / NOT-TESTED, and
  remaining unverified items consolidated.

## Removed / Superseded Work

Listed so older commits are not misread as current capability.

- Earlier iOS / Libbox / IPA build experiments were removed by `5ce3c4d675`
  when the fork was narrowed to the VPS-only server product.
- Earlier Linux client-full and Windows client build profiles were removed by
  the same convergence.
- Earlier HTTP/3 client connection-pool and fallback/backoff work is not part of
  the current server scope; `http3_connection_pool` and `http3_fallback` no
  longer exist in the option or transport packages.
- HTTP/3 client-specific work in this history targets a client that this product
  no longer ships.

The server-side HTTP/3 work that remains is limited to the server listener and
its request handling.

## Maintenance Notes

- **Upstream sync** — rebase/merge from upstream `testing`; fork changes are kept
  concentrated in new files, option parsing, registries and build tags to limit
  conflict surface. See [`docs/FORK-DIFF.md`](docs/FORK-DIFF.md).
- **Production tags** — read from `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`;
  scripts and workflows read the same file so they cannot drift.
- **Registry changes** — every registration in
  `include/registry_jiejie_server.go` must be justified by the production
  topology fixture; the registry audit test fails on drift.
- **Known unverified areas** — HTTP/3 Caddy differential, parts of the
  half-close matrix, packet-level H3 SETTINGS, connection migration behaviour,
  and a controlled BBR/CUBIC benchmark. These are recorded as NOT-TESTED and
  should not be treated as validated.
- **Detailed documentation** — architecture and audits live under [`docs/`](docs/);
  `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md` states what is verified per
  component.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
