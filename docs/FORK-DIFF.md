# Fork diff manifest

Base: `SagerNet/sing-box` `testing`
Fork: `Piggy-Cat-bit-shadow/sing-box`
Current version: `1.15.0-jiejie-masquerade.3`
Development branch: `feat/jiejie-server-edition`
Production branch: `testing`

This fork intentionally changes only the following areas. Everything is
optional and off by default; an unmodified configuration behaves like upstream.
See [JIEJIE-SERVER.md](JIEJIE-SERVER.md) for the full reference.

## Patch 1: HTTP inbound masquerade

The HTTP inbound can use the existing Hysteria2-style `masquerade` schema for
failed authentication in the shared HTTP/2 and HTTP/3 handler. Authenticated
HTTP CONNECT, CONNECT-UDP, HTTP Datagram, QUIC, and routing paths are not
changed. See [FORK-MASQUERADE.md](FORK-MASQUERADE.md).

## Patch 2: AnyTLS fallback

The AnyTLS inbound exposes `sing-anytls`' existing `FallbackHandler` using
`fallback` and `fallback_for_alpn` options. It does not change the AnyTLS wire
protocol, authentication algorithm, padding, outbound, or `sing-anytls`.
Fallback occurs after TLS termination and routes only to the configured backend.
See [FORK-ANYTLS-FALLBACK.md](FORK-ANYTLS-FALLBACK.md).

## Patch 3: configurable HTTP/3 fallback backoff

`common/httpclient/http3_transport.go` gains an optional `http3_fallback` client
option (`initial_backoff`, `max_backoff`, `multiplier`, `reset_on_success`).
Absent, the upstream schedule (5m, doubling, 48h cap) is used unchanged. State
stays keyed by request authority and is cleared on a successful HTTP/3 round
trip. HTTP/2 fallback logic is untouched.

## Patch 4: HTTP/3 connection pool

`common/httpclient/http3_transport.go` gains an optional
`http3_connection_pool` client option (`size`, `strategy`). `size: 1` (or an
absent object) is exactly the upstream single-transport behaviour. `size: 2`
creates two independent HTTP/3 transports, hence two independent QUIC
connections. Non-rewindable request bodies are always served by one member and
are never replayed onto another connection.

This patch also fixes an upstream leak: `http3FallbackTransport.Close()` closed
only the HTTP/3 transport and leaked the HTTP/2 fallback.

## Patch 5: HTTP server resource profile

`transport/http/server.go`, `server_h2.go`, `server_h3.go` and
`option/http_server_profile.go` add an optional `server_profile` and a direct
`max_header_bytes` for the HTTP inbound. The profile only fills fields the user
left unset; explicit values always win; an unset profile changes nothing. The
upstream ~unlimited `MaxIncomingStreams` default and the 1 MiB header default are
kept for unconfigured inbounds.

The same file exposes `bbr_profile`, accepting exactly the three profiles that
`sing-quic/congestion_meta2` really defines (`conservative`, `standard`,
`aggressive`). Unset means `standard`, which is the previous hardcoded value.

## Patch 6: unauthenticated resource limits

`transport/http/unauthenticated_limiter.go` and
`option/http_unauthenticated_limits.go` add an optional
`unauthenticated_limits` option. It bounds pre-authentication traffic per source
IP only (port dropped, IPv4-mapped IPv6 unmapped), releases the budget as soon as
authentication succeeds, expires idle entries, and caps the number of tracked
IPs to defeat map exhaustion. A request is rejected only when it both fails
authentication and exceeds the budget, so a legitimate client is never denied
service. Rejections never emit `401`/`407` or auth headers.

`transport/http/source_h3.go` also fixes source resolution for HTTP/3: quic-go
exposes the peer address through a request-context key rather than
`http.Request.RemoteAddr`, so per-source-IP logic would otherwise see an empty
address on the public UDP/443 path.

## Patch 7: log classification

`transport/http/h3_error_class.go` classifies HTTP/3 and QUIC errors using
`errors.Is`, `errors.As` and real quic-go error codes — never string matching —
so only unambiguously expected lifecycle events are quiet and every real fault
stays an error. `protocol/anytls/inbound.go` logs the normal fallback path at
debug instead of info, and the masquerade auth-failure path logs at debug because
the client receives an ordinary web response.

## Patch 8: build profiles

`release/BUILD_TAGS_JIEJIE_SERVER` adds a reduced optional-component tag set.
`release/DEFAULT_BUILD_TAGS_OTHERS` is untouched, so full upstream build
capability is preserved. No protocol source is deleted; the size reduction comes
from not registering optional components.

## Patch 9: minimal server registry

`include/registry.go` and `include/quic.go` gain a
`!jiejie_server_minimal` build constraint, and two new files provide the minimal
variant:

* `include/registry_jiejie_server.go` (`jiejie_server_minimal`) registers only
  the protocols and services this server's production config references.
* `include/quic_minimal.go` (`with_quic && jiejie_server_minimal`) registers the
  non-functional stubs for Hysteria/Hysteria2/TUIC/QUIC-DNS/realm without
  importing those packages, and leaves MASQUE HTTP/3 to
  `transport/http/server_h3.go`, which `with_quic` compiles on its own.

Excluded types are still registered as stubs so a config referencing them fails
with a clear message at `sing-box check`. No upstream protocol source is edited
or deleted, and neither the full nor the plain Jiejie build changes behaviour.

`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` is
`with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0`.

`release/jiejie-production-topology.json` is a secret-free fixture of the full
production topology (MASQUE H2/H3 with masquerade and limits, AnyTLS with
fallback, ShadowTLS v3, SS2022, a residential SOCKS outbound, selectors, route
rules and the local-AGH DNS setup). CI requires every artifact to accept it, and
requires the minimal build to reject a protocol it deliberately excludes.

## Maintenance and CI

CI now has one job and one product: it tests broadly and publishes exactly one
binary. The workflow runs three jobs:

* **lint-and-unit-tests** — `gofmt`, upstream golangci-lint, `vet` and unit tests
  under **both** the production/minimal tag set and the upstream default tag set,
  race tests under the production tag set, and HTTP/3 pool benchmarks as a
  regression reference. The production tag set is the one that must pass; the
  upstream run is a compatibility signal and never substitutes for it.
* **integration-tests** — builds the production binary with
  `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` and runs two groups:
  * **Group A (production, minimal tags)** — `TestJiejie*`: AnyTLS fallback and
    valid AnyTLS, MASQUE H2/H3 masquerade, authenticated CONNECT, the H3
    connection pool, H3 → H2 fallback, and the unauthenticated limiter.
  * **Group B (upstream compatibility, default tags)** — the upstream HTTP/2 and
    HTTP/3 inbound and forward suites, which need the full tag set (and in some
    cases Docker, which the runner lacks) and are therefore run only as a subset.
  Test logs stay in the job output and are **not** uploaded as artifacts.
* **build-production** — needs both jobs above, so the shipped binary is only
  produced after everything has passed. It builds `sing-box-linux-amd64`, audits
  dependency pruning with a temporary unstripped copy (deleted immediately and
  never uploaded), verifies version and tags, runs `sing-box check` against the
  secret-free production fixture, asserts an excluded protocol is still rejected,
  enforces the binary size guard, writes the SHA256 and uploads exactly one
  artifact.

The production binary is produced by the official Go linker in a single
`go build` invocation with `-trimpath` and `-ldflags "-s -w"`, which drops the
symbol table and DWARF debug information. No external `strip`, `objcopy`,
`eu-strip`, or UPX/packer step is applied, so the published artifact is exactly
what the Go linker emitted.

`test/go.mod` is pinned to the same `sing-tun` version as the main module and no
longer carries a `replace` pointing at a sibling checkout, so `./test/...`
builds in a normal clone and in CI.

There are no other intentional sing-box runtime behavior changes.

## Deliberately not implemented

* **`memory_budget`** — a byte-accurate QUIC memory budget cannot be built
  honestly on the current quic-go/sing-quic lifecycle. Deterministic resource
  limits are used instead. See section 12 of [JIEJIE-SERVER.md](JIEJIE-SERVER.md).
* **A native SNI front door or TCP/443 SNI dispatcher** — Nginx owns TCP/443.
* **Resurrecting the `28435` + njs AnyTLS classifier** — permanently retired.
* **Forking `sing-anytls` or reimplementing fallback with `net.Dial`/`io.Copy`.**

## Upstream sync policy

```sh
git fetch upstream
git switch feat/jiejie-server-edition
git log --oneline HEAD..upstream/testing
git diff HEAD...upstream/testing
git rebase upstream/testing        # or: git merge upstream/testing
```

Merge or rebase only after resolving the patches above and running the server
workflow. Never reset `testing` to `upstream/testing` and never force-push
`testing`.

After every sync, verify: HTTP masquerade on H2 and H3, AnyTLS fallback,
authenticated CONNECT and CONNECT-UDP, H2/H3 capability, the new unit and
integration tests, and the Linux amd64 artifacts.
