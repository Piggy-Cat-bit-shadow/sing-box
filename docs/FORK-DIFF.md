# Fork diff manifest

Base: `SagerNet/sing-box` `testing`
Fork: `Piggy-Cat-bit-shadow/sing-box`
Current version: `1.15.0-jiejie-masquerade.4`

**Jiejie Server Edition is a VPS-only fork.**

This repository ships exactly one custom product: a minimal Linux amd64
production server binary.

It does not ship or maintain:

- iOS clients
- Apple Libbox products
- Windows clients
- Linux full clients
- TrustTunnel
- general-purpose client features

The single long-term branch is `testing`. Work lands there; short-lived
`feat/jiejie-*` branches exist only while a change is being verified, and are
deleted once its workflows are green.

This fork intentionally changes only the server-side areas listed below.
Everything is optional and off by default; an unmodified configuration behaves
like upstream. See [JIEJIE-SERVER.md](JIEJIE-SERVER.md) for the full reference.

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

## Patch 3: HTTP server resource profile

`transport/http/server.go`, `server_h2.go`, `server_h3.go` and
`option/http_server_profile.go` add an optional `server_profile` and a direct
`max_header_bytes` for the HTTP inbound. The profile only fills fields the user
left unset; explicit values always win; an unset profile changes nothing. The
upstream ~unlimited `MaxIncomingStreams` default and the 1 MiB header default are
kept for unconfigured inbounds.

The same file exposes `bbr_profile`, accepting exactly the three profiles that
`sing-quic/congestion_meta2` really defines (`conservative`, `standard`,
`aggressive`). Unset means `standard`, which is the previous hardcoded value.

`server_profile`'s `idle_timeout` is applied to **both** QUIC idle timers on the
HTTP/3 listener: `quic.Config.MaxIdleTimeout` (transport) and
`http3.Server.IdleTimeout` (application). Only the first was wired before, and
the transport timer is refreshed by any packet including a bare PING, so a peer
could complete the handshake and then hold the connection open indefinitely
without ever opening a request stream. The application timer is armed at
connection creation, stopped when a request stream arrives and reset only when
the last stream closes, so long-lived CONNECT tunnels are unaffected.

`max_header_bytes` is enforced by HTTP/3 as well as HTTP/2. quic-go
v0.61.0-sing-box-mod.7 checks both the raw HEADERS frame length and the decoded
field section, answers an oversized block with `431`, and bounds trailers the
same way; the handler is never invoked for a rejected request.

## Patch 4: unauthenticated resource limits

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

## Patch 5: log classification

`transport/http/h3_error_class.go` classifies HTTP/3 and QUIC errors using
`errors.Is`, `errors.As` and real quic-go error codes — never string matching —
so only unambiguously expected lifecycle events are quiet and every real fault
stays an error. `protocol/anytls/inbound.go` logs the normal fallback path at
debug instead of info, and the masquerade auth-failure path logs at debug because
the client receives an ordinary web response.

## Patch 6: the production build profile

`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` is the one profile this fork ships:
`with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0`.

The upstream `release/DEFAULT_BUILD_TAGS*` files are untouched, so upstream build
capability is preserved. No protocol source is deleted; the size reduction comes
from not registering optional components.

## Patch 7: minimal server registry

`include/registry.go` and `include/quic.go` gain a
`!jiejie_server_minimal` build constraint, and two new files provide the minimal
variant:

* `include/registry_jiejie_server.go` (`jiejie_server_minimal`) registers only
  the protocols and services this server's production config references.
* `include/quic_minimal.go` (`with_quic && jiejie_server_minimal`) leaves every
  QUIC-protocol registration empty. MASQUE HTTP/3 is implemented by
  `transport/http/server_h3.go`, which `with_quic` compiles on its own and needs
  nothing registered here.

The empty registrations are deliberate. An earlier revision imported protocols
purely to return a friendlier error for a type the build removes, which pulled
the very packages the trim exists to remove back into the import graph. A config
naming a removed type now fails `sing-box check` with "unknown inbound type"
(or the equivalent), which is the honest outcome.

No upstream protocol source is edited or deleted, and the upstream full build is
unchanged.

`release/jiejie-production-topology.json` is a secret-free fixture of the full
production topology (MASQUE H2/H3 with masquerade and limits, AnyTLS with
fallback, ShadowTLS v3, SS2022, a residential SOCKS outbound, selectors, route
rules and the local-AGH DNS setup). CI requires every artifact to accept it, and
requires the minimal build to reject a protocol it deliberately excludes.

## Maintenance and CI

Two workflows, one product.

**Jiejie Fast** (`.github/workflows/jiejie-fast.yml`) is the fast gate on every
push and pull request:

* **format-and-lint** — `gofmt` and upstream golangci-lint.
* **server-tests** — `vet` and unit tests under the production tag set, plus race
  tests for the server's concurrent state.
* **build-gate** — the Server Minimal binary must compile, must still exclude the
  pruned protocols, and must accept `release/jiejie-production-topology.json`.

**Linux amd64 server** (`.github/workflows/server-linux-amd64.yml`) is the
release gate:

* **lint-and-unit-tests** — `gofmt`, lint, `vet` and unit tests under **both** the
  production/minimal tag set and the upstream default tag set. The production tag
  set is the one that must pass; the upstream run is a compatibility signal and
  never substitutes for it.
* **production-minimal-integration** — builds the production binary and runs
  `TestJiejie*` (AnyTLS fallback, MASQUE H2/H3 masquerade, authenticated CONNECT
  and CONNECT-UDP, the unauthenticated limiter) and the actual-binary process
  tests. Test logs stay in the job output and are **not** uploaded as artifacts.
* **build-production** — needs both jobs above, so the shipped binary is only
  produced after everything has passed. It builds `sing-box-linux-amd64`, audits
  dependency pruning with a temporary unstripped copy (deleted immediately and
  never uploaded), verifies version and tags, runs `sing-box check` against the
  secret-free production fixture, asserts an excluded protocol is still rejected,
  enforces the binary size guard, writes `BUILD-INFO-VPS.txt` and the size
  report, and uploads exactly one artifact.

The single published artifact is
`Jiejie-VPS-linux-amd64-<version>-<sha>`.

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
git switch testing
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
