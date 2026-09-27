# Build profiles

This fork is **one source tree** that produces **three separate binaries**. The
profiles differ only in build tags, the registry, platform glue, CI and packaging.
They do not differ in protocol implementation.

```text
                    single source tree (branch: testing)
                              │
        ┌─────────────────────┼─────────────────────┐
        ↓                     ↓                     ↓
  Linux Server Minimal   macOS Client Lite   macOS Client Naive
  jiejie_server_minimal  jiejie_client_macos jiejie_client_macos
                                               + with_naive_outbound
```

## Why the profiles exist

A production server and a desktop client are different products with different
threat models and different dependency budgets.

The server serves one known VPS topology. It needs exactly the inbounds that
topology uses and almost no outbounds, and every extra protocol is attack surface
and binary size on a machine that runs unattended.

A desktop client is loaded by a third-party GUI that runs whatever the user
configured. It needs a wide protocol set and a TUN inbound, but it has no server
role at all: it never listens for proxy connections.

Sharing one source tree keeps the protocol implementations single-copy. A fix to
MASQUE framing, Naive padding, HTTP/2 flow control or a buffer ownership bug lands
once and reaches every profile.

## The three profiles

| | Server Minimal | macOS Lite | macOS Naive |
|---|---|---|---|
| Tag file | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE` |
| Target | `linux/amd64` | `darwin/arm64` | `darwin/arm64` |
| `CGO_ENABLED` | `0` | `0` | `1` |
| Build tags | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` | `with_gvisor,with_quic,with_utls,with_clash_api,jiejie_client_macos,badlinkname,tfogo_checklinkname0` | Lite tags **+** `with_naive_outbound` |
| Registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` | same as Lite |
| Binary size (measured) | 48,605,024 B | 57,934,354 B | 76,166,402 B |
| SHA-256 (measured) | `be2ccbc2df38…` | `55d8dc6fd953…` | `fa976ee5491c…` |

All three were built twice on a `darwin/arm64` M1 host with Go 1.25.5 and produced
**bit-identical** binaries. See [Reproducibility](#reproducibility).

### Linux Server Minimal

`jiejie_server_minimal`. The production VPS binary. Registers only what the
production topology serves, and `direct`/`socks` outbounds. Contains no client
helpers, no Cronet, no GUI-facing services and no unused protocol trees.

### macOS Client Lite

`jiejie_client_macos`. The default desktop core.

Includes: TUN, `mixed`/`http`/`socks` inbounds, DNS (UDP/TCP/DoT/DoH/DoQ/DoH3/
local/hosts/FakeIP), Reality/VLESS, VMess, AnyTLS, Shadowsocks, ShadowTLS, Snell,
Trojan, Hysteria2, TUIC, the **MASQUE client** endpoint, the native `api` service,
and the Clash compatibility API.

Excludes: Cronet, the Naive implementation (the type resolves to a stub with an
actionable error), the Native Naive server, `masque-server`, OpenVPN, OpenConnect,
Tailscale, WireGuard, Tor, SSH, and all server-only services.

Must build **CGO-free**, so it can be cross-compiled and embedded by a GUI.

### macOS Client Naive

Lite plus `with_naive_outbound` and `CGO_ENABLED=1`. Adds the Cronet-backed Naive
outbound. Cronet is **not** a dependency of Lite: it is a separate profile because
it is a large CGO static library that most users never need.

## What each profile registers

The difference between profiles is a **registry** difference, not a code
difference. `include/registry_jiejie_*.go` decides which packages enter the import
graph; a package that is not imported is dropped by the linker along with its whole
dependency tree. No upstream protocol source is edited or deleted, so upstream
build capability keeps working.

The MASQUE endpoint roles are split for exactly this reason:

```go
// protocol/masque/endpoint.go
func RegisterClientEndpoint(registry *endpoint.Registry)  // masque-client only
func RegisterServerEndpoint(registry *endpoint.Registry)  // masque-server only
func RegisterEndpoint(registry *endpoint.Registry)        // both; upstream/server
```

The macOS client calls `RegisterClientEndpoint`, so:

```text
macOS:   masque-client  ✅      masque-server  ❌
Server:  serves MASQUE through protocol/http + transport/http
```

Calling the combined `RegisterEndpoint` would have shipped a TUN-binding
CONNECT-IP server endpoint inside a desktop client.

## Building

Every profile is built from the same checkout by a script that reads its tag file,
so the profile definition lives in exactly one place.

```bash
# Server Minimal (linux/amd64, CGO off)
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64

# macOS Lite (darwin/arm64, CGO off)
./scripts/ci/build-macos-client.sh arm64 lite dist/sing-box-darwin-arm64

# macOS Naive (darwin/arm64, CGO on)
./scripts/ci/build-macos-client.sh arm64 naive dist/sing-box-darwin-arm64-naive
```

All builds use `-trimpath -buildvcs=false`.

## Verifying a build

```bash
# registry and symbol audit: what is registered, and what is merely linked
./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64

# configuration check against the profile fixture
./scripts/ci/check-macos-client-config.sh dist/sing-box-darwin-arm64 /tmp/cfg

# runtime smoke: start, Clash API, mixed inbound, clean SIGTERM
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64

# headless: native API, dashboard, Clash compatibility API
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64
```

## Reproducibility

Same source, same Go, same dependencies, same profile ⇒ **identical SHA-256**.
Measured by building each profile twice and comparing:

```text
server-minimal  be2ccbc2df38207d5b4b4880551bfa836476c3c5197ac1195956e323634574a3
macos-lite      55d8dc6fd95304f909d3ba201a148b05e7dfa74375925b72336487bf36491bf4
macos-naive     fa976ee5491c987b2c3665afa40a2479802e04078a3896f7763618fb503f617e
```

Three inputs are removed to make this hold:

- `-trimpath` removes the build directory, which would otherwise embed the
  machine-specific checkout path.
- `-buildvcs=false` removes the VCS stamp, which embeds the commit and a dirty
  flag.
- No timestamp or random id is injected at link time.

`macos-naive` was the expected exception, because it links a prebuilt Cronet static
library under CGO and an external archive could embed a build id. Measurement shows
it does not, so all three profiles are held to the same standard rather than
exempting the CGO leg.

`.github/workflows/jiejie-profiles.yml` builds each profile twice and fails if the
hashes differ.

## CI

`jiejie-profiles.yml` is the **cross-product gate**: it builds all three profiles
from one commit SHA in one run, and its summary job fails unless every profile
passed. That is the check that makes "one source tree, multiple profiles" true in
practice rather than only in intent — a divergence cannot hide between two
workflows if a single status covers all three.

It also fails if the shared packages are duplicated:

```text
protocol/masque, transport/masque, transport/http, protocol/naive
  → must exist in exactly one place
  → no file inside the MASQUE packages may be named for a platform
```

Per-profile workflows are kept and are not redundant:

- `server-linux-amd64.yml` carries the server's binary size ceiling, reference
  coverage and focused checks.
- `client-macos.yml` carries the macOS launchd, headless and artifact checks.
- `jiejie-fast.yml` and `jiejie-masque-reference.yml` carry protocol-level tests.

They fail independently on purpose: a red macOS client must not block a server
release.
