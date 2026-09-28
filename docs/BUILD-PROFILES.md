# Build profiles

This fork is **one source tree** that produces **two binaries**, one per product.
The profiles differ only in build tags, the registry, platform glue, CI and
packaging. They do not differ in protocol implementation.

```text
              single source tree (branch: testing)
                          │
        ┌─────────────────┴─────────────────┐
        ↓                                   ↓
  Linux Server Minimal              macOS Client
  jiejie_server_minimal             jiejie_client_macos
  linux/amd64, CGO=0                darwin/arm64, CGO=1
  -> sing-box-linux-amd64           -> sing-box-darwin-arm64
```

The macOS core is ONE product. It ships NaiveProxy (Cronet) **and** MASQUE **and**
the client protocol set the production configuration actually uses, because those
are the capabilities the product is for. There is no lite/naive split, and there is
no "wide client" registry either: a capability that is needed is in the product,
and a capability that is not needed is not built at all.

## Why the profiles exist

A production server and a desktop client are different products with different
threat models and different dependency budgets.

The server serves one known VPS topology. It needs exactly the inbounds that
topology uses and almost no outbounds, and every extra protocol is attack surface
and binary size on a machine that runs unattended.

The client is a personal, headless-first CLI core driven by launchd, with the
Native API and its Web Dashboard as the only control plane. It needs a TUN inbound
and the outbound protocols its own configuration names, but it has no server role
at all: it never listens for proxy connections.

Sharing one source tree keeps the protocol implementations single-copy. A fix to
MASQUE framing, Naive padding, HTTP/2 flow control or a buffer ownership bug lands
once and reaches every profile.

## The two profiles

| | Server Minimal | macOS Client |
|---|---|---|
| Tag file | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` |
| Target | `linux/amd64` | `darwin/arm64` |
| `CGO_ENABLED` | `0` | `1` (Cronet) |
| Build tags | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` | `with_gvisor,with_quic,with_utls,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0` |
| Registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| Binary size (measured) | 48,605,024 B | 73,432,802 B |
| SHA-256 (measured) | `be2ccbc2df38…` | `fa976ee5491c…` |
| Workflow | `server-linux-amd64.yml` | `client-macos.yml` |
| Artifact | `Jiejie-Linux-amd64-<version>-<sha>` | `Jiejie-macOS-arm64-<version>-<sha>` |

Both were built twice on a `darwin/arm64` M1 host with Go 1.25.5 and produced
**bit-identical** binaries, including the CGO/Cronet macOS build. See
[Reproducibility](#reproducibility).

### Linux Server Minimal

`jiejie_server_minimal`. The production VPS binary. Registers only what the
production topology serves, and `direct`/`socks` outbounds. Contains no client
helpers, no Cronet, no GUI-facing services and no unused protocol trees.

### macOS Client

`jiejie_client_macos`. THE macOS core, built for `darwin/arm64`. It is headless-first:
launchd supervises it, the CLI drives it, and the sing-box Web Dashboard served by
the Native API on `http://127.0.0.1:9090/` is its only user interface.

Includes:

- **NaiveProxy** — the Cronet-backed `naive` outbound over HTTP/2 and QUIC/HTTP3
- **MASQUE** — the `masque-client` endpoint (CONNECT-IP / CONNECT-UDP over H2/H3),
  with the shared `transport/masque` and `transport/http` data plane
- TUN (gVisor) and `mixed` inbounds
- DNS: UDP, TCP, DoT, DoH, DoQ, DoH3, local, hosts, FakeIP
- the production outbound allowlist: Reality/VLESS, AnyTLS, Shadowsocks, ShadowTLS,
  Naive, the MASQUE client outbound (`http`), and the
  `direct`/`block`/`selector`/`urltest` primitives
- the native `api` service — the ONLY management plane, and the thing that serves
  the Web Dashboard

Excludes: `masque-server`, the Native Naive **server** inbound, OpenVPN,
OpenConnect, Tailscale, WireGuard, Tor, SSH, every outbound outside the allowlist
(`socks`, `snell`, `trojan`, `vmess`, `hysteria2`, `tuic`), and all server-only
services.

Three things are not "excluded" but **deleted from the fork**, and no build tag can
bring them back:

- the **Clash API** (`experimental/clashapi/`, `option.ClashAPIOptions`,
  `with_clash_api`). A config with `experimental.clash_api` now fails as an unknown
  field, which is the intended outcome — there is no second controller and no port
  for Yacd or MetaCubeXD to reach;
- the **LXD daemon** (`lxd/`, the `sing-box lxd` subcommand, `with_lxd`);
- the **launcher RPC surface** (`with_lx_command`, and the 13 launcher RPCs that
  were dropped from `daemon/started_service.proto`).

Builds with **CGO enabled**, because `with_naive_outbound` links the prebuilt
Cronet static library. That is accepted rather than worked around: the alternative
would be a second CGO-free core that cannot speak NaiveProxy, which is exactly the
split this consolidation removed.

A capability that is required is asserted to be present in the SHIPPED binary, not
merely requested by a tag name. The workflow checks the symbol table for
`cronet-go.NewNaiveClient`, `protocol/masque.(*ClientEndpoint)`, `transport/masque`,
`transport/http`, `sagernet/gvisor` and the TUN inbound, and checks that the Naive
stub, `masque-server`, `sing-box/lxd.` and `sing-box/experimental/clashapi.` are
absent.

`with_gvisor` and `with_quic` are both **required**, and neither is a leftover from
a removed feature:

- `with_gvisor` is what selects the TUN userspace stack. The stack itself lives in
  the `sing-tun` dependency and its Darwin files are gated on this tag, so it is
  not "unused code kept for symmetry" — it is the tag that makes TUN work.
- `with_quic` is required for **MASQUE HTTP/3**. The QUIC *outbounds* (hysteria2,
  tuic) were removed by simply not calling `registerQUICOutbounds`; the tag stays,
  because MASQUE is a different consumer of it. Dropping `with_quic` "because
  Hysteria2 is gone" would silently break MASQUE.

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

# macOS Client (darwin/arm64, CGO on)
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64
```

There is one macOS product and one architecture, so there is no flavor argument and
no Intel variant to select.

All builds use `-trimpath -buildvcs=false`.

## Verifying a build

```bash
# registry and symbol audit: what is registered, and what is merely linked
./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64

# configuration check against the profile fixture
./scripts/ci/check-macos-client-config.sh dist/sing-box-darwin-arm64 /tmp/cfg

# runtime smoke: start, mixed inbound, clean SIGTERM
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64

# headless: the Native API — the only control plane — and the dashboard
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64
```

## Reproducibility

Two builds of the same source on the **same machine** produce an identical
SHA-256, for both products. Each workflow asserts this by building twice and
comparing, so a change that reintroduces a timestamp or a random id fails the job.

```text
Linux amd64   two builds on a darwin/arm64 M1 host   identical
macOS arm64   two builds on a darwin/arm64 M1 host   identical
macOS arm64   two builds on the macOS CI runner      identical
```

Measured hashes, for reference:

```text
Linux amd64   18e72cc1f6e966cdf73ebcdfc8d63530be3fa244b4ad7c6013d105fb9123deab   local, 33,870,008 B
macOS arm64   fa976ee5491c987b2c3665afa40a2479802e04078a3896f7763618fb503f617e   superseded, 76,166,402 B
macOS arm64   73,432,802 B                                                        current, after the registry trim
```

The macOS hash from the wider registry is kept only as a historical marker: the
shipped binary is now the trimmed one at **73,432,802 B**. Sizes are recorded rather
than hashes for the current build because the macOS core is CGO and its bytes vary
across machines (see below) — the size does not, which is what makes it a useful
guard.

Three inputs are removed to make same-machine builds identical:

- `-trimpath` removes the build directory, which would otherwise embed the
  machine-specific checkout path.
- `-buildvcs=false` removes the VCS stamp, which embeds the commit and a dirty
  flag.
- No timestamp or random id is injected at link time. Build time lives only in the
  `BUILD-INFO` sidecar.

### Cross-machine: measured, and NOT identical for the macOS core

The two macOS hashes above have the same byte size but different bytes. That is a
measurement, not rounding, and it is recorded because the temptation is to claim
more than is true.

The Linux profile is pure Go, so its hash matches across machines running the same
Go version. The macOS core is **CGO**: it compiles the cgo-generated objects and
links the Cronet static archive with the host's Apple clang, so two machines with
different Xcode command-line tools produce different bytes from identical source.

What that means in practice:

- **Same-machine reproducibility is enforced by CI.** Two builds on one runner must
  match, and the job fails if they do not.
- **Cross-machine reproducibility is not guaranteed for the macOS core.** Its
  SHA-256 is a same-run integrity check and a download-verification hash, not a
  fingerprint of the source.

Closing this would mean pinning the Xcode toolchain version in CI and comparing
against a locally pinned toolchain. That is **NOT DONE** and is left as an open
item rather than implied to pass.

## CI

There are exactly two workflows, one per product:

```text
testing push
     │
     ├── Linux amd64   ->  sing-box-linux-amd64
     │
     └── macOS arm64   ->  sing-box-darwin-arm64
```

Each is a **single job**: one checkout, one setup-go with cache, one cache restore,
one build. Splitting a job adds another runner startup, checkout, setup-go, cache
restore and dependency resolution, which this workload does not need.

**The binary is built ONCE per workflow.** Every subsequent step — version and tag
agreement, config check, runtime smoke, headless smoke, registry and symbol audit,
capability verification, size ceiling, reproducibility, SHA-256, BUILD-INFO and the
upload — reads that same file. Nothing re-runs `go build` to inspect something the
binary already contains; the audit scripts analyse the shipped binary directly.

### Quick path vs deep checks

A push runs formatting, focused vet, the core unit tests under the product's tag
set, one build, and the artifact checks.

Everything expensive is behind a manual input on BOTH workflows:

```yaml
workflow_dispatch:
  inputs:
    deep_checks:
      description: Run expensive deep validation
      required: false
      default: false
      type: boolean
```

Linux deep checks: race tests, the fuzz campaign, the upstream-default tag build
and tests, the `test/jiejie/reference` interop suite plus the Caddy/forwardproxy
reference differential tests, and the MASQUE reference interop.

macOS deep checks: race tests, the fuzz campaign, the upstream-default build, and
the Cronet engine A/B (which needs a live Naive server and otherwise reports NOT
TESTED).

Both workflows also `cancel-in-progress` on the same branch, so a rapid sequence of
pushes only builds the newest commit, and both ignore documentation-only changes so
a README edit does not rebuild a kernel.

### What is deliberately not done

- **No `pull_request` trigger.** This is a personal fork with a single development
  branch; there is no PR workflow to protect.
- **No `paths:` allowlist.** `paths-ignore` is used instead, because an allowlist
  silently stops building when a new source directory is added.
- **No full `golangci-lint` on every push.** It downloads and compiles a second Go
  toolchain, which is a poor trade against `gofmt` and `go vet` for an artifact
  build. The lint configuration is unchanged and still runnable locally or in deep
  checks.
- **No duplicate cache.** `setup-go`'s own cache is used with
  `cache-dependency-path: go.sum`; there is no second `actions/cache` for the same
  `GOMODCACHE`.
- **No `go mod download all`** and no `go clean -cache`/`-modcache`. `go test` and
  `go build` read the module cache on demand.

## Known pre-existing test results

These are recorded so a future reader does not mistake them for damage from the
consolidation, and so the baseline is explicit rather than rediscovered.

### `test/jiejie` under the macOS client tag set

Running the full `test/jiejie` suite with `jiejie_client_macos` produces **17
failures**. Every one is a **server-profile test that lacks a build constraint**, so
it runs under client tags and asserts on things the client profile correctly does
not have:

| group | why it fails under client tags |
|---|---|
| AnyTLS inbound / ALPN fallback (9 tests) | the client registers the anytls *outbound*, not the inbound |
| ShadowTLS decoy / probe (3 tests) | the client registers the shadowtls *outbound*, not the inbound |
| registry audits (4 tests) | assert the **server** registry's inbound set |
| residential SOCKS outbound | a server-only outbound |

Measured on the revision before this work (`49579cf32`) and on the current HEAD:
**17 failures both times, with no test failing in one and not the other.** Verified
by diffing the sorted failure lists:

```bash
# before
git checkout 49579cf32 && cd test && \
  go test -tags "with_gvisor,with_quic,with_utls,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0" \
    -count=1 ./jiejie/ 2>&1 | grep '^--- FAIL' | sort > /tmp/before.txt
# after
git checkout testing && cd test && \
  go test -tags "with_gvisor,with_quic,with_utls,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0" \
    -count=1 ./jiejie/ 2>&1 | grep '^--- FAIL' | sort > /tmp/after.txt
comm -13 <(sed 's/ ([0-9.]*s)//' /tmp/before.txt | sort) \
         <(sed 's/ ([0-9.]*s)//' /tmp/after.txt | sort)   # empty
```

The proper fix is a `jiejie_client_macos` (or `!jiejie_server_minimal`) build
constraint on those files so they are compiled only into the profile they describe.
That is **not done here**, because it is an unrelated change to files this work does
not otherwise touch, and doing it would have hidden whether the consolidation
itself caused anything. The client-specific assertions that matter live in
`macos_client_registry_audit_test.go` and `macos_client_fixture_audit_test.go`,
which are constrained to `jiejie_client_macos` and pass.

### `test/jiejie` under the server tag set

Two additional failures, also **pre-existing and verified identical on
`49579cf32`**:

```text
TestAuditLoopbackIsReachableByDefault
TestAuditRouteRuleBlocksLoopback
```

These are Naive loopback audit tests, unrelated to the build-profile work. They are
recorded so the server baseline is not mistaken for a clean run.

> **Correction (UoT).** An earlier revision of this page also listed
> `TestAuditUoTV2NonConnectMode` and `TestAuditUoTV2NonConnectMultipleTargets` here
> as pre-existing Naive UoT failures with an `EOF` during the handshake. That was
> **wrong**. Both were failures of the TEST HARNESS, not the product: they framed an
> HTTP/1 CONNECT payload as Naive padded data, and HTTP/1 is a raw tunnel. They now
> pass. See [JIEJIE-NAIVE-UOT-FALSE-P0.md](JIEJIE-NAIVE-UOT-FALSE-P0.md).

### What is green

```text
go test ./...                             24 packages ok, 0 FAIL (main module)
go test -race ./transport/masque           ok 34.1s
go test -race ./transport/http             ok  4.8s
go test -race ./protocol/naive             ok  3.2s
go test -race ./route                      ok  2.9s
go test -race ./common/httpclient          ok  3.7s
```

Plus, for the one macOS product: registry audit PASS, config check PASS, runtime
smoke PASS, headless smoke PASS, and the negative assertions that the Clash API and
LXD daemon packages are absent from the shipped binary.
