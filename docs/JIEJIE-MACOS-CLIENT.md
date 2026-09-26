# Jiejie macOS Client Edition

This document describes the macOS Client Edition of the Jiejie sing-box fork: what
it is, what it contains, why each part is included or excluded, and what has
actually been verified.

- **Product** — a native macOS CLI sing-box core, intended to be loaded by a
  third-party GUI as an external core.
- **Branch** — `macos-client`
- **Base branch** — `testing` (Jiejie Server Edition)
- **Base SHA** — `783c2bb52318a12dd2a3b7c16ab2f33e7ebbb9da`
- **Target** — `darwin/arm64` (required), `darwin/amd64` (also built)

## What this is not

It is worth being blunt, because the sing-box ecosystem has several products that
sound similar:

- **not** an official sing-box build, and **not** a replacement for upstream
  sing-box;
- **not** an Apple app — there is no Swift GUI, no `sing-box-for-apple`, no
  NetworkExtension target, no Xcode project, no IPA, and no App Store build;
- **not** the Jiejie Server Edition — that is a Linux amd64 VPS product on the
  `testing` branch with an entirely separate build profile and registry;
- **not** a libbox library — `libbox` is not built or shipped here.

## Architecture

The repository carries two independent products. They share one source tree and
one set of upstream-derived packages, and are separated entirely by build tags and
registries. Neither product's build can accidentally select the other's registry,
because the constraints are mutually exclusive.

```text
testing                          macos-client
└── Jiejie Server Edition        └── Jiejie Client Edition
    └── Linux amd64                  └── macOS
        └── jiejie_server_minimal        └── jiejie_client_macos
```

| | Server Edition | Client Edition |
| --- | --- | --- |
| branch | `testing` | `macos-client` |
| platform | Linux amd64 | macOS arm64 / amd64 |
| build tag | `jiejie_server_minimal` | `jiejie_client_macos` |
| tag file | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` |
| registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| workflow | `server-linux-amd64.yml` | `client-macos.yml` |
| artifact | `Jiejie-VPS-linux-amd64-…` | `Jiejie-Client-macOS-arm64-…` |

The three registries are mutually exclusive and complete:

| condition | registry compiled |
| --- | --- |
| `!jiejie_server_minimal && !jiejie_client_macos` | `include/registry.go` (upstream full) |
| `jiejie_server_minimal` | `include/registry_jiejie_server.go` |
| `jiejie_client_macos` | `include/registry_jiejie_client_macos.go` |

`include/quic.go` carries the same constraints, with three variants:
`include/quic.go` (upstream full), `include/quic_minimal.go` (server) and
`include/quic_client_macos.go` (client).

## Relationship to the removed iOS/client lines

Commit `5ce3c4d675` ("narrow the fork to VPS-only and remove the iOS/client
product lines") deleted the fork's earlier client work: `BUILD_TAGS_JIEJIE_CLIENT_FULL`,
`BUILD_TAGS_JIEJIE_CLIENT_WINDOWS`, `build-client.sh`, an "Apple slim" registry,
the iOS workflow, and the HTTP client / H3 client / MASQUE client runtime.

**That commit was not reverted, and nothing from `5ce3c4d675^` was restored
wholesale.** It was read as a design reference only. The reasons are concrete:

- the code has had several rounds of development since;
- the fork re-synced with upstream `testing` (`c992b1fab`), so the API moved;
- MASQUE/HTTP/QUIC code continued to evolve;
- `sing` is now pinned to a fork with its own patch;
- the test system changed;
- the old iOS slim registry served a *mobile, in-app* client, which is a
  different product from a desktop CLI core.

What was actually taken from the old design: the *structure* of a client registry
separate from the server one, and the observation that `local` is a mandatory DNS
boot dependency. What was rejected is listed under
[Historical client work: reviewed and rejected](#historical-client-work-reviewed-and-rejected).

## Build profiles

Two profiles exist, and the tag sets live in exactly one file each. The build
script, the workflow and `build-info.sh` all read those files rather than
repeating the list, so they cannot drift.

### `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` — lite (default)

```text
with_gvisor,with_quic,with_utls,with_clash_api,jiejie_client_macos,badlinkname,tfogo_checklinkname0
```

CGO is **off**. The result is a self-contained binary with no native library
dependencies.

### `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE` — naive

```text
with_gvisor,with_quic,with_utls,with_clash_api,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0
```

CGO is **on**. This adds the Naive outbound and links `cronet-go`'s prebuilt
Chromium network stack.

### Why each tag is present

| tag | why |
| --- | --- |
| `with_gvisor` | **Required for TUN on Darwin.** `sing-tun`'s `stack_gvisor*.go` and `tun_darwin_gvisor.go` are gated on it. Without this tag the gVisor stack is unavailable on macOS. |
| `with_quic` | Hysteria2, TUIC, the v2ray QUIC transport that VLESS needs, and the DoQ/DoH3 DNS transports. |
| `with_utls` | uTLS fingerprinting. Reality depends on it. |
| `with_clash_api` | The external controller a third-party GUI talks to. A hard requirement. |
| `jiejie_client_macos` | Selects this registry. See the note below. |
| `with_naive_outbound` | Naive only, in the `naive` profile. |
| `badlinkname`, `tfogo_checklinkname0` | Match the fork's existing profiles. |

> **A trap worth recording.** The profile originally omitted `jiejie_client_macos`.
> The build still succeeded and `sing-box version` still printed the right tags,
> because `-tags` was passed through — but the *upstream* registry was compiled
> and shipped. The only thing that revealed it was
> `go list -f '{{.IgnoredGoFiles}}' ./include/`. The workflow now asserts the
> registry file set explicitly, and separately asserts that the tags the binary
> reports equal the tags the tag file declares.

### Why the excluded tags are excluded

| tag | why not |
| --- | --- |
| `with_acme` | A client consumes CA-signed certificates; it never issues its own. |
| `with_tailscale` | Large tree; the client does not offer Tailscale. |
| `with_ccm`, `with_ocm` | Out of scope for a proxy client. |
| `with_cloudflared` | Out of scope. |
| `with_usbip` | Out of scope. |
| `with_openvpn`, `with_openconnect` | Large trees; not part of the client feature set. |
| `with_dhcp` | The desktop client does not use DHCP DNS. |
| `with_wireguard` | The WireGuard endpoint is not part of the client feature set. |

The lite core is **56 MB** against **108 MB** for the upstream default tag set
built for the same platform — a 48% reduction, achieved entirely by
registration-level trimming.

## Registry

`include/registry_jiejie_client_macos.go` (`jiejie_client_macos`) and
`include/quic_client_macos.go` (`with_quic && jiejie_client_macos`).

This is a **client** registry, and it is deliberately much larger than the server
one. The server serves exactly one known VPS topology and can register almost
nothing; a GUI core runs whatever the user configured.

### Inbounds

| type | why |
| --- | --- |
| `tun` | The VPN interface. The primary reason a macOS GUI core exists. |
| `mixed` | Single-port HTTP+SOCKS. The GUI default for local proxy mode. |
| `socks` | GUIs name it explicitly. |
| `http` | GUIs name it explicitly. |
| `direct` | Local passthrough listener. |

No other inbound is registered. In particular no `redirect`/`tproxy` (Linux
netfilter only) and no server-side protocol inbounds.

### Outbounds

| type | why |
| --- | --- |
| `direct`, `block` | Routing primitives. `block` is registered here even though the server build drops it: GUI templates define a named `block` outbound and use it as a `route.final` or selector member, which is a configuration error if absent. |
| `selector`, `urltest` | Group management. Required by every GUI. |
| `socks`, `http` | Upstream proxy chaining. |
| `shadowsocks` | SS and SS2022. |
| `shadowtls` | ShadowTLS v3. |
| `snell` | Snell. |
| `trojan` | Trojan. |
| `vless` | VLESS, including Reality and Vision. |
| `vmess` | VMess. |
| `anytls` | AnyTLS. |
| `hysteria2` | Hysteria2 (via `with_quic`). |
| `tuic` | TUIC (via `with_quic`). |
| `naive` | **See below.** |

### The Naive decision

`naive` **resolves** in the lite profile, and that is intentional rather than an
oversight. Upstream ships `include/naive_outbound_stub.go` behind
`!with_naive_outbound`, which registers the type with a constructor that always
fails and names the tag that enables it:

```text
naive outbound is not included in this build, rebuild with -tags with_naive_outbound
```

So a GUI offering a Naive node gets an actionable message, not "unknown outbound
type", and because the stub imports no Cronet code, the CGO dependency stays out
of the lite binary. `TestClientMacOSNaiveOutboundIsAStubNotAnImplementation`
asserts that construction *fails*, which is what proves it is the stub.

**The Naive outbound was verified to build and run on darwin/arm64**, so it is a
tradeoff rather than a blocker. See [Naive status](#naive-status).

### DNS transports

The area most at risk of being trimmed too far. All of these are registered:

| type | why |
| --- | --- |
| `udp` | Plain DNS. |
| `tcp` | Truncation fallback and explicit `type: tcp` servers. |
| `tls` | DoT. |
| `https` | DoH, and DoH3 when `with_quic` is on. |
| `quic` | DoQ. |
| `h3` | DoH3. |
| `hosts` | Static host entries. |
| `fakeip` | The FakeIP pool GUI templates use for sniffed domains. |
| `local` | **Required, not optional.** See below. |

`local` is a **boot dependency**. `box.go` unconditionally initialises the DNS
transport manager with a fallback that creates a `C.DNSTypeLocal` transport, so
omitting it does not remove a feature — it makes every start fail with
`default DNS server fallback: transport type not found: local`. This was
established on the server profile by running the build, not by reading code, and
it applies identically here. There is a dedicated test for it.

`resolved` is deliberately absent: it is a systemd/D-Bus transport with no meaning
on Darwin. `dhcp` and `mdns` are not registered.

> **A coupling that could not be trimmed.** `dns/transport/mdns` *is* linked into
> the binary, because `dns/transport/local` imports it unconditionally
> (`local.go`, `local_preferred.go`) for its neighbour/preferred-domain resolver,
> and `local` is mandatory. Removing it would require editing upstream
> `dns/transport/local`, which this fork does not do — the trim is
> registration-level and build-tag-level only. The audit therefore records the
> coupling honestly and instead asserts the property that matters: **mdns must not
> be usable as a transport type**, checked behaviourally by requiring
> `sing-box check` to reject `type: mdns`.

### Endpoints, services, certificates

- **Endpoints: none.** This is the single largest dependency saving in the
  profile. No WireGuard, Tailscale, OpenVPN, OpenConnect or MASQUE endpoint.
- **Services: none** beyond the Clash API, which `with_clash_api` compiles in
  through `include/clashapi.go`, independently of the registry file.
- **Certificate providers: none.** A client consumes CA-signed certificates.

### Excluded protocols

`tor`, `ssh`, `bridge`, `hysteria` (v1, superseded by Hysteria2), and all
server-side inbound registration. These remain in the source tree; a package the
registry does not import never enters the import graph, so the linker drops it and
its whole dependency tree. **No upstream protocol source is edited or deleted**,
which is what keeps the upstream full build working — verified by building it.

## Clash API

The external controller is a hard requirement, because that is how a third-party
GUI drives an external core.

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "default_mode": "rule"
    }
  }
}
```

Verified to answer, on a real running process, on both flavors:

| endpoint | verified |
| --- | --- |
| `GET /version` | yes — returns `{"meta":true,"premium":true,"version":"sing-box 1.15.0-jiejie-masquerade.5"}` |
| `GET /proxies` | yes — `GLOBAL`, `proxy`, `auto`, `manual-node`, `direct`, `block` |
| `GET /proxies/select` | yes — type `Selector`, with a populated `all` list |
| `GET /proxies/urltest` | yes — type `URLTest`, with a populated `all` list |
| `GET /connections` | yes |
| `GET /configs` | yes |
| `GET /traffic` | yes — streams JSON objects |

## TUN

TUN is the core capability of a macOS GUI core, and it is **not** trimmed.

- `protocol/tun` is registered.
- The gVisor TUN stack is available (`with_gvisor`).
- The TUN inbound is present in the config fixture and passes `sing-box check`.

**Runtime TUN is NOT-TESTED.** Creating a `utun` device requires root and
reconfigures the host's routing table, which a CI runner must not do and which
would be destructive on a developer machine. The config check and the runtime
smoke test therefore cover registration, parsing and the startup path, and the
runtime smoke test removes only the TUN inbound so it can bind. This boundary is
stated rather than papered over.

Note that the fixture and example do **not** set the `stack` option. It is
deprecated as of sing-box 1.15.0 (removal scheduled for 1.17.0) and upstream's
guidance is to remove it to get `sing-tun`'s own TCP/IP stack. `with_gvisor`
remains required regardless, because it gates the Darwin TUN implementation files.

## Naive status

Verified by building and running, not by inference:

| check | result |
| --- | --- |
| `darwin/arm64` compile with `with_naive_outbound` and `CGO_ENABLED=1` | **PASS** |
| binary runs (`version`) | **PASS** |
| `sing-box check` on a valid `naive` outbound config | **PASS** |
| Naive against a real remote NaiveProxy server | **NOT-TESTED** |

The lite flavor deliberately does not enable it. Rationale:

- Cronet is a **CGO** dependency that links a prebuilt Chromium network stack. The
  lite profile is deliberately CGO-free so the core is self-contained.
- It enlarges the binary: 56 MB (lite) → 74 MB (naive) for arm64.
- A Cronet problem must never block the core itself, which is the whole reason
  the profiles are separate rather than one profile with a flag.

The audit distinguishes the flavors at the symbol level, because both register the
`naive` *type* and only one links the implementation: it counts `cronet-go`
symbols and requires zero for lite and non-zero for naive.

## GUI usage

This core is designed to be loaded as an **external sing-box executable**. No
specific GUI is required or assumed — any GUI that can be pointed at an external
sing-box binary will work, including GUI clients that manage their own TUN device
and expect only a working sing-box core.

```bash
# 1. Make it executable.
chmod +x sing-box-darwin-arm64

# 2. Confirm it runs and is the right build.
./sing-box-darwin-arm64 version
#   sing-box version 1.15.0-jiejie-masquerade.5
#   Environment: go1.25.5 darwin/arm64
#   Tags: with_gvisor,with_quic,with_utls,with_clash_api,jiejie_client_macos,badlinkname,tfogo_checklinkname0
#   CGO: disabled

# 3. Validate a configuration before running it.
./sing-box-darwin-arm64 check -c config.json

# 4. Run it.
./sing-box-darwin-arm64 run -c config.json

# Other useful commands:
./sing-box-darwin-arm64 format -c config.json      # reformat a config
./sing-box-darwin-arm64 generate reality-keypair   # Reality key material
```

A starting-point configuration is shipped at
`test/jiejie/macos-client/example-config.json`. It is validated by CI on every
run. It contains **no real credentials or endpoints** — the server address is a
documentation address and the Reality public key is a throwaway generated for the
example. Replace them.

> **Port note.** The example uses `7890` for the mixed inbound and `9090` for the
> Clash API, which are the conventional sing-box defaults. If the machine already
> runs a proxy on those ports, the core fails to start with
> `bind: address already in use`. Change `listen_port` and
> `external_controller` before running it on such a machine.

## Building

```bash
# lite core (default), darwin/arm64
./scripts/ci/build-macos-client.sh arm64 lite dist/sing-box-darwin-arm64

# naive core, darwin/arm64 (CGO on)
./scripts/ci/build-macos-client.sh arm64 naive dist/sing-box-darwin-arm64-naive

# Intel
./scripts/ci/build-macos-client.sh amd64 lite dist/sing-box-darwin-amd64
```

The script reads the tag file rather than repeating the tag list, injects the
version from `release/JIEJIE_VERSION` (otherwise `sing-box version` prints
`unknown`, because `constant.Version` defaults to that), and passes
`-trimpath -buildvcs=false`. No timestamp is linked in, so the artifact is
reproducible: **two consecutive builds of the same commit produced an identical
SHA-256**, verified.

## Verification

Every script below can be run locally and is run in CI.

```bash
BIN=dist/sing-box-darwin-arm64

./scripts/ci/check-macos-client-config.sh   "$BIN" /tmp/fixture   # config check
./scripts/ci/check-macos-client-runtime.sh  "$BIN" /tmp/runtime   # runtime + Clash API
./scripts/ci/audit-macos-client-registry.sh "$BIN"                # registry + symbols
```

Unit tests:

```bash
TAGS="$(cat release/BUILD_TAGS_JIEJIE_CLIENT_MACOS)"
go test -tags "$TAGS" ./include/... ./route/... ./dns/... ./option/... \
                      ./common/... ./protocol/... ./transport/...
(cd test && go test -tags "$TAGS" -run 'TestClientMacOS' ./jiejie/)
```

### Test matrix

| area | status | how |
| --- | --- | --- |
| `gofmt` | **PASS** | `gofmt -l .` clean |
| lint | **PASS** | `golangci-lint` "0 issues" |
| `go vet` (client tags) | **PASS** | exit 0 over the shipped packages |
| unit tests (client tags) | **PASS** | `route`, `dns`, `option`, `common`, `protocol`, `transport` |
| client registry audit tests | **PASS** | 12/12 `TestClientMacOS*` |
| darwin/arm64 lite build | **PASS** | native build, 56,154,130 bytes |
| darwin/arm64 naive build | **PASS** | native build, 74,401,618 bytes |
| darwin/amd64 lite build | **PASS** | cross-build on arm64 host |
| `sing-box version` | **PASS** | version, arch and tags all correct |
| reproducible build | **PASS** | identical SHA-256 across two builds |
| config check (lite) | **PASS** | full fixture, no warnings |
| config check (naive) | **PASS** | full fixture |
| example config check | **PASS** | checked in CI |
| runtime smoke (lite) | **PASS** | real process, real API |
| runtime smoke (naive) | **PASS** | real process, real API |
| Clash API `/version`, `/proxies`, `/connections`, `/traffic`, `/configs` | **PASS** | real HTTP against a running process |
| selector / urltest readable | **PASS** | via Clash API |
| SIGTERM clean exit | **PASS** | exit 0, no panic |
| registry symbol audit | **PASS** | both flavors |
| excluded packages absent (`go tool nm`) | **PASS** | masque, openvpn, openconnect, ssh, tor, redirect, resolved, ssmapi, usbip, wireguard, hysteria v1, dhcp, bridge |
| `jiejie_server_minimal` still builds | **PASS** | Linux amd64 build unaffected |
| upstream full registry still builds | **PASS** | 108 MB darwin build |
| **runtime TUN / real system traffic** | **NOT-TESTED** | needs root and host route changes |
| **GUI actually loading this core** | **NOT-TESTED** | no GUI is installed or driven here |
| **real proxy connectivity** | **NOT-TESTED** | fixture servers are `127.0.0.1` placeholders |
| **Naive against a real remote server** | **NOT-TESTED** | no remote endpoint available |
| **darwin/amd64 artifact executed** | **NOT-TESTED** | an arm64 host cannot run it |
| **Hysteria2 / TUIC over real WAN** | **NOT-TESTED** | no remote endpoint available |

Nothing in the `NOT-TESTED` rows is claimed as passing.

## Historical client work: reviewed and rejected

Each item from `5ce3c4d675^` was evaluated against the current HEAD, not assumed
useful. None was restored.

| item | decision | reason |
| --- | --- | --- |
| `BUILD_TAGS_JIEJIE_CLIENT_FULL` | **rejected** | It was the upstream default tag set, not a client-minimal profile: it enabled `with_acme`, `with_tailscale`, `with_ccm`, `with_ocm`, `with_cloudflared`, `with_usbip`, `with_openvpn`, `with_openconnect`. None serve a macOS proxy client. The new profile derives its tags from actual client requirements instead. |
| `BUILD_TAGS_JIEJIE_CLIENT_WINDOWS` | **rejected** | Windows-only concerns (`with_purego`); irrelevant to macOS. |
| iOS slim registry (`registry_jiejie_ios_slim.go`) | **rejected** | Served an in-app mobile client. Its own comment says it trimmed hysteria/hysteria2/tuic as "not part of the Jiejie client feature set" — the opposite of what a desktop client needs. Kept as a structural reference for splitting client and server registries. |
| `include/quic_ios_slim.go` | **rejected** | Registered no Hysteria2/TUIC. Superseded by `include/quic_client_macos.go`, which registers both. |
| HTTP client / H3 client pool (`transport/http/client*.go`, `client_h3_slot.go`) | **rejected** | A custom HTTP/3 pool with promotion, backoff and blackhole handling. The current HEAD has its own evolved HTTP transport, and reintroducing a parallel client stack would duplicate it and add maintenance cost with no demonstrated client benefit. |
| `option/http3_pool.go`, `option/http3_fallback.go` | **rejected** | Options for the above. The current `QUICOptions` no longer has those fields. |
| MASQUE client (`protocol/masque`, `transport/masque/client.go`) | **rejected** | A client for the MASQUE *server* this fork runs. It is a Server Edition companion, not a general client protocol a GUI needs. The packages remain in the tree for the server build. |
| `protocol/http/outbound.go` (HTTP proxy outbound) | **accepted** | Uniquely among the old client work, this is an ordinary client capability that upstream registers and the fork's VPS narrowing removed. The client registry restores it. Found by `sing-box check`, not by reading source. |
| `scripts/ci/build-client.sh` | **rejected, reimplemented** | Its structure was sound but it knew only the deleted flavors, and it did not inject the version, so its binaries would have reported `unknown`. `build-macos-client.sh` is new: flavor-aware, version-injecting, and it reads the tag file. |
| iOS workflow (`jiejie-ios.yml`, 1117 lines) | **rejected** | Built Apple app artifacts. Out of scope; this branch is a CLI core, not an app. |
| `cmd/internal/build_libbox` profile plumbing | **rejected** | libbox is not built here. |
| `clients/apple` submodule pin | **rejected** | The fork's custom pin was undone by `5ce3c4d675`; it stays at the upstream baseline. Not re-pinned. |
| `test/jiejie/jiejie-ios-client-fixture.json` | **rejected** | An iOS fixture naming protocols this profile deliberately excludes (hysteria, tuic). Replaced by `test/jiejie/macos-client/jiejie-macos-client-fixture.json.tmpl`, which covers the macOS profile's actual registry. |

## Preserved fork work

The client branch is cut from `testing`, so it inherits the fork's cross-platform
improvements. The following were audited as genuinely client-relevant and are
retained unchanged:

| change | why it is client-relevant |
| --- | --- |
| `sing` replace → `Piggy-Cat-bit-shadow/sing` | Preserves packet batching through the `canceler` timeout wrappers. This sits on the ordinary UDP data path — an idle-timeout wrapper around *every* UDP session — so a tunnel that implemented batching previously lost it silently. Verified to compile into the client build; the lite binary links the patched `sing`. |
| `route/conn.go` connected-UDP fast path | Removes the per-packet destination lookup and enables connected-socket batch read/write for fixed-destination tunnels. |
| `adapter/inbound.go` `UDPConnectPacketConn` | The declaration that lets the router opt into the connected path safely. |
| `adapter/upstream.go` `applyUDPConnect` | Ensures both packet wrappers make the same decision, so the two entry points cannot drift. |
| `route/packet_destination_guard.go` + `metadata.UoTDatagramDestinations` | **Security fix.** UoT v1/v2 non-connect forms carry a per-datagram destination that the session-level routing decision does not cover; without this, a session approved for one address could reach another, exposing loopback and internal services. Applies to any client using UoT. |
| `common/badhttp/badhttp.go` source-address hardening | **Security fix.** `SourceAddress` no longer consults the client-forgeable `X-Forwarded-For`; `metadata.Source` feeds `source_ip_cidr` rules, logs and audit trails. |
| `common/tls/alpn_view.go` | Fixes a real defect where TCP and QUIC shared one ALPN list, letting a TCP client negotiate `h3` and a QUIC client negotiate `h2`. Not client-specific, but correct for any build serving both transports. |
| `common/uot/router.go` datagram-destination flag | The producer side of the guard above. |
| `option/simple.go` HTTP resource bounds | Server-side profile, but the validation and error-reporting improvements are shared code. |

Server-only work (Native Naive inbound, HTTP masquerade, the unauthenticated
limiter, server resource profiles, `jiejie_server_minimal`, MASQUE listener
topology, VPS ACLs) is left in the tree and is **not** registered by the client
registry, so it does not enter the client binary. This was verified with
`go tool nm`, not assumed.

## Known limitations

1. **Runtime TUN is unverified.** Registration, parsing and the startup path are
   tested; actually creating a `utun` device and routing system traffic is not,
   because it needs root and mutates host routes.
2. **No GUI has been used to load this core.** The binary satisfies the external
   core contract (`version`, `check`, `run`, `format`, Clash API), which is what a
   GUI consumes, but the GUI-side integration is untested.
3. **No real proxy connectivity was exercised.** All fixture servers are
   `127.0.0.1` placeholders, by design: a smoke test must not depend on a live
   remote endpoint.
4. **`dns/transport/mdns` is linked** through the mandatory `local` transport,
   though it is not registered. Removing it would require editing upstream.
5. **`naive` resolves in the lite profile but cannot construct.** This is
   deliberate and produces an actionable error, but a GUI that probes types by
   resolution rather than by construction may misreport Naive as available.
6. **The amd64 artifact is not executed in CI**, because an arm64 runner cannot
   run it.
7. **`include/*.go` helper functions are unused** under any minimal registry, so
   `golangci-lint`'s `unused` check reports ~19 functions if lint is run with the
   minimal tags. This is pre-existing and profile-independent — the Linux server
   profile reports the same 19 on `testing`. Lint therefore runs with the default
   tag set, as the server workflow already does.

## Upstream sync

The same policy as the server branch:

```sh
git fetch upstream
git switch macos-client
git log --oneline HEAD..upstream/testing
git diff HEAD...upstream/testing
git rebase upstream/testing        # or: git merge upstream/testing
```

Never reset or force-push either branch. After every sync, re-run the full
verification set above, and in particular re-check:

- the three registries are still mutually exclusive;
- `with_gvisor` is still what gates the Darwin TUN files in `sing-tun`;
- `local` is still a DNS boot dependency;
- the `sing` replace still applies and the client build still compiles.
