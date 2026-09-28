# Jiejie macOS Client Edition

This document describes the macOS Client Edition of the Jiejie sing-box fork: what
it is, what it contains, why each part is included or excluded, and what has
actually been verified.

- **Product** — a native macOS CLI sing-box core. The primary usage is headless
  daemon plus browser Web Dashboard; loading it as an external core from a
  third-party GUI is also supported.
- **Branch** — `testing`. The client and the server share ONE branch and ONE source
  tree; the former `macos-client` branch was consolidated into `testing` and is no
  longer a development line.
- **Profile** — ONE. `jiejie_client_macos`, built for `darwin/arm64` with CGO=1.
  It contains NaiveProxy (Cronet) and MASQUE.
- **Target** — `darwin/arm64` only. Intel builds were removed: this is one product
  for one architecture.

See [`BUILD-PROFILES.md`](BUILD-PROFILES.md) for the complete profile matrix,
build commands and reproducibility measurements.

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

The repository carries ONE source tree that produces three build profiles. They
share every protocol and transport package, and are separated entirely by build
tags and registries. No profile's build can accidentally select another's
registry, because the constraints are mutually exclusive.

```text
                     testing  (single source tree)
                          │
      ┌───────────────────┼───────────────────┐
      ↓                   ↓                   ↓
 Linux Server Minimal  macOS Lite        macOS Naive
 jiejie_server_minimal jiejie_client_macos jiejie_client_macos
                                           + with_naive_outbound
```

There is no "Mac copy" of any protocol. MASQUE, Naive, HTTP/2, HTTP/3, QUIC,
buffering and framing all live in one place and are consumed by every profile.

| | Server Minimal | macOS Lite | macOS Naive |
| --- | --- | --- | --- |
| branch | `testing` | `testing` | `testing` |
| platform | Linux amd64 | macOS arm64 | macOS arm64 |
| build tag | `jiejie_server_minimal` | `jiejie_client_macos` | `jiejie_client_macos` + `with_naive_outbound` |
| tag file | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` | same |
| registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` | same as Lite |
| CGO | `0` | `0` | `1` (Cronet) |
| workflow | `server-linux-amd64.yml` | `client-macos.yml` | `client-macos.yml` |
| artifact | `Jiejie-Linux-amd64-…` | `Jiejie-macOS-arm64-…` | `Jiejie-macOS-arm64-…` |

There is exactly one macOS profile, so the table above collapses to a single macOS
column. Each product is built from one commit by its own workflow
(`server-linux-amd64.yml`, `client-macos.yml`), and each workflow builds its binary
exactly once and reuses it for every check and for the upload.

The three registries are mutually exclusive and complete:

| condition | registry compiled |
| --- | --- |
| `!jiejie_server_minimal && !jiejie_client_macos` | `include/registry.go` (upstream full) |
| `jiejie_server_minimal` | `include/registry_jiejie_server.go` |
| `jiejie_client_macos` | `include/registry_jiejie_client_macos.go` |

`include/quic.go` carries the same constraints, with three variants:
`include/quic.go` (upstream full), `include/quic_minimal.go` (server) and
`include/quic_client_macos.go` (client).

### Control plane vs data plane

The client has two independent planes, and keeping them separate is what makes a
broken dashboard harmless:

```text
DATA PLANE   inbound (tun / mixed) -> router -> DNS -> outbound -> network
             Nothing here depends on the control plane.

CONTROL PLANE  native `api` service  -> gRPC-Web / WebSocket -> Web Dashboard
               Clash `clash_api`     -> REST / WebSocket     -> third-party GUIs
```

If the dashboard fails to download, is corrupt, or is unreachable, the data plane
is unaffected: the core still starts, proxies, resolves DNS and runs TUN. The
control plane is a consumer of the core, never a dependency of it.

### macOS helper scripts

| script | purpose |
| --- | --- |
| `scripts/macos/run-headless.sh` | foreground runner: validates then `exec`s the core |
| `scripts/macos/launchd.sh` | install / start / stop / restart / status / logs / uninstall |
| `scripts/macos/install-launchd.sh` | wrapper for `launchd.sh install` |
| `scripts/macos/uninstall-launchd.sh` | wrapper for `launchd.sh uninstall` |

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

## Build profile

ONE profile, and its tag set lives in exactly one file. The build script, the
workflow and `build-info.sh` all read that file rather than repeating the list, so
they cannot drift.

### `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS`

```text
with_gvisor,with_quic,with_utls,with_clash_api,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0
```

CGO is **on**, because `with_naive_outbound` links `cronet-go`'s prebuilt Chromium
network stack.

`build-macos-client.sh` asserts that every required tag is present and refuses to
build otherwise. That is deliberate: a tag-file edit dropping `with_naive_outbound`
would still produce a working binary, so nothing else in the pipeline would notice
that the shipped core silently lost NaiveProxy.

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

The macOS core is **76 MB** against **108 MB** for the upstream default tag set
built for the same platform. It is larger than a trimmed CGO-free core would be,
because it ships NaiveProxy and MASQUE rather than excluding them; the saving
against upstream still comes entirely from registration-level trimming.

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

`naive` is a **real, working outbound** in this core. The profile enables
`with_naive_outbound`, which links the Cronet implementation, so a NaiveProxy node
works rather than producing an error.

This is worth stating precisely, because the type resolves either way: upstream
ships `include/naive_outbound_stub.go` behind `!with_naive_outbound`, and that stub
registers the type with a constructor that always fails with

```text
naive outbound is not included in this build, rebuild with -tags with_naive_outbound
```

So a type-level check cannot distinguish a working implementation from a stub, and a
regression that dropped the tag would leave most checks passing while users lost
NaiveProxy. The distinction is asserted three ways:

- `TestClientMacOSNaiveOutboundIsARealImplementation` asserts that construction with
  empty options fails for a REAL reason (missing TLS), **not** with the stub's
  "not included in this build" message.
- `scripts/ci/audit-macos-client-registry.sh` requires Cronet symbols and requires
  the stub string to be absent.
- The `client-macos.yml` capability step checks `cronet-go.NewNaiveClient` in the
  shipped binary's symbol table.

See [Naive status](#naive-status).

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

- **Endpoints: `masque-client` only.** MASQUE is a first-class client transport
  (CONNECT-IP / CONNECT-UDP over HTTP/2 or HTTP/3), so the client role is
  registered. The **server** role is not: see below.
- **Services:** the native `api` service (which serves the Web Dashboard) plus the
  Clash API, which `with_clash_api` compiles in through `include/clashapi.go`,
  independently of the registry file.
- **Certificate providers: none.** A client consumes CA-signed certificates.

#### Why the MASQUE roles are split

`protocol/masque` holds BOTH endpoint roles in one package, and
`masque.RegisterEndpoint` registers both at once. That helper is wrong for this
profile in both directions:

- calling it would ship `masque-server` — a TUN-binding CONNECT-IP endpoint — inside
  a desktop client that has no server role;
- not calling it at all, which was the previous state, left `masque-client`
  **unreachable**: the implementation was compiled into the binary but a valid
  `type: masque-client` configuration failed with "unknown endpoint type".

The registration is therefore split:

```go
masque.RegisterClientEndpoint(registry)  // masque-client only  ← this profile
masque.RegisterServerEndpoint(registry)  // masque-server only
masque.RegisterEndpoint(registry)        // both; upstream and server builds
```

The resulting macOS surface is exactly:

```text
masque-client  ✅
masque-server  ❌
```

The protocol and transport source stays SHARED — this is one registry entry, not a
second implementation — so every framing, capsule, H3 and packet-ownership fix
continues to benefit both roles. The `transport/masque` and `transport/http`
packages are linked in full.

Because the roles live in one package, the audit no longer excludes the whole
`protocol/masque` PACKAGE; "client present, server absent" is the real invariant and
is asserted at symbol level by `scripts/ci/audit-macos-client-registry.sh` and at
type level by `test/jiejie/macos_client_registry_audit_test.go`.

The client fixture and the example configs both contain a `masque-client` endpoint
wired into the selector, so `sing-box check` in CI covers the registration. This was
verified to be a real guard: building the client with the registration removed makes
the fixture fail with `endpoints[0]: unknown endpoint type: masque-client`.

### Excluded protocols

`tor`, `ssh`, `bridge`, `hysteria` (v1, superseded by Hysteria2), and all
server-side inbound registration. These remain in the source tree; a package the
registry does not import never enters the import graph, so the linker drops it and
its whole dependency tree. **No upstream protocol source is edited or deleted**,
which is what keeps the upstream full build working — verified by building it.

## Management planes

sing-box ships **two independent management services**. Both are available in this
build, they run simultaneously in one process, and they serve different purposes.

> **Daemon command RPCs.** The launcher's proxy list in daemon mode is served by the
> `lx_command` RPCs (`GetGroups`, `GetOutbounds`, `URLTestOutbound`), which are gated
> by `with_lx_command` — a build tag **separate** from `with_lxd`, which gates the
> daemon process itself. Both are in this build's tags, and both are required:
> dropping `with_lx_command` leaves a core that advertises a daemon it cannot answer
> `GetGroups` on, which is exactly the omission that once produced an empty proxy
> page. See [JIEJIE-DAEMON-RPC-COMPAT.md](JIEJIE-DAEMON-RPC-COMPAT.md) for the full
> contract, and `scripts/ci/check-jiejie-daemon-rpc-contract.sh` for the guard that
> fails CI if either tag or any launcher-called RPC goes missing.

| | native `api` | Clash compatibility |
| --- | --- | --- |
| config key | `services: [{"type":"api"}]` | `experimental.clash_api` |
| protocol | gRPC over gRPC-Web, WebSocket, and h2c | REST + WebSocket |
| dashboard | **yes** — serves the sing-box Web Dashboard | external UI only |
| role | primary control plane | compatibility |

The native service is the **primary** plane; the Clash API is retained as a
**compatibility** plane. It is deliberately not removed: third-party GUIs, existing
dashboards, ecosystem tools and debugging workflows depend on it.

### Native API service

```json
{
  "services": [
    {
      "type": "api",
      "tag": "api",
      "listen": "127.0.0.1",
      "listen_port": 9090,
      "dashboard": { "enabled": true, "path": "dashboard" }
    }
  ]
}
```

`listen` is loopback by default in the shipped example. `secret` is supported: set
it and the credential is required on the API, which matters if you ever bind a
non-loopback address. The API also supports TLS (`tls`) and CORS
(`access_control_allow_origin`), and `access_control_allow_private_network`
controls whether a browser on a public page may reach a private-network address.

`Dashboard` accepts three forms: `true`, a path string, or an object. The object
form adds `download_url`, `http_client` and `update_interval`.

Verified to work against a real running process, over real HTTP:

| operation | method | verified |
| --- | --- | --- |
| version | `GetVersion` | **PASS** — returns `1.15.0-jiejie-masquerade.5`, grpc-status 0 |
| groups | `SubscribeGroups` | **PASS** — decodes to the real selector/urltest tree with `type`, `selectable`, `selected` |
| switch selector | `SelectOutbound` | **PASS** — and the change reads back (`auto` → `direct`) |
| URL test | `URLTest` | **PASS** |
| traffic / status | `SubscribeStatus` | **PASS** — streams |
| logs | `SubscribeLog` | **PASS** — streams |
| connections | `SubscribeConnections` | **PASS** — streams |
| close connections | `CloseAllConnections` | **PASS** |
| outbound list | `SubscribeOutbounds` | **PASS** — streams |
| clash mode | `SetClashMode` | **PASS** |
| clear logs | `ClearLogs` | **PASS** |

### Web Dashboard

The dashboard is **not** vendored into this repository. The profile reuses
upstream's mechanism, which is the right design for all four reasons the task
cares about:

- the binary stays clean — no front-end source in the tree;
- the dashboard is independently updatable;
- it is not coupled to the core;
- **a dashboard failure cannot stop the core.** The static file server and the
  download live in the control plane. If the download fails, is corrupt, or the
  network is unreachable, the core still starts, proxies, resolves DNS and runs
  TUN. Verified: the core was started with an empty dashboard directory and no
  reachable archive path and kept serving traffic.

Configuration: `dashboard.enabled`, `path` (default `dashboard`, relative to the
working directory), `download_url` (default is upstream's
`sing-box-dashboard` `gh-pages` archive), `http_client`, and `update_interval`
(default 24h). The download is etag-aware, so an unchanged archive is not
re-fetched.

Serving: `GET /` redirects `302` to `/dashboard/`, which serves the SPA. If
`dashboard.path` already contains files **without** an `.etag` marker file, they
are treated as user-provided and auto-update is disabled — that is how you vendor
your own UI.

Verified locally against a real download:

| check | result |
| --- | --- |
| archive downloads, extracts, serves | **PASS** |
| `GET /` redirects to `/dashboard/` | **PASS** (302) |
| `GET /dashboard/` returns real HTML | **PASS** |
| JS bundle served | **PASS** (1.25 MB, HTTP 200) |
| dashboard fetch in CI | **NOT-TESTED** — CI must not depend on the public network |

### Clash compatibility API

```json
{
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9091",
      "default_mode": "rule"
    }
  }
}
```

Verified to answer, on a real running process, on both flavors:

| endpoint | verified |
| --- | --- |
| `GET /version` | **PASS** — `{"meta":true,"premium":true,"version":"sing-box 1.15.0-jiejie-masquerade.5"}` |
| `GET /proxies` | **PASS** — `GLOBAL`, `select`, `auto`, `direct`, `block` |
| `GET /proxies/select` | **PASS** — type `Selector`, populated `all` |
| `GET /proxies/urltest` | **PASS** — type `URLTest`, populated `all` |
| `GET /connections` | **PASS** |
| `GET /configs` | **PASS** |
| `GET /traffic` | **PASS** — streams JSON |

Both planes were confirmed working **in the same process**, on separate ports.

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

The macOS core **enables it**. NaiveProxy is a headline capability of this product,
so it is in the shipped binary rather than behind a second profile.

The cost is accepted deliberately:

- Cronet is a **CGO** dependency that links a prebuilt Chromium network stack, so
  the macOS core is CGO=1 and is not self-contained. The alternative would be a
  second CGO-free core that cannot speak NaiveProxy, which is the split that was
  removed.
- The core is ~76 MB for arm64, against ~56 MB for a CGO-free build that excludes
  Naive and MASQUE.

The audit asserts this at the symbol level, because the `naive` *type* resolves
whether or not the implementation is linked: it requires `cronet-go` symbols to be
present and requires the stub's "not included in this build" string to be absent.

## Usage

Two modes, and the same binary supports both. They are not exclusive: pick one,
or run the headless mode and point a GUI at it later.

| | Mode A — Headless + Web Dashboard | Mode B — External GUI Core |
| --- | --- | --- |
| control | your browser | the GUI |
| needs a GUI | no | yes |
| recommended | **yes** | optional |
| TUN | needs root | GUI manages it |
| works unattended | yes, via launchd | depends on the GUI |

### Mode A — Headless + Web Dashboard (recommended)

No third-party GUI is required. sing-box serves its own dashboard, and launchd
keeps it running.

```bash
chmod +x sing-box-darwin-arm64

# 1. Validate.
./sing-box-darwin-arm64 check -c config.json

# 2. Set up a working directory OUTSIDE ~/Desktop, ~/Documents and ~/Downloads
#    (see the TCC note below), then run in the foreground:
./scripts/macos/run-headless.sh config.json

# 3. Open the dashboard.
open http://127.0.0.1:9090/
```

Step 2 can be replaced by a supervised service:

```bash
./scripts/macos/install-launchd.sh config.json   # install + start
./scripts/macos/launchd.sh status                # is it running?
./scripts/macos/launchd.sh restart
./scripts/macos/launchd.sh logs                  # follow the logs
./scripts/macos/uninstall-launchd.sh
```

install-launchd.sh and uninstall-launchd.sh are thin wrappers over
`scripts/macos/launchd.sh`, which also provides `start`, `stop`, `restart`,
`status` and `logs`. Run it with no arguments for the full list.

The dashboard gives you: run status and traffic, outbound and selector groups,
switching a selector, running a URL test, live connections and closing them, and
logs.

**The dashboard is optional at runtime.** If it fails to download or is corrupt,
the core still starts and proxies — the control plane and the data plane are
separate. Nothing about the proxy depends on the UI.

### Mode B — External GUI Core (optional)

Any GUI that can be pointed at an external sing-box executable works. No specific
GUI is required or assumed, including GUI clients that manage their own TUN device
and expect only a working sing-box core.

```bash
chmod +x sing-box-darwin-arm64

# Confirm it runs and is the right build.
./sing-box-darwin-arm64 version
#   sing-box version 1.15.0-jiejie-masquerade.5
#   Environment: go1.25.5 darwin/arm64
#   Tags: with_gvisor,with_quic,with_utls,with_clash_api,jiejie_client_macos,badlinkname,tfogo_checklinkname0
#   CGO: disabled

./sing-box-darwin-arm64 check  -c config.json
./sing-box-darwin-arm64 run    -c config.json

# Other useful commands:
./sing-box-darwin-arm64 format -c config.json      # reformat a config
./sing-box-darwin-arm64 generate reality-keypair   # Reality key material
```

GUIs that expect a Clash-style controller should point at
`experimental.clash_api.external_controller`; GUIs that speak the native API
should point at the `services` `api` entry. Both are in the shipped examples.

### Example configurations

Two starting points ship and are validated by CI on every run. Neither contains
real credentials or endpoints — the server address is a documentation address and
the Reality public key is a throwaway generated for the example.

| file | purpose |
| --- | --- |
| `test/jiejie/macos-client/example-headless.json` | Mode A: TUN + mixed, native API with dashboard on `127.0.0.1:9090`, Clash API on `127.0.0.1:9091` |
| `test/jiejie/macos-client/example-config.json` | Mode B: TUN + mixed, Clash API only, for external-GUI use |

> **Port note.** Both examples use the conventional sing-box ports (`7890` mixed,
> `9090`/`9091` controllers). If the machine already runs a proxy on those ports,
> the core fails to start with `bind: address already in use`. Change
> `listen_port`, `listen_port` and `external_controller` before running on such a
> machine. This is not hypothetical: it happened while testing this build.

> **TCC note (`~/Desktop`, `~/Documents`, `~/Downloads`).** macOS privacy
> protection blocks launchd from reading binaries and configs under those
> directories. The failure is silent and misleading: `launchctl` reports
> `state = running` with a real pid, while the process is blocked in `dyld`
> before it ever execs, producing no output, no log lines and no listening port.
> Keep the binary, the config and the working directory somewhere unprotected,
> for example `~/.local/share/jiejie/`. Running in the foreground is unaffected,
> because Terminal already holds the user's grant. `install-launchd.sh` warns
> when it detects this.

### Privilege model

The two modes have genuinely different requirements, and it is worth being precise
about which is which.

| mode | root required? | why |
| --- | --- | --- |
| mixed / SOCKS / HTTP proxy | **no** | binds an unprivileged port above 1024 on loopback |
| TUN | **yes — always** | creating a `utun` device goes through the `AF_SYSTEM` / `SYSPROTO_CONTROL` "utun" kernel control, which macOS restricts to root |

Verified on this machine: a mixed-only config runs as uid 501 with no privilege
escalation. The same binary with a TUN config fails as uid 501 with

```text
FATAL start inbound/tun[tun-in]: configure tun interface: Connect: operation not permitted
```

and adding `auto_route` / `strict_route` does not change the failure point — it
fails at `utun` creation, before any routing is touched. This is a kernel-level
restriction, not a file-permission problem, so `chmod`/`chown` cannot solve it and
this project does not attempt to.

Consequences, stated plainly:

- **TUN mode cannot run from a per-user LaunchAgent.** A LaunchAgent runs as your
  uid and cannot create a `utun`. `install-launchd.sh` refuses a TUN config at
  install time rather than letting launchd restart-loop on the error forever.
- TUN mode is therefore either run in the foreground with `sudo`, or installed as
  a **root LaunchDaemon** in `/Library/LaunchDaemons`.
- This project does **not** install a root daemon by default. That is a
  system-wide privileged change and should be a deliberate decision; the emitted
  plist documents how to adapt it if you want that.
- No insecure escalation helper is provided, and none is planned.

## Building

```bash
# THE macOS core, darwin/arm64 (CGO on)
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64
```

There is one macOS product and one architecture, so there are no flavor or Intel
variants to select.

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
./scripts/ci/check-macos-client-headless.sh "$BIN" /tmp/headless  # native Web API + control plane
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
| client registry audit tests | **PASS** | 20/20 `TestClient*` |
| capability verification | **PASS** | NaiveProxy, MASQUE, gVisor, Hysteria2, TUIC, Clash API, TUN all confirmed in the shipped symbol table |
| darwin/arm64 build (canonical) | **PASS** | native build, 76,166,402 bytes, arm64 only |
| `sing-box version` | **PASS** | version, arch and tags all correct |
| reproducible build | **PASS** | identical SHA-256 across two builds |
| config check | **PASS** | full fixture, no warnings |
| example config check | **PASS** | checked in CI |
| runtime smoke | **PASS** | real process, real API |
| Clash API `/version`, `/proxies`, `/connections`, `/traffic`, `/configs` | **PASS** | real HTTP against a running process |
| selector / urltest readable | **PASS** | via Clash API |
| SIGTERM clean exit | **PASS** | exit 0, no panic |
| registry symbol audit | **PASS** | single canonical core |
| excluded packages absent (`go tool nm`) | **PASS** | masque, openvpn, openconnect, ssh, tor, redirect, resolved, ssmapi, usbip, wireguard, hysteria v1, dhcp, bridge |
| `jiejie_server_minimal` still builds | **PASS** | Linux amd64 build unaffected |
| upstream full registry still builds | **PASS** | 108 MB darwin build |
| native `api` service accepted by `check` | **PASS** | `services: [{"type":"api"}]` |
| native API `GetVersion` over gRPC-Web | **PASS** | real HTTP, grpc-status 0 |
| native API groups / selector state | **PASS** | `SubscribeGroups` decoded |
| native API switch selector | **PASS** | read back `auto` → `direct` |
| native API URLTest / CloseAllConnections / ClearLogs / SetClashMode | **PASS** | grpc-status 0 |
| native API streaming (`Status`, `Log`, `Connections`, `Outbounds`) | **PASS** | real frames |
| both management planes in one process | **PASS** | native + Clash on separate ports |
| Web Dashboard download, extract, serve | **PASS** | real archive from upstream, HTML + 1.25 MB bundle |
| `GET /` → `/dashboard/` redirect | **PASS** | 302 |
| core runs with dashboard unavailable | **PASS** | control plane does not gate the data plane |
| `run-headless.sh` start + SIGINT | **PASS** | exit 0, signal reaches the core |
| launchd install / start / stop / restart / status / uninstall | **PASS** | real LaunchAgent, real `launchctl` |
| launchd KeepAlive respawn after SIGKILL | **PASS** | `runs=4`, new pid, API answering again |
| mixed mode without root | **PASS** | runs as uid 501, no escalation |
| TUN mode without root | **PASS** (as a documented refusal) | fails with `operation not permitted`, as expected |
| **runtime TUN / real system traffic** | **NOT-TESTED** | needs root; `sudo` requires a password, so TUN-up could not be exercised |
| **dashboard fetch inside CI** | **NOT-TESTED** | CI must not depend on the public network |
| **GUI actually loading this core** | **NOT-TESTED** | no GUI is installed or driven here |
| **real proxy connectivity** | **NOT-TESTED** | fixture servers are `127.0.0.1` placeholders |
| **Naive against a real remote server** | **NOT-TESTED** | no remote endpoint available |
| **darwin/amd64** | **removed** | the product targets Apple Silicon only |
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
| `sing` replace → `Piggy-Cat-bit-shadow/sing` | Preserves packet batching through the `canceler` timeout wrappers. This sits on the ordinary UDP data path — an idle-timeout wrapper around *every* UDP session — so a tunnel that implemented batching previously lost it silently. Verified to compile into the client build; the macOS core links the patched `sing`. |
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
5. **`naive` is a real, working outbound.** It is no longer a stub, so a GUI that
   probes types by resolution gets the right answer and the outbound actually
   constructs.
6. **Intel Macs are not supported.** There is no darwin/amd64 artifact; the
   product targets Apple Silicon only.
7. **`include/*.go` helper functions are unused** under any minimal registry, so
   `golangci-lint`'s `unused` check reports ~19 functions if lint is run with the
   minimal tags. This is pre-existing and profile-independent — the Linux server
   profile reports the same 19 on `testing`. Lint therefore runs with the default
   tag set, as the server workflow already does.
8. **TUN mode cannot be supervised by a per-user LaunchAgent.** It needs root, so
   it needs a root LaunchDaemon or a foreground `sudo` run. The project
   deliberately does not install a root daemon for you.
9. **The dashboard is fetched from the public internet on first start.** If that
   fetch is blocked, the dashboard is unavailable until you provide files at
   `dashboard.path` yourself (drop an `.etag`-less directory there and auto-update
   is disabled). The core is unaffected either way.
10. **A LaunchAgent cannot read files under `~/Desktop`, `~/Documents` or
    `~/Downloads`.** macOS TCC blocks it, and the failure appears as a hang with a
    running pid. Keep the binary and config elsewhere.
11. **The dashboard UI itself was not driven in a browser here.** Its HTTP surface
    (redirect, HTML, JS bundle) was verified over HTTP, but no browser session was
    automated, so "a human can click through it" is inferred rather than tested.
12. **`run-headless.sh` is a convenience wrapper, not a supervisor.** It does not
    restart the core on crash; use launchd for that.

## Upstream sync

One branch now, so one sync policy:

```sh
git fetch upstream
git switch testing
git log --oneline HEAD..upstream/testing
git diff HEAD...upstream/testing
git rebase upstream/testing        # or: git merge upstream/testing
```

Never reset or force-push. After every sync, re-run the full verification set
above, and in particular re-check:

- the three registries are still mutually exclusive;
- `with_gvisor` is still what gates the Darwin TUN files in `sing-tun`;
- `local` is still a DNS boot dependency;
- the `sing` replace still applies and the client build still compiles.
