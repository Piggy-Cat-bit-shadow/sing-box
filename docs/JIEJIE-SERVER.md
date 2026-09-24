# Jiejie Server Edition

This fork is a long-lived, deliberately small customisation of sing-box for one
specific production server. It is **not** an architectural fork. Every feature
is optional, off by default, individually testable, and confined to a handful of
files so that rebasing onto upstream stays cheap.

Priority order when trade-offs conflict:

> reliability > protocol correctness > upstream maintainability > measured
> performance > resource control > probe resistance > binary size > log tidiness

Performance work never overrides protocol correctness.

## 1. Production topology this fork targets

This fork exists to serve this topology and nothing else. It does not replace
any part of it.

```
Public TCP/443  -> Nginx Stream -> SNI routing
                                    |
                                    +-> 127.0.0.1:28436  sing-box AnyTLS (TLS)
                                    |     +- valid AnyTLS        -> proxy
                                    |     +- non-AnyTLS / bad pw -> native fallback
                                    |                                127.0.0.1:28437
                                    +-> 127.0.0.1:28440  sing-box HTTP version=2
                                          +- CONNECT / CONNECT-UDP (authenticated)
                                          +- otherwise -> masquerade -> 127.0.0.1:28437

Public UDP/443  -> sing-box MASQUE HTTP version=3
                     +- CONNECT / CONNECT-UDP (authenticated)
                     +- otherwise -> masquerade -> 127.0.0.1:28437

127.0.0.1:28437 -> Nginx normal web (/var/www/api)
```

**Nginx remains the owner of TCP/443.** sing-box owns UDP/443 only. This fork
deliberately does **not** implement a native SNI front door, a TCP/443 SNI
dispatcher, or a replacement for Nginx Stream, and it does not resurrect the
retired `28435` + Nginx njs AnyTLS classifier. Nginx is not only a proxy front
end; it serves HTTPS, subscriptions and other web services on the same port.

sing-box never hosts the `28437` web server. It is reached over loopback as a
reverse-proxy target.

## 2. What this fork changes versus upstream

Only these areas are modified. Nothing else in sing-box behaves differently.

| Area | Files | Default when unconfigured |
| --- | --- | --- |
| HTTP inbound masquerade | `option/simple.go`, `transport/http/masquerade.go`, `transport/http/server_h2.go`, `protocol/http/inbound.go` | upstream behaviour |
| AnyTLS native fallback | `option/anytls.go`, `protocol/anytls/inbound.go` | upstream behaviour |
| HTTP/3 connection pool | `option/http3_pool.go`, `common/httpclient/http3_transport.go` | one transport |
| Server resource profile | `option/http_server_profile.go`, `transport/http/server.go` | upstream defaults |
| HTTP/3 BBR profile | `option/http_server_profile.go`, `transport/http/server_h3.go` | standard |
| Unauthenticated limits | `option/http_unauthenticated_limits.go`, `transport/http/unauthenticated_limiter.go` | no limiter |
| Log classification | `transport/http/h3_error_class.go`, `protocol/anytls/inbound.go` | quieter expected paths only |
| Build profile / CI | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`, `.github/workflows/` | unchanged default build |

See [FORK-DIFF.md](FORK-DIFF.md) for the patch manifest.

## 3. Features that are OFF by default

Every one of these is inert until you write it into a config. An unmodified
configuration behaves like upstream.

* `masquerade` — unset means upstream 401/407 challenges.
* AnyTLS `fallback` / `fallback_for_alpn` — unset means no fallback.
* `server_profile` — unset means upstream limits (including ~unlimited
  `MaxIncomingStreams` and the 1 MiB header cap).
* `max_header_bytes` — unset means the upstream 1 MiB.
* `bbr_profile` — unset means `standard`, i.e. exactly the previous behaviour.
* `unauthenticated_limits` — unset or `enabled: false` installs no limiter.

## 4. Recommended configuration for a 1 GiB VPS

### 4.1 MASQUE H3 inbound (UDP/443)

```json
{
  "type": "http",
  "tag": "masque-h3",
  "listen": "::",
  "listen_port": 443,
  "version": 3,
  "users": [{"username": "REPLACE_ME", "password": "REPLACE_ME"}],
  "tls": {
    "enabled": true,
    "server_name": "riri.zhuzhu.jiejie12131.top",
    "certificate_path": "/etc/sing-box/cert.pem",
    "key_path": "/etc/sing-box/key.pem"
  },
  "server_profile": "jiejie-balanced-1g",
  "masquerade": {
    "type": "proxy",
    "url": "http://127.0.0.1:28437",
    "rewrite_host": true
  },
  "unauthenticated_limits": {
    "enabled": true,
    "max_concurrent_per_ip": 8,
    "requests_per_second": 10,
    "burst": 20,
    "idle_timeout": "10s",
    "max_tracked_ips": 4096
  }
}
```

### 4.2 MASQUE H2 inbound (behind Nginx Stream on 28440)

```json
{
  "type": "http",
  "tag": "masque-h2",
  "listen": "127.0.0.1",
  "listen_port": 28440,
  "version": 2,
  "users": [{"username": "REPLACE_ME", "password": "REPLACE_ME"}],
  "tls": {
    "enabled": true,
    "server_name": "riri.zhuzhu.jiejie12131.top",
    "certificate_path": "/etc/sing-box/cert.pem",
    "key_path": "/etc/sing-box/key.pem"
  },
  "masquerade": {
    "type": "proxy",
    "url": "http://127.0.0.1:28437",
    "rewrite_host": true
  },
  "unauthenticated_limits": {
    "enabled": true,
    "max_concurrent_per_ip": 8,
    "requests_per_second": 10,
    "burst": 20,
    "idle_timeout": "10s"
  }
}
```

`server_profile` is intentionally not applied to the loopback H2 listener: the
resource pressure this profile addresses comes from the publicly reachable
UDP/443 socket, and the H2 path is already behind Nginx.

### 4.3 AnyTLS inbound (behind Nginx Stream on 28436)

```json
{
  "type": "anytls",
  "tag": "anytls",
  "listen": "127.0.0.1",
  "listen_port": 28436,
  "users": [{"name": "REPLACE_ME", "password": "REPLACE_ME"}],
  "tls": {
    "enabled": true,
    "server_name": "api.zhuzhu.jiejie12131.top",
    "certificate_path": "/etc/sing-box/cert.pem",
    "key_path": "/etc/sing-box/key.pem"
  },
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 28437
  }
}
```

## 5. `server_profile` and `max_header_bytes`

`server_profile` supplies **defaults only**. Any field you set explicitly always
wins, and an unset profile changes nothing.

```json
{
  "server_profile": "jiejie-balanced-1g",
  "max_header_bytes": 65536
}
```

`jiejie-balanced-1g` expands to:

| Field | Value |
| --- | --- |
| `max_header_bytes` | 64 KiB |
| `max_concurrent_streams` | 256 |
| `idle_timeout` | 60s |

`max_header_bytes` can also be set directly, with or without a profile.

### `max_concurrent_streams` and the baseline that matters

Upstream never sets `MaxIncomingStreams` to a bounded value; this fork does
**not** change that default. Only selecting a profile tightens it.

The baseline is worth stating precisely, because comparing against the wrong one
gives the wrong answer. Measured against the pinned
quic-go v0.61.0-sing-box-mod.7:

| Baseline | `MaxIncomingStreams` |
| --- | --- |
| quic-go raw zero-value default (`internal/protocol/params.go`) | 100 |
| Effective MASQUE H3 baseline (`transport/http/server_h3.go` replaces a zero with `1<<60`) | effectively unlimited |
| `jiejie-balanced-1g` | 256 |

So against quic-go's raw default the profile looks like a 2.5× increase, but
against the baseline that actually ships — the MASQUE HTTP/3 listener, which
must not cap concurrent CONNECT streams at 100 — the profile **lowers** the
limit from effectively unlimited to a bounded 256. That is the intended
direction, and `TestJiejieProfileStreamLimitIsConservativeForTheMASQUEPath`
asserts it while recording the raw default so neither reading is hidden.

### What the profile deliberately does NOT set

The profile sets no receive window and no keep-alive, and this is a correction
rather than an omission. Measured against quic-go v0.61.0-sing-box-mod.7
(`internal/protocol/params.go`):

| QUIC parameter | quic-go default |
| --- | --- |
| `InitialStreamReceiveWindow` | 2 MiB |
| `MaxStreamReceiveWindow` | 6 MiB |
| `InitialConnectionReceiveWindow` | 10 MiB |
| `MaxConnectionReceiveWindow` | 15 MiB |
| `KeepAlivePeriod` | 0 (disabled) |

`common/httpclient.NewQUICConfig` assigns a configured `stream_receive_window` to
**both** the initial and the maximum window. An earlier revision of this profile
set 4 MiB and 16 MiB, which therefore *raised* the initial windows above the
library defaults (2 MiB → 4 MiB and 10 MiB → 16 MiB) and added a 30s keep-alive
that actively pings idle connections. That is the opposite of a
memory-conservative profile on a 1 GiB host, and it was never measured. It has
been removed.

The option schema cannot currently express initial and maximum windows
separately, so lowering a maximum would unavoidably raise an initial. The honest
choice is to leave both alone. If you want to tune them, set them explicitly and
measure — an explicit value always wins over the profile.

Treat the profile as bounding **stream count, header size and idle lifetime**,
which are the parts that are unambiguously binding. Do not read it as a total
memory bound: see the note in section 12 about connection-level admission.

## 6. `bbr_profile`

The dependency `github.com/sagernet/sing-quic/congestion_meta2` really does
export three profiles, so all three are exposed. Nothing is invented.

| Value | Notes |
| --- | --- |
| `conservative` | `ProfileConservative` |
| `standard` | `ProfileStandard` — the default, and the previous hardcoded value |
| `aggressive` | `ProfileAggressive` |

Unset means `standard`, byte for byte the old behaviour. Unknown names are
rejected at config load. A test asserts this enum matches the profiles the
dependency actually defines, so it cannot silently drift.

Changing this profile is **unmeasured** on this server. Treat it as an A/B
experiment (see [JIEJIE-BENCHMARK.md](JIEJIE-BENCHMARK.md)); do not assume
`aggressive` is faster.

## 7. `unauthenticated_limits`

Bounds what an unauthenticated peer can consume on a publicly exposed inbound.

| Field | Type | Default when enabled |
| --- | --- | --- |
| `enabled` | bool | `false` |
| `max_concurrent_per_ip` | int | `8` |
| `requests_per_second` | number | `10` |
| `burst` | int | `20` |
| `idle_timeout` | duration | `10s` |
| `max_tracked_ips` | int | `4096` |

How it behaves:

* Keyed on the **source IP only**. The port is dropped, so one host cannot
  multiply its budget by opening many connections. IPv4-mapped IPv6 is unmapped,
  so `::ffff:1.2.3.4` and `1.2.3.4` share one budget.
* Applies **only** to unauthenticated traffic. Authenticated CONNECT,
  extended CONNECT, CONNECT-UDP, datagram and routed traffic is never limited.
* **A request is never refused merely for exceeding the budget.** The limiter is
  an accounting pre-filter; a request is rejected only when it *both* fails
  authentication *and* has exceeded the budget. This is what distinguishes an
  abusive peer from a legitimate client that simply reconnects frequently.
* Idle entries expire after `idle_timeout`; an entry with an in-flight request is
  never expired or evicted, so a peer cannot reset its own budget by waiting.
* `max_tracked_ips` bounds the map itself, defeating a flood from random source
  addresses. When full, the least recently seen idle entries are evicted.
* Standard library only (`netip`, `sync`). No new dependency.

### What an over-limit request receives

An over-limit request is answered by a **locally generated decoy**, not by the
masquerade handler:

* status `429`, `Content-Type: text/html`, `Retry-After`, and a small static body;
* no `401`, no `407`, no `WWW-Authenticate`, no `Proxy-Authenticate`;
* **no request to the masquerade backend.**

The backend point is the reason this changed. Serving the proxy masquerade
over-limit meant that every over-limit probe still issued one real HTTP request to
the configured backend, so an attacker kept driving backend load no matter how far
over budget it went. That is not a resource bound despite the name.
`TestUnauthenticatedLimiterDoesNotHitMasqueradeBackend` counts real backend hits
and requires them to stay at 1 once the budget is exhausted.

The decoy is deliberately **not** a cached copy of the backend page: caching would
require fetching it, and a stale or per-user page would be a worse disguise than a
generic server response.

### What the limiter does and does not hide

It hides that the endpoint is a **proxy**: no auth challenge, no proxy-specific
headers, and an over-limit response that looks like an ordinary rate-limited web
server.

It does **not** claim path-level indistinguishability, and an earlier revision of
this document overstated it. The decoy answers every over-limit request with the
same body and does not forward the request path, so a prober that compares
responses to different paths can tell them apart. Anything that forwarded the path
would have to reach the backend, which is exactly what the limiter exists to
avoid. The trade is deliberate: bound the backend, keep the proxy signal out, and
do not promise more than that.

## 8. Log behaviour

* **Masquerade auth failure** (masquerade configured, client served a normal
  page): `DEBUG`. Previously this logged `ERROR authentication failed` even
  though the client received `200`.
* **Real 401/407** (no masquerade configured): still `ERROR`.
* **AnyTLS native fallback** (the normal path for a non-AnyTLS client):
  `DEBUG`. Previously `INFO`, which produced a steady stream under public
  scanning.
* **AnyTLS TLS handshake failure, routing error, backend failure**: still
  `ERROR`.
* **Expected HTTP/3 closures** — `H3_NO_ERROR`, request cancelled/rejected/
  incomplete, version fallback, idle timeout, handshake timeout, context
  cancellation, orderly `net.ErrClosed`: not reported as errors.
* **Everything else** — protocol violations, frame/settings/stream errors, QPACK
  failures, datagram errors, internal errors: still `ERROR`.

Classification uses only `errors.Is`, `errors.As` and real quic-go error codes.
**No string matching is used anywhere.**

## 9. Deterministic resource bounds instead of a fake `memory_budget`

**Scope of these bounds, stated precisely.** They bound stream count, header
size, idle lifetime, receive windows and rate. They do **not** bound the number of
QUIC connections. `max_concurrent_streams` limits streams within a connection and
the unauthenticated limiter counts HTTP requests, so neither stops a peer from
opening many QUIC connections that complete a handshake and never send a request.
There is currently no connection-count or per-source connection cap.

Adding one would mean hooking quic-go's connection acceptance, which is a
structural change to a pinned dependency, so it is deliberately not implemented.
If connection-count admission is added later this section must be updated; until
then, treat the profile as bounding streams and memory *per connection*, not the
number of connections.

An earlier plan proposed a `memory_budget` option. It is **not implemented**.

A byte-accurate budget cannot be built honestly on top of the current
quic-go / sing-quic connection and stream lifecycle: there is no supported way
to measure the real allocation attributable to a QUIC connection or stream, so
any such option would report a number that does not correspond to reality.
Shipping it would be worse than shipping nothing.

Instead this profile uses **deterministic, inspectable bounds**:

| Control | Bound it establishes |
| --- | --- |
| `max_concurrent_streams` | streams per connection |
| `stream_receive_window` | buffer per stream |
| `connection_receive_window` | buffer per connection |
| `max_header_bytes` | per-request header allocation |
| `idle_timeout` | how long idle state is retained |
| `unauthenticated_limits.max_concurrent_per_ip` | in-flight unauthenticated work per source |
| `unauthenticated_limits.max_tracked_ips` | limiter memory ceiling |

These are predictable, testable and independent of allocator behaviour. Use them
and observe real RSS; do not trust a synthetic budget number.

## 10. How to restore upstream behaviour

Delete the fork's optional keys from your config. Specifically:

* remove `masquerade`
* remove AnyTLS `fallback` and `fallback_for_alpn`
* remove `server_profile`,
  `max_header_bytes`, `bbr_profile`, `unauthenticated_limits`

With all of them absent the binary behaves like upstream sing-box for every one
of these code paths. You can also just use the
`sing-box-linux-amd64-full` artifact, which is built with upstream's default
tags, and simply not write the new keys.

## 11. Build profiles

| File | Purpose |
| --- | --- |
| `release/DEFAULT_BUILD_TAGS_OTHERS` | upstream default tags — untouched |
| `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` |
| `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` |

The Jiejie set drops optional components the server does not use:

`with_gvisor`, `with_dhcp`, `with_wireguard`, `with_tailscale`, `with_ccm`,
`with_ocm`, `with_cloudflared`, `with_usbip`, `with_openvpn`,
`with_openconnect`, `with_clash_api`, `with_naive_outbound`.

Tag audit — what is actually true:

* Those tags only gate optional `include/*.go` registrations.
* **`with_quic` is required** and is kept: it enables `transport/http/server_h3.go`.
* `with_utls` is kept deliberately, because it is the uTLS/REALITY client path
  and is cheap to retain for client-side testing.
* **ShadowTLS does not need `with_utls`.** `protocol/shadowtls` builds
  unconditionally and no ShadowTLS file references uTLS.
* AnyTLS, MASQUE/HTTP, Shadowsocks (incl. 2022), ShadowTLS v3, TUIC, Hysteria2,
  VLESS, VMess, Trojan, Naive, Snell, SOCKS, Mixed and Direct are **all
  compiled unconditionally** — none is behind a build tag.
* DNS, TLS and the core local services are unconditional.
* `with_acme` is retained even though this server's certificates come from
  Nginx; it is small and removing it would break `sing-box` TLS issuance if the
  binary is ever reused elsewhere.
* **No protocol source file is deleted.** The size reduction comes purely from
  not registering optional components.

### The `jiejie_server_minimal` build

A third, more aggressive profile for this one server. It trims at the
**protocol registration level** rather than at the optional-component level: the
default `include/registry.go` registers roughly twenty protocols, and the minimal
registry registers only what the production config actually references.

No upstream source is edited or deleted. Packages the registry does not import
never enter the import graph, so the Go linker removes them.

| Registry | Default build | `jiejie_server_minimal` |
| --- | --- | --- |
| Inbounds | tun, redirect/tproxy, direct, socks, http, mixed, shadowsocks, snell, vmess, trojan, naive, shadowtls, vless, anytls, hysteria, tuic, hysteria2, cloudflared, tailscale | **http, anytls, naive, shadowtls, shadowsocks** |
| Outbounds | direct, bridge, block, selector, urltest, socks, http, shadowsocks, snell, vmess, trojan, naive, tor, ssh, shadowtls, vless, anytls, hysteria, tuic, hysteria2, tailscale | **direct, socks** |
| Endpoints | WireGuard, OpenConnect, OpenVPN, MASQUE, Tailscale | none |
| DNS transports | tcp, udp, tls, https, hosts, local, mdns, fakeip, quic, http3, resolved, dhcp, tailscale, openconnect, openvpn | **udp, local** |
| Services | api, resolved, ssmapi, hysteria realm, derp, ccm, ocm, oom killer, usbip | none |
| Cert providers | ACME, Tailscale, Cloudflare Origin CA | none |

Every entry in the minimal column exists because the production configuration
uses it. Nothing is registered for test convenience: the integration tests drive
real protocol clients, and the client-side fork features run against the full
build instead.

Three of these deserve an explicit justification, because the obvious answer is
wrong in each case:

* **`socks` appears only as an outbound.** It is the residential SOCKS5 upstream.
  The `socks` inbound is deliberately absent; it previously existed only so tests
  could use an in-process client, which let the test harness dictate the
  production binary.
* **`local` DNS appears even though only `local-agh` (UDP) is configured.** It is
  not a feature choice: `box.go` unconditionally initialises the DNS transport
  manager with a fallback that constructs a `local` transport, so omitting it
  makes every start fail with
  `default DNS server fallback: transport type not found: local`. This was found
  by running the build, not by reading the config.
* **`block` is absent and that is safe.** A route `reject` action returns a
  `RejectedError` from `route/rule/rule_action.go` and never resolves an outbound,
  so reject rules work without it. Verified in source.

The `tcp` DNS transport is absent and is not needed for truncation fallback:
`dns/transport/udp.go` `Exchange()` inspects `response.Truncated` and calls its
own `exchangeTCP()`, which dials TCP through the same dialer and never consults
the transport registry. Covered by `TestJiejieMinimalDNSTruncatedTCPFallback`.

MASQUE HTTP/3 is unaffected by the QUIC trim: `transport/http/server_h3.go` is
compiled by `with_quic` itself and needs no protocol registration. The server
keeps HTTP/2, HTTP/3, QUIC, CONNECT, CONNECT-UDP, UoT, standard TLS, DNS
(`direct.domain_resolver` and the local AGH setup), IPv4/IPv6, route/rules, the
AnyTLS fallback, the HTTP masquerade and every Jiejie Server Edition feature that
runs server-side.

Excluded types are **not** registered as stubs. An earlier revision imported
`protocol/naive` and `transport/v2ray` purely to return a friendlier error, which
pulled the very packages the trim exists to remove back into the import graph. A
config that references a removed type now fails at `sing-box check` with
`unknown inbound type` (or the equivalent). The one safety net that needs no
import already exists upstream: `transport/v2ray.NewQUICServer` returns
`os.ErrInvalid` when no constructor is registered.

Measured artifact sizes (Linux amd64, `-trimpath`, `-ldflags "-s -w"`, no UPX,
no external strip):

| Artifact | Size |
| --- | --- |
| `sing-box-linux-amd64` (the only published binary) | ~32.2 MiB |

Exact byte counts and the SHA256 are printed by CI; read them from the run output
rather than from this table. The full and plain Jiejie tag sets still exist in the
repository and can be built by hand for debugging, but CI no longer publishes
them.

#### Why the uTLS library and `badlinkname` are still present

Both were investigated rather than assumed:

* **The `with_utls` tag IS removed from the minimal build; the uTLS library is
  not.** These are two different things and an earlier revision of this document
  conflated them. The minimal tag set is
  `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` — it does
  not contain `with_utls`, so sing-box's own uTLS feature wrapper
  (`common/tls/utls_client.go`, `reality_client.go`, `reality_server.go`) is not
  compiled and the config option `tls.utls.enabled` is unavailable.
  What remains is the library: `quic-go` imports `github.com/metacubex/utls`
  unconditionally from `internal/handshake/tls_conn_utls.go`, with no build tag
  of its own, and `with_quic` is mandatory for MASQUE HTTP/3. The minimal binary
  therefore still contains uTLS symbols. Removing those would require forking
  quic-go, which this fork does not do.
* **`badlinkname` is kept.** It costs about 131 KiB in the minimal build and
  enables kTLS (`common/ktls`, 106 symbols) plus the `badtls` read-wait path that
  `common/tls` uses on every connection. Paying 131 KiB to avoid risking a
  production TLS path is the right trade, and `tfogo_checklinkname0` is its
  companion check tag.
* **`with_acme` was dropped** from the minimal profile: certificates are
  provisioned by acme.sh outside sing-box.

#### Dependencies that remain, and why

Audited against the **Linux** analysis build, because the symbol set differs by
platform and an audit run on macOS gives misleading answers. Measured on
linux/amd64 under the minimal tag set:

| Dependency | Symbols | Why it cannot be removed |
| --- | --- | --- |
| `github.com/metacubex/utls` | ~1304 | `quic-go` imports it unconditionally from `internal/handshake/tls_conn_utls.go`, with no build tag of its own. Removing it means forking quic-go. |
| `github.com/godbus/dbus` | ~577 | Arrives through `common/settings`, which `common/listener` and `route` both import. It is Linux-only, so it does not appear in a macOS analysis build at all — which is exactly how an earlier audit missed it and CI caught it. |
| `github.com/sagernet/sing-box/service/powerreport` | ~118 | Imported directly by `common/dialer` for traffic attribution. |
| `github.com/sagernet/sing-box/service/oomkiller` | 0–41 | Also referenced by `common/dialer`, but the linker drops it on some platforms; the count varies, so it is reported rather than asserted. |
| `github.com/mattn/go-runewidth` | ~38 | Pulled in by the `cmd/sing-box` CLI for terminal table formatting. Not on the proxy data path. |
| `github.com/sagernet/sing-box/protocol/tailscale` | exactly 3 | The `generate tailcat` CLI subcommand. |

That last one was tested for removal. Gating `generate tailcat` behind
`jiejie_server_minimal` does remove the package, but it saved only **4,096 bytes**
because the linker had already dead-code-eliminated the unused functions and only
package metadata remained. Four kilobytes does not justify the extra
build-constrained file, so the change was reverted under this fork's stopping
rule.

Everything else that was targeted is confirmed absent from the Linux build:
hysteria, hysteria2, tuic, vless, vmess, trojan, tor, ssh, snell, bridge, mixed,
redirect, tun, the MASQUE endpoint, naive, the QUIC DNS transport, resolved,
origin_ca, ssmapi, api, and certmagic.

#### Where the remaining size goes

The binary is now dominated by Go runtime metadata rather than by any single
removable dependency: `pclntab`, type information and string tables account for
most of the file. The largest identifiable non-runtime item is
`github.com/mattn/go-runewidth`, pulled in by the `cmd/sing-box` CLI for terminal
output formatting — not part of the proxy data path, and not removable without
editing upstream CLI code.

Further reduction would mean changing upstream code or excluding the CLI, both of
which conflict with the rule that this fork stays rebaseable. The remaining
trim is therefore considered exhausted for this design.

Measured on the development machine: full ≈ 108 MB, Jiejie ≈ 58 MB, and the
Jiejie build passes `sing-box check` against a secret-free fixture of the real
production topology.

### The single production artifact

CI publishes **exactly one** binary, and it is built from
`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`:

```
sing-box-linux-amd64
sing-box-linux-amd64.sha256
```

That is the only artifact the workflow uploads. `full`, the plain Jiejie build,
the `GOAMD64=v3` build and the `CGO_ENABLED=0` build are no longer produced by
the default workflow. Their tag files and source-level build capability remain in
the repository, so they can still be built by hand for debugging:

```sh
TAGS=$(cat release/DEFAULT_BUILD_TAGS_OTHERS)
go build -trimpath -tags "$TAGS" -o sing-box-debug ./cmd/sing-box
```

They are compatibility and debugging capabilities, not parallel releases.

The only build-time variations that were formerly published and are worth
knowing about if you ever build manually:

* `GOAMD64=v3` requires the host CPU to satisfy Go's amd64 v3 requirements
  (AVX2); check with `lscpu`. A v3 binary will crash with an illegal instruction
  on an unsupported CPU, and the VPS host CPU can change under you.
* `CGO_ENABLED=0` produces a static binary. The production artifact keeps CGO
  enabled, which is the normal Go behaviour for this target.

### Binary size guard

Because the minimal build is now the product, CI enforces a raw ELF size ceiling
of **38,000,000 bytes** (`MAX_BINARY_BYTES` in the workflow). A build over that
limit fails with `production binary size regression`, which almost always means a
protocol or service that should have been pruned has found its way back into the
registry. As of `1.15.0-jiejie-masquerade.5` the raw ELF is **33,775,908 bytes**
(32.2 MiB), up **16,384 bytes (+0.049%)** from `1.15.0-jiejie-masquerade.4` on the
same toolchain, leaving about 4.03 MiB of headroom for normal Go and dependency
growth. The guard measures the raw binary, never the artifact archive size.

## 12. Rebasing onto upstream

```sh
git fetch upstream
git switch testing
git rebase upstream/testing        # or: git merge upstream/testing
```

Then run the server workflow and re-verify manually:

1. `sing-box check` on a production-shaped config.
2. Authenticated CONNECT and CONNECT-UDP over both H2 and H3.
3. Masquerade for unauthenticated and wrong-password probes on both H2 and H3.
4. AnyTLS fallback reaches the Nginx web backend; valid AnyTLS still proxies.
5. `transport/http` and `common/httpclient` unit tests, including the
   `net.ErrClosed` regression guard in `h3_error_class_test.go`.

Conflict surface is intentionally small and concentrated in:
`option/http.go`, `option/simple.go`, `common/httpclient/http3_transport.go`,
`transport/http/server.go`, `transport/http/server_h2.go`,
`transport/http/server_h3.go`, `protocol/http/inbound.go`,
`protocol/anytls/inbound.go`, plus the matching tests.

Never force-push `testing`. Never reset `testing` to `upstream/testing`.

The two most likely conflict points after an upstream rebase:

* `transport/http/server.go` / `server_h2.go` — upstream owns the header
  limit constant and the auth-failure branch. Re-apply the `maxHeaderBytes`
  field and the `serveAuthFailure` split if upstream rewrites those lines.

## 13. What is experimental

Treat these as unproven on this server until you measure them:

* `bbr_profile` values other than `standard`.
* `GOAMD64=v3` and `CGO_ENABLED=0` artifacts.
* Any non-default `stream_receive_window` / `connection_receive_window`.

## 14. Source capability vs the published artifact

The fork's **source** and the **published artifact** are not the same thing, and
conflating them is misleading.

| Capability | In the fork's source | In `sing-box-linux-amd64` |
| --- | --- | --- |
| `http` / `anytls` / `shadowtls` / `shadowsocks` inbounds | yes | yes |
| `direct` / `socks` outbounds | yes | yes |
| UDP DNS | yes | yes |
| Hysteria, TUIC, VLESS, VMess, Trojan, naive, tor, ssh, snell, mixed, tun, … | yes | **no** |

`sing-box-linux-amd64` is built from
`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`, which registers only the inbound
types the production topology uses and only the `direct` and `socks` outbounds.
It is a **server**, and it is the only product this fork ships.

Client-side equivalents (an `http` outbound, the HTTP/3 connection pool, the
configurable fallback schedule) are not part of this fork and are not published.
Use upstream sing-box for a client.

## 15. Unauthenticated traffic: what is bounded, and where the source IP comes from

### The H2 path behind Nginx sees Nginx, not the client

The production topology is:

```
public TCP/443 -> Nginx Stream -> 127.0.0.1:28440 -> sing-box HTTP/2
```

There is no PROXY protocol on that hop, so the source address sing-box observes for
HTTP/2 is **127.0.0.1** — the Nginx process — not the public client. Any per-IP
policy on the H2 inbound therefore applies to a single address, which makes it a
**global budget for that listener** rather than a per-client one.

The H3 path is different:

```
public UDP/443 -> sing-box HTTP/3
```

sing-box accepts those QUIC connections directly, so per-source-IP limits there
are genuinely per client.

Consequences to be aware of:

* On H3, `unauthenticated_limits` is per real client IP, as intended.
* On H2, `max_concurrent_per_ip` and `requests_per_second` collapse into one
  shared budget for everything arriving through Nginx. That is still a useful
  bound — it caps how much unauthenticated work the loopback listener can
  generate — but it is not per client.
* If you need real per-client IPs on the H2 path you must add PROXY protocol on
  the Nginx hop and enable it in sing-box. That is deliberately **not**
  implemented here; it would change the listener and the config schema.

The production fixture uses `unauthenticated_limits` on both listeners. Treat the
H2 entry as a loopback budget, not a per-client limit.

### The body bound

A failed-authentication request may reach the masquerade backend, so its request
body is capped at 256 KiB (`maxUnauthenticatedBodyBytes`). Without this a
failed-auth probe could stream an arbitrarily large body through the reverse
proxy. Over-limit requests never reach the backend at all and receive the local
decoy instead.

## 16. No unmeasured performance claims

This fork does **not** claim that any option makes the server faster. The
benchmarks in CI are regression references on shared runners, and loopback
numbers do not predict a real path. Whether `size: 2` helps, and by how much,
is to be determined by your own A/B on the VPS —
see [JIEJIE-BENCHMARK.md](JIEJIE-BENCHMARK.md).

## 17. Related documents

* [JIEJIE-PROBE-RESISTANCE-MATRIX.md](JIEJIE-PROBE-RESISTANCE-MATRIX.md) — what
  each public protocol does for an unauthenticated or wrongly authenticated
  probe, the resource bounds, and the honest list of what is still
  protocol-observable.
* [JIEJIE-NGINX-ALPN-HARDENING.md](JIEJIE-NGINX-ALPN-HARDENING.md) — the
  operator-side hardening of the Nginx Stream front door for the MASQUE H2 SNI.
  This is a production front-door change, not a sing-box change, and it is not
  applied by anything in this repository.
* [JIEJIE-FIELD-MATRIX.md](JIEJIE-FIELD-MATRIX.md) — per-field implementation
  status, including the items deliberately left NOT IMPLEMENTED.
* [FORK-DIFF.md](FORK-DIFF.md) — the patch manifest.
