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
| HTTP/3 fallback backoff | `option/http3_fallback.go`, `common/httpclient/http3_transport.go` | upstream 5m/x2/48h |
| HTTP/3 connection pool | `option/http3_pool.go`, `common/httpclient/http3_transport.go` | one transport |
| Server resource profile | `option/http_server_profile.go`, `transport/http/server.go` | upstream defaults |
| HTTP/3 BBR profile | `option/http_server_profile.go`, `transport/http/server_h3.go` | standard |
| Unauthenticated limits | `option/http_unauthenticated_limits.go`, `transport/http/unauthenticated_limiter.go` | no limiter |
| Log classification | `transport/http/h3_error_class.go`, `protocol/anytls/inbound.go` | quieter expected paths only |
| Build profiles / CI | `release/BUILD_TAGS_JIEJIE_SERVER`, `.github/workflows/` | unchanged default build |

See [FORK-DIFF.md](FORK-DIFF.md) for the patch manifest.

## 3. Features that are OFF by default

Every one of these is inert until you write it into a config. An unmodified
configuration behaves like upstream.

* `masquerade` — unset means upstream 401/407 challenges.
* AnyTLS `fallback` / `fallback_for_alpn` — unset means no fallback.
* `http3_fallback` — unset means the upstream 5m/x2/48h schedule.
* `http3_connection_pool` — unset or `size: 1` means a single transport.
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

## 5. MASQUE client recommended configuration

```json
{
  "type": "http",
  "tag": "masque-out",
  "server": "riri.zhuzhu.jiejie12131.top",
  "server_port": 443,
  "version": 3,
  "username": "REPLACE_ME",
  "password": "REPLACE_ME",
  "tls": {
    "enabled": true,
    "server_name": "riri.zhuzhu.jiejie12131.top"
  },
  "http3_connection_pool": {
    "size": 2,
    "strategy": "round_robin"
  },
  "http3_fallback": {
    "initial_backoff": "5s",
    "max_backoff": "5m",
    "multiplier": 2,
    "reset_on_success": true
  }
}
```

## 6. `http3_fallback`

Controls how long a client stays on an earlier HTTP version after an HTTP/3
failure, per request authority.

| Field | Type | Default (upstream) |
| --- | --- | --- |
| `initial_backoff` | duration | `5m` |
| `max_backoff` | duration | `48h` |
| `multiplier` | number | `2` |
| `reset_on_success` | bool | `true` |

* Absent object reproduces the upstream schedule exactly.
* `reset_on_success` is a pointer internally, so omitting it defaults to `true`
  while an explicit `false` still works.
* A successful HTTP/3 round trip clears the authority's broken state
  immediately, so HTTP/3 becomes preferred again at once.
* State stays keyed by authority; expired entries are evicted on read.
* The recommended values above give 5s, 10s, 20s, 40s, 80s, 160s, then a 5m
  ceiling — a transient UDP loss no longer parks a client on HTTP/2 for hours.
* If `max_backoff` is below `initial_backoff` it is clamped up.

H2 fallback behaviour is unchanged.

## 7. `http3_connection_pool`

| Field | Type | Default |
| --- | --- | --- |
| `size` | int, 1..8 | `1` |
| `strategy` | string | `round_robin` |

* `size: 1` (or an absent object) is exactly the upstream single-transport
  behaviour, including lazy connection setup.
* `size: 2` creates two fully independent `http3.Transport` instances, so
  concurrent requests use two separate QUIC connections rather than two streams
  on one connection.
* Sizes above 8 and unknown strategies are rejected at config load.
* **Start with `size: 2`.** Larger values are not recommended without your own
  measurements.

Replay safety (enforced in tests):

* A request whose body cannot be rewound (no `GetBody`) is always served by the
  same pool member and is never retried onto another connection, so a consumed
  body can never be replayed.
* Bodyless and rewindable requests rotate.
* Broken/fallback state is keyed by authority, not by pool member, so one dead
  connection cannot poison the pool.

## 8. `server_profile` and `max_header_bytes`

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
| `stream_receive_window` | 4 MiB |
| `connection_receive_window` | 16 MiB |
| `idle_timeout` | 60s |
| `keep_alive_period` | 30s |

`max_header_bytes` can also be set directly, with or without a profile.

Upstream never sets `MaxIncomingStreams` to a bounded value; this fork does
**not** change that default. Only selecting a profile tightens it.

## 9. `bbr_profile`

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

## 10. `unauthenticated_limits`

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

### Anti-fingerprinting

A rejected request is answered with the **masquerade handler** when one is
configured, otherwise a bare `429`. It never returns `401`/`407` and never emits
`WWW-Authenticate` or `Proxy-Authenticate`. The limiter must not itself reveal
that the endpoint is a proxy; tests assert this for both the masquerade and
non-masquerade cases.

Because a limited request still receives the decoy page, the limiter is
deliberately not visible to a prober. What it bounds is the rate at which such
requests are admitted.

## 11. Log behaviour

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

## 12. Deterministic resource bounds instead of a fake `memory_budget`

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

## 13. How to restore upstream behaviour

Delete the fork's optional keys from your config. Specifically:

* remove `masquerade`
* remove AnyTLS `fallback` and `fallback_for_alpn`
* remove `http3_fallback`, `http3_connection_pool`, `server_profile`,
  `max_header_bytes`, `bbr_profile`, `unauthenticated_limits`

With all of them absent the binary behaves like upstream sing-box for every one
of these code paths. You can also just use the
`sing-box-linux-amd64-full` artifact, which is built with upstream's default
tags, and simply not write the new keys.

## 14. Build profiles

| File | Purpose |
| --- | --- |
| `release/DEFAULT_BUILD_TAGS_OTHERS` | upstream default tags — untouched |
| `release/BUILD_TAGS_JIEJIE_SERVER` | `with_quic,with_utls,with_acme,badlinkname,tfogo_checklinkname0` |
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
| Inbounds | tun, redirect/tproxy, direct, socks, http, mixed, shadowsocks, snell, vmess, trojan, naive, shadowtls, vless, anytls, hysteria, tuic, hysteria2, cloudflared, tailscale | http, anytls, shadowtls, shadowsocks, socks, direct |
| Outbounds | direct, bridge, block, selector, urltest, socks, http, shadowsocks, snell, vmess, trojan, naive, tor, ssh, shadowtls, vless, anytls, hysteria, tuic, hysteria2, tailscale | direct, block, selector, urltest, socks, http, shadowsocks, shadowtls, anytls |
| Endpoints | WireGuard, OpenConnect, OpenVPN, MASQUE, Tailscale | none |
| DNS | tcp, udp, tls, https, hosts, local, mdns, fakeip, quic, http3, resolved, dhcp, tailscale, openconnect, openvpn | tcp, udp, tls, https, hosts, local, resolved, plus non-functional QUIC/HTTP3 stubs |
| Services | api, resolved, ssmapi, hysteria realm, derp, ccm, ocm, oom killer, usbip | resolved |
| Cert providers | ACME, Tailscale, Cloudflare Origin CA | none |

MASQUE HTTP/3 is unaffected by the QUIC trim: `transport/http/server_h3.go` is
compiled by `with_quic` itself and needs no protocol registration. The server
keeps HTTP/2, HTTP/3, QUIC, CONNECT, CONNECT-UDP, UoT, standard TLS, DNS
(`direct.domain_resolver` and the local AGH setup), IPv4/IPv6, route/rules, the
AnyTLS fallback, the HTTP masquerade and every Jiejie Server Edition feature.

Excluded protocol types are still registered as **stubs** that return a clear
error, so a config referencing them fails at `sing-box check` with a useful
message instead of an "unknown type" error.

Measured artifact sizes (Linux amd64, `-trimpath`, `-ldflags "-s -w"`, no UPX,
no external strip):

| Artifact | Size |
| --- | --- |
| `sing-box-linux-amd64-full` | ~74.7 MiB |
| `sing-box-linux-amd64-jiejie` | ~41.1 MiB |
| `sing-box-linux-amd64-jiejie-minimal` | ~33.0 MiB |

That is about 55.9% smaller than the full build and 19.8% smaller than the
Jiejie build. Exact byte counts and SHA256 values are printed by CI and should be
read from the run output rather than from this table.

#### Why uTLS and `badlinkname` are still present

Both were investigated rather than assumed:

* **uTLS cannot be removed.** `quic-go` imports `github.com/metacubex/utls`
  unconditionally from `internal/handshake/tls_conn_utls.go`, with no build tag,
  and `with_quic` is mandatory for MASQUE HTTP/3. Dropping `with_utls` changes
  the linked uTLS symbol count from 1307 to 1297 — it removes the sing-box uTLS
  client wrapper, not the library. Removing uTLS outright would require forking
  quic-go, which is out of scope by design.
* **`badlinkname` is kept.** It costs about 131 KiB in the minimal build and
  enables kTLS (`common/ktls`, 106 symbols) plus the `badtls` read-wait path that
  `common/tls` uses on every connection. Paying 131 KiB to avoid risking a
  production TLS path is the right trade, and `tfogo_checklinkname0` is its
  companion check tag.
* **`with_acme` was dropped** from the minimal profile: certificates are
  provisioned by acme.sh outside sing-box.

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

### Experimental artifacts

These are **not** the production default and are never deployed automatically.

* `sing-box-linux-amd64-jiejie-v3` — built with `GOAMD64=v3`. Only deploy this
  if the host CPU satisfies Go's amd64 v3 requirements; check with
  `lscpu`/`/proc/cpuinfo` for AVX2 and BMI2. Keep the generic artifact as the
  fallback, because the VPS host CPU can change.
* `sing-box-linux-amd64-jiejie-static` — built with `CGO_ENABLED=0`. Built only
  if it compiles; the CI step is non-fatal. The default production artifact
  keeps CGO enabled.

## 15. Rebasing onto upstream

```sh
git fetch upstream
git switch feat/jiejie-server-edition
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
* `common/httpclient/http3_transport.go` — upstream owns the broken-state map.
  Re-apply the schedule and the pool on top.

## 16. What is experimental

Treat these as unproven on this server until you measure them:

* `http3_connection_pool.size > 1` — correctness is tested; the throughput gain
  is not.
* `bbr_profile` values other than `standard`.
* `GOAMD64=v3` and `CGO_ENABLED=0` artifacts.
* Any non-default `stream_receive_window` / `connection_receive_window`.

## 17. No unmeasured performance claims

This fork does **not** claim that any option makes the server faster. The
benchmarks in CI are regression references on shared runners, and loopback
numbers do not predict a real path. Whether `size: 2` helps, and by how much,
is to be determined by your own A/B on the VPS —
see [JIEJIE-BENCHMARK.md](JIEJIE-BENCHMARK.md).
