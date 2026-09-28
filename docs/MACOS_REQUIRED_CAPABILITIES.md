# MACOS_REQUIRED_CAPABILITIES

Derived from the REAL production configuration on this machine, not from
assumptions about what a desktop client might use.

- Config: `/Users/jie/归类/singbox/我的🐷🐷（singbox版）.json`
- Binary: `/Users/jie/归类/singbox/sing-box`
- LaunchDaemon: `/Users/jie/归类/singbox/com.jiejie.singbox.plist`
  (`ProgramArguments` = `run -c /Users/jie/归类/singbox/我的🐷🐷（singbox版）.json`)
- Verified: `sing-box check` on that config exits 0 with the currently shipped binary.

No secrets, UUIDs, passwords or private domains are recorded here. Only
type/capability, which is what the registry decisions depend on.

## Inbounds

| type | tag | notes |
|---|---|---|
| `tun` | `tun-in` | keys: address, auto_route, platform, udp_timeout |
| `mixed` | `mixed-in` | keys: listen, listen_port |

Only two. `mixed` provides HTTP and SOCKS on one port, so the standalone `socks`
and `http` INBOUND registrations are NOT required by this config. `direct` as an
inbound is not used.

## Outbounds

| type | tag | notes |
|---|---|---|
| `direct` | `direct` | |
| `vless` | 🇺🇸 美国｜Vless Reality Vision | Reality |
| `anytls` | 🇺🇸 美国｜AnyTLS | |
| `naive` | 🇺🇸 美国｜NaiveProxy | Cronet implementation |
| `shadowsocks` | 🇺🇸 美国｜SS2022 ShadowTLS | 2022 |
| `shadowtls` | `shadowtls-ss2022-out` | detours to the shadowsocks outbound |
| `http` | 🇺🇸 美国｜MASQUE | the MASQUE client outbound |
| `vless` | 🇺🇸 美国｜住宅 Vless Reality Vision | Reality |
| `anytls` | 🇺🇸 美国｜住宅 AnyTLS | |
| `selector` | 🌍 国外流量 | members: Vless, AnyTLS, Naive, SS2022, MASQUE |
| `selector` | 🤖 AI | members: residential AnyTLS, residential Vless, Naive |

**Not present**: `urltest`, `hysteria2`, `tuic`, `trojan`, `vmess`, `snell`,
`socks`, `block`, `wireguard`, `ssh`, `tor`, `tailscale`, `openvpn`.

`block`/`reject` is exercised through the route rule action `reject`, not as an
outbound. `block` remains registered because it is a trivial built-in and the
route action resolves through it.

## DNS

| piece | value |
|---|---|
| servers | `hosts`, `https` (cn-doh), `fakeip` |
| rules | `predefined`, `route` to hosts / cn-doh / fakeip |
| keys | servers, rules, final, cache_capacity, strategy |

So the required DNS transports are `hosts`, `https` and `fakeip`.

`local` does NOT appear as an explicit server, but it MUST stay registered: it is
the startup/bootstrap fallback the router uses when no transport is otherwise
resolvable. Removing it breaks DNS bootstrap even though the config never names
it. This is exactly the "not named != unused" trap.

## Services

| type | tag |
|---|---|
| `api` | `api` |

Exactly one. The Native API is the only management service.

## Route

| piece | value |
|---|---|
| actions used | `reject`, `route`, `sniff` |
| final | 🌍 国外流量 (a selector) |
| auto_detect_interface | true |
| default_http_client | set |
| rule_set count | 1 |

## Experimental

Only `cache_file`. **No `clash_api`** — the production config does not use it, so
removing the feature cannot break this deployment.

## http_clients

One entry, used as the rule-set fetch proxy.

## Allowlist decisions

KEEP (proven by the config above):
`direct`, `vless`, `anytls`, `naive`, `shadowsocks`, `shadowtls`, `http`
(MASQUE client), `selector`, `block`, `tun`, `mixed`.

KEEP as infrastructure:
`api` service, DNS `hosts`/`https`/`fakeip`/`local`, route, rule_set, urltest
(the `urltest` OUTBOUND is absent from the config, but the selector UI's delay
test resolves through the URLTest gRPC method, so the type stays registered).

REMOVE from the macOS registry (unused here):
`hysteria2`, `tuic`, `trojan`, `vmess`, `snell`, `socks` outbound, `http`
outbound-as-proxy is kept for MASQUE, standalone `socks`/`http`/`direct` inbounds.

REMOVE entirely from the fork (not macOS-specific):
`experimental/clashapi`, `lxd`, `with_clash_api`, `with_lxd`, `with_lx_command`,
and the launcher RPC surface.
