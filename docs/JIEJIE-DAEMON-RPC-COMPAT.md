# JiejieBox daemon RPC compatibility

This document is the contract between this core's `daemon/` gRPC surface and the
JiejieBox / singbox-launcher client. It exists because the two drifted silently once
and the symptom was a proxy page that showed nothing.

## The failure this documents

Against the macOS client core in daemon mode, the launcher reported:

```text
无法读取代理列表
正在运行的守护进程内核不提供代理分组列表，因此这里无法列出或切换节点。
```

and in its log:

```text
cannot read the proxies of group "...": daemon GetGroups:
rpc error: code = Unimplemented desc = unknown method GetGroups
```

This was **not** a UI bug and **not** a broken daemon. The launcher's proxy list
worked exactly as designed; the core's descriptor did not declare the RPCs the list
depends on.

## Root cause

Two independent protobuf definitions were in play:

| Side | Source of its `.proto` |
| --- | --- |
| launcher | generated from `SagerNet/sing-box @ 94c41b50`, recorded in its `internal/daemonpb/SYNC_REV` |
| this core | `daemon/started_service.proto` in this repository |

`94c41b50` declares a block of `lx_command` RPCs. This fork's proto never had that
block, so the methods the launcher called were absent from the served descriptor. A
method absent from the descriptor is rejected by the **gRPC transport** with
`unknown method <Name>`; no handler is ever reached.

### `with_lxd` is not `with_lx_command`

The two build tags are deliberately separate, and conflating them is what made the
omission easy to ship:

| Tag | Gates |
| --- | --- |
| `with_lxd` | the `sing-box lxd` daemon: the host process, its control channel, its service lifecycle |
| `with_lx_command` | the daemon **command RPCs** the launcher drives its proxy UI with |

The macOS profile had `with_lxd` and not `with_lx_command`, so it advertised a daemon
it could not answer `GetGroups` on. `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` now
carries both, and `scripts/ci/check-jiejie-daemon-rpc-contract.sh` fails if either is
removed.

## The three-way behaviour, as measured on a real binary

| Build | `GetGroups` result | What it means to a client |
| --- | --- | --- |
| method absent from the descriptor | `Unimplemented desc = unknown method GetGroups` | indistinguishable from a broken connection, a typo or a version skew |
| declared, no `with_lx_command` | `Unimplemented desc = GetGroups is not included in this build, rebuild with -tags with_lx_command` | a deterministic "this build lacks it", and it names the fix |
| declared + `with_lx_command` | the handler answers | the product works |

The middle row is why the RPCs are declared **unconditionally** while the handlers
are tag-gated. Every build serves the same descriptor, so the generated client is
identical everywhere and a missing tag produces a deterministic refusal rather than
an invisible method.

## Why `codes.Unimplemented` specifically

The launcher's capability probe (`core/daemon_rpc_compat.go`) classifies by gRPC
status:

- `Unimplemented` → the method is not in this build; the launcher degrades to its
  Clash HTTP fallback and reports `UnsupportedReason: "daemon_no_group_rpc"`.
- **any other status** (`InvalidArgument`, `FailedPrecondition`, `NotFound`) → the
  method **exists** and rejected this particular request.

So a stub returning `errors.New("not supported")` or `codes.Unknown` would be
misread as "the method exists", and the UI would offer a control the core cannot
honour. `Unimplemented` is the only correct code for a stub, and it is what
`started_service_command_lx_stub.go` returns.

## RPC matrix

| RPC | Handler | Build gate | Launcher uses |
| --- | --- | --- | --- |
| `GetGroups` | real | `with_lx_command` | yes — proxy list |
| `GetOutbounds` | real | `with_lx_command` | yes — node list |
| `URLTestOutbound` | real | `with_lx_command` | yes — single-node latency |
| `SelectOutbound` | real | always built | yes — node switching |
| `SubscribeGroups` | real | always built | yes — live push |
| `SubscribeOutbounds` | real | always built | yes — live push |
| `SubscribeConnections` | real | always built | yes |
| `GetVersion` | real | always built | yes |
| `GetRunningConfig` | `Unimplemented` | n/a | yes — **not ported** |
| `GetRules` | `Unimplemented` | n/a | yes — **not ported** |
| `GetPool` | `Unimplemented` | n/a | yes — **not ported** |
| `GetDNSGroups` | `Unimplemented` | n/a | yes — **not ported** |
| `SubscribeDNSQueries` | `Unimplemented` | n/a | yes — **not ported** |
| `GetURLViaOutbound` | `Unimplemented` | n/a | yes — **not ported** |
| `GetChains` | `Unimplemented` | n/a | yes — **not ported** |
| `SetChainPositionEnabled` | `Unimplemented` | n/a | yes — **not ported** |
| `GetChainCloneConfig` | `Unimplemented` | n/a | yes — **not ported** |
| `SetEndpointEnabled` | `Unimplemented` | n/a | yes — **not ported** |

"Not ported" is deliberate, not an oversight. Each back subsystem this fork does not
have: outbound chains, a rule provider, DNS server groups, endpoint lifecycle state.
Porting a real handler requires the corresponding adapter interface. A control the
core silently ignores is worse for the user than an honest refusal.

`GetRunningConfig` in particular is valuable and small-looking but is entangled with
the chain state this fork lacks; it is reported as NOT PORTED rather than
half-written.

## What keeps this from drifting again

| Guard | Catches |
| --- | --- |
| `scripts/ci/check-jiejie-daemon-rpc-contract.sh` | a method the launcher calls that this proto does not declare or the server does not register; a missing tag in the macOS profile; contamination of the Server Minimal profile |
| `TestJiejieDaemonRPCContract` | a method that is not reachable over a real gRPC connection |
| `TestJiejieDaemonRPCSurfaceIsComplete` | a renamed or moved method, at the descriptor level |
| `TestGetGroups*`, `TestURLTestOutbound*` | a handler that answers wrongly while still being registered |
| `scripts/ci/smoke-jiejie-daemon-rpc.sh` | a SHIPPED BINARY whose tags omit `with_lx_command` |

The unit tests cannot catch the original bug on their own: they compile against
*this* repo's proto, so they agree with it by definition. Only the guard, which
compares against the launcher's own generated method set, and the binary smoke test,
which inspects the artifact, can see drift.

## If you change the daemon RPC surface

1. Edit `daemon/started_service.proto`. Field numbers and method names are the wire
   ABI: never renumber, never rename.
2. Run `make proto` (needs `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`).
3. If you add a method the launcher calls, either implement it under
   `with_lx_command` or stub it with `codes.Unimplemented`.
4. Run `scripts/ci/check-jiejie-daemon-rpc-contract.sh`.
5. If it is on the proxy-UI critical path, confirm
   `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` enables the real implementation, and run
   `scripts/ci/smoke-jiejie-daemon-rpc.sh` against the built binary.
