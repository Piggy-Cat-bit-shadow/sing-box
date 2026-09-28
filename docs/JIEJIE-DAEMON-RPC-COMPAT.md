# Daemon RPC surface (launcher compatibility removed)

## Status: removed

This fork no longer implements, tests or maintains a launcher RPC contract. The
`singbox-launcher` / JiejieBox integration was removed, along with the LXD daemon
it was built on.

What was removed:

| Removed | What it was |
|---|---|
| `lxd/` | the LXD daemon package (82 files) |
| `cmd/sing-box/cmd_lxd_lx.go` | the `sing-box lxd` subcommand |
| `with_lxd` | the build tag gating the daemon |
| `with_lx_command` | the build tag gating the launcher command RPCs |
| `GetGroups`, `GetOutbounds`, `URLTestOutbound` | the pull-mode RPCs the launcher's proxy UI called |
| `GetRules`, `GetPool`, `GetDNSGroups`, `GetRunningConfig`, `GetURLViaOutbound`, `GetChains`, `SetChainPositionEnabled`, `GetChainCloneConfig`, `SetEndpointEnabled`, `SubscribeDNSQueries` | the rest of the launcher extension surface |
| `scripts/ci/check-jiejie-daemon-rpc-contract.sh`, `scripts/ci/smoke-jiejie-daemon-rpc.sh` | the CI guards for that contract |

The RPCs were deleted from `daemon/started_service.proto` and the generated code was
regenerated, rather than left declared-but-unimplemented. A method that exists in the
descriptor and always answers `codes.Unimplemented` is a compatibility layer for a
client that no longer exists.

## What remains

`daemon/` is kept. It is not launcher-specific: `service/api/server.go` builds the
Native API on `daemon.NewAttachedService` and `daemon.NewServer`, and the Dashboard
is served from that gRPC-Web surface.

The Native API on the StartedService surface still provides everything the Dashboard
uses, and each of these is covered by `scripts/ci/check-macos-client-headless.sh`
against a real running process:

`GetVersion`, `SubscribeGroups`, `SelectOutbound`, `URLTest`, `SubscribeStatus`,
`SubscribeLog`, `SubscribeConnections`, `SubscribeOutbounds`, `CloseAllConnections`,
`ClearLogs`, `SetClashMode`.

`SetClashMode` is worth calling out: despite the name it is a **Native API** method
driving `experimental/clashmode`, which is retained because `box.go`,
`daemon/instance.go` and `route/rule/rule_item_clash_mode.go` all depend on it. It has
nothing to do with the removed Clash API.

## History

The original version of this document described a real failure — the launcher reported
"无法读取代理列表" because `GetGroups` was declared but unimplemented in the shipped
build. That contract is now moot: there is no launcher, so there is nothing to stay
compatible with.
