# Jiejie sing-box fork

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的个人 fork。

**一套源码，一条开发分支，两个产品。**

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

Server 与 macOS Client 共享全部协议与 transport 源码（MASQUE、Naive、HTTP/2、
HTTP/3、QUIC、buffer、framing、安全修复）。两者只通过 **build tags、registry、
平台 glue、CI 与打包** 区分，不存在第二份实现。

---

## 构建 profile

| | Server Minimal | macOS Client |
| --- | --- | --- |
| 平台 | `linux/amd64` | `darwin/arm64` |
| build tag | `jiejie_server_minimal` | `jiejie_client_macos` 等 9 个 |
| registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| CGO | `0` | `1`（Cronet） |
| tag 文件 | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` |
| 实测大小 | 33,767,608 B | 76,819,250 B |

macOS tag 完整列表：

```text
with_gvisor,with_quic,with_utls,with_clash_api,with_naive_outbound,
with_lxd,jiejie_client_macos,badlinkname,tfogo_checklinkname0
```

Server tag：

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

两个产品都可用 `-trimpath -buildvcs=false` **逐字节复现**。

详细说明见 [`docs/BUILD-PROFILES.md`](docs/BUILD-PROFILES.md)。

---

## 构建

```bash
# Linux Server Minimal
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64

# macOS Client（Cronet，需要 CGO）
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64
```

构建脚本从 `release/BUILD_TAGS_*` 读取 tag，profile 定义只有一处，不会与 CI 脱节。

---

## Server Minimal 功能

面向单台 VPS 的生产二进制，只注册该拓扑真正使用的组件：

- **inbound**：MASQUE over HTTP/2 与 HTTP/3（UDP/443）、AnyTLS、ShadowTLS v3、
  Shadowsocks 2022
- **outbound**：`direct` 与住宅 SOCKS5 上游
- 不含客户端组件、Cronet、GUI 相关 service，也不含未使用的协议树

### 组件职责划分

这台 VPS 上的代理能力**不是由一个 sing-box 进程全部承担**的：

| 组件 | 负责 |
| --- | --- |
| **Jiejie sing-box Server Core** | MASQUE L4（HTTP CONNECT / CONNECT-UDP，HTTP/3 主路径 + HTTP/2 fallback）、AnyTLS、ShadowTLS v3、Shadowsocks 2022、direct / 住宅 SOCKS5 出口、local DNS → AdGuard Home |
| **Caddy** | NaiveProxy（`forwardproxy@udpintcp`），含 UoT v2 |
| **Xray** | VLESS Reality / Vision / XHTTP |

因此 **Native Naive inbound 已从 Server Minimal 裁剪**：NaiveProxy 由 Caddy 提供，
sing-box 不再注册该 entry point。`protocol/naive` 源码保留（full registry、客户端
测试与 macOS Naive 仍在使用），只是不再进入本 profile 的 import graph。

同理，MASQUE 在本产品中是 **L4 HTTP proxy 模型**（`type: http`），不是
`masque-client` / `masque-server` L3 endpoint。

---

## macOS Client 功能

macOS 客户端交付**原生 CLI sing-box core**，主推使用方式是
**JiejieBox GUI → mTLS → sing-box `lxd` daemon**。同时也支持 CLI 直接运行、
浏览器 Web Dashboard，以及被第三方 GUI 当作外部 core 加载。

**darwin/arm64，CGO=1（Cronet）**，一个内核包含全部需要的功能：

- **NaiveProxy**：Cronet 实现的 `naive` outbound（HTTP/2 与 QUIC/HTTP3）
- **MASQUE**：`masque-client` endpoint（CONNECT-IP / CONNECT-UDP over H2 或 H3），
  使用共享的 `transport/masque` 与 `transport/http` 数据面
- **inbound**：`tun`（gVisor）、`mixed`、`socks`、`http`、`direct`
- **outbound**：`direct`、`block`、`selector`、`urltest`、`socks`、`http`、
  Shadowsocks（含 2022）、ShadowTLS、Snell、Trojan、VLESS（含 Reality / Vision）、
  VMess、AnyTLS、Hysteria2、TUIC
- **DNS**：UDP、TCP、DoT、DoH、DoQ、DoH3、local、hosts、FakeIP
- **管理面**：原生 `api` service（Web Dashboard）、Clash 兼容 API、`lxd` daemon
- 不含：`masque-server`、Native Naive **server** inbound、OpenVPN / OpenConnect /
  Tailscale / WireGuard / Tor / SSH

NaiveProxy 与 MASQUE 的存在不是靠 tag 名字保证的：CI 会直接检查**最终 binary 的
symbol table**，确认 `cronet-go.NewNaiveClient`、`masque-client`、
`transport/masque`、gVisor、Clash API 等确实链接，且 Naive stub 与
`masque-server` 确实不存在。

### headless 使用

```bash
# 前台运行
./sing-box run -c config.json

# 浏览器打开 Web Dashboard
open http://127.0.0.1:9090
```

进程管理脚本：

```text
scripts/macos/run-headless.sh
scripts/macos/install-launchd.sh
scripts/macos/uninstall-launchd.sh
```

**权限模型（重要）**：拉起 TUN 需要 root，这一点不能用 helper 绕过。

**macOS TCC 限制**：LaunchAgent 不应依赖 `~/Desktop`、`~/Documents`、
`~/Downloads`，默认配置目录放在后台服务可访问的路径。

完整说明见 [`docs/JIEJIE-MACOS-CLIENT.md`](docs/JIEJIE-MACOS-CLIENT.md)。

---

## 验证

```bash
# registry 与 symbol 审计（一次 nm 覆盖 registry、symbol、capability）
./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64

# 配置检查（由上面的审计内部调用，同时验证 fixture 与 example-config.json）
./scripts/ci/check-macos-client-config.sh dist/sing-box-darwin-arm64 /tmp/cfg

# 运行时 smoke（启动、Clash API、mixed inbound、SIGTERM）
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64

# headless（原生 API、dashboard、Clash 兼容 API）
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64
```

CI 只有两个 workflow，一个产品一个：

```text
.github/workflows/server-linux-amd64.yml   ->  sing-box-linux-amd64
.github/workflows/client-macos.yml         ->  sing-box-darwin-arm64
```

两者都是**单个 job**，各自只 build 一次，之后所有检查（tag 校验、config check、
runtime/headless smoke、registry/symbol audit、size、SHA256、BUILD-INFO、上传）
都复用同一个 binary。

耗时的深度验证（vet、race、fuzz、reproducibility、reference suite、Cronet A/B）
不在普通 push 上运行，改为手动 `workflow_dispatch` + `deep_checks=true`。

---

## 更新记录

本轮开发周期内的主要改动。commit hash 可在 GitHub 上直接查看。

### 产品裁剪与 registry

- `f043f6f39` — 从 Server Minimal registry 与 production fixture 移除 Native Naive
  （NaiveProxy 已由 Caddy 提供），并补上「必须不存在」的 contract 断言。
- `5af859762` — 新增 macOS minimal client registry 与 build profile。
- `8f1ba42a9` — 拆分 MASQUE client / server endpoint 注册，使 macOS 只链接 client 角色。
- `564822086` — 注册原生 `api` service，使 Web Dashboard 可达。
- `486b7e8e1` — 把 LXD daemon 支持移植进 macOS core（mTLS + `lxd` 子命令）。
- `387820439` — 移除 dev-only 的 `sing-tun` replace。

### MASQUE / HTTP3

- `a2a7a9a30` — 消除 HTTP/3 CONNECT-UDP 的 deferred activation 竞态。
- `ecdc966ab` — 拒绝 CONNECT-IP template target 中的反斜杠。
- `143f886e2` — peer 提前断开时释放 setup-window datagram。
- `62d59003e` — 在返回成功前完成 CONNECT-UDP target setup。
- `4fc9984b3` — capsule 路径接受最大的普通 IPv6 包。

### 性能（均有 benchmark 数据）

- `9739c42a8` / `3b8d99a21` — HTTP/3 datagram ingress 去掉一次整包拷贝。
- `6d94da584` — packet hot path 状态读取改为 immutable snapshot + atomic.Pointer。
- `01ae0d308` — 批量转发 HTTP/3 CONNECT-UDP 包。
- `ec2b4b91e` — CONNECT-UDP 使用 connected UDP。
- `680f5d89d` — 调整生产 HTTP/2 receive window。
- `6678bf348` — 首次传输后扩大 tunnel buffer。
- `4130117ae` — 增加 opt-in 的 single Cronet engine 开关（默认行为不变）。

细节与未测项见
[`docs/JIEJIE-MASQUE-PERFORMANCE.md`](docs/JIEJIE-MASQUE-PERFORMANCE.md)。

### Naive

- `bbcabc9a2e` — UoT v1/v2 数据面与端到端覆盖。
- `45f6686a61` — Native Naive inbound（认证 CONNECT、Padding、Web masquerade）。
- `58985a3759` — 与官方 NaiveProxy 客户端的兼容性验证。
- `23af897bfd` — 停止接受非标准的 `-connect-authority` header。
- `fb90272a50` — Padding 写路径遵守 `io.Writer` 的 short-write 契约。

### 正确性与依赖

- `7756ee514` — 修复带后缀的开发版本号触发 `invalid deprecated note` panic。
- `df31ff950` — 上游同步后修复 test module。
- [`d24028a6091`](https://github.com/Piggy-Cat-bit-shadow/sing/commit/d24028a609112cc5636bd123cb9a87f4691342eb)（**另一个仓库** `Piggy-Cat-bit-shadow/sing`，不是本仓库）— `control: add EnableUDPFragment`，供上游同步后使用。本仓库通过 `go.mod` 的 `replace` 指向该 fork。

### CI

- `89819993c` — 精简产品验证：移除低信息量的 full jiejie suite、upstream-default
  兼容构建与重复的 macOS step；go vet / reproducibility 移入 deep。
- `0a3993a8c` — 移除 QUICHE live interop。
- `d738f6c73` — Linux fast path 只构建 kernel，不再跑协议实验。
- `c3c654978` — `build-server.sh` 成为唯一构建入口并注入 version。

完整开发历史可用 `git log --no-merges` 查看；本 README 只列主要改动。

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/BUILD-PROFILES.md`](docs/BUILD-PROFILES.md) | 两个 profile、构建、可复现性、CI |
| [`docs/JIEJIE-MACOS-CLIENT.md`](docs/JIEJIE-MACOS-CLIENT.md) | macOS 客户端完整说明 |
| [`docs/JIEJIE-SERVER.md`](docs/JIEJIE-SERVER.md) | 服务端部署说明 |
| [`docs/JIEJIE-MASQUE-PERFORMANCE.md`](docs/JIEJIE-MASQUE-PERFORMANCE.md) | MASQUE 性能测量与决定 |
| [`docs/JIEJIE-NAIVE-CLIENT-AUDIT.md`](docs/JIEJIE-NAIVE-CLIENT-AUDIT.md) | Naive 客户端审计与未测项 |
| [`docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md`](docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md) | MASQUE 参考实现对照审计 |

---

## Upstream

同步 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的 fork。协议实现
尽量保持与 upstream 一致；本 fork 的差异集中在 registry、build tags、CI 与打包，
以及有测量依据的性能与硬化改动。

面向用户的上游文档（配置格式、协议说明）仍适用于本项目。

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
