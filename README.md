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
平台 glue、CI 与打包** 区分，不存在 Server 版和 Mac 版的第二份实现。

macOS 端是**一个**完整内核：包含 NaiveProxy（Cronet）与 MASQUE，不再区分 lite/naive。

以前 `testing` + `macos-client` 双开发线的状态已经结束：macOS client 的内容全部并入
`testing`，不再需要跨分支同步。

---

## 构建 profile

| | Server Minimal | macOS Client |
| --- | --- | --- |
| 平台 | `linux/amd64` | `darwin/arm64` |
| build tag | `jiejie_server_minimal` | `jiejie_client_macos` + `with_naive_outbound` |
| registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| CGO | `0` | `1`（Cronet） |
| tag 文件 | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` |
| 实测大小 | 48,605,024 B | 76,166,402 B |
| artifact | `Jiejie-Linux-amd64-…` | `Jiejie-macOS-arm64-…` |

两个产品都可用 `-trimpath -buildvcs=false` **逐字节复现**（连续两次构建 SHA-256
一致，包括 CGO/Cronet 的 macOS 内核）。

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

- **inbound**：MASQUE over HTTP/2 与 HTTP/3（UDP/443）、AnyTLS、Native Naive
  （含 UoT v1/v2 与 Web masquerade）、ShadowTLS v3、Shadowsocks 2022
- **outbound**：`direct` 与住宅 SOCKS5 上游
- 不含客户端组件、Cronet、GUI 相关 service，也不含未使用的协议树

---

## macOS Client 功能

macOS 客户端交付**原生 CLI sing-box core**。主推使用方式是
**headless daemon + 浏览器 Web Dashboard**，不需要第三方 GUI；也支持被第三方 GUI
当作外部 core 加载。

**darwin/arm64，CGO=1（Cronet）**，一个内核包含全部需要的功能：

- **NaiveProxy**：Cronet 实现的 `naive` outbound（HTTP/2 与 QUIC/HTTP3）
- **MASQUE**：`masque-client` endpoint（CONNECT-IP / CONNECT-UDP over H2 或 H3），
  使用共享的 `transport/masque` 与 `transport/http` 数据面
- **inbound**：`tun`（gVisor）、`mixed`、`socks`、`http`、`direct`
- **outbound**：`direct`、`block`、`selector`、`urltest`、`socks`、`http`、
  Shadowsocks、ShadowTLS、Snell、Trojan、VLESS、VMess、AnyTLS、Hysteria2、TUIC
- **DNS**：UDP、TCP、DoT、DoH、DoQ、DoH3、local、hosts、FakeIP
- **管理面**：原生 `api` service（Web Dashboard）、Clash 兼容 API
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

## MASQUE

MASQUE 是 Server 与 Client **共享的数据面**，只有 registry 角色不同：

```text
protocol/masque/       共享实现
transport/masque/      共享数据面（session、framing、capsule、CONNECT-IP）
transport/http/        共享 HTTP/2 / HTTP/3 与 datagram 处理

RegisterClientEndpoint()  →  masque-client
RegisterServerEndpoint()  →  masque-server
RegisterEndpoint()        →  两者（upstream / server 默认）
```

- macOS Client 只注册 `masque-client`，**不注册** `masque-server`
- 因此 macOS 上：

```text
masque-client  ✅
masque-server  ❌
```

已完成的性能工作（均有 benchmark 与 benchstat 数据）：

- **HTTP/3 datagram ingress 去掉一次整包 memcpy**：geomean `-56.69%`
  （p=0.000, n=10），MTU 尺寸吞吐 `+184%`
- **packet hot path 状态读取改为 immutable snapshot + atomic.Pointer**：
  `-95.25%`（p=0.000, n=8），`B/op`、`allocs/op` 均为 0
- **route lookup**：已 benchmark（1/4/16/64/256 条），依实测**保留线性扫描**
- **客户端 QUIC congestion control**：新增可配置项，默认仍为 quic-go 行为

细节与未测项见
[`docs/JIEJIE-MASQUE-PERFORMANCE.md`](docs/JIEJIE-MASQUE-PERFORMANCE.md)。

---

## Naive

- **Server Minimal**：Native Naive inbound，含 UoT v1/v2 与 Web masquerade
- **macOS Naive**：Cronet 实现的 Naive outbound（HTTP/2 与 QUIC/HTTP3）

已移除 macOS 上**无用的 server-only HTTP/3 listener linkage**
（`protocol/naive/quic` 的 `init()` 只安装 server listener），实测减少 19 个 symbol；
binary 体积变化很小，收益在正确性——client 不再链接它跑不起来的 server。

Cronet engine 策略（`insecure_concurrency` 在 macOS 默认起 N 个 engine）增加了
opt-in 的 `insecure_concurrency_single_engine` 开关，**默认行为未改**；A/B 需要真实
Naive server，因此标记为 **NOT TESTED**，benchmark 脚本已提交。

细节见
[`docs/JIEJIE-NAIVE-CLIENT-AUDIT.md`](docs/JIEJIE-NAIVE-CLIENT-AUDIT.md)。

---

## 验证

```bash
# registry 与 symbol 审计
./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64

# 配置检查
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

耗时的深度验证（race、fuzz、reference suite、Cronet A/B）
不再在普通 push 上运行，改为手动 `workflow_dispatch` + `deep_checks=true`。

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [`docs/BUILD-PROFILES.md`](docs/BUILD-PROFILES.md) | 两个 profile、构建、可复现性、CI |
| [`docs/JIEJIE-MACOS-CLIENT.md`](docs/JIEJIE-MACOS-CLIENT.md) | macOS 客户端完整说明 |
| [`docs/JIEJIE-MASQUE-PERFORMANCE.md`](docs/JIEJIE-MASQUE-PERFORMANCE.md) | MASQUE 性能测量与决定 |
| [`docs/JIEJIE-NAIVE-CLIENT-AUDIT.md`](docs/JIEJIE-NAIVE-CLIENT-AUDIT.md) | Naive 客户端审计与未测项 |
| [`docs/JIEJIE-SERVER.md`](docs/JIEJIE-SERVER.md) | 服务端部署说明 |

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
