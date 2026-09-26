# Jiejie sing-box fork

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的个人 fork，维护
**两条互相独立的产品线**。

> **你正在读的分支是 `macos-client`（Jiejie Client Edition）。**
> 服务端产品线在 `testing` 分支，本文档对应的是其中的 Server Edition 说明；
> Client Edition 的完整说明见 [`docs/JIEJIE-MACOS-CLIENT.md`](docs/JIEJIE-MACOS-CLIENT.md)。

| | Jiejie Server Edition | Jiejie Client Edition |
| --- | --- | --- |
| 分支 | `testing` | **`macos-client`** |
| 平台 | Linux amd64 VPS | macOS arm64 / amd64 |
| build tag | `jiejie_server_minimal` | `jiejie_client_macos` |
| registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| workflow | `server-linux-amd64.yml` | `client-macos.yml` |
| artifact | `Jiejie-VPS-linux-amd64-…` | `Jiejie-Client-macOS-arm64-…` |

两条产品线共用同一份源码树，**只靠 build tags 和 registry 隔离**，互斥且不会互相
污染：改动其中一条不需要、也不会影响另一条。

## Jiejie Client Edition（macOS）

macOS 客户端产品线交付的是**原生 CLI sing-box core**，供第三方 GUI 作为
**外部 core** 加载。

- 是：`sing-box-darwin-arm64` 可执行文件，支持 `version` / `check` / `run` /
  `format` 和 Clash API
- **不是**：Apple App、不是 Swift GUI、不是 NetworkExtension、不是 libbox、不是
  App Store 构建，也不是官方 sing-box 的替代品
- 目标架构：`darwin/arm64`（必需）、`darwin/amd64`
- profile：`jiejie_client_macos`（lite，默认）/ `jiejie_client_macos` +
  `with_naive_outbound`（naive）
- 详细设计、测试矩阵与已知限制：[`docs/JIEJIE-MACOS-CLIENT.md`](docs/JIEJIE-MACOS-CLIENT.md)

```bash
chmod +x sing-box-darwin-arm64
./sing-box-darwin-arm64 version
./sing-box-darwin-arm64 check -c config.json
./sing-box-darwin-arm64 run   -c config.json
```

---

# Jiejie Server Edition

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的个人
**server-only** fork。

- 面向：**Linux amd64 VPS**，一套固定的生产拓扑（Nginx Stream 持有 TCP/443，
  sing-box 持有 UDP/443）
- 不是：通用 sing-box 替代品，也不是桌面 / 移动客户端；Apple、Linux client-full、
  Windows client profile 均已移除
- 上游分支：`testing`
- 生产 profile：`jiejie_server_minimal`
- 交付方式：GitHub Actions artifact，**没有 stable GitHub Release**
- 详细设计文档：[`docs/`](docs/)

生产二进制只提供这一个拓扑需要的服务端能力；源码中仍然存在的其它协议模块**不在**
生产构建内（见[构建范围](#构建范围build-scope)）。

## Upstream

| 项目 | 值 |
| --- | --- |
| 上游仓库 | https://github.com/SagerNet/sing-box |
| 跟踪分支 | `testing` |
| 当前上游基线 | `132b38e9c`（Bump version，2026-09-26） |
| fork 当前版本 | `1.15.0-jiejie-masquerade.5` |
| fork 当前 HEAD | `3878204393` |

本仓库跟踪上游 `testing` 分支，并维护一组服务端改动。协议实现、路由、DNS、TLS
和传输层均来自上游；本仓库增加的是部署相关的服务端行为、注册表裁剪与验证。

最近一次上游同步是 `c992b1fab0`（Merge upstream testing into Jiejie testing），
把上游 `132b38e9c` 合并进 fork 的 `71f0f1288`。该次同步保留了全部 fork hardening，
并在合并过程中发现并修复了三个真实的生产回归（见
[Upstream Sync 与合并期修复](#upstream-sync-与合并期修复)）。

历史基线：MASQUE Pre-VPS code closure 的基线 commit 是 `864be35e`，它**不是**当前
HEAD，只是当时那一轮代码收口的记录。

## 当前状态

| 项目 | 状态 |
| --- | --- |
| Native Naive | H1 / H2 / H3、Padding、half-close、ALPN、认证、Web masquerade、资源与 churn 边界、UoT v1/v2、目标 ACL 均已有实测覆盖；与 pinned Caddy / forwardproxy reference 做差分 |
| MASQUE CONNECT-UDP | production minimal 的实际发布路径；H2 / H3 均有运行测试与 reference interop，含 IPv6、Datagram / Capsule fallback、NAT rebinding、impairment 与队列所有权 |
| MASQUE CONNECT-IP | 协议实现与 full-registry reference interop 已有证据；**不是** production minimal 发布的 endpoint |
| MASQUE Packet Too Big | IPv4 live H3 与 IPv6 生成、session ownership 已 PASS；**IPv6 live H3 仍 NOT-TESTED** |
| Google QUICHE | 已 build 并 run；三个结果**互不相同**：HTTP/3 transport LOCAL PASS、GitHub runner INCONCLUSIVE-TIMEOUT、CONNECT-UDP / CONNECT-IP EXECUTED-FAILED（interop 未建立，root cause UNCONFIRMED） |
| 当前阶段 | Pre-VPS code closure 已完成；下一步为 Linux amd64 VPS 实机验收 |
| 实机结果 | NOT-TESTED；本地 / CI 的 PASS 不等于 VPS PASS |

上述状态只描述代码与测试能证明的范围。真实 VPS 尚未验收，因此这里不使用
“production ready”一类的结论。逐项证据边界见
[`docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md`](docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md)
顶部的 `CURRENT STATUS`，以及
[`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md)。

### Native Naive

覆盖范围（均为实测，非源码存在性）：

| 维度 | 状态 |
| --- | --- |
| HTTP/1、HTTP/2、HTTP/3 inbound | PASS |
| Caddy / forwardproxy reference 差分 | PASS（pinned 版本） |
| Padding 协商与 segmentation | PASS |
| ALPN（TCP 与 QUIC 相互隔离） | PASS |
| 双向 half-close | PASS |
| 认证（含 constant-time 凭据比较） | PASS |
| Web masquerade（非代理请求） | PASS |
| 资源边界与 churn（2000 sessions 标准） | PASS |
| UoT v1 / v2 | PASS（CI 中实际执行，不跳过） |
| 目标 ACL（含逐 datagram 目标） | PASS |
| 真实 WAN / 长时 soak | NOT-TESTED |

### MASQUE CONNECT-UDP

这是当前 production minimal 实际发布的唯一 MASQUE endpoint（HTTP inbound，
HTTP/2 与 HTTP/3 两条路径）。

| 维度 | 状态 |
| --- | --- |
| HTTP/2 CONNECT-UDP（经 Nginx Stream） | PASS |
| HTTP/3 CONNECT-UDP（UDP/443） | PASS |
| HTTP Datagram 与 Capsule fallback | PASS（两条路径均有） |
| IPv4 / IPv6 | PASS（两种 transport 的 IPv6 均有 live 覆盖） |
| 认证边界 | PASS（无凭据不建立 tunnel） |
| 目标 ACL | PASS |
| 资源限制（未认证 limiter、请求体上限） | PASS |
| NAT rebinding / migration | PASS（受控测试环境；真实移动网络 NOT-TESTED） |
| loss / duplication / reordering | PASS（受控 impairment relay） |
| batching（batch reader / writer） | PASS（功能路径 + Linux 真实 UDP socket） |
| 队列所有权与背压 | PASS（`tun.OutboundQueue` 语义 + ownership 回归测试） |
| early datagram 处理（setup window） | PASS（含 early-disconnect 释放回归） |
| 真实 WAN / PMTU / CGNAT | NOT-TESTED |

### MASQUE CONNECT-IP

旧 README 把它笼统写成单一 PASS，这里按维度拆开，因为各项证据强度不同：

| 维度 | 状态 | 说明 |
| --- | --- | --- |
| 协议实现 | PASS | control capsule、地址分配、路由广播、IPv4 / IPv6 解析 |
| full-registry reference interop | PASS | 对 pinned connect-ip-go 的真实 interop |
| Packet Too Big（生成 + ownership） | PASS | ICMP 生成与 owning session 隔离 |
| live H3 Packet Too Big E2E（IPv6） | NOT-TESTED | 缺少合适的 asymmetric origin |
| QUICHE CONNECT-IP tunnel interop | EXECUTED-FAILED | 见下节，interop 未建立 |
| production minimal inclusion | **NO** | `masque-server` 只在 full registry 注册 |

### Google QUICHE

QUICHE 已由 `scripts/ci/jiejie-quiche-live-interop.sh` 实际 build 并 run（作为
EXTERNAL TOOL，不进入 `go.mod`）。**三个结果不能压缩成一个 PASS 或 FAIL：**

| 项目 | 当前状态 | 证据 |
| --- | --- | --- |
| QUICHE HTTP/3 transport | **LOCAL PASS**；GitHub runner **INCONCLUSIVE-TIMEOUT** | `TestReferenceQuicheH3TransportLiveInterop`；run `36238936300` |
| QUICHE CONNECT-UDP tunnel | **EXECUTED-FAILED** — interop NOT established | `TestReferenceQuicheConnectUDPLiveInterop`；进程以 `QUIC_CONNECTION_CANCELLED` 非零退出 |
| QUICHE CONNECT-IP tunnel | **EXECUTED-FAILED** — interop NOT established | `TestReferenceQuicheConnectIPLiveInterop`；同样的可观测失败 |
| QUICHE root cause | **UNCONFIRMED** | 进程在发出任何 CONNECT 之前就失败；四个候选原因已由测量排除，其余无法用现有证据归因 |

术语含义（不要混用）：

- **EXECUTED-FAILED** = 进程运行了并给出不一致结果。这是**真实观测到的失败**，
  不是“没有测试”，本身也不构成对任何一方实现有缺陷的证据。
- **INCONCLUSIVE-TIMEOUT** = 进程运行了但在执行期限被终止。没有观测到交换，
  因此两个方向都不成立。
- **NOT-RUN** = 没有进程执行；这同样不是 PASS。

**没有主张任何 QUICHE MASQUE tunnel interop。** 低成本的 protocol-vector 检查
（`TestQuicheOracle*`）仍然在每次 push 运行并固定 QUICHE 的决策表，
但 **protocol-vector check ≠ live interop**。

### Packet Too Big

按粒度记录，不统称为 “PTB PASS”：

| 项目 | 状态 |
| --- | --- |
| IPv4 live H3 Packet Too Big | PASS（真实 `quic-go` `DatagramTooLargeError`） |
| IPv6 Packet Too Big generation | PASS |
| IPv6 live H3 Packet Too Big | NOT-TESTED |
| Packet Too Big session ownership | PASS |

**ownership 的隔离意义**：PTB 必须回到产生该条件的 owning session，不能广播到其它
peer，也不能错误投递。若投递按错误的目的地址重新推导，一个 peer 的网络状况会泄漏进
另一个 peer 的 session。回归测试以“恰好一个 session 收到、其余收到零个”断言这一点
（`TestPacketTooBigIsDeliveredOnlyToTheOwningSession`、
`TestPacketTooBigIsNotBroadcastToEverySession`）。

以上均不构成完整网络环境验证；真实 PMTU 与 ICMP 可达性属于 VPS 阶段项目。

## 构建产物

CI 会产出三个 GitHub Actions artifact，用途完全不同：

| Artifact | 用途 |
| --- | --- |
| `Jiejie-VPS-linux-amd64-<version>-<sha>` | 真正用于 Linux amd64 VPS 部署的生产 minimal 二进制 |
| `naive-caddy-parity-<sha>` | Native Naive 与 pinned Caddy / forwardproxy reference 做差分测试后生成的 CI 报告 |
| `quiche-live-interop` | Google QUICHE live interop 的日志与 provenance（`quiche-interop.log`、`QUICHE-PROVENANCE.txt`） |

`Jiejie-VPS-linux-amd64-*` 只包含：

```text
sing-box-linux-amd64
sing-box-linux-amd64.sha256
BUILD-INFO-VPS.txt
SIZE-REPORT-linux.txt
```

`naive-caddy-parity-<sha>` **不是** Caddy binary，不是代理程序，也不是 VPS 部署程序。
它只包含：

```text
naive-caddy-parity.json
naive-parity.log
```

`quiche-live-interop` 同样**不是**可部署 binary，它只是 interop 的执行日志与
QUICHE 来源信息；其中的结局按上节的 QUICHE 分类阅读，不要当成 PASS。

部署 VPS 时只需要 `Jiejie-VPS-linux-amd64-*`；另外两个仅用于兼容性审计与追溯。

artifact 名称中的 `<version>` 与 `<sha>` 随构建 commit 变化，不写死。

## 快速使用

本仓库**没有 stable GitHub Release**，交付方式是 Actions artifact。因此获取方式与
上游不同，请按下面的步骤做。

**1. 取得生产二进制**

打开 GitHub → Actions → `Linux amd64 server` → 选择 `testing` 上的一次成功运行 →
下载 artifact `Jiejie-VPS-linux-amd64-<version>-<sha>`。
只有 `build-production` job 成功（即 `lint-and-unit-tests` 与
`production-minimal-integration` 都通过）之后该 artifact 才会产生。

```bash
unzip Jiejie-VPS-linux-amd64-*.zip
sha256sum -c sing-box-linux-amd64.sha256
```

**2. 确认拿到的是正确的构建**

```bash
./sing-box-linux-amd64 version
```

输出应包含 `with_quic` 与 `jiejie_server_minimal`，且**不应**包含
`with_tailscale`、`with_openvpn`。`Tags` 一行即为生产标签，
`Revision` 一行是构建所用的 commit SHA。

**3. 校验配置**

```bash
./sing-box-linux-amd64 check -c config.json
```

配置不合法时以非零退出，并在 stderr 说明原因。

[`release/jiejie-production-topology.json`](release/jiejie-production-topology.json)
是一个**无密钥的拓扑 fixture**，可以用来自检部署骨架。它引用的证书路径是
`/tmp/jiejie-fixture/{cert,key}.pem`，因此需要先按 CI 的方式生成一张自签证书，
否则 `check` 会因为读不到证书而失败（这是预期行为，不是配置错误）：

```bash
mkdir -p /tmp/jiejie-fixture
openssl req -x509 -newkey rsa:2048 \
  -keyout /tmp/jiejie-fixture/key.pem -out /tmp/jiejie-fixture/cert.pem \
  -days 1 -nodes -subj "/CN=example.test"
./sing-box-linux-amd64 check -c release/jiejie-production-topology.json
```

这个 fixture 只用于拓扑自检，**不是**可直接上线的配置：真实部署必须换成自己的
证书、密码与监听地址。

**4. 运行**

```bash
./sing-box-linux-amd64 run -c config.json
```

常用全局 flag：`-c/--config`（可重复）、`-C/--config-directory`、
`-D/--directory`（工作目录）、`--disable-color`。

**5. 配置与部署文档在哪**

| 内容 | 位置 |
| --- | --- |
| 生产拓扑、各 inbound 的推荐配置、`server_profile`、`bbr_profile`、`unauthenticated_limits` | [`docs/JIEJIE-SERVER.md`](docs/JIEJIE-SERVER.md) |
| 生产拓扑 fixture（可作为配置骨架） | [`release/jiejie-production-topology.json`](release/jiejie-production-topology.json) |
| VPS 实机验收步骤 | [`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md) |
| 本 fork 相对上游的完整改动 | [`docs/FORK-DIFF.md`](docs/FORK-DIFF.md) |

注意本 fork 的生产拓扑要求 **Nginx Stream 持有 TCP/443**，sing-box 只持有 UDP/443
以及若干 loopback 端口；不是单进程监听 443 的部署。

## 构建范围（Build Scope）

面向 Linux amd64 的服务端最小化构建。裁剪发生在**注册层面**：minimal registry
不 import 未使用的包，链接器随之丢弃。上游完整构建仍然可用，位于
`include/registry.go`（`!jiejie_server_minimal`）。

生产构建标签（直接取自
[`release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL`](release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL)，
不在 README 里另写一份）：

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

注册表实际注册项（`include/registry_jiejie_server.go`）：

| 注册表 | 内容 |
| --- | --- |
| Inbound（5） | `http`、`anytls`、`naive`、`shadowtls`、`shadowsocks` |
| Outbound（2） | `direct`、`socks` |
| Endpoint（0） | 无。`EndpointRegistry()` 返回空注册表 |
| Service（0） | 无。因此 systemd-resolved service 与 D-Bus 依赖都不在二进制内 |
| Certificate provider（0） | 无 |
| DNS transport | `udp`、`local` |

**保留的 inbound**

```text
HTTP       (MASQUE HTTP/2 与 HTTP/3)
AnyTLS
Native Naive
ShadowTLS
Shadowsocks 2022
```

**保留的 outbound**

```text
direct
SOCKS5
```

**保留的 DNS transport**

```text
udp
local   （box.go 的 DNS transport fallback 在启动时必需）
```

**minimal 生产构建不包含的功能**

| 类别 | 不包含 |
| --- | --- |
| QUIC 代理协议 | Hysteria、Hysteria2、TUIC |
| 代理协议 | VMess、VLESS、Trojan、Snell |
| 客户端运行时 | Naive outbound、Cronet / Chromium 客户端栈 |
| 网络端点 | TUN、WireGuard、Tailscale、OpenVPN、OpenConnect |
| Outbound | HTTP、Shadowsocks、ShadowTLS、AnyTLS、selector、urltest |
| DNS | DoT、DoH、DoQ、hosts、resolved |
| Service | Clash API 及未使用的 service |
| 证书 provider | 未使用的证书 provider |
| Endpoint | MASQUE `masque-server`（full registry 才有） |

注意：Native Naive 的 **inbound 保留**，被排除的只是 Naive outbound 与客户端运行时。

**源码中存在 ≠ 生产二进制包含。** 上表描述的是 production minimal binary 实际**不包含**
什么。仓库里仍然可以读到这些模块的源码（上游完整构建仍需它们），但 minimal registry
不注册、不 import，因此不会进入链接结果。判断某个能力是否在生产二进制里，标准做法是
查注册表并实测：

```bash
./sing-box-linux-amd64 version                      # 看 Tags 一行
./sing-box-linux-amd64 check -c <一个 vmess 配置>    # 应 FAIL：unknown inbound type
```

生产产物大小上限 38000000 bytes，由 `server-linux-amd64.yml` 的 size guard 强制；
超限时 workflow 直接失败，而不是静默放宽上限。

## Change Log

### Native Naive

- `45f6686a61` — 加入 Native Naive inbound：认证 CONNECT、可选 Padding 协商、
  Web masquerade。
- `77607290f5` — 暴露 HTTP/2 服务端资源参数（`max_concurrent_streams`、
  `idle_timeout`、收发窗口）。
- `ec1e7ab294` — 将 Native Naive inbound 注册进生产注册表。
- `bbcabc9a2e` — 加入 UoT v1/v2 数据路径及端到端覆盖。
- `c3de03ad48` — UoT 会话结束后释放其占用的资源。
- `568e93f140` — 覆盖 Web masquerade 的非代理请求路径。
- `58985a3759` — 与官方 NaiveProxy 客户端做兼容性验证。
- `c0ba174912` — Linux socket 层验收覆盖；收敛一个 UDP 丢包发现。
- `ce0496a311` — 针对生产 minimal registry 构建的最终验收。
- `d0087e877e` — 独立覆盖 UoT 的各条异常路径。
- `4085c086dc` — HTTP/2 并发、Padding 边界与目标控制审计。
- `23af897bfd` — 不再接受非标准的 `-connect-authority` header。
- `b24e294300` — TLS/ALPN、listener 矩阵与异常生命周期审计。
- `6fd7135235` — v1/v2 往返之外的 UoT 数据面审计。
- `41bd528cb2` — 审计 masquerade 后端实际收到的内容。
- `fb90272a50` — Padding 写路径按标准 `io.Writer` 短写契约处理。
- `eace39c3e6` — 确定性的 Padding codec benchmark。
- `0c83345a3f` — 逐 stream 的认证隔离与 authority 处理。
- `593f634a1a` — CONNECT 保留 `net/http` 已经预读的 tunnel payload。
- `3bbf179078` — UoT 路径插桩；定位到丢包与 hijack 交互的关联。
- `10e1f2a957` — 加入确定性丢包回归测试与真实的 retry 测试。
- `d1f3798a63` — churn 验收标准收紧到 2000 sessions。
- `d4ead1498a` — UoT 会话按逐 datagram 目标执行 ACL；附带 Naive ACL 配置模板。
- `2ec06e451f` — UoT 回归测试在 CI 中实际执行，不再跳过。
- `1dc734f754` — 以故障注入替代 UoT skip；补充 STUN 与 IPv6。
- `d2af551c40` — tunnel 生命周期与 Linux 资源占用覆盖。
- `3c6e0aad37` — 约束 Padding 取值范围，超大值不再导致连接终止。
- `fe57895393` — 恢复完整 Padding 范围，修正 buffer 回归测试。
- `e9d3293806` — CONNECT Padding 协商与 reference 对齐。
- `f2907e79a5` — HTTP CONNECT 边界情况与 reference 对齐。
- `cc9df81f07` — 建立 Caddy / forwardproxy 差分兼容性 harness。
- `83efc0bf00` — 对照 Caddy 的 HTTP/3 审计；固定 Cronet 客户端版本。
- `b32bb58f91` — HTTP/1 tunnel framing 与 reference 对齐。
- `1d66e934f3` — 来源身份默认使用 transport peer。
- `7be29e4ba9` — HTTP/2 option 边界在解码期校验。
- `dccf70987e` — HTTP/3 构造函数缺失时返回规范的能力错误。
- `c630c9775c` — TCP 与 QUIC 的 TLS ALPN 列表相互隔离。
- `9c6052b050` — Native Naive HTTP/3 服务端采用关闭 0-RTT 的策略。
- `34628b6daf` — 覆盖各种 Forwarded header 形态，防止来源伪造。
- `ade5f465c6` — 使用规范的 QUIC 缺失错误；扩大边界覆盖。
- `ece998f21f` — 以字节比对确定 HTTP/1 tunnel framing；去除一个误报的差异。
- `1be7647977` — 在运行时验证 TCP/QUIC ALPN 隔离。
- `9885c45cf6` — 针对 reference 的真实 HTTP/2 差分探针。
- `d480202829` — 测量 H3 stream 上限；标注剩余的 H3 差异。
- `0245deff82` — CONNECT response flush 纳入连接建立流程检查。
- `d921493382` — HTTP/3 incoming stream 数恢复为 quic-go bounded default
  （`MaxIncomingStreams` 不再显式设置）。
- `086aba2a45` — Padding codec 与 CONNECT authority 模糊测试。
- `318dbee27d` — 差分结论与产物表达改为无歧义。
- `2fbab5b96f` — Basic credential 比较改为 constant-time，去除明显的认证 timing signal。
- `bc50e66ea7` — HTTP/2 / HTTP/3 tunnel flush 失败正确向上传播。
- `aa32bdf781` — 未认证代理 challenge 与 Caddy / forwardproxy reference 对齐。
- `497fb9272c` — 分离 bare Caddy 与 probe-resistant reference profile，避免错误比较。
- `d22dd89443` — QUIC tuning 改为 opt-in，协议默认行为更接近 reference。
- `11fd30d330` — 覆盖双向 tunnel half-close。
- `1f0547577e` — 官方 NaiveProxy client preamble 对 Web masquerade 的真实行为验证。
- `2e49e4508c` — 大 payload Padding segmentation 与 reference 实测比较。
- `59401b422d` — mixed-address ACL hardening regression。
- `1f9014c854` — malformed CONNECT port 不再被错误 coercion。
- `8618312690` — 对照 reference 的校验式 HTTP/3 差分。
- `10191b11c7` — shared TLS config 增加 transport-scoped ALPN view。
- `d6820d0e7a` — tcp+udp inbound 下 TCP / QUIC ALPN 真正隔离。
- `65e2270028` — padded response segmentation 与 forwardproxy reference 对齐。
- `b16660ed18` — 去除 username-existence timing signal。
- `242d8c2cba` — zero-length padded frame 仍然产生读取进度，避免 no-progress 行为。
- `f74d9254cd` — QUIC version list 与 reference 对齐并固定。
- `8ed7051c62` — 测量 HTTP/3 server defaults 与 Caddy reference 的差异。
- `b67b3f6ae4` — 在运行时走到 HTTP/3 pseudo-header guard，不再只靠静态检查。
- `f730f6e50` — HTTP/3 half-close 双向覆盖。
- `9a553a7ff` — 固定 shared TLS config 在各 ALPN view 之间的生命周期归属。
- `40b6d6fcc` — 真实 QUIC congestion-control validation（不再只做配置层断言）。
- `385383dcc` — CI 中真正执行 HTTP/3 differential against the pinned reference。
- `96eafce9b` — QUIC unit tests 从 repository root 执行，覆盖到需要 QUIC 的包。
- `419a7e2efe` — 修正 write-contract fixture 的 buffer geometry，消除由 buffer-pool
  状态暴露出的 flaky race；生产逻辑未变化。

### HTTP / MASQUE

#### 当前能力边界

| 范围 | 当前状态 | 发布关系 |
| --- | --- | --- |
| CONNECT-UDP over H2 / H3 | PASS（本地 / CI / reference evidence） | production minimal 实际发布路径 |
| CONNECT-IP | 协议实现与 full-registry reference interop PASS；production inclusion = NO | 不是 production minimal endpoint |
| HTTP Datagram / Capsule fallback | PASS | CONNECT-UDP / CONNECT-IP 均有覆盖 |
| IPv4 / IPv6 | PASS（已有对应测试范围内） | CONNECT-UDP production path 已覆盖 IPv6 |
| NAT rebinding / impairment | PASS（受控测试环境） | 真实 WAN 仍待 VPS 验收 |
| Packet Too Big | IPv4 live H3 PASS；IPv6 generation PASS；IPv6 live H3 NOT-TESTED；ownership PASS | 见上面的 Packet Too Big 表 |
| Google QUICHE | 已 build / run：H3 transport LOCAL PASS（runner INCONCLUSIVE-TIMEOUT）、CONNECT-UDP / CONNECT-IP EXECUTED-FAILED、root cause UNCONFIRMED | 不是 interop PASS |
| Real VPS / WAN | NOT-TESTED | 下一阶段 |

当前 production minimal 实际发布的是 HTTP inbound 上的 CONNECT-UDP（HTTP/2 / HTTP/3）。

CONNECT-IP 的 `masque-server` endpoint 只在 full registry 中存在，用于 reference /
protocol 验证，不属于当前 VPS minimal artifact 的生产 endpoint。

#### 服务端基础与生产路径

- `d53c867b7d` — inbound masquerade handler：非代理请求落到 Web 后端。
- `f7e51ef60e` — 服务端资源 profile 与 header 限制选项。
- `9771af9f49` — `server_profile` 与 `max_header_bytes` 在运行中的 server 上生效。
- `38491df890` — 未认证资源限制（每 IP 并发、速率、burst、tracked-IP 上限）。
- `7e57fe8c77` — 超限请求不再到达 masquerade 后端。
- `1276eb85a2` — 固定 H3 到 H2 路径上的重放安全不变式。
- `747c62d263` — request body 上限在数据路径上强制执行。
- `cce49f3877` — limiter 过期行为改为实测，不再依赖假设。
- `80ad6df293` — 零错误码的 H3 关闭在连接边界归一化。
- `27cd75af45` — HTTP/3 application idle timeout 强制执行。
- `cd8d702122` — HTTP/3 上强制 request header 限制。
- `0eccef3c40` — 认证先于缺失 handler 的响应。
- `127ae9c3b9` — 未认证名额释放按每次获取幂等。
- `a3cb8abf58` — HTTP / MASQUE 的来源身份默认取 transport peer；
  `X-Forwarded-For`、`Forwarded`、`X-Real-IP` 不参与安全来源判定。
- `2fb3ba6930` — 服务端资源选项边界校验。

#### Reference hardening

- `969909bc16` — 拒绝 ROUTE_ADVERTISEMENT 跨 protocol 的 overlap：
  protocol 0 代表所有 protocol，同一 range 不能用不同 protocol 重复声明。
- `b656b062f9` — overlap validation 改为线性时间，避免 O(n²) 造成的 CPU DoS。
- `a529b68c83` — 限制单个 control capsule 内的 address / route entry 数量。
- `e4f847ecf7` — MASQUE H3 QUIC tuning 改为 opt-in，默认贴近 quic-go reference。
- `ab9c9f09d9` — CONNECT-UDP request path corpus。
- `32b1d25cbf` — CONNECT-UDP / CONNECT-IP 对 pinned masque-go / connect-ip-go 的真实
  reference interop。
- `b81244bdf7` — H3 DATAGRAM → Capsule fallback 的真实 wire test。
- `97e1487782` — RFC 9931 §8：conventional HTTP/1.1 CONNECT 被拒后关闭 connection。
- `e4d2f6c1af` — `Contains` 与 `lookup` 对 server own-address 的语义保持一致。
- `66f0e94360` — 针对 attacker-controlled MASQUE parser 的 fuzz targets。
- `528858c444` — reference interop 按 case 使用正确 binary，避免 false-green / false-fail。
- `6efcf0a75f` — CONNECT-IP ICMP fixture 改为真正指向 server gateway。
- `0783a33b3b` — CONNECT-IP 在 HTTP Datagrams 未协商时使用 Capsule fallback。
- `01f20ce4e6` — QUIC NAT rebinding / migration 行为实测。
- `c5e2d3eb48` — active tunnel shutdown 与资源回收实测。
- `858284e5a0` — send queue backpressure 与 buffer ownership。
- `0cc6074e3d` — HTTP Datagram size accounting 在各 varint 边界固定。
- `1325727a56` — IPv6 extension-header protocol 解析的 regression。
- `86002b56f0` — IP packet parser 与 capsule fragmentation fuzz。
- `824cd658a8` — `decrementHopLimit` 对 malformed IP header 做防御性 hardening。
  两个生产调用点此前均已由 `packetAddresses` 完成校验拦截，这不是线上可利用的 panic。
- `429d8b6774` — Proxy-Status 与认证信息泄漏边界审计。
- `a12e5c258c` — 关闭 reference CI 双向的 false-green 漏洞。
- `0735d419c6` — MASQUE reference hardening merge 到 `testing`。

> **RFC 9931：**
> §8 对 conventional HTTP/1.1 CONNECT 的拒绝路径包含 server-side close 要求；
> CONNECT-UDP 被拒后关闭 connection 在本 fork 中属于 **SECURITY-HARDENING**，
> 不是 §6.3 对 server 的 MUST。
> §6.3 约束的是 HTTP/1.x CONNECT-UDP client 不得 optimistic send UDP payload。

#### Pre-VPS code closure

- `c70249783f` — 修复 reference harness 的 IPv6 control-capsule decoder：
  地址前的 byte 是 IP Version（4 / 6），不是 address byte length（4 / 16）。
  这是 TEST-HARNESS bug，不是 production bug。
- `5434688268` — 修正 vacuous fuzz corpus（旧 seed 实际上全部 invalid），并补真正的
  CONNECT-UDP path fuzz。
- `7ae42c98d4` — 所有 MASQUE fuzz target 真正进入 bounded CI，并加 coverage guard。
- `7bb4342755` — source identity 改为通过 routing layer 实际测量，不再靠错误的测试注释推断。
- `8530321703` — NAT rebinding / source-port churn 不能重置 per-IP unauthenticated
  limiter bucket。
- `988df7a358` — live context-ID 边界、zero-length UDP、datagram error semantics。
- `4fc9984b39` — 修正 MASQUE Capsule 路径的 IPv6 inner-packet 上限：
  普通 IPv6 packet 最大总长度可达到 65575 bytes，旧的 65535 hard bound 会静默丢弃
  合法的 65536–65575 byte IPv6 packet；jumbogram 仍不支持。
  这是本轮唯一确认的 production MASQUE bug。
- `ba7f62a4ba` — IPv4 / IPv6 Packet Too Big 的完整证据链（含两个 checksum）。
- `1dbf363d49` — 受控 UDP impairment relay 验证 quic-go + MASQUE stack 在
  loss / duplication / reordering 之后可以 survival / recover。
  这验证的是 stack 行为，不是 sing-box 自己实现了 packet loss recovery。
- `daa49073e8` — CONNECT-UDP H2 / H3 的 IPv6 live coverage；同时纠正 RFC 9931 §6.3
  的引用。
- `e823b4312b` — MASQUE reference audit 收口，并新增 Pre-VPS acceptance checklist。
- `41a04ceb14` — cross-session ownership / route policy、control burst、IPv6 extension chain 覆盖。
- `36d404826b` — Google QUICHE 作为第三个 protocol oracle。
  当时状态是 **CHECKED (protocol vectors)**：读取 pinned 源码并固定其 decision table 与
  unit vectors；没有 build、没有 run、没有 live interop，
  因此不是 QUICHE PASS，也不是 QUICHE interop PASS。
  **此条已被后续工作取代**：QUICHE 之后已实际 build 并 run，
  当前状态见上面的 [Google QUICHE](#google-quiche) 表（三个结果互不相同）。
- `0dbfc43d1e` — 记录 QUICHE vector check 的分类，并把 RFC 9931 client-side half
  重新分类。
- `4db6f90f98` — RFC 9931 client-side half 对当前 server-only product 归类为
  OUT-OF-SCOPE。
- `583bfc84f3` — QUICHE oracle tests 真正进入 reference CI 的 run filter。
- `864be35ebc` — 把 linearity regression test 改为抗 shared-runner noise 的
  ratio / 最小值测量。这是 TEST fix，不是 production performance optimization。

#### 当前剩余边界

- **Google QUICHE MASQUE tunnel interop** — 已 build 并 run，但**未建立 interop**。
  CONNECT-UDP 与 CONNECT-IP 均为 EXECUTED-FAILED，root cause UNCONFIRMED；
  HTTP/3 transport 为 LOCAL PASS / GitHub runner INCONCLUSIVE-TIMEOUT。
  详见上面的 [Google QUICHE](#google-quiche) 表，不要压缩为单一结论。
- **CONNECT-IP live H3 Packet Too Big E2E（IPv6）** — NOT-TESTED。
  PTB generation 已测试；真实 `DatagramTooLarge` E2E 仍缺少合适的 asymmetric origin。
- **Real VPS / WAN behaviour** — NOT-TESTED。
  下一步按 `docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md` 验收。
- **RFC 9931 client-side half** — OUT-OF-SCOPE-FOR-SERVER-PRE-VPS。
  production minimal 不发布 MASQUE client endpoint。

#### Upstream Sync 与合并期修复

`c992b1fab0`（Merge upstream testing into Jiejie testing）把上游 `132b38e9c` 合并进
fork 的 `71f0f1288`。50 处冲突按类型处理；fork hardening 全部保留；Phase 4 sing pin、
生产拓扑与 minimal registry 均未改变，也没有恢复任何上游 workflow。

合并过程暴露/引入了**三个真实生产回归**，均已修复：

- `c992b1fab0` — `Server.Contains` 丢失 server own-address guard：
  只要任一 session 广播了隧道网段，服务器自身地址就会被判定为 tunnel-owned。
  `lookup` 一直有该 guard，`Contains` 没有，两者语义不一致。
- `c992b1fab0` — ROUTE_ADVERTISEMENT 重叠检测只比较相邻项：
  protocol 0（全协议）后接 protocol 6 / 17 的同段广播会被接受。
  改为 per-protocol high-water 检测，保持线性时间。
- `c992b1fab0` — `decrementHopLimit` 未校验 IPv4 头长度：
  `packetAddresses` 校验的是头部**声明的**长度，因此 peer 提供的 datagram 可以让
  checksum 计算读到切片之外并 panic 服务协程（远程 DoS）。
  现在对声明长度做**上下双端**约束（IHL=0 会反转切片边界，过大的 IHL 会越界）。

同时把 MASQUE 测试从上游已删除的 session send queue 迁移到 `tun.OutboundQueue`
（上游把队列所有权移到了该类型）。三个针对旧 `sendQueue` API 的测试被
OutboundQueue 语义下的饱和、取消与 shutdown 测试取代，不变量保留，
**没有跳过或放宽任何断言**。

- `143f886e21` — 修复 setup-window early-disconnect 下已确认的 datagram buffer
  ownership / leak（见下）。
- `3878204393` — 修复本次同步首次推送暴露的两个 CI 失败：
  `test/go.mod` 中上游遗留的 `replace ../../sing-tun`（本地并排检出用，本仓库与
  CI 都没有该目录，导致 `test/` 下任何 go 命令在运行前就失败），
  以及四个 lint 失败。根模块的 sing pin 未受影响。

#### Setup-window datagram ownership

- `143f886e21` — CONNECT-UDP target 尚未 resolve 时，datagram 会被暂存在
  setup window；`settle()` 是当时**唯一**的排空路径。peer 在 setup 期间发完
  datagram 就断开时，连接先关闭、`settle()` 永不执行，暂存的 buffer 永不释放。
  任何能访问监听端口的客户端都可触发。
  修复后 close 与 settle 通过共享的 `takeEarlyDatagrams()` 争抢同一份所有权：
  先到者负责 flush 或 release，另一方拿到空队列，避免 double claim 与泄漏。
  对应回归覆盖：`transport/http/early_datagram_ownership_test.go`
  （早断释放、release 而非仅丢引用、settle 与 close 竞态）。

  这是**已确认的 datagram buffer ownership / leak 修复**，
  不构成“全面解决 MASQUE 内存泄漏”的结论。

#### Batching 与 packet timeout wrapper

- `953e0a729a` — 将 `github.com/sagernet/sing` pin 到 fork
  `github.com/Piggy-Cat-bit-shadow/sing` 的 `fix/packet-batch-timeout`
  （commit `c0ee76200ae3`，伪版本 `v0.9.6-0.20260926122709-c0ee76200ae3`）。
  该修复让 packet timeout wrapper 保留 `ConnectedPacketBatchReader` /
  `ConnectedPacketBatchWriter` 能力，而不是在包装后丢失它。
  `go.mod` 中的 `replace` 锁定到确切 commit；已核对解析后的模块目录中
  这些 batch creator 确实存在。
- `9d6bfc783f` — 对 timeout wrapper 的 batch 路径做 benchmark。
- `c51772f6aa` — 在 Linux 上用**真实 UDP socket** 验证 batching 穿过 timeout wrapper。
- `e7f7dde6af` / `4d22f4767d` — 验证 batching 在 timeout wrapper 之后仍然存活，
  收敛 timeout 下的 batch forwarding 缺口。

**证据分级（不要越级推导）：**

| 项目 | 状态 |
| --- | --- |
| batch 路径功能性证据（跨平台） | PASS |
| Linux 真实 UDP socket 证据（`linux \|\| netbsd` build tag） | PASS（CI 执行） |
| `sendmmsg` / `recvmmsg` syscall 路径 | PASS（上述真实 socket 测试覆盖） |
| `UDP_SEGMENT` / GSO 证据 | PASS（受控测量，非 WAN） |
| batch benchmark | 存在并可本地运行；**CI 不运行 benchmark** |
| 真实 VPS 吞吐量 | **NOT-TESTED** |

**禁止**从 “batch benchmark 更快” 推导 “VPS 吞吐量提高 X%”。
真实 WAN 性能属于 VPS 阶段项目，当前保持 NOT-TESTED。

### AnyTLS

- `e97ea9ce82` — inbound fallback 后端。
- `3570205356` — fallback 经由配置的后端转发。
- `b1814cd660` — `fallback_for_alpn` 在运行时按协商出的 ALPN 路由。
- `f30f63e0d6` — 以现有 TCP 超时预算约束 TLS 完成后的首个 application read。
- `5ef800316b` — 以实测固定 ALPN 行为。
- `7a5212d8b7` — 修正 ALPN fallback 语义（命中映射、默认 fallback、需启用 TLS）。
- `93fa2708cb` — 认证前探测失败按错误类型分类。
- `1804358ab2` — 服务端故障在日志分类中保持可见，常规 peer 生命周期事件不记为错误。

### ShadowTLS / SS2022

- `20ce0a05ad` — 固定 ShadowTLS v3 探测 fallback 行为。
- `1804358ab2` — peer 生命周期与服务端故障分类分离（同样适用于 AnyTLS）。
- `ec1e7ab294` — Shadowsocks 2022 注册为生产 detour 目标。

### Routing / ACL

- `d4ead1498a` — UoT 非 connect 会话按逐 datagram 目标执行 ACL。
  该 guard 只做 allow/reject，不为单个 datagram 重新选择 outbound。
- `7029722bff` — 为本机管理服务增加受限的 self-target 端口例外，
  不放宽通用目标 ACL。
- `f45e465b83` — 自建 HTTPS 目标改写到一个隔离的 loopback Web ingress，
  避免重新进入公网代理 front door。代理 ingress hostname 在后缀改写之前先被拒绝。
- `189bc6d0ed` — 记录 loopback Web ingress 及其改写顺序。

### Minimal Build / Registry

- `bb5b56a460` — 加入 Jiejie server 构建 profile。
- `98d8ef0cb3` — 注册表层面的 `jiejie_server_minimal` 服务端构建。
- `d8a3c8c222` — fixture 反映真实生产的 inbound detour。
- `9d63f155f2` — 从 minimal 注册表移除仅供测试使用的协议注册。
- `918c1521d8` — minimal 构建的生产运行时集成覆盖。
- `61c05bb63d` — CI 只测试并发布 minimal 生产构建。
- `5ce3c4d675` — 收敛为 VPS-only 服务端产品；移除 iOS / 客户端产品线。
- `0b27085f6a` — 对照生产拓扑审计注册表。

### CI / Validation

- `b21371720a` — version、build-info、构建与打包脚本。
- `d71841fc6e` — Fast workflow：并发控制、缓存与构建 gate。
- `61c05bb63d` — 生产构建选择收敛到 minimal 产物。
- `b49c78ca56` — CI gate 与 Naive 服务端进入生产的状态对齐。
- `142df6d2db` — race detector 覆盖 `./route`。
- `75a32bcd7f` — Naive 差分测试针对固定版本的 reference 运行。
- `4ed6dff200` — Naive HTTP/3 集成测试实际执行，不再跳过。
- `9cce35ec3b` — HTTP/2 差分测试实际在 CI 中运行。
- `a4f22a5949` — 上游 `testing` 同步 merge。
- `935ffeca8` — CI 执行 MASQUE 包与 QUIC-tagged HTTP tests。
- `e81f84994` — QUIC-tagged HTTP tests 从 repository root 执行，覆盖到需要 QUIC 的包。
- `fc575d959` — 新增的 TLS 与 QUIC unit tests 进入 CI。
- `96eafce9b` — QUIC unit tests 从 repository root 执行。
- `a12e5c258c` — reference CI 双向 false-green 漏洞关闭。
- `528858c444` — reference interop 按 case 使用正确 binary。
- `7ae42c98d4` — bounded fuzz 覆盖所有 MASQUE target；新增 fuzz target 若没有进入
  workflow，coverage 检查会让 CI fail。
- `583bfc84f3` — QUICHE oracle tests 进入 reference run filter。
- `864be35ebc` — 时间敏感的线性度断言改为抗噪声的 ratio 测量，避免 shared runner flaky。
- `3878204393` — 移除 `test/go.mod` 中上游遗留的 dev-only `replace ../../sing-tun`；
  该 replace 指向本仓库与 CI 都不存在的并排检出，使 integration job 在运行任何测试前
  就失败。同时清除四个 lint 失败。

reference suite 另有一个 coverage guard（`scripts/ci/check-reference-coverage.sh`，
并有自己的 `check-reference-coverage.test.sh`）：在 `test/jiejie/reference` 中定义
但没有被 `-run` filter 匹配到的测试，会让 CI fail，而不是静默跳过。

生产 artifact 只在
`lint-and-unit-tests`、`production-minimal-integration`、`build-production`
三个 job 全部通过后才发布（`build-production` 的 `needs` 显式声明前两者）。
其中 `production-minimal-integration` 以真实 production minimal binary 运行
`test/jiejie` 的集成套件。

注意：`naive-caddy-parity` 与 `quiche-live-interop` 都是 CI 报告 artifact，
不是生产 artifact，也不是可部署 binary。

三个 workflow 的分工：

| Workflow | 触发 | 作用 |
| --- | --- | --- |
| `jiejie-fast.yml` | push 到 `testing` / `feat/jiejie-*` / `cleanup/*` / `sync/*`、PR | 快速 vet + unit + race；`build-gate` |
| `server-linux-amd64.yml` | 同上 | 完整 vet / unit / race、production minimal 集成、生产构建与 artifact、size guard |
| `jiejie-masque-reference.yml` | **仅 `workflow_dispatch` 与每周 schedule** | reference interop 与 QUICHE live interop（构建成本高，**不是** per-push） |

benchmark **不在 CI 中运行**（`batch_timeout_bench_test.go` 等仅供本地执行）；
因此不要用 CI 绿灯推导任何性能结论。

### Documentation / Audit

- `5c620c33a4` — 最初的 Jiejie Server Edition 文档。
- `7c0267f2cc` — Native Naive server、UoT 与 masquerade。
- `8764f6ec61` — VPS 探测面边界。
- `427defcbf7` — 生产协议能力矩阵。
- `5c5440577d` — 审计结论与实测覆盖对齐：删除过期的 H3 结论，将过宽的 PASS
  标签下调为 PARTIAL / NOT-TESTED，并汇总所有未验证项。
- `d159ec09d`、`762b0cede`、`67e55b387` — MASQUE reference audit 的 Phase 1 / 2 / 3 记录。
- `e823b4312b` — MASQUE reference audit 收口，并新增 Pre-VPS acceptance checklist。

文档：

| 文件 | 内容 |
| --- | --- |
| [`docs/JIEJIE-SERVER.md`](docs/JIEJIE-SERVER.md) | 生产拓扑、各 inbound 配置、资源 profile、日志与构建 profile |
| [`docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md`](docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md) | MASQUE reference audit；顶部 `CURRENT STATUS` 为当前状态，其后为 HISTORICAL |
| [`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md) | VPS 实机验收 checklist；Part 1 = local / CI，Part 2 = only-real-VPS |
| [`docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md`](docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md) | 按组件说明验证状态（较早段落可能为历史状态） |
| [`docs/JIEJIE-NAIVE-H3-AUDIT.md`](docs/JIEJIE-NAIVE-H3-AUDIT.md) | Native Naive H3 / QUIC 对照 reference 的审计 |
| [`docs/JIEJIE-NAIVE-SERVER.md`](docs/JIEJIE-NAIVE-SERVER.md) | Native Naive 服务端行为与 UoT |
| [`docs/JIEJIE-NAIVE-TARGET-ACL.md`](docs/JIEJIE-NAIVE-TARGET-ACL.md) | Naive / UoT 目标 ACL |
| [`docs/JIEJIE-PROBE-RESISTANCE-MATRIX.md`](docs/JIEJIE-PROBE-RESISTANCE-MATRIX.md) | 探测面边界 |
| [`docs/FORK-DIFF.md`](docs/FORK-DIFF.md) | 本 fork 相对上游的完整改动清单 |
| `naive-caddy-parity-<sha>` artifact | Caddy / forwardproxy differential 的 machine-readable 与 log 输出（CI artifact，不是文档文件） |

## Removed / Superseded Work

列出这些是为了避免以后维护时把旧 commit 误读为当前能力。

- 早期的 iOS / Libbox / IPA 构建实验已由 `5ce3c4d675` 移除，
  该 commit 将 fork 收敛为 VPS-only 服务端产品。
- 早期的 Linux client-full 与 Windows 客户端构建 profile 也在同一次收敛中移除。
- 早期的 HTTP/3 客户端连接池与 fallback/backoff 工作不属于当前服务端范围；
  `http3_connection_pool` 与 `http3_fallback` 已不存在于 option / transport 包中。
- 本历史中的 HTTP/3 客户端相关工作面向的是当前产品已不再发布的客户端。

仍然保留的 HTTP/3 工作仅限于服务端 listener 及其请求处理。

Apple / iOS / macOS 客户端工作、Linux client-full 与 Windows client profile
均不属于当前产品；当前产品只有 Linux amd64 VPS server。

## Maintenance Notes

- **上游同步** —— 从上游 `testing` rebase/merge；fork 改动尽量集中在新增文件、
  option 解析、注册表与 build tag，以缩小冲突面。见
  [`docs/FORK-DIFF.md`](docs/FORK-DIFF.md)。
  同步后务必核对 fork hardening 是否仍然存在于**生产调用路径**上，而不只是文件还在；
  最近一次同步（`c992b1fab0`）就是在这一步发现 `Contains` guard 与路由重叠检测丢失。
- **生产标签** —— 从 `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` 读取；
  脚本与 workflow 读同一个文件，避免漂移。README 不复制该值作为权威来源。
- **注册表改动** —— `include/registry_jiejie_server.go` 中的每一项注册都必须由生产
  拓扑 fixture（`release/jiejie-production-topology.json`）支撑；
  注册表审计测试会在漂移时报错。
- **sing 依赖 pin** —— `go.mod` 只有一个 `replace`，指向 fork
  `github.com/Piggy-Cat-bit-shadow/sing` 的 packet-batch-timeout 修复。
  这是有意保留的 pin，不要在同步时丢弃。
- **已知未验证项** —— 只保留当前仍然成立的项目：
  - **Google QUICHE MASQUE tunnel interop** —— 已 build / run 但未建立 interop：
    CONNECT-UDP 与 CONNECT-IP 为 EXECUTED-FAILED，root cause UNCONFIRMED；
    HTTP/3 transport 为 LOCAL PASS / runner INCONCLUSIVE-TIMEOUT。
    这不是“未测试”，也不是 PASS。
  - **CONNECT-IP live H3 Packet Too Big E2E（IPv6）** —— NOT-TESTED。
  - **真实 VPS / WAN**（含 PMTU、CGNAT、长时 soak、真实吞吐）—— NOT-TESTED。
  - **mobile NAT rebinding / CGNAT** —— NOT-TESTED，需要真实移动网络。

  MASQUE 的当前验证边界见上面的 `HTTP / MASQUE` → `当前剩余边界`，
  完整验收见 [`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md)。
  该文档区分 Part 1（本地 / CI 已确立，VPS 上只作回归）与 Part 2（只有真实 VPS 能确立），
  **Part 1 的结果不得报告为 Part 2 的结果**。

  以下项目此前列为 NOT-TESTED，现已由实测覆盖，不再属于未验证项：Native Naive 的
  HTTP/3 Caddy differential、已覆盖的 half-close 矩阵、MASQUE NAT rebinding /
  migration、MASQUE IPv6 路径、MASQUE 的 loss / duplicate / reorder 行为、
  Linux 真实 UDP socket 上的 batching。

  `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md`、`docs/JIEJIE-NAIVE-H3-AUDIT.md` 与
  `docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md` 的较早段落可能仍保留历史状态描述；
  与更新的测试、commit 及 Pre-VPS closure 冲突时，
  以当前代码、当前测试、当前 CI 与最新 closure 章节为准
  （`docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md` 顶部有明确的 `CURRENT STATUS` 表，
  其后全部为 HISTORICAL）。
- **详细文档** —— 架构与审计位于 [`docs/`](docs/)；
  `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md` 按组件说明验证状态。

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
