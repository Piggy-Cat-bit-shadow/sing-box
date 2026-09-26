# Jiejie Server Edition

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的个人服务端 fork。

- 上游分支：`testing`
- 产品范围：Linux amd64 服务端
- 生产 profile：`jiejie_server_minimal`
- 详细设计文档：[`docs/`](docs/)

## Upstream

| 项目 | 值 |
| --- | --- |
| 上游仓库 | https://github.com/SagerNet/sing-box |
| 跟踪分支 | `testing` |
| fork 基线 | `b609f959f5` |
| fork 版本 | `1.15.0-jiejie-masquerade.5` |

本仓库跟踪上游 `testing` 分支，并维护一组服务端改动。协议实现、路由、DNS、TLS
和传输层均来自上游；本仓库增加的是部署相关的服务端行为、注册表裁剪与验证。

MASQUE Pre-VPS code-closure baseline：`864be35e`（不是 README 更新后的 current HEAD，
只是本轮代码收口的基线 commit）。

## 当前状态

| 项目 | 状态 |
| --- | --- |
| Native Naive | Caddy / forwardproxy reference parity、H1 / H2 / H3、Padding、half-close、ALPN、认证与资源边界均已有实测覆盖 |
| MASQUE HTTP/2 / HTTP/3 | Pre-VPS code closure 已完成；代码侧与 CI 侧无已知 blocker |
| MASQUE CONNECT-UDP | production minimal 的实际发布路径；H2 / H3 均有运行测试与 reference interop |
| MASQUE CONNECT-IP | 有 full-registry reference / protocol 验证；不是当前 production minimal 发布的 endpoint |
| 当前阶段 | 下一步为 Linux amd64 VPS 实机验收 |
| 实机结果 | NOT-TESTED；本地 / CI 的 PASS 不等于 VPS PASS |

上述状态只描述代码与测试能证明的范围。真实 VPS 尚未验收，因此这里不使用
“production ready”一类的结论。

## 构建产物

CI 会产出两个 GitHub Actions artifact，用途完全不同：

| Artifact | 用途 |
| --- | --- |
| `Jiejie-VPS-linux-amd64-<version>-<sha>` | 真正用于 Linux amd64 VPS 部署的生产 minimal 二进制 |
| `naive-caddy-parity-<sha>` | Native Naive 与 pinned Caddy / forwardproxy reference 做差分测试后生成的 CI 报告 |

`naive-caddy-parity-<sha>` **不是** Caddy binary，不是代理程序，也不是 VPS 部署程序。
它只包含：

```text
naive-caddy-parity.json
naive-parity.log
```

部署 VPS 时只需要 `Jiejie-VPS-linux-amd64-*`；`naive-caddy-parity-*` 仅用于兼容性审计与追溯。

artifact 名称中的 `<version>` 与 `<sha>` 随构建 commit 变化，不写死。

## 构建范围（Build Scope）

面向 Linux amd64 的服务端最小化构建。裁剪发生在**注册层面**：minimal registry
不 import 未使用的包，链接器随之丢弃。上游完整构建仍然可用，位于
`include/registry.go`（`!jiejie_server_minimal`）。

生产构建标签：

```text
with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0
```

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

注意：Native Naive 的 **inbound 保留**，被排除的只是 Naive outbound 与客户端运行时。

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
| CONNECT-IP | PASS（已有 full-registry reference / protocol evidence） | 不是 production minimal endpoint |
| HTTP Datagram / Capsule fallback | PASS | CONNECT-UDP / CONNECT-IP 均有覆盖 |
| IPv4 / IPv6 | PASS（已有对应测试范围内） | CONNECT-UDP production path 已覆盖 IPv6 |
| NAT rebinding / impairment | PASS（受控测试环境） | 真实 WAN 仍待 VPS 验收 |
| Google QUICHE | CHECKED (protocol vectors) | 没有 build / run，不是 interop PASS |
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
  状态是 **CHECKED (protocol vectors)**：读取 pinned 源码并固定其 decision table 与
  unit vectors；没有 build、没有 run、没有 live interop，
  因此不是 QUICHE PASS，也不是 QUICHE interop PASS。
- `0dbfc43d1e` — 记录 QUICHE vector check 的分类，并把 RFC 9931 client-side half
  重新分类。
- `4db6f90f98` — RFC 9931 client-side half 对当前 server-only product 归类为
  OUT-OF-SCOPE。
- `583bfc84f3` — QUICHE oracle tests 真正进入 reference CI 的 run filter。
- `864be35ebc` — 把 linearity regression test 改为抗 shared-runner noise 的
  ratio / 最小值测量。这是 TEST fix，不是 production performance optimization。

#### 当前剩余边界

- **Google QUICHE live interop** — NOT-TESTED。当前只有 protocol-vector CHECKED。
- **CONNECT-IP live H3 Packet Too Big E2E** — NOT-TESTED。
  PTB generation 已测试；真实 `DatagramTooLarge` E2E 仍缺少合适的 asymmetric origin。
- **Real VPS / WAN behaviour** — NOT-TESTED。
  下一步按 `docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md` 验收。
- **RFC 9931 client-side half** — OUT-OF-SCOPE-FOR-SERVER-PRE-VPS。
  production minimal 不发布 MASQUE client endpoint。

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

reference suite 另有一个 coverage guard：在 `test/jiejie/reference` 中定义但没有被
`-run` filter 匹配到的测试，会让 CI fail，而不是静默跳过。

生产 artifact 只在
`lint-and-unit-tests`、`production-minimal-integration`、`build-production`
三个 job 全部通过后才发布。

注意：`naive-caddy-parity` 是 CI compatibility report artifact，不是生产 artifact。

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
| [`docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md`](docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md) | MASQUE reference audit，含 Phase 1/2/3 与 Pre-VPS closure |
| [`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md) | 下一步 VPS 实机验收 checklist；区分 local / CI evidence 与 only-real-VPS evidence |
| [`docs/JIEJIE-NAIVE-H3-AUDIT.md`](docs/JIEJIE-NAIVE-H3-AUDIT.md) | Native Naive H3 / QUIC 对照 reference 的审计 |
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
- **生产标签** —— 从 `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` 读取；
  脚本与 workflow 读同一个文件，避免漂移。
- **注册表改动** —— `include/registry_jiejie_server.go` 中的每一项注册都必须由生产
  拓扑 fixture 支撑；注册表审计测试会在漂移时报错。
- **已知未验证项** —— 只保留当前仍然成立的项目：
  - **Google QUICHE live interop** —— NOT-TESTED。只有 protocol-vector CHECKED；
    QUICHE 未 build、未 run。
  - **CONNECT-IP live H3 Packet Too Big E2E** —— NOT-TESTED。
  - **真实 VPS / WAN** —— NOT-TESTED。

  MASQUE 的当前验证边界见上面的 `HTTP / MASQUE` → `当前剩余边界`，
  完整验收见 [`docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`](docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md)。

  以下项目此前列为 NOT-TESTED，现已由实测覆盖，不再属于未验证项：Native Naive 的
  HTTP/3 Caddy differential、已覆盖的 half-close 矩阵、MASQUE NAT rebinding /
  migration、MASQUE IPv6 路径、MASQUE 的 loss / duplicate / reorder 行为。

  `docs/JIEJIE-PRODUCTION-PROTOCOL-MATRIX.md` 与 `docs/JIEJIE-NAIVE-H3-AUDIT.md`
  的较早段落可能仍保留历史 NOT-TESTED 描述；与更新的测试、commit 及 Pre-VPS closure
  冲突时，以当前代码、当前测试、当前 CI 与最新 closure 章节为准。
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
