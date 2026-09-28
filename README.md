# Jiejie sing-box

基于 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) 的长期维护 fork，围绕
**Linux Server Minimal**、**macOS Client**、**MASQUE**、**Naive/Cronet**、**LXD**，
以及一组经过验证的 correctness / performance 修复。

本 README 同时是一份**工程状态说明 + 修复台账**。目标是：只读这一页，就能知道这个
fork 为什么存在、当前发布什么、改过哪些关键问题、根因是什么、怎么验证、哪些仍未验证。

---

## 1. Current State

```text
Branch          testing
HEAD            747ca9e3d
JIEJIE_VERSION  1.15.0-jiejie-masquerade.6
Upstream base   710d7c715  (SagerNet/sing-box testing)
Upstream ahead  0 commits  (merge-base == upstream/testing)
```

| Profile | Platform | Size | Tags |
| --- | --- | --- | --- |
| Linux Server Minimal | `linux/amd64`, CGO=0 | **33,767,608 B** | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` |
| macOS Client | `darwin/arm64`, CGO=1 | **76,819,250 B** | `with_gvisor,with_quic,with_utls,with_clash_api,with_naive_outbound,with_lxd,jiejie_client_macos,badlinkname,tfogo_checklinkname0` |

CI（最近一次实测）：

```text
Linux fast   ✅  ~49s
macOS fast   ✅  ~148s
Linux deep   ✅  ~385s
macOS deep   ✅  ~418s
```

### Audit Status

| Severity | Open |
| --- | ---: |
| P0 | 0 |
| P1 | 0 |
| P2 | 0 |
| P3 | 0 |

`SUSPECTED: 0`

**No open findings from the current audit cycle.** 这不等于"没有 bug"，只表示本轮审计
（源码调用链、build tags、registry、dependency graph、final binary、tests、benchmark）
未留下未关闭的发现。

`External validation pending: 1`

- **Cronet engine A/B**（`insecure_concurrency_single_engine`）——
  `NEEDS_AUTHORIZED_BENCH_SERVER`，见 [§6](#6-known--unverified-items)。

---

## 2. Product Profiles

### Linux Server Minimal

只注册该 VPS 拓扑真正使用的组件：

| 类别 | 内容 |
| --- | --- |
| MASQUE L4 | HTTP CONNECT、CONNECT-UDP、HTTP/3 主路径、HTTP/2 fallback |
| 其它 inbound | **Native Naive**、AnyTLS、ShadowTLS v3、Shadowsocks 2022 |
| outbound | `direct`、住户 SOCKS5 |
| DNS | `udp`、`local`（`box.go` 启动依赖） |

**这台 VPS 的代理能力不由一个 sing-box 进程全部承担**：

| 组件 | 负责 |
| --- | --- |
| **Jiejie sing-box Server Core** | 上表内容，**含 NaiveProxy 服务端（Native Naive inbound）** |
| **Xray** | VLESS Reality / Vision / XHTTP |

**Native Naive 是本 profile 的正式生产能力，不是兼容性补丁。** 它是本部署的
NaiveProxy 服务端：TCP/443 经 Nginx Stream 按 SNI 送达该 inbound。`protocol/naive`
承载大量 fork-specific 工作（UoT v1/v2、HTTP/1.1/H2 兼容、padding、Web masquerade、
target ACL / SSRF hardening、ALPN isolation、H2 资源控制、生命周期与 half-close 修复），
全部编入本 profile。见 [Native Naive 服务端](docs/JIEJIE-NAIVE-SERVER.md)——该文档明确描述
其 **without Caddy** 的拓扑。

**Caddy 不是当前 NaiveProxy 数据面。** 历史迁移文档
[JIEJIE-NAIVE-MIGRATION.md](docs/JIEJIE-NAIVE-MIGRATION.md) 中的 "Caddy" 一律指
**迁移前的旧后端或回滚目标**，已标记为 HISTORICAL / MIGRATION COMPLETED。

只注册 Naive **inbound**；Naive **outbound** 与 Cronet 客户端栈仍不进入本 profile 的
import graph（`protocol/naive/outbound.go` 自带 `with_naive_outbound` tag，本 profile 不设置）。
"需要 Native Naive inbound" 与 "with_naive_outbound" 是两个不同概念。
MASQUE 在本产品中是 **L4 HTTP proxy 模型**（`type: http`），不是 `masque-*` L3 endpoint。

### macOS Client

原生 CLI core，主推 **JiejieBox GUI → mTLS → `sing-box lxd` daemon**；同时支持 CLI
直接运行、浏览器 Web Dashboard、被第三方 GUI 当作外部 core 加载。

| 类别 | 内容 |
| --- | --- |
| 平台 / 传输 | TUN/gVisor、QUIC、uTLS、Cronet |
| 数据面 | Naive/Cronet、MASQUE client |
| inbound | `tun`、`mixed`、`socks`、`http`、`direct` |
| outbound | Shadowsocks / SS2022、ShadowTLS、Snell、Trojan、VLESS、VMess、AnyTLS、Hysteria2、TUIC、HTTP、SOCKS、`direct`、`block`、`selector`、`urltest` |
| DNS | UDP、TCP、DoT、DoH、DoQ、DoH3、local、hosts、FakeIP |
| 管理面 | native API、Clash API、LXD daemon |
| 明确不含 | `masque-server`、Native Naive server、Tailscale / WireGuard / OpenVPN / OpenConnect / Tor / SSH |

---

## 3. Fork-Specific Changes

相对 upstream，这个 fork 改了什么，以及为什么。

| 领域 | 为什么存在 | 主要差异 | 文档 |
| --- | --- | --- | --- |
| **MASQUE / HTTP** | 本 fork 唯一自研的 L4 数据面，server 与 client 共用实现，只用 registry 区分角色 | client/server endpoint 注册拆分；H3 datagram ingress 去 memcpy；hot path 改 immutable snapshot；CONNECT-UDP 竞态修复 | [性能](docs/JIEJIE-MASQUE-PERFORMANCE.md) · [参考审计](docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md) |
| **Naive / Cronet** | macOS 客户端核心能力，需与服务端 Native Naive 实现互通 | 链接真实 Cronet（`cronet-go.NewNaiveClient`）；移除 client 上无用的 server-only H3 listener；新增 opt-in `insecure_concurrency_single_engine`（默认 `false`，**未验证**）。注意：`protocol/naive` **同时**包含真实的服务端实现（`inbound.go`），不是纯客户端/测试代码 | [审计](docs/JIEJIE-NAIVE-CLIENT-AUDIT.md) · [服务端](docs/JIEJIE-NAIVE-SERVER.md) |
| **LXD** | JiejieBox 需要持久化 daemon + mTLS 控制面，GUI 退出后 VPN 不能断 | 移植 LXD daemon 能力进 macOS core（`lxd/`、`daemon/`、`cmd/sing-box/cmd_lxd_lx.go`）：`lxd --state-dir/--service`、`lxd client add/list/remove` | [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) |
| **Server Minimal** | 面向单台 VPS 的最小化构建，registry 须与真实生产配置一致 | `include/registry_jiejie_server.go` 注册 5 个 inbound：HTTP/MASQUE、AnyTLS、**Native Naive**、ShadowTLS v3、SS2022；Naive outbound 不注册 | [服务端](docs/JIEJIE-SERVER.md) |
| **macOS Client** | 一个内核包含全部客户端能力，不分 lite/naive | 独立 registry；`masque-client` 只注册 client 角色 | [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) |
| **CI / build** | 每个 CI 分钟都应产生新的故障信息 | 两 workflow、单 job、单 build；fast 只验证 shipping artifact，deep 保留 vet/race/fuzz/reference/reproducibility | [构建 profile](docs/BUILD-PROFILES.md) |
| **Dependency fork** | 需要 upstream 尚未吸收的 patch | `go.mod` 中 `replace github.com/sagernet/sing => github.com/Piggy-Cat-bit-shadow/sing` | [§8](#8-upstream) |

---

## 4. Repair / Audit Ledger

统一格式：Problem / Root cause / Fix / Verification / Commit / Status。

`Status` 取值：`CLOSED` · `PASS` · `NOT TESTED` · `BLOCKED EXTERNALLY`。

### AUD-P1-001 — Fork prerelease 被误判为 stable

**Problem**
`1.15.0-jiejie-masquerade.6` 被 deprecated checker 当成 stable release。带后缀的开发
版本下，任何 removal schedule 已过期的 note 都会触发
`panic: invalid deprecated note: missing-domain-resolver`，可直接杀死 root daemon。

**Root cause**
`badversion.Parse()` 只对 `-<name>.<digits>` 形式的 prerelease 填充
`PreReleaseIdentifier`；自定义 suffix 使其**留空**，而 `Impending()` 恰好用
`PreReleaseIdentifier == ""` 判断 stable。三个 scheduled 在 1.14.0 的 note 因
`versionMinor = 14-15 = -1` 全部 panic。upstream 不受影响——它发布 `1.15.0-beta.N`。

**Fix**
只在 `Impending()` 内改用标准 SemVer 判断稳定性
（`semver.Prerelease("v"+C.Version) == ""`），**不修改** `badversion.Parse()` 的全局语义。
panic 未削弱：真实 stable 版本仍会 panic。

**Verification**
- `1.15.0-jiejie-masquerade.6` → 不再 panic（修复前 panic）
- `1.15.0-beta.1`、`1.15.0-alpha.7`、`unknown` → 不 panic
- `1.15.0` 真 stable → invariant 仍触发 panic
- 打上真实 version stamp 的 binary：`check` 由 panic 变为正常报错
- fast / deep CI 通过

**Commit** [`7756ee514`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/7756ee51443e75f263f1a94d69f7ee6ab00e49a6)

**Status** CLOSED

---

### AUD-P2-001 — Native Naive incorrectly removed from Server Minimal  ❌ 结论已被推翻

> **此审计的结论是错误的，且已被 `f043f6f39` 实际执行、造成生产故障。**
> 保留此记录是为了留下一份"错误审计"的样本：它展示了错误的拓扑假设如何被
> 固化成契约测试，进而让 CI 认证一个无法启动的二进制。
> 当前正确状态见 [AUD-P2-002](#aud-p2-002--server-minimal-错误移除生产所需的-native-naive-inbound)。

**Problem（当时的主张）**
Server Minimal 注册并链接了 Native Naive inbound，production fixture 也描述它。
当时主张 NaiveProxy 已改由 Caddy 提供，因此该 listener、UoT 数据面与 HTTP/2
masquerade 属于"从不启动的多余组件"。

**Root cause（真正的根因）**
审计依据的是**错误/过期的生产拓扑假设**："Caddy 已取代 Native Naive"。

该假设与真实部署不符，也与本仓库中长期维护的 Native Naive 服务端实现相矛盾——
`protocol/naive/inbound.go` 是真实的服务端实现，`docs/JIEJIE-NAIVE-SERVER.md`
明确描述其 **without Caddy** 的拓扑，仓库内还有 52 个专项 Naive 测试文件。

换言之：**审计把一个正在生产使用、且经过大量专项优化的能力，判定成了死代码。**

**Impact**
发布的 Server Minimal 二进制拒绝真实生产配置：

```
FATAL decode config: inbounds[5]: unknown inbound type: naive
```

**Fix**
在 production Server Minimal profile 中恢复 Native Naive 注册；把 Native Naive
恢复到 production fixture contract；并让 CI 在它再次被移除时失败。

**关于 −102,400 B 体积结果**
该测量本身是真实的（like-for-like，`33,870,008 → 33,767,608 B`），但**必须明确**：

> 这是一次建立在错误生产拓扑假设上的裁剪实验，
> **不是有效的生产优化成果。**

当时"核心收益不是体积，而是 contract correctness、attack surface 缩小"的论述
**方向恰好相反**：移除 Native Naive **破坏**了 production contract，
使 CI 认证了一个无法启动真实生产的二进制。体积收益 −102,400 B 远不足以抵消该后果
（恢复成本约 +106,496 B）。

同样不能用"移除 Native Naive 缩小了 attack surface"来论证：它移除的是一个
**在生产中实际接收 TCP/443 流量的** listener，不是不可达代码。

**Not changed（当时唯一做对的部分）**
`protocol/naive` 源码未被删除，因此本轮恢复无需重写实现。这一点值得保留：
**审计结论是错的，但它没有破坏实现本身。**

**Commit** [`f043f6f39`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f043f6f39)

**Status** ❌ REVERSED — 结论错误，已由 AUD-P2-002 恢复

---

### AUD-P2-002 — Server Minimal 错误移除生产所需的 Native Naive inbound

**Problem**
最新上传的 Linux Server Minimal 二进制（`1.15.0-jiejie-masquerade.6`）在真实美国 VPS 上
执行 `check` 失败：

```
FATAL decode config: inbounds[5]: unknown inbound type: naive
```

**Root cause**
`include/registry_jiejie_server.go` 不注册 Native Naive inbound，且
`release/jiejie-production-topology.json` 被改写为不含 `naive` inbound。
两者都基于同一个错误推断："Caddy 的 `forwardproxy@udpintcp` 已替代 Native Naive 用法"。

**该推断与事实不符。当前生产 NaiveProxy 服务端就是 sing-box Native Naive inbound，
不是 Caddy。** TCP/443 经 Nginx Stream 按 SNI 送达该 inbound；Caddy 不是当前
NaiveProxy 数据面。这一点有仓库自身证据支持：`protocol/naive/inbound.go` 是真实服务端
实现，`docs/JIEJIE-NAIVE-SERVER.md` 明确描述 **without Caddy** 的拓扑，
`docs/JIEJIE-NAIVE-MIGRATION.md` 是一次已完成的迁移（原先正是 Caddy → Native Naive）。

更严重的是，移除时把 contract 测试从"断言存在"倒转为"断言不存在"
（`TestRegistryOmitsNativeNaive`、`TestProductionFixtureExcludesNativeNaive`），
于是 CI 无法再发现该缺失，反而**认证**了一个无法启动真实生产的 binary。

**性质澄清**
本次不是"为了让旧配置能 check 而临时恢复兼容性"。Native Naive 是 Server Minimal
**正式的生产核心能力**，与 MASQUE、AnyTLS、ShadowTLS、SS2022 同级，且承载大量
fork-specific 优化（UoT v1/v2、padding、masquerade、target ACL / SSRF hardening、
ALPN isolation、H2 资源控制、生命周期与 half-close 修复）。本轮**只修 registry 与文档
描述，未修改、未回退 `protocol/naive` 的任何实现**。

**Impact**
新二进制无法解析当前生产配置，服务端无法启动。生产配置本身没有错，也不需要修改。

**Fix**
- `include/registry_jiejie_server.go`：恢复 `protocol/naive` import 与
  `naive.RegisterInbound(registry)`，inbound 入口 4 → 5。
- `release/jiejie-production-topology.json`：恢复生产 `naive` inbound（tag `naive-in`、
  `127.0.0.1:28438`、HTTP/2 receive window、example 凭据、TLS、masquerade）及 4 条
  代表真实语义的 route rule。**未**恢复已退役的 UoT 端口 28439，使 fixture 与当前生产一致。
- contract 测试从断言 absence 翻转为断言 presence，并命名生产原因。

**未恢复**
Naive **outbound** 仍不注册。`protocol/naive/outbound.go` 与 `single_engine_option_test.go`
自带 `with_naive_outbound` tag，而 inbound 侧无 tag，因此恢复 inbound 不需要该 tag，
`BUILD_TAGS_JIEJIE_SERVER_MINIMAL` 不变；`go list -deps ./cmd/sing-box` 确认 cronet 为 0。
socks / direct / mixed / tun / vless / vmess / trojan / hysteria2 / tuic 等仍未注册，
未回退为 upstream full registry。

**Verification**（全部使用真实 `jiejie_server_minimal` tag 集，非 full build）
- 复现：修复前二进制对生产形状配置报 `inbounds[5]: unknown inbound type: naive`
- `sing-box check` 完整 production fixture：**PASS**（rc=0）
- `TestRegistryProvidesNativeNaiveInbound`：registry 提供 `naive`；移除注册后该测试失败，
  并复现 VPS 上的同一条 FATAL
- `TestProductionFixtureDeclaresNativeNaive`：fixture 声明 naive inbound、tag、端口与
  receive window；且 28439 未被恢复
- `TestRegistryAuditFindsTheExpectedSet` 额外显式断言 naive **outbound** 不在生产 topology 中
- 住宅 SOCKS 优化未回归：`protocol/socks`、`route`、`option` 全部 PASS；
  `tcp_preconnect` / `tcp_tuning` / `ConnectionCopyTuner` / early buffer growth 均保留
- 依赖裁剪审计 PASS；契约测试 12/12 PASS

**二进制影响（实测）** `33,792,184 → 33,898,680 B`（**+106,496 B, +0.315%**）。
恢复生产协议必然变大；优先级为 **production correctness > binary size**。

**Commit** 本记录所在提交

**Status** CLOSED

---

### Secondary repair records

格式同上（Problem / Root cause / Fix / Verification / Commit / Status），此处压缩为表，
细节可用 `git show <commit>` 复核。

| Record | Problem | Root cause | Fix | Verification | Commit | Status |
| --- | --- | --- | --- | --- | --- | --- |
| **CI streamline** | fast path 重复编译 `./jiejie`、重复 binary audit、full jiejie suite 为 soft-fail、vet/reproducibility 放错层、fuzz 20s/target、upstream-default 检查不发布的产品 | CI 结构逐步叠加，未按"每 CI 分钟是否产生新故障信息"重划 | fast 只验证 shipping artifact；deep 保留 vet/race/fuzz/reference/reproducibility；contract 拆轻量 package；macOS capability 断言并入一次 `nm`；full jiejie 与 upstream-default 移出自动 CI（源码保留）；fuzz→5s | `Linux fast 147s→49s`、`macOS fast 258s→148s`、`Linux deep 3233s→385s`；contract/pruning 断言修改前先失败 | [`89819993c`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/89819993c)、[`d6df17231`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/d6df17231) | CLOSED |
| **CI concurrency collision** | 手动 `deep_checks=true` dispatch 与同 ref 的 push run 互相取消 | `concurrency.group` 只按 `github.ref` 区分，未含运行模式 | group key 加入 `deep`/`fast`；同模式 supersession 保留 | 实测 fast 与 deep 四者同时存活并全部通过；修复前相同操作会取消 fast | [`747ca9e3d`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/747ca9e3d) | CLOSED |
| **badhttp / XFF hardening** | source 经 `ForwardedSource` 取 `X-Forwarded-For` 首项，客户端可自选 `metadata.Source`（参与 `source_ip_cidr`、limiter、日志、审计） | 该 helper 位于默认路径，而两个部署都没有可校验该 header 的前端 | 4 个调用点改用传输层 peer；新增 `PeerAddress`；`SourceAddress` 返回 peer；`ForwardedSource` 保留并 deprecated | revert 后伪造地址重新进入 `metadata.Source` 且测试失败；覆盖单条/多条/畸形/RFC 7239/`X-Real-IP`/IPv6 | [`a3cb8abf5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a3cb8abf5) | CLOSED |
| **Naive inbound 注释修正** | 注释称 `badhttp.SourceAddress` "has no other caller"，实际有 6 个 | 该注释在思考 merge conflict 时写下，未复查 | 仅修正注释，列明真实 callers 与该 helper 已硬化这一事实；**安全决策未变** | 逐个检查全部非测试调用点；与 `upstream/testing` 比对语义 | [`b3a1f53db`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3a1f53db) | CLOSED |
| **Naive test decoupling** | shape 测试依赖已删除的 production naive fixture，清理后失败 | 把"runtime 规则语义"与"fixture 里存在 naive"绑在一起；前者仍有价值 | 抽取共享 `selfHostedWebRules()`，runtime 与 shape 测试验证同一份定义；规则顺序继续断言 | 交换 deny/rewrite 顺序 → 测试真实失败；jiejie suite 在 minimal tags 下首次全绿（56.6s） | [`3d873c4f5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3d873c4f5) | CLOSED |

### Product integrity & audit records

| Record | Method | Result | Status |
| --- | --- | --- | --- |
| **macOS product integrity** | 对最终 binary 逐一验证 registry / symbol / config / runtime | 5 inbound、15 outbound、`masque-client`、8 DNS transport、native API、Clash API、gVisor、uTLS、Cronet、LXD 全部链接且可解析；`masque-server` correctly pruned；Native Naive **server** correctly absent；XHTTP not in this tree | `over-pruning: NO` · `over-inclusion: NO` · PASS |
| **Server product integrity** | registry 与 dependency graph 对照真实生产职责 | `protocol/naive` 保留源码但不在 graph 中；profile 与生产职责一致 | `over-pruning: NO` · `over-inclusion: NO` · PASS |
| **Fuzz** | 13 targets；高风险 remote parser 全部检查 | `parseAuthority` 23 个对抗输入 → 0 panic；LXD admin plane 有 body 上限与 panic recovery；**No HIGH gap found**，故未新增 target | PASS |
| **Memory** | MASQUE hot path benchmark + `-race` lifecycle/ownership/shutdown | 相关 benchmark **0 allocs/op**；含显式 goroutine 累积与 queued buffer 释放断言；**本轮未发现已确认的 leak** | PASS |

上述 integrity 审计是"本轮未发现 over-pruning / leak"，不等于"绝对不存在"。

---

## 5. Performance Evidence

以下数字均已在本轮**重新复测**（同机、同 Go 版本、较晚 commit），不是从历史记录搬运。

| Claim | 历史 | 复测 | 结论 |
| --- | --- | --- | --- |
| `IngressBuffer` geomean | −56.69% | **−56.5%** | VERIFIED |
| `SessionConfigRead` | −95.25% | **−95.56%** | VERIFIED |
| mutex read (uncontended) | 94.065 ns | **91.935 ns** | VERIFIED |
| atomic snapshot read | 4.472 ns | **4.082 ns** | VERIFIED |
| mutex read (contended) | 105–112 ns | **105.5 ns** | VERIFIED |

> **这些是 MICROBENCHMARK（in-memory, ns/op），不是公网吞吐。** 本仓库不声称任何
> real-socket 或 real-VPS 吞吐量。方法与完整表格见
> [`docs/JIEJIE-MASQUE-PERFORMANCE.md`](docs/JIEJIE-MASQUE-PERFORMANCE.md)。

相关 commits：`9739c42a8` / `3b8d99a21`（H3 ingress 去 memcpy）、`6d94da584`（immutable
snapshot）、`01ae0d308` / `ec2b4b91e`（CONNECT-UDP 批处理与 connected UDP）、
`680f5d89d` / `6678bf348`（receive window 与 tunnel buffer）。

---

## 6. Known / Unverified Items

### Cronet engine A/B — NOT TESTED

`insecure_concurrency_single_engine`（**opt-in，默认 `false`**）允许 macOS 上让
`insecure_concurrency` 共享**一个** Cronet engine 而非启动 N 个。

```text
Status:   NOT TESTED
Reason:   NEEDS_AUTHORIZED_BENCH_SERVER
Default:  false (unchanged, upstream platform behaviour preserved)
```

**没有证据支持任何一种说法**：不能写"single engine 更快"，也不能写"multi engine 更快"。
二者在吞吐 / 延迟 / RSS / 线程数 / FD 上的差异**尚未测量**。

```bash
# 需要授权的 benchmark server；无授权 server 时脚本会明确拒绝并打印 NOT TESTED
./scripts/ci/bench-naive-cronet-engine.sh <server_host> [server_port]
```

### 其它

- **XHTTP**：当前 sing-box 树中不存在（VLESS XHTTP 由 Xray 承担）。
- **QUICHE live interop**：已从 CI 移除，**不应恢复**。

---

## 7. Build & Verification

```bash
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64

./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64
./scripts/ci/check-macos-client-config.sh  dist/sing-box-darwin-arm64 /tmp/cfg
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64
```

构建脚本从 `release/BUILD_TAGS_*` 读取 tag，profile 定义只有一处。config check 由
registry audit 内部调用（同时验证 fixture 与 `example-config.json`）。

**可复现性**：两个 profile 均可用 `-trimpath -buildvcs=false` 逐字节复现；macOS 连续
构建两次 SHA-256 一致（已实测）。

**CI 结构**：两个 workflow，各自**单 job、单 build**，之后所有检查复用同一 binary。

```text
.github/workflows/server-linux-amd64.yml   ->  sing-box-linux-amd64
.github/workflows/client-macos.yml         ->  sing-box-darwin-arm64
```

---

## 8. Upstream

同步 [SagerNet/sing-box](https://github.com/SagerNet/sing-box) `testing` 分支。

```text
Upstream base  710d7c715
Ahead          0 commits
```

即：当前 `upstream/testing` 与 merge-base 相同，fork 尚未落后于 upstream。

### Dependency fork（另一个仓库）

`go.mod` 依赖一个 fork：

```text
replace github.com/sagernet/sing => github.com/Piggy-Cat-bit-shadow/sing
```

该仓库中的关键 commit：

```text
d24028a609112cc5636bd123cb9a87f4691342eb
subject: control: add EnableUDPFragment
```

> ⚠️ **该 commit 属于 `Piggy-Cat-bit-shadow/sing`，不是本仓库。**
> <https://github.com/Piggy-Cat-bit-shadow/sing/commit/d24028a609112cc5636bd123cb9a87f4691342eb>

存在原因：upstream 尚未提供该 API，而上游同步后本仓库需要它。

面向用户的上游文档（配置格式、协议说明）仍然适用。

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
