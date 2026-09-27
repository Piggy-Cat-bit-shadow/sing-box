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
| 其它 inbound | AnyTLS、ShadowTLS v3、Shadowsocks 2022 |
| outbound | `direct`、住户 SOCKS5 |
| DNS | `udp`、`local`（`box.go` 启动依赖） |

**这台 VPS 的代理能力不由一个 sing-box 进程全部承担**：

| 组件 | 负责 |
| --- | --- |
| **Jiejie sing-box Server Core** | 上表内容 |
| **Caddy** | NaiveProxy（`forwardproxy@udpintcp`，含 UoT v2） |
| **Xray** | VLESS Reality / Vision / XHTTP |

因此 **Native Naive 不属于 Server Minimal**（见 [AUD-P2-001](#aud-p2-001--native-naive-server-over-inclusion)）。
`protocol/naive` 源码保留，只是不进入本 profile 的 import graph。
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
| **Naive / Cronet** | macOS 客户端核心能力，需与 Caddy 侧实现互通 | 链接真实 Cronet（`cronet-go.NewNaiveClient`）；移除 client 上无用的 server-only H3 listener；新增 opt-in `insecure_concurrency_single_engine`（默认 `false`，**未验证**） | [审计](docs/JIEJIE-NAIVE-CLIENT-AUDIT.md) |
| **LXD** | JiejieBox 需要持久化 daemon + mTLS 控制面，GUI 退出后 VPN 不能断 | 移植 LXD daemon 能力进 macOS core（`lxd/`、`daemon/`、`cmd/sing-box/cmd_lxd_lx.go`）：`lxd --state-dir/--service`、`lxd client add/list/remove` | [macOS 客户端](docs/JIEJIE-MACOS-CLIENT.md) |
| **Server Minimal** | 面向单台 VPS 的最小化构建，registry 须与真实职责一致 | `include/registry_jiejie_server.go` 只注册 4 个 inbound；Native Naive 已移除 | [服务端](docs/JIEJIE-SERVER.md) |
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

### AUD-P2-001 — Native Naive Server over-inclusion

**Problem**
Server Minimal 仍注册并链接已退出生产的 Native Naive inbound，production fixture 也仍
描述它（`naive-in`、`28438`、`28439` 及 5 条 route rule）。NaiveProxy 已改由 Caddy 提供，
所以每个生产 binary 都多带一个从不启动的 listener、UoT 数据面与 HTTP/2 masquerade。

**Root cause**
注册与 fixture 都早于"NaiveProxy 迁到 Caddy"这一变化，未同步。属 fork 配置问题，
非 upstream 代码问题。

**Fix**
从 Server Minimal registry 移除 `protocol/naive` import 与 `naive.RegisterInbound`；
从 production fixture 移除 naive inbound 及全部相关 route rule（inbounds 6→5，rules 9→4）。

**Not changed**
`protocol/naive` 源码完整保留（23 个文件）——full registry、客户端测试、macOS Naive
仍在使用；macOS Cronet Naive outbound 完全不变。

**Verification**
- dependency graph：`protocol/naive` 已不在 619 个包中
- contract 测试改为断言 **absence**（`TestRegistryOmitsNativeNaive`、
  `TestProductionFixtureExcludesNativeNaive`），且在源码修改**之前**先失败
- runtime smoke PASS；pruning audit PASS（23 pruned / 5 required）；CI 全绿

**二进制影响（实测，like-for-like）** `33,870,008 → 33,767,608 B`（−102,400 B, −0.30%）。
**核心收益不是体积**，而是 contract correctness、attack surface 缩小、profile 与真实
生产职责对齐。0.30% 很小，如实记录。

**Commit** [`f043f6f39`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/f043f6f39)

**Status** CLOSED

---

<details>
<summary>Earlier audit records（CONNECT-IP · upstream merge · badhttp/XFF · 注释修正）</summary>

### Naive test decoupling

**Problem**
`TestJiejieNaiveSelfHostedWebRuleShapeMatchesProduction` 依赖已删除的
production naive fixture，因此在上面的清理后失败——它断言的 production 形状已不存在。

**Root cause**
该测试把"runtime 测试用的规则语义"和"production fixture 里存在 naive"绑在了一起。
前者仍然有价值（`protocol/naive` 仍在 full registry 中），后者已不成立。

**Fix**
抽取共享 `selfHostedWebRules()`，让 runtime test 与 shape test 验证**同一份规则定义**，
不再要求 production profile 存在 Naive。规则**顺序**（security 属性）继续断言。

**Verification**
- 交换 deny / rewrite 顺序 → 测试真实失败并给出原因
- 整个 jiejie suite 在 production minimal tags 下首次全绿（56.6s）
- 无测试为满足自身而把 Native Naive 加回生产 registry

**Commit** [`3d873c4f5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/3d873c4f5)

**Status** CLOSED

---

### CONNECT-IP target audit（相邻路径完整审计）

**Problem**
`ecdc966ab` 已修复 target 分类器不接受反斜杠的问题。本轮目标：确认**相邻解析路径**
没有被同一问题绕过。

**Root cause（历史修复）**
分类器拒绝 `:` 与 `/`，但不拒绝 `\`，于是 `/masque?target=a\b` 产出 `Domain = "a\b"`。
实测无 traversal / injection（Go resolver 视为未知主机），属 validation gap 而非可利用逃逸。

**Fix（历史）** `ContainsAny(target, ":/")` → `ContainsAny(target, ":/\\")`。

**Verification（本轮）**
完整链路：request → `EscapedPath` → regex 捕获（仍是转义态）→ **一次** `PathUnescape`
→ 分类器 → `Scope.Domain` → **原样**传入 `dnsRouter.Lookup`。

- raw 与 single-encoded 分隔符 → **拒绝**
- double/triple-encoded → 接受为**字面 percent 序列**（`a%252Fb` → `a%2Fb`，不含分隔符），
  实测惰性且正确
- 只有**一次** `PathUnescape`，下游不再 decode
- 全链路无 `path.Clean` / `filepath.Clean`（不存在 filesystem 与 URL 语义分歧）
- `parseAuthority` 23 个对抗输入 → 0 panic

**结果** `NO ADJACENT BUG FOUND`。新增
`TestTemplateEncodingMatrixIsTheWholeAttackSurface` 与 `TestTemplateNeverDecodesTwice`
防止未来引入 double decode；注入该缺陷后两者均真实失败，`template.go` 未改动。

**Commits** [`ecdc966ab`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/ecdc966ab)（历史修复）、
[`b3218f340`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3218f340)（审计回归测试）

**Status** PASS / CLOSED

---

### Upstream merge-conflict per-function audit

**Problem**
历史上多次 upstream merge 都做过人工 conflict resolution，需确认没有覆盖掉 upstream 修复。

**Method** `git show --remerge-diff` 找出真正发生人工 resolution 的文件（而非仅凭 commit
message 推断），再逐个函数比对 merge-base / upstream / 当前 fork。

**结果** 3 个 upstream merges · **77** 个真实 conflict-resolution 文件（其中 **38** 个在
priority path）· `common/badhttp`、`transport/http`、`transport/masque` 均完成**完整逐函数**
比对。

**关键事实** `upstream/testing == merge-base`，即 upstream 自 base 以来**没有任何新 commit**，
因此不存在"未吸收的 upstream 修复"。

**结论** `Lost upstream fix: NO`

本轮保留的 fork fixes（均为 fork 自己引入，且经 revert 验证）：`common/badhttp` XFF
hardening、`transport/http` deferred activation（延迟 200 OK 至 target setup 完成）、
`transport/masque` memcpy removal。

**Status** PASS / CLOSED

---

### badhttp / XFF hardening

**Problem**
MASQUE 与通用 HTTP inbound 曾通过 `badhttp.ForwardedSource` 解析 source，取
`X-Forwarded-For` 的第一个有效项。任何能连上 listener 的客户端都能借此选择
`metadata.Source` —— 而它参与 `source_ip_cidr` 路由规则、unauthenticated limiter、
日志与审计。

**Root cause**
`ForwardedSource` 被放在默认路径上，而两个部署都没有可校验该 header 的前端
（Nginx Stream 在 L4 转发、不添加该 header；HTTP/3 直接终结 QUIC）。

**Fix**
H2 / H1 的 tunnel 与 proxy 共 4 个调用点改用传输层 peer（H3 用 QUIC peer，否则
`request.RemoteAddr`）。新增 `PeerAddress`；`SourceAddress` 改为返回 peer；
`ForwardedSource` 保留并标记 deprecated。

**Verification**
- revert 该修改 → 伪造地址重新进入 `metadata.Source`，测试失败
- 覆盖单条 / 多条 / 畸形列表 / `Forwarded`(RFC 7239) / `X-Real-IP` / 全部同时 /
  IPv6 值
- 本轮另确认：live MASQUE path（`transport/http/server_h2.go`）**不依赖**
  `badhttp.SourceAddress`

**Commit** [`a3cb8abf5`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/a3cb8abf5)

**Status** CLOSED

---

### Naive inbound 注释修正

**Problem**
`protocol/naive/inbound.go` 的安全说明中有一句支撑性事实错误：
声称 `badhttp.SourceAddress` "has no other caller in this repository"。实际有 6 个。

**Root cause**
该注释在思考 merge conflict 时写下，未复查。

**Fix**
仅修正注释：列明真实 callers，并说明该 helper 已被本 fork 硬化（同样不读 XFF），
且 Naive 直接读 `RemoteAddr` 的真正原因（需要在 hijack 之前取地址）。
**安全决策本身未变。**

**Verification** 逐个检查全部非测试调用点；与 `upstream/testing` 比对 helper 语义。

**Commit** [`b3a1f53db`](https://github.com/Piggy-Cat-bit-shadow/sing-box/commit/b3a1f53db)

**Status** CLOSED

---

</details>

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
