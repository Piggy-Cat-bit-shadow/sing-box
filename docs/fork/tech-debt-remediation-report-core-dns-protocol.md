# JiejieBox 技术债务整改施工报告 —— 核心 / DNS / protocol 分册

> **施工代理：** 负责 `dns/**`、`protocol/**`（MASQUE/Tailscale/OpenVPN/OpenConnect/WireGuard 的
> keep-idle 方法除外）、`service/**`（oomkiller 除外）、`common/trafficcontrol/**`、
> `common/urltest/**`、`common/mux/**`、`option/**`，以及资源/缓存/状态类 TD 项。
> **未提交任何 commit**（按工单要求：工作树保持 dirty，由父代理统一提交/推送）。
> 本文件是分册；父代理可将其并入 `docs/fork/tech-debt-remediation-report.md`。

---

## 1. Git 与环境

| 项 | 值 |
|---|---|
| START_SHA | `6927861bf4659171561260dda7b18a0d6a326f8b` |
| origin/testing | `6927861bf4659171561260dda7b18a0d6a326f8b`（施工起点与远端一致） |
| Branch | `testing` |
| Toolchain / OS / arch | `go1.25.5 darwin/arm64`（`GOTOOLCHAIN=go1.25.5`） |
| TAGS | `release/DEFAULT_BUILD_TAGS`（含 `with_quic,with_xhttp,with_clash_api,...`） |
| Apple / Android 子模块 | `clients/apple` `+ddf444e`（dirty，未触碰）、`clients/android` `fc21909`（dirty，未触碰） |
| 施工前既有脏文件 | `M clients/android`、`M clients/apple`、`?? build-screens-doc.py`、`?? capture-screens.sh` —— **全部原样保留** |
| 施工期间他人在改的文件 | `.github/workflows/*`、`box.go`、`common/power/governor.go`、`common/sniff/**`、`experimental/libbox/**`、`route/network.go`、`route/reference.go`、`route/route.go`、`go.sum` 等 —— **未触碰** |
| 是否 push | 未 push（父代理负责） |
| 是否触发 Actions | 未触发（无 commit、无 push） |

施工期间 `common/sniff/tls.go` 一度处于他人半成品状态（`bufio` 重声明，编译失败），阻塞了
所有依赖 `route/` 的测试。我为不干扰他人而使用 `/tmp/tdmirror` 影子副本迭代，**最终全部证据
均在真实工作树上重跑**（见 §4）。

---

## 2. 项目状态总览

| TD | 状态 | 主要文件 | 关键证据 | 测试 |
|---|---|---|---|---|
| **TD-002** mixed/SOCKS early-data 首段字节与并发所有权 | **FIXED** | `protocol/mixed/inbound.go`、`protocol/socks/firstpayload.go`（新） | 旧实现 `-race` 报 `resolved`/`delegate` 竞争且第 0 轮丢整段载荷（`EOF (got 0/128 bytes)`） | `protocol/mixed/earlydata_ownership_test.go`（4 项，含 200 轮重复 + 真实 copy 循环） |
| **TD-016** early-data 缓冲所有权 / exactly-once 释放 | **FIXED** | `protocol/socks/firstpayload.go` | 旧实现 Close 路径永不归还池缓冲；直接改调 `CachedConn.Close()` 会与 sing 的非原子 `buffer` 字段竞争 | `protocol/socks/firstpayload_test.go`（9 项，含 200 轮 Read‖Close、capture‖Close） |
| **TD-007** SOCKS4 USERID 伪造身份 | **FIXED** | `protocol/socks/inbound.go` | RED：`SOCKS4 user id "alice" was promoted to metadata.User with no users configured` | `protocol/socks/inbound_identity_test.go`（6 项：no-users / verified / rejected / SOCKS5 回归） |
| **新发现（A1 同族）** 独立 SOCKS inbound 截断流水线首段 | **FIXED** | `protocol/socks/inbound.go` | RED：`read payload (one read): EOF (got 0/517 bytes)` ×3 子用例 | `protocol/socks/inbound_payload_test.go`（3 项，含 5 种分片） |
| **新发现（上游继承）** 成功握手即上报 `onClose` | **FIXED** | `protocol/socks/inbound.go` | RED：`onClose ran 1 times on a live session that was never closed`（`N.CloseOnHandshakeFailure` 在 err==nil 时也调用回调） | 同上（确定性断言于 `NewConnection` 返回后） |
| **TD-008/013** RDRC/exact/NXDOMAIN/持久键跨网串用 | **FIXED** | `dns/client.go` | RED：新网仍命中旧网缓存（`queries=1` 而非 2）、NXDOMAIN 跨网压制、远程 transport `environment == 0`（无命名空间） | `dns/cache_remote_environment_test.go`（4 项）+ `dns/cache_remote_environment_stress_test.go`（100 轮） |
| **TD-006** sticky_sessions 队列有界 + 重 pin 一致性 | **FIXED** | `protocol/group/loadbalance_strategy.go` | RED ①：旧实现队列 48 > 上限 32（每 key 一个历史节点，无界）；RED ②：`the fresh pin was evicted by its own stale queue node` | `protocol/group/loadbalance_affinity_test.go`（6 项，含 10 万步与参考模型对照） |
| **TD-025** 门禁保真度（本面） | **部分 FIXED** | `protocol/group/urltest_recheck_handoff_test.go` | 旧测试自行 `checking.Store(false)` 复位被测标志；改为真实 round 占用 guard | 重写 + 新增 TD-005 反证测试 |
| **TD-005** URLTest checking 误报 | **REFUTED**（原机制不成立） | `protocol/group/urltest.go` | `defer g.checking.Store(false)` 仅在 Swap 成功后注册，败者提前 return，结构上无法释放胜者 guard | `TestALosingPeriodicRoundDoesNotReleaseTheWinnersGuard` 固定该行为 |
| **TD-014** DNS 串行池并发惊群 | **INTENTIONAL（非缺陷）** | `dns/transport/conn_pool.go`（已回滚我的尝试） | 仓库自有 §8 契约测试要求并发查询**并行**（`GreaterOrEqual(connections, 2)`），与审计要求的"突发复用单连接"直接冲突 | `dns/transport/conn_pool_burst_test.go` 把现状测成契约（dials == burst、peak 建立并发 == 1、绝不复用同一连接给两个调用者） |
| **TD-020** Linux D-Bus signal loop 永驻 | **FIXED（代码）/ 运行验证 BLOCKED** | `dns/transport/local/local_resolved_linux.go` | 旧实现 `for signal := range signalChan` 且无人关闭该 channel、Close 既不 `RemoveSignal` 也不 join → 每实例一个不朽 goroutine | 无（本机无 system bus / 无 systemd-resolved，且包内没有可复用的 monitor fake；见 §8） |
| **TD-001** 网络 transition token 遗弃 | **部分遗留，已移交** | `route/network.go`（他方所有） | 见 §8.1 | 未施工 |
| **TD-003** iOS pause/wake 接线 | **REAL，已移交** | `clients/apple`（禁改）/ `build/apple-client-macos` / `experimental/libbox` | 见 §8.2 | 未施工 |
| **TD-010** MASQUE 正常拆除污染 Ready/日志 | **REAL，已移交** | `transport/masque/client.go`（他方 `transport/**` 面） | 见 §8.3 | 未施工 |
| **TD-011** OomKiller 自触发 GC | **REAL，已移交** | `service/oomkiller/timer.go`（他方所有） | 见 §8.4 | 未施工 |
| **TD-004 / TD-041/042 / TD-043/044** | **REAL，已移交** | `transport/http/**`、`test/go.mod`、`scripts/ci/**` | 见 §8.5–8.7 | 未施工 |

---

## 3. 重点正确性论证

### 3.1 TD-002 —— 首次使用必须 exactly-once 且有 happens-before

**生产调用路径（静态确认）**：`route/conn.go` 的 `NewConnection` 在拨号后同时启动两个 copy
goroutine；两侧都会在首个 transfer 完成时经 `refreshUnwrap()` 重新展开 wrapper 链：

- upload：`N.UnwrapCountReader(source)` 沿 `ReaderWithUpstream` 走到
  `FirstPayloadConn.ReaderReplaceable()`，随后同 goroutine 调 `Read()`；
- download：`N.UnwrapCountWriter(destination)` 沿 `WriterWithUpstream` 走到
  `WriterReplaceable()`，随后 `Write()`。

两侧的首次进入由**对端字节**驱动，彼此之间没有顺序或有互斥 → 旧实现中未同步的
`resolved`/`delegate` 会被两个 goroutine 无 happens-before 地写。

**RED（旧实现，真实树）**：

```text
WARNING: DATA RACE
Read at ... by goroutine 10:
  mixed.(*earlyDataConn).use()            protocol/mixed/inbound.go:258
  mixed.(*earlyDataConn).ReaderReplaceable()  inbound.go:324
Previous write at ... by goroutine 11:
  mixed.(*earlyDataConn).use()            protocol/mixed/inbound.go:259
  mixed.(*earlyDataConn).WriterReplaceable()  inbound.go:333
--- FAIL: TestEarlyDataFirstUseIsSerializedRepeatedly
    round 0: upload read: EOF (got 0/128 bytes)
```

即：不只是竞争报告，**第 0 轮就整段丢掉 early data**（客户端在握手同一段里发出的首段载荷）。

**FIX**：`use()` 改为 `sync.Once`（解析最多一次、结果即便为 nil 也视为已解析，并为所有后续
读者建立 happens-before），委托对象改为本仓库自有的 `protocol/socks/firstpayload.go`
（`FirstPayloadConn`），读/写能力分别回答：缓冲未消费时 `ReaderReplaceable()==false`（禁止
splice 越过未消费字节），`WriterReplaceable()==true`（写路径不因入站缓冲而退化）。

**GREEN**：`TestEarlyDataFirstUseIsSerialized`、`...Repeatedly`（200 轮）、
`TestEarlyDataCopyLoopsConservePayload`（真实 copy 循环双向、逐字节守恒、`bytesDelivered` 不超
过客户端写入量）全部通过，`-race -count=20` 通过。

### 3.2 TD-016 —— 池缓冲的所有权与"不能引入新竞争"

- 旧 `earlyDataConn.Close()` 走内嵌 `net.Conn`，因此 `reader.BufferedConn()` 产生的
  `*bufio.CachedConn` 永远不会被 Close：正常路径下缓冲在 `CachedConn.Read` 耗尽时归还，
  **提前关闭则一直不归还**（GC 可回收，但池缓冲不回池）。
- 直接"补上 `delegate.Close()`"是错的：`CachedConn.buffer` 是非原子字段，其 `Read` 与 `Close`
  并发即构成 sing 侧数据竞争（我无法修改 pinned 外部模块）。因此改为自有委托：
  - 互斥锁只保护缓冲字段，**绝不跨越 socket I/O**；`Close` 在锁内 swap 出缓冲后再释放并关 socket；
  - 释放点恰好一次：`Read` 排空、`WriteTo` 交出、`Close` 三者互斥；
  - `Close` **刻意不解析**（不 drain parser 的 reader）：Close 可能在握手仍在读时到达，
    drain 会让 parser 读到 EOF 并与之竞争。测试固定该契约：
    `close consulted the parser reader 0/0 times`。
- 半关闭能力透传：`CloseRead/CloseWrite/ReadFrom/WriteTo/Upstream` 全部转发，未以"消除 race"
  换取能力（测试 `TestFirstPayloadCapabilitiesAreForwarded`）。

**红色用例**：`TestFirstPayloadConcurrentReadAndCloseIsSerialized`（200 轮 Read‖Close，断言读到
的缓冲字节数只能是 0 或全长，且 buffer 恰好释放一次）、
`TestFirstPayloadCaptureRacingCloseDoesNotStrandTheBuffer`（200 轮 capture‖Close）。

### 3.3 TD-008/013 —— DNS 缓存的跨网隔离必须覆盖远程 transport

**逐层读/写键（施工前）**：

| 层 | 读键 | 写键 | 跨网隔离（旧） |
|---|---|---|---|
| exact cache | `dnsCacheKey{Question, transportTag, clientSubnet, environment}` | 同 | 仅对实现 `Environment()` 的 local/mdns/dhcp 生效；**远程 transport `environment==0`** |
| NXDOMAIN（按名） | `nxdomainKeyFrom(key)` | 同 | 同上（`environment` 字段存在但恒为 0） |
| RDRC（持久 verdict） | `rdrcNamespace(tag, environment)` | 同 | `environment==0` 时退化为纯 tag → **跨网共享** |
| 持久 exact cache | `persistentName()`（含 `environment` 后缀） | 同 | `environment==0` 时不加后缀 → **跨网共享** |
| singleflight | `dnsExchangeKey`（含 cacheKey） | — | 随 cacheKey 一起（受同样影响） |
| Fake-IP 映射 | 反向映射另按 generation 校验，ResetNetwork 时 Purge | — | 已有独立隔离（未改） |

**根因**：`Client.environmentHash()` 对非 `DNSTransportWithEnvironment` 直接返回 0；而
`Router.ResetNetwork` 已经为**每一个**已知 transport 重钉环境（`refreshTransportEnvironments`），
`NetworkManager` 也在每次真实切换时发布新指纹。缺的只是"远程 transport 也读这个 pin"。

**RED**（旧实现）：

```text
--- FAIL: TestRemoteTransportCacheDoesNotCrossNetworks
    expected: 2, actual: 1  (the answer cached on the previous network was served on the new one)
--- FAIL: TestRemoteTransportNegativeVerdictDoesNotCrossNetworks
    expected: 2, actual: 1  (the NXDOMAIN verdict from the previous network suppressed the query on the new one)
--- FAIL: TestRemoteTransportPersistentAndRDRCNamespacesFollowTheNetwork
    Should not be zero, but was 0 (a remote transport must carry the network it serves)
```

**FIX**：`environmentHash` 对无 `Environment()` 的 transport 返回**该 transport 的 pinned 网络
环境**；`finishCacheKey` 去掉"无 environment 即直接接受"的早退，使写入也受同一比较约束。键一律
取 pin（不是 manager 的当前值），因此不会把查询盖到 transport 尚未服务的网络上。

**GREEN**：4 项新测试 + 100 轮 reset 压力（跨网必须换答案、同网 reset 不得作废命名空间、
goroutine 数回落）全部通过，`./dns/...` 全绿。

### 3.4 两个新发现的正确性缺陷（审计未列，A1 同族）

1. **独立 SOCKS inbound 截断流水线首段**：`protocol/socks/inbound.go` 原本把
   `std_bufio.NewReader(conn)` 直接内联传参后丢弃，握手缓冲区里属于隧道的字节永久 stranded。
   RED：`read payload (one read): EOF (got 0/517 bytes)`（socks5 单段/内核分片、socks4 单段）。
   FIX：与 mixed 共用 `FirstPayloadConn`（reader 与 wrapper 共享）。
2. **成功握手即上报 onClose**：`N.CloseOnHandshakeFailure(conn, onClose, err)` 在 `err==nil` 时
   **仍会调用** onClose（见 pinned sing 源码），因此每次成功握手都把"仍在运行的会话"上报为已关闭；
   在 `inbound_detour` / TUN 链路上，这正是外层 flow 的关闭通知，owner 会在第一次调用时释放 flow。
   FIX：仅在 `err != nil` 时调用（与本仓库 mixed/anytls/route 的既有写法一致）。
   **同根因未修**：`protocol/shadowtls/inbound.go:120` 形状完全相同（上游逐字继承），需要
   shadowtls service 级测试桩，已列入 §8.8 移交。

### 3.5 pinned sing 模块中的竞争（外部，已移交）

`protocol/socks/lazy.go` 的 `responseWritten bool`：上传 goroutine 经
`ConnHandshakeSuccess` 的 defer 写，下载 goroutine 经 `WriterReplaceable()` 读，完全无同步。
在我的 copy-loop 测试中（未预先触发惰性响应时）`-race` 稳定命中：

```text
WARNING: DATA RACE
Write at ... by goroutine 10:
  sing/protocol/socks.(*LazyConn).ConnHandshakeSuccess.func1()  lazy.go:31
  ... LazyConn.Read()  lazy.go:72
Previous read at ... by goroutine 11:
  sing/protocol/socks.(*LazyConn).WriterReplaceable()  lazy.go:95
```

危害不止"竞争报告"：两个 goroutine 都可能读到 false，从而**各写一次 SOCKS 响应帧**，客户端流会
被重复的响应污染。修复需改 `github.com/Piggy-Cat-bit-shadow/sing`（另一仓库，pinned 版本）：
`responseWritten` 改为 `atomic.Bool` 或 `sync.Once`，随后 bump go.mod pin——属跨仓库决策，
本代理未改（禁止新增/私改依赖 fork，除非无其它修法；此处应由父代理决定）。

---

## 4. 测试清单（真实输出）

| 命令 | 结果 | 摘要 |
|---|---|---|
| `go build -tags "$TAGS" ./...` | **PASS（仅已知 libbox 链接失败）** | 唯一错误：`link: .../experimental/libbox: invalid reference to runtime.fwdSig`（工单允许） |
| `go test -count=1 -tags "$TAGS" ./...` | **仅 2 项失败，均非本分册** | ① `experimental/libbox [build failed]`（上述已知链接问题）；② `route` 的 `TestTheGovernorDrivesTheManagerThroughARealBoundary`（`route/reference_reuse_test.go:382`）——该测试文件在工作树中是 **untracked（`?? route/reference_reuse_test.go`）**，由并发施工的 Apple/生命周期代理正在编写，配套改动为 `M route/reference.go`、`M common/power/governor.go`；其 fake transport 与我的改动无交集。其余全部 PASS。 |
| `go test -race -count=1 -tags "$TAGS" ./protocol/mixed/... ./protocol/socks/... ./protocol/group/... ./dns/...` | **PASS（EXIT 0）** | 我改动的四个包族 |
| `go test -race -count=20 -tags "$TAGS" -run '<新测试>' ...` | **PASS（EXIT 0）** | 新测试 ×20 |
| `gofmt -l` | **干净** | 我改动的文件均无输出 |
| `go mod tidy -diff` | **go.mod 无变化；go.sum 有既有漂移** | 见 §8.10 |
| `GOOS=linux GOARCH={amd64,arm64} go build ./dns/transport/local/` + `go vet` | **PASS** | TD-020 改动的 linux 编译验证 |
| `go build ./...`（**无 tag**，TD-004） | **FAIL** | `transport/http`：`undefined: http3LifecycleTracer` / `classifyH3ErrorCode` / `h3ErrorExpected` |
| `bash scripts/ci/check-go-module-integrity.sh` | 未运行（CI 代理面） | 逻辑审查见 §8.6 |

改动规模（`git diff --stat` + 新文件）：

```text
 dns/client.go                                  |  39 +++++--
 dns/transport/local/local_resolved_linux.go    |  40 ++++++-
 protocol/group/loadbalance_strategy.go         | 107 ++++++++++++++---
 protocol/group/urltest_recheck_handoff_test.go | 128 ++++++++++++++++----
 protocol/mixed/inbound.go                      | 154 +------------------------
 protocol/socks/inbound.go                      |  53 ++++++++-
 6 files changed, 316 insertions(+), 205 deletions(-)

新增（生产）：protocol/socks/firstpayload.go (279)
新增（测试）：protocol/socks/{firstpayload_test,harness_test,inbound_identity_test,inbound_payload_test}.go (1044)
            protocol/mixed/earlydata_ownership_test.go (248)
            protocol/group/loadbalance_affinity_test.go (345)
            dns/transport/conn_pool_burst_test.go (275)
            dns/cache_remote_environment_test.go (299) + ..._stress_test.go (110)
```

### 4.1 红/绿对照（每条均已构造）

| 项 | OLD（RED，原文摘录） | NEW（GREEN） |
|---|---|---|
| TD-002 | `WARNING: DATA RACE ... earlyDataConn.use() ...`；`round 0: upload read: EOF (got 0/128 bytes)` | 4 项通过，`-count=20 -race` 通过 |
| SOCKS early data | `read payload (one read): EOF (got 0/517 bytes)` ×3 | 5 种分片全部逐字节一致、无 replay |
| 成功握手 onClose | `onClose ran 1 times on a live session that was never closed` | 0 次；拒绝路径仍恰好 1 次 |
| TD-007 | `SOCKS4 user id "alice" was promoted to metadata.User with no users configured` | no-users 恒为 `""`；verified 保留；wrong user 被拒 |
| TD-006 队列上界 | `"48" is not less than or equal to "32"` | `queueRetained() <= 2*limit` 恒成立（10 万步） |
| TD-006 陈旧节点 | `the fresh pin was evicted by its own stale queue node` | 新鲜 pin 存活、FIFO 淘汰最老活 pin |
| TD-008/013 | `expected 2, actual 1`（跨网命中旧答案 / NXDOMAIN 压制） | 跨网必换答案；同网仍命中；命名空间随网变化 |
| TD-005 | 审计机制无法成立（结构性论证 + 新测试固定） | `TestALosingPeriodicRoundDoesNotReleaseTheWinnersGuard` PASS |

---

## 5. 构建与产品验证

| 平台 / 配置 | 命令 | 结果 |
|---|---|---|
| macOS arm64 产品 tags | `go build -tags "$TAGS" ./...` | PASS（除已知 libbox 链接） |
| macOS arm64 无 tag | `go build ./...` | FAIL（TD-004，见 §8.5） |
| Linux amd64/arm64（仅 local resolver 包） | `GOOS=linux go build ./dns/transport/local/` | PASS |

未做（环境不允许）：真机 iOS/macOS NE、Linux systemd-resolved 实网、Xray/Naive/MASQUE 参考互通。
这些一律**不得**记为 PASS。

---

## 6. 性能与资源

- 未做任何性能改动，也未声称任何提速。TD-009/019/021/027/036/037 等阶段 D 项未触碰。
- 本面唯一与性能相关的是**不引入退化**：`FirstPayloadConn` 在无 early data 时全路径透传，
  且修复了旧实现"无 early data 时读侧永不 unwrap"的不对称（旧 `ReaderReplaceable()` 在无缓冲时
  返回 false，使 `syscall.Conn` 无法被发现）；有缓冲时仍拒绝 splice（正确）。
- 资源守恒证据：`dns` 100 轮 reset 压力、`protocol/group` 10 万步缓存压力、`protocol/mixed`
  200 轮并发首发压力，均在断言后由 goroutine 计数/对象计数收敛（非墙钟比值）。

---

## 7. 提交与推送

- **本代理未创建任何 commit、未 push、未触发 Actions。** 工作树保持 dirty（含他方改动与用户
  既有脏文件）。改动文件清单见 §2 与 `git status`。

---

## 8. 剩余项与移交（精确到行）

### 8.1 TD-001（移交：Apple/生命周期代理；文件 `route/network.go`）
当前树**已实现**审计要求的大部分设计：`transitionToken`、`transitionOwns`、
`commitTransition(token)`（仅在仍持有时 settle）、`beginTransition` 先发布 unstable 再发布 token、
`NetworkTransitionSnapshot` 原子读、锁序（`interfaceUpdateAccess` 决定 → `resetRunAccess` 执行 →
`transitionAccess` 仅管所有权）。

**残留缺陷（真实、可定位）**：`updateInterface` 在**通知已 claim token 之后**存在早退路径：
- `route/network.go:1059-1062`：`platformInterface.UsePlatformNetworkInterfaces()` 为真且
  `networkInterfaces.Load()` 中找不到 `defaultInterface.Index` 时 `return`（注释即 `// race`）；
- 更早的 `ctx.Err() != nil` 早退（`route/network.go:1029`）由后续通知接管，属**安全**路径；
  但 `Name == ""` 这条**没有任何后续通知**时无人接管。

后果：`networkResetPending` 卡在 true、`transitionOwner` 悬挂、`NetworkTransitionStable()` 永久
false → `dns/client.go` 的 `operation.startedStable=false` 使**每一次 DNS 查询立即返回
`errNetworkTransitioning`**，且 generation guard 拒绝缓存写入；没有任何 watchdog/重试。
复现矩阵（工单 A2 已给出）：注入 `UsePlatformNetworkInterfaces()==true` + 索引缺失 + 无第二次
通知 → 断言"最终必须收敛"。

建议最小修法（他方实现）：在 `Name == ""` 分支上做**有界重试/重算接口状态**（重新读取
`networkInterfaces` 并重新 dispatch），重试上界内仍不完整则**以安全结算收尾**（例如按"接口信息
未知"降级处理并 commit 自己的 token），Close 可取消、不得无限重试或泄漏 timer。

### 8.2 TD-003（移交：Apple 代理；`clients/apple` 禁止改）
证据：
- iOS 侧（`clients/apple` 子模块）**完全没有** `ScreenStateObserver` / `recordScreenState` /
  `wakeNow` 的引用（grep 为空）→ 屏幕解锁不会驱动 `DeviceWake`；
- macOS overlay（`build/apple-client-macos/Library/Network/ScreenStateObserver.swift:1-28`）确实在
  display-on 时同时调用 `commandServer.recordScreenState(true)` **与** `commandServer.wakeNow()`，
  并在 `ExtensionProvider.swift:248` 接线；
- `experimental/libbox/command_server.go:329 RecordScreenState` 目前**只**写遥测
  （`service/powerreport/recorder.go:345 → recordPlatformEvent(eventTypeScreenOn/Off)`），不驱动策略；
  `WakeNow()`（同文件 321）才是策略入口。

结论：审计所述"`RecordScreenState` 仅遥测、iOS 未接线"在**当前树依旧成立**；修法在 Apple 客户端
（或 overlay）把真实可靠的屏幕恢复事件接到 `WakeNow()`/`DeviceWake`，或在 libbox 提供最小可测
策略入口，并把注释改成与行为一致。

### 8.3 TD-010（移交：`transport/**` 所属代理；我刻意未编辑）
`transport/masque/client.go`：
- `loop()` 第 301 行 `c.lastError = err` 对**非中断结束**无条件记录（正常拆除、对端关闭、idle
  timeout 都算）；
- 第 305-307 行对任何 `err != nil` 打 `logger.Error("connection closed")`；
- `WaitReady()`（405-423）在 `current == nil` 时**直接返回 `lastError`** → 重连窗口内的新 flow
  会拿到上一个会话的拆除错误（"陈旧错误污染 Ready"）。
- 服务端**已有** typed 分类器 `transport/masque/server.go:615 sessionErrorIsExpected()`（先看
  `transportHTTP.CarriesQuicSemantics` / `IsExpectedH3Closure`，再退回 `E.IsClosedOrCanceled`）。

建议修法：`loop()` 复用同一分类器——仅当 `!sessionErrorIsExpected(err)` 才写 `lastError`；期望
结束以 Debug/Trace 记录（或按既有信息级），真实 QUIC/TLS/auth 错误保持错误级与错误链。
测试：正常拆除后 `WaitReady` 必须等待**下一个**会话而不是立即返回旧错误；真实 H3/auth 错误仍
ERROR；Suspend/Resume/RestartSession 行为不变。

### 8.4 TD-011（移交：Apple/资源代理；`service/oomkiller/**`）
`service/oomkiller/timer.go:353` `idleGC := gcCycles == t.lastGCCycles`（"自上次采样以来没有
GC"）用作**空闲证据**；第 357 行的放行条件为
`!belowResume && now-lastRelease >= defaultReleaseInterval(1s) && (shrank || idleGC)`；随后
第 373 行调用 `runtimeDebug.FreeOSMemory()`（其自身强制一次 GC）。

自反馈链：release 触发的 GC 让**下一次**采样看到 cycle 增长（`idleGC=false`）从而跳过；但只要
应用继续空闲（后台/锁屏场景），再下一次采样又满足 `idleGC=true` → 只要用量长期停留在
`[resume, trigger)` 区间，就会**每秒一次强制 GC**（`defaultReleaseInterval = 1s`，
采样间隔上界 `defaultMaxInterval = 10s`）。即审计所述"自身 GC 无限触发"，速率受冷却限制而非
消除；与"低发热"目标冲突。

建议修法：引入独立的 `lastReleaseGCCycles`（release 之后的基线），把"自然 GC"与
`FreeOSMemory` 自己触发的 GC 区分开，使 `idleGC` 不再被自身回收重新置位；保留真实压力下的
主动回收能力与冷却。测试用注入 clock + GC 计数 + heap 采样：恒定高位 RSS、无自然 GC 时断言
回收次数存在严格上界。

### 8.5 TD-004（移交：CI/构建代理）
`go build ./...`（无 tag）失败于 `transport/http`：

```text
transport/http/client.go:239:33: undefined: http3LifecycleTracer
transport/http/stream_error.go:170:5: undefined: classifyH3ErrorCode
transport/http/stream_error.go:170:34: undefined: h3ErrorExpected
```

三者均由 `//go:build with_quic` 文件定义（`transport/http/client_h3.go:227`、
`transport/http/h3_error_class.go:24`），而 `client.go` 与 `stream_error.go` 无 tag。
需要编译期互斥的最小非 QUIC 定义（不存在的能力返回既定不支持错误或保守分类），
并在 `verify.yml` 增加无标签构建门禁（当前 `verify.yml` 只有带 tag 构建）。

### 8.6 TD-041/042（移交：CI/构建代理）——已复现
规范化映射（`go list -m -json`，root vs `test/`）：

| 模块 | root | test |
|---|---|---|
| `sing` | `v0.9.7-0.20260929150544-…` → **Piggy** `v0.9.6-0.20261004070536-dc9f4ea02e02` | 同（一致） |
| `sing-tun` | `v0.9.7-0.20261007151655-…` → **Piggy** `v0.0.0-20261008172655-8dde9c8cbe27` | `v0.9.7-0.20261007151655-…` → **无 Replace**（上游，`Dir=…/sing-tun@v0.9.7-…`） |
| `quic-go` | → **Piggy** `v0.61.1-0.20260929231714-…` | 同（一致） |
| `cronet-go` | → **Piggy** `v0.0.1-143.0.7499.109-2.0.…` | 同（一致） |
| `gvisor` | 无 replace | 无 replace（一致） |

**结论：`test` 模块实际编译/测试的是上游 `sing-tun`，而非 Fork。** 且
`scripts/ci/check-go-module-integrity.sh` 的 `PARITY_REPLACES=(sing, quic-go)` **不含
`sing-tun`**，因此该守卫对这条不一致**不会失败**；`REQUIRE_CHECKED` 只要求"被发现且被检查"，
并不比对独立期望清单——双方同时漏掉条目时守卫仍会通过（审计的判断成立，需独立 manifest）。

### 8.7 TD-043/044（移交：CI/构建代理）
- `with_xhttp` **存在**于 `release/DEFAULT_BUILD_TAGS` 与 `DEFAULT_BUILD_TAGS_OTHERS`；
  `include/v2rayxhttp.go`（`//go:build with_xhttp`）与 `transport/v2rayxhttp/register.go` 是真实注册路径；
- **没有任何门禁会因产品 tag 缺少 `with_xhttp` 而失败**：`scripts/ci/verify-full-capabilities.sh`
  完全没有 XHTTP 用例；`server-linux-amd64.yml` 的 `go list -deps` 期望清单包含
  `experimental/clashapi`、`transport/http`，但**不含** `transport/v2rayxhttp`/`include`；
  `scripts/ci/build-server.sh` 只是读取 tag 文件，没有独立期望集合。
- 文档/脚本陈述过期：`scripts/ci/build-server.sh:14-16` 声称"与上游唯一偏差是移除
  `with_clash_api`"，但当前 `DEFAULT_BUILD_TAGS_OTHERS` **包含** `with_clash_api`，且 Clash API
  仍在依赖审计清单里 → 该注释与事实不符（`build-macos-client.sh` 同款说明亦需复核）。

### 8.8 shadowtls 同根因（待指派）
`protocol/shadowtls/inbound.go:120` 与已修的 socks 完全同形（上游逐字继承）：
`N.CloseOnHandshakeFailure(conn, onClose, err)` 无条件调用 → 成功握手即上报 live session 已关闭。
修法一行（`if err != nil` 包裹），但需要 shadowtls service 级测试桩；本代理未擅自改动无测试
覆盖的路径。

### 8.9 TD-009 的静态证据（Phase D，未改）
`protocol/socks/guard.go:197-241` 的 `forwardedConn` 文档明确声称其存在意义是"让 routing 层探测的
`syscall.Conn`、`io.ReaderFrom`、`io.WriterTo`、半关闭都保持可达"，但该类型**只**实现了
`ReadFrom/WriteTo/CloseRead/CloseWrite/ReaderReplaceable/WriterReplaceable/Upstream`，
**没有** `SyscallConn()`（我已 grep 确认）。因此 `addressGuard`（由 `GuardSOCKS5Address` 安装在
mixed 与独立 socks 的每条连接上）不满足 `syscall.Conn`，`copyDirect`/splice 的 syscall 探测在
guard 处即告失败——这正是 TD-009 所述"guard 失去 splice"的机制。

**未修改**的理由：这是纯性能能力（拒绝 splice 永远安全），而工单把 TD-009 归入阶段 D，要求
"真正 wrapper 链的 syscall 可见性 + Linux splice 实际命中率"作为先决证据；本机无 Linux 数据面，
无法给出 before/after。建议在 Linux 上先测 guard 前后 `copyDirect` 命中率与吞吐，再决定是否
把 `SyscallConn()` 加到 `forwardedConn`（一行，但需数据支撑）。

### 8.10 其它观察
- `go mod tidy -diff`：**`go.mod` 无差异**；`go.sum` 存在既有漂移（大量 `/go.mod` 哈希行可被 tidy
  删除）。我的改动未引入任何新依赖，故该漂移与本分册无关；`test/go.mod`、`go.sum` 属 CI 代理面。
- `dns/transport/conn_pool.go` 我一度实现"突发复用"（等待在外连接返回 + 重新检查 idle），在真实
  树上被 §8 契约测试
  （`dns/transport/serial_lifecycle_test.go:883 TestSerialPoolConcurrencyContract`：要求
  `connections >= 2`，"把并发查询串到一条连接上会把突发变成队列"）**否决**。我据此**回滚**了该
  实现（`git show HEAD:dns/transport/conn_pool.go` 原样恢复），改为把现状测成契约：
  `dns/transport/conn_pool_burst_test.go` 固定 dials==burst、peak 并发建立==1、同一连接绝不
  同时交给两个调用者。**TD-014 的"突发复用单连接"与本仓库既有契约互斥**，属需要产品决策的
  冲突项，本代理未以弱化既有断言的方式"通过"。

---

## 9. 发布门禁（本代理负责面）

| 门禁 | 现状 | 说明 |
|---|---|---|
| DNS 跨网隔离 | **GREEN（新）** | exact/NXDOMAIN/RDRC/持久键均按 pinned 网络环境分域；跨网必重查，同网 reset 不作废 |
| early-data 首段完整性 | **GREEN（新）** | mixed + 独立 socks；分片矩阵 + 逐字节守恒 + 无 replay |
| early-data 并发所有权 | **GREEN（新）** | barrier 首发竞争测试 + 真实 copy 循环；`-race -count=20` |
| sticky 缓存有界 | **GREEN（新）** | map ≤ limit、queue ≤ 2×limit、陈旧节点不能淘汰新 pin |
| SOCKS4 身份不可伪造 | **GREEN（新）** | 无 users 时不写入 `metadata.User`；有 users 时保留原语义 |
| DNS 串行池突发 | **RED-BY-CONTRACT** | 与 §8 契约冲突，未修（见 §8.9） |
| 无 tag 构建 | **RED** | TD-004，移交 |
| `test` 模块 sing-tun 同 pin | **RED** | TD-041/042，移交 |
| `with_xhttp` 门禁 | **RED（缺门禁）** | TD-043/044，移交 |
| Linux D-Bus loop 生命周期 | **GREEN（代码）/ 运行 BLOCKED** | TD-020 |
| Linux splice / auto_redirect / nfqueue 真实数据面 | **BLOCKED** | 本机无 Linux 数据面 |
| iOS 真机（锁屏/解锁、热点、jetsam） | **DEVICE UNVERIFIED** | 无真机 |
| 参考实现互通（Xray REALITY / Naive / MASQUE-H3） | **UNVERIFIED（本代理未运行）** | 由父代理的 INTEROP-REALITY 门禁负责；我只确认未改动 REALITY 行为 |

---

## 10. TD-025 门禁保真度（本面逐项）

| 工单条目 | 本面状态 | 证据 |
|---|---|---|
| `route/interface_transition_coalescing_test.go`（不要直接写 token 字段代替通知与认领） | **未做（他方面）** | 该文件测试 `route/network.go` 的通知/认领状态机，属 Apple/生命周期代理面，我未编辑 |
| `dns/*environment*_test.go` 增加**不实现** `DNSTransportWithEnvironment` 的远程 transport stub | **DONE** | `dns/cache_remote_environment_test.go` 的 `remoteTransport` 无 `Environment()`，被 4 个测试使用；另有 2 个 100 轮压力测试 |
| `protocol/group/loadbalance_test.go` 既测容量又测历史队列与重复 key 存活 | **DONE** | 原有 `TestLoadBalanceStickyIsBounded` 仅断言 `size() <= limit`（弱断言）保留未动；新增 `loadbalance_affinity_test.go` 直接断言 `queueRetained() <= 2*limit`、`queuePending()` 不因重 pin 增长、陈旧节点不能淘汰新 pin、并与参考 FIFO 模型 10 万步对照 |
| `protocol/group/urltest_recheck_handoff_test.go` 不要由测试自己复位被测 `checking` | **DONE（主要项）** | `TestForcedRoundQueuesWhenAGuardIsHeldByARealRound` 由**真实 round** 占用并释放 guard（测试不写该标志）；`TestALosingPeriodicRoundDoesNotReleaseTheWinnersGuard` 固定"败者不释放"。仍保留 `TestForcedRecheckIsQueuedRatherThanDroppedWhenBusy` 作为**显式声明**的状态布置单元测试（它断言的是 `queueForcedRecheck` 记账，释放与该断言无关，不构成"测试自证"），已在报告中标注 |
| `route/scheduler_copy_matrix_test.go` 测试真实 guard→earlyDataConn→router 链 | **部分（本面已由更强形式覆盖）** | 该文件不引用 early-data wrapper（grep 为空），它测的是调度器 gate 链的自有 double；我这边新增的真实链路测试是 `TestEarlyDataCopyLoopsConservePayload`（真实 `bufio.CopyWithIncreateBuffer` 双向 + 真实 wrapper + 真实 inbound），以及 `TestEarlyDataFirstUseIsSerialized` 从真实路由对象取 `Upstream()`。未改该文件 |
| `route/splice_socket_owner_test.go` 确认可达性 + 两次并发 Close exactly-once | **未改（先验证）** | `go test -run 'TestScheduler|TestSplice|TestSocketOwner|...' ./route/` PASS；该文件的语义审查属 `route/conn.go`（我的面）但工单要求"先确认代码可达性"，本代理未在无设备/数据面证据下改动 |
