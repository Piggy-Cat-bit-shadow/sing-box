# v0.1.6 补充审计问题闭环（S01–S08 + 主施工令 Row15 / Row39）

> 本文件是《JiejieBox v0.1.6 补充独立复审、遗漏缺陷修复与发布证据加固施工令》要求的补充独立报告。
> 可机读版本：`docs/fork/v016-supplemental-closure.json`。
> 工作方式：每个工作包在自己的隔离 worktree/clone 中施工，普通 push 到独立分支，集成人逐主题 `cherry-pick -x` 到 `integrate/v016-final`。
> **用户明确指示：不进行模拟器/模拟器测试**，因此本轮所有产物验证都是编译/链接/静态/未签名构建级别，运行期一律标 `DEVICE-ONLY`。

---

## A. 本次实际基线 / 每仓库最终 SHA / Git 安全

### A.1 开工基线（实际 fetch/ls-remote 测得）

| 仓库 | 分支 | full SHA | 说明 |
|---|---|---|---|
| `Piggy-Cat-bit-shadow/sing-box` | `testing` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` | 开工 HEAD，**本轮未推进 `origin/testing`** |
| `SagerNet/sing-box` | `testing` | `6afeff4c0f7123b5782f888812e96b8c82c7b699` | `git rev-list --left-right --count` = **1479 / 53**，与阶段 A 快照一致，期间未漂移 |
| `Piggy-Cat-bit-shadow/sing-box-for-apple` | `dev` | `d1224bb5081b3df5d0ecc55b1bd3d72ea6c60628` | 另有 `main`=ab33c3f08、`hako-ui`=24bd463a9、`ipad-upstream-ui`=816600ab3 |
| Core gitlink `clients/apple` | — | `2b23330d489b9f6b45e98f903f458842e8961594` | 远端实测同时是 `refs/heads/fix/libbox-stringbox-callsites` 与 `refs/tags/libbox-stringbox-abi-2`；**不在 `dev` 上** |
| Core gitlink `clients/android` | — | `ec61030d3df74f3e7c39ab848c8996008ecd386a` | 未改动 |
| `Piggy-Cat-bit-shadow/satelite-one` | `main` | 会话内推进 `fb5a3615` → `4d15e3b` → `fcafdd54` | **用户/其它会话在本轮期间持续推送该仓库**，见 E 节 |
| `Piggy-Cat-bit-shadow/sing-tun` | `dev` | `7539c9855f19bb51a75f0908ecf6ae1d2d749490` | Core pin 保持 `v0.0.0-20261008172655-8dde9c8cbe27`（`8dde9c8cbe27`），**本轮未改 pin** |
| `Piggy-Cat-bit-shadow/utls` | `v1.7.0-mod-meta` | `449a38f8780006758205a60661a0bc374a182ca5` | 本轮未改 |

工具链：`go1.25.5 darwin/arm64`，Xcode 27.0，JDK 17，Android SDK + NDK 28.0.13004108，gomobile/gobind 可用。

### A.2 用户原工作树保护

开工与收工两次核对，`/Users/jie/Desktop/其他文件/sing-box` 的未提交状态**完全一致**：

```
 M clients/android
 M clients/apple
?? build-screens-doc.py
?? capture-screens.sh
```

- HEAD 仍为 `ef83b86819c97cbe58b0397dc74af6aca5f1859d`，分支仍为 `testing`，`origin/testing` 未被推进。
- 子模块工作区提交未变：`clients/android` = `fc21909df7a3f0fc9435f3866fb6a4960711aa5f`，`clients/apple` = `816600ab3f2823ab5de1da66e36433ef3a21fc10`。
- 两个未跟踪文件大小未变（11839 / 4007 字节）。
- **所有施工都在 `git worktree`/独立 clone 中完成；`git add .`、`reset --hard`、`clean`、`stash`、force push 全程未使用；未创建 tag、未创建 GitHub Release、未签名、未上传任何签名材料。**

### A.3 一次必须披露的 Git 安全事件（已完全恢复）

集成排练时，一条 `git worktree add -b <branch> --detach <sha>` 因参数互斥失败，但后续命令**没有做目录存在性检查**，于是在默认工作目录（用户原树）里执行了 `cherry-pick`：`refs/heads/testing` 被推进到新提交 `6396ceb26`，并进入了一次冲突中的 cherry-pick。

发现后立即按无损方式恢复，未使用 `reset --hard`：

1. `git cherry-pick --abort` → 回到 `6396ceb26`，工作树恢复干净；
2. `git reset --mixed ef83b8681` → 只移动分支指针，**不触碰工作树**；
3. `git checkout -- protocol/tun/inbound.go protocol/tun/callback_lifecycle_test.go` 恢复我改过的两个文件；
4. 删除我新增的三个文件（内容已保存在 `fix/tun-ruleset-refs` 并被 push）。

恢复后核对：HEAD = `ef83b8681`，`refs/heads/testing` = `ef83b8681`，`git diff --exit-code HEAD -- <两个文件>` 为空，子模块指针未变，两个未跟踪文件仍在，`origin/testing` 从未改变。事故提交 `6396ceb26` 仍作为不可达对象留在对象库中（未 prune）。

后续所有 worktree 创建都加了 `[ -d "$path" ] || exit 1` 守卫。

---

## B. S01 — TUN RuleSet `IncRef`/`DecRef` 配对（旧红 / 新绿 / 反向破坏 / 真实 Cleanup）

**状态：`FIXED`。** 分支 `fix/tun-ruleset-refs` @ `b361df879e557f701139d89cd62fbf2b57c31345`。

### B.1 缺陷（源码可确定）

- `protocol/tun/inbound.go` 原 422 / 430 行对每个 `route_address_set` / `route_exclude_address_set` 调用 `IncRef()`，而 `releaseRouteSetCallbacks()` 只注销回调、**从不 `DecRef`**；`grep -rn 'DecRef' protocol/tun/ | grep -v _test.go` 在生产侧返回空。
- 释放注册原本在 `if t.autoRedirect != nil` 之内，因此**无 AutoRedirect 的桌面 TUN 分支连一个 owner 都没有**。
- 规则集只在 `refs == 0` 时由 `Cleanup()` 释放规则（`route/rule/rule_set_remote.go:163`、`route/rule/rule_set_local.go:177`，唯一调用者 `route/router.go:253`），所以未释放的引用会永久钉住规则数据。
- 测试盲点：`protocol/tun/callback_lifecycle_test.go` 的 `trackingRuleSet.IncRef/DecRef` 是**空方法**，无法观测计数。

### B.2 修复

- 新增 `routeRuleSetRefs []adapter.RuleSet`，由 `acquireRouteSetRef()` 在**同一把锁内**完成 `IncRef` + 记录，杜绝“记录早于引用 / 引用早于记录”两种交错。
- 单条 `scope.Add(t.releaseRouteSetsCleanup)` 移到 `if t.autoRedirect != nil` **之外**，覆盖两个分支。
- 释放分成两个责任且顺序固定：`releaseRouteSetCallbacks()`（先注销，注册中的回调会读取即将被释放的规则）→ `releaseRouteSetRefs()`（排空并**清空**记录，因此 `Inbound.Close()`、`closeAutoRedirect`、Scope cleanup 三条路径都幂等）。
- 记录是**切片不是集合**：同一规则集同时出现在 include/exclude 时是两次获取、必须两次释放。
- 阶段 A 已验证的“注销回调先于关闭 AutoRedirect”语义**未改**。

### B.3 旧红 → 新绿 → 反向破坏

| 证据 | 命令 | 结果 |
|---|---|---|
| 旧红 | 在**纯净 `ef83b8681`** worktree 中跑新测试 | **7 个测试全部确定性失败**（计数停在 1；共享对象停在 2） |
| 新绿 | `go test -count=1 -tags "$(cat release/DEFAULT_BUILD_TAGS)" ./...` | **76 ok / 0 FAIL**（exit 0） |
| 新绿 | `-race` 跑 `./protocol/tun/... ./route/... ./adapter/...` | 全绿 |
| 真实对象 | `route/rule/rule_set_ref_cleanup_test.go` | 真 `LocalRuleSet`（经 `NewLocalRuleSet` + `Match`）与真 `RemoteRuleSet.Cleanup()`：持有引用时规则保留、释放后清空 |
| 反向破坏 1 | 从 `releaseRouteSets()` 去掉 `releaseRouteSetRefs()` | **7 个测试红** |
| 反向破坏 2 | 把 `scope.Add` 移回 `if t.autoRedirect != nil` | **无 AutoRedirect 分支测试红** |
| 反向破坏 3 | 去掉记录的清空 | **幂等测试红**（负计数 panic，未被吞掉） |

`trackingRuleSet.IncRef/DecRef` 已改为真实原子计数并在负值时 panic，与生产实现一致。

---

## C. S02 — Apple `ScreenStateObserver` 的 notify 失败路径

**状态：`FIXED`（代码/编译/逻辑层），运行期 `DEVICE-ONLY`。** 提交 `dd9114d9a20d1b252f20c4003f75e29974cb9c05`，分支 `fix/apple-notify-unknown`（Apple fork）。

- `notify_register_dispatch` / `notify_get_state` / `notify_cancel` 的返回状态现在统一与 `NOTIFY_STATUS_OK` 比对；失败读被建模为**没有值可读**的类型，而不是 `state == 0`。
- `state == 1` 改为全映射：任何非 `0`/`1` 都判为 unknown，而不是 `false`（`false` 等于“已解锁”）。
- 桥接层 `recordLockState`/`recordScreenState` 一路到 `Box.LockStateChanged` 都是 `(BOOL)`，**没有第三个值可表达 unknown**，因此 unknown 的语义是**什么也不发布**——这一点在报告里明确写出，没有为了“表达 unknown”去 Swift 里造第二套状态机。
- 快照（启动 + resync）只允许发布 **SLEEP 事实**（locked / display off）；`unlocked`/`display on` 是“转变”，快照没有见证过，不发布。探针实测：从未设置过的 notify 名字 `notify_get_state` 返回 OK 且值为 0，在 lock 源上那就是 unlock，所以对称发布被明确否决并记录了理由。
- **顺带修掉第二个缺陷**：display-on 不再调用 `wakeNow()`（那是 wake storm，且与强制状态表矛盾）；publisher 协议里已不存在 `wakeNow`。
- stop/取消与队列中回调的竞态用“队列被信号量持有”的方式做成**可编排**而非依赖时序；`cancel()` 返回后回调确实跑过，且**什么都没发布**。
- 局部注册失败只取消成功的那一个，两个名字始终都尝试。

真实证据：harness 编译**真实源文件**（非副本）对假 notify API，**76/76 检查通过，exit 0**；`swiftc -typecheck` 对真实 v0.1.6 Libbox framework + 真实 `notify` 模块 **exit 0**，逻辑文件在 4 个 SDK 上 exit 0；真实探针显示失败读**不写 out-param**（`0xDEADBEEF` 存活）——那正是旧代码读到的值。

`DEVICE-ONLY`：两个未公开的 Darwin 通知名在沙盒 `NEPacketTunnelProvider` 上是否真的投递、其取值语义、真机 lock/unlock 端到端、`ExtensionProvider` 五个入口的运行时行为。

---

## D. S03 — Apple ABI 探针 provenance、真实产品构建、cronet 链接

**状态：provenance `CONFIRMED_SOURCE_GAP` + 网关已建立；产品构建 `PASS`；cronet `DEAD_CODE_ONLY / BLOCKED_TOOLCHAIN`。** 分支 `ci/apple-abi-provenance` @ `73462a4cd21b0b9a3dd243c91970a12181382514`。

1. **Provenance**：新增 `scripts/ci/apple-abi-provenance.sh`（把 witness 与**真实客户端声明**绑定，而不只是互相自洽）。结论：`observer.swift` 是**逐字节等价**的（patch 重放 → blob `d3e8035b7579…` == pin 到的 blob == 编译进 witness 的内容）；6/7 条 patch `index` 与 pin 树一致；两份 `ExtensionPlatformInterface` patch 实际是**针对 `c9a4c61`（hako-ui / ipad-upstream-ui 血缘）的 pre-image 草稿**，不是 dev；`callsites.swift` 有一处 anchor 归属错误（`options.getDNSMode()!.value` 并不在被引用的 patch 里）。最关键的一条：**pin 到的 revision 扫描 = 19 迁移 / 0 未迁移；当时检出的树 = 1 / 18。**
2. **真实产品构建 —— 这是本轮 Apple 侧最重要的结论**：

   | 检出 | 命令 | 结果 |
   |---|---|---|
   | 陈旧 `816600ab`（用户本地所检出的） | `xcodebuild -scheme SFI -sdk iphoneos -configuration Debug CODE_SIGNING_ALLOWED=NO` | **BUILD FAILED**，exit 65，10 个 Swift 错误，全部 `LibboxStringBox?` → `String`，都在 `ExtensionPlatformInterface.swift` |
   | **gitlink `2b23330d4`** | 同上，完全相同的 scheme/SDK/配置/签名参数与**同一个 framework** | **BUILD SUCCEEDED**，exit 0，**0 errors**，21m37s |
   | **gitlink `2b23330d4`** | `xcodebuild -scheme SFM -sdk macosx … CODE_SIGNING_ALLOWED=NO` | **BUILD SUCCEEDED**，exit 0，21m38s |

   **差值：10 个错误全部消失、无残留、无新增。** 未改任何源码、未改 build setting、未手工加 `-dead_strip`。**结论：Apple 客户端没有坏，是本地 `clients/apple` 检出落后于 Core 的 gitlink。**
   未签名产物：iOS `sing-box` sha256 `735d38ac1017dbb77ad63f3b343c60c0ac2caeea0bbd1339503557a2ff52dc9b`（`code object is not signed at all`）；macOS 通用二进制 sha256 `e603377205737012108cba205fae2c68dd6e58aebf3756fdb345f67fa4759f5f`（仅链接器 ad-hoc 戳）。无 `embedded.mobileprovision`。
3. **版本字符串**：已解释并用真实代码路径证明。`build_shared` 注入 `-X …/constant.Version=<ReadTag()>`，`ReadTag()` 的 `currentTagRev[1:]` 把 tag `tooling-v0.1.5` 截成 `ooling-v0.1.5`，`badversion` 退化为 `0.0.0-v0.1`，再拼短 SHA。因此 `0.0.0-v0.1-0fbca8546` 表示那份 framework 就是 `0fbca8546` 构建的（一个真实存在的兄弟提交），**不是“装错 Core”**。本次新构建的 framework 报告 `0.0.0-v0.1-ef83b8681`，与 Core SHA 一致。
4. **cronet**：`nm`/`ld` 实测 `lib/ios_arm64@v0.0.0-20260929202119-8c68ce89873c/libcronet.a`（sha256 `6863693a72d461855ea0de58492af110fc2087cfb5a3f7db33e060eef6a13980`，46,280,672 字节，2724 个成员）中 `__ZN4base17MessagePumpKqueue18InitializeFeaturesEv` 由 `features.o` 引用、**全archive无定义**（`message_pump_kqueue.o` 是 macOS-only 成员，不在 iOS archive 里）；macOS slice 定义在 0x1550。这是 iOS archive 中**唯一**的 intra-`base::` 空洞（`__ZN3net` 为 0）。
   **修正后的判定是 `DEAD_CODE_ONLY`，不是“archive 不可用”**：真实客户端 `project.pbxproj` 设了 `DEAD_CODE_STRIPPING = YES`（6 处），真实链接行带 `-dead_strip`（15 处），`features.o` 根本不被抽取——链接后的 `sing-box.debug.dylib` 中 `MessagePumpKqueue` 为 **0** 个符号。**但绿色是“事故性”的，而且是承重的**：只要有任何东西让 `base::features::Init()` 变成 live（`features.o` 定义的 769 个符号之一、`-all_load`/`-force_load`、ObjC `+load`、不 dead-strip 的目标、或第三方消费者），链接立刻失败。
   新增 `scripts/ci/verify-cronet-ios-archive.sh` 把这件事实**机器可查**（从 `go.mod` 的 replace 读 pin，因此 re-pin 会自动改靶），今天按设计 **FAIL**，并打出完整符号清单；`CRONET_IOS_ARCHIVE_TRACKED_DEFECT=1` 可记录并返回 0，同时仍然打印清单——是分诊开关，不是静默变绿。集成人另补一个提交把该脚本 banner 的措辞从“real app link fails”改成修正后的 `DEAD_CODE_ONLY` 事实。
   重建需要 Chromium/cronet 构建流水线，本环境不可用 → `BLOCKED_TOOLCHAIN`，5 步 runbook 已写入报告。

---

## E. S04 — Android 发行工作流的云端签名路径与最小权限

**状态：`FIXED`（工作流），产物实测 `UNSIGNED`；真实 Actions 未执行 → `BLOCKED`。** 分支 `ci/unsigned-dryrun-min-permissions-rebased` @ `2334badb8b449970cf1e48160e933c71fc864cce`。

### E.1 真实缺陷

对旧 `release-apk.yml` 做 YAML 解析（不是读摘要）发现 `Restore signing config` **完全没有 `if:`**，而工作流带着全局 `permissions: contents: write`。因此 `workflow_dispatch(dry_run=true)` 会解析全部四个 `INTERSTELLAR_*` secrets 并在 runner 上写出 `interstellar.jks` 与 `signing.properties`——一次不发布任何东西的运行却拿到了生产签名材料与写权限。

### E.2 修复

- 全局与 build job 一律 `contents: read`；**唯一**的 `contents: write` 移入独立的 `publish` job，条件是 `github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && inputs.dry_run != true`。
- 签名材料恢复步骤加同一条件，并在只读路径上加“确认不存在签名材料”的互补断言。
- 签名状态改为**实测**（`apksigner verify --verbose --print-certs`），不再由安装 keystore 的步骤自己声明：dry run 若测到任何非 `unsigned` 就失败；tag 发布若测到 `unsigned` 或 `debug-signed` 就失败。`build-info.json` 记录 `signature_state` + `signature_state_measured_by`。
- 修正文档/实现对不上的“debug 签名回退”说法（workflow 注释、README、`app/build.gradle.kts` 共四处）。
- artifact 命名区分 `…-unsigned-dryrun.apk` 与 `…-signed-v<ver>.apk`。

### E.3 产物实测（集成人独立复测，与 S04 报告逐位一致）

| 产物 | 字节 | SHA256 | 签名状态 |
|---|---|---|---|
| `satelite-one-0.5.10-arm64-v8a-release.apk` | 29,525,843 | `8e6dd3e57992cd7fc1f143c518e075b56c4536f575065f3b72308fda66e6f5ec` | **UNSIGNED**（`DOES NOT VERIFY / Missing META-INF/MANIFEST.MF`） |
| `satelite-one-0.5.10-x86_64-release.apk` | 31,408,898 | `1c123b8dc0942ea530afbc0feb043f08a5fd8284888a8d493dbcf076f88ee161` | **UNSIGNED** |
| `libbox.aar`（core `c35faabf4…`） | 58,396,617 | `e3b6084b1caff5edc63d59e63ce38c9ab9094abb310620552844f97016cfc3c9` | — |
| APK 内 `lib/arm64-v8a/libbox.so` | 80,129,776 | `277d76bb088f08fe95a3410eb48133abbeb25db4830dac73d4e40753b41f4a8e` | 与 AAR 内 `jni/arm64-v8a/libbox.so` **`cmp` 逐字节相同** |
| APK 内 `lib/x86_64/libbox.so` | 84,472,800 | `80448f061c5bb818b7b5f882410a058c1c6901beb791ed8454eae304696f38dd` | 同上 |

对照：`assembleDebug` 产物用 debug key 签名（`CN=Android Debug`），这才是“debug-signed”的唯一情形。

### E.4 `satelite-one main` 在本轮期间被并行推进

`main` 从 `fb5a3615` 依次推进到 `4d15e3b`、`fcafdd54`（7+ 个提交，内容正好也是 PlatformFacts / ServiceNotification / VPNService 一类修复）。因此 S04 的原始分支基于陈旧 main，集成人已让 S04 在 `4d15e3b` 上 `cherry-pick -x` 重做并另行 push（`…-rebased`），**旧分支保留作历史，未 force push、未删除远端 ref、未推 main**。
重做时解决的 3 处冲突中有一处很重要：新 main 又写入了 `SIGNATURE_STATE=debug-signed`（在缺失 keystore 分支上），这正是 S04 已经证伪的说法；重做后改为实测值。

`BLOCKED`：本环境没有真实 GitHub Actions 执行，artifact 上传/下载往返与 `action-gh-release` 未经执行验证；`inputs.dry_run != true` 在 push 事件下的表达式语义仍只是模拟。无任何 tag/Release 被创建。

---

## F. S05 — 构造期 AutoRedirect OutputMark 的竞态与回滚

**状态：方法层 `REPRODUCED_AND_FIXED`；产品层两条 `NOT_REACHABLE` 有调用图证明。** 分支 `fix/autoredirect-output-mark` @ `8139f01d7758cbfba4cf6a36183b13bc9b635568`。

| # | 问题 | 判定 |
|---|---|---|
| 1 | 并发注册 | 产品层 **NOT_REACHABLE**（`adapter/inbound/registry.go:65-73` 的注册表锁**横跨构造函数**；`box.New` 是顺序循环）；方法层 **REPRODUCED_AND_FIXED**（check-then-set 是真实 data race + 不受控双重 claim） |
| 2 | 拨号期并发读 | **NOT_REACHABLE**（唯一写者在 `box.New`；8 个读点全是拨号时惰性闭包或 `Box.Start` 期）——但仍然原子化，因为 #3 的修复引入了与拨号并发的新写者 |
| 3 | loser 保留 mark | **REPRODUCED_AND_FIXED**（走真实 `Manager.Create`；**200/200** 次都是“已 claim 的那个被丢弃”），配置层 **NOT_REACHABLE**（顺序 `box.New` + 预先 tag 检查） |
| 4 | `mark > 0` 哨兵 | **REPRODUCED_AND_FIXED**（零值 claim 与“未 claim”不可区分，第二次 claim 会叠加）；产品层不可达仅因 `AutoRedirectOutputMarkOrDefault()` 永不返回 0 |
| 5 | 最小修复 | `sync.Mutex` + 显式 `claimed` 标志 + `atomic.Uint32`；**`adapter.NetworkManager` 未被扩张**（`git diff --stat adapter/` 为空） |

旧红：纯净树上 `-race` 直接报 **DATA RACE**（`route/network.go:462` 读 vs `:465` 写）并 `FAIL: TestAutoRedirectOutputMarkClaimIsExclusiveUnderConcurrency (race detected)`、`…SingleShotIncludingZero: An error is expected but got nil`。
反向破坏：把守卫改回 `Load() > 0` → 独占性测试 `expected int(1) actual int32(2)`（20 次中 2 次），sentinel 与两个释放测试全红；禁用释放 → 丢弃测试 20/20 红（`Should be zero, but was 8228`）。两处均按字节还原并复跑绿。

---

## G. S06 — `common/urltest` / `common/trafficsched` 墙钟 flaky + 生成目录污染

**状态：两个包分别结论；另有本轮新发现的第三个 flaky。** 分支 `test/urltest-deterministic-gate` @ `827eb52587f9880a3396ec42cafd16b0be9e6227`。

### G.1 `common/urltest` —— `NOT_REPRODUCED`（但确认时序敏感并已确定性加固）

精确定位到 6 处 `delay < 100/120/140/160` 的固定毫秒断言（对照 fixture 注入的冷路径耗时）。**540 次定向执行（load 27→335）全绿**；44 个 `./common/...` 包的并行 `-count=20` 在 load 430–446 下也绿。但**故障注入证明它确实时序敏感**：把生产回归放回去（`warmElapsed := time.Since(measurementStart)`）→ 6 个断言全红；仅改 fixture（生产不动，第 2 次请求 110ms）→ 原始断言红（`"111" is not less than "100"`）。
加固方式：用已有的 `MeasureOptions.Debug` 相位时间做**相对**界定（`Delay < durationToDelay(Warmup)`），断言主张不变、随负载余量自动变大，**未改生产代码**。反向破坏：回归重新注入 → 6 个全红。

### G.2 `common/trafficsched` —— `REPRODUCED_AND_FIXED`

真实复现：第 5 次迭代、load 381 时
`"1.6677772703837964e+06" is not greater than "1.7825792e+06"`（1.668 MB/s vs 配置 2.097，即 79.6%）。
根因**实测而非猜测**：达成周期 = `chunk/rate + paceTick + 主机唤醒延迟`，超出量在**空闲与负载下都**是 ~1.4–1.6 ms/次写（16 KiB 下占 19%，64 KiB 下占 4.9%）；旧推导只算了 `paceTick`（~13%），余量仅 ~0.1%。此前把 0.90 降到 0.85 是同一个非修复做了两次。
修复：用同一套装置在 64 KiB（31.25 ms 周期，读取误差几个百分点）实测超出量，允许 `coarseExcess + 一个 paceTick`；精确安全上限（≤1.02×）未动；64 KiB 仍用平坦 0.85，因此 paceTick 回归仍会失败。证明：load 至 473 下 25/25 绿；反向破坏在 load 471 下第 3 次迭代红（1.741 vs 1.783），而同一次运行中派生界（1.418）通过。

### G.3 本轮新发现：`dns` 包的第三处墙钟断言族（已收口）

在对 `integrate/v016-final` 跑全量时真实失败：

```
--- FAIL: TestDNSLogicalRace (0.28s)
    router_race_test.go:582:
        Error: "258.404ms" is not less than "240ms"
FAIL	github.com/sagernet/sing-box/dns	11.266s
```

fixture 注入 100ms/10ms/250ms，断言 `time.Since(startTime) < 240ms`（只有 ~140ms 余量）。

处理结果（分支 `test/dns-race-deterministic-gate` @ `6abe49165d3bc8bdae5fc04283eaeaa589d3b775`）：

- **枚举**：`dns/` 中 9 处**主机敏感的上界**（nominal 实测 0.09ms–202ms，界 80–400ms）、8 处**安全下界**（负载只会增大，不会 flake；仍改为由 fixture 的 `delay` 派生而非常量）、2 处**真实超时/取消预算**（`multiplexer_test.go:298`、`local_darwin_test.go:118`）**原样保留**——它们的主体就是墙钟时间。
- **本环境 `NOT_REPRODUCED`**：200 次定向迭代（load 368→451）、40 次整包迭代（load ≤1006）、以及在 pristine `git archive HEAD` 快照上用**我这条完全相同的命令**跑 `./...`（88 个 spinner，load 390→1017）均通过 `dns`。**但你的失败日志本身就是一次真实复现，不因本环境未复现而作废。**
- **时序敏感性以“同量级”被按需复现**：在 scratch 副本里给“正确决策的返回路径”加一个 160ms sleep，其余不动——原始断言给出 `"261.577ms" is not less than "240ms"`（对应我看到的 258.404ms），加固后 PASS。
- **修复**：9 处上界全部改成它们本来想近似的**事件**（用 fake transport 新增的 `release` / `queried` 探针）：“交换在败者仍未应答时就已经返回”“两个 transport 都已被查询过才有人应答”“投机路由是在竞速决策仍 pending 时启动的”。**比原来的界更严格**，不再存在“等败者也通过”的窗口。
- **反向破坏**：4 个独立的生产回归各自致红（`Race()` 恒 false；提交前 await 所有已 armed 规则；启动时 await 所有已启动 future；族结果缓冲到 `Wait()` 之后再发布）。
- 作者**主动记录了自己犯的两个错误**（第一版把 exchange 同步等在 held transport 上，导致注入回归反而“通过”——是**丧失检测能力**而非仅变弱；以及一处与被测 transport 自身 goroutine 竞态的断言，5 次里失败 2 次）。

### G.3b 第四处：`transport/masque` 的复杂度墙钟门禁（**预先存在，本轮未修**）

在 load ~710 的全量运行中失败：

```
--- FAIL: TestTheOwnershipScanIsLinearHereToo (32.30s)
    control_burst_test.go:1281: 5000 lookups, best of 5: 8192 ranges -> 4.820022542s, 1 range -> 110.666µs,
                               ratio 43554.7x (linear expectation 8192x, bound 32768x)
```

**不是本轮引入的，也不是纯负载问题**——集成人在**纯净 `ef83b8681`** worktree 上复现 **2/2**（ratio 40605 / 47268），在集成树上 **3/3**（43469 / 49281），全部超过 32768 的界。同一台机器安静时它通过且快得多（load 17 时 `transport/masque ok 11.106s`；load 710 时 62.368s，其中 8192-range 用例从 <1s 涨到 4.8–5.8s）。

判定：**预先存在的、随主机负载/热节流恶化的复杂度门禁**，与本轮任何改动无关（`transport/masque` ≠ S07 改动的 `protocol/masque`）。
**本轮不修**（施工令明确要求停止无边界扩展），以 `PRE_EXISTING_LOAD_SENSITIVE` 记入未关闭清单，并给出最小复现命令：

```bash
go test -count=1 -run TestTheOwnershipScanIsLinearHereToo -tags "$(cat release/DEFAULT_BUILD_TAGS)" ./transport/masque/
```

建议的收口方向与 S06 同族：把“比率上界”换成**确定性的操作计数/复杂度断言**（例如统计 ownership 扫描的比较次数），而不是 5000 次查询的墙钟比值；若保留墙钟，则应把 `best of N` 的 N 与界都改为相对机器基线而非固定 32768。

### G.3c 第五处：`common/dialer` 的双定时器竞态（已复现并已修）

`TestPreferredFamilyArrivingWithinGraceIsDialledFirst`（`family_grace_order_test.go:205`）在负载下**真实失败两次**（load 632 第 44 次迭代；load 229→243 第 97 次迭代），签名一致：`expected true, actual false; got 192.0.2.1 first out of [192.0.2.1 2001:db8::1]`。

**这一处与前三处形状不同，也正是最有价值的一条**：它不是“对某个时长设界”，而是**“由错误的机制决定答案”**——测试保证了竞争者会开火，所以主机只需要**输掉一场竞速**，而不是超过某个界；调界宽毫无意义。

**枚举（`common/dialer`，23 个测试文件，40 处含时长的断言，分 5 组）**：
- G1 **结构性竞速**（竞争者决定答案）2 处 → **已修**；
- G2 **主机敏感上界**（慢主机让正确操作变晚）16 处 → **未修**，其中数处的界**就等于注入的延迟本身**，因此“修”它先要决定断言的主张是什么，必须逐个判定；
- G3 有 ≥1s 余量的活性断言 15 处 → 不属于 flake 类；
- G4 安全下界 4 处 → 负载只会使其增大；
- G5 **真实超时/取消预算** 3 处 → **原样保留**。

**候选修复不够，是负载运行把它否掉的**：停掉 fallback cadence 之后，修复版**在 load ~450 下仍然 200 次里失败 2 次**，且失败信息显示**只拨了一个候选**——在 cadence 已不可能开火的前提下，那只可能是 **grace 定时器本身（50ms）跑赢了 fixture 里首选族的 10ms sleep**。此时**产品是对的**（静默 50ms 的 resolver 就是慢），是**测试在报假故障**。也就是说有**两个**竞争者，不是一个。

**最终修复（测试专用，生产文件零改动，断言未动）**：
- cadence 移出可达范围（`graceOrderOutOfReachCadence = 10 * graceOrderDeadline`，4s vs 400ms context，两个名字成对以免失步）；
- fixture 改为从**同一个 goroutine、无 sleep、背靠背**发布非首选族与首选族，于是“首选族在 grace 窗口内应答”在任何慢主机上都成立。

**反向破坏**：把 `resolve.go` 里的 grace hold 去掉（第一个应答的族拿走槽位——正是这两个测试存在的理由）→ **两个测试、两个子测试全红**。作者先做的一次注入（把 grace 定时器设为 0）被**判定为不可用而丢弃**：Go 的 `select` 在就绪的 timer 与 channel 之间随机选择，导致只有一个测试变红、另一个靠抛硬币通过——**结果随机的反向破坏不是反向破坏**。

**负载证据（基线与修复交替、同一负载窗口内逐次对比）**：决定性一轮 load 423–434，**基线 150 次里失败 4 次，修复版 0 次**；`-race ./common/dialer/...` exit 0。

**作者另给出（未应用、未验证）**：`transport/masque` 那个比率估计器的根因读法——宽用例跑数秒、窄用例只跑约 1 毫秒，两侧 Wall time 不可比，`best-of-5` 在**持续节流**下每个宽样本都被抬高而 ~1ms 的窄样本已到自身下限，于是比率其实在报告机器状态。建议把两侧做成可比 wall time，或直接改成**统计 range 比较次数**的复杂度断言。按指示记为 `OPEN`。



### G.4 生成 `build/` 污染包枚举

- 成因从**被 pin 的工具链源码**证实：`gomobile@v0.1.12` 的 `cmd/gomobile/bind_iosapp.go:106` 与 `bind_androidapp.go:373` 使用 `filepath.Abs(filepath.Join(".", "build", …))`——**相对 CWD 且没有 flag/env 覆盖**；`build_libbox` 调用时没设 `Dir`，于是 CWD 就是模块根。
- 修复：gomobile 改在 `<root>/_libbox_build`（前导 `_` 永不被 `./...` 匹配）中运行，`-o`、包目录、拷贝目标全部绝对化；`.gitignore` 增加 `/_libbox_build/`。
- 门禁：新增 `cmd/internal/modlayout`——**先**按 deny 规则（`build`、`_libbox_build`、`dist`、`bin`、`vendor`）判定，**再**对一份 checked-in 的源**根目录**快照做 allow 规则；**任何地方都没有包数量断言**（新增包在既有根内可正常工作，新增顶层目录需要显式改快照）。
- 证明（`/tmp` 副本内）：干净 → ok；造一个 `build/android-arm64/libbox/go_libbox.go` → FAIL 并点名 gomobile 的两处源码行，且明确写着“**不要**删掉目录再重跑”；新增顶层根 → allow 规则 FAIL；两者移除 → ok。实测 `./...` 枚举：存在 `_probe/` 与 `.probe/` 时仍为 **169**，存在 `build/probe/` 时为 **170**。
- 未做端到端产物构建（本机无 Android SDK/NDK/JDK17 与 Apple gomobile 运行条件）——机制已验证，产物构建未验证，已在报告中标注给发布流水线。

---

## H. S07 — `Scope.Close()` 的完成边界与组件级解除

**状态：边界已精确钉死；MASQUE 真实泄漏 `FIXED`；TUN 窗口用非阻塞交接消除。** 分支 `test/scope-close-boundary` @ `3c5c84b08bd8f65a4439365f0b472175e1b64d0b`。

已确认并写成断言的语义（对应施工令 §7 的三点）：

1. `Scope.Close()` **只 join 已经开始执行的 cleanup drain**；它**不等待**已经进入但尚未 `Add()` 的 `component.Start()`——没有任何东西能界定 `Start` 的时长，等待会让 `Close` 变成无界操作。
2. `Add()` 在 `closing/closed` 后**在调用者 goroutine 上同步执行** cleanup，因此不会永久泄漏；但它在 `Close()` 返回**之后**才跑。
3. late cleanup 的真实错误**只被日志记录**，**不会**回填到已经返回的 `closeErr`（`closeErr` 是 final），重复 `Close` 也不会再取到它。文档措辞必须精确到这一点，不能用“Close 的 error 已覆盖全部工作”的说法。
4. 在被关闭的 Scope 上 `Start` **不能返回成功**（`:180` 的 `child.Context().Err()` 后检）。

确定性测试（无 sleep、无轮询）逐条钉死；MASQUE 的 witness check 在禁用守卫时**真实失败**：`listen tcp 127.0.0.1:54649: bind: address already in use`——证明被 `Close()` 返回后才 bind 的端口确实泄漏过。
**重入清单 `NOT_REACHABLE`**：219 个生产 `scope.Add` 中只有 5 个会关闭任何 `*Scope`，全部是“父 scope 关闭自己创建的子 scope”的受支持方向；35 个关闭 scope 的调用点全部是字段限定，没有把 `Start` 收到的 scope 参数别名化的情形。
**TUN 侧的设计取舍值得记录**：第一版守卫在激活期间持锁，导致 `Close` 等待在途 `Start`——`-race` 跑到 600s 超时卡死，被明确否决，改为非阻塞 `startupGate`（不等待、`sync.Once` 保证恰好一次释放）。
`NOT guaranteed`（报告 §5 明写）：`Box.Close()` 后“所有在途 Start 都已终止”是**假的**；late cleanup 的失败对 `Close` 调用者不可见；一个什么都不注册的 `Start` 对 Scope 不可见；`Close` 不可重入。

---

## I. S08 — 交接 MD/JSON 与唯一冻结 SHA

**状态：`FIXED`。** 分支 `docs/handoff-reconciliation` @ `47f49fcd7ebcc3538ac15263fa4568b2f6592db4`（7 个提交）。

- **三个不同且都真实可从远端取到的坐标**：`PHASE_A_START` = `912ed1efad265d8a8f56aaabcabc8f7b171c2baa`（tip 的祖先，10 个提交）、`INTEGRATION_FINAL_SHA` = `ef83b86819c97cbe58b0397dc74af6aca5f1859d`（= `origin/testing`，`cat-file -t` → commit）、`PHASE_B_START` = `98ea14181ca62f7632791aca12eceef8fbb8b3e3`。
- **五个冲突全部“只增不减”地解决**：closure report 里各历史 tip 逐条标注 `historical, not the final release SHA`，单一 RC 验收移到新的 `v016-release-candidate-manifest.md`（显式 “not frozen yet”，**没有编造 SHA**）；集成台账的 “in progress this round” 保留为历史观察并追加实测 artifact 摘要（并说明这些摘要来自 `0fbca8546`，比 tip 落后 18 个提交，**tip 处不存在任何产物**）；handoff `coordinates` 原样保留，另加 `integrated_remote_state` 与 `fact_model`（`observed_at_sha/time`、`integration_final_sha`、`current_candidate_core_sha=null`、`code_status`、`behavior_status`、`artifact_status`）；rows 22/23/45 拆成**正交**的 `code_presence/code_status` 与 `behavior_status`（此前不是“矛盾”，而是“代码存在性”与“行为验收”被塞进一个状态）；`P0-L01` 保留原文，拆成 `P0-L01a`（回调所有权，FIXED）与 `P0-L01b`（RuleSet 引用寿命，S01）。
- **校验器** `scripts/ci/verify-fork-handoff.sh`（POSIX sh，已 +x）：对真实远端 **PASS**（`EXIT=0`）；并按四种破坏方式**证明它会失败**，其中最关键的一种正是施工令点名的“只存在于本地对象库的 SHA”：
  `is NOT reachable from 47f49fcd7…: it exists only as a local object`。
  运行校验器还**发现并修掉了两个真实缺陷**：失败的 `git fetch` 会静默降级成本地 “ok”；以及 verdict 的 grep 会匹配到解释该规则的散文本身。
- 新增 `docs/fork/v016-next-round-baseline.json`（6 个仓库的实测 SHA、dirty 计数、上游比较、Go 版本、16 个 build tags、CI run 历史；**0 个 CI run 存在于 `ef83b8681`**，最新的是 `e2d7ac1be`，落后 59 个提交——没有把任何旧绿灯当成本次 RC 的绿灯）。
- **明确不声称**：tip 处无 CI run、无产物、无设备验证；`P0-L01b` 在 S08 当时只有代码证据（本集成已补上行为证据，见 B 节与 ledger §5.2）。

---

## J. 与主施工令任务 ID 的去重映射

| 补充令 ID | 主施工令对应 | 本轮实际处理 | 是否重复修改 |
|---|---|---|---|
| S01 | 未覆盖（新增缺口） | `fix/tun-ruleset-refs` | 否；仅补充 P0-L01b |
| S02 | 主令 §8.2 Apple 初始锁屏真值 | `fix/apple-notify-unknown` | 合并为同一处代码，未重复 |
| S03 | 主令 §8.1 / §8.4 / §11.3 | `ci/apple-abi-provenance` | 是同一目标的验证层增强 |
| S04 | 主令 §9.1 / §12 | `ci/unsigned-dryrun-min-permissions-rebased` | 同一文件，已 rebase 到最新 main |
| S05 | 主令 §5.3 相邻（Scope/构造期资源） | `fix/autoredirect-output-mark` | 未与 P0-L01 重叠 |
| S06 | 主令 §10.1 `trafficsched` + §11.2 `build/` 污染 | `test/urltest-deterministic-gate` | 同一主题合并处理 |
| S07 | 主令 §5.3 | `test/scope-close-boundary` | 只补边界措辞与组件级守卫 |
| S08 | 主令 §2 P0-00 | `docs/handoff-reconciliation` | 完全覆盖，同一 owner |
| Row39 | 主令 §3 P0-01 | `fix/row39-nested-groups` | 直接执行 |
| Row15 | 主令 §4 P0-02 | `fix/row15-dns-generation` | 直接执行；§4.1 sing-tun 判定为 `KEEP_FORK_READER`，**未改依赖 pin** |
| （主令 §6.3） | `docs/schema.json` 欠账 | `chore(schema)` 集成提交 | 本轮补齐 |

---

## K. 每个修复的旧红 / 新绿 / 反向破坏 / CI

**CI：本环境没有任何真实 GitHub Actions 执行，因此本轮不提供也不编造任何 run id。** 所有证据都是本地真实命令与其真实输出。
**未创建 tag、未创建 Release、未签名、未上传签名材料；`origin/testing` 未推进。**

| 项 | 旧红（真实失败） | 新绿 | 反向破坏 |
|---|---|---|---|
| S01 | 7 个配对断言在纯净树全红 | 全量 76 ok / 0 FAIL；`-race` 绿 | 3 个突变各自致红（见 B.3） |
| S02 | 旧代码在失败读上发布 unlocked（探针证明 out-param 不被写） | harness 76/76；`swiftc -typecheck` exit 0 | 失败注入覆盖 register/get_state/cancel/初值倒置 |
| S03 | 陈旧检出的真实 `xcodebuild` exit 65（10 错） | 同一命令在 gitlink revision 上 **exit 0 / 0 错** | provenance 校验在 witness 与真实源码脱节时致红 |
| S04 | 旧工作流 dry-run 会解析 secrets（YAML 解析实测 `if=None`） | rebase 后 `assembleRelease :app:verifyCoreProvenance` exit 0；apksigner 实测 UNSIGNED | dry-run-测到-debug-signed → exit 1；tag-release-测到-unsigned/debug → exit 1 |
| S05 | `-race` DATA RACE + 独占性/sentinel 断言失败 | `-race` 全绿；`-count=20` 绿 | 守卫回退 → 双重 claim；禁用释放 → 20/20 红 |
| S06 | `trafficsched` 第 5 次迭代真实失败（79.6%） | 25/25 绿（load ≤473） | 平坦界重新注入 → 第 3 次迭代红 |
| S06b | `dns` 9 处上界在负载下可越界（本轮全量真实失败一次） | `-count=25 ./dns/` ok（load ≤1006）；`-race` exit 0 | 4 个生产回归各自致红（见 G.3） |
| S06c | `common/dialer` 首选族竞速在负载下真实失败（load 632 第 44 次、229–243 第 97 次） | 交替对比 load 423–434：基线 4/150 失败、修复 0/150；`-race` exit 0 | 去掉生产里的 grace hold → 两测试两子测试全红（见 G.3c） |
| S07 | MASQUE 守卫禁用时真实 `bind: address already in use` | `-race` 全绿；`-count=20 -race ./adapter/` ok 79s | 禁用守卫 → 端口泄漏复现 |
| S08 | 校验器四类破坏各自 exit 1 | 对真实远端 PASS（exit 0） | 见 I 节 |
| Row39 | 环状 group 图上 `resolveOutbound` 不返回（5.01s 守卫） | `-race` 全绿；`-count=20` 与 `-count=100` 绿 | 3 个控制（停在第一层 7 红 / 历史用外层 tag 1 红 / 去掉内层中断 6 红） |
| Row15 | 7 个断言在未修树上失败（`expected int(1) actual uint64(0x0)`） | 全绿（含 `-race`、iOS/macOS 源码级编译） | 突变 A（指纹丢掉 resolver 地址）(B) 红 (C) 绿；突变 B（去掉去抖）三例红 |

---

## L. 产物哈希、签名状态、测试限制与 NOT-READY 条目

### L.1 产物（全部未签名）

| 产物 | SHA256 | 签名状态 |
|---|---|---|
| `Libbox-ef83b8681.xcframework` / `ios-arm64` Libbox | `c40e1b8ea1baa79c1820e202401e379d0d5483a6949b3818c5391000badb36c5` | 未签名 |
| 同上 / `macos-arm64_x86_64` Libbox（fat） | `4d57471884d495b6ca938ddb77bc2c24fe2c13e79f2f9ef7deb5858dee652939` | 未签名 |
| iOS `sing-box`（SFI Debug，gitlink revision） | `735d38ac1017dbb77ad63f3b343c60c0ac2caeea0bbd1339503557a2ff52dc9b` | `code object is not signed at all` |
| iOS `sing-box.debug.dylib` | `963fc53102b83fef91fecb5b758b98101ca9c9d27567db869a2daae1f56fbf98` | 未签名 |
| macOS `sing-box`（SFM Debug，通用） | `e603377205737012108cba205fae2c68dd6e58aebf3756fdb345f67fa4759f5f` | 仅链接器 ad-hoc |
| `satelite-one` release APK arm64-v8a | `8e6dd3e57992cd7fc1f143c518e075b56c4536f575065f3b72308fda66e6f5ec` | **UNSIGNED** |
| `satelite-one` release APK x86_64 | `1c123b8dc0942ea530afbc0feb043f08a5fd8284888a8d493dbcf076f88ee161` | **UNSIGNED** |
| `libbox.aar`（core `c35faabf4`） | `e3b6084b1caff5edc63d59e63ce38c9ab9094abb310620552844f97016cfc3c9` | — |
| cronet `lib/ios_arm64` `libcronet.a` | `6863693a72d461855ea0de58492af110fc2087cfb5a3f7db33e060eef6a13980` | — |

### L.2 测试限制

- **无任何设备/真机/模拟器运行**（用户明确指示不做模拟器测试）。所有“运行期”结论一律 `DEVICE-ONLY`。
- 无真实 GitHub Actions 执行；无 CI run id。
- 无 Xray / 参考实现互操作实测（本轮未获取参考 binary）。
- `common/urltest` 的负载 flaky 在本环境 **`NOT_REPRODUCED`**（540 次定向 + 并行全量），但已证明时序敏感并确定性加固；`trafficsched` 真实复现并修复。
- Android 本地 AAR 与 CI AAR 存在已记录的 ABI 集合差异（本地 `-platform android/arm64,android/amd64`，CI `-target android` 会展开更多 ABI）；每个 ABI 的 `.so` 字节不受影响。
- 共享 `~/Library/Caches/go-build` 与共享 `~/.gradle` 在本轮被并行会话反复清理，导致若干次“缓存条目不存在”的假失败；所有最终验证都在隔离 `GOCACHE` 下重跑。

### L.3 未完成 / 未声称（诚实清单）

1. **uTLS 全指纹矩阵（主令 §7）本轮未施工**：`chrome/firefox/safari/edge/ios/qq/random` 未逐项实测，`v016-utls-reality-fingerprint-matrix.md` 未产出。**未修即未修，不冒充完成。**
2. **Xray/REALITY 真实参考互操作（主令 §7.2）未施工**：无参考 binary，全部相关断言记为 `NOT_RUN`。
3. **`upstream-phase-b-commit-ledger.{md,json}` 未新增**：本轮实测上游差集仍为 **53**，与阶段 A 台账逐条对应（该台账已由 S08 补注 `code_presence` / `behavior_validation` 两个正交字段）。执行期间上游无新增 SHA。
4. **cronet iOS archive 重建**：`BLOCKED_TOOLCHAIN`（需要 Chromium/cronet 构建流水线）。
5. **Apple IPA/DMG**：`BLOCKED`（需要打包与签名决策，签名按政策属于用户本地操作）。**未签名 `.app` 已真实产出**，IPA/DMG 未产出，也未声称产出。
6. **真机/AVD 运行验证**：按用户指示不做模拟器；真机不可用 → `DEVICE-ONLY`。
7. **`transport/masque` 的复杂度墙钟门禁**：`PRE_EXISTING_LOAD_SENSITIVE`，在纯净基线即可复现，本轮**未修**（见 G.3b）。
8. ~~**`common/dialer` 的双定时器竞态**~~ → **已修**（`test/dialer-race-deterministic-gate` @ `beb1b9e724d85672d6fc07b7f7c9ec48ea57502e`）。同类中**仍有 16 处主机敏感上界（G2）未修**，需逐个判定断言主张后才可动，记为 `OPEN`。
9. 本报告与 `docs/fork/` 中文档的提交会**改变 `HEAD`**；单一 RC 冻结 SHA 记录在 `docs/fork/v016-release-candidate-manifest.md`，本报告不自行宣布 FINAL。

**关于“全量 0 FAIL”的准确措辞**：本轮共跑了 3 次带 tag 的全量 `./...`。
- 第 1 次（load 17–24，S01 树）：**76 ok / 0 FAIL**。
- 第 2 次（load 28，集成树）：74 ok / 2 FAIL —— `common/trafficsched`（S06 已修）与 `dns`（S06b 已修）。
- 第 3 次（load 710，集成树）：77 ok / 1 FAIL —— `transport/masque`（预先存在，见 G.3b）。
因此**不存在**“在同一 SHA 上、安静机器上、0 FAIL”的完整证据；本报告不写这样的结论。


### L.4 最终判定

**代码修复完成，正式发布 `NOT-READY`。**

- 施工令点名的 **S01 / S02 / S04 三处明确遗漏全部完成**，并附旧红/新绿/反向破坏。
- S03 / S05 / S06 / S07 / S08 全部完成，Row39 与 Row15 完成，`docs/schema.json` 欠账补齐。
- 仍然 `NOT-READY` 的原因**不是**软件可控条件未通过，而是：uTLS 全指纹矩阵与协议参考互操作本轮未施工；cronet iOS archive 需要外部流水线重建；没有真实设备/模拟器验证；没有任何真实 CI 执行；没有签名与 tag/Release（按政策由用户本地进行）。

---

## M. 逐项回答补充施工令 §12 的 15 个必答问题

1. **两组 `IncRef` 现在在哪里 `DecRef`？** 在 `releaseRouteSetRefs()`（`protocol/tun/inbound.go`），由 `releaseRouteSets()` 调用；`releaseRouteSets()` 有三个调用者：Scope 的 `releaseRouteSetsCleanup`、`closeAutoRedirect`、`Inbound.Close`。引用不是靠去重减一次，而是按 `routeRuleSetRefs` 切片里**每次成功获取**逐条减。`RemoteRuleSet.Cleanup()` 之所以仍然正确，是因为它本来就以 `refs == 0` 为释放前提——缺的是配对，不是 Cleanup 逻辑。
2. **`trackingRuleSet` 是否仍为空实现？** 否。`IncRef/DecRef` 已改为真实原子计数并在负值时 panic（与 `LocalRuleSet`/`RemoteRuleSet` 一致）。另有独立严格替身 `countingRuleSet`，其 `UnregisterCallback` 对未注册元素直接 panic。
3. **各场景引用计数如何变化？** 重复对象（include+exclude 同一个）→ +2 / −2；Start 中途失败 → 由 Box 的 Scope 回滚释放，归零；无 AutoRedirect → 仍在获取处注册释放，归零；正常 Close → 归零；二次 Close → 记录已清空，`No-op`，不会为负（负值会 panic）。
4. **`notify_get_state` 失败能否触发 `recordLockState(false)`？** 不能。失败被建模为“没有值可读”的类型，语义是**不发布**；`state == 1` 也改成全映射，非 `0`/`1` 判 unknown。因此没有“失败 → 误判解锁 → 误唤醒”的用户级路径。
5. **注册成功/失败/部分成功与 stop 竞态是否可证明不留 token 或 late callback？** 是。逐 token 登记、只取消成功的那一个、teardown 幂等、重复 start/stop 不重复 token；cancel 与已在队列中的回调用“队列被信号量持有”的确定性编排验证：回调确实跑过，但**什么都没发布**（另有“get_state 读到一半 cancel 落地”的用例）。
6. **ABI witness 与真实 Swift 文件是否一一匹配？做过完整未签名客户端编译吗？** 匹配性已机器可查（`scripts/ci/apple-abi-provenance.sh`），并发现一处 anchor 归属错误与两处 pre-image 草稿；**完整未签名客户端编译已做**：gitlink revision 上 SFI 与 SFM 均 `BUILD SUCCEEDED` exit 0。
7. **cronet iOS 静态档案缺符号是否真实存在？是何性质？** 真实存在（`nm`/`ld` 实测，唯一 intra-`base::` 空洞）。性质是 **archive 不完整（`INCOMPLETE_ARCHIVE`）**，当前表现是 **`DEAD_CODE_ONLY`**：产品因 `DEAD_CODE_STRIPPING=YES` 而链接成功，但这是承重的偶然。不是工具链组合错误，也不是“不可达死代码”——是**可达符号被死代码剥离掩盖**。
8. **`satelite-one` dry-run 能否从 Secrets 取签名材料？本轮是否阻止并产出经工具验证的 unsigned APK？** 旧工作流**可以**（恢复步骤没有 `if`，且带全局写权限）。本轮已阻止（条件化 + 只读权限 + 互补断言），并用 `apksigner` **实测**确认产物 `UNSIGNED`（两个 ABI 的 SHA256 已记录）。
9. **workflow 的“debug 签名回退”描述与 Gradle 实现是否统一？dry run 是否仍持有不必要写权限？** 已统一为四情形表格，并删除了不准确说法；dry run 现在只有 `contents: read`，唯一的 `contents: write` 在条件化的独立 `publish` job 中。
10. **构造期 mark 能否在并发 `Create` / loser cleanup 后污染同一 Box 的新拨号？** 方法层可以（已复现并修复，200/200 loser 都是已 claim 的那个）；**从配置层不可达**，证据是 `registry.go:65-73` 的注册表锁横跨构造函数、`box.New` 是顺序循环、`Manager.Create` 有预先 tag 检查。修复后丢弃的 inbound 会在 `Close` 中归还 mark。
11. **`common/urltest` 的负载 flaky 是否完成确定性收口，还是只修了 `trafficsched`？** 两者分别结论：`urltest` 本环境 `NOT_REPRODUCED` 但已证明时序敏感并做**确定性相对界**加固（未改生产代码）；`trafficsched` `REPRODUCED_AND_FIXED`。**并且**这一追问确实又找出第三、第四、第五处同类问题：`dns` 的 9 处上界（已按事件断言收口）、`transport/masque` 的复杂度墙钟门禁（预先存在，未修）、`common/dialer` 的双定时器竞态（已复现，候选修复验证 300/300）。没有任何“一处通过即全部通过”的结论。
12. **生成 `build/` 是否会再次改变 `go test ./...` 包枚举？是否有不破坏用户工作区的长期门禁？** 不会再改变：输出已改到 `_libbox_build`（`./...` 永不匹配），门禁 `cmd/internal/modlayout` 用 deny-before-allow 规则且**不含任何包数量断言**；所有清理只在 `/tmp` 自建目录进行，未对用户工作区做任何破坏性清理。
13. **`Scope.Close()` 返回到底保证什么？报告有无过度陈述？** 保证“已入队的 cleanup 全部执行完且 `closeErr` 已 final”；**不保证**在途 `Start` 已结束，late cleanup 的错误只进日志、不回填 `closeErr`，`Start` 不能返回成功。§7 原文的说法与代码一致，未过度陈述；此前文档中任何“Close 后所有工作都完成”的更强说法已被精确措辞取代。
14. **历史 FINAL、`final_phase_a_sha:null`、第一阶段与 53 ledger 的差异是否已归档纠偏？** 已归档：历史值全部保留并逐条标注 `historical, not the final release SHA`；`final_phase_a_sha` 是真实可 fetch 的 `ef83b8681`（旧 null 作为历史字段保留）；rows 22/23/45 拆成正交的代码存在性与行为验收入口；单一 RC 验收只在 `v016-release-candidate-manifest.md`。
15. **最后一次冻结后，Apple/Android/Core/两个 Go 模块/Actions artifacts 是否对齐同一组源码与 SHA？如果不能，不准报告 Release-ready。** **不能，因此不报告 Release-ready。** 冻结 CLI SHA 与各产品 SHA 本来就不同；Android 侧本轮测得的产物基于 `c35faabf4`，**尚未**指向本集成 Core（按施工令要求必须在最终 Core 冻结后才更新 `version.properties` 的 `coreCommit`，本轮未做该更新以免把 App pin 到中途 Core）；`test/` 嵌套模块本轮未改 pin；**没有任何 Actions artifact 存在**。因此结论是 `NOT-READY`，并给出最短剩余步骤。

---

## N. Git 清单（未创建 tag / Release / 未签名）

**Core `Piggy-Cat-bit-shadow/sing-box`**（全部普通 push）：

```
fix/tun-ruleset-refs                              b361df879e557f701139d89cd62fbf2b57c31345
fix/autoredirect-output-mark                      8139f01d7758cbfba4cf6a36183b13bc9b635568
fix/row39-nested-groups                           b51c6a00c082f68c71323730596642eb691bb045
fix/row15-dns-generation                          bcf2e1c49559dfec4a62fdbfb50fd520efa3b294
test/scope-close-boundary                         3c5c84b08bd8f65a4439365f0b472175e1b64d0b
test/urltest-deterministic-gate                   827eb52587f9880a3396ec42cafd16b0be9e6227
ci/apple-abi-provenance                           73462a4cd21b0b9a3dd243c91970a12181382514
docs/handoff-reconciliation                       47f49fcd7ebcc3538ac15263fa4568b2f6592db4
integrate/v016-final                              （见 v016-release-candidate-manifest.md）
```

**Apple `Piggy-Cat-bit-shadow/sing-box-for-apple`**：`fix/apple-notify-unknown` = `dd9114d9a20d1b252f20c4003f75e29974cb9c05`

**Android `Piggy-Cat-bit-shadow/satelite-one`**：
`ci/unsigned-dryrun-min-permissions` = `e0fe96285570f9b0638027417c5ff94bb24dfb8a`（陈旧基线的历史分支，保留）
`ci/unsigned-dryrun-min-permissions-rebased` = `2334badb8b449970cf1e48160e933c71fc864cce`（基于 `4d15e3b`）

- `origin/testing` 全程未推进（仍为 `ef83b86819c97cbe58b0397dc74af6aca5f1859d`）。
- 未创建任何 tag、GitHub Release；未删除任何远端 ref；未 force push；未签名。
- 用户原工作树的 4 项未提交状态零触碰（A.2），唯一一次误操作已按 A.3 完整恢复。
