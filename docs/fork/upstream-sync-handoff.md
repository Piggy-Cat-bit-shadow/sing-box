# Upstream sync handoff — PHASE_A → PHASE_B

Machine-usable handoff for the two-stage lifecycle remediation. **PHASE_B must read this before
touching anything it lists**, so that no commit is cherry-picked twice and no lifecycle interface is
rearranged a second time.

A JSON twin with the same per-commit fields lives beside this file:
`docs/fork/upstream-sync-handoff.json`. **Both files are generated from the same facts**; the phase-A
SHA they record is compared mechanically by `scripts/ci/verify-fork-handoff.sh`.

## 0. Fact model — orthogonal axes, not one status

This document used to carry one status per row, which let "the code is present" and "the behaviour was
tested" collapse into a single word. They are now separate fields everywhere in this file and in the
JSON twin:

| Field | Meaning |
| --- | --- |
| `observed_at_sha` / `observed_at_time` | the historical revision and UTC instant at which a fact was measured |
| `integration_final_sha` | what Stage A actually pushed |
| `current_candidate_core_sha` | the frozen release candidate; **null until the integrator genuinely freezes one** |
| `code_status` | `exact` / `semantic` / `missing` / `adapted` / `n/a` |
| `behavior_status` | `tested` / `fail` / `blocked` / `not_tested` |
| `artifact_status` | an actual `sha256`, or `absent`, or `blocked` — never an intention |

**Orthogonality rule.** `code_status` and `behavior_status` are independent, and a row may be
`code_status=semantic` **and** `behavior_status=not_tested` at the same time. That combination is
neither "done" nor "missing". A row is release-ready only when `code_status ∈ {exact, n/a}` **and**
`behavior_status = tested` **and**, where an artifact is required, `artifact_status` is a real digest.

### 0.1 Verified integration coordinates (added by the reconciliation)

Three different, real, remote-fetchable coordinates. Immutable for the record — do not re-point them.

```
PHASE_A_START=912ed1efad265d8a8f56aaabcabc8f7b171c2baa
INTEGRATION_FINAL_SHA=ef83b86819c97cbe58b0397dc74af6aca5f1859d
PHASE_B_START=98ea14181ca62f7632791aca12eceef8fbb8b3e3
```

| Field | Value | Verified by |
| --- | --- | --- |
| `PHASE_A_START` | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` | ancestor of the integration tip; `git rev-list --count` = 10 |
| `INTEGRATION_FINAL_SHA` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` | `git ls-remote origin refs/heads/testing`; `git fetch origin testing`; `git cat-file -t` → `commit` |
| `PHASE_B_START` | `98ea14181ca62f7632791aca12eceef8fbb8b3e3` — the reconciliation tree tip: the last **content** commit of `docs/handoff-reconciliation`. Its child adds only this coordinate, so both carry the same tree | `git rev-parse`, and after the push `git ls-remote origin refs/heads/handoff-reconciliation` + ancestry against it |
| `upstream_comparison_head` | `6afeff4c0f7123b5782f888812e96b8c82c7b699` | `git ls-remote upstream refs/heads/testing` |
| `merge_base` | `7a3d4e4a8e71bd7fa824959efdb57b4f39738802` | `git merge-base origin/testing upstream/testing` |
| Divergence at reconciliation | fork **1479** ahead, upstream **53** ahead | `git rev-list --left-right --count origin/testing...upstream/testing` |
| CI runs at `INTEGRATION_FINAL_SHA` | **0** | `gh run list --commit ef83b8681…` returned `[]`; the newest run on the repo is at `e2d7ac1be`, **59 commits** behind |

**No CI PASS is claimed for the integration tip.** The Actions evidence that exists is historical and
belongs to older SHAs; `docs/fork/v016-next-round-baseline.json` lists it with its real conclusions.

## 0.2 Coordinates as PHASE_A recorded them — historical, not current remote state

Everything in this table is the PHASE_A working record. `fork_origin_testing`, `pushed` and
`final_phase_a_sha` describe the state **before** integration; the verified post-integration values are
in §0.1 and in the JSON twin's `integrated_remote_state`.

| Field | Value |
| --- | --- |
| `PHASE_A_START` | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` = `origin/testing` at the time of the work |
| `FINAL_PHASE_A_SHA` | see §7 — the tip of `fix/lifecycle-stage1`; the integrator sets it when cherry-picking. **Now verified as `ef83b86819c97cbe58b0397dc74af6aca5f1859d`; the historical value was `null`** |
| `PHASE_A_BASE` (last commit of A before the branch) | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` |
| Fork `origin/testing` | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` — **not moved by PHASE_A** (historical; `origin/testing` is now `ef83b8681`) |
| Upstream comparison HEAD | `upstream/testing` = `6afeff4c0f7123b5782f888812e96b8c82c7b699` |
| Merge base | `7a3d4e4a8e71bd7fa824959efdb57b4f39738802` |
| Divergence | origin 1469 ahead, upstream 53 ahead (historical; at reconciliation: fork 1479, upstream 53 — see §0.1) |
| Branch | `fix/lifecycle-stage1` in worktree `/tmp/s1-life` |
| Pushed | no — integrator cherry-picks with `-x` (**re-verified at reconciliation: still true** — `refs/heads/fix/lifecycle-stage1` does not exist on `origin`; the fork had exactly one remote branch, `testing`) |
| Build tags | `release/DEFAULT_BUILD_TAGS` (with_quic, with_dhcp, with_wireguard, with_utls, with_acme, with_clash_api, with_tailscale, with_ccm, with_ocm, with_cloudflared, with_naive_outbound, with_usbip, with_openvpn, with_openconnect, with_xhttp, badlinkname) |
| Toolchain | `GOTOOLCHAIN=go1.25.5`, `go version go1.25.5 darwin/arm64` |
| Submodule / gitlink changes | **none** |
| Dependency / `replace` changes | **none** |
| Apple / Android API or ABI impact | **none** — `adapter.NetworkManager` was deliberately left unextended to avoid one |

## 1. Status per item

Legend: **FIXED** = code changed and tested · **COVERAGE** = behaviour was already correct, a
load-bearing test was added · **NOT-APPLICABLE** = measured, no reachable defect, deliberately not
changed · **DEFERRED** = a real item, explicitly handed to PHASE_B · **BLOCKED** = needs a device.

| Item | Status | Owner | Commit(s) |
| --- | --- | --- | --- |
| `P0-L01` TUN rule-set callback Scope ownership | **FIXED** | PHASE_A | `53a3f97e8`, `f2c728d10` |
| `P0-L01b` MASQUE server endpoint teardown ownership | **FIXED** | PHASE_A | `e3349044a` |
| `P0-L02` bridge index ownership | **COVERAGE** | PHASE_A | `6019786ae` |
| `P0-L02` auto-redirect constructor side effect | **NOT-APPLICABLE** | PHASE_A | — |
| `P0-L03` `Scope.Start × Close × Add` contract | **FIXED** | PHASE_A | `ffdbfa334` |
| `P1-L05` close-path error semantics (`69601481f`) | **FIXED** | PHASE_A | `f2ea18240` |
| `P1-L04` callbacks / watchers / DBus / background loops | **PARTIAL → PHASE_B** | PHASE_B | — |
| `P1-L06` idle/reuse ownership (`efe4db9332`, `17e950e74c`) | **DEFERRED** (behaviour axis; see §1.1) | PHASE_B | — |
| `P1-L07` on-demand resume + Apple device events (`c6d5bafa36`) | **DEFERRED / DEVICE-ONLY** (behaviour axis; see §1.1) | PHASE_B | — |
| `P2-L08` layered dynamic Scope and restart boundaries | **PARTIAL** | PHASE_A (contract) / PHASE_B (mapping) | `ffdbfa334` |

### 1.1 Rows 22, 23 and 45 — the one-status reading reconciled

`docs/fork/upstream-53-ledger.md` classifies rows 22 (`efe4db9332`), 23 (`17e950e74c`) and 45
(`c6d5bafa36`) as **PATCH-EQUIVALENT / SEMANTIC-EQUIVALENT**, while the table above lists them as
**DEFERRED**. Both are correct: they answer different questions. The ledger measured **code presence
at the fork tip**; PHASE_A recorded **who owns validating the behaviour**. The rows are therefore
split along the fact model of §0, and neither document's original verdict is deleted:

| Row | SHA | `code_status` (presence) | `behavior_status` | Derived release status | Evidence |
| --- | --- | --- | --- | --- | --- |
| 22 | `efe4db9332` | `semantic` — patch-id `fbf7738a92` reachable; the only absent line is a compile-time interface assertion the fork does not need | `not_tested` | **NOT-READY** | ledger row 22 |
| 23 | `17e950e74c` | `semantic` — patch-id `4aaa2372cb`; 466/481 lines; the fork threads `devicePaused` + `SetKeepIdleConnections` instead of upstream's `idleFlushed` | `not_tested` | **NOT-READY** | ledger rows 23, §5.23 |
| 45 | `c6d5bafa36` | `exact` — patch-id `dd19d1cb6c`; 19/19 lines; reverse-apply 5/5 PRESENT | `blocked` | **BLOCKED** (device-only) | ledger row 45 |

So "the fork already has this code" and "nobody has validated this behaviour" are both true, and
neither statement is allowed to overwrite the other. The same split is in the JSON twin under
`upstream_commits[].code_presence` / `.behavior_status`.

## 2. Files touched by PHASE_A — do not re-litigate these

```
adapter/lifecycle.go                        | 138 ++++++++++++-    (P0-L03 + P1-L05)
adapter/lifecycle_scope_test.go             | 320 ++++++++++++++    (new, P0-L03)
adapter/lifecycle_error_semantics_test.go   | 176 ++++++++++++      (new, P1-L05)
protocol/tun/inbound.go                     |  49 ++++-             (P0-L01)
protocol/tun/scope_ownership_test.go        | 268 ++++++++++++++    (new, P0-L01)
protocol/masque/server.go                   |  37 +++-              (P0-L01b)
protocol/masque/scope_ownership_test.go     | 137 +++++++++++++     (new, P0-L01b)
protocol/bridge/scope_ownership_test.go     | 120 +++++++++++       (new, P0-L02)
box_close_test.go                           |  +58 (net)           (P1-L05, Box level)
docs/fork/lifecycle-scope-upstream-sync-report.md       (new)
docs/fork/lifecycle-scope-resource-ledger.md            (new)
docs/fork/lifecycle-scope-test-matrix.md                (new)
docs/fork/upstream-sync-handoff.md                      (this file)
docs/fork/upstream-sync-handoff.json                    (new)
```

**Do not weaken `box_close_test.go`.** `TestBoxCloseRepeatsTheFirstResult` deliberately injects a
real teardown failure, not a cancellation: a cancelled cleanup is not reported as a failure by
contract, so a cancellation there would assert the opposite. The cancellation case lives in
`TestBoxCloseDistinguishesCancellationFromTeardownFailure`, which covers both halves.

**Do not re-do:** the callback ownership in `protocol/tun/inbound.go`, the endpoint teardown in
`protocol/masque/server.go`, the bridge index wiring, or the `Scope` state machine and error filter in
`adapter/lifecycle.go`. **Do not revert or "simplify"** the `closeAutoRedirect` ordering, the
`sync.Once` in `ServerEndpoint.Close`, the expand-before-filter in `Scope.Close`, or the
`scope.Add`-at-acquisition placement in either component — each has a reverse-break test that fails
without it, listed in `docs/fork/lifecycle-scope-test-matrix.md`.

## 3. Commit classification (§13 field set)

| SHA | subject | subsystem | patch-equiv? | semantic-equiv? | decision | implemented_by | tests | risk | owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `a691a44023` | Refactor lifecycle to scoped cleanup | `adapter` | yes | yes | **ALREADY-PRESENT** | n/a — `adapter/lifecycle.go` verbatim identical at baseline | existing | none | PHASE_A |
| `69601481fd` | Ignore closed and canceled errors in scope cleanup | `adapter` | yes | yes | **ABSORBED** | `f2ea18240` | `adapter/lifecycle_error_semantics_test.go` (6 tests) | low — filter is close-scoped and expands before judging | PHASE_A |
| `02537831e1` | Move auto-redirect and bridge index allocation out of constructors | `protocol/bridge`, `protocol/tun` | bridge: yes / tun: no | bridge: yes / tun: n/a | **PARTIAL** — bridge already present + coverage; auto-redirect `NOT-APPLICABLE`; Linux-only gate **not** absorbed | `6019786ae` (tests) | `protocol/bridge/scope_ownership_test.go` (4 tests) | none | PHASE_A |
| `a364ff4794` | Remove unimplemented hot reload from managers | `adapter` | unknown | unknown | **NOT-APPLICABLE** to the lifecycle P0 set | — | — | — | PHASE_B |
| `efe4db9332` | Close idle connections of unreferenced outbounds and DNS servers | `route`, `common/httpclient`, DNS transports | no | no | **DEFERRED** — real gap, deliberately not attempted · *`code_status`: `semantic` (ledger row 22, patch-id `fbf7738a92`) · `behavior_status`: `not_tested`* | — | — | high if rushed: misclassifying an active multiplexed stream as idle | PHASE_B |
| `17e950e74c` | Improve idle connection management | `route`, `common/httpclient` | no | no | **DEFERRED** · *`code_status`: `semantic` (ledger row 23, patch-id `4aaa2372cb`) · `behavior_status`: `not_tested`* | — | — | as above | PHASE_B |
| `c6d5bafa36` | Fix on-demand endpoint resume | endpoints (MASQUE/OpenVPN/OpenConnect/Tailscale/WG) | not verified | not verified | **DEFERRED** · *`code_status`: `exact` (ledger row 45, patch-id `dd19d1cb6c`) · `behavior_status`: `blocked` (device-only)* | — | — | needs the endpoint suspend/resume matrix | PHASE_B |
| `6e3c86f518`, `fd26ea8578` | Use screen state to end device pause on iOS | Apple platform | n/a | already handled by the Fork's own chain | **NOT-APPLICABLE** | — | — | `screen-on != unlocked` must be preserved | PHASE_B (do not touch) |
| `78d44d52d9` | Reset network on DNS server changes | `route`, `dns` | no | no | **OWNER: PHASE_B** (feature correctness, not lifecycle) | — | — | — | PHASE_B |
| `df8e2edfd5` | Rework forward NAT with UDP mapping and fragment support | `route` | no | no | **OWNER: PHASE_B** | — | — | — | PHASE_B |
| FakeIP persistence, protocol sniff, Xray, Xcode cache | various | various | no | no | **OWNER: PHASE_B** | — | — | — | PHASE_B |

## 4. What PHASE_B must NOT do

1. **Do not re-cherry-pick or re-implement** anything in §3 marked ABSORBED / ALREADY-PRESENT /
   PARTIAL.
2. **Do not reintroduce a second `Scope`/`ResourceManager`**, and do not migrate component interfaces
   to a new `Close()` standard.
3. **Do not remove the `scope.Add`-at-acquisition pattern.** A cleanup must be owned from the moment
   the resource exists, because the Box's rollback for a failed start is closing the Scope.
4. **Do not "optimise" `Scope.Close` by removing the `closeDone` join** — a second concurrent closer
   would again report SUCCESS for a teardown that had not finished.
5. **Do not replace `E.Expand` with the raw cleanup result** before the filter. `E.IsClosed` is
   `errors.Is` over a multi-error, so filtering an aggregate hides a real failure travelling with a
   cancelled one. There is a test that fails for exactly this.
6. **Do not close active MASQUE/HTTP2/QUIC/XHTTP transports** in the name of lifecycle uniformity —
   especially the iOS background-push "wake for a moment" path (§2.2).
7. **Do not touch** `runtimecoord.Coordinator` and its environment/reset epochs, `ReferenceManager`
   reuse and idle draining, the Power Governor and the Apple Sleep/Wake/Lock axes, DNS/Fake-IP/RDRC
   isolation, the TUN Direct Fast Path, the low-memory iOS target, or local-only signing.
8. **Do not weaken the `screen-on != unlocked` rule**, and do not treat the Fork's Apple lock-state
   chain as equivalent to upstream's screen-state-only commit.

## 5. Transferred ownership — PHASE_B must skip these

PHASE_A consumed work that a naive reading of the plan might assign to PHASE_B. Explicitly transferred:

- The whole of `P1-L05` / upstream `69601481fd`. **PHASE_B must not re-apply it.**
- The `Scope.Start × Close × Add` contract. **PHASE_B must not restate or re-derive it**; it is
  committed, tested and documented in `adapter/lifecycle.go`.
- The bridge index Scope-ownership tests. The bridge half of `02537831e1` is done.
- The TUN rule-set callback ownership and the MASQUE server endpoint teardown. Both are done; if
  PHASE_B touches `protocol/tun/inbound.go` or `protocol/masque/server.go` for a feature reason, it
  must keep `scope.Add(t.releaseRouteSetCallbacksCleanup)`, `scope.Add(t.closeAutoRedirect)` and
  `scope.Add(s.Close)` exactly where they are.

## 6. Open items, with what would close them

| ID | Item | Status | What closes it |
| --- | --- | --- | --- |
| `P1-L04` | Per-component async exit proofs outside the Scope | **PARTIAL** | PHASE_B: for each of `route/network.go` monitors, `dns/transport/local/local_resolved_linux.go` D-Bus, `protocol/tailscale/endpoint.go` global hooks, openvpn/openconnect read loops, prove or bound the exit. The Scope level is proven; the component level is not |
| `P1-L06` | idle/reuse ownership | **DEFERRED** | PHASE_B, per §8 of the work order |
| `P1-L07` | on-demand resume, Apple lock/screen precedence | **DEFERRED + DEVICE-ONLY** | PHASE_B code review + a real iOS/macOS device |
| `P2-L08` | resource generation vs logical network generation mapping | **PARTIAL** | The Scope contract supports dynamic replacement now; the generation modelling in `dns/transport/local` and URLTest rounds is untouched |
| `DEVICE-ONLY-1` | Real TUN route teardown and auto-redirect programming (nftables/pf) | **BLOCKED** | Root on Linux and a device with `auto_redirect`; see the runbook in §8 |
| `DEVICE-ONLY-2` | NetworkExtension memory pressure, idle trim vs active flows, jetsam | **BLOCKED** | A real iOS device |
| `DEVICE-ONLY-3` | Apple lock/screen/device-wake event ordering | **BLOCKED** | A real iOS/macOS device |

## 7. Commits (cherry-pick with `-x`, in this order)

| # | SHA | Subject |
| --- | --- | --- |
| 1 | `53a3f97e8` | `fix(tun): give the rule-set callbacks to the Scope that closes them` |
| 2 | `f2c728d10` | `fix(tun): release rule-set callbacks before closing the auto-redirect` |
| 3 | `e3349044a` | `fix(masque): give the server endpoint's teardown to the Scope that closes it` |
| 4 | `6019786ae` | `test(bridge): pin the Scope ownership of the bridge instance index` |
| 5 | `ffdbfa334` | `fix(adapter): define the Scope Start x Close x Add contract` |
| 6 | `f2ea18240` | `fix(adapter): stop reporting already-closed and cancelled cleanup as failure` |
| 7 | `3afa000d6` | `test(box): distinguish a cancelled close from a real teardown failure` |

**`53a3f97e8` and `f2c728d10` must be taken together.** The first carries the callback ownership fix,
but its `closeAutoRedirect` body was captured while the worktree was mid-mutation, so it closes the
auto-redirect before releasing the callbacks. The second restores the intended order and says so in
its message. Cherry-picking #1 alone leaves a broken ordering that
`TestStartRegistersReleaseBeforeAutoRedirectTeardown` catches.

`FINAL_PHASE_A_SHA` is the branch tip after the seven commits above **plus** the documentation commit;
the integrator records the exact value when it cherry-picks. PHASE_B must work from the real current
HEAD of `testing` after integration, not from any SHA written in a planning document.

**Resolved (added by the reconciliation):** the integrator did cherry-pick and push. The measured
values are `PHASE_A_START=912ed1efad265d8a8f56aaabcabc8f7b171c2baa`,
`INTEGRATION_FINAL_SHA=ef83b86819c97cbe58b0397dc74af6aca5f1859d` (10 commits integrated) and
`PHASE_B_START` as pinned in §0.1. The seven cherry-picks above landed as `75bba3d65`, `b6f1a0c8a`,
`9235f90ab`, `2d475ecd4`, `9dd91d51b`, `482e4d3a8`, `1490efc57` on top of `912ed1efa`, followed by
three documentation commits (`1331e8567`, `2aecf64eb`, `ef83b8681`).

## 8. Device-only runbook (Chinese, as required)

以下场景**未在 CI 或本机验证**，不得仅凭 CI 推断为“设备验证通过”。

### DEVICE-ONLY-1：真实 TUN 路由卸载与 auto_redirect

1. Linux root 环境，配置含 `auto_redirect` 的 tun 入站，另加 `route_address_set` /
   `route_exclude_address_set` 各一个远端 rule-set。
2. 启动后确认 `nft list table inet sing-box`（或 iptables）已建立，且 `ip rule` / `ip route` 正常。
3. 执行一次 rule-set 更新（触发远端刷新），确认 `updateRouteAddressSet` 被调用且地址集变化生效。
4. 关闭 Box（不是单独调用 TUN.Close）。确认：nftables/iptables 表已删除、TUN 接口已消失、
   无残留路由与 fd、进程退出后 rule-set 不再有任何回调（本次修复的核心断言）。
5. 反向验证：把 `scope.Add(t.releaseRouteSetCallbacksCleanup)` 注掉重编译，第 4 步应观察到
   回调仍被调用（日志出现对已关闭 auto-redirect 的更新错误）。

### DEVICE-ONLY-2：NetworkExtension 内存压力

真实 iOS 设备 + 已在使用的活跃传输（MASQUE / H2 / QUIC），触发内存压力与深度息屏，
确认 idle trim 不误伤活跃流，goroutine / fd / 堆稳定，未被 jetsam。

### DEVICE-ONLY-3：Apple 锁屏 / 亮屏 / 设备唤醒

真实 iOS/macOS 设备：锁定 + 屏幕亮 + 后台 push 不得被判为解锁；真实解锁才解除 pause；
重复事件幂等；stop 之后事件无效。**屏幕亮 != 已解锁。**

### DEVICE-ONLY-4：MASQUE server endpoint 关闭

真实设备或可创建 TUN 的宿主机：配置一个 MASQUE server endpoint，启动后确认监听端口与
设备存在，关闭 Box 后确认端口释放、设备消失、无残留 goroutine。CI 只能验证到本文档所述的
Scope 所有权层。

## 9. Verification performed by PHASE_A (reference SHAs)

| Command | Result |
| --- | --- |
| `go test -count=1 -tags "$TAGS" ./...` | 76 ok / 0 FAIL, exit 0 |
| `go build -tags "$TAGS" ./...` | exit 0 |
| `go build ./...` (untagged) | exit 0 |
| `gofmt -l .` | empty |
| `go mod tidy -diff` | empty, exit 0 |
| `go test -count=1 -race -tags "$TAGS" ./adapter/... ./protocol/tun/ ./protocol/masque/ ./protocol/bridge/` | all ok |
| `go test -count=20 -race -tags "$TAGS" -run '<all new tests>'` on those four packages | all ok |
| `common/trafficsched` inside `./...` | passed; known load-sensitive flake **did not reproduce** |

`build/` (gomobile-generated Go in the repo root) was checked for and is **absent**, so `go test ./...`
does not walk it and the 76-package count is not inflated.

No CI run exists for this stage: the branch was not pushed, so there is no `head_sha`, job ID or
artifact provenance to reference. Nothing in this handoff claims device verification.
