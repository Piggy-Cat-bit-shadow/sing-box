# Lifecycle Stage A — scoped cleanup and upstream design absorption

Two-stage lifecycle remediation, **stage A** (lifecycle). Stage B (non-lifecycle upstream delta) takes
over from the handoff in `docs/fork/upstream-sync-handoff.md`.

| | |
| --- | --- |
| Worktree | `/tmp/s1-life` (isolated; the shared tree was not touched) |
| Branch | `fix/lifecycle-stage1` |
| Baseline | `912ed1efa` = `origin/testing`, unchanged by this stage |
| Stage A final SHA | `f2ea18240` (6 commits, see §8) |
| Upstream comparison | `upstream/testing` = `6afeff4c0f7123b5782f888812e96b8c82c7b699` |
| Merge base | `7a3d4e4a8e71bd7fa824959efdb57b4f39738802` |
| Divergence at that point | origin 1469 ahead / upstream 53 ahead |
| Pushed | **no** — the work order for this stage forbids pushing; the integrator cherry-picks with `-x` |

---

## 1. Is the Fork's `Scope` already equivalent to upstream's scoped cleanup, and was any base
interface re-refactored?

**Yes, and no.**

`git diff a691a4402375535f0329eb9026ab904cfdc1b2eb HEAD -- adapter/lifecycle.go` was empty at the
baseline, confirming the work order's premise exactly. The task was therefore not to re-introduce
`Scope`. No second Scope or ResourceManager was created, no component interface was migrated to a new
`Close()` standard, and the 115-file mechanical port was not performed.

This stage **did** change `adapter/lifecycle.go`, for two reasons that are additive rather than
structural:

- The concurrency contract of `Start`/`Close`/`Add` was undefined, and three windows in it are
  reachable in the product (§4). Upstream has the same windows; §5 of the work order authorises
  defining the state machine, and the "prefer a call-boundary gate if serialisation already removes
  the race" escape was measured and does not apply — `box.go` documents that Close may run while
  Start is in flight.
- The single upstream commit made to the file since `a691a440`, `69601481fd`, was absorbed (§5).

`Scope` remains an ownership-and-cleanup object only. It is not a network-generation validity
arbiter, and nothing in this stage coupled it to one.

## 2. Are the TUN callbacks unregistered by a normal `Box.Close()`, and can a rule-set still reach a
closed inbound?

**Before: no and yes. After: yes and no.** This was the most serious finding of the stage.

`Inbound.Close()` calls `releaseRouteSetCallbacks()`, but nothing on the product close path ever calls
`Inbound.Close()`. `Box.Close()` → `Scope.Close()` runs `scope.Add` entries only; `adapter/inbound/manager.go`
reaches the inbound through `scope.Start`, and the inbound never handed the Scope a cleanup. The
stored `routeRuleSetCallback` slice made the omission look handled. Upstream `a691a44023` registers the
`UnregisterCallback` through `scope.Add` right after each `RegisterCallback`; the Fork had replaced
that with the slice and lost the registration.

Consequence: the rule-set kept an observer pointed at a torn-down `*Inbound` for the lifetime of the
process, and the next rule-set update called `t.autoRedirect.UpdateRouteAddressSet()` on a closed
auto-redirect.

The pre-existing test `protocol/tun/callback_lifecycle_test.go` asserted that `Inbound.Close()`
releases the callbacks. It was true, and it stayed green while the product leaked, because it called
`Inbound.Close()` directly — the "test that verifies the wrong object" trap this project has been
bitten by. The new tests drive `Scope.Start` instead.

Fixed in `53a3f97e8` and `f2c728d10`. `Box.Close()` alone now completes the cleanup.

## 3. Do `NewInbound`, AutoRedirect and the bridge index all have error rollback and a unique owner?

**Bridge index: yes, and it was already better than upstream.** `acquireIndex` is idempotent,
`releaseIndex` is idempotent, and `allocateIndex(scope)` hands the release to the Scope — upstream
`02537831e1`'s bridge half is patch-equivalent here. What was missing was not correctness but
**coverage of the wiring**: `index_leak_test.go` drives the helpers directly (its own comment says so),
so deleting the `scope.Add` inside `allocateIndex` would leak a process-global slot per Box close with
every existing test still green. Four tests now drive the real `adapter.Scope` and all four fail on
that mutation (`6019786ae`).

**AutoRedirect: unique owner, no reachable rollback gap, and the constructor claim judged
NOT-APPLICABLE rather than changed.** `tun.NewAutoRedirect` acquires nothing in the pinned sing-tun
fork — it assigns fields and adjusts marks — so upstream's "move it out of the constructor" buys
nothing here. The one genuine constructor-phase side effect is `RegisterAutoRedirectOutputMark`, and
it is bounded by the per-Box `NetworkManager`: it is the last statement in `NewInbound` (no later
error edge), no path hands a `NetworkManager` across Boxes, and no `MemoryNetworkManager` or
equivalent exists. Full reasoning in `docs/fork/lifecycle-scope-resource-ledger.md` §2. Upstream's
Linux-only gate on `auto_redirect` was **deliberately not absorbed** — §4.5 forbids hardcoding a
platform as unavailable, and the Fork's Apple/Android platform entry must stay.

**A second defect of the same class was found and fixed: `protocol/masque/server.go`.** A MASQUE
server endpoint acquired a device, a listener, a TLS config and an HTTP/3 server and never handed its
`Close` to the Scope, so a real `Box.Close()` left the device and the listening socket open. Fixed in
`e3349044a`. It was found by sweeping every `Start(stage, scope)` type for a `Close` the Scope cannot
reach — the sweep returned exactly two hits on the baseline and none on the final tree.

The full constructor scan (24 candidates) and the false positives are in the resource ledger.

## 4. After `Close()` returns, can a resource registered later still be alive?

**Before: yes. After: no.** `Scope.Add` had no closed-state check. A component whose `Start` ran
outside the lock could append to a queue that `Close` had already taken, and nothing would ever walk
it again — a silent, permanent leak.

Reachable, not theoretical: `box.go` states that `Close` is exported and "an embedder may call it from
any goroutine - including while Start is still running, which the daemon deliberately allows"; and
every dynamic sub-scope in the tree (`dns/transport/local` `serverScope`, `service/resolved`, and the
`resolverScope`s of openvpn/openconnect/tailscale) starts transports into a scope another goroutine
may be replacing.

`Add` on a closing Scope now runs the cleanup on the caller's goroutine, outside the lock, before it
returns. `Start` additionally refuses to report success for a Scope that was cancelled while the
component was starting, because a nil return would tell the caller a live component exists when its
resources have already been released. Five tests fail on the original Scope and pass now; three
reverse-breaks pin each change (`ffdbfa334`, evidence in the test matrix).

## 5. Do repeated and concurrent closes agree?

**Before: no. After: yes.** `Close` took the queue and nil'd it under the lock, so a second concurrent
caller found nothing to do and returned **SUCCESS immediately** — for a teardown that had not finished
and might still fail. The caller could not tell a clean close from a broken one.

`Close` now records the drain result in `closeErr` and closes a `closeDone` channel when it finishes;
every later caller joins that channel and returns the same result. Two concurrent Closes run the
cleanup exactly once and return identical errors
(`TestScopeConcurrentCloseReturnsTheSameResult`, deterministic: whichever closer wins the queue, the
other must not report nil).

`Box.Close()`'s existing `sync.Once` + `atomic.Pointer[error]` meeting mechanism on top was preserved
untouched, as §2.2 requires.

## 6. Is there a wait proof for async task exit, and are there uninterruptible paths?

**Scope-level: yes.** No goroutine is created by `Scope` at all — no timer, no polling loop, no
background cleanup. The join is a channel receive on the drain the first closer is already running, so
the wait is bounded by the cleanups themselves and there is nothing to abandon.
`TestScopeSpawnsNoGoroutines` runs 500 start/close cycles over all four stages and requires the
goroutine count not to grow.

**Component-level: partly, and this stage did not extend it.** `Box.Close()` unregisters the pause
callback and closes the Power Governor *before* the Scope drains, so no lifecycle event can arrive
during teardown. OpenVPN's `loopGroup.Wait()` and the dynamic DNS `serverScope`s already had their
waits, and the work order explicitly forbids writing a second set. The narrower question — whether
every individual HTTP/2, D-Bus and OpenVPN read loop has a bounded exit proof of its own — is **not
closed by this stage** and is recorded as open in the handoff.

## 7. Can the dynamic DNS and endpoint sub-scopes still be replaced while the Box stays open?

**Yes — and this stage made that safe rather than changing it.** No change was made to the
replacement logic in `dns/transport/local/local_resolved_linux.go`, `local_shared.go`,
`service/resolved/transport.go`, or the openvpn/openconnect/tailscale resolver scopes. What changed is
that the `Scope` those transports start into now has a defined contract: a cleanup registered after
the sub-scope began closing is released immediately instead of being dropped, and `Start` into a
cancelled sub-scope reports the cancellation instead of success. That is exactly the interleaving a
server-set replacement creates.

Every one of those call sites closes a *different* scope than the one a cleanup is registered on
(checked, not assumed), which is the direction the contract supports.

## 8. Are normal cancellation and real teardown failure distinguished at close?

**Before: no. After: yes** (`f2ea18240`). `Scope.Close` aggregated every cleanup error, so a resource
already torn down by a network transition reported "closed"/"canceled" and made an orderly shutdown
look like a fault — the same principle this project applies elsewhere, that a local cancellation is
not a remote failure.

The filter is narrow and local: only `Scope.Close`, which is a declared close context. The result is
**expanded before each error is judged**, because `E.IsClosed` is `errors.Is` over a multi-error and
would return true for an aggregate carrying one cancelled error and one real failure — discarding the
real failure with it. There is a test for exactly that, and removing the `E.Expand` fails only that
test. Real failures (route removal, cache flush, rule-set persistence) are still returned, and that
test passes both before and after. One deliberate difference from upstream: the filtered errors are
reported through the Scope logger before being dropped, so filtering removes them from the result
without losing the observation.

## 9. Are active connections, the idle pool, network generation, `TrimMemory` and on-demand resume
semantics preserved?

**Yes — none of them was touched.** This stage changed six files: `adapter/lifecycle.go`,
`protocol/tun/inbound.go`, `protocol/masque/server.go`, and their tests. In particular it did not
touch `runtimecoord.Coordinator` or its environment/reset epochs, `ReferenceManager` and its
idle-only/active-stream policy, the Power Governor or the Apple Sleep/Wake/Lock axes, DNS/Fake-IP/RDRC
isolation, the TUN Direct Fast Path, or local-only signing.

The evidence is the suite rather than an argument: the root package (which holds
`box_lifecycle_test.go`, `box_lifecycle_ordering_test.go`, `box_lifecycle_stress_test.go`,
`box_cross_kind_cycle_test.go`, `box_power_test.go`, `box_close_test.go`), `route/`, `route/rule`,
`dns/...`, `protocol/direct`, `protocol/group`, `protocol/tun`, `experimental/libbox` and
`transport/masque` are all `ok` in the final full run (§10). The DNS-hijack-before-Direct-Fast-Path
ordering contract in particular is unchanged and still covered by
`protocol/tun/direct_fast_path_dns_test.go` and `judge_flow_truth_table_test.go`.

## 10. What was actually run

```console
$ export GOTOOLCHAIN=go1.25.5
$ TAGS=$(cat release/DEFAULT_BUILD_TAGS)
# with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,
# with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,with_xhttp,badlinkname

$ go test -count=1 -tags "$TAGS" ./...      # 76 ok / 0 FAIL, exit 0
$ go build -tags "$TAGS" ./...              # exit 0
$ go build ./...                            # untagged, exit 0
$ gofmt -l .                                # empty
$ go mod tidy -diff                         # empty, exit 0
$ go test -count=1 -race -tags "$TAGS" ./adapter/... ./protocol/tun/ ./protocol/masque/ ./protocol/bridge/
$ go test -count=20 -race -tags "$TAGS" -run '<all new tests>' ./adapter/ ./protocol/tun/ ./protocol/masque/ ./protocol/bridge/
```

`build/` was checked for and does not exist in the tree, so `go test ./...` does not walk
gomobile-generated Go and the 76 count is not inflated.

**`common/trafficsched` — known load-sensitive flake, did not reproduce.** It passed inside `./...` in
106.8 s. `uptime` reported load 8.56 (1-min average) at the start of the run and 16.82 at the end.
This is reported as "the flake did not reproduce at this load", not as a fix and not as a regression.

**Not run, and why.** No `libbox`/`test/` nested-module build and no Apple/Android artifact build:
this stage was forbidden from touching `clients/apple` and `clients/android`, and no Apple/Android
API or ABI surface changed (`adapter.NetworkManager` was deliberately left alone precisely to avoid
one — see §3). No CI run: the work order for this task forbids pushing, and a CI `head_sha` cannot
exist for an unpushed branch.

## 11. Which upstream commits were absorbed, which were judged inapplicable

| Upstream | Subject | Decision | Why |
|---|---|---|---|
| `a691a44023` | Refactor lifecycle to scoped cleanup | **ALREADY-PRESENT** | `adapter/lifecycle.go` is verbatim identical at the baseline. No mechanical port. The Fork's `protocol/tun/inbound.go` *diverged* from it and lost the callback registration — absorbed in `53a3f97e8` |
| `69601481fd` | Ignore closed and canceled errors in scope cleanup | **ABSORBED** (`f2ea18240`) | The only upstream commit to `adapter/lifecycle.go` since `a691a440`. Expanded-before-filter, narrow and close-scoped, plus evidence retention. See §8 |
| `02537831e1` | Move auto-redirect and bridge index allocation out of constructors | **PARTIAL / SEMANTIC-EQUIVALENT** | Bridge half already present and stricter than upstream; coverage added. Auto-redirect half `NOT-APPLICABLE` — `tun.NewAutoRedirect` acquires nothing here and the output-mark claim is per-Box bounded. The Linux-only restriction was **not** absorbed |
| `a364ff4794` | Remove unimplemented hot reload from managers | **NOT-APPLICABLE to this stage** | Not a lifecycle defect; no unreachable lifecycle state was found that this commit addresses. Owner: stage B ledger |
| `efe4db9332` | Close idle connections of unreferenced outbounds and DNS servers | **OUT OF SCOPE / P1-L06** | §8 of the work order. Not attempted: it is an idle/reuse policy change with real risk to active multiplexed streams, and this stage's mandate is the P0 set. Owner: stage B, explicitly transferred |
| `17e950e74c` | Improve idle connection management | **OUT OF SCOPE / P1-L06** | Same as above. `ReferenceManager` reuse and idle draining were deliberately left alone per §2.2 |
| `c6d5bafa36` | Fix on-demand endpoint resume | **NOT-ATTEMPTED / P1-L07** | Endpoint `SetKeepIdleConnections(true)` → `Resume()` semantics were not verified. Owner: stage B |
| `6e3c86f518`, `fd26ea8578` | Use screen state to end device pause on iOS | **NOT-APPLICABLE (already handled)** | The Fork has its own Apple screen/lock-state chain; §2.2 requires preserving it and `screen-on != unlocked`. `clients/apple` was out of bounds for this stage |
| `78d44d52d9`, `df8e2edfd5`, FakeIP persistence, sniff, Xray, Xcode build | Feature correctness | **OWNER: STAGE B** | §1's cross-stage split assigns these to the second document. Not touched |

No upstream file was ported mechanically.

## 12. Was this stage committed, and what are the SHAs?

Committed on `fix/lifecycle-stage1` in the isolated worktree. **Not pushed** (forbidden for this
stage). The integrator cherry-picks with `-x`; all six commits are individually buildable and tested.

| SHA | Subject |
| --- | --- |
| `53a3f97e8` | `fix(tun): give the rule-set callbacks to the Scope that closes them` |
| `f2c728d10` | `fix(tun): release rule-set callbacks before closing the auto-redirect` |
| `e3349044a` | `fix(masque): give the server endpoint's teardown to the Scope that closes it` |
| `6019786ae` | `test(bridge): pin the Scope ownership of the bridge instance index` |
| `ffdbfa334` | `fix(adapter): define the Scope Start x Close x Add contract` |
| `f2ea18240` | `fix(adapter): stop reporting already-closed and cancelled cleanup as failure` |

`53a3f97e8` and `f2c728d10` must be taken together: the first carries the ownership fix, and its
working tree was captured mid-mutation, so its `closeAutoRedirect` body has the teardown order
inverted. The second restores it and says so in its message. No submodule or gitlink changed; no
dependency or `replace` changed.

## 13. Are there release-reachable lifecycle problems left unfixed because of "historical debt"?

None that this stage found and could safely fix. The two ownership defects and the three Scope
concurrency windows are fixed and tested. Three items are **open by decision, not by debt**, and are
listed in the handoff with owners:

- **P1-L06 (idle/reuse ownership)** — `efe4db9332` and `17e950e74c` are genuine gaps, deliberately not
  attempted here because mistaking an active multiplexed stream for idle is worse than the leak.
- **P1-L07 (on-demand / Apple device events)** — `c6d5bafa36` not verified.
- **Per-component async exit proofs** — whether every HTTP/2, D-Bus and OpenVPN read loop has a
  bounded exit of its own was not established. The Scope level is proven; the component level is not.

## 14. What could not be established

- **Real device behaviour.** No TUN interface can be created in this environment (no root; macOS utun
  requires it), and no iOS/macOS/Android device was available. TUN and MASQUE teardown is therefore
  proven at the seam production also uses — a real `Scope`, the real `Start` entry point, the
  production userspace device and a real listening socket — with a device or a platform interface
  injected only where the OS would otherwise be required. Real auto-redirect programming of
  nftables/pf, real TUN route teardown, NetworkExtension memory pressure and jetsam remain
  `DEVICE-ONLY`.
- **Apple/Android build and ABI verification.** Out of bounds for this stage.
- **`-count=20 -race` on the untouched packages.** Run only on the four packages this stage changed.
- **The `common/trafficsched` flake at high load.** Not reproduced at load 8.56–16.82; the load-56
  failure mode is reported, not explained.

---

## 15. The seven hard invariants (§2.1), verified one by one

Each invariant is stated, then what was actually checked against the real code, then the artifact
that keeps it true. Where an invariant is only partly established, that is said rather than implied.

### I1 — Acquire and register before the next possible failure point

*Rule: a socket, file, tun, stack, timer, DBus handler, callback, goroutine, temporary hook or bridge
index must be handed to a unique owner before the next possible failure; anything acquired before
construction needs a stated reason and a local defer/rollback.*

**Verified.** A source-level scan of every `New*`/`Create*`/`Initialize` produced 24 candidates, all
judged (ledger §1). Two were real gaps and both were fixed by moving ownership to the acquisition,
not to the end of the start sequence:

- the TUN rule-set callbacks (`protocol/tun/inbound.go`), acquired in `StartStateStart` before
  `tun.New`, `NewStack`, `ProcessPlatformOptions`, `tunStack.Start`, `tunIf.Start` and
  `autoRedirect.Start` — every one of which can fail;
- the MASQUE endpoint device, acquired in `StartStateInitialize` before four more fallible steps.

The bridge index already compiled with this rule. No constructor in the tree was found to acquire a
resource it does not also register, with the single measured exception recorded as `NOT-APPLICABLE`
(the auto-redirect output mark, ledger §2).

*Kept true by:* the sweep re-run on the final tree returns no hits; the resource ledger records every
verdict.

### I2 — A single releaser

*Rule: one resource is released by one proven final action; `Close()` and `scope.Add()` must not
double-close or double-unregister unless the underlying object is explicitly idempotent and that has
been verified.*

**Verified** by making each releaser idempotent by construction and testing it:

- `releaseRouteSetCallbacks` clears its element slice under the lock and calls `UnregisterCallback`
  outside it, so a second call finds nothing — pinned by `TestCloseIsIdempotentForCallbacks` and by
  `TestScopeOwnedCallbacksCannotFireAfterClose`, which reaches the teardown through both the Scope and
  an explicit `Close()`;
- `backendBase.releaseIndex` is guarded by `indexAcquired` — pinned by `TestReleaseIndexIsIdempotent`
  and `TestScopeCloseCannotDoubleRelease`;
- `ServerEndpoint.Close` was **given** a `sync.Once` in this stage precisely because two paths (the
  Scope and the duplicate-tag loser in `adapter/endpoint/manager.go`) can now reach it — pinned by
  `TestServerEndpointCloseIsExactlyOnce`, which fails if the `Once` is removed;
- `Scope.Close` runs the queue exactly once and records the result — pinned by
  `TestScopeConcurrentCloseReturnsTheSameResult` and `TestScopeCloseIsIdempotentAndOrdered`.

*Kept true by:* the reverse-break tests listed above. No lock is held across an external `Close`:
`Scope.Add` runs a late cleanup after releasing its mutex, and `releaseRouteSetCallbacks` releases
outside the inbound's lock (pre-existing and preserved).

### I3 — Cleanup ordering and dependency inversion, with a local DAG where LIFO is not enough

*Rule: block new events and connections, stop producers, cancel the context, wait for in-flight work,
then release consumers and dependencies; where necessary follow a local DAG rather than trusting that
LIFO holds for every dependency.*

**Verified, and this is where LIFO was proven insufficient.** `Scope.Close` runs cleanups in reverse
registration order. The rule-set callbacks are acquired in `StartStateStart` and the auto-redirect is
closed in `StartStatePostStart`, so by registration order the release would run **last** — after the
auto-redirect it protects is already gone. That is the one window the release exists to close.

The order is therefore expressed *inside* one cleanup (`closeAutoRedirect` releases first, then closes),
not by position, and `TestStartRegistersReleaseBeforeAutoRedirectTeardown` drives both real stages
through a real Scope and asserts *when* the auto-redirect was closed relative to the release. Its
reverse-breaks are the sharpest evidence: registering the bare `autoRedirect.Close` fails it, and
inverting the body fails it, while every count-based test stays green — the defect is invisible to
counting, which is why the assertion is about ordering.

The rest of the DAG is unchanged: `Box.Close` unregisters the pause callback and closes the Power
Governor **before** the Scope drains, so no lifecycle event arrives during teardown; the governor is
registered first in `preStart` so it is stopped last. The DNS-hijack-before-Direct-Fast-Path-bypass
contract in `JudgeFlow` was not touched and is still covered by
`protocol/tun/direct_fast_path_dns_test.go` and `judge_flow_truth_table_test.go`.

### I4 — Cancellation is not exit

*Rule: `cancel()` is a request; completion needs a Join/WaitGroup/completion signal or a controlled
underlying Close. Any path where a goroutine can touch a released object after `Box` returns is a
suspicion.*

**Scope level: established.** `Scope` creates no goroutine at all — no timer, no polling loop, no
background cleanup. The join in `Close` is a receive on a channel the first closer closes when the
drain finishes, so the wait is bounded by the cleanups themselves and there is nothing to abandon.
`TestScopeSpawnsNoGoroutines` runs 500 cycles over all four start stages and requires the goroutine
count not to grow. This directly satisfies the §5 prohibition on "a background `go cleanup()` that
permanently abandons a goroutine".

**Component level: not established by this stage.** Whether every individual HTTP/2, D-Bus and OpenVPN
read loop has a bounded exit proof of its own was not determined. It is recorded as open with owner
PHASE_B in the handoff (`P1-L04`). Saying otherwise would be a claim this stage did not earn.

### I5 — Partial start failure must roll back

*Rule: a failure in `Initialize`, `Start`, `PostStart` or `Started` must leave no resource behind, and
a repeat start must build a new instance rather than reviving a closed Scope.*

**Verified end to end.** `Box.Start` closes the Box when `start()` returns an error, and `Box.Close`
closes the Scope; because this stage moved every new registration to the acquisition, that existing
rollback now covers failures at every later step as well. Pinned by:

- `TestScopeStartFailureRollsBackEveryAcquiredResource` — a component acquires three resources and
  then fails; all three run;
- `TestScopeOwnsRouteSetCallbacks` and `TestScopeOwnsServerEndpointTeardown` — both drive a real
  `Scope.Start` whose component fails *after* acquiring, then assert the release;
- `TestScopeRefusesToRestartAfterClose` — a closed Scope refuses every stage, and a fresh instance is
  the supported restart;
- the pre-existing `protocol/bridge/index_leak_test.go`, which covers abandoned constructors and
  repeated failed starts at scale.

### I6 — Deterministic concurrent close semantics

*Rule: `Close` must be idempotent or explicitly reject; two concurrent Closes must not unregister the
same list node twice; `Close` concurrent with `Start` must not leave resources that are Added
afterwards.*

**Verified.** Three windows were found, made deterministic tests, and closed:

| Window | Before | After | Test |
| --- | --- | --- | --- |
| `Add` after `Close` took the queue | appended to a queue nobody walks — permanent silent leak | runs immediately on the caller's goroutine, outside the lock | `TestScopeRunsCleanupAddedWhileClosing` (deterministic), `TestScopeAddRacingCloseRunsEachCleanupExactlyOnce` (10 000 barrier iterations), `TestScopeConcurrentAddAndCloseStress` |
| `Start` in flight while `Close` runs | returned success for a closed Scope | reports the cancellation | `TestScopeStartDoesNotReportSuccessAfterClose` |
| two concurrent `Close` | the second returned SUCCESS for a teardown that had not finished | both join the drain and return the same result, cleanup exactly once | `TestScopeConcurrentCloseReturnsTheSameResult` |

No wall-clock assertion is used anywhere: the deterministic window is forced with channels, and the
statistical one is released from a single barrier. The contract's one stated limit — `Close` is not
reentrant from a cleanup on the **same** Scope — is documented in the code, and every nested scope in
the tree was checked to close a *different* scope than the one it was registered on.

### I7 — Network lifecycle is not resource lifecycle

*Rule: `NetworkEpoch`/`Rebind`/`Suspend`/`Resume`/`Drain`/`Trim` is not `Close`; persistent resources
rebuilt for a network change still need correct generation ownership.*

**Verified by non-interference, which is the strongest available form for this stage.** The Scope is
an ownership-and-cleanup object only; this stage did not couple it to any generation notion, and did
not change `runtimecoord.Coordinator`, its environment/reset epochs, `ReferenceManager` reuse and idle
draining, the Power Governor and the Apple Sleep/Wake/Lock axes, DNS/Fake-IP/RDRC isolation, or the
TUN Direct Fast Path.

The evidence is the run rather than an argument: the root package — which holds
`box_lifecycle_test.go`, `box_lifecycle_ordering_test.go`, `box_lifecycle_stress_test.go`,
`box_cross_kind_cycle_test.go`, `box_power_test.go` and `box_close_test.go` — together with `route/`,
`route/rule`, `dns/...`, `protocol/direct`, `protocol/group`, `protocol/tun`, `experimental/libbox`
and `transport/masque`, are all `ok` in the final full run.

**What this stage did change is the dynamic-replacement case**: a cleanup registered on a sub-scope
that another goroutine is replacing is now released instead of dropped, and `Start` into a cancelled
sub-scope reports the cancellation. That is `P2-L08`'s replacement path supported, not restructured —
`dns/transport/local`, `service/resolved` and the openvpn/openconnect/tailscale resolver scopes keep
their own generation logic unchanged.

### Cross-cutting: the full lifecycle with no leak, ghost callback, deadlock, double release,
post-close resurrection or cross-generation contamination

The composite path asked for — **construct → start → multi-stage start → close → concurrent close →
start-failure rollback → restart with a new instance** — is covered by the union of:
`TestScopeConcurrentAddAndCloseStress` and `TestScopeSpawnsNoGoroutines` (which run all four start
stages), `TestScopeRunsCleanupAddedWhileClosing` (close concurrent with a start),
`TestScopeConcurrentCloseReturnsTheSameResult` (concurrent close),
`TestScopeStartFailureRollsBackEveryAcquiredResource` (failure rollback),
`TestScopeRefusesToRestartAfterClose` (new instance), and the component-level tests above — all under
`-race`, with `-count=20` on the new tests. No test in this stage uses a wall-clock threshold, and no
goroutine is created by the code under test.
