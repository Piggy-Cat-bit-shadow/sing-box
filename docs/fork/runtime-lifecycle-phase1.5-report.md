# Phase 1.5 — runtime lifecycle / network recovery

What was built, what was already there, what the tests prove, and what is still not covered.

Phase 1 is `lx-stability-audit-phase1.md`. This phase establishes the runtime-resource foundation
that the deferred protocol work (XHTTP, VLESS Encryption, REALITY) is meant to build on, and it
implements LX 041 in-tree. The architectural model is in `runtime-lifecycle-phase1.5.md`; this
document is the engineering record.

## 1. Baseline

| | |
| --- | --- |
| Branch | `testing` |
| Baseline HEAD | `9e20e7c74` — *stability: pin the gVisor nil-handshake guard fork (LX 048)* |
| Dependency forks at baseline | `Piggy-Cat-bit-shadow/sing-tun` (LX 040), `Piggy-Cat-bit-shadow/gvisor` (LX 048) — both untouched |
| Third fork added | **none** |
| Toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`) |

041 was reread from `SPECS/TASKS/041-WG_HANDSHAKE_GIVEUP_REBIND` before implementing, including
`HISTORY.md`: v1 shipped "give-up only" and the field dump showed the residual problem was
**latency**, not correctness — the user measures a node in the 0–35 s after a wake and the give-up
cycle takes ~90 s. v2 added an early trigger and an event nudge. This implementation follows that
conclusion; the earlier Phase-1 note ("give-up only, no flag") would have reproduced the field
residue.

## 2. What was already there, and what was actually missing

Established by reading the tree, not by assuming the brief's inventory. Four pieces already existed
and are reused, not duplicated:

| Existing mechanism | Verdict |
| --- | --- |
| `NetworkResetGeneration` + `NetworkTransitionSnapshot` | Already the single ownership authority, with the DURING-transition case handled (`startedStable`). Reused. |
| `common/dialer` ownership guard (`captureEpoch` / `stillCurrentEpoch`) | Already rejects a connection that began in a previous generation. Reused; **no second epoch was created**. |
| DNS generation barrier (`dns.Router.ResetNetwork` advances first, then resets transports) | Already stronger than the audit assumed. No change; the hazard list is now pinned by named tests. |
| Real-vs-generated traffic discrimination (`Router.RouteConnectionEx` → `observeTraffic`) | Already structural. Reused as the definition of "demand". |

What was genuinely missing:

1. no coordination between the recovery decisions of different resources — each had its own timer
   or none at all, and a reset burst fanned out to everything;
2. a background probe could wake a suspended endpoint (WireGuard's `DialContext` always resumed);
3. no trim path: `ReleaseMemory` was the only memory response and it resets the network;
4. LX 041 itself;
5. `adapter.Router` had no memory-trim surface at all, so idle DNS pools were outside every trim.

## 3. Files changed

Added:

| File | What |
| --- | --- |
| `adapter/runtime.go` | `ErrResourceSuspended`, background-probe context marker, `RebindReason`, `Rebindable`, `RecoveryWindow` |
| `common/runtimecoord/coordinator.go` | the coordinator: generation publication, per-resource recovery window, cancellation |
| `common/runtimecoord/coordinator_test.go` | 14 tests |
| `transport/wireguard/recovery.go` | LX 041 |
| `transport/wireguard/recovery_test.go` | 11 tests |
| `common/httpclient/managed_transport_reset_test.go` | 4 tests (transport-epoch replacement) |
| `protocol/group/urltest_background_probe_test.go` | 4 tests (probe origin + health exemption) |
| `protocol/masque/lifecycle_generation_test.go` | 4 tests (single engine, Close, suspend, leak) |
| `route/runtime_coordinator_integration_test.go` | 5 tests (epoch agreement, trim ≠ reset) |
| `docs/fork/runtime-lifecycle-phase1.5.md` | model + invariants |
| `docs/fork/runtime-lifecycle-phase1.5-report.md` | this file |

Modified:

| File | Change |
| --- | --- |
| `adapter/network.go` | `NetworkManager.TrimMemory(ctx)` |
| `adapter/router.go` | `Router.TrimIdleResources()` |
| `box.go` | construct + register the coordinator; attach the reference manager to the router; close the coordinator **first** so its cleanup runs **last** |
| `route/network.go` | `NetworkManager.TrimMemory`; publish each transition to the coordinator |
| `route/router.go` | `TrimIdleResources`; `SetReferenceManager` |
| `route/reference.go` | `TrimIdleResources` (progressive pass) |
| `transport/wireguard/endpoint.go` | recovery state/registration; session-state observer; the resume gate; the device-wake nudge callback; `Close` teardown |
| `protocol/group/urltest.go` | read the probe origin **before** the operation context is rebuilt; apply it to the operation context; exempt `ErrResourceSuspended` from health accounting |
| `transport/masque/client.go` | `ActiveLoops()` + loop counter |
| `daemon/started_service.go`, `experimental/clashapi/api_meta_group.go` | declare `ProbeForeground` on the user-initiated RPC paths |
| `service/oomkiller/timer.go` | the idle-release path calls `TrimMemory` before `FreeOSMemory` |
| `dns/transport` test doubles | none needed |
| `route/rule/rule_item_rule_set_test.go`, `protocol/masque/constructor_services_test.go` | new interface methods on the doubles |

## 4. Interfaces added or changed

```go
// adapter
type NetworkManager interface {
    ...
    TrimMemory(ctx context.Context)     // NEW: progressive; must not reset or dial
}
type Router interface {
    ...
    TrimIdleResources()                 // NEW: progressive; must not reset or dial
}

var ErrResourceSuspended error          // NEW: local idle decision, not a path failure
func IsResourceSuspended(err error) bool
func ContextWithBackgroundProbe(ctx) context.Context
func IsBackgroundProbe(ctx) bool

type RebindReason uint8                 // NEW
type Rebindable interface { RebindStale(ctx, RebindReason) error }   // NEW, optional
const RecoveryWindow = 90 * time.Second

// transport/masque
func (c *Client) ActiveLoops() int64    // NEW: makes the single-engine invariant assertable

// common/runtimecoord
func New() *Coordinator
func (c *Coordinator) Epoch() uint64
func (c *Coordinator) Advance(epoch uint64)
func (c *Coordinator) Register(label string) (*Registration, func())
func (c *Coordinator) GenerationChanged() (uint64, <-chan struct{})
func (r *Registration) Stale() bool
func (r *Registration) Acknowledge()
func (r *Registration) ScheduleRebind(adapter.RebindReason) bool
func (r *Registration) CompleteRebind()
func (r *Registration) WakeAllowsRebind() bool
```

`adapter.Lifecycle` is unchanged. No `Suspend`/`Resume`/`Wake`/`Rebind`/`Trim` was added to it, and
no protocol that lacks a long-lived binding had to implement anything.

## 5. The coordinator, and how it stays small

Responsibilities are registration, generation publication, cancellation and the recovery window.
It has no protocol knowledge and no per-resource state beyond a window and a pending flag. The
network manager publishes to it from `beginTransition`, **after** the transition lock is released
(invariant 8); the lock guards ownership only.

Two decisions worth recording:

**The window is armed when a rebind is GRANTED, not when it completes.** The first version armed it
on completion. A test with four same-window give-ups that each complete instantly then granted four
rebinds — the coalescing was silently absent, and it would have been four socket rebuilds per burst
in production. Caught by `TestScheduleRebindCoalescesABurst`; fixed by arming at schedule time.

**A published generation is not an acted-on generation.** `Stale()` reports true from the moment a
transition is published until the resource acknowledges the rebuild. The first version compared
counters and reported "current" as soon as the notification was delivered, which is exactly when a
resource is still holding sockets bound to the old network. Caught by
`TestAdvancePublishesMonotoneGenerations`; fixed with `observed` + `Acknowledge()`.

## 6. LX 041 — root cause and implementation

**Failure mode.** After sleep/wake or a handover, the per-flow state on the path (NAT mapping, DPI
classification) is gone while the peer keeps retrying handshakes into the same 5-tuple. The retry
cycle gives up after `MaxTimerHandshakes`, and then keeps the dead socket forever: the endpoint is
configured, the device is up, and it never connects again.

**Signal.** `Device.SetSessionStateFunc` (verified in the pin, `wireguard-go
v0.0.8-0.20260929150556-ca3bc60c4ce7`). The device publishes `PeerSessionHandshake` when a retry
series starts, `PeerSessionEstablished` on success, and `PeerSessionExpired`/`PeerSessionNone` when
the cycle gives up. The callback is delivered under the peer's session-state lock and must not call
back into `Device`, so it records primitives and nudges a non-blocking channel; all policy runs on
the recovery worker.

**Three triggers, one mechanism.**

| Trigger | Signal | Reason |
| --- | --- | --- |
| give-up | `PeerSessionExpired` / `PeerSessionNone` | `handshake-give-up` |
| early | `PeerSessionHandshake` still current after 15 s | `session-expired` |
| nudge | `pause.EventDeviceWake` | `device-wake` |

**Rebind.** Unpinned `listen_port`: `IpcSet("listen_port=0")` releases the ephemeral port and
`BindUpdate` opens a new one — a new 5-tuple, which is what a manual reconnect does and what heals
it in the field. The endpoint's own lock is not held across the UAPI call.

## 7. Debounce model

One rebind per resource per `RecoveryWindow` (90 s), shared by all three triggers, enforced by the
registration. A burst of four give-ups is one rebind. A rebind in flight coalesces further triggers.
A trigger of a different *kind* in the same window is still the same series and coalesces. A new
network generation clears the window, because the previous window described a network that is gone:
a failure after a handover is a new fact and may be acted on immediately. A burst of ten resets with
no failure signal produces **zero** rebinds — a reset is not evidence that anything is broken.

## 8. Stale model, and why stale ≠ dead

Nothing is closed on a network change. A resource is *marked* stale: the next operation that would
reuse it rebuilds lazily. Concretely: the DNS pools drop cached connections but checked-out ones
survive to natural completion; the HTTP transport epoch is replaced with the old epoch retired only
when its last user releases it; a WireGuard endpoint is not torn down at all — only its socket is
reopened, and only when a proven failure or a device wake earns it. No active flow is killed by a
reset, a trim or a recovery.

## 9. Wake semantics (no background wake)

`DialContext` and `ListenPacket` on a suspended WireGuard endpoint now refuse a **background probe**
with `adapter.ErrResourceSuspended` instead of resuming. A demand dial is unmarked and resumes as
before. The marker is set by the automatic URLTest path and deliberately *not* by the user-initiated
paths (`StartedService.URLTest` RPC, the Clash API delay test), which are demand in the product
sense.

The health layer treats the sentinel as "not measured": it logs at debug and leaves the member's
existing health evidence untouched, so a periodic timer cannot move a group's selection. A real dial
failure is still recorded as one.

One wiring defect was found here and fixed: `URLTestGroup.operationContext` rebuilds the operation
context from the group's own context, so a marker on the caller's context is dropped. The origin is
therefore read from the caller *before* the rebuild and re-applied to the operation context. Without
that, every round looked foreground and would have woken idle endpoints — the exact opposite of the
requirement.

## 10. Network generation model

Unchanged in mechanism, newly shared in practice. The dial layer's ownership guard remains the only
authority for "was this connection produced for the current network"; the DNS generation barrier
remains the only authority for DNS; the coordinator's epoch is published from the *same* transition,
and a route-level test asserts the two counters do not drift. Nothing polls: the coordinator pushes
once per transition, and resources that have no continuous worker pull at reuse time
(`Registration.Stale`).

## 11. MASQUE

No lifetime change. The audit's three concerns were each either already handled or now pinned:

1. **Remembered H2/H3 verdict across a network change.** `ManagedTransport.Reset` swaps the epoch and
   (for the Go engine) builds a fresh inner transport, so the H3-broken backoff memory — which lives
   inside that transport — does not survive. Pinned by
   `TestManagedTransportResetReplacesTheInnerTransport`; the counter-cases (no reset → one epoch;
   `Close`/`CloseIdleConnections` → no rebuild) are pinned too. The rebuild is lazy, so a reset does
   not produce a dial.
2. **`Close` vs a blocked writer.** The H2 request path already wires cancellation
   (`context.AfterFunc` → `cancel`) and the H3 setup does the same with `CancelRead`/`CancelWrite`;
   the tunnel setup uses `context.AfterFunc` as well. Newly assertable rather than assumed: the
   single-engine invariant is pinned by `Client.ActiveLoops()` under a 20-round
   restart/suspend/resume cycle.
3. **H3 CONNECT with no response.** Already bounded: the request context cancels the stream before
   and after `SendRequestHeader`, so a peer that completes the QUIC handshake and never answers
   CONNECT cannot park a build — the read fails with the context error.

## 12. DNS

No implementation change was required, and that is a finding rather than an omission. The generation
barrier and the pool reset already cover every hazard LX 108 named, and each has a named test
(`TestDialStartedBeforeResetIsNotHandedOut`, `TestIdleConnectionIsNotReusedAfterReset`,
`TestReleaseOfAConnectionFromAReplacedStateIsNotPooled`, `TestSerialPoolResetDropsConnections`,
`TestGenerationAdvancesOnlyOncePerReset`, `TestLateResponseAfterResetIsNotRecorded`). Phase 1.5's
contribution is the other half: idle DNS transport connections are now inside the memory-trim path,
which they were not before.

## 13. Memory pressure

`service/oomkiller` still owns the policy and the Darwin pressure source is untouched. The change is
one step in the existing idle-release path: memory that is elevated but below the trigger now calls
`NetworkManager.TrimMemory` before `FreeOSMemory`. Trim closes idle outbound/endpoint connections and
idle DNS transport connections, and does nothing else — no reset, no wake, no rebuild, no dial. The
aggressive path (`ReleaseMemory`) is unchanged and still resets.

Two tests pin the distinction at the manager level: a trim must not advance the network generation
and must reach the router's trim path; `ReleaseMemory` must advance it and reach the reset.

## 14. Race and deadlock analysis

- The coordinator's lock guards bookkeeping only; `Advance` notifies with it released (invariant 8),
  and a test proves `Advance` returns while a concurrent `Epoch()` would otherwise deadlock.
- `NetworkManager.beginTransition` publishes via a deferred call, so the coordinator is never
  notified under `transitionAccess`.
- The WireGuard session callback runs under the peer's session-state lock; it takes only its own
  lock, never `stateAccess`, never the device.
- `IpcSet`/`BindUpdate` are called with no endpoint lock held — the same rule `Start` follows, for
  the same reason (the device's UAPI runs the pause/network callbacks, which take `stateAccess`).
- `Close` sets `closing`/`closed` under the locks the worker reads, so a rebind cannot outlive its
  endpoint; tested for both the scheduled and the in-flight case.
- `-race` is clean on all new suites. The one pre-existing race
  (`transport/wireguard` → sing-tun `stack_go.go` Start/Close, `TestStackDeviceConcurrentStartAndCloseDoNotPanic`)
  is unchanged and documented in Phase 1.

## 15. Regression matrix

| # | Case | Test | Result |
| --- | --- | --- | --- |
| A | multiple give-ups → one rebind | `TestGiveUpBurstProducesOneRebind`, `TestScheduleRebindCoalescesABurst`, `TestConcurrentTriggersGrantOneRebind` (32 goroutines) | pass |
| B | suspended endpoint → marked stale, **no** wake; later demand wakes | `TestSuspendedEndpointIsNotReboundByRecovery`, `TestWakeNudgeOnlyRebindsAStaleSession`, `TestResumeGateRefusesOnlyBackgroundWork` | pass |
| C | background probe does not wake an idle endpoint | `TestAutomaticHealthProbeIsMarkedAndSuspendedMembersKeepTheirEvidence`, `TestBackgroundProbeDoesNotWakeASuspendedEndpoint`, `TestFreshEvidenceSkipsTheMemberEntirely` | pass |
| D | user demand may recover/wake | `TestForegroundProbeIsNotMarkedAsBackground`, `TestResumeGateRefusesOnlyBackgroundWork` | pass |
| E | generation N operation must not be published as N+1 | Phase 1 dialer ownership guard (`common/dialer`) + `TestTransitionPublishesTheCoordinatorAtTheSameEpoch` | pass |
| F | new demand after the transition builds against the new generation | `TestNewGenerationGrantsItsOwnRebind`, `TestManagedTransportResetReplacesTheInnerTransport` | pass |
| G | Close vs debounce | `TestCloseCancelsAScheduledRebind`, `TestCoordinatorCloseInvalidatesRegistrations`, `TestMasqueCloseRefusesLaterRecovery` | pass |
| H | Close vs in-flight rebind | `TestCoordinatorCloseInvalidatesRegistrations`, `TestMasqueCloseRefusesLaterRecovery` | pass |
| I | 10 resets → no 10 rebuilds | `TestResetBurstDoesNotProduceRebuilds`, `TestTrimDoesNotResetTheNetwork` | pass |
| J | stale remembered H2 cannot stick (H3 verdict not carried over) | `TestManagedTransportResetReplacesTheInnerTransport` | pass |
| K | H3 CONNECT with no response is bounded | `transport/http` `context.AfterFunc` paths + existing H3 lifecycle tests | covered |
| L | DNS does not blindly reuse a stale pooled connection | the six named DNS tests | pass |
| M | memory pressure trims idle, preserves active, triggers nothing | `TestTrimDoesNotResetTheNetwork`, `TestTrimReachesTheRoutersTrimPath`, `TestReleaseMemoryResetsTheNetwork`, `TestManagedTransportCloseIdleConnectionsDoesNotRebuild` | pass |
| N | restart stress, no worker/goroutine accumulation | `TestRecoveryDoesNotAccumulateWorkers` (25 cycles), `TestMasqueRestartCyclesDoNotLeakLoops` (15 cycles) | pass |

Additional invariants pinned: epoch monotonicity and no-backwards-advance
(`TestAdvancePublishesMonotoneGenerations`), late registration is not stale
(`TestRegistrationStaleUntilItObserves`), removal invalidates
(`TestRemovalInvalidatesRegistration`), nil coordinator is inert and a no-op path
(`TestNilCoordinatorIsInert`, `TestTransitionWithoutACoordinatorStillAdvancesTheEpoch`), a healthy
session is never stale (`TestEstablishedSessionIsNotStale`), the device-wake nudge is wired and
distinct from the network-wake callback (`TestDeviceWakeNudgeIsWiredAndSkipsIdleEndpoints`), and the
WireGuard state callback is race-free under concurrent readers
(`TestSessionStateCallbackIsRaceFree`).

## 16. Performance

The requirement was "no new idle cost", and the shape of the change respects it:

- **idle:** zero new goroutines, timers or traffic. The WireGuard worker is created on the first
  give-up and exits when nothing is stale; the coordinator has no goroutine and no timer at all —
  it is a lock, a counter and a channel. `TestRecoveryDoesNotAccumulateWorkers` and
  `TestMasqueRestartCyclesDoNotLeakLoops` make an accumulation a failure.
- **per-transition:** one `Advance` → one lock, one channel close and N registration notifications,
  where N is the number of registered resources (currently the WireGuard endpoints, so one per
  endpoint with recovery). Not O(endpoints) per second — there is no polling anywhere.
- **per-dial:** one boolean context lookup on the WireGuard dial path.
- **memory pressure:** the trim closes pools that exist to be reused, so it strictly reduces
  memory. `TestManagedTransportCloseIdleConnectionsDoesNotRebuild` proves it cannot cause a dial.

No benchmark is claimed. The assertions are structural (counters, cycle tests) rather than
timing-based, which is what the brief asked for.

## 17. Full validation

| Check | Result |
| --- | --- |
| `gofmt -l cmd include option protocol route service transport common dns adapter box.go` | clean |
| `go test -tags <release> ./...` | 56 packages ok |
| `common/tlsfragment` (3 tests) | **pre-existing, environment**: no external network (`dial tcp 1.1.1.1:443: connect: operation timed out`) |
| `experimental/libbox` `[build failed]` | **pre-existing**: test-binary-only `link: invalid reference to runtime.fwdSig` under `badlinkname`; the release binary links fine |
| `go test -race` on all new suites | pass |
| `go mod tidy -diff` | clean |
| `scripts/ci/verify-upstream-assumptions.sh` | PASS (both forks, no changes) |
| main release binary | links (127 MB) |
| linux/amd64, darwin/arm64, darwin/arm64+`low_memory` | OK |
| windows/amd64 | OK without `badlinkname`; **pre-existing** `tfo-go/v2: invalid reference to net.(*netFD).init` with it |
| android/arm64 + `with_gvisor` libbox, linux/amd64 + `with_gvisor` libbox | OK |
| build with `with_naive_outbound` | **pre-existing, environment**: cronet-go has no prebuilt lib for linux/amd64, windows/amd64 or android/arm64 |
| `with_gvisor` provenance / 048 tripwire | PASS (unchanged) |
| 040 tripwire | PASS (unchanged) |

## 18. Unresolved risks

1. **No device-level reproduction.** The give-up and early triggers are driven deterministically
   through the real callback and the real rebind path, but the recovery was not observed healing a
   real tunnel across a real handover. Field validation is still owed, as it was for 041 in its
   source project.
2. **A pinned `listen_port` limits recovery.** The socket is reopened on the same port, so the
   5-tuple does not change; if the intermediate device pinned the flow, that is not enough. Logged
   when it applies; not fixable in-tree without silently changing the user's configuration.
3. **Proactive re-initiation is bounded by the pin.** `SetSessionStateFunc`'s contract forbids
   calling back into `Device`, and the pin exposes no public "initiate now", so recovery reopens the
   socket and the next demand initiates. Both real scenarios are demand-driven, so this costs
   nothing in practice, but a trigger with zero pending data would only move the socket.
4. **The early window (15 s) is a judgement, not a measurement.** It is derived from the retry
   cadence and the field report, and it is one constant. A network slow enough that a legitimate
   handshake exceeds 15 s would earn one rebind per window; the rebind is bounded and idempotent, so
   the cost is a reopened socket, not a loop.
5. **`Registration.Acknowledge` is opt-in.** A future resource that observes a generation and
   rebuilds must call it, or `Stale()` keeps reporting true for it and it rebuilds on every reuse.
   The failure is conservative (extra rebuilds, never reuse of a stale resource), but it is a
   contract a new integration must follow.
6. **Two counters still exist** (`networkResetGeneration` and the coordinator epoch). They are
   asserted equal in the transition path, but they are not the same object.

## 19. Commits

See §20 for the final HEAD; the phase is 7 logical commits on `testing`:

| # | Commit | Contents |
| --- | --- | --- |
| 1 | `runtime: add the resource lifecycle coordinator` | `adapter/runtime.go`, `common/runtimecoord/*`, coordinator tests |
| 2 | `network: publish each transition to the runtime coordinator` | `route/network.go`, `route/router.go`, `box.go`, manager-level trim split, route integration tests |
| 3 | `wireguard: recover a stale handshake without waking an idle endpoint` | `transport/wireguard/{recovery.go,recovery_test.go,endpoint.go}` — LX 041 |
| 4 | `urltest: keep background probes from waking idle resources` | `adapter` probe marker use, `protocol/group/urltest.go`, probe tests, daemon/Clash foreground declaration |
| 5 | `masque: pin the single-engine and transport-epoch invariants` | `transport/masque/client.go`, MASQUE lifecycle tests, `common/httpclient` epoch tests |
| 6 | `runtime: trim idle resources under memory pressure` | `service/oomkiller/timer.go`, trim tests |
| 7 | `docs(fork): phase 1.5 runtime lifecycle model and report` | both docs, audit status update |

## 20. Final HEAD

`testing` at the tip of this phase. Remote: `origin/testing` on
`github.com/Piggy-Cat-bit-shadow/sing-box`. The exact SHA and the push state are reported in the
session summary, because this document is written before the final push.

## 21. Recommended Phase 2 entry point

The foundation is in place; the protocols that were deferred can now be integrated without each
inventing its own worker. The recommended order:

1. **XHTTP** (carry-list 050/061/076/077/082/094/104) — the first real consumer. It should register
   with the coordinator during `Start`, capture the ownership guard for any reusable connection, and
   return `adapter.ErrResourceSuspended` rather than waking a suspended resource from background
   work. Doing it first exercises the capability model on something new rather than on a protocol
   already retrofitted.
2. **QUIC / Naive** runtime integration — both hold pools that are already epoch-replaced; the work
   is verifying they are inside the trim path and that a background probe cannot wake them, which is
   the same test shape as §15 C/D.
3. **VLESS Encryption** and **REALITY** — protocol-level, and should need nothing from this phase
   beyond the invariants.

Two things should be done *before* that work rather than during it: field-validate 041 (§18.1), and
add the `Acknowledge` call to any new resource's rebuild path as part of its integration checklist
(§18.5).
