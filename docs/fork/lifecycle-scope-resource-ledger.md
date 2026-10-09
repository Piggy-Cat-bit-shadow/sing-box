# Lifecycle Stage A — resource ownership ledger

Stage A of the two-stage lifecycle remediation. This ledger is the §4 step 1 artifact: every
`New*` / `Create*` / `Initialize` in the tree was scanned for an acquisition with a real side effect,
and each one is recorded with its allocation site, its first error edge, its owner and its release.

Baseline: `912ed1efa` (`origin/testing`). Branch `fix/lifecycle-stage1`.

Method: a source-level scan of every constructor-shaped function for goroutine spawn, listener bind,
file open, timer/ticker, signal handler, process-global registration, finalizer and raw socket. 24
candidates came back. Each was then read and judged; the table below records the verdict for every
one that is not a false positive.

## 1. Verdicts

| # | Allocation site | Resource | First error edge | Owner | Release | Verdict |
|---|---|---|---|---|---|---|
| 1 | `protocol/tun/inbound.go` `Start(StartStateStart)` — `routeRuleSet.RegisterCallback` | rule-set observer registration, per route and per exclude rule-set | `tun.New` / `NewStack` / `tunIf.Start` after registration | **was: none** → `Scope` | `releaseRouteSetCallbacks` (idempotent), registered via `scope.Add` at acquisition | **DEFECT, FIXED** (`53a3f97e8`, `f2c728d10`) |
| 2 | `protocol/masque/server.go` `Start(StartStateInitialize)` — `device.New` | userspace/system TUN device | `tlsConfig.Start`, `device.Start`, `listener.Start`, `ListenHTTP3` in `StartStateStart` | **was: none** → `Scope` | `ServerEndpoint.Close` (now `sync.Once`-guarded), registered via `scope.Add` at acquisition | **DEFECT, FIXED** (`e3349044a`) |
| 3 | `protocol/bridge/backend.go` `allocateIndex` | one of `bridgeMaxInstances` process-global slots | `allocateBridgeIndex` itself; later Start steps | `Scope` | `releaseIndex` (idempotent) via `scope.Add` | already correct — **tested proof added** (`6019786ae`) |
| 4 | `protocol/tun/inbound.go` `NewInbound` — `networkManager.RegisterAutoRedirectOutputMark` | process-wide fwmark that `common/dialer` consults for every outbound socket | none — the call is the last statement of `NewInbound` | `route.NetworkManager`, which is per-Box | none needed | **NOT-APPLICABLE** — see §2 |
| 5 | `experimental/cachefile/cache.go` `New` — `time.NewTimer(...)` then `Stop()` | stopped timer | n/a | `CacheFile` | timer never armed | **FALSE POSITIVE** — a stopped timer holds no goroutine and no OS resource |
| 6 | `common/listener/listener.go` `New` (called from the v2ray websocket/http/httpupgrade/grpclite/usbip server constructors, and `masque`) | listening socket | n/a | the component | `Listener.Close` via the component's `scope.Add` in `Start` | **FALSE POSITIVE** — `listener.New` only records options; `Start` binds |
| 7 | `service/oomkiller` `NewService`, `route/network.go` `NewNetworkManager`, `box.go` `New` | service registration into the context | later constructor steps | the `Box` / `daemon.Instance` | `scope.Add` in `preStart` / `Close` | already correct |
| 8 | `protocol/group/urltest.go` `NewURLTestGroupWithExpected`, `common/networkquality/http3.go`, `internal/memmetrics/sampler.go`, `protocol/tailscale/tailssh`, `route/conn.go`, `service/resolved` | goroutine / timer | n/a | component | component `Close` registered via `scope.Add` in `Start` | already correct — the goroutine is started by `Start`, not by the constructor |

## 2. Why item 4 is NOT-APPLICABLE rather than a defect

`RegisterAutoRedirectOutputMark` is called from the constructor and has no release path, which looks
like exactly the shape upstream `02537831e1` moved out of constructors. It was measured rather than
assumed, and it is not reachable as a leak here:

- `route.NewNetworkManager` is called from `box.go:378` inside `NewBox`, and the manager is
  discarded with the Box. There is no `MemoryNetworkManager`, no gitlink or `replace` that hands one
  across Boxes, and `experimental/libbox`'s handover preserves the platform interface, not the
  network manager. Two Boxes therefore get two managers and each may claim its own mark, so the
  "two Boxes" case in §4.4 cannot collide.
- Within `NewInbound` the call is the **last** statement. There is no later error edge inside the
  constructor that could discard the inbound with the mark still claimed.
- The manager's duplicate-tag loser path (`adapter/inbound/manager.go`) does call
  `common.Close(inbound)` on an object whose mark is not released, but reaching that with the mark
  claimed requires two concurrent `Create` calls for the same tag where the winner is not itself an
  auto-redirect TUN — and any other auto-redirect TUN would have failed the claim first with "only
  one auto-redirect can be configured".

The `Box`-lifetime bound is what decides this, and it is also why moving the claim into `Start` would
buy nothing: the only thing it could release is a mark on a manager that is already being destroyed.
Changing it would require a new method on the `adapter.NetworkManager` interface and therefore every
implementation and test double of it — a wide blast radius for no reachable failure. Recorded rather
than changed.

## 3. The ownership sweep that found item 2

Item 1 was found by reading one file. To find the rest of its class rather than stopping there, every
type with

```go
func (x *T) Start(stage adapter.StartStage, scope *adapter.Scope) error
```

was checked for a `Close() error` method and for a `scope.Add` inside that `Start`. A type that has a
`Close` but never hands it to the Scope is a type whose teardown the product never runs, because
`Scope.Close()` walks `scope.Add` entries only and never calls a component's `Close`.

Result on the baseline: exactly two hits — `protocol/tun/inbound.go` and `protocol/masque/server.go`.
Both are now fixed and both have a regression test. Re-running the sweep on the final tree returns
none.

## 4. Ownership rules this stage pins

1. **Acquire and register in the same breath.** Every `scope.Add` added by this stage sits at the
   acquisition, not at the end of the start sequence, so every later failure edge — and every
   failure of the Box start as a whole — is covered by `Box.Start`'s existing rollback, which closes
   the Scope.
2. **One releaser, proven idempotent.** `releaseRouteSetCallbacks` clears its element slice under the
   lock and releases outside it; `releaseIndex` is guarded by `indexAcquired`; `ServerEndpoint.Close`
   is guarded by a `sync.Once`. The Scope path and the explicit-`Close` path can both reach each of
   them and the second reach is a no-op.
3. **Block new events before tearing down.** `closeAutoRedirect` releases the rule-set callbacks
   *before* it closes the auto-redirect they would be delivered to, because reverse registration
   order alone puts the release last. See `docs/fork/lifecycle-scope-test-matrix.md`.
4. **No lock is held across an external `Close`.** `Scope.Add` runs a late cleanup outside its mutex;
   `releaseRouteSetCallbacks` takes the elements under the inbound's lock and calls
   `UnregisterCallback` outside it (pre-existing, preserved).

## 5. S07 — the completion boundary of `Scope.Close()` (main order §5.3)

Stage A pinned *what* the Scope owns. This section pins *when* the owner is done, because a report
that says "after `Box.Close()` every in-flight `Start` has terminated" is stronger than the code.

**The exact boundary.** `Scope.Close()` waits for the cleanup drain and for nothing else
(`adapter/lifecycle.go`, the `scopeClosing` branch on `closeDone` and the drain itself):

- when it returns, every cleanup that was in the queue has run and `closeErr` is final;
- it does **not** wait for a `component.Start()` that is already running and has not reached `Add()`
  yet. Nothing bounds how long a `Start` may take, so waiting would make `Close` unbounded;
- a cleanup registered after that point runs synchronously inside `Add()`, on the registering
  goroutine — after `Close` returned. That prevents a permanent leak, it does not make the late
  resource part of the teardown `Close` reported;
- an error from such a late cleanup is logged by `Add()` and nowhere else. It is not aggregated into
  the already-returned `closeErr`, and because `closeErr` is final a later `Close` does not pick it
  up either;
- a `Start` that was in flight must report failure, not success — `Scope.Start` re-reads the child
  scope's context after the component returns and returns `E.Cause(ctxErr, ...)`.

Pinned by `adapter/lifecycle_close_boundary_test.go`
(`TestScopeCloseDoesNotWaitForAnInFlightStart`, `TestScopeCloseDoesNotFoldInALateCleanupError`,
`TestScopeCloseJoinsAnAlreadyStartedDrain`, `TestScopeCloseDoesNotWaitForAStartThatNeverRegistered`)
and by the report `S07-scope-close-boundary.md`.

**Registration inventory (219 production `scope.Add` sites).** A cleanup can only deadlock by
re-entering the *same* Scope's `Close()`. A mechanical scan of every production `scope.Add(...)`
argument found exactly five registrations that close a `*Scope` at all:

| Registration | Scope it closes | Direction |
|---|---|---|
| `protocol/openvpn/dns_transport.go:85` | `t.resolverScope` (`adapter.NewScope` at :132) | parent → nested child |
| `protocol/openconnect/dns_transport.go:84` | `t.resolverScope` (`adapter.NewScope` at :209) | parent → nested child |
| `protocol/tailscale/dns_transport.go:99` | `t.resolverScope` (`adapter.NewScope` at :177) | parent → nested child |
| `service/resolved/transport.go:106` | `servers.serverScope` (`adapter.NewScope` at :268) | parent → nested child |
| `dns/transport/local/local.go:94` | `serverSet.serverScope` (`adapter.NewScope` at :103 area) | parent → nested child |

Every one of them closes a scope the component created for itself, from a cleanup registered on the
scope it was *handed*. That is the supported direction the `Scope.Close` comment names, and it is
what every dynamic sub-scope in the tree does. None of the five closes the scope it was registered
on, and no production cleanup calls `Close()` on a variable named `scope` at all (the 35
scope-closing call sites in the tree are all field-qualified: `s.scope` (the Box root, closed by
`Box.close()`, never registered as a cleanup), `p.scope` (a scope the certificate provider creates
in its own `Start`, never registered through `scope.Add`), and the nested `resolverScope` /
`serverScope` / `storeScope` / `serverSet.serverScope` values above). Verdict: **NOT_REACHABLE**.

**Two components that acquire after the drain (S07 §4).**

- `protocol/masque/server.go` — **reachable, fixed.** `StartStateInitialize` registers `s.Close` at
  the device acquisition, but `StartStateStart` binds the listening socket *later*. A drain that runs
  while that start is in flight closes a listener that has not been started yet (a no-op), and the
  bind then opens a port that `Scope.Close()` has already returned over. `common/listener` has no
  Start-after-Close guard (`Listener.Start` binds unconditionally), unlike the two in-tree devices.
  Fix: `ServerEndpoint` publishes `closed` under `startAccess` before releasing, and re-checks it
  after the bind (`acquiredStillOwned`); if the endpoint was closed meanwhile, `Start` releases the
  socket it just bound itself.
- `protocol/tun/inbound.go` — **window identified, handoff added.** `StartStateStart` registers both
  releases at acquisition, but `StartStatePostStart` *activates* them: `tunStack.Start()` and
  `tunIf.Start()`, and the latter is where `NativeTun.Start` programs the platform routing table.
  `NativeTun.Start` has no closed check, so an activation that lands after the drain would add routes
  whose cleanup has already run. A guard that simply held a lock across the activation was rejected:
  it makes the drain wait for an in-flight `Start`, which is exactly the unbounded wait `Close` must
  not have. The fix is a non-blocking handoff (`startupGate`): the Scope's cleanup releases the
  resource directly when no activation is in flight, and otherwise records the decision and leaves
  the release to the activation, which performs it as soon as the platform call returns. Exactly one
  release reaches the platform layer (`sync.Once`), and neither side waits for the other.
