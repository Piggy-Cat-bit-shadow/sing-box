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
