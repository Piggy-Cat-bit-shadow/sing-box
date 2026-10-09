# Lifecycle Stage A — test matrix and evidence

Baseline `912ed1efa` (`origin/testing`), branch `fix/lifecycle-stage1`. Every item below records the
proof that the defect is real, the red test, the minimal change and the reverse-break that shows the
test is load-bearing.

House rules applied throughout: a change without a red-check is not evidence; a test that drives the
wrong object is worse than no test; a wall-clock assertion measures the machine, so every assertion
here is count- or accounting-based, and every interleaving is chosen with a channel or a barrier
rather than a sleep.

## 1. P0-L01 — TUN rule-set callback Scope ownership (`53a3f97e8`, `f2c728d10`)

**Proof the defect is real.** Two independent lines:

```console
$ git log --oneline a691a440..upstream/testing -- protocol/tun/inbound.go   # not empty: upstream differs
$ grep -rn "releaseRouteSetCallbacks" --include=*.go .
./protocol/tun/inbound.go:592:	t.releaseRouteSetCallbacks()      # inside Inbound.Close
./protocol/tun/inbound.go:605:func (t *Inbound) releaseRouteSetCallbacks() {
```

`releaseRouteSetCallbacks` has exactly one production caller, `Inbound.Close()`, and
`adapter/inbound/manager.go` reaches the inbound through `scope.Start(name, inbound, stage)`. The
Scope runs `scope.Add` entries only and never calls a component's `Close()`, and the TUN inbound
never handed it one. Upstream `a691a44023` — the very commit the Fork's `adapter/lifecycle.go` is
verbatim identical to — registers `scope.Add(func() error { routeRuleSet.UnregisterCallback(callback); return nil })`
immediately after each `RegisterCallback`. The Fork replaced that with the stored-slice design and
lost the registration.

**The misleading test.** `protocol/tun/callback_lifecycle_test.go` already asserted that
`Inbound.Close()` releases the callbacks. It passed, and it stayed passing, while the product leaked —
it calls `inbound.Close()` directly, which the product never does. That is the "test that verifies
the wrong object" failure mode, and it is why the new tests drive `Scope.Start` instead.

**Red.** `protocol/tun/scope_ownership_test.go`, on the unmodified tree, with a real `adapter.Scope`,
the real `Inbound.Start` entry point and an injected platform-interface failure placed after the
registration block:

```console
--- FAIL: TestScopeOwnsRouteSetCallbacks
    expected: 2
    actual  : 0
    every callback Start registered must be released by Scope.Close() alone
--- FAIL: TestScopeOwnedCallbacksCannotFireAfterClose
    Should be empty, but was [0x14000091720]
    no observer may survive the Scope that owned it
```

**Minimal change.** `scope.Add(t.releaseRouteSetCallbacksCleanup)` at the acquisition, plus
`closeAutoRedirect` so the release precedes the auto-redirect teardown rather than following it.

**Reverse-break.**

| Mutation | Result |
|---|---|
| remove `scope.Add(t.releaseRouteSetCallbacksCleanup)` | `TestScopeOwnsRouteSetCallbacks`, `TestScopeOwnedCallbacksCannotFireAfterClose` FAIL |
| register the bare `t.autoRedirect.Close` instead of `t.closeAutoRedirect` | `TestStartRegistersReleaseBeforeAutoRedirectTeardown` FAIL |
| invert the order inside `closeAutoRedirect` | `TestStartRegistersReleaseBeforeAutoRedirectTeardown` FAIL; the count-based tests still pass, which is the point — they cannot see an ordering defect |

The third mutation is the one that matters: it is why the ordering test asserts *when* the
auto-redirect was closed relative to the release, instead of counting releases.

## 2. P0-L01b — MASQUE server endpoint teardown (`e3349044a`)

Found by the ownership sweep described in the resource ledger, not by reading one file.

**Proof.** `ServerEndpoint.Start` acquires a device in `StartStateInitialize` and a TLS config, a
listener and the HTTP/3 server in `StartStateStart`; `Close` releases all of them. No `scope.Add`
appears anywhere in its `Start`. The only production caller of `ServerEndpoint.Close()` was the
duplicate-tag loser path in `adapter/endpoint/manager.go`, which by construction never runs for a
started endpoint. `protocol/masque` is registered in the default build (`include/registry.go:121`).

**Red.** `protocol/masque/scope_ownership_test.go` drives the real Scope and both real `Start`
stages, with the production userspace device (`device.New` with `System:false`), a real listening
socket on an ephemeral port, and a real `masque.Server`:

```console
--- FAIL: TestScopeOwnsServerEndpointTeardown
    expected: 1
    actual  : 0
    closing the Scope must run the endpoint's teardown
```

**Reverse-break.**

| Mutation | Result |
|---|---|
| remove `scope.Add(s.Close)` | `TestScopeOwnsServerEndpointTeardown` FAIL |
| remove the `sync.Once` from `Close` | `TestServerEndpointCloseIsExactlyOnce` FAIL |

## 3. P0-L02 — constructor-phase system side effects

**Bridge index: already correct, coverage added (`6019786ae`).** The Fork's
`backendBase.acquireIndex` / `releaseIndex` / `allocateIndex` are at least as strict as upstream
`02537831e1` (idempotent acquire, idempotent release, Scope-owned), and `protocol/bridge/index_leak_test.go`
already proves the constructor claims nothing and that the helpers balance. What no test pinned was
the **wiring**: `index_leak_test.go` drives the helpers directly and its own comment says so. Every
existing test in the package passes with the `scope.Add` inside `allocateIndex` deleted, which would
leak one process-global slot per Box close. Four new tests drive the real `adapter.Scope`; all four
fail when that `scope.Add` is removed:

```console
##### REVERSE-BREAK: remove the scope.Add inside allocateIndex #####
--- FAIL: TestScopeCloseReleasesBridgeIndex
--- FAIL: TestRepeatedStartThroughScopeHoldsOneSlot
--- FAIL: TestScopeCloseCannotDoubleRelease
--- FAIL: TestOneScopeCloseDoesNotReleaseAnothersSlot
```

No production change. This is stated as a coverage gap closed, not as a red test, because the
behaviour was already correct.

**Auto-redirect: measured, judged NOT-APPLICABLE.** See
`docs/fork/lifecycle-scope-resource-ledger.md` §2 for the full reasoning. In short: the
`NewInbound`-time output-mark claim is bounded by the per-Box `NetworkManager`, it is the last
statement in the constructor (no later error edge), and no path hands a `NetworkManager` across
Boxes. Upstream's `tun.NewAutoRedirect` move was also checked against the pinned sing-tun fork: it
assigns fields and adjusts marks, and acquires nothing, so moving it would be motion without effect
here. Upstream's Linux-only restriction was **not** absorbed — §4.5 forbids hardcoding a platform as
unavailable, and the Fork's platform auto-redirect entry must stay.

**Constructor scan.** 24 candidates, all judged; the table and the false positives are in the
resource ledger. No other constructor in the tree acquires a resource it does not also register.

## 4. P0-L03 — Scope.Start × Scope.Close × Scope.Add (`ffdbfa334`)

**Proof the race is reachable, from the tree's own documentation.** `box.go:97-100`:

> closeOnce makes Close idempotent and safe to call concurrently. The daemon serialises its own stop
> against start, but Close is exported and an embedder may call it from any goroutine - **including
> while Start is still running, which the daemon deliberately allows**.

`Scope` is also used for dynamic sub-lifecycles that start and close transports at runtime while the
Box stays open: `dns/transport/local/local_resolved_linux.go` and `local_shared.go` (`serverScope`),
`service/resolved/transport.go`, and the `resolverScope`s of `protocol/openvpn`, `protocol/openconnect`
and `protocol/tailscale`.

**Red.** `adapter/lifecycle_scope_test.go` on the unmodified Scope:

```console
--- FAIL: TestScopeRunsCleanupAddedWhileClosing
--- FAIL: TestScopeStartDoesNotReportSuccessAfterClose
--- FAIL: TestScopeAddRacingCloseRunsEachCleanupExactlyOnce
--- FAIL: TestScopeConcurrentCloseReturnsTheSameResult
--- FAIL: TestScopeConcurrentAddAndCloseStress
```

Three guard tests passed before and after and must keep passing: rollback of a Start that acquired
three resources and then failed, reverse-order idempotent Close, and refusal to restart a closed
Scope.

**Minimal change.** `open`/`closing`/`closed` under the existing mutex, plus a `closeDone` channel.
`Add` on a closing Scope runs the cleanup on the caller's goroutine outside the lock; `Start` reports
the cancellation instead of success; `Close` records the drain result and later callers join it.

**Reverse-break.**

| Mutation | Result |
|---|---|
| `Add` always appends | the four Add/Close tests FAIL |
| second `Close` returns early | `TestScopeConcurrentCloseReturnsTheSameResult` FAIL |
| drop the post-`Start` cancellation check | `TestScopeStartDoesNotReportSuccessAfterClose` FAIL |

**Determinism.** The 10 000-iteration Add/Close race is released from one barrier, never a sleep. The
deterministic version of the same window is `TestScopeRunsCleanupAddedWhileClosing`, which holds the
component's `Start` open, closes the Scope to completion, and only then lets `Add` run — so the losing
interleaving is chosen rather than hoped for.

**Contract stated in the code.** `Close` is not reentrant from a cleanup running on the SAME Scope;
closing a nested Scope from a parent's cleanup is the supported direction. Every nested scope in this
tree closes a *different* scope than the one it was registered on, which was checked rather than
assumed.

## 5. P1-L05 — close-path error semantics, absorbing `69601481f` (`f2ea18240`)

**Proof.** `git log a691a440..upstream/testing -- adapter/lifecycle.go` returns that commit and
nothing else. The Fork aggregated every cleanup error unconditionally.

**Red.** `adapter/lifecycle_error_semantics_test.go`:

```console
--- FAIL: TestScopeCloseDoesNotReportAlreadyClosedResourcesAsFailures
--- FAIL: TestScopeCloseDoesNotReportCancellationAsFailure
--- FAIL: TestScopeCloseKeepsARealFailureInsideAnAggregate
--- FAIL: TestScopeCloseKeepsARealFailureAlongsideCancellation
--- FAIL: TestScopeCloseKeepsTheFilteredErrorsAsEvidence
--- PASS: TestScopeCloseStillReportsRealFailures        # must pass before AND after
```

**Why expanding first is not optional.** `E.IsClosed` is `errors.Is` over a multi-error, so it
returns true for an aggregate that carries one cancelled error *and* one real failure. Judging the
aggregate as a unit would discard the real failure with it. Reverse-break:

```console
##### MUTATION J: filter the AGGREGATE as a unit (no Expand) #####
--- FAIL: TestScopeCloseKeepsARealFailureInsideAnAggregate
```

That mutation fails **only** that test, which is precisely the failure mode the expand exists to
prevent.

| Mutation | Result |
|---|---|
| remove the filter entirely | the five tests FAIL |
| append `cleanup()` without `E.Expand` | only `TestScopeCloseKeepsARealFailureInsideAnAggregate` FAILs |

**Deliberate difference from upstream.** The filtered errors are reported through the Scope logger
before being dropped, and `TestScopeCloseKeepsTheFilteredErrorsAsEvidence` pins it.

## 6. Commands run

```console
$ export GOTOOLCHAIN=go1.25.5; TAGS=$(cat release/DEFAULT_BUILD_TAGS)
$ go test -count=1 -tags "$TAGS" ./...                    # 76 ok / 0 FAIL, exit 0
$ go build -tags "$TAGS" ./...                            # exit 0
$ go build ./...                                          # untagged, exit 0
$ gofmt -l .                                              # empty
$ go mod tidy -diff                                       # empty
$ go test -count=1 -race -tags "$TAGS" ./adapter/... ./protocol/tun/ ./protocol/masque/ ./protocol/bridge/
$ go test -count=20 -race -tags "$TAGS" -run '<all new tests>' ./adapter/ ./protocol/tun/ ./protocol/masque/ ./protocol/bridge/
```

No `build/` directory of gomobile-generated Go exists in the tree; it was checked and is absent, so
`go test ./...` does not walk one and the package count is not inflated.

### Known load-sensitive flake

`common/trafficsched` is the known load-sensitive package: it passes 3/3 in isolation at load 13 and
has been observed to fail inside `go test ./...` at load 56. **It did not reproduce in this stage's
full run** — it passed inside `./...` in 106.8 s. Load observed: 8.56 (1-min average) when the run
started, 16.82 when it finished. That is reported as "the flake did not reproduce at this load", not
as a fix and not as a regression.

**Environment note.** The unit tests here cannot create a real TUN interface (no root, and macOS
utun requires it), which is why the TUN and MASQUE tests inject a failure or a userspace device at
the seam that production also uses. Real TUN/bridge/auto-redirect behaviour on device is
`DEVICE-ONLY` — see the handoff document.

## 7. Box-level close semantics, and one regression this stage caused and fixed (`3afa000d6`)

Absorbing the closed/cancelled filter **broke an existing test**, and that is recorded rather than
quietly edited:

```console
--- FAIL: TestBoxCloseRepeatsTheFirstResult (0.00s)
    box_close_test.go:89:
    Error: Expected error with "context canceled" in chain but got nil.
```

`TestBoxCloseRepeatsTheFirstResult` injected `context.Canceled` as its teardown failure. Its stated
intent is error **repetition** — "the first Close's error is reported to every caller, so a repeated
Close does not look like a clean shutdown when teardown actually failed" — and the value was only ever
"some error". Once `Scope.Close` stopped reporting a cancelled cleanup as a failure, that fixture
asserted the opposite of the contract.

The resolution strengthens the coverage instead of weakening the assertion:

- the repetition test now injects a real teardown failure, so its assertion keeps exactly the strength
  it had;
- a new `TestBoxCloseDistinguishesCancellationFromTeardownFailure` pins the contract at the Box level,
  with two sub-cases: a teardown that only observed cancellation and `net.ErrClosed` returns nil, and
  a real failure travelling alongside them is still returned to every caller with the filtered errors
  absent from the result.

Reverse-break: removing the closed/cancelled filter from `Scope.Close` fails
`TestBoxCloseDistinguishesCancellationFromTeardownFailure` and leaves
`TestBoxCloseRepeatsTheFirstResult` green — the division the two tests are meant to have.

No assertion was weakened, no test was deleted, and no `|| true` was added.
