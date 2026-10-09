# JiejieBox v0.1.6 kernel final additional hardening — report

**Round:** the additional work package after the two earlier orders. **Baseline:** `integrate/v016-final`
at `96fd0263c1be4b683bb99d6a14a369974cc13220`. **Work branch:**
`fix/v016-core-final-hardening-20261009`. **Machine-readable twin:**
[`v016-core-final-hardening.json`](v016-core-final-hardening.json).

**Verdict: `NOT-READY`.** One release blocker is `NOT_RUN` or `ENVIRONMENT_BLOCKED` for reasons outside
this machine's control — a GitHub Actions dispatch is refused by the repository, which is a repository
setting — and one is `BLOCKED_DEPENDENCY` on a reference binary this environment cannot obtain. Sources
are fixed and locally verified; the marker in
[`v016-final-release-verdict.md`](v016-final-release-verdict.md) stays `NOT-READY`.

Two P0 findings were confirmed by deterministic reproduction on the baseline and fixed. One P1 test
debt was closed by replacing a host-sensitive gate with an exact work count. One new fail-closed gate
was added and self-tested. Everything else is reported with its real status rather than a claim.

## 1. What was measured at the start and the end

| Coordinate | Start | End |
| --- | --- | --- |
| `origin/integrate/v016-final` | `96fd0263c1be4b683bb99d6a14a369974cc13220` | `96fd0263c1be4b683bb99d6a14a369974cc13220` (**unmoved**; this round pushed to a work branch and did not integrate) |
| `origin/testing` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` (**unmoved**) |
| work branch | — | `fix/v016-core-final-hardening-20261009` at `d8f4b87933d5d40fc682effe162dc1f977ada0eb` |
| commits added | — | 6 |
| original work tree | not touched (never opened) | not touched |

Every command in this round ran in an **isolated clone** at
`%TEMP%\jiejie-core-hardening-20261009\core`, created for this round, with its own `GOCACHE`. The
user's original work tree was never the working directory of any command: the shell preamble asserted
`git rev-parse --show-toplevel` equals the clone root before any `git add`, `git commit` or
`git checkout`, and refused to operate when the current branch was `testing`. The one comparison run
against the baseline used a **second** clone (`%TEMP%\jiejie-baseline-compare\core`).

Toolchain: `go1.25.5 windows/amd64` (matching the `go 1.25.5` directive in `go.mod`), tags
`release/DEFAULT_BUILD_TAGS`, `GOTOOLCHAIN=local`. There was no Go, no `git` and no `gh` on `PATH` at
the start of the round; a portable Go toolchain, the bundled Git, and MinGW-w64 GCC 16.2.0 (needed for
`-race`, which requires cgo on Windows) were provisioned into `%TEMP%`, outside the repository.

## 2. P0 findings: confirmed by reproduction, then fixed

### P0-01 — `protocol/masque`: the HTTP/3 acquisition escaped the close decision

`id` **P0-01** · `classification` **CONFIRMED_BUG** · `status` **FIXED_AND_VERIFIED**

**`production_path`.** `protocol/masque/server.go`: `ServerEndpoint.Start` (`StartStateStart`) →
`acquiredStillOwned` → `http.Server.ListenHTTP3` → `transport/http.ConfigureHTTP3ListenerFunc`
(`transport/http/server_h3.go:27`) → `listener.ListenUDP` + `qtls.ListenEarly` → the returned QUIC
listener. Owner of the resource: the `closeOnce` body of `ServerEndpoint.Close` (`server.go`), which is
the only reader of `s.http3Server`. The other reachable close path is `adapter/endpoint/manager.go`
(duplicate-tag loser) and the third is `adapter.Scope.Close`, which runs the cleanup `Start` registered
through `scope.Add(s.Close)`.

The acquisition happened **after** the ownership re-check:

```go
err = s.listener.Start()
if err = s.acquiredStillOwned(); err != nil { return E.Errors(err, s.listener.Close()) }
if s.http3 {
    s.http3Server, err = s.httpServer.ListenHTTP3(...)   // after the check
}
s.started.Store(true)
```

`adapter.Scope.Close` does not wait for a `Start` that is already running, so when `ListenHTTP3`
executed, the Scope's cleanup queue had been drained and `closeOnce` was spent. The QUIC listener was
therefore published into a field whose single reader had already run: the UDP socket outlived the
endpoint, the Scope and `Box.Close()`. The same ordering left `started` **true** on a closed endpoint,
which is a second, independently observable defect: `WritePackets`, `DialContext` and
`ListenPacketWithDestination` gate on it, so a released endpoint answered them as if it were ready.

**`old_red` (real failure, exact command).**

```sh
go test -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=1 -timeout 300s \
  -run TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing -v ./protocol/masque/
```

On the baseline source: `--- FAIL: TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing`, with

```
close_boundary_h3_test.go:175: Should be false
    Messages: a closed endpoint must never advertise itself as started
```

The test fixture is the **production** path: `NewServerEndpoint` with HTTP/3, TLS and a real listener
on an ephemeral port, so the device, the listener, the MASQUE server, the HTTP server and the TLS
config are production objects. The acquisition is held open by wrapping
`transport/http.ConfigureHTTP3ListenerFunc` — a test-local gate around the **real** factory, which
binds a real UDP socket and returns the real QUIC listener. Nothing models the H3 lifecycle.

**`fix`.** The acquisition is now a two-phase commit under `startAccess`:

- `Start` acquires the listener into a **local** (`var http3Server io.Closer`), never into the field.
- `publishAcquiredHTTP3` takes `startAccess`, checks `closed`, and either publishes or refuses. The
  decision and the publication are one mutation.
- On refusal the caller closes the listener it just acquired and returns **without** publishing it and
  **without** storing `started`, so a rolled-back `Start` leaves no trace and a closed endpoint never
  advertises itself as ready.
- The lock is **not** held across `ListenHTTP3`, which binds a socket and starts the QUIC accept loop;
  it is held only for the comparison and the assignment. There are exactly two interleavings and
  neither loses the resource: Close first → nothing is published and Start releases its own
  acquisition; publication first → Close's release list is built after it and contains it.
- No MASQUE HTTP/1, HTTP/2 or HTTP/3 routing or traffic semantics changed, and the HTTP/3-free path is
  unchanged (the branch is not taken).

**`new_green`.**

```sh
go test -race -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=100 -timeout 900s \
  -run 'TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing|TestServerEndpointH3WindowOnRepeatedInterleavings|TestServerEndpointReleasesAListenerBoundAfterClose|TestServerEndpointStartAfterCloseDoesNotBind|TestScopeOwnsServerEndpointTeardown|TestServerEndpointCloseIsExactlyOnce' \
  ./protocol/masque/
```

→ `ok github.com/sagernet/sing-box/protocol/masque 10.095s`, exit `0`. The interleaving test also runs
`-count=1` green with the whole package. The port is proven free by rebinding it, not by inspecting a
pointer; a rolled-back `Start` is proven by `endpoint.http3Server == nil`.

**`reverse_break`.** Removing the commit guard from `publishAcquiredHTTP3` (publishing unconditionally,
as the baseline did) makes the same test fail at the primary assertion:

```
close_boundary_h3_test.go:204: Expected nil, but got: &quic.EarlyListener{...}
    Messages: Start published the HTTP/3 listener it acquired while Close was draining ...
```

and the repeated-interleaving test fails with `iteration left the HTTP/3 listener published`. The
break is applied and reverted with a script that refuses to run unless its anchor matches exactly
once, so a "break" that silently did nothing cannot be reported as evidence.

**`perf`.** No new allocation, no new goroutine, no new ticker, and no lock on the data path: the only
added work is one mutex acquisition per `Start` of an HTTP/3 endpoint and one comparison per
`Close`. The HTTP/3 case is the endpoint's own startup, not a per-connection path.

**`ci`** `NOT_RUN` — see §5.

### P0-02 — `dns`: the reverse mapping could be refilled after its own purge

`id` **P0-02** · `classification` **CONFIRMED_BUG** (two, one of them a reachability question that the
round asked to verify) · `status` **FIXED_AND_VERIFIED**

**`production_path`.** `dns/router.go`: `prepareExchange` captures the generation →
`Router.Exchange` → `recordReverseMappingFrom` → `reverseMappingGenerationCurrent` →
`dnsReverseMapping.AddWithLifetime`. The invalidation sources are `observeDNSEnvironment` (a
resolver/search-domain change: epoch advance + `Purge`) and `ResetNetwork` (a network transition:
`networkGeneration.Add(1)` + `Purge`). The other consumer is `route/route.go` `LookupReverseMapping`
from the connection-matching path.

**(a) The check and the write were two steps.** `recordReverseMappingFrom` asked the generation whether
the captured epoch was current and *then* wrote, with no shared boundary, so a purge that landed in the
gap removed nothing that the write was about to add: an answer to a question asked under the previous
resolver set was recorded as if it belonged to the current one, and route-rule matching read that name
until its TTL expired. This is the same class of defect the earlier round fixed in `ResetNetwork` by
advancing the epoch first — the remaining hole was between the check and the write.

**`old_red`.** On the baseline source, with the round's decision seam added and nothing else changed:

```sh
go test -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=1 -timeout 240s -run 'TestReverseMapping' ./dns/
```

→ 4 of 4 relevant tests `FAIL`:
`TestReverseMappingAnswerIsNotRecordedAcrossAnEnvironmentChange`,
`TestReverseMappingAnswerIsNotRecordedAcrossANetworkTransition`,
`TestReverseMappingLookupObservesTheEnvironmentWithoutANewQuery`,
`TestReverseMappingBatchIsAllOrNothing`.

**(b) The second, reachability question — answered YES.** `LookupReverseMapping` was a bare cache
`Get`. Every other DNS cache is namespaced by the live environment hash, but this one is guarded only
by the generation, and the generation moves only when *something* observes the environment. Observation
happened on the DNS query path, so between a resolver change and the first new query a route rule
matching a connection that needs no DNS request (a literal address, or a name already known) could read
a name learned from the retired resolver set. That is real, not hypothetical: the test asserts it with
**no DNS query issued after the change**, and on the baseline it reads the old name back.

**`fix`.**

- The comparison and the writes are now **one decision under `dnsEnvironmentAccess`**, the lock the
  invalidation protocol is performed under. The epoch is re-read inside that lock through
  `dnsGenerationLocked`. The answers are extracted before the lock; nothing inside it calls out, waits,
  takes another lock, or performs I/O.
- There is deliberately **no** second, lock-free read of the counter: a lock-free read has no
  synchronising edge with the purges it must be ordered against, so it would be a race rather than a
  guard. (The round's own first attempt at this deadlocked — `dnsEnvironmentAccess` is not reentrant,
  and the capture side takes it — which the first test run caught immediately; the locked variant
  exists so the commit path has exactly one acquisition.)
- `LookupReverseMapping` now observes the environment before it reads. The cost is the same observation
  `dnsGeneration` already performs several times per exchange, moved onto the connection path.
- A response's answers are accepted or refused **as a batch**, so a multi-address answer cannot land
  half in the old epoch.
- The **DNS environment epoch stays independent of the network epoch**: a DNS-only change does not call
  `transport.Reset`, does not advance `networkGeneration`, and does not touch NetworkManager's reset
  epoch. The test asserts all three (transports not reset, network epoch unmoved, generation advanced).
- Fake-IP answers are excluded at extraction, so a fake address never enters the cache route policy
  reads as "what this address really is".

**`new_green`.**

```sh
go test -race -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=50 -timeout 900s -run 'TestReverseMapping' ./dns/
go test -race -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=1 -timeout 900s ./dns/... ./route/...
```

→ `ok github.com/sagernet/sing-box/dns 1.346s` (exit `0`) for the `-count=50` race run; `dns`,
`dns/transport`, `dns/transport/fakeip`, `group`, `hosts`, `quic` and `route` all `ok` under `-race`.

**`reverse_break`.** Two breaks, both real:

- Deciding from an epoch snapshot taken **before** the seam (the baseline's shape: read the epoch, then
  let the purge land) fails `TestReverseMappingAnswerIsNotRecordedAcrossAnEnvironmentChange`,
  `...AcrossANetworkTransition`, `TestReverseMappingBatchIsAllOrNothing` and
  `TestReverseMappingRecordingIsRefusedOnceTheInvalidationHasCompleted`.
- Removing the observation from `LookupReverseMapping` fails
  `TestReverseMappingLookupObservesTheEnvironmentWithoutANewQuery`.

Two other mutations were tried and **rejected as evidence** rather than reported: replacing the locked
read with `reverseMappingGenerationCurrent` does not fail the tests, and neither does removing only the
lock, because in both the observation inside `reverseMappingGenerationCurrent` still advances the epoch
before the comparison and the answer is still refused. A "break" that does not break is not a reverse
break, and it is not claimed as one.

**`perf`.** The commit path takes one lock acquisition that the path is a strict reordering of (the
observation the same path already performed), and the extraction of A/AAAA records happens before the
lock, so the critical section is a comparison plus at most one cache write per record. A
before/after `-bench` comparison is **not** reported here: the benchmark harness for this exact path
was not built in this round, and an unmeasured claim would be worse than a gap. What is reported is the
shape: no new allocation per answer, no per-query lock beyond the one already taken, and
`LookupReverseMapping` now performs one observation per connection that previously performed none —
the cost of correctness on a path that was reading a retired epoch.

## 3. P1 findings

### P1-01 — `transport/masque` complexity gate: real reproduction, closed with an exact work count

`id` **P1-01** · `classification` **TEST_DEFECT** · `status` **FIXED_AND_VERIFIED**

**`production_path`.** `transport/masque/server.go` `Server.lookup` → `transport/masque/client.go`
`RoutesContain` → `AddressRange.Contains`. A peer can advertise up to `maxRoutesPerCapsule` (= 8192)
ranges and every routed packet walks them, so this is a per-packet cost.

**What was wrong.** Two tests pinned "the scan is linear" with a wall-clock ratio between an
8192-range loop and a one-range loop (`TestTheOwnershipScanIsLinearOverAdvertisedRanges` in
`ownership_policy_test.go`, `TestTheOwnershipScanIsLinearHereToo` in `control_burst_test.go`). The
second's bound was `4 × 8192 = 32768`. **MEASURED:** the ratio came out at 40605x–49281x and reproduced
on the integration branch **and** on a clean baseline. A linear scan legitimately costs ≈8192x over
8192 ranges, and the one-range side is ≈10 µs per lookup, dominated by the fixed per-lookup cost
(`s.addresses` map access, the RWMutex, the server's own-address comparison), so ordinary scheduling
noise moves the ratio by tens of percent. A bound with 4x of headroom over the true expectation was
crossing on the host. Raising it would have kept a host-sensitive gate while reducing what it detects,
which the order forbids.

**`fix`.** The claim is now pinned by counting the ranges the **production loop** visits. `RoutesContain`
was rewritten from `slices.ContainsFunc` into an explicit loop that reports each visited range to an
optional package-level counter which is `nil` in production — one comparison against a variable per
visited range, no atomic, no always-on global counter on a hot path. The exact count is host-independent:

| assertion | what it pins |
| --- | --- |
| `TestOwnershipScanVisitsEveryAdvertisedRangeOnce` | exactly one visit per advertised range on a total miss, at **1, 64, 1024 and 8192** ranges |
| `TestOwnershipScanWorkIsProportionalToAdvertisedRanges` | doubling 1024 → 2048 ranges doubles the count |
| `TestOwnershipScanStopsAtTheMatchingRange` | a match stops the walk (expressed against `Server.lookup`'s backward advertisement order) |
| `TestOwnershipScanIsNotAnsweredFromTheAddressMapWithoutScanning` | an owned address visits zero ranges |
| `TestOwnershipScanVisitsNothingWithoutAdvertisedRanges` | the vacuity guard |

The two old tests keep a **REPORTED, NOT ASSERTED** per-lookup figure so a constant-factor regression is
still visible in the log, and `BenchmarkOwnershipScanCostByRangeCount` reports ns/op and allocs/op.

**`old_red`.** The measured ratios above are the reproduction: `40605x–49281x` against a `32768x` bound
on correct, linear code.

**`new_green`.** `go test -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=20 -timeout 900s -run
'TestTheOwnershipScanIsLinearOverAdvertisedRanges|TestTheOwnershipScanIsLinearHereToo|TestOwnershipScan'
./transport/masque/` → `ok ... 80.623s`, exit `0`. Whole package `-race`: `ok ... 70.811s`.

**`reverse_break`.** A mutation that still counts every range but stops **consulting** them after the
first fails `TestOwnershipScanVisitsEveryAdvertisedRangeOnce`,
`TestOwnershipScanWorkIsProportionalToAdvertisedRanges` (`the 1024-range measurement visited 32 ranges,
want 32768`) and `TestOwnershipScanStopsAtTheMatchingRange`.

**`perf` (measured, same host, `-benchtime 2000x`).**

| ranges | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| 1 | 43.25 | 0 | 0 |
| 64 | 686.5 | 0 | 0 |
| 1024 | 11929 | 0 | 0 |
| 8192 | 89650 | 0 | 0 |

Linear in the range count, ≈11 ns per visited range, zero allocations at every size.

**What the count can and cannot detect — stated rather than hidden.** It detects any change to *how many*
ranges the scan consults (a skipped range, an early return, extra passes). It cannot detect a
constant-factor regression *inside* the per-range comparison, because that work happens once per visit
either way; the benchmark is what covers that. It is also not a complexity-class proof for a
hypothetical future index structure — it is an exact statement about the loop that exists.

### P1-02 — `common/dialer` wall-clock bounds: inventoried, one first-party flake chased, not reproduced

`id` **P1-02** · `classification` **TEST_DEFECT** (documented, largely unaddressed) · `status` **OPEN**

The order states the previous round counted **16** host-sensitive upper bounds in `common/dialer`. This
round performed a full re-inventory of all 23 `*_test.go` files in the package and found **51**
time-bounded assertions, which decompose as:

- **34 direct wall-clock upper bounds**, of which 16 use a *product* timing constant
  (`preferredFamilyGrace` 50 ms, `fallbackDelay`/`testFallbackDelay`/`N.DefaultFallbackDelay` 300 ms),
  14 use an arbitrary hardcoded literal, and 4 sit at or below typical host timer granularity;
- **17 bounded liveness watchdogs**, which are legitimate and must stay.

The narrower 16-item reading matches the previous round's count exactly, which is consistent with — but
does not prove — that round having scoped to product-constant bounds only. The full per-item table was
built during this round as working material and is deliberately **not** committed to this repository:
it is a 51-row analysis with file:line coordinates, and its machine-readable summary is carried in the
JSON twin instead, so the repository does not accumulate a second, competing inventory document.

**What was actually done.** `go test -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=3 -timeout 900s
./common/dialer/...` → `ok ... 39.217s`, exit `0`; `-race -count=1` → `ok ... 13.889s`, exit `0`. **The
package did not reproduce a single flake in this environment, so no bound was changed.** Changing 34
assertions on a hypothesis, with no reproduction, would trade a documented risk for an undocumented
regression — the order's own rule is that a resolution must not reintroduce user-visible latency, and
that cannot be judged without a failing case.

**The four most objectively dangerous bounds**, reported for the next round rather than changed blind:

| file:line | test | bound | why it is the weakest |
| --- | --- | --- | --- |
| `dual_stack_production_test.go:465` | `TestProductionDialerRemembersFamilyFailure` | `< 40 ms` | below typical Windows timer granularity (≈15.6 ms), for a DNS→stream→scheduler→dial path |
| `dual_stack_producer_test.go:216` | `TestLateFamilyAnswerDoesNotStrandTheProducer` | `< 150 ms` | the window is **shorter** than the 200 ms slow-family delay it is contrasted against |
| `dual_stack_production_test.go:363` | `TestDomainPathHealthyPreferredIsNotDelayed` | `< 100 ms` | 3x the product grace (50 ms); load alone can cross it |
| `dual_stack_production_test.go:394` | `TestDomainPathSingleFamilyIsNotPenalised` | `< 100 ms` | same margin, and the property is an ordering property |

Two of the 14 arbitrary literals are strictly **redundant**: `dual_stack_literal_test.go:208` and
`:295` already prove the same mechanism on the next lines with a channel barrier and a call counter, so
the time bound adds nothing but a failure mode.

**Why this is `OPEN` and not closed by tuning.** The order requires an item-by-item table with old red,
new green and a reverse break per item. That table exists; the red does not, on this host. Manufacturing
one by injecting load would produce a reproduction of the *host*, not of a defect.

### P1-03 — uTLS fingerprint × Xray/REALITY/VLESS/XHTTP/Vision reference matrix

`id` **P1-03** · `classification` **BLOCKED_DEPENDENCY** / **NOT_RUN** · `status` **BLOCKED**

**`production_path`.** The kernel's uTLS profile selection and ClientHello construction
(`common/tls`), the REALITY server conversion, and the XHTTP transport. The pinned fork is
`Piggy-Cat-bit-shadow/utls@6c3e08ed4`.

**Why it is not run.** The matrix requires **real** reference Xray binaries at `v26.3.27` and
`v26.9.30`, downloaded and SHA-verified, driving real handshakes with a real payload round trip. This
environment does not have them and the round's own rules forbid substituting a fake reference
("禁止用……'Xray 参考 binary 不可用则 SKIP 后整套 PASS' 替代真实互操作"). The known open items from the
earlier round — `edge`, `ios` and `qq` having no equivalent upstream preset fix, and `random` having a
chance of drawing an incompatible preset — are therefore **still open**, and this report does not
downgrade them: no fingerprint × reference row is claimed as PASS.

**What was done instead, and its exact weight.** Nothing in this report is offered as a substitute for
the matrix. The honest statement is: `NOT_RUN`, with the axis definition and the required artefacts
recorded so the next round can execute it:
`.github/workflows/interop-xray.yml` (`workflow_dispatch`), `test/interop/`, and
`release/DEFAULT_BUILD_TAGS_OTHERS` are the intended harness.

**Root cause of the likely next finding, recorded as a hypothesis and not as a conclusion.** If
`edge`/`ios`/`qq` fail, the suspect is the uTLS fork's preset data, which this round may not modify.
A kernel-side fix is only admissible if it is a real fix; silently substituting Chrome for `edge` and
reporting PASS for `edge` is forbidden and was not done.

### P1-04 — TUN `Close`/OutputMark/RuleSet: adjacency review

`id` **P1-04** · `classification` **RISK_NOT_REACHABLE** (on the evidence available) · `status` **OPEN**

**`production_path`.** `protocol/tun/inbound.go` `Inbound.Close` (`autoRedirectOutputMarkClaimed`,
`autoRedirectMarkReleaser`, `tunStack`, `tunIf`, `releaseRouteSets`), `adapter.NetworkManager`
`ReleaseAutoRedirectOutputMark`, `adapter.Scope` cleanup, and the duplicate-tag loser in
`adapter/endpoint/manager.go`.

**What this round established.** `Inbound.Close` is not documented as single-call-only, and the
question the order asks — whether two concurrent `Close` calls, or a new owner claiming the **same**
mark, can double-release or clear a new owner's claim — is a question about a reachable call graph, not
about a code smell. The round did **not** complete the composed test the order asks for (two concurrent
`Close`s + a `Manager.Create` duplicate loser + a new same-value mark claim), so the honest status is
**not verified**, not "verified safe".

Two invariants were re-confirmed by reading the current source and were not changed:

- `releaseRouteSets` unregisters the rule-set callback **before** `DecRef`, so an observer cannot be
  invoked against a reference that is already gone.
- `ReleaseAutoRedirectOutputMark` keeps its exclusivity for `mark = 0`.

**Why nothing was changed.** A fix here would add synchronization to a path whose reachability was not
demonstrated, and the order explicitly forbids adding locks to a high-frequency path for a scenario that
may be unreachable. The correct next step is the composed test, which is written down here as the
outstanding item rather than skipped silently.

### P1-05 — release evidence gate: string-filling can no longer pass, and the self-reference is resolved

`id` **P1-05** · `classification` **TEST_DEFECT** (an evidence gate that could be satisfied by prose) ·
`status` **FIXED_AND_VERIFIED**

**The hole.** `scripts/ci/verify-fork-handoff.sh` verifies that the handoff Markdown and JSON agree and
that the recorded coordinates resolve from the remote. It reads **no CI run**. Every release
precondition was therefore satisfiable by writing strings: a candidate SHA, a run id and the word
`success` are text as far as it was concerned. It was, correctly, a *handoff-integrity* gate; it was
being read as a release gate, and the order is right that it is not one.

**What was added.** `scripts/ci/verify-release-acceptance.sh` — a strict, **fail-closed** acceptance
gate. It accepts a release claim only when a run exists that is:

- at the **frozen candidate SHA**, compared as a full 40-hex string (an abbreviation is refused);
- `completed`, with `conclusion == success`, and the run's own workflow **name** matching the required
  workflow (a similar-looking name is not the workflow);
- carrying every required job as completed and successful — a skipped, cancelled, timed-out or neutral
  required job is a failure — with the jobs snapshot proven to belong to *this* run;
- carrying every declared artifact, with the **digest** that was recorded for it, or refused.

Everything it cannot read is a **failure**, never a pass: a missing snapshot directory, a missing run
list, a missing jobs list, a missing artifact list, or an absent token and curl when `--fetch` was asked
for. It reads API snapshots rather than the network, so it is deterministic and can be tested against
deliberately broken evidence; `--fetch` fills them through the REST API.

**`new_green`.** `scripts/ci/verify-release-acceptance-test.sh` — **18 cases, all green**:

```
ok    complete-evidence            exit 0 (expected 0)
ok    wrong-sha                    exit 1 (expected 1)
ok    queued-run                   exit 1 (expected 1)
ok    failed-run                   exit 1 (expected 1)
ok    cancelled-run                exit 1 (expected 1)
ok    similar-workflow-name        exit 1 (expected 1)
ok    skipped-required-job         exit 1 (expected 1)
ok    missing-required-job         exit 1 (expected 1)
ok    wrong-artifact-digest        exit 1 (expected 1)
ok    artifact-without-digest      exit 1 (expected 1)
ok    required-artifact-absent     exit 1 (expected 1)
ok    jobs-snapshot-absent         exit 1 (expected 1)
ok    runs-snapshot-absent         exit 1 (expected 1)
ok    snapshot-directory-absent    exit 1 (expected 1)
ok    skipped-job-declared-optional exit 0 (expected 0)
ok    all-jobs-optional            exit 0 (expected 0)
ok    declared-artifact-outranks-allow-no-artifacts exit 1 (expected 1)
ok    optional-job-does-not-excuse-others exit 1 (expected 1)
PASS  verify-release-acceptance self-test: 18 case(s) behaved as required
```

The self-test found three real defects in the gate while it was being written (a stream-mixing bug that
dropped findings, a workflow-name list that split on spaces, and a file that shipped with a UTF-8 BOM),
which is the point of having one. The step now runs on every push from `verify.yml`, next to the
existing release-gate self-test.

**The self-reference problem, resolved by naming the coordinates rather than faking one SHA.** Writing a
run id into the repository necessarily produces a **new** commit, so "all evidence shares the HEAD SHA"
and "the run id is recorded in the tree" cannot both hold. The manifest and verdict now state the four
coordinates and their admissible uses:

| coordinate | what it is | may it be the released commit? |
| --- | --- | --- |
| **candidate code SHA** | the frozen object CI actually ran | **yes** — the only one, if the rule is "the released commit must have been tested" |
| **evidence commit SHA** | the later docs-only commit recording the run id | **no** — never presented as tested |
| **integration branch tip** | where the work lives before a freeze | no |
| **`testing` release tip** | what a release is cut from | it is the release ref; unmoved by this round |

The freeze is therefore two ordered steps: freeze and push the candidate (no run id in the tree), then
record the run id in a second, docs-only commit that states the tested object is the candidate from step
one.

**`verify-fork-handoff.sh` corrections.** It gained an explicit, read-only `--candidate-branch REF`. The
default `BRANCH=testing` made a candidate still on an integration branch unresolvable, and the only
alternative would have been to push `testing` to make a validator green. The flag relaxes nothing and
the script now prints, in its own output, that a pass with it is a candidate verification and **not** a
release acceptance. Verified: default exits `0`; `--candidate-branch integrate/v016-final` exits `0` and
resolves `integration_final_sha` against the remote tip.

**Stale prose corrected, as corrections and not rewrites.** `v016-final-release-verdict.md` carried two
statements that were true when written and are false now: the Apple row ("blocked on the client source
tree") and the S01 row ("`IncRef`/`DecRef` **open**"). Both are corrected in a dated **Corrections**
section that says the earlier report was corrected; **no client repository was read, built, checked out
or modified for it**, and client acceptance is explicitly out of this round's scope. Neither correction
moves the verdict.

**`ci`.** The gate's self-test is wired into `verify.yml`, but the workflow cannot be dispatched — see
§5, `ENVIRONMENT_BLOCKED`.

### P1-06 — same-SHA kernel CI

`id` **P1-06** · `classification` **ENVIRONMENT_BLOCKED** · `status` **BLOCKED**

**What was attempted.** Dispatching the kernel's own workflows at the exact round-5 SHA
`d8f4b87933d5d40fc682effe162dc1f977ada0eb` on
`fix/v016-core-final-hardening-20261009`:

```sh
curl -X POST -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/Piggy-Cat-bit-shadow/sing-box/actions/workflows/verify.yml/dispatches \
  -d '{"ref":"fix/v016-core-final-hardening-20261009"}'
```

**The real answer, quoted rather than paraphrased:**

```
HTTP 422
{"message":"Actions has been disabled for this repository.",
 "documentation_url":"https://docs.github.com/rest/actions/workflows#create-a-workflow-dispatch-event"}
```

It is the same for `{"ref":"testing"}`, so it is not a ref problem: the repository refuses workflow
dispatches. The workflow files are `active` and 910 runs exist on the repository, so what is refused is
**starting** one, not running a workflow. **This is a repository setting that the kernel repository's
owner controls, not a missing capability of this round.** Per the order, the result is reported as
`CI_NOT_RUN`; no run id, no URL and no conclusion is invented, and no green run from another commit is
borrowed.

The exact commands to run once dispatch is enabled are in the JSON twin (`ci.next_commands`).

**Consequence for the acceptance gate.** `verify-release-acceptance.sh` cannot be run online from here
for the same reason. Its offline half is fully self-tested (18/18), and its online half is written and
unexercised against a real API. That is stated as `FIXED_NOT_FULLY_VERIFIED`, not as verified.

### P2 — Scoped lifecycle adjacency

`id` **P2-01** · `classification` **NOT_RUN** · `status` **OPEN**

`adapter/Scope.Close` honestly documents that it waits for the cleanup drain and **not** for a `Start`
already running, and that a late cleanup error can only be logged. This round did not add the
per-component ownership-gate review the order asks for (MASQUE, TUN, DNS sub-scopes, URLTest). One
consumer of that gap — `protocol/masque` — **was** fixed and is reported as P0-01; nothing else was
changed, and no component is claimed safe by association.

## 4. Honest account of the local test results, per SHA

All results below are for the **hardened** tree (`d8f4b879` plus the report commit) unless the row says
otherwise. Results are never merged across SHAs.

| command | tags | result |
| --- | --- | --- |
| `go test -race -count=100` (P0-01 focused set) `./protocol/masque/` | DEFAULT | **ok** 10.095s, exit 0 |
| `go test -race -count=50` (P0-02 focused set) `./dns/` | DEFAULT | **ok** 1.346s, exit 0 |
| `go test -race -count=1` `./dns/... ./route/...` | DEFAULT | **ok** (dns 8.841s, route 8.557s, route/rule 1.099s) |
| `go test -race -count=1` `./transport/masque/` | DEFAULT | **ok** 70.811s |
| `go test -race -count=1` `./adapter/...` | DEFAULT | **ok** |
| `go test -race -count=1` `./common/dialer/...` | DEFAULT | **ok** 13.889s |
| `go test -race -count=1` `./protocol/group/...` | DEFAULT | **ok** 7.127s |
| `go test -count=3` `./common/dialer/...` | DEFAULT | **ok** 39.217s |
| `go test -count=20` (converted complexity tests) `./transport/masque/` | DEFAULT | **ok** 80.623s |
| `go test -race -count=1` `./protocol/tun/` | DEFAULT | **FAIL** — 2 tests, **pre-existing on the baseline**, see below |
| `go test -race -count=1` `./protocol/masque/` (whole package) | DEFAULT | **FAIL** — 1 test, **pre-existing on the baseline**, see below |
| `go test -race -count=100` `./protocol/masque/` (whole package) | DEFAULT | **timed out at 1800s** — the package has many `t.Parallel()` tests and does not fit 100 repetitions in the budget; this is a budget statement, not a quality statement |

**Two failures were proven pre-existing by running them on an unmodified baseline clone at
`96fd0263c1be4b683bb99d6a14a369974cc13220`:**

- `protocol/masque` `TestRacerDoesNotTreatUDPConnectAsSuccess` — fails identically on the baseline
  (`bootstrap_race_test.go:191`, `"context deadline exceeded" should not contain "context deadline
  exceeded"`). Pre-existing, **not** caused by this round.
- `protocol/tun` `TestGoStackTCPRefusedBecomesAResetForTheDevice` and
  `TestGoStackTCPResetFromARealPeerReachesTheRelay` — both fail identically on the baseline. They assert
  on **host kernel** loopback behaviour (a refused connect must be reported as a refusal; `SO_LINGER 0`
  must produce a kernel RST) and this Windows host reports `wsarecv: An existing connection was forcibly
  closed by the remote host` instead. `ENVIRONMENT`, pre-existing.

**One failure was a local artefact, diagnosed rather than reported as a regression.**
`route` `TestTrafficClassResolvedBeforeChainIsPublished` failed on the hardened tree and passed on the
baseline. It is a **source-text** test: it counts literal occurrences in `route/route.go`. The
difference was the file's **line endings** in the working tree (CRLF versus LF), which changes whether
the multi-line pattern matches — not the code. `git diff HEAD --numstat -- route/route.go` is empty, and
the whole `route` package is `ok` under `-race` once the file is byte-identical to the committed blob.
This is a genuine fragility of that test (it is sensitive to how the file was checked out), and it is
recorded here as an observation for the next round rather than fixed in this one.

**Working-tree note.** `git status` in the isolated clone reports 103 entries, all with
`git diff HEAD --numstat` of **zero**: they are mode and line-ending differences produced by this
clone's Git configuration (`autocrlf=true` from the bundled portable Git, and a filesystem that cannot
store a POSIX execute bit), not content changes. `git diff --cached` is empty. Committed blob content
for every file this round touched is LF-only and correct.

**`go vet`** was run on every package this round modified: `./protocol/masque/`, `./dns/`,
`./transport/masque/` — all exit `0`.

## 5. Workflows: what actually ran

| workflow | invoked? | run id | head SHA | conclusion |
| --- | --- | --- | --- | --- |
| `verify.yml` (`Verify`) | **attempted, refused** | — | — | `NOT_RUN` — HTTP 422 "Actions has been disabled for this repository" |
| `interop-xray.yml` (`Reference interop (Xray)`) | **not attempted** | — | — | `NOT_RUN` — dispatch is refused repository-wide, and the reference binaries are also unavailable (P1-03) |
| `server-linux-amd64.yml` (`Linux amd64`) | **attempted, refused** | — | — | `NOT_RUN` — same refusal |
| `windows-core-amd64.yml`, `android-core-arm64.yml` | not attempted | — | — | `NOT_RUN` |
| `release.yml`, `client-*.yml` | deliberately not attempted | — | — | release paths are out of scope; the order forbids triggering anything that signs, tags or publishes |

**No workflow ran in this round.** Nothing in this report quotes a run id, a URL or a conclusion,
because none exists.

## 6. The fifteen closing questions

1. **Start SHA, end SHA, and are the earlier 30 commits still reachable?** Start
   `96fd0263c1be4b683bb99d6a14a369974cc13220`; end `d8f4b87933d5d40fc682effe162dc1f977ada0eb` on the work
   branch. `git merge-base --is-ancestor 96fd0263 HEAD` → **yes**, and
   `git rev-list --count ef83b868..96fd0263` → **30**. All 30 are reachable and unchanged.
2. **Is the original work tree and `origin/testing` unchanged?** The original work tree was never
   opened, never the working directory of a command, and never `checkout`/`stash`/`reset`. `origin/testing`
   is `ef83b86819c97cbe58b0397dc74af6aca5f1859d` at the start and at the end. `origin/integrate/v016-final`
   is `96fd0263…` at both ends: this round did not integrate (see §7).
3. **Can an interleaving around `ListenHTTP3`/`started.Store` leave an H3 resource or a wrong
   `started`?** It could, and one did on the baseline: after `Close` returned, `started` was **true** and
   the QUIC listener was published into a field whose only reader had run. The proof is
   `TestServerEndpointReleasesAnH3ListenerAcquiredWhileClosing` and
   `TestServerEndpointH3WindowOnRepeatedInterleavings`; the fix is the two-phase commit, and the
   reverse break re-reds both.
4. **Are the DNS generation check and the Add/Purge one atomic protocol, on both paths?** Yes, on both.
   `TestReverseMappingAnswerIsNotRecordedAcrossAnEnvironmentChange` (DNS-only) and
   `TestReverseMappingAnswerIsNotRecordedAcrossANetworkTransition` (`ResetNetwork`) both force the
   invalidating ordering with a real environment change and a real purge, and both fail on the baseline.
5. **Does `LookupReverseMapping` read an old name after a DNS-only change and before the next query?**
   It did — that is P0-02(b), reproduced with **no** query after the change. It now observes the
   environment first, and a reverse break that removes that observation re-reds the test.
6. **Why will the `transport/masque` complexity test no longer false-red on host load, and can it catch
   a quadratic mutation?** Because the gate is no longer a clock: it counts the ranges the production
   loop visits, exactly, at 1/64/1024/8192. Host load cannot move a count. It catches any mutation that
   changes how many ranges are consulted (demonstrated); it does **not** catch a constant-factor
   regression inside one comparison, which is why the benchmark reports ns/op and allocs/op.
7. **What is the disposition of the 16 dialer G2 items, and are any fixed wall-clock bounds objectively
   dangerous?** The re-inventory found 34 upper bounds plus 17 watchdogs (51 total); the narrower 16-item
   reading matches the earlier count but was not confirmed as its scope. Nothing was changed, because the
   package did not reproduce a single flake here (`-count=3`, and `-race`). Four bounds are objectively
   weak and are tabulated in §3/P1-02: `<40 ms` (below Windows timer granularity), `<150 ms` against a
   200 ms fixture delay, and two `<100 ms` bounds at 2–3x the product grace. Status `OPEN`, honestly.
8. **The uTLS fingerprint × two Xray references matrix?** **Not run.** No row is claimed. `edge`, `ios`,
   `qq` and `random` remain open exactly as the earlier round left them; the suspected root cause is the
   pinned uTLS fork's preset data, which this round may not modify, and which was not modified.
9. **Is TUN OutputMark's duplicate-Close / new-owner-same-mark / ABA risk production-reachable?**
   **Not established.** The composed test the order specifies was not completed, so the honest answer is
   "unknown", not "safe". The two invariants that were re-read (`callback-before-DecRef`;
   `ReleaseAutoRedirectOutputMark` exclusivity at `mark=0`) are unchanged. No lock was added on a
   high-frequency path for an unreachable-on-evidence scenario.
10. **Can the handoff script's `RELEASE-READY` still be fooled by string fields?** That script can still
    be satisfied on its own terms — it checks documents, not runs, and that is now stated in the script,
    in the verdict and in the manifest. The release claim, however, can no longer be made from it: the
    strict gate refuses 15 deliberately broken evidence sets and one complete one is accepted, with
    fail-closed behaviour when evidence cannot be read.
11. **How does the single-SHA acceptance avoid the "writing the run id creates a new SHA"
    self-reference, and is the released SHA the tested SHA?** By naming four distinct coordinates and
    forbidding them from being presented as one: the tested object is the **candidate code SHA**, the run
    id lives in a later **evidence commit** that is explicitly never the tested object, and a release ref
    must point at the candidate. Nothing released in this round: `testing` is unmoved, so the question is
    answered as a rule plus a written freeze procedure, not as an accomplished release.
12. **Which workflows really ran, per SHA, with run ids and conclusions?** **None.** Each is listed in §5
    as `NOT_RUN`, with the API's own refusal message as the reason.
13. **The real `go test`/`go vet`/`go build`/tag/race statistics, and every failure?** §4. Counts: 6
    commits; 14 files touched; ~2050 insertions. `go vet` clean on all three modified packages.
    `-race` green on `dns`, `route`, `route/rule`, `transport/masque`, `adapter/...`, `common/dialer`,
    `protocol/group`. Failures: two **pre-existing** (`protocol/masque`
    `TestRacerDoesNotTreatUDPConnectAsSuccess`; `protocol/tun`'s two real-datapath tests), proven
    pre-existing on a separate baseline clone, and one **local artefact** (the `route` source-text test
    and CRLF), diagnosed and shown to be a test fragility rather than a regression. One **budget**
    failure: `-count=100` over the whole `protocol/masque` package exceeded 1800 s. No results from
    different SHAs are combined anywhere in this report.
14. **Can this round's binaries/artefacts be traced to one Core SHA, with SHA256, tags and a repeatable
    command?** No artefact was produced this round. Building one locally would prove nothing about the
    shipped product, and no artefact is claimed. The instruction that "跨 OS / tags 的 Cronet 链接不兼容应
    按仓库真实支持的 release tags 拆分，不能用删功能编译成绿色冒充全功能绿" is respected by not producing a
    reduced-feature build and calling it a green build.
15. **What decides the final verdict, and which blockers are external versus kernel-controllable?** The
    marker stays `NOT-READY`. **Kernel-controllable and done:** both P0 fixes, the complexity gate, the
    acceptance gate with its self-test, the handoff-script corrections and the two stale-prose
    corrections. **Kernel-controllable and not done:** the dialer bounds (no reproduction here), the
    composed TUN mark test, the P2 scoped-lifecycle review. **External:** the GitHub Actions dispatch
    refusal (a repository setting), the Xray reference binaries, and Windows-specific kernel-behaviour
    tests. The two P0 findings are fixed and locally verified; the acceptance chain is not closed,
    because closing it needs a real run at a frozen SHA, which needs dispatch to be enabled.

## 7. Integration status — deliberately not performed

The round's construction order allows a fast-forward or an isolated integration push to
`integrate/v016-final` **only if the remote has not drifted and the gates pass**. The remote has not
drifted (`origin/integrate/v016-final` is still `96fd0263…`), but the gates have **not** passed in the
sense that matters: no CI run exists at any SHA of this round, so the "same-SHA acceptance" precondition
is unmet. Publishing to the integration branch while the acceptance chain is open would be exactly the
substitution of history for evidence that this round exists to prevent. The six commits therefore sit on
`fix/v016-core-final-hardening-20261009`, pushed normally, and **the user decides when to integrate**.

Nothing was tagged, nothing was signed, no Release was created, `testing` was never pushed to, and no
repository other than `Piggy-Cat-bit-shadow/sing-box` was written to — including all of `satelite-one`,
the client repositories, `sing-tun`, `sing`, `utls`, `cronet-go` and `quic-go`, which were not even
cloned. The `clients/*` gitlinks were not moved and no `submodule update --remote` was run.
