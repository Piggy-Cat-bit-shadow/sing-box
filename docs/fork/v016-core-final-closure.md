# v0.1.6 kernel final closure

**Round:** the closure work package. **Baseline:** `integrate/v016-final` at
`96fd0263c1be4b683bb99d6a14a369974cc13220`. **Deliverable:** the integration line advanced to the work
branch's tip, and the ten published theme branches proven integrated and removed.

**Status: `DEV-CONSOLIDATED / RELEASE-NOT-READY`.** Every software-controllable gate this round set out
to close is closed and evidenced below: the two P0 windows, the composed TUN mark test that the previous
round left `OPEN`, the reproducibility question about the dialer bounds, the release acceptance gate's
self-test, and the branch consolidation. `testing` now carries all 42 commits and the remote went from
thirteen branches to two.

The release gates that remain are the two the repository's own state blocks, and the verdict in
[`v016-final-release-verdict.md`](v016-final-release-verdict.md) stays `NOT-READY` for exactly those:
**no CI run exists at any SHA of this round** (GitHub Actions refuses dispatch, see §7) and **no Xray
reference interop evidence exists** (no reference binaries, see §6).

The distinction this round was built on, and it holds: entering `testing` is a DEVELOPMENT
consolidation, not a release. Nothing was tagged, signed, released or deployed.

## 1. The coordinates

| Coordinate | Value |
| --- | --- |
| `SOURCE_SHA` (what was tested and frozen) | `6b6fa34da2b82da5a0ee2387f0fb1cc548901dca` |
| previous round's tip | `41365e123a7e21c9eaaa9f3d4ecceb34fac3fd76` |
| `integrate/v016-final` at round start | `96fd0263c1be4b683bb99d6a14a369974cc13220` |
| `testing` at round start | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` |
| work branch | `fix/v016-core-final-hardening-20261009` |
| commits this round | **5** |
| total ahead of `testing` | **42** |

Ancestry re-verified with git at the start of the round, not recalled:

```
origin/testing (ef83b8681)
  └─ 30 commits → origin/integrate/v016-final (96fd0263c)
                       └─ 7 commits → 41365e123   (the previous round)
                            └─ 5 commits → 6b6fa34d   (this round)
```

`git merge-base --is-ancestor origin/testing origin/integrate/v016-final` → yes.
`git merge-base --is-ancestor origin/integrate/v016-final origin/fix/...` → yes.
`git rev-list --count origin/testing..HEAD` → 42.

### This round's commits

| SHA | Subject |
| --- | --- |
| `a367bbe3` | masque,dns,route,tun: close the readiness window, serialise every DNS invalidation, and fix three platform test defects |
| `37bbc17c` | tun: make the auto-redirect mark claim exactly-once, and close the redirect when the claim is refused |
| `53819acd` | docs(fork): the branch cleanup ledger, with a per-commit integration proof |
| `441e9c75` | dialer: replace the tightest host-sensitive bound with the event gap it was standing for |
| `6b6fa34d` | tailscale: give the DNS-transport reach test the build tag its package requires |

## 2. P0-A — the MASQUE readiness window

**Classification: `CONFIRMED_BUG`, fixed.** `classification_basis`: deterministic test plus a reverse
break that re-reds it.

**`production_path`.** `protocol/masque/server.go` `ServerEndpoint.Start` (`StartStateStart`) →
`publishStarted` / `acquiredStillOwned` → `http.Server.ListenHTTP3` →
`transport/http.ConfigureHTTP3ListenerFunc` (`transport/http/server_h3.go:27`) → `listener.ListenUDP` +
`qtls.ListenEarly` → the QUIC listener. The single reader of `s.http3Server` is the `closeOnce` body in
`ServerEndpoint.Close`; the other close paths are `adapter/endpoint/manager.go` (duplicate-tag loser)
and `adapter.Scope.Close` through `scope.Add(s.Close)`. The data path gates on `s.started`:
`WritePackets`, `DialContext`, `ListenPacketWithDestination`.

**The window.** The previous round moved the *publication* of the listener into the critical section but
left the readiness flag outside it:

```go
if err = s.publishAcquiredHTTP3(http3Server); err != nil { ... }   // takes and RELEASES startAccess
s.started.Store(true)                                             // outside it
```

`Close` publishes `closed` under that lock and stores `started = false` outside it. So this interleaving
was reachable: publish → release the lock → `Close` runs to completion (publishing `closed`, releasing
the listener, the HTTP/3 server, the device and the TLS config) → `started.Store(true)`. The endpoint
was closed *and advertising itself as ready*, so a released endpoint answered the data path as live.

**`fix`.** `publishStarted` is now the endpoint's single readiness decision, reached by both the HTTP/3
branch and the H1/H2 branch: ownership comparison, publication of whatever was acquired, and the
readiness flag are one critical section. A second `Start` on a live endpoint is refused rather than
overwriting a listener whose only release is the spent `closeOnce` body. The lock still does not cover
`ListenHTTP3`.

**`old_red` / `new_green`.** The window is held open by a real seam on `ServerEndpoint`
(`testPublishStartedHook`, nil in production), which fires after the decision is committed and the lock
released - the only place a test can hold this side open, because everything the decision excludes takes
the same lock and would deadlock rather than interleave.

```sh
go test -tags "$(cat release/DEFAULT_BUILD_TAGS)" -count=1 -timeout 300s \
  -run 'TestStartDoesNotAdvertiseReadinessAfterCloseCompleted' -v ./protocol/masque/
```

**`reverse_break`.** Moving the store back outside the critical section re-reds it at
`readiness_boundary_test.go:174`, the assertion on `started` after `Close` returned. Applying and
reverting the break is scripted, and the script refuses to run unless its anchor matches exactly once,
so a break that silently did nothing cannot be reported as evidence.

**`perf`.** One mutex acquisition per HTTP/3 endpoint start, one comparison per `Close`, no new
allocation, goroutine or ticker, and no lock on the data path.

Supporting tests in the same file pin the H1/H2 branch, two concurrent `Close` calls agreeing, and
repeated start/stop. `-race -count=20` on the focused set: `ok`.

## 3. P0-B — the DNS invalidation linearization

**Classification: `CONFIRMED_BUG` for the `ClearCache` half; `RISK_NOT_REACHABLE` for the
`ResetNetwork` ordering half.** `classification_basis`: the first has a deterministic reverse break that
re-reds it; the second does not, and is described accordingly.

**`production_path`.** `dns/router.go`: `prepareExchange` captures the generation → `Router.Exchange` →
`recordReverseMappingFrom` → `commitReverseMappingAnswers` (`dnsEnvironmentAccess`, epoch comparison,
writes). The invalidation sources are `observeDNSEnvironment` (DNS-only change: epoch advance + purge),
`ResetNetwork` (network transition: `networkGeneration` advance + purge), and `ClearCache`. The consumer
is `route/route.go` `LookupReverseMapping` on the connection-matching path.

### P0-B.1 — `ResetNetwork`'s barrier did not include its own purge — `RISK_NOT_REACHABLE`

`ResetNetwork` advanced `networkGeneration` with a lock-free atomic add, then reset the transports, then
re-pinned the environment, and only then purged the reverse mapping. The commit compares the epoch under
`dnsEnvironmentAccess`, so no second acquisition could get between its comparison and its writes - but
the epoch itself was readable in two pieces. It now advances **and** purges under that lock, which makes
the two halves of the barrier one step and mutually exclusive with the commit. The observable order the
reset promises is preserved: epoch first, transports after, re-pin last; the lock covers the two steps
only and never `transport.Reset`, `refreshTransportEnvironments`, or any I/O.

**Honest scope.** The mutation that restores the old ordering does **not** make the new tests red, and it
is not claimed to. What is demonstrated is the mutual exclusion itself
(`TestNetworkResetCannotLeaveARetiredAnswerBehind` asserts that `ResetNetwork` cannot complete while the
commit holds the lock), not a user-visible leak from the old shape. The reordering closes a hole in the
stated invariant and makes the barrier true; it is reported as hardening, not as a confirmed defect.

### P0-B.2 — `ClearCache` purged inside the commit's critical section — `CONFIRMED_BUG`

`ClearCache` is a third invalidation source and the only one that advances **no epoch**, so nothing
ordered its purge against a concurrent commit at all: the purge could land between the commit's
comparison and its writes, and the write that followed left an entry that survived a completed
`ClearCache`. It now purges under `dnsEnvironmentAccess`.

**`reverse_break`.** Removing the lock re-reds `TestClearCacheAlsoSerialisesWithTheCommit`
(`ClearCache completed while the commit held dnsEnvironmentAccess`).

### P0-B.3 — the read side

`LookupReverseMapping` observes and reads in **one** critical section. Two mutations were tried:
removing the observation re-reds `TestReverseMappingLookupObservesTheEnvironmentWithoutANewQuery`;
removing only the lock does **not** re-red anything, because the observation inside
`reverseMappingGenerationCurrent` still advances the epoch before the comparison. Reported as a rejected
mutation rather than claimed as a break.

`-race -count=50` on the focused set: `ok`.

## 4. P1 — the combination test, and the platform defects it found

### P1-04 — the TUN auto-redirect mark, as one composed scenario

**Classification: `CONFIRMED_BUG` for the constructor leak; hardening for the atomicity change.**

`protocol/tun/auto_redirect_mark_combination_test.go` is the scenario the previous round left `OPEN` by
name: **concurrent `Inbound.Close` + `adapter/inbound.Manager.Create`'s duplicate-tag loser + a new owner
claiming the SAME mark value + concurrent reads of the mark.**

It records what the race actually looks like rather than what it was assumed to look like.
`Registry.Create` holds its mutex **across** the constructor call, so constructors are globally
serialised even for different tags - which is why `route.NetworkManager.RegisterAutoRedirectOutputMark`
says the registry lock "happens to serialise them today" and refuses to depend on it. The first version
of this test held one constructor open and hung; that is how the property was found, and it is written
down in the test.

Two product changes:

1. `autoRedirectOutputMarkClaimed` is an `atomic.Bool` consumed with `CompareAndSwap`. `Close` has two
   independent callers (the Scope's drain and the manager's loser), and `if claimed { claimed = false;
   release() }` lets both reach the releaser - the second release being the one that can strip a claim a
   new owner took in between, since the mark value comes from the configuration and a restart reuses it.
2. A refused mark claim now **closes the redirect the constructor already built**. `NewInbound` creates
   the auto-redirect and *then* claims the mark; when the claim is refused it returned an error with
   `autoRedirect` still holding an open redirect - its rules, its network monitor, its goroutines - and
   the caller receives `nil` instead of the `*Inbound`, so nobody could ever close it.

**`reverse_break`, honest.** The atomic change's reverse break does **not** reliably discriminate: the
tests pass with the `CompareAndSwap` and pass with a mutation that puts the plain bool back. The window
between reading the flag and storing it is nanoseconds and there is no seam in production to hold it
open, so the claim made is "the double release is structurally impossible", not "the double release was
observed". `TestMarkReadsAreRaceFreeDuringClose` is what the race detector has to say about it.

`-race -count=5` on the six combination tests: all `ok`, no data race.

### P1 — three platform test defects, each with a measured cause

| Test | Symptom on this host | Cause, measured | Fix |
| --- | --- | --- | --- |
| `protocol/tun` `TestGoStackTCPRefusedBecomesAResetForTheDevice`, `TestGoStackTCPResetFromARealPeerReachesTheRelay` | "the kernel did not refuse / did not reset" for failures that really happened | `syscall.ECONNREFUSED` and `syscall.ECONNRESET` on Windows are **synthetic** (`APPLICATION_ERROR + n` = 536870934/5) and never equal the errno the API returns: **1225** (`ERROR_CONNECTION_REFUSED`, from ConnectEx) and **10054** (`WSAECONNRESET`). Verified against Go's own `Error()` tables | platform-specific error identity in `platform_error_windows_test.go` / `platform_error_other_test.go`; the assertions are unchanged (a real refusal and a real reset, from real loopback sockets) and nothing is skipped |
| `protocol/masque` `TestRacerDoesNotTreatUDPConnectAsSuccess` | failed with `context deadline exceeded` where the test demanded it must not | a **genuine BSD/Winsock divergence**: UDP to a closed port is silently dropped on POSIX (handshake times out) and answered with ICMP port-unreachable on Windows (socket reports `WSAECONNRESET`: "forcibly closed") | the assertion accepts either real hard failure and still rejects the racer's own `no bootstrap candidates` sentinel and any third error; the elapsed-time bound is gone because it asserted the host |
| `route` `TestTrafficClassResolvedBeforeChainIsPublished` | reported "a publish site forgot to resolve the class" for code that resolves it everywhere | it counted a **literal multi-line byte sequence** in `route.go`, so a CRLF checkout made the count 0 instead of 3. MEASURED: it fired while `git diff HEAD --numstat -- route/route.go` was empty | rewritten as a structural check over the parsed syntax tree; `TestTrafficClassOrderingCheckIgnoresLineEndings` asserts LF and CRLF judge identically, and `TestTrafficClassOrderingCheckCatchesReordering` proves it still catches a reordered, a class-less, an unresolved and a trackers-first tree |

### P1 — the dialer bound with a reproducible false red

**Classification: `TEST_DEFECT`, fixed with a reproduction.**

`TestProductionDialerRemembersFamilyFailure` asserted a second connection completes in **under 40 ms**.
MEASURED on this host, same scenario, same build:

| Load | Elapsed | Source of the number |
| --- | --- | --- |
| idle | 16.5 ms, 17.0 ms | the test as written |
| 16 goroutines spinning and touching memory | **735.9 ms**, **844.7 ms** | the round's own load diagnostic |

The load does not change what the scheduler does; it changes how long a goroutine waits to be scheduled.
The 30 idle runs that passed are the same measurement, not a defence.

**`fix`.** The contract is that the healthy family's first attempt does **not** wait out the fallback
delay. `recordingDialer` has recorded a timestamp per attempt since the fixture was written, so a
`firstAttempt(address)` accessor makes that an assertion about the **spacing of two events**, bounded by
the test's **own** `fallbackDelay` (150 ms) instead of a constant - self-scaling, and still catching a
scheduler that failed to start the healthy family early. MEASURED margin when idle: 15.2-26.0 ms against
150 ms, a factor of six to ten.

**The other three flagged bounds were left alone**: `<100 ms`, `<100 ms` and `<150 ms` were each run 30
times and did not false-red. Widening 34 assertions on a hypothesis is what the round explicitly
forbade, and the same reasoning applies to three.

### P1 — a pre-existing defect the untagged gate found

`protocol/tailscale/dns_transport_reach_test.go` asserts on `*DNSTransport`, which only exists in
`dns_transport.go`, a file gated on `with_tailscale`. The test file carried no tag, so the package's
**test binary** did not build untagged:

```
protocol/tailscale/dns_transport_reach_test.go:47:20: undefined: DNSTransport
protocol/tailscale/dns_transport_reach_test.go:62:12: undefined: DNSTransport
```

MEASURED: `go test -run '^$' ./...` failed on exactly this package, and failed the same way at the
baseline `96fd0263`; this round does not touch `protocol/tailscale`. It matters because the Verify
workflow gates the untagged configuration on test binaries **linking**. `go build ./...` was unaffected
because it does not compile test files, which is how it survived: every configuration the product is
actually built with includes `with_tailscale`, so only the untagged gate ever saw it. The tag is the fix,
not a skip - the tests still run where the type exists. Whole-tree `go test -run '^$' ./...` is now clean.

## 5. Local test results, all at `SOURCE_SHA` = `6b6fa34da2b82da5a0ee2387f0fb1cc548901dca`

`go1.25.5 windows/amd64`, `GOTOOLCHAIN=local`, `CGO_ENABLED=1` with MinGW-w64 GCC 16.2.0 for `-race`.
Results are never combined across SHAs.

| Run | Command | Result |
| --- | --- | --- |
| Race, round's packages | `go test -race -count=1 -tags DEFAULT ./protocol/masque/... ./transport/masque/... ./dns/... ./route/... ./protocol/tun/... ./adapter/... ./common/dialer/...` | **PASS** - every package `ok` (masque 319.6s, transport/masque 70.0s, dns 8.8s, dns/transport 7.3s, fakeip 1.4s, group 1.5s, hosts 1.1s, quic 1.2s, route 8.5s, route/rule 1.1s, protocol/tun 4.0s, adapter 1.8s, adapter/outbound 1.1s, common/dialer 13.9s) |
| P0 focused, repeated | `go test -race -count=20` (P0-A set) and `-count=50` (P0-B set) | **PASS** |
| P1-01 gate, repeated | `go test -count=20` (converted complexity tests) | **PASS** |
| P1-04 combination | `go test -race -count=5` (six mark tests) | **PASS** |
| Dialer, repeated | `go test -count=30` (converted bound), `-count=3` (whole package), `-race -count=1` (whole package) | **PASS** |
| Untagged link gate | `go test -run '^$' ./...` | **PASS** after the tailscale fix (failed at baseline) |
| Untagged full suite | `go test -count=1 ./...` | 6 tests fail in 4 packages - **all pre-existing, see below** |
| Tagged full suite | `go test -count=1 -tags DEFAULT ./...` | 9 packages `setup failed` - **the tag set, not the code, see below** |
| Vet | `go vet` on the round's packages, tagged and untagged | **clean** |

### The 6 failures in the untagged full suite are all pre-existing

Each was re-run on a **separate clone of the baseline** at `96fd0263` and reproduced identically, and
this round touches none of the four packages:

| Package | Tests | `classification` | Why |
| --- | --- | --- | --- |
| `common/tlsspoof` | `TestIntegrationSpooferOpenClose`, `TestIntegrationConnInjectsThenForwardsRealCH`, `TestIntegrationSpooferInjectThenWrite` | `PRE_EXISTING_ENVIRONMENT` | `tls_spoof: open WinDivert: windivert: open SCM: Access is denied` - the WinDivert driver needs administrator rights this environment does not have |
| `common/windivert` | `TestIntegrationTamperedCacheRepaired`, `TestIntegrationOpenSendOnly`, `TestIntegrationCloseTwice`, `TestIntegrationRecvAbortsOnClose`, `TestIntegrationConcurrentOpen` | `PRE_EXISTING_ENVIRONMENT` | same driver, same refusal |
| `common/tls` | `TestWindowsClientHandshakeTLS13`, `TestWindowsClientRoundtripTLS13`, `TestWindowsClientTLS13PostHandshakeConcurrentWrite` | `PRE_EXISTING_FAIL` | `tls handshake: read handshake: unexpected EOF`, identical at baseline |
| `common/urltest` | `TestFastFixtureReportsOneNotZero`, `TestLazyHandshakeDelayStaysInTheWarmUp`, `TestDebugCallbackIsPerMeasurement`, and intermittently `TestMeasurementUsesTheSplitTarget`, `TestOrdinaryResponseHeadersSucceed` | `PRE_EXISTING_FLAKY` | the failing SET varies between runs on BOTH trees: `-count=5` on the baseline failed 3 of 5 runs for `TestOrdinaryResponseHeadersSucceed` and 4 of 5 for `TestFastFixtureReportsOneNotZero`, and the hardened tree failed the same tests in a different pattern |

### The 9 `setup failed` packages are a tag-set error, not a code failure

```
FAIL github.com/sagernet/sing-box/include [setup failed]
  imports github.com/sagernet/sing-box/protocol/naive
  imports github.com/sagernet/cronet-go/all: build constraints exclude all Go files in .../cronet-go/all@v0.0.0-...
```

`release/DEFAULT_BUILD_TAGS` contains `with_naive_outbound`, whose implementation links **cronet**, which
exists for Apple platforms only. The repository already carries the Windows-appropriate set in
`release/DEFAULT_BUILD_TAGS_OTHERS`, which omits it, and the untagged run above is the configuration that
actually works here. The round's rule applies and was followed: **a target that genuinely cannot link on
an OS is split by the repository's real release tags, not turned green by deleting a feature.** No
feature was removed to make anything green; the tag-set mistake is reported instead.

## 6. The branch consolidation

### The ledger

[`v016-branch-cleanup-ledger.md`](v016-branch-cleanup-ledger.md) is the per-commit proof, committed
**before** any deletion. **34 unique commits** across the ten theme branches, every one mapped to a
commit in the integration line by one of three kinds of evidence: an ancestor, a
`(cherry picked from commit <sha>)` trailer, or a matching `git patch-id --stable`.

One commit needed manual resolution and is documented rather than waved through: `8139f01d`
(`fix/autoredirect-output-mark`) has no trailer, is not an ancestor, and its patch-id does not match
anything. Its change **is** present, as `cc0bc577` - identical subject, identical file list, identical
per-file counts (5 files, 587 insertions, 27 deletions), and a message describing the same three defects.
The diffs differ only because `fix/tun-ruleset-refs` was integrated in between and rewrote the
surrounding region of `protocol/tun/inbound.go`. Verified by **capability** rather than by diff: all four
markers the commit introduced are present in the target, `route/network.go` is byte-identical at the two
commits, and the three test files it added exist and pass.

The ledger also records a measurement error worth keeping, because it changed a verdict: computing a
single commit's patch-id by piping its diff into `git patch-id` and taking field 1 yields the patch-id of
the **diff**, not the mapping from a target commit to its own id - and that mistake marked an integrated
commit as unmapped.

### The fast-forward and the deletions

Both were executed, and the constraints that governed them were enforced by the scripts rather than by
intention:

**Fast-forward.** Preconditions checked against the LIVE remote immediately before the push: the
remote `testing` had to equal the expected pre-round SHA (`ef83b868…` - it did), the target had to be
the remote work branch (`fdd56c0e…` - it was), the working tree had to be clean, and
`git merge-base --is-ancestor <live testing> <target>` had to pass. It did, and the remote reported
`ef83b868..fdd56c0e` - a fast-forward of **42 commits gained, 0 lost**. No force push, no reset, no
rebase was used anywhere in this round.

**Deletions.** Eleven branches removed, one at a time, each with three gates re-evaluated against the
live remote at that moment:

1. `origin/testing` still at `fdd56c0e` (the fast-forward landed);
2. the branch's live HEAD still equal to the SHA the ledger recorded - **all ten matched, so there was
   no drift and nothing was skipped**;
3. every commit the branch has that `ef83b8681` does not, mapped by ancestor, trailer or patch-id. A
   single unmapped commit would have skipped that branch; none did, including the manual case, which is
   allowed through only by the recorded `8139f01d → cc0bc577` resolution.

Result: `deleted=10 skipped=0 refused=0` for the theme branches, plus `integrate/v016-final`, which was
deleted after `git rev-list --count testing..integrate/v016-final` and its reverse both returned **0** -
exactly contained, not merely superseded.

**Thirteen remote branches became two:**

```
fdd56c0e0edd6ee4026124c4755be06e04e4b62f  refs/heads/testing
fdd56c0e0edd6ee4026124c4755be06e04e4b62f  refs/heads/fix/v016-core-final-hardening-20261009
```

There is now exactly one long-term development line. The `fix/...` branch is kept at the same commit as
the named landing point for this round's candidate; removing it is cosmetic and the user can do it at
any time.

No permission, branch-protection or repository setting was changed to make any deletion succeed, and no
refused deletion was worked around - there were none to work around.

## 7. What could not be done, and why - `CI_NOT_RUN`

The kernel's own workflows could not be dispatched at any SHA. The repository's real answer, quoted:

```
HTTP 422
{"message":"Actions has been disabled for this repository.",
 "documentation_url":"https://docs.github.com/rest/actions/workflows#create-a-workflow-dispatch-event"}
```

The same for `{"ref":"testing"}`, so it is not a ref problem. The workflow files are `active` and 910
runs exist on the repository - what is refused is **starting** one. It is a repository setting the
kernel repository's owner controls, not a missing capability of this round. `gh` is also not installed in
this environment; the REST API was used directly.

**Consequence, stated plainly:** there is **no same-SHA CI evidence** for the consolidation. The
`solo_local` results in §5 are the entire verification, they come from one machine, and they do not
replace a CI run. The acceptance gate `scripts/ci/verify-release-acceptance.sh` self-tests 18/18 offline,
and its `--fetch` half remains **unexercised** - reported as `FIXED_NOT_FULLY_VERIFIED`, not as verified.

## 8. Git safety: what was and was not done

| Constraint | Status |
| --- | --- |
| Only `Piggy-Cat-bit-shadow/sing-box` written | **held** - no other repository was cloned, built, branched, tagged or pushed |
| `clients/*` gitlinks | **untouched**; no `submodule update --remote` |
| No client build or release | **held** |
| No `git reset --hard`, `git clean`, `git stash`, force push, force-with-lease, rebase | **held** |
| No `git add .` / `git add -A` | **held** - every `git add` enumerated files; `git diff --cached --name-status` and `--check` were read before every commit |
| No write command in the user's original work tree | **held** - that tree was never a working directory |
| Isolated clone, `origin` = the fork | **held** - `git rev-parse --show-toplevel` verified before every change group |
| No tag, Release, signature, deployment | **held** |
| `testing` never force-pushed | **held** - fast-forward only |
| Branch-protection changes | **none** |

One environmental property is recorded because it caused real confusion and was resolved rather than
worked around: this host's Git is configured `core.autocrlf=true`, so a fresh clone checks out shell
scripts as CRLF while the committed blobs are LF-only. `git status` in the first clone of this round
showed 1384 modified paths with **zero** content difference. Re-materialising the index byte-exactly
(`core.autocrlf=false` + `git checkout-index -a -f`) produced a clean tree, and every blob this round
committed was verified CRLF-free afterwards.

## 9. The release gates that remain

| Gate | State | Evidence |
| --- | --- | --- |
| Same-SHA real CI run, successful | `CI_NOT_RUN / ENVIRONMENT_BLOCKED` | §7 - the API's own refusal. No run id, URL or conclusion is invented |
| Xray / uTLS reference matrix | `BLOCKED_DEPENDENCY / NOT_RUN` | no reference binaries at `v26.3.27` / `v26.9.30`; **no fingerprint × reference row is claimed as PASS** |
| Shippable artifacts with digests at one SHA | `NOT_RUN` | none were produced; building them locally would prove nothing about the shipped product |
| Single-SHA acceptance pass | `NOT_RUN` | needs the run above |
| Official release | **`NOT-READY`** | the marker is unchanged and may only move after the four rows above are satisfied and the user separately authorises a release |

`scripts/ci/verify-fork-handoff.sh` exits `0` on this tree and
`scripts/ci/verify-release-acceptance-test.sh` exits `0` with 18/18. The verdict marker is still
`<!-- release-verdict: NOT-READY -->`.
