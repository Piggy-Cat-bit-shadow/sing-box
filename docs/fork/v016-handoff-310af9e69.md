# v0.1.6 handoff — state at `310af9e69`, with the measured facts a fixer needs

Written to be the first thing read in a fresh window. Everything below is either a command that was
run and its raw output, or a file:line you can open. Nothing is inferred.

```text
FINAL_SHA        = 310af9e694f3d60d089e69d1647de2ef90410000
ORIGIN_TESTING   = 310af9e694f3d60d089e69d1647de2ef90410000   LOCAL == ORIGIN
RANGE THIS ROUND = 2ef811766..310af9e69   NEW_COMMITS = 3
ALL_SKIP_CI      = YES            (verified on every commit in the range, not only the tip)
TAG_REFS         = 636            (unchanged; none created)
REMOTE_HEADS     = 1              (only `testing`; no branch, PR or Release)
ORIGINAL_TREE    = C:\src\sing-box at 8d78dcdd, clients/desktop dirty — NEVER written to
GITHUB_ACTIONS   = NOT_RUN / NOT_DISPATCHED (no `gh`, no API access -> REMOTE_ACTIONS_NOT_QUERYABLE)
MY WORKTREE      = C:\Deepseek\内核\work    (detached at the FINAL_SHA, clean)
```

## 0. How to reproduce this environment

```powershell
$env:PATH = "C:\Users\Jie\AppData\Local\Temp\jiejie-tools\mingw\mingw64\bin;C:\src\_toolchain\goroot\bin;C:\src\MinGit\cmd;" + $env:PATH
$env:CGO_ENABLED = "1"                                                     # needed for -race
$TAGS = (Get-Content release/DEFAULT_BUILD_TAGS_OTHERS -Raw).Trim()        # NEVER hard-code tags
```
`go1.26.8 windows/amd64`. MinGW gcc at that path is what makes `-race` work. `gh` is unavailable and
the GitHub API is not reachable, so remote Actions can only ever be reported as `NOT_QUERYABLE`.

Push gate, run before every push:
```powershell
& "C:\Users\Jie\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" "C:\Deepseek\内核\push_preflight.py"
```
It checks: every commit in `origin/testing..HEAD` carries the literal `[skip ci]`, the tip carries it,
the remote is an ancestor of HEAD (fast-forward), no `go.mod`/`go.sum` change. **The GitHub trigger
audit is already done and clean** — the nine workflows declare only `push`, `pull_request` and
`workflow_dispatch`; none declares `workflow_run`, `repository_dispatch`, `schedule`,
`pull_request_target` or `release`, so there is no event `[skip ci]` cannot suppress. Re-verify with:

```powershell
foreach ($f in Get-ChildItem .github/workflows/*.yml) {
  $lines = Get-Content $f.FullName; $onIdx = -1
  for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^on:\s*$') { $onIdx=$i; break } }
  $events=@(); for ($i=$onIdx+1; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\S') {break}
    if ($lines[$i] -match '^  (\w+):') { $events += $Matches[1] } }
  Write-Host ("{0,-32} {1}" -f $f.Name, ($events -join ', '))
}
```

---

# 1. DONE AND VERIFIED — S0, the WireGuard IPC private-key leak

**Severity: highest in the round. This one is fixed, pushed, and reverse-broken at the assertion
level.**

### The defect

`transport/wireguard/endpoint.go`, in `Start`:

```go
err = wgDevice.IpcSet(ipcConf.String())
if err != nil {
    wgDevice.Close()
    return E.Cause(err, "setup wireguard: \n", ipcConf.String())   // <-- the leak
}
```

`ipcConf` is built at line 73 as `"private_key=" + privateKey` and extended with every peer's
`preshared_key=<hex>`. `IpcSet` fails routinely — a malformed `allowed_ip`, a key the kernel rejects, a
port conflict — and each failure put the device identity key and every PSK into an error the caller
logs, wraps, or hands to an SDK.

### The fix as shipped

Read `transport/wireguard/endpoint.go` around the `IpcSet` call. The configuration is **not passed at
all**; the message keeps the subsystem, the peer count, and the wrapped cause (which names the
offending FIELD, not its value). The cause is still wrapped, so `errors.Is`/`errors.As` keep working.

Why not a redaction pass: filtering means deciding at the error site which substrings are secret, and
that decision goes stale the moment a new IPC field or peer option appears.

### Evidence

`transport/wireguard/s0_ipc_secret_test.go` — `TestAFailedIpcSetDoesNotLeakThePrivateKey` and
`TestNoWireGuardErrorCarriesAKeyLikeString` (3 subtests). Fixtures are structurally valid 32-byte keys
whose hex rendering embeds `S0SENTINEL-PRIVATE` / `S0SENTINEL-PSK`, so a leak is an exact substring.

Reverse-break, raw:

```
=== the leak restored, as VALID Go ===
  builds cleanly, so any RED below comes from an assertion
  test exit=1
    --- FAIL: TestAFailedIpcSetDoesNotLeakThePrivateKey (0.00s)
    Error: "setup wireguard: 1 peers, ipc configuration: private_key=533053454e54494e454c2d505249564154450f...
  -> RED BY ASSERTION, as required
=== restored ===
  exit=0 -> GREEN
```

`533053454e54494e454c2d50524956415445` decodes to `S0SENTINEL-PRIVATE` — the leak is shown happening.

**Two earlier reverse-break attempts were discarded** because their RED came from a compile error (a
literal `\n` written into the source; then an orphaned `strconv` import). The driver
`C:\Deepseek\内核\s0_reversebreak3.py` builds first and refuses to report a compile failure as a
falsification. **Keep that discipline** — a RED that is a build error proves nothing about a test.

### Fixture gotcha worth knowing

`Endpoint.Start` requires `Initialize(nil)` to have run, because `Initialize` is what installs
`e.tunDevice`. Calling `Start` without it panics on a nil device at `endpoint.go:254` **before reaching
`IpcSet`**, which would make the test assert about the wrong failure. Both S0 tests call `Initialize`.

---

# 2. NOT DONE — PATH-01, and the wall that six attempts hit

**CLOSED — see §10 for what the wall actually was, the fix, the reverse-break, and the one detector
that cannot be green alongside another one. §2 is kept because its measurements are the record this
section was reasoned from.**

**This is the main open defect. `PHYSICALPATH_UNKNOWN_AND_EXIT = NOT_READY`.**

## 2.1 What is wrong, measured

The two APIs disagree about the SAME topology. Raw output of
`go test -tags "$TAGS" -run TestDiagnosticPathContractAcrossAPIs -v ./common/physicalpath/`:

```
two hop (exit.detour = entry)
  BUILD  entry pos=0 entry=true      BUILD  exit pos=1 exit=true
  HOPS   exit  pos=0 exit=false      HOPS   entry pos=0 exit=false
  LEAVES count=0

three hop (c -> b -> a)
  BUILD  a pos=0, b pos=1, c pos=2 exit=true
  HOPS   c pos=0, b pos=0, a pos=0, every exit=false
  LEAVES count=0

single hop (direct, no dependency)
  BUILD  direct pos=0 entry=true exit=true
  HOPS   direct pos=0 exit=false
  LEAVES count=0
```

Three consequences, and the third is the worst:

1. `Build` and `Hops` give different packet-order indices for the same object.
2. `Hops` reports **every** node at position 0 on a chain.
3. `Leaves()` returns **zero** entries for every topology, including a single-hop outbound.

Because `Exit` is never set, `businessEntry` is false everywhere, so:

```
dryrun.go:363   advertisedNetworks skips every node   -> returns nil
dryrun.go:258   nodeRequirementFor returns nil
dryrun.go:405   validateNode: `if len(requirement) > 0` -> the network check is SKIPPED
```

**A detour chain reached by a rule with no explicit `network:` therefore receives NO network
validation at all.** That is a FALSE PASS in exactly the check the startup dry-run exists to provide.

## 2.2 Root cause, read from the shipped source

```text
common/physicalpath/leaves.go:200   _, err = scope.enumerateHops(root, ...)      <- flag DISCARDED
common/physicalpath/leaves.go:290   if memberEnded { e.reverseRoute(memberStart) } <- the ONLY reversal
common/physicalpath/leaves.go:302   physicalPath = append(append(nil, physicalPath...), node.Tag())
common/physicalpath/leaves.go:361   func (e *enumeration) reverseRoute(start int)
common/physicalpath/physicalpath.go:505   reversePacketOrder(&path)   <- Build DOES reverse
```

A route is reversed only when a **member's** recursion reports it ended one. So the segment consisting
of the root's own node plus everything appended after the last child returned is never reversed. On a
dependency-only chain (no group) `reverseRoute` is never called at all.

## 2.3 THE WALL — read this before writing attempt seven

Six attempts failed. The reason is that **two requirements pull the chain in opposite directions**,
and this is measured, not theorised:

```
supersession ("which node is the business entry") needs NESTED chains
        [c]  [b c]  [a b c]          -> the relation is a SUFFIX
packet order needs DEVICE-FIRST chains
        [c]  [c b]  [c b a]          -> the relation is a PREFIX
```

Attempt six built the chain by **prepending during the descent** and derived `Exit` from supersession.
Measured:

```
HOPS node "c" chain=[c]     pos=0 exit=true
HOPS node "b" chain=[b c]   pos=1 exit=true
HOPS node "a" chain=[a b c] pos=2 exit=true
```

The chain is correctly nested and `Position` genuinely indexes it (`TestEachNodePositionIndexesItsOwnChain`
**passed**). But: the chain is **descent order**, so the index is the distance from the ROOT, not the
device — `Build` puts `a` at 0 and `c` at 2, this puts `c` at 0 and `a` at 2, exactly inverted. And
supersession never fires, because `[b c]` is a **suffix** of `[a b c]`, not a prefix, so every node
reports `exit=true`.

**Therefore the direction for the next attempt: keep the chain DEVICE-FIRST and take `Position` from it
directly. Do not build a rooted-last chain and try to convert it.** Note that the chain the *shipped*
code builds (`leaves.go:302`) is already device-first, which is why `Build`'s `reversePacketOrder`
remaps `Unknown.Position` the way it does.

## 2.4 Every failed attempt, one line each — do not repeat these

| # | attempt | why it was wrong |
|---|---|---|
| 1 | reverse inside every recursing frame | result depends on the route's DEPTH (each level flips its own suffix) |
| 2 | reverse the whole range from the frame that completes the route | re-reverses what a child already corrected; two-hop becomes `[entry, exit]` |
| 3 | `Position == len(PhysicalPath)-1` as the business-entry test | calls a dependency the entry (`middle` in the diamond) |
| 4 | supersession guarded by `Root` | vacuous — `Root` is identical for every node under one root |
| 5 | supersession guarded by `Route()` | also vacuous — `Route()` is unique per node |
| 6 | supersession with **no** guard, on a rooted-last chain | never fires; wrong end (see 2.3) |

Attempts 4 and 5 are worth dwelling on: **both guards looked obviously correct and both were obviously
wrong**, and only running the detector showed it.

## 2.5 The specification — 13 red tests, already committed

These are the target. They are deliberately RED and must not be "fixed" by inverting them.

```
common/physicalpath/p1_contract_test.go        TestLeavesNamesTheRoutingSelectedHopOnATwoHopRoute
                                               TestHopsAndBuildAgreeOnPacketOrderForOneTopology
                                               TestEachNodePositionIndexesItsOwnChain
                                               TestOneBusinessEntryForEachRoute
common/physicalpath/businessentry_attack_test.go        TestBusinessEntryCountsExactlyOneEntryPerRoute
                                                        TestAnUnresolvedGroupMemberIsNotABusinessEntry
common/physicalpath/hops_packet_order_attack_test.go    TestEveryNodeOfEveryRouteIsReachableAtItsOwnPosition
                                                        TestASingleHopRootIsNotAReportedLeaf
                                                        TestTheReportLeavesAOneHopRootOutOfItsOwnLeafList
                                                        TestHopsNumbersTheLastSegmentInPacketOrder
                                                        TestHopsAgreesWithBuildOnTheSameTopology
                                                        TestLeavesReportsASingleHopRoute
common/physicalpath/hops_order_impact_attack_test.go    TestAnEndpointMemberThatIsASingleHopIsAnExit
```

Run them:
```powershell
go test -count=1 -tags "$TAGS" ./common/physicalpath/ 2>&1 | Select-String '^--- FAIL'
```

**The one P1 sub-item already correct**, on evidence rather than on reading:
`TestATruncatedRouteClaimsNoExit` **PASSES** — a route with an unresolved dependency reports its
`Unknown` and claims no exit.

## 2.6 Files you may edit for PATH-01

`common/physicalpath/leaves.go` (the enumeration and the reversal), and `common/physicalpath/dryrun.go`
(`businessEntry`, `nodeRequirementFor`, `advertisedNetworks`, `anyNodeCarries` — all three read
`businessEntry`, so they recover together once `Position`/`Exit` are right). `physicalpath.go`'s
`reversePacketOrder` is the reference for what packet order means.

Also fix while you are there (`P5`, low risk, currently wrong and misleading):

- `physicalpath.go` around line 536 cites `TestControlPathIsRootToLeafRegardlessOfPacketOrder`, **which
  does not exist**. The test that actually pins it is `TestControlPathIsShorterThanThePhysicalPath`.
- `status.go`'s `PathStatus.ControlPath` comment says "CONTROL chain in packet order"; the field is
  descent order.
- `leaves.go`'s `PathNode.Exit` comment still describes the old "node with no dependency" rule.
- `dryrun.go`'s `nodeRequirementFor`/`advertisedNetworks` comments still say "first hop / position 0",
  which `businessEntry` replaced.

---

# 3. IN FLIGHT — two subagents, no commits yet

Both were launched against `4c56ed86f` and had not committed when this was written. Their worktrees
still exist; check them first, and do not duplicate the work.

**`C:\Deepseek\内核\wD2` — D / StatusView (P3).** Owns `common/physicalpath/status.go` only.
- `P3.1` a `nil` receiver is dereferenced: the shape is an explicit `if v != nil && ...` followed by an
  unconditional `v.walk.Lock()`, which is worse than no check because it tells a reader the case is
  handled.
- `P3.2` the `walk sync.Mutex` may be a historic artefact — it was added for the `Resolver`'s old
  shared per-walk state, which a previous round moved into a per-call `walkScope`. Two questions
  needing separate answers: is it still *necessary*, and is it *safe* to hold across calls to external
  reporter methods (a reporter that calls back into the view is a self-deadlock).
- `P3.3` `Disconnect()` versus an in-flight snapshot: needs an explicit linearisation rule.
- Also: a panicking reporter must not become a silent `READY`, and error strings must stay redacted.

**`C:\Deepseek\内核\wC2` — C / Group (P2 + P4).** **P2 HAS LANDED** as `35246a212`, cherry-picked onto the tip as `96e6dc41`:
872 insertions across `protocol/group/selector.go` and
`protocol/group/selector_selection_state_test.go`. `protocol/group`, `route` and the root package are
all green. **`physicalpath_edge_test.go` (P4) is still UNCOMMITTED in `wC2`** — it is a new untracked
file, so check there before redoing P4. Owns `protocol/group/selector.go` and
`common/physicalpath/dryrun.go`.
- `P2` `Selector.References()` returns `s.tags[:1]` when `selected == nil`, even when `defaultTag` is a
  different member. **The trap**: `References()` may carry a structural role for the start-order sort
  and the cross-kind cycle check, so changing it could break the dependency graph or mask a cycle.
  Enumerate every caller first. The four states that must stay distinguishable: `ConfiguredDefault`,
  `PersistedSelection`, `LiveCommittedSelection`, `Unknown/Preview`.
- `P4` `hasNetworkFilteringGroup(resolver, nodes)` returns true if ANY node's control path has ANY
  filtering group, while `nodeRequirementFor` only sees one node's path — so an inner `loadbalance` can
  appear to protect an outer `selector` that does not filter. Needs per-EDGE reasoning, not a global
  boolean.

**Caution for both**: the subagent worktrees are 3 commits behind the tip. Rebase or cherry-pick onto
`310af9e69` before integrating.

---

# 4. NOT STARTED — the rest of the prompt's scope

| item | where to look | note |
|---|---|---|
| `e2e/TestRejectReplyCode` intermittency | `e2e/` | measured in an earlier round at 1-of-3 in the full package at the final SHA and **1-of-4 at the round's BASE with no changes present**, so pre-existing; 5/5 in isolation. Needs an event/barrier injection to find the real cause, not a longer timeout |
| `common/dialer` 30s deadline | `common/dialer/dual_stack_scheduler.go`, `resolve.go` | `TestLiteralBothFailReturnsPromptly` returned at **exactly** the caller's 30s deadline under package load while both attempts fail within 5ms — consistent with a lost completion signal. Two suspect arms: `dual_stack_scheduler.go:320-323` and `resolve.go:596-601` |
| `common/tls` 3 cases | `common/tls/windows_client_test.go` | `BLOCKED_EXTERNAL`: this host's Schannel has no TLS-1.3-over-TCP (Windows 10 19044). Only the three tests that pin `MinVersion/MaxVersion = TLS13` fail; every other Windows TLS test passes |
| `common/tlsspoof`, `common/windivert` | — | `BLOCKED_EXTERNAL`: `windivert: open SCM: Access is denied`, session not elevated. All 19 non-driver windivert tests pass |
| the seven-layer fault tree | — | D4 DNS/FakeIP, D6 MTU/fragment, D7 stop/reconnect/platform were not walked this round |
| a fresh serial full scan | — | must be run at whatever SHA you finish on; record `FULL_TEST_COVERAGE` / `FULL_TEST_RESULT` / `FULL_TEST_SHA_MATCH` as three separate fields |

---

# 5. Already verified in earlier rounds — do not redo

These have evidence and should not be rebuilt. If you touch their files, re-run their tests.

- **Upstream absorption, MERGE-01.** Upstream is `SagerNet/sing-box` (remote `upstream`, tip
  `6afeff4c0`), merge-base `7a3d4e4a`. 53 upstream commits: **42 patch-equivalent, 11 genuinely new,
  0 REAL_GAP**. Three places the fork is stronger than upstream. One genuine divergence is a *product
  decision*: the fork treats a DNS-only change as a DNS-generation change and never a network
  transition (`dns/router.go:1266-1317`, enforced by
  `route/dns_only_change_is_not_a_network_transition_test.go`), and upstream's own commit deletes the
  same cgo reader the fork uses. **LX (`Leadaxe/sing-box-lx`) is NOT the upstream** — and it does not
  even contain `transport/v2rayxhttp` or `common/physicalpath`, so there was never an LX patch for
  SPEC 119 or 121.
- **Destination DNS ownership on the wire.** `e2e/detour_wire_order_test.go` and
  `e2e/destination_ownership_stand_test.go`: a real two-hop stand (two real SOCKS5 servers, a real
  origin, a real sing-box instance) showing the entry is asked for the exit's address and the exit for
  the origin; plus ownership ON -> address at the peer, OFF -> the name still travels, and no answer ->
  fail closed with the peer receiving nothing.
- **urltest / clashapi.** Go's Windows monotonic clock reads `KUSER_SHARED_DATA.InterruptTime`, so a
  successful sub-tick measurement reported the `0` "no result" sentinel. `common/urltest/measure.go`
  now cannot emit it on success; the fix also cured `experimental/clashapi`, whose 503 came from
  `proxies.go:351`'s `delay == 0` and which needed no change of its own.
- **WireGuard bind/lifecycle.** `listen_port` really binds or `Start` fails closed; a nil dialer no
  longer panics process-fatally from a background goroutine.
- **MTU.** TUIC measured on the wire (1232 -> 1232); WireGuard framing measured as
  `16 + min(ceil16(inner), MTU) + 16`, so worst-case padding does not enter the conservative capacity —
  and that bound holds for `inner <= MTU`, first breaking at `inner = MTU+1`.
- **H3 fallback memory**, **COPY-01 allocation audit**, **cross-build matrix** (windows/amd64,
  linux/amd64, linux/arm64, darwin/arm64, freebsd/amd64 all build) and **libbox ABI** (383 exported
  symbols identical to the round's base).

---

# 6. Product decisions that are yours, not a fixer's

1. **HY2 ChromeParrot.** The pinned `quic-go` forces `initialPacketSize = 1250` whenever ChromeParrot
   is set (`config.go:105-125`), and no other config field can lower the first flight. A proven
   1232 ceiling is therefore ineffective there: `1250 + 48 = 1298` bytes over IPv6 on a 1280-byte
   path. The only in-repo lever is disabling ChromeParrot, which abandons the fingerprint. **Needs
   authorisation to touch the fork.**
2. **`mtu < 1280` with an IPv6 address is refused at construction** (IPv4-only low MTUs are kept).
   That rejects a configuration which used to start.
3. **A nested WireGuard endpoint shrinks its MTU** to its detour's proven ceiling (1408 inside a 1408
   tunnel becomes 1328). Intended, logged, wire-visible.
4. **`common/httpclient`'s 48h HTTP/3 cap** is reachable only by failures concurrent inside one window,
   because an expired entry is deleted on read. The comment reads like a doubling ladder; the code is
   a concurrency-amplified one.
5. **The `sing` fork allocates a `BufferedVectorisedWriter` buffer unpooled above 64KiB** — the one
   genuinely avoidable per-write allocation found, inside a read-only dependency.

---

# 7. Closing status at `310af9e69`

```text
IPC_SECRET_LEAK                = FIXED_VERIFIED   (assertion-level reverse-break, sentinel visible)
PHYSICALPATH_UNKNOWN_AND_EXIT  = NOT_READY        (13 red detectors are the specification)
  truncated-route-claims-no-exit = ALREADY_FIXED  (that test passes today)
SELECTOR_SELECTION_CONTRACT    = PENDING          (wC2, no commits yet)
STATUSVIEW_LIFECYCLE           = PENDING          (wD2, no commits yet)
NESTED_GROUP_NETWORK_POLICY    = PENDING          (wC2, no commits yet)
WG_BIND_AND_LIFECYCLE          = READY
DNS_OWNERSHIP_AND_L0           = READY
H3_FALLBACK                    = READY
MTU_PATH_BUDGET                = BLOCKED_EXTERNAL (HY2 ChromeParrot; needs fork authorisation)
PER_HOP_STATUS                 = READY            (but see P3 — it reports through Path.Exit(),
                                                   which is correct, while the dry run reports through
                                                   PathNode.Exit, which is not, so the two can name
                                                   different hops in one report)
E2E_AND_DUAL_STACK_STABILITY   = NOT_READY        (not investigated this round)
INDEPENDENT_DEBUG              = PARTIAL
FULL_TEST_COVERAGE             = NOT_RUN at this SHA
CROSS_PLATFORM                 = PASS_WITH_SCOPE  (5 targets build; ABI identical, 383 symbols)
CI                             = NOT_RUN_BY_REQUEST
RELEASE                        = NOT_READY
```

## 7.1 What I would do first in the new window

1. Check `C:\Deepseek\内核\wC2` and `C:\Deepseek\内核\wD2` for commits, rebase them onto `310af9e69`,
   run their tests, integrate. Two of the prompt's five P-items may already be done.
2. PATH-01, using §2.3: keep the chain device-first, take `Position` from it directly, and make `Exit`
   the node whose chain is not a prefix of any longer chain on the same route. The 13 red tests in §2.5
   are the acceptance criteria; run them after every step.
3. Then the e2e/dialer intermittency (§4), which is the last unknown that is reproducible offline.

**Standing rules that cost time when forgotten**: every commit subject needs the literal `[skip ci]`;
run the preflight before every push; never write `C:\src\sing-box`; no dependency or `go.mod` change;
never trigger Actions; and **a reverse-break whose RED is a compile error is not evidence** — that
mistake was made twice this round and both attempts had to be thrown away.

---

# 8. P2/P3 INTEGRATION STATUS — read this before starting

Both subagent fixes were rescued onto the tip. **The branch is green except for the PATH-01
detectors.**

```text
P2  selector          LANDED   35246a212 -> 96e6dc41   protocol/group, route, root all green
P3  StatusView        LANDED   798c57eb -> 03995f6da   D's 14 tests green, also under -race -count=3
```

`common/physicalpath` currently fails 13 tests, and they are ALL the PATH-01 specification — verified
under `-race`: **zero `WARNING: DATA RACE`**, 13 `--- FAIL`, every name in §2.5. Do not read that FAIL
as a new regression.

## What P3 changed, and the two guards whoever wires it up must not break

- **A nil `*StatusView` is now a LEGAL VALUE** answering UNKNOWN with a reason (`absentStatus`),
  `Connected()==false`, `Disconnect()` a no-op. Chosen over a refusal because the file's own policy is
  that a diagnostic must not crash on the graph it describes, and over an empty `PathStatus` because an
  empty answer has no unknowns and reads as "walked and clean". The typed-nil path (a nil receiver
  behind a non-nil interface) is covered by the same contract and tested explicitly.
- **The `walk sync.Mutex` was REMOVED, not shrunk.** It protected nothing this package owns: `Resolver`
  is written only in `NewResolver` and in `configure`, which copies; the per-walk state lives in a
  stack value. It was held across calls to external reporter methods, and a reporter that calls back
  into the view **self-deadlocked** — shown with real runtime stacks. Measured cost of the lock:
  parallel snapshots went from 4409–5032 ns/op to 954–1214 ns/op, a ~4x serialisation.
  **If anyone re-adds per-walk state to `Resolver`, a lock has to come back WITH a measurement, and
  these two tests are the tripwire:** `TestAReentrantReporterDoesNotDeadlockTheView`,
  `TestOneViewsSnapshotsDoNotSerialiseBehindEachOther`.
- **The `Disconnect` rule has three clauses** and only the first was implemented before: `Disconnect`
  publishes and returns without waiting; a snapshot reads the generation BEFORE and AFTER observing and
  both must find it connected; a call starting after `Disconnect` returned reports disconnected, and an
  observation that STRADDLED the teardown is discarded rather than published. The real hole was the
  second half — a walk past the pre-check could read hops from a dismantled graph.
- **A panicking reporter fails UNKNOWN, not silent READY**, with the half-read claim/error/generation
  fields discarded so a hop that claimed Ready then panicked cannot be reported ready. The panic value
  is rendered outside the recover frame and redacted.
- **Three real redaction leaks were found BY A RED TEST, not by reading**: `{"password":"hunter2"}`,
  `password="hunter2"`, and `access_token=`/`db_password=` (because `_` was treated as a word
  character). Fixing the last one naively would have introduced a NEW leak — with `_` allowed,
  `X_Authorization: Bearer sk-...` falls to the keyword path, which stops at the first space and would
  have redacted "Bearer" and kept the token — so both matchers now share one boundary rule.

Allocation claim, independently re-measured on the integrated tree: **1200 B/op, 9 allocs/op**, both
before and after — the containment, the generation re-read and the nil contract added zero allocations.

**Still not wired**: `StatusView` is referenced only by its own tests; `box.go` does not construct one.
Whoever wires it should rely on the nil contract and must not re-introduce the lock.

---

# 9. FINAL INTEGRATED STATE — all four fixes landed, PATH-01 is the only red

```text
P5  citations/comments   (mine, low risk)   see §2.6 — still open
S0  WG private key       FIXED_VERIFIED     assertion-level reverse-break, sentinel printed
P2  selector             LANDED             35246a212 -> 96e6dc41
P3  StatusView           LANDED             798c57eb -> 03995f6da
P4  edge network policy  LANDED             a49e04dd -> f2dd95d6
```

`common/physicalpath` fails exactly **13** tests and they are **all** the PATH-01 specification in
§2.5. Verified under `-race -count=1` over the whole package binary: **zero `WARNING: DATA RACE`**,
13 `--- FAIL`, every name accounted for. `gofmt -l` clean on `common/physicalpath`, `protocol/group`,
`route` and the root package. `protocol/group`, `route`, the root package, `adapter/...` and
`adapter/outbound` are all green.

**Do not read that FAIL as a regression, and do not "fix" it by inverting the detectors.**

## What P4 actually changed, and the mutation that makes it trustworthy

The defect: `hasNetworkFilteringGroup(resolver, nodes)` returned true if ANY node's control path
contained ANY filtering group, so an inner filtering group exempted an OUTER non-filtering selector's
whole subtree. Raw RED on `outer(loadbalance) -> inner(selector) -> [tcp-only, udp-only]` with both
networks delivered: **`[]` failures** — a miss, not a misattribution.

The fix is per EDGE: a node is exempt only when the group that **handed it the flow** filters, which
is the INNERMOST group on its control path (the last element — a group is never emitted as a hop, so
the last element is always the immediate parent). `hasNetworkFilteringGroup` is deleted and replaced
by per-filtering-group responsibility: `filteringGroups()` (de-duplicated by IDENTITY, not tag) +
`nodesUnder()` + the existing `anyNodeCarries`. The failure is attributed to the FILTERING GROUP with
its route named rather than to the root.

**The mutation that matters, in the fixer's own words**: mutation M5 — *never exempt anyone* — fails
`START-01-B2`, `START-01-B3` and the new blanket case. So the exempt edge is load-bearing in **both**
directions: removing it causes false refusals, not just missed ones. A fix in this area that only
proved the miss would be half-verified.

**Nine previously-legal configurations re-run: all nine still start**, all six refusals keep their
reasons. Fixing the miss did NOT become a false refusal.

## What P2 actually changed, and the trap that turned out not to exist

`Selector.References()` returned `s.tags[:1]` while nothing was selected, and through the real
`SnapshotStatus` consumer that became `Decision = "node-a"`, `Committed = true` for a selector
configured `default: node-b` that had never started.

**The trap was checked before the change, and it does not exist for this method**: the start-order
sort (`manager.go:341`), the cycle lint and the cross-kind check all walk `Dependencies()`, which for
a selector is the whole declared tag list; `cross_kind_cycle.go:155` reads `References()` only for a
DNS *transport*; and the one caller that would notice, `route/reference.go`'s idle walk, first runs at
`StartStateStarted` (3), after outbounds start at `StartStateStart` (1). So `References()` could be
changed directly, to `nil` — matching what `URLTest.References` and physicalpath's **own `testGroup`
fixture** already do.

**Why not `defaultTag`: `status.go` maps ANY single reference to `Committed = true`, so returning the
configured default would still display a configured value as live — the same defect with a better
name.** That is pinned by mutation M3, which specifically catches the plausible wrong fix.

The four states are now explicit and never merged: `SelectionUnknown`, `SelectionConfigured`,
`SelectionPersisted` (validated against the DECLARED tag list, so the accessor cannot race `Start`),
`SelectionCommitted`. Only `SelectionCommitted` carries `Committed`.

## Flaky test flagged, not fixed

`route::TestConfiguredRateShapesTheRealTCPCopyPath` failed once under a 5-package parallel run. It
self-describes as "wall-clock over a fixed payload" (`route/traffic_scheduler_integration_test.go:70`),
passes 3/3 in isolation and passed 4 earlier full-suite runs. The copy path and scheduler are
untouched by any of these changes. It should be made load-independent or marked as timing-sensitive —
**do not "fix" it by widening the band.**

## Still open

1. **PATH-01** — §2.3 gives the direction (keep the chain device-first, take `Position` from it
   directly), §2.4 lists the six failed attempts so they are not repeated.
2. **P5** — the stale citations and comments in §2.6. Low risk, currently misleading.
3. **`StatusView` is still not constructed by `box.go`.** It is referenced only by its own tests. The
   nil contract means a box whose view failed to build reports UNKNOWN rather than crashing, but
   nothing in-tree reaches it yet.
4. **`SelectionStatus()` is available but not wired into any UI** — "configured but not committed" is
   displayable rather than displayed. No consumer was changed.
5. **The P4 fixer's own honesty note**: the reverse-break mutated the worktree from pristine copies in
   a temp directory (both files restored byte-identical, hashes in their report) rather than in a
   separate clone. Weaker isolation than the other agents used; the hashes are the evidence.

---

# 10. PATH-01 CLOSED at `d7d542d0b` — what the wall actually was

§2 is superseded by this section. The direction §2.3 prescribed ("keep the chain DEVICE-FIRST and take
`Position` from it directly") was right; what it did not say is that the chain has to END at the node
it describes, and that is the whole of the wall.

```text
ORIGIN_TESTING = 12c0a9e6032675d45db4ee3864fc3d404ade6a84   LOCAL == ORIGIN
COMMITS FROM 26d2c4d9f, all [skip ci]:
  1f6b7b85d  PATH-01: number every route in packet order, from the frame that owns it
  d7d542d0b  the redaction backstop also matches a spaced assignment (§10.5)
  dd0e32094  a group reached as a dependency extends the route above it (§10.6)
  f170a1907  this section (docs)
  eb202f996  an echoed hop is charged to the node budget; the nested shape pinned
  2c4240231  a truncated route is numbered too, so both APIs order it the same way (§10.7)
  c216688f9  dialer: a race with no winner must end when both sides have reported (§10.8)
  032ed4947  the dialer finding, in this document (§10.8)
  fa45c786a  e2e: a truncated read is the pinned defect, not evidence that it was fixed (§10.9)
  3c3dd135b  sniff: the leak check counts this package's goroutines, not the process's (§10.10)
  291698273  group: observe what a traffic failure leaves before the recheck decides (§10.10)
  12c0a9e60  power: the observation window must be far inside the deadline it measures (§10.10)

FULL_TEST_COVERAGE = 83 test packages (`go list` over ./... with the production tag set)
FULL_TEST_RESULT   = 79 ok / 4 FAIL at 12c0a9e60, 316s, `go test -count=1 -tags "$TAGS" ./...`
FULL_TEST_SHA_MATCH = YES (the scanned SHA equals origin/testing)
  the 4: common/physicalpath (the ONE unsatisfiable detector, §10.3 - not an unfinished fix)
         common/tls, common/tlsspoof, common/windivert (BLOCKED_EXTERNAL: this host's Schannel has no
         TLS 1.3 over TCP, and the driver tests need an elevated session)
NO UNEXPLAINED FAILURE remains, and no failure is attributable to the four flakes this round fixed.
```

## 10.1 The mechanism, measured before the fix

`Hops` discarded the flag its own top-level call returned (`leaves.go:200`,
`_, err = scope.enumerateHops(root, ...)`), so **the segment consisting of the root's own node was
never numbered**: `Position` stayed 0 everywhere and `Exit` stayed false unless a group's member loop
happened to reverse the range. `businessEntry` then read `Position == len(PhysicalPath)-1`, which on a
three-hop route under a group is true for the **middle** hop:

```text
node a  chain "a -> b -> c"  pos=0 exit=false entry=false
node b  chain "b -> c"       pos=1 exit=false entry=TRUE     <- the wrong hop
node c  chain "c"            pos=2 exit=true  entry=false    <- the routing-selected hop, UNCHECKED
report: reachable=true failures=0                            <- a FALSE PASS
```

## 10.2 The fix

`enumerateHops` returns a three-valued `routeOutcome` (`routeContinues` / `routeComplete` /
`routeTruncated`) instead of a bool, because "the route ended" and "the route ended at its FAR END"
license different things. The frame that **owns** a route numbers it exactly once — a group's member
loop for a member route, and `Hops` itself for the route that begins at the root. `completeRoute`
replaces `reverseRoute`: it reverses the declared range into packet order and gives each node the
**prefix of that route which ends at it**, so `Position` is the last index of the field beside it and
the node that no longer chain extends is the far end. The prefixes of one route share one backing
array, so memory is linear in nodes, not quadratic in chain depth.

`businessEntry` is now `Exit && Resolved`. The old `Position == len(PhysicalPath)-1` test held for
**every** node once the chain ends at the node, which is exactly how it named the middle hop; `Exit` is
the enumeration's own statement of the far end, and `Resolved` keeps the one node that is `Exit`
without being a far end (a group member that names no object) out of the answer.

```text
three hop under a group:  a "a" pos=0, b "a -> b" pos=1, c "a -> b -> c" pos=2 exit=true
                          udp delivered to a tcp-only c -> reachable=FALSE   (was TRUE)
diamond route A:          shared "shared" pos=0 exit=false, middle "shared -> middle" pos=1
                          exit=true, requirement=[tcp]                        (was []: unvalidated)
```

## 10.3 The two things that CANNOT both be green — with proof

**1. `businessEntry` for a member that does not resolve.** `TestAnUnresolvedGroupMemberIsNotABusinessEntry`
asserts `require.False(t, businessEntry(missing))` on the node `{Tag:"absent", PhysicalPath:[], Position:0,
Exit:true, Resolved:false}`. `TestBusinessEntryCountsExactlyOneEntryPerRoute/group_whose_member_does_not_resolve`
segments that node into a route **of its own** (its `Position` is pinned to 0 by the first test, so it
cannot continue the other member's route) and then demands **exactly one** business entry in it — which
is the same node, so it demands `true`. The failing output prints the route as `root=group size=1.
Nodes: [absent(absent pos=0 dep)]`. No assignment satisfies both; the first detector is the
product-correct one and is kept green. **This is a defect in the specification, not in the code.**

**2. The diamond's chain string.** `diamond_routes_test.go`'s route-A expectation for `shared` is now
`{physicalChain: "shared", position: 0, exit: false, required: tcp}`. The previous value
(`"shared -> middle"`, position 0) was introduced by **`0ad08d645`, one of the six failed attempts** —
its own diff rewrites the expectation from the pre-attempt `{physicalChain: "middle -> shared",
position: 1}`. That string is incompatible with the field's documentation ("the packet-order chain that
ends at this node"), with `TestEachNodePositionIndexesItsOwnChain` and with
`TestEveryNodeOfEveryRouteIsReachableAtItsOwnPosition`: `position: 0` beside a two-element chain means
`Position != len(PhysicalPath)-1` and a chain that does not end at its node. One field of one green
test was updated; `position`, `required` and a new `exit` field carry the per-route distinction the
test exists for. **This is the only test expectation changed by 1f6b7b85d and it is called out in the
commit message too.**

If the diamond string is preferred over those two detectors, the correct resolution is to change the
two detectors — deliberately, in one commit, with this section as the reason — not to reinstate the
failed attempt's representation.

## 10.4 Reverse-break, both mutations compile

```text
MUTATION A  `leaves.go` + `dryrun.go` restored to 26d2c4d9 (the pre-fix source), tests untouched
            go build exit=0  ->  13 tests RED BY ASSERTION (the 12 detectors + the diamond string)
MUTATION B  the ONE line: `_, err = scope.enumerateHops(root, ...)` again, `completeRoute(0)` gone
            go build exit=0  ->  16 tests RED BY ASSERTION, including three that were GREEN before:
              TestADeliveredNetworkTheChainCannotCarryIsAccepted   (the false PASS returns)
              TestADeliveredNetworkIsEnforcedOnATwoHopChain
              TestADeliveredNetworkIsEnforcedOnASingleHopRoot
```

Mutation B is the load-bearing evidence in **both** directions: it shows the discarded outcome was the
defect, and it shows that a "fix" that only redefined `businessEntry` without numbering the root's route
would break three previously-green product-level network checks.

## 10.5 Also closed this round

- **P5** — `physicalpath.go` cited `TestControlPathIsRootToLeafRegardlessOfPacketOrder`, which does not
  exist (the pinning test is `TestControlPathIsShorterThanThePhysicalPath`); `status.go`'s
  `PathStatus.ControlPath` said "packet order" for a descent-order field; the "first hop / position 0"
  wording on `nodeRequirementFor`/`advertisedNetworks` now names `businessEntry`; `PathNode.Exit`'s
  comment no longer describes the removed "node with no dependency" rule.
- **A redaction leak P3 did not cover** (`d7d542d0b`). The matcher required the separator to TOUCH the
  keyword, so `password = hunter2`, `token : abc123`, `"password" : "hunter2"`, `password:\thunter2`,
  `password =\thunter2` and `api_key   =   sk-...` all returned their secrets verbatim — the TAB case
  worst, because a tab is a value terminator and the scan therefore found an empty value and gave up.
  Space and TAB are now skipped before the separator (only when a separator follows, so
  `the password field is required` stays readable) and after it; a newline is deliberately not skipped.
  Reverse-broken with `go build` exit 0 first: all 8 new positive cases RED with the secret in the
  message, all 4 negative controls green. Found by adversarial verification of P3, which also proved
  P3's `_`-boundary change was a strict improvement (16/41 probe inputs leaked before it, 9/41 after,
  zero regressions).

## 10.6 A follow-up defect that 1f6b7b85d INTRODUCED, and its fix (`dd0e32094`)

Measuring a shape no test built — a leaf whose declared dependency resolves to a GROUP (`L.detour = G`)
— found a **false PASS created by the PATH-01 fix itself**:

```text
node "L"   route="L"        chain="L"   pos=0 exit=false entry=false   <- nothing asked of it
node "m1"  route="G -> m1"  chain="m1"  pos=0 exit=true  entry=true
node "m2"  route="G -> m2"  chain="m2"  pos=0 exit=true  entry=true
reachable=true failures=0                       <- UDP delivered to a TCP-only L, accepted
```

Before 1f6b7b85d the shape was refused **by accident**: the un-numbered route left `L` at `Position 0`
with a one-element chain, which the OLD `businessEntry` read as "nothing is dialled through me" — true
for the wrong reason. Replacing that predicate removed the accident, so this was a regression to
repair, not a pre-existing gap. The lesson generalises: **a predicate that is right by accident is a
liability, and the shape it was accidentally right about is exactly the one no test covers.**

The fix: a group reached as a DEPENDENCY is a branch of one route that already has hops in it, so the
hops above it are ECHOED once per member and each member route ends at `L`. `enumerateHops` now takes
the index the route begins at; `dependency_on_group_test.go` (3 tests) is the detector, reverse-broken
by deleting the echo (`go build` exit 0 first; both model tests RED by assertion, the product test RED
with `reachable=true failures=[]`).

## 10.7 The truncated route was still ordered differently by the two APIs

Reading the diagnostic output for the truncated topologies after §10.6 — the one place the two APIs are
printed side by side — showed a disagreement that had survived every detector:

```text
three hop with the entry missing (c -> b -> missing-a)
  BUILD hops = [b pos=0, c pos=1] + unknown missing-a pos=2
  HOPS       = [c pos=0, b pos=1]          <- the OPPOSITE order
```

Both agreed the route has no exit; they disagreed about the ORDER of the hops that ARE known. The
detectors could not see it: `TestATruncatedRouteClaimsNoExit` asserts the exit rule only, and it passes
under either order — which is exactly why a detector that only pins the half you were looking at is not
enough.

`completeRoute` is now `numberRoute(start, complete bool)`: a truncated route is numbered in packet
order like any other (`c` is dialled through `b` whether or not `b`'s dependency exists, and `Build`
reverses such a path too), and `complete` false leaves every node of it without an exit.
`cross_api_agreement_test.go` is the new detector: six linear topologies compared hop by hop for order,
`Position` and exit — the entity the round's headline is about, asserted rather than printed.
Reverse-broken by numbering only the complete routes (`go build` exit 0 first, then the middle-missing
row RED with both orders in the message, while `TestATruncatedRouteClaimsNoExit` stayed GREEN — the
proof that the new detector covers something the old one cannot).

## 10.8 The `common/dialer` 30s stall was a PRODUCTION defect, and it is fixed (`c216688f9`)

§4 listed this as "consistent with a lost completion signal" and named two suspect arms
(`dual_stack_scheduler.go:320-323`, `resolve.go:596-601`). **Neither is the cause**, and it is not a
lost signal either: the exit condition itself was wrong.

`raceWithPendingOriginal` (`resolve.go:913`) looped `for winner == nil` while each side reports EXACTLY
ONCE on a capacity-one channel. When BOTH attempts fail there is no winner, both channels deliver and
are then drained forever, and the select blocks on two dead channels until the caller's context
expires. The other arm (`dialRecoveredOrReport`, `resolve.go:641`) always handled that case, which is
why it only appeared when the head-start timer fired before the original reported.

```text
pristine, -run TestLiteralBothFailReturnsPromptly -count=200 x20 batches (4000 runs): 3 failures
  --- FAIL: TestLiteralBothFailReturnsPromptly (30.00s)   "30.0009301s" is not less than "5s"
goroutine dump AT the stall: 1 goroutine in raceWithPendingOriginal (resolve.go:914), 0 workers,
  counters enter=1 A1=0 B=1 origRecv=1 recRecv=1 cancel=0   <- both channels delivered, no winner
```

It reproduces in ISOLATION, so it is not a load artefact - load only decides which of the two arms runs
(2ms-publish vs 5ms-dial boundary), which is also why adding debug logging masked it (0/2600) and why
the shipped detector sees it ~1% of the time.

The fix breaks the loop on `winner != nil || (originalSettled && recoveredSettled)`. No timeout is
widened. `literal_pending_failure_test.go` pins the broken arm deterministically, and I re-ran the
reverse-break myself rather than trusting the report: **pristine code + new test → `go build` exit 0,
then RED by ASSERTION at `"30.0007495s" is not less than "5s"`; fixed code → PASS at 0.20s**; the
shipped detector `-count=50` ok, the full package ok, `-race` ok.

User impact: whenever the sniffed-domain recovery answers quickly (a cached DNS answer) while the
application's literal address is slower than the head start and ALSO fails, the connect hung for the
whole connect timeout instead of failing at once.

## 10.9 The `e2e/TestRejectReplyCode` flake: an observation defect on top of the pinned one (`fa45c786a`)

Reproduced at **2 in 12** full `./e2e/` runs, **0 in 20** when the same tests run in ONE process, and
**0 in 30** once stderr logging was added - the window is microseconds. Silent atomic counters kept it
(1/14), which is how the trace below was captured.

The failing assertion was NOT the SOCKS5 reply code: it was the HTTP CONNECT half, and the helper threw
the observation away (`httpConnectStatus` returned `"", err.Error()` on any read error). The 40-byte
`200 Connection established` head IS written (`transport/http/server_conn.go:110`); the reject path
(`route/route.go:163` -> `:87` -> `conn.Close()`, which a handed-off CONNECT does not route through
`transport/http/server.go:216`) then closes ABORTIVELY, and that close destroys a response the peer has
already received:

```text
[XFLAKE] serveConnect wrote200 127.0.0.1:58314 blocked.test:443
[XFLAKE] serveConnect handedOff 127.0.0.1:58314
readHTTPHead failed after 29 byte(s): wsarecv: An existing connection was forcibly closed by the remote host
```

An isolated plain-Go microbenchmark pins the OS rule: write-then-CLEAN-close is observable 4959/4959,
write-then-ABORTIVE-close loses the response 4869/5000 (361 of them zero-byte), `SetLinger(0)` likewise.

So the client observes the head, part of it, or a reset with no bytes - three faces of the SAME pinned
defect - and the test was reading the last two as "the defect may have been fixed". The fix keeps the
bytes read, asserts `200` on a complete OR partial head (logging the truncation), accepts a zero-byte
abort with a log, and still fails on a read DEADLINE so a hang is never excused. No timeout is widened
and a future fix is still detected: a proxy that decides before answering sends a status line that is
not 200.

**The production ordering is NOT changed** - announce "established", then refuse is inherited from
upstream (upstream sing's `protocol/http/handshake.go` does the same) and the test's own header records
it as a product decision owned by `protocol/**`.

```text
before, this session: subset via go test, 20 separate processes   2 failures
after:                same command                                0 failures
after:                full ./e2e/, 6 separate processes           0 failures (16-18s each)
```

## 10.10 Three more flakes the full scans found, and the mechanism of each

The round's full serial scans are what surfaced these. None is caused by this round's changes, all
three are pre-existing, and each failed ONLY inside the whole suite - which is why they had survived.

**`common/sniff`, `TestPeekStream{CancelledContextStillTerminates,DoesNotOutliveItsDeadline}`**
(`3c3dd135b`). The leak check compared a PROCESS-GLOBAL `runtime.NumGoroutine()` against a baseline
taken before a 64-iteration loop. That count is moved by everything else in the binary: 93 tests in one
process, several of them completing real TLS handshakes, plus a previous `-count` repetition's
goroutines. MEASURED: 1 failure per 10 iterations of the two tests, PASS alone, and one failure in a
full package run - a leak reported in a test that had not leaked. The fix counts the goroutines whose
stack names this package. The check still fires: with a deliberately leaked goroutine added to
`PeekStream` (`go build` exit 0 first) BOTH tests go RED by assertion.

**`protocol/group`, `TestTrafficDialFailureDoesNotDeleteHealthEvidence`** (`291698273`). Failed in BOTH
of the round's first two scans (`expected node-a, actual node-b`), 10/10 alone. The test asserts the
state left by a failed business dial, but that failure also REQUESTS a forced recheck
(`clearSelectionFor` -> `requestRecheck`), and the recheck's round probes with `mode = TestHistoryHealth`
where a failed probe DELETES that member's health measurement (`urltest.go:1170-1175`). So the test was
racing the product's own verdict - which is the documented contract ("a traffic failure may REQUEST a
recheck; the recheck decides"). The fix gates the health probe, so the two observations become
sequential: the state the failure leaves, then the verdict the released recheck reaches. Strictly
stronger than before - it now also fails if a traffic failure stops requesting a recheck, or if a
failed health check stops invalidating its own measurement (proved by removing the deletion:
`go build` exit 0, then RED by assertion).

**`common/power`, `TestCoalescedNotificationsNeverReportAStateThatIsOver`** (`12c0a9e60`). Failed the
third scan at `expected 0x2 (quiescent), actual 0x3 (deep-idle)`. `ObserveTraffic` moves DEEP_IDLE ->
QUIESCENT synchronously AND re-arms the deadline; the test then slept 50ms against a `DeepIdleAfter` of
**60ms**. Ten milliseconds of margin is inside `time.Sleep`'s noise band on a loaded machine, so the
assertion could read the state the (correct) timer had just moved to. The test's own comment already
claimed "a deadline long enough that the state cannot legitimately move on by itself during the test",
so the deadline now says that: 600ms against the 50ms window (and the sibling tests' windows were
raised out of the noise band too: 150->400ms, 100->300ms). No assertion is weakened.

## 10.11 Still open after this round

1. **`StatusView` is still not constructed by `box.go`** (§9.3) — unchanged by this round.
2. **`SelectionStatus()` is not wired into any UI** (§9.4) — unchanged.
3. **`ValidateRoots` alone accepts a root whose declared *dependency* does not resolve** (a group
   *member* that does not resolve is reported; a `detour` that names nothing is not). MEASURED:
   `exit.detour = missing-entry` gives `Reachable=true, failures=0, nodes=1` from `ValidateRoots`
   while `Build` reports the Unknown. Production start is **not** exposed — `lintOutbounds`
   (`adapter/outbound/manager.go:372`) refuses `dependency[X] not found for outbound[Y]` before the dry
   run, for outbounds and endpoints alike — so this is an API-level gap, and adding a hop for the
   missing tag would double-report the same defect at the manager level. Left as-is, deliberately.
4. **`route::TestConfiguredRateShapesTheRealTCPCopyPath`** — wall-clock band test, flagged by the
   previous round, not fixed here (§9). Do not widen the band. It did NOT fail any of this round's four
   full scans, so its rate is low; the three flakes that did recur are fixed (§10.10).
5. **`e2e/TestRejectReplyCode`** — CLOSED as an observation defect (§10.9). The production ordering it
   pins (announce "established", then refuse) is still a product decision owned by `protocol/**`.
6. **The seven-layer fault tree** (D4 DNS/FakeIP, D6 MTU/fragment, D7 stop/reconnect/platform) is still
   not walked (§4), and `common/tls`, `common/tlsspoof`, `common/windivert` remain BLOCKED_EXTERNAL.

## 10.12 The worktrees this round left behind, and what is in them

`git worktree list` still shows the investigation worktrees. Their content is INTEGRATED (or
deliberately not); nothing there is a pending deliverable:

```text
work    ae0846ea8   the integration worktree, clean, == origin/testing
wB2     4c56ed86f   pre-round, untouched
wC2     a49e04dd4   P4's own commit, which is f2dd95d6 in the line above
wD      b634f3c2a   pre-round, untouched
wD2     798c57eb4   P3's own commit, which is 03995f6da in the line above
wDL     1f6b7b85d   the dialer fix and its test - BOTH are committed as c216688f9, so the `M` there is
                    not pending work
wE2E    1f6b7b85d   all four instrumented files reverted; one untracked evidence file
                    (FLAKE_evidence_TestRejectReplyCode.txt) whose decisive excerpt is quoted in §10.9
```

# 11. Closing status at `12c0a9e60`

```text
IPC_SECRET_LEAK                = FIXED_VERIFIED   (assertion-level reverse-break, sentinel visible)
SELECTOR_SELECTION_CONTRACT    = LANDED           (P2: 96e6dc41, six callers enumerated first)
STATUSVIEW_LIFECYCLE           = LANDED           (P3: 03995f6da, runtime stacks for all three defects)
NESTED_GROUP_NETWORK_POLICY    = LANDED           (P4: f2dd95d6, per-edge, mutation M5 both directions)
PATH_01_PACKET_ORDER_AND_EXIT  = FIXED_VERIFIED   (1f6b7b85d + four follow-ups; 12 of 13 detectors green,
                                                   the 13th proven unsatisfiable alongside another)
  unknown-and-exit             = also closed      (truncated routes: ordered like Build, no exit claimed)
  dependency-on-a-group        = also closed      (a false PASS this round introduced, then repaired)
REDACTION_BACKSTOP             = HARDENED         (d7d542d0b: spaced assignments, 8 new cases)
DIALER_DEADLINE_STALL          = FIXED_VERIFIED   (c216688f9: production defect, independent reverse-break)
E2E_REJECT_REPLY_FLAKE         = CLOSED           (fa45c786a: observation contract, not the product order)
SUITE_FLAKES_FOUND_BY_SCANNING = 3 CLOSED         (sniff, protocol/group, power - §10.10)
PER_HOP_STATUS                 = MODEL READY      (StatusView not yet constructed by box.go)
CROSS_PLATFORM                 = PASS_WITH_SCOPE  (unchanged this round)
FULL_TEST_COVERAGE             = 83 packages
FULL_TEST_RESULT               = 79 ok / 4 FAIL, all four accounted for (1 spec + 3 BLOCKED_EXTERNAL)
FULL_TEST_SHA_MATCH            = YES
CI                             = NOT_RUN_BY_REQUEST   (no Actions event was ever triggered)
RELEASE                        = NOT_READY        (blocked on the product decisions in §6 and the
                                                   external blockers; no unexplained failure remains)
```

The standing rules were honoured: every commit carries `[skip ci]`; the preflight ran before every push;
`C:\src\sing-box` is still at `8d78dcdd` with only `clients/desktop` dirty; no `go.mod`/`go.sum` change;
no Actions event was triggered; and every reverse-break in this section was built FIRST, so no RED here
is a compile error.

