# JiejieBox v0.1.6 — next-stage closure, real-network debug and release-candidate acceptance

Integrator's final report. Every number is a command output. Where something was **not** run, it says
so in the section it belongs to rather than being folded into a green summary.

Companion documents in this directory:

- `v016-nextstage-g0-ledger.md` — the G0 record, the worktree ownership map, the structural findings
  read before any fix, and the round-1 adversary outcome.
- `v016-handoff-310af9e69.md` — the previous round's handoff. Its §2 and §4 are **history that was
  overturned**, as the order warns; §10–13 are the live record it was read from.

---

## A. Git identity and isolation

```text
START_SHA                        = 686c937cbb13aafdfe6276c8813993dfcb51d9ac
LIVE_ORIGIN_AT_START             = 686c937cbb13aafdfe6276c8813993dfcb51d9ac
FINAL_CODE_SHA                   = 666470cbe70e734240bd51d547e00b4b950eb8b1   (the last CODE commit;
                                   the exact scan SHA, see §I)
ORIGIN_TESTING_FINAL             = the tip of this document's own commit, and it is verified equal to
                                   the local HEAD rather than written down:
                                       git rev-parse HEAD   ==   git rev-parse origin/testing
                                   A document cannot cite the SHA of the commit that contains it
                                   without changing it, so the shipped pushes are named by the range
                                   each one reported — `686c937cb..04528b8bf`, `04528b8bf..3f703f2a0`,
                                   `3f703f2a0..3862ea982`, `3862ea982..eb01cb8a3`, `eb01cb8a3..7c248c0ac`
                                   and `7c248c0ac..` onwards for the audit pass — every one an ordinary
                                   fast-forward, with no force and no rejection.
FAST_FORWARD                     = YES  (`git merge-base --is-ancestor origin/testing HEAD` exit 0
                                   before every push)
NEW_COMMITS                      = 42   (every subject contains the literal `[skip ci]`; 0 missing)
REMOTE_HEADS                     = refs/heads/testing only (`git ls-remote --heads origin`)
REMOTE_TAGS                      = 636 refs/tags, and the local and remote tag SETS are byte-identical
                                   (`git ls-remote --tags --refs` vs `git for-each-ref refs/tags`,
                                   `Compare-Object` empty) — nothing created, moved or pushed
OTHER_REPOS_TOUCHED              = NO
GO_MOD_GO_SUM_CHANGED            = NO   (`git diff --stat <base>..HEAD -- go.mod go.sum` empty)
GITLINKS_CHANGED                 = NO   (clients/android, clients/apple, clients/desktop all identical
                                         to the base; clients/desktop = 32f915ba595601dbc2dd346c33fe9fedd3e72979)
CI_REMOTE                        = OBSERVED, NOT_RUN_BY_REQUEST
```

**Correction to this report's own G0 record, and to the order's premise.** The order says a Harness
without `gh`/API access may only say `REMOTE_ACTIONS_NOT_QUERYABLE`; that premise is false here — the
repository is public and unauthenticated `api.github.com` answers. The read-only query after the push:

```text
total workflow runs in the repository   = 910
runs created on or after 2026-10-10     = 0        <-- this round pushed on 2026-10-10
latest run on branch `testing`          = 2026-10-08T20:31:45Z, head e2d7ac1be ("Verify", success)
```

So the push triggered **nothing**, which is the empirical confirmation of the `[skip ci]` mechanism the
preflight gate enforces. **One number in the on-disk G0 ledger was truncated and is corrected here**: the
remote tag count was recorded as "20 refs/tags" because the G0 command that produced it was
`Select-Object -First 20`. Measured properly, the remote carries **636** tag refs, exactly matching the
local set. No tag was created, moved or pushed: the push named a single ref,
`HEAD:refs/heads/testing`, and the two tag sets compare equal.

The committed batch:

```text
8299f30ec  fix(physicalpath): the exported dry run refuses a truncated route instead of leaving it to a lint
9ebc42928  test(route): the leak census carries a frame boundary, so route/rule cannot move it
967b46cfb  test(route): "reversible" says which goroutines it is about
cb44ea1a1  fix(route): a destination this instance issued as a fakeip placeholder must not escape to a peer
7759b97ac  fix(daemon): the service context is the caller's, not a snapshot taken at construction
89e151acf  fix(http): the HTTP/3 verdict belongs to the newest attempt, not the last one to report
1949a0179  test(http): a real loopback HTTP/3 stand, and the wiring that reaches it on a transition
8074ad52e  test(route): name the scheduler tests for the userspace copy loop they actually measure
64a568b99  test(http): measure the ordering guard's cost, and bound where it may be paid
d429f4f2c  test(http): print the negotiated transport, so the H3 claim can be quoted rather than trusted
1cfb61b44  test(e2e): a truncated 200 head is the pinned defect, not a failed assertion
5228da88a  style(http): gofmt the HTTP/3 stand's struct literals
d1292bff5  feat(box): the read-only status view now lives in the Box lifecycle
e5b0897f4  test(group,power): two tests that could not fail now fail on the defect they name
f8b0af5f6  test(sniff): the leak census is calibrated, so one leaked goroutine fails it
675d72bc5  test(adapter): the issuance ledger's own bounds, and the row that forbids a range block
4cf54556d  test(dns,e2e): the wire recording is the discriminator; a citation to a file that never existed
2aedd90b2  fix(wireguard): a rebind revoked mid-reopen may not claim the new generation
d439268b1  test(tlsspoof): pin the fake ClientHello's unprivileged contract, and attribute the driver-bound half
b5059ef0a  test(route): attack the goroutine census instrument, and pin its scope
48dd4469e  test(group,power,sniff): instruments that could not fail, made to move
6140afcc5  test(daemon,adapter): the ledger's reachability walked hop by hop, and the interval boundary measured
a3fbc153b  style(wireguard): gofmt the rebind lease probes
45aab788f  test(box): the Failure pointer is a caller-owned value, and the straddle test asserts its premise
c2d93396e  test(route,sniff): two adversarial probes could not survive -count, and one measured a predicate that is gone
eca26d8fe  test(wireguard): the port table is machine-wide, so the socket census carries the release claim
eb01cb8a3  docs(fork): the audit-pass corrections, and the final scan at the frozen code SHA
7c248c0ac  docs(fork): state how the desktop handoff copy is verified, and why its hash is not written here
2f36515bc  docs(fork): one mangled edit in section A repaired, and the push ranges completed
da14572a7  test(box,sniff): the nested status scalars verified against running code, and the census allowance's zero margin measured
10f9e17d2  test(sniff): the leak assertion is "returns to baseline", because testify's own tick is not deterministic
eac9cc83d  test(sniff): the frame-shape probe captured its readings atomically, because testify's ticks overlap
2366c73ac  test(group): the sensitivity control identifies its own workers, so other tests cannot cancel it
95159084c  fix(adapter,sniff): the ledger's ceiling is observable, and the leak contract is tested at the moment it claims
b5c0009d1  test(sniff,adapter): the two-half leak predicate's blind lifetime, and the ledger bounds measured
5c15c822b  test(adversary-g): the false-deny direction, the H3 guard's claim/effect split, and the release witness
ae46d3958  fix(transport/http): the HTTP/3 verdict claim and its effect are one transaction
8ae8f10d3  fix(physicalpath,wireguard): a truncated route cannot hide behind a sibling, and the release witness checks its precondition
666470cbe  test(sniff): the frame-shape controls are scoped to the frames they are about
```

The last fourteen exist because the round's own gate and the adversary's re-tests were run **verbatim**
rather than approximated, because the adversary's second round was run on the **final HEAD** as §15
requires, and because four of its findings landed in work that had already been reviewed. See §L.3,
§L.3b, §L.3c and §H.5.

Each agent's commit was cherry-picked with `-x` onto the integration tip; the order's requirement that
no agent share a worktree was kept — seven detached worktrees, one writer per file, no file written by
two agents.

### A.1 ORIGINAL_DIRTY_WORKTREE_UNTOUCHED — hash-backed

`C:\src\sing-box` is the repository's **main worktree** and is the user's dirty tree. Before and after:

```text
BEFORE  HEAD = 8d78dcddcc434ed9091a3654e3f6b0b542fa3461   branch = testing
        git status --porcelain = " M clients/desktop"
        git diff --stat        = clients/desktop | 0
        gitlink                = 160000 32f915ba595601dbc2dd346c33fe9fedd3e72979 0  clients/desktop
AFTER   HEAD = 8d78dcddcc434ed9091a3654e3f6b0b542fa3461   branch = testing
        git status --porcelain = " M clients/desktop"
```

Nothing was written, checked out, stashed, reset, cleaned, added, committed or built there at any point.

### A.2 Desktop handoff copy

The order asks for the report to live in `docs/fork/` **and not only** at a Windows path, and the round
was given as a file on the Desktop, so two copies exist and are verified byte-identical:

```text
C:\Users\Jie\Desktop\JiejieBox_v016_686c937c_NextStage_Closure_ReleaseCandidate_Final_Report.md
C:\Users\Jie\Desktop\JiejieBox_v016_686c937c_NextStage_G0_Baseline_Ledger.md
```

The check that matters, and how to repeat it: `git status --porcelain` is empty at the tip, so the
worktree file **is** the committed blob; `Get-FileHash -Algorithm SHA256` on the worktree file and on
the desktop copy returns the same digest, and `git hash-object <worktree file>` equals
`git rev-parse HEAD:<path>` — which is what proves the desktop copy is the thing that shipped rather
than a re-rendering of it. The digests are deliberately **not** written into this document: a file
cannot contain its own hash, and the previous two push rounds each invalidated a SHA written into the
document that then contained it. They are reported outside the artefact instead.

---

## B. Requirements, item by item

| Item | Verdict | One-line basis |
|---|---|---|
| **FIP-01** historic FakeIP address dialled as a literal | `FIXED_VERIFIED` | RED on the wire at baseline (`198.18.0.2:443` reached the peer in 4 rows); GREEN after, with both proof sources measured end to end and both reverse-breaks run. Boundaries in §C. |
| **D7-02** revoked WG rebind completing and claiming the new generation | `FIXED_VERIFIED` (result ownership) + `BLOCKED_DEPENDENCY` (interruption) | The claim is now withheld; the reopen still cannot be interrupted and that is proven structural, not asserted. §D. |
| **RNET-03** real connection churn / H3 resource growth | `VERIFIED_WITH_SCOPE`, two product defects fixed | A real loopback H3 handshake (ALPN `h3` read from the server's own connection state), 25 real transitions, and two genuine defects (`FAILED_PRODUCT_FIXED`). Rows without an artifact stay `NOT_RUN`. §E. |
| **STATUS-04** `StatusView` in the Box lifecycle | `LANDED_VERIFIED` | `box.go` +226/−0 additive, one new public method, ABI identical at 383 symbols, four reverse-breaks each RED by assertion. §F. |
| **Windows 3 packages** | `EXPLICIT_PASS_FAIL_BLOCKED` | `common/tls` ×3 = `BLOCKED_ENV` with a **corrected** root cause; `common/windivert` ×5 and `common/tlsspoof` ×3 = `BLOCKED_EXTERNAL`; everything else in those packages PASSES, and 6 previously-missing unprivileged `tlsspoof` tests were added. §I. |
| **HY2 / ChromeParrot / MTU product boundary** | `PRESERVED_VERIFIED` | Untouched, and re-run green: `protocol/hysteria2` (1250 first datagram under ChromeParrot) and `common/dialer` (1232 ceiling). §J. |
| Exported `ValidateRoots` accepting a truncated route | `FIXED_VERIFIED` | Found by the integrator; `reachable=true, err=nil` at baseline, refused now. §L. |
| `route::TestConfiguredRateShapesTheRealTCPCopyPath` naming | `SAFE_WITH_SCOPE` | Renamed to what it measures; no band, no assertion, no socket added. §E. |
| `common/sniff`, `protocol/group`, `common/power` instruments | `FIXED_VERIFIED` | Three tests that could not fail now fail on the mutation they name, each with a calibrating control. §H. |
| This round's own evidence under `-race -count=3` | `FIXED_VERIFIED` | Nine defects that only the order's gate could see, seven of them in the round's own instruments — two probes that could not survive repetition, one measuring a predicate that was gone, one confounded by a machine-wide port table, one data race inside an adversary's own probe, and two sensitivity controls other tests' goroutines could cancel. The last was caught by the FINAL scan, after the gate was already green. §L.3, §L.3b, §L.3c. |
| The HTTP/3 verdict guard | `FIXED_VERIFIED` | Found by the fresh adversary: the claim was atomic but its effect was a separate read-modify-write, so a stale outcome still won — 1896 and 1758 times in 200000. Now one transaction, with a reverse-break against the integrator's own diff. §H.5. |
| The wireguard release witness | `FIXED_VERIFIED` with a stated limit | `census 0` does not imply "no socket" during a reopen. The helper now checks the precondition it was silently assuming; what a precondition cannot cover is recorded in it. §H.5. |
| Six pinned product policies (1250, IPv6 underlay, `mtu<1280`, DNS-only, 48 h backoff, >64 KiB buffer) | `PRESERVED_VERIFIED` | Each located by its own artifact and re-run green. §J. |

`RELEASE` is a separate, single verdict in §N; this table is not one.

---

## C. FIP-01 — the historic FakeIP address

### C.1 What the baseline did, measured

`route/route.go` gated the whole FakeIP treatment on membership in the **currently configured** range.
A range move or a removed fakeip server therefore turned a placeholder the Box itself handed out into
an ordinary literal. On a real loopback SOCKS5 stand at the baseline, with `go vet ./e2e/...` exit 0
(`OLD_RED_WAS_COMPILE_ERROR=NO`):

```text
EGRESS-A3   issued=198.18.0.2 oldRange=198.18.0.0/16 newRange=198.20.0.0/16 code=0x00 accepts=0->1 requests={atyp=1 target=198.18.0.2 port=443}
EGRESS-A4   issued=198.18.0.2 fakeipRemoved                     code=0x00 accepts=0->1 requests={atyp=1 target=198.18.0.2 port=443}
EGRESS-A10  http-connect target=198.18.0.2:443                  code=0x00 accepts=0->1 requests={atyp=1 target=198.18.0.2 port=443}
```

The peer is a real listening TCP server that records the CONNECT target **before** dialling, so
`requests=…` is a wire fact and not a log line. After the fix all three read
`code=0x01 accepts=N->N requests=none`.

### C.2 The shape of the fix

Issuance is remembered as an **interval**, not a set of addresses, because `nextAddress` walks a
generation's range in order and wraps only at the end — so a generation costs O(1) memory, the record
is exact, and an address **beyond the cursor stays reachable**. That representation is what makes a
blanket block structurally impossible rather than merely discouraged.

The ledger is owned by whoever owns the *sequence* of Boxes, and is registered once per application
session. It records from exactly two call sites, neither on a construction path:
`Store.Start` records the **retired** generation from the metadata it is about to destroy, and
`Store.Create` records as the walk advances. `daemon.StartedService.CheckConfig` builds a throwaway Box
and never calls `Start`, so a configuration check cannot write.

Two proof sources, both measured:

- **in-process** — an address Box 1 issued is refused by Box 2 built from the same root context (the
  real reload shape: close one Box, build the next);
- **durable** — `Store.Start` records the retired generation before `FakeIPReset()` destroys it, so the
  refusal survives a full restart, **including the case where the new Box has no fakeip server at all**
  and `dnsTransport.FakeIP()` is nil. That is why the ledger is read from the **router's** context and
  not through the DNS transport manager.

### C.3 The compatibility positive, and the reason it is not optional

`198.18.0.0/15` is **live, routed traffic space on the host this round was built on**. Its TUN
interface's resolver answers every query — including one for a name that cannot exist — with an address
inside the default FakeIP range, and those addresses are reachable:

```text
github.com   -> 198.19.0.15      api.github.com -> 198.19.0.17
example.com  -> 198.19.0.55      cloudflare.com -> 198.19.4.148
a-random-nonexistent-xyz-12345.com -> 198.19.4.149
TCP connect 198.19.0.15:443 -> CONNECTED=True
```

A blanket guard over that range would black-hole the machine. This was quoted to the fixer as the
concrete counterexample, and it is the citation behind the second reverse-break: replacing the
proof-based refusal with a union-of-ranges refusal turns the A7 positives RED —
`literal=198.18.0.9 code=0x01 requests=none`, `198.20.0.9 code=0x01`, `198.18.0.2 code=0x01`,
`198.18.4.200 code=0x01`, each with *"must stay reachable … a compatibility regression for every address
that merely LOOKS like a placeholder"*.

Measured reachability after the fix, at the peer, all `code=0x00` with the literal as the CONNECT
target: `198.18.0.9` and `198.20.0.9` inside a range another generation used; `198.18.0.2` with no
fakeip server at all; `198.18.4.200` inside a **retired** range past its record; a currently mapped
address still maps; a custom range still maps.

### C.4 Boundaries — stated, not papered over

1. **There is no true in-process reload of a Box in this tree.** `daemon/started_service.go:251`
   closes the old instance and `daemon/instance.go:85 newInstance` builds a brand-new `box.New`. So
   the order's A3 ("同一可热重载实例") is **not constructible**, and the call chain proving it is in the
   ledger document §2.1. A two-Box stand and a real reload are the same shape — which is why the
   fix could close it at all.
2. **C5 is the COMMON path, not an edge case.** With no ledger in the context — the CLI, `cmd_check`,
   `cmd_tools`, libbox configuration validation, every test harness — nothing is recorded and behaviour
   is unchanged. A fresh machine or a cross-process client gets **"cannot be attributed to this
   instance"**. No interception is claimed there, and none is faked with a range rule. The adversary
   confirmed the nil-ledger path is a safe no-op: every read answers false/zero, every write is
   accepted, no panic.
3. **The 4-in-6 spelling is normalised, but the escape half is not reproducible on a plain SOCKS5
   client.** `sing`'s SOCKS serializer calls `.Unwrap()`, so `::ffff:198.18.0.2` arrived as
   `198.18.0.2` and mapped correctly **before** this round. Normalisation still matters for the other
   consumers: the router now reports `IPVersion=4` for a mapped address where it previously reported 0.
   The entry paths that do **not** unwrap (`redirect.go:66` and the endpoint inbounds) are
   **UNMEASURED** — recorded as unmeasured, not as covered.
4. **Two bounded over-approximations on the durable path, with numbers.** The persisted cursor leads the
   true high-water mark by at most `reservedAddressCount` = **1024**, and the interval starts one
   address below the first address `Create` can hand out. Both are in the safe direction, both are
   documented on the functions that produce them, and a dedicated row keeps an address beyond the
   recorded interval reachable so neither can become a range block.
5. **A range smaller than the 1024-address reservation window can wrap, and the record then covers much
   of the range**, so a literal there IS refused. That is the over-approximation showing through; the
   A7b row prints the recorded intervals rather than tuning a literal until it passes.
6. Not run: TUN/UDP egress. A10 is SOCKS5 + HTTP CONNECT only.

### C.5 Two bugs the fixer's own tests found in the fixer's own fix

Recorded in the commit messages rather than quietly corrected, because both are instructive: an interval
**union** glued a wrapped range's tail and head into an inverted interval containing **nothing** — the
same defect in a new place, repaired by removing the union — and a seed re-derived its interval start
from the range instead of using the cursor it was given, dropping the reservation window.

---

## D. WireGuard — D7-02

### D.1 The defect and the claim that had to change

`RebindStale` observed its lease context once at entry. Measured with the rebind held inside a real
socket open and the generation advanced underneath it, the unfixed code returned **success** for a
reopen performed for a generation that no longer existed — so a caller records a superseded generation
as healthy. At baseline, `go vet` exit 0, `OLD_RED_WAS_COMPILE_ERROR=NO`:

```text
--- FAIL: TestSupersededRebindDoesNotClaimTheNewGeneration
    the reopen was reported as a recovery for a generation that had been superseded while it ran:
    got <nil>; a caller recording that would be treating an old result as current-generation health
--- FAIL: TestRevokedWakeRebindDoesNotClaimTheNewGeneration
    a device-wake rebind must not claim a recovery for the generation that superseded it: got <nil>
```

A **first** RED test passed on the unfixed code and was discarded: revoking *before* `RebindStale` is
caught by the entry guard that always existed. The revocation has to land **inside** the socket open,
which is why the fixture fires a probe from the listener control.

### D.2 What is fixed, and what is provably not fixable here

The fix attacks **result publication**, which is the half this layer owns. `errRevokedRebind` plus
`revokedRebindError{Unwrap() []error}` keeps two facts true at once — `errors.Is(err, errRevokedRebind)`
withholds the claim, while `errors.Is(err, context.Canceled)` keeps a *correct* reopen out of the
warning path — because wrapping either inside the other loses the other.

**Interruption is `BLOCKED_DEPENDENCY`, and it is proven rather than asserted.** The socket reopens
inside `BindUpdate` → `StdNetBind.Open` → `net.ListenConfig.Control`, whose signature is
`func(network, address string, conn syscall.RawConn) error`; `wireguard-go`'s `conn.listenNet` reaches
it from `ListenPacket(context.Background(), …)`. A reflection assertion on the stdlib types pins the
signature, and a test shows a **already-cancelled** context still runs the hook. So the honest bound is:
this layer can refuse to **start** a reopen and refuse to **claim** one; it cannot **interrupt** one.

The previous round was corrected for claiming a `ctx.Err()` re-check implemented atomic cancellation and
for calling a bounded release a "30 second hard bound". Neither claim is made here, and the abort guard
is documented as *the update to the segment the entry guard already covered*, not as a lease-identity
check.

### D.3 The four properties, measured separately

- **Result ownership** — the claim is withheld; reverse-break reduces `rebindOutcome` to `return
  rebindErr`, keeping both abort guards, and 5 tests go RED by assertion. That is the sharpest form of
  the break, because the "no reopen after cancellation" half still looks correct.
- **Resource uniqueness** — `BindUpdate` closes the old bind and waits `netc.stopping.Wait()` for its
  receive goroutines *before* opening the new one, so at most one socket exists at any instant. The
  census (`(*Device).RoutineReceiveIncoming` frames) reads exactly 2 quiescent, **0 while the reopen is
  in flight**, and 2 after — and the OS port table shows every abandoned port free after 20 consecutive
  rebinds.
- **Lifetime** — `Close` does not return while the socket operation is held and does return after
  release. This is a *conditional* claim, deliberately: it is not a hard timeout.
- **Cancellation scope** — exactly two points where this layer still has a choice, plus the claim check.

### D.4 Instrument, and one review the integrator reversed

The census is a package-frame count scoped by the **receiver address parsed off the frame** — a first
attempt scoped by `EndpointOptions.Tag` read 0 for 60 live workers, because the stack printer renders a
struct-field string as a pointer. Sensitivity is `0 → 60 → 0`, exact, under `-race`, and a census taken
from inside a `require.Eventually` closure reads the same number (no self-count).

The fixer's first version added a production `workerEntry` field purely so the census had something to
park on. The integrator blocked it: `rebindHook` already runs **synchronously on the recovery
goroutine**, so a test blocking there parks a worker whose stack names `(*Endpoint).recoveryLoop`
anyway. The field was deleted — **−11 lines of production surface, zero new seams** — and the
sensitivity control was rebuilt through the existing hook. Two production coalescing rules had to be
honoured to reach 60 residents, and a worker that loses the race is *replaced* rather than counted,
which is what makes the count exact under `-race`.

### D.5 Out of scope, with evidence rather than silence

`Registration.Acknowledge()` and `Stale()` have **no production caller** anywhere in the tree — so a
transport that rebuilds is never recorded as current by the coordinator, and `Stale()` has no production
reader. This is a coordinator-integration gap, not D7-02; it is reported in §M as a bounded finding with
the grep that establishes it, and was not changed unilaterally.

---

## E. Network / HTTP-3 / MASQUE — RNET-03

### E.1 The manager model is not the connection layer, and the difference was respected

The existing `route/interface_churn_cost_test.go` result (25 transitions, bounded and reversible) uses a
counting router and stand-in managers. This round built the layer above it: a **real loopback HTTP/3
stand** whose handshake is verified from the **server's own** `*quic.Conn.ConnectionState()` —
`NegotiatedProtocol == "h3"`, `request.Proto == "HTTP/3.0"`, a real QUIC version, datagrams negotiated,
SNI `example.test`, and a payload that round-tripped over the CONNECT-3 stream. Not a 200 OK.

### E.2 Two product defects, both fixed and both reverse-broken

1. **The HTTP/3 fallback verdict was decided by ARRIVAL order, not ATTEMPT order.**
   `openConnectStream` releases the connection lock after `acquire`, so the stream open, the SETTINGS
   wait and the response read all happen outside it; an attempt that started first can report last, and
   a stale failure armed the verdict on top of a newer success (and a stale success cleared a newer
   failure). Symptom: for the backoff window — 5 s, doubling to a 5-minute ceiling — every dial skips
   H3 and uses H2/H1, a **silent protocol downgrade with no error**, and the escalation step is charged
   so the next genuine failure is remembered up to 2× longer. Fixed by stamping each attempt before it
   is made and recording an outcome only if no newer one exists (a CAS loop — this is the dial path, not
   a place for a mutex); `ResetConnections` supersedes everything in flight.
2. **`Client.Close()` had no closed state**, so a dial racing teardown performed a whole QUIC handshake
   and installed a connection on an already-closed `http3.Transport` that nothing then owned. Reported
   honestly as **HARDENED, NOT OBSERVED IN PRODUCTION**: `Scope.Close` cancels the box context before
   its cleanups, and no path was found where a dial holding a live context is issued after
   `Client.Close()`.

### E.3 Wiring, not a method the product might not call

`NetworkManager.resetNetworkLocked` → `adapter.InterfaceUpdateListener.InterfaceUpdated` →
`protocol/http.Outbound.InterfaceUpdated` → `Client.ResetConnections()`. The last link is now closed on
real sockets by a new test: the outbound dials over H3, a second dial **reuses** the connection
(control), `InterfaceUpdated` runs, and the egress must then accept a **second** handshake. Not
covered: `protocol/masque.ClientEndpoint.InterfaceUpdated → RestartSession`, which is MASQUE's own
restart path.

### E.4 The matrix, row by row

| Row | Verdict | What was observed |
|---|---|---|
| Normal H3, stable network | `VERIFIED_WITH_SCOPE` | ALPN `h3`, proto `HTTP/3.0`, QUIC v1, SNI `example.test`, datagrams true, 1 accepted connection, 1 tunnel served, payload round-tripped, 1 connection + 1 raw socket held, **0 fallback dials**; 8 sequential tunnels reuse ONE QUIC connection |
| Normal H2, stable network | `SAFE_WITH_SCOPE` | package suite green; no dedicated H2 stand was built |
| Default fingerprint / ChromeParrot | `VERIFIED_UNTOUCHED` | no diff on those paths; MTU and ChromeParrot tests green |
| H3 caller cancel vs genuine failure | `VERIFIED_WITH_SCOPE` | both halves on real sockets: cancel mid-handshake leaves the verdict unarmed, 0 live connections, and the blackhole's byte counter > 0 (the Initial really went out); a genuine failure is remembered once, suppresses the next attempt (proven by socket count), expires on the production clock, then recovers with a real ALPN h3 handshake |
| Same generation, success interleaved with an old failure | `FAILED_PRODUCT_FIXED` | defect 1 above |
| A→B→A ×25 + bursts + Close | `VERIFIED_WITH_SCOPE` | **26 handshakes, every one ALPN h3**, 26 tunnels each attributed to the environment current at the time, ends holding 1 connection + 1 raw socket, 0 fallback dials, package census back to baseline; a 24-transition burst lands on the FINAL environment; Close is idempotent and a later dial fails instead of hanging |
| DNS-only change is not a network transition | `VERIFIED_WITH_SCOPE` | existing route artifact, re-run green |
| DNS generation split between A and AAAA | `VERIFIED_WITH_SCOPE` — **corrected from `NOT_RUN`** | The row is covered, by an artifact Agent C did not own and therefore did not find: `dns/cross_generation_family_test.go::TestLookupFamiliesDoesNotMixGenerations` holds the IPv6 family genuinely in flight behind a real barrier, lands a real `router.ResetNetwork()` **between** the two halves, and then asserts (a) each published family result carries only its own family, (b) both families answered on opposite sides of the reset, and (c) the AAAA answer that **spanned** the reset is not served from cache on the next lookup — checked through the production `Lookup` path by counting upstream queries rather than by a hand-built cache key, which the test's own comment explains is the only way that assertion means anything. Strengthened by `dns/family_no_merge_test.go` and `dns/complete_lookup_generation_test.go`. This is why "not in my worktree" and "not run" are different statements, and the matrix now says which one it was. |
| Fail-closed DNS ownership on/off | `VERIFIED_WITH_SCOPE` | existing artifacts re-run: ON sends the address, OFF sends the name, and on failure the real peer's recording is **EMPTY** |
| FakeIP stale-range movement | `VERIFIED_WITH_SCOPE` | covered by Agent A's dedicated e2e rows (§C); 17 rows, including the retired-generation refusal and the beyond-the-cursor positive |
| MASQUE outer initial 1250 vs the 1232 ceiling | `VERIFIED_WITH_SCOPE` | existing artifacts re-run green; nothing MTU-shaped was changed |
| Real CONNECT / SOCKS / UDP | `VERIFIED_WITH_SCOPE` | package suites green plus the new wiring test; the shared `Client` gains only the verdict ordering and the closed flag |
| Real iOS radio / roam / WARP | `NOT_RUN_EXTERNAL_DEVICE` | the stand's environment source is a decision source and says so in its own header; **no claim above rests on it** |

### E.5 What the stand does NOT record, stated rather than implied

§10.1 asks the stand to record, per egress, *where DNS was asked*, which egress carried the connection,
ALPN/transport, and close counts. Measured against that list:

| Asked for | In the stand |
|---|---|
| which egress carried the connection | **yes** — each environment's egress attributes the tunnels it served, and the 25-transition churn asserts each cycle's tunnel lands on the environment that was current |
| ALPN / transport | **yes** — read from the server's own `*quic.Conn.ConnectionState()`, not from a status code |
| close counts | **yes** — per-egress accepted/closed, plus `TestH3StandCensusDetectsDeliberatelyLeakedConnections` |
| actual socket count / worker census | **yes** — client and egress censuses, with the package-frame scoping stated in §E.4's instrument note |
| URLTest / H3 backoff verdict count, H2↔H3 fallback count | **yes** — `client_h3_backoff_memory_test.go` and the stand's fallback-dial counter |
| **where DNS was asked** | **NO.** The stand does not instrument the DNS layer. Every DNS-position claim in this report comes from the existing `dns/` artefacts instead (`dns/router.go`'s transport selection, the ownership fail-closed rows, the A/AAAA generation-split row), not from this stand. |

That last row is a real hole in the *stand* and it is recorded as one. It does not leave a matrix row
uncovered — the DNS rows are covered elsewhere and are marked as such — but "the H3 stand records where
DNS was asked" would have been a claim I could not support.

Why 26 handshakes for 25 transitions: the first tunnel makes handshake #1, and each transition retires
the live connection so the next dial **must** re-handshake. The transitions are sequential, so no two
connections coexist, and one connection plus one raw socket are held afterwards.

**One row is honest about the opposite direction**: `TestH3StandResetSupersedesAnInFlightAttempt` is
**not** baseline-red — at the base the outcome is a race between the marking goroutine and the reset
goroutine. Its value is determinism, and it says so in the test. The discriminating REDs for defect 1
are the three unit tests and the stand's stale-success test.

**Naming accuracy.** `route::TestConfiguredRateShapesTheRealTCPCopyPath` was renamed to
`TestConfiguredRatePacesTheUserspaceTCPCopyLoop` and its sibling corrected too. The harness is
`net.Pipe()`, `route` splice runs before the copy loop, and `uploadStreamGate` returns `nil, nil` for a
syscall-capable pair — which `route/conn.go` already states as this round's scope. **No band, no
assertion and no socket was added**, and no TCP path was introduced to make the old name true.
`docs/fork/v016-handoff-310af9e69.md` still cites the old name twice; left as history.

---

## F. STATUS-04 — the read-only status view in the Box lifecycle

### F.1 The gap was measured, not asserted

Round 1 of the adversary established it as a fact rather than a suspicion: **every** call site of
`NewStatusView()`/`SnapshotStatus` was in a `_test.go` file or in `status.go` itself, and the only
non-test `.Disconnect()` hits were a *different* type in `experimental/boxdd`. The model had no
production owner at all, for two independent reasons: `physicalpath.NewResolver` had exactly one
construction site in the tree — a transient local inside the start-time dry run — and `close()` had no
linearisation point at which to detach a view.

### F.2 What landed

`box.go` **+226/−0, purely additive**: one `StatusView` and one `Resolver` built in `New` through a
named `newStatusSurface(outboundManager.Outbound)`; `s.statusView.Disconnect()` as the **first**
statement of `close()`, inside `closeOnce`, before the pause callback, the governor and `scope.Close()`;
and exactly **one** new public method, `func (s *Box) Status(root, network string) physicalpath.PathStatus`.

Design decisions that are contracts, not preferences:

- **The view is not handed out.** A `*StatusView` carries the only mutator in this surface
  (`Disconnect`), so returning it would hand a caller a capability to detach the Box's own diagnostic.
  Returning values makes that unrepresentable instead of documented.
- **The snapshot is EMPTY, not pinned.** A `Selections` entry *replaces* the live answer, so any pin is
  a claim; filling it from declared defaults or a cachefile preference is exactly "a preference
  presented as the route the traffic takes".
- **Committed is true exactly for `SelectionCommitted`.** `group.Selector.SelectionStatus()` had zero
  production callers at baseline; the Box is now its real consumer, and a configured default and a
  historical preference are named as preferences with the decision field left empty.
- **No lock across a reporter**, no goroutine, no timer, no context registration.

### F.3 Verification

`RED` was taken with an **overlay** substituting the baseline `box.go`, so the probe compiles on both
trees and fails at **runtime**, not by compile error (`OLD_RED_WAS_COMPILE_ERROR=NO`). Four
reverse-breaks, each compiled first and each RED by assertion:

1. delete the `Disconnect` wiring → 5 tests RED, including the scope-cleanup witness observing
   `Connected()==true` during teardown;
2. restore `walk sync.Mutex` → the reentrant-reporter test RED after 10 s;
3. at the real consumer site, treat a configured default as committed → RED **through the real config
   loader**;
4. delete `New`'s wiring entirely → the whole config-driven surface RED.

`-race -count=3` on the root package green; ABI identical: `go doc -all ./experimental/libbox` filtered
to `^func |^type ` yields exactly **383** symbols, the historical baseline.

### F.4 Two adversary findings, one acted on and one corrected

- **Acted on**: an independent adversary deleted `New`'s wiring (`go vet .` exit 0) and measured which
  assertions stayed green. Six did — including the "committed only when committed" test and the
  straddling test — because a nil view answers `absentStatus`/`disconnectedStatus`, so **every negative
  assertion is satisfied vacuously**. Its sharpest sub-finding was right in substance: the straddling
  rule's test could not distinguish "the read was discarded" from "there was no view".
  `TestStatusConcurrentWithClosePublishesNoHalfClosedPath` now **asserts its own premise**
  (`instance.statusView.Connected()` before the concurrent phase), and the file records the scope.
- **Corrected**: the adversary's conclusion that the straddling claim was therefore "proven by nothing"
  was too strong. Six of the same assertions **do** catch the wiring removal, so `New`'s wiring cannot
  be deleted silently; what is true is that the *fixture-driven* tree cannot see `New` by construction.
  That is a statement about the evidence map, not a false green — and it is recorded that way.
- **Closed, genuinely new**: `PathStatus.Failure` — a `*HopFailure` whose `Reached`/`Unreached` are
  slices — was **uncovered at the Box level**, because no fixture in either file implemented
  `HopErrorReporter`, so no test had ever produced a non-nil `Failure`. A new test drives a three-hop
  chain with the middle hop failing (so both slices are non-empty), clobbers every reachable field
  including in-place slice writes, and re-reads. Reverse-break: caching the `*HopFailure` makes it RED.

---

## G. Seven-layer debug

The order's D1–D7 codes are fault-tree levels, not files. What this round actually exercised:

| Level | This round |
|---|---|
| **D1** config → object init → error paths and credential leakage | `common/tls` / `tlsspoof` / `windivert` attribution (§I); `go vet ./...` findings recorded, not silenced; redaction coverage re-read at both the `physicalpath` and Box levels |
| **D2** start / pre-check → PhysicalPath, Selector, group, UoT → false allow/deny | `ValidateRoots` truncated-route false READY found and fixed (§L); `protocol/group` single-flight instrument rebuilt (§H) |
| **D3** wire, two hops → destination DNS ownership / FakeIP / L0 → real misdial | FIP-01 at the real SOCKS5 and HTTP CONNECT peers, with the peer's recording as the assertion (§C) |
| **D4** DNS / Route / FakeIP → historic issuance, generation, reverse mapping, cache landing | the issuance ledger, both proof sources, the retired-generation row, and the reverse-mapping mutation observed by three e2e detectors |
| **D5** H3 / H2 / QUIC / HTTP / URLTest → fallback, backoff, half-close, error racing | real loopback H3 stand; verdict ordering fixed; cancel vs genuine failure separated (§E) |
| **D6** MTU / fragment → IPv4/IPv6, QUIC outer/inner, nested clamp | policy preserved and re-run (§J); the outer-initial-vs-inner-MTU conflation stays pinned where it was |
| **D7** runtime / power / rebind → Close, pause/wake, 25+ transitions, leaks | WG rebind result ownership (§D); 25 real H3 transitions with a real connection census (§E); `common/power` coalesced-notification staleness test made falsifiable (§H) |

Each level has a legal positive, an invalid negative, a lifecycle interleave and a mutation that is RED
by assertion, spread across the sections above. What is **not** covered is named there too — most
importantly the real-device rows (`NOT_RUN_EXTERNAL_DEVICE`) and the DNS A/AAAA generation split.

---

## H. The independent adversary

Three rounds, and the adversary wrote none of the code it attacked. Its value was not agreement.

### H.1 What it confirmed, by falsifying the alternatives

| Claim under attack | Verdict | How |
|---|---|---|
| the FakeIP `domain_resolver` wire detector | `CLAIM_SUPPORTED` | deleting `dns/router.go:1935-1939` compiles and puts `198.18.0.2:443` back on the real peer |
| the dialer double-failure detector | `CLAIM_SUPPORTED` | restoring the pre-fix race condition compiles and reproduces `30.0003129s is not less than 5s` |
| the churn census's `-1` correction was hiding a leak | **refuted by its own measurement** | baseline 1 outside a closure vs 1 inside; the instrument moves for exactly one injected worker |
| the ledger is not silently inert | `CLAIM_SUPPORTED` | walked all **six** context hops `newInstance` performs; the existing registration test pinned one |
| the compatibility positive survives falsification | `CLAIM_SUPPORTED` | interval is exactly `198.18.0.1..198.18.0.5`; beyond-cursor and unrelated literals reachable in both current and retired ranges |
| the reverse-mapping block is observed | **DECIDED** (round 1 left it open) | disabling it makes three e2e tests RED **with wire-level messages** |
| §10.10's group gate is structural, not a timing gate | `CLAIM_SUPPORTED` | the pre-fix mutation is RED by assertion, and the gate blocks *before* any verdict is returned |

### H.2 What it found, and what was done

Two **false greens** and one mis-scoped instrument were confirmed by mutation with `go vet` exit 0
first, and all three are now fixed with the adversary's own calibration kept:

1. **`protocol/group` — the single-flight test counted rounds, not goroutines.** Deleting the guard left
   both tests that name it GREEN, because a second downstream guard collapses the rounds. The test now
   counts the goroutines actually executing `(*URLTestGroup).drainHealthRechecks` in a **deterministic
   window** (every requester returned, the blocking probe not yet released). Reverse-break:
   `"101" is not less than or equal to "2"`.
2. **`common/power` — the coalesced-notification test asserted nothing.** Its drain loop had no
   assertion in it, and the property in its name was unfalsifiable both before and after the
   `DeepIdleAfter` widening. It now drains to quiet and asserts the last delivered state is not one the
   governor has left. Reverse-break: RED with *"a coalesced notification reported a state that is OVER"*.
3. **`common/sniff` — the leak allowance was never calibrated.** `before` is read on the test goroutine
   while the predicate runs on testify's, so `> before+4` was really an allowance of **3**; a fixed leak
   of one, two or three goroutines was invisible and only four was caught. Now exact, with a control
   proving the census moves by exactly one, and a one-goroutine leak in `PeekStream` makes **both**
   lifecycle tests RED.

It also found the census predicate matching the `route/rule` subpackage (fixed with a frame boundary
plus a scope test and a sensitivity control), a stale citation to a file that never existed, and an
e2e HTTP-CONNECT reply-code assertion that is environment-dependent rather than discriminating.

### H.3 What it got wrong, recorded because the error mode is the lesson

It reported `interfaceTransitionHarness.holdResetLock` as dead code and concluded a documented
measurement was not reproducible. **It is live** — `route/android_handover_generation_test.go` uses it
at `:39→:51→:62→:66→:67` and again at `:78→:87`. The adversary withdrew the finding and named the error
mode exactly: *the hit was in its own grep output and it bound it to the wrong symbol without opening
the file*. That is recorded as this round's instrument lesson, because a repo-wide search that misses a
hit is the one error class that can turn a supported claim into a false accusation. It also
transcribed a commit SHA with the right first nine hex digits and the wrong tail, which the integrator
had to resolve against the object store; both are noted so neither is repeated.

### H.4 The adversary's later rounds, including two retractions of its own work

The order requires a second adversarial round **on the final HEAD** (§15) and a mandatory closure loop in
which every fix made from the adversary's findings is re-tested by the adversary (§15.1). Both were run.
The results matter as much for what they corrected as for what they found.

**Re-tested fixes, all `FIX_CONFIRMED`:** the group single-flight census (mutation re-applied, `5/5` RED),
the power coalesced-notification assertion (`5/5` RED on the stale-notification mutation, and the
adversary confirmed the assertion *does* distinguish a legitimate stale-then-current ordering from an
uncorrected one), the route census-scope predicate (it verified the replacement is strictly stronger
than the test it caused to be deleted), and the two `-count` repairs.

**`FIX_WEAKER_THAN_CLAIMED`, twice, both against the integrator's own work and both now closed:** the
sniff `-1` margin (item 5 in §L.3b) and the two-half predicate's blind lifetime (item 5 again). The
adversary also declined to claim a clean result in the direction it could not measure — "a transient
outliving the primary under load I mark reasoned, not measured" — which is the right call and is
recorded as such rather than as a pass.

**The ledger's bounds (D4), measured, one finding acted on:**
- the **1024-generation cap evicts silently** — closed by exporting the ceiling (§L.3b item 6);
- the **reservation is exactly 1024 addresses**, bounded by the persisted cursor and not widening with
  it, with the address one past the cursor reachable (the compatibility positive holds);
- the **wrap path cannot produce a blanket block** — a generation contributes at most two intervals, the
  union is deliberately not taken, and an inverted interval's near-miss is recorded. The FAIL condition
  the integrator named (a wrapped head-to-tail span) is unreachable by construction;
- one residual noted, not a defect: the 1024 bound lives in the store's reservation, not in the ledger,
  so a hand-edited or corrupt cachefile cursor could widen the refused set to whatever it names.

**Two retractions, both the adversary's own, and both the same error class.** It withdrew its round-1
claim that `holdResetLock` was dead code. In round 5 it **retracted its round-3 finding [21]** as well:
it had claimed the straddling test "passes vacuously with a nil view", but `statusTestBox` builds its
instance with `newStatusSurface` directly, so those tests drive a real live view and are *immune to the
wiring mutation by construction* rather than vacuous. Its own words: *"I inferred a fixture's shape from
a mutation result instead of reading how it built the instance — the same error class I named in round 2,
for the second time."* Only two tests in `box_status_test.go` are genuinely vacuous under that mutation,
and that was already recorded.

Both retractions are kept in this report rather than quietly dropped, because a mutation result is not
evidence about a fixture until the fixture has been read — that is this round's instrument lesson, and
it was learned twice.

**What the adversary reached, and what it did not.** Its final pass explicitly reported FOUR areas
unreached — D2's false-DENY direction, D5's H3 attempt-sequence guard, the wireguard release witness, and
the WG/H3 reverse questions — and said so before writing its conclusions rather than padding them. Those
four were handed to a **fresh, independent adversary** (`G`), which reached all four — see §H.5. Its own
unreached items are recorded there too, as unanswered rather than passed.

### H.5 The fresh adversary (G), and the three defects in the integrator's own work it found

F's final pass reported four areas it had not reached and said so before writing its conclusions. Those
four went to a **new, independent adversary** with no involvement in any of this code. It reached all
four and found three defects, **all of them in work the integrator had already reviewed and shipped**.

**D5 — the HTTP/3 guard ordered the claims, not the effects. Product defect, fixed.**
`claimHTTP3Outcome` is a correct monotone max-CAS, and G confirmed it is immune to the false-negative
direction (an attempt merely issued and never reporting cannot suppress an older outcome; its mutation
M1 proved the comparison is load-bearing). But every caller then mutated the verdict in a **separate**
read-modify-write, so both attempts pass the claim and the effects land in either order. Measured over
200000 iterations: an old failure armed the verdict after a newer success cleared it **1896** times, and
re-armed it after a real `ResetConnections` — the A→B→A case the guard exists for — **1758** times. The
earlier fix had removed the deterministic version of the bug and left a racy one. Fixed by making the
claim and its effect one transaction; G's witness now reads `0/0/0`, and removing exactly those locks
reproduces `case1=782 case3=762` of 100000 — a reverse-break against the integrator's own diff rather
than against G's tree.

**Item 7 — the release witness could not establish its own precondition. Fixed.**
`socketCensus == 0` does **not** imply "no socket": `bind.Open` binds udp4 and then udp6 before
assigning the bind, and the receive goroutines start only after `Open` returns. G pinned that state
deterministically by arming the fixture's gate from inside the udp4 entry — `port=60108 census=0
port_occupied=true` — where the census half passes for a device that holds a socket and the port half
excuses the occupied port with the same number, so the two halves the file treats as independent are
blind together. The assertions were sound at their call sites only because the tests call
`onPauseUpdated` synchronously and nothing reopens, which was true, unstated and unchecked. Now checked,
with a reverse-break: with the precondition the helper refuses in that state; removing it makes the
same call pass.

**D2's residual — a truncated route could hide behind a sibling. Fixed.**
The truncation check ran *after* an "if any node has Exit, this route is fine" early return, so
`L.detour = G` with `G -> [m1 complete, m2 (detour=ghost)]` reported `reachable=true failures=0`. Since
`Report.Reachable` is documented as the stronger question, that was a false READY from the exported API
rather than a caller's lint problem. The check is now per-node and runs before any question about exits.
G's verdict table had that case recorded as accepted — it had pinned the residual as current behaviour —
and the row is updated with its history in place rather than deleted.

**What G got right that is worth recording.** It decided D2 by a **two-tree differential**: the same
assertions run against the tree and against an `-overlay` that substitutes the pre-change `dryrun.go`,
with the author's own test as the positive control. That is the only method that can answer "is a legal
configuration newly refused", and it is why its PASS is worth more than an argument. It also declined to
claim what it could not measure — the mirror direction of the D5 race (0 in 200000, *"not observed,
reported as unproven rather than denied"*) and an escaped wireguard leak (*"not demonstrable"*) — rather
than letting a clean sample stand in for a proof.

**Still not reached, and stated as such:** an independent route/DNS-cache leak instrument for A→B→A and
DNS-only changes (the cache/worker half was reached only through the author's own tests), and a
wireguard bind path that spawns no receiver. Neither is a pass.

### H.6 The two confirmations that matter most for the two riskiest claims


- **The ledger is reachable.** A fix that silently does nothing while every unit test passes is the
  worst outcome available, and the six-hop walk is what rules it out — with a control showing a lookup
  *can* return nil, so the walk is not vacuous.
- **The compatibility positive is real.** A blanket block is the obvious way to make FIP-01 green and
  would have broken the machine this round was built on; the reachability rows are the guard against it.

---

## I. Full test coverage, result and SHA

```text
SCAN_SHA            = 666470cbe70e734240bd51d547e00b4b950eb8b1   (the last CODE commit)
FINAL_CODE_SHA      = 666470cbe70e734240bd51d547e00b4b950eb8b1
FULL_TEST_SHA_MATCH = IDENTICAL_CODE_TREE_DOCUMENT_ONLY_TIP

                      The pushed tip is this report's own docs-only commit, above the scanned SHA.
                      `git diff --stat 666470cbe..HEAD -- . ':(exclude)docs/fork'` is EMPTY — no test
                      file and no production file is added by it — so the tree the scan covered and the
                      tree that ships are the same code tree. A document cannot cite its own commit SHA
                      without changing it, which is exactly why this field has a third value.

COMMAND             = go test -count=1 -tags "$TAGS" -json -timeout 3600s ./...
                      run via `cmd /c "... > final_full_scan4.jsonl 2> final_full_scan4.err"` with
                      $LASTEXITCODE read on the immediately following statement, so the exit code is
                      go's and not a pipeline's
GO_EXIT             = 1
RAW LOG             = docs/fork/v016-nextstage-final-scan.jsonl   (0 bytes on stderr)
                      C:\Deepseek\内核\final_scan_meta3.txt        (SHA + tags + timestamp)
PACKAGES_TOTAL      = 171 reporting packages
PACKAGES_WITH_TESTS = 84   (81 ok + 3 FAIL)
DISTINCT_TESTS      = 7071
BUILD_FAILURES      = 0
LAST EVENT          = package pass  ->  REACHED_MODULE_END

FULL_TEST_COVERAGE  = REACHED_MODULE_END
FULL_TEST_RESULT    = COMPLETED_WITH_FAILURES
```

The scan was re-run **three times** as the round closed, each time after a change that could have moved
it, and the last one is the one recorded above. Each re-run found something the previous one had not:
the second found a defect in two of the round's own instruments (§L.3b), and the third found a fifth
instrument defect that only appears when the whole package runs together (§L.3c). **The failing set is
byte-identical to the historical one in all three**: the same 11 names in the same 3 packages, and no
package regressed at any point.

### I.1 The failing set is exactly the historical one — no new failure

```text
common/tls         (3)  TestWindowsClientHandshakeTLS13
                        TestWindowsClientRoundtripTLS13
                        TestWindowsClientTLS13PostHandshakeConcurrentWrite
common/tlsspoof    (3)  TestIntegrationConnInjectsThenForwardsRealCH
                        TestIntegrationSpooferInjectThenWrite
                        TestIntegrationSpooferOpenClose
common/windivert   (5)  TestIntegrationCloseTwice
                        TestIntegrationConcurrentOpen
                        TestIntegrationOpenSendOnly
                        TestIntegrationRecvAbortsOnClose
                        TestIntegrationTamperedCacheRepaired
TOTAL              = 11
```

Those 11 names are **byte-identical to the historical set**, in the same three packages, and every one
is attributed in §I.4 — three `BLOCKED_ENV`, eight `BLOCKED_EXTERNAL`. `common/trafficsched`, whose
intermittent failure is analysed in §I.6, **passed** in this scan, which is consistent with its measured
rate rather than with it having been fixed.

The package count moved from the previous round's 80 ok / 3 FAIL (83 with tests) to **81 ok / 3 FAIL
(84 with tests)**. The one added package is `daemon`, which had **no test files at all** before this
round; it now has two, one of which is the regression test for the context-cloning defect in §A's commit
list.

### I.2 The CI premise in the order is FALSE, and the correction matters

The order says a Harness without `gh`/API access may only say `REMOTE_ACTIONS_NOT_QUERYABLE`. **This box
has unauthenticated API access** — the repository is public — so the honest value is
`CI_REMOTE = OBSERVED`, not "not queryable". Measured read-only, with nothing triggered:

- the repository has **910** recorded workflow runs;
- the live YAML at HEAD has exactly **two** workflows with any `push` trigger: `verify.yml`
  (`push: branches: [testing]`, `pull_request`, `workflow_dispatch`) and `android-core-arm64.yml`
  (`push: branches: [testing]` **plus a path filter**, `workflow_dispatch`). The other **seven** are
  `workflow_dispatch`-only;
- no tag, release, schedule, `workflow_run`, `repository_dispatch`, `pull_request_target`, `create`,
  `deployment` or `merge_group` trigger exists anywhere;
- the empirical split: **85 commits whose subject contains `[skip ci]` produced 0 runs; 315 ordinary
  commits produced 51 runs.** So `[skip ci]` does suppress the two push workflows — and it is
  **irrelevant to the other seven**, which only a human dispatch can start.

Nothing was dispatched, re-run or triggered, and no remote branch, tag, Release or PR was created. The
integrator's push used the ordinary fast-forward form only, and every one of the 25 commits carries the
literal marker.

### I.3 The push itself triggered nothing — measured, not assumed

The query above was re-run **after** the push: runs created on or after 2026-10-10 = **0**, and the
newest run on `testing` is still from `2026-10-08T20:31:45Z`. That is the end-to-end confirmation of the
mechanism, from GitHub's own record rather than from the preflight script's reading of the commit
messages.


### I.4 The three blocked packages, re-attributed

The order's stated root causes were partly wrong, and a historical explanation is not a certificate:

| Package | Tests | Verdict | Measured condition |
|---|---|---|---|
| `common/tls` | 3 | `BLOCKED_ENV` | **The old wording ("returns an unexpected record") is wrong.** With `MinVersion: 1.3` Schannel emits a **malformed record layer** — first record `16 fe fd 00 00`, version `0xfefd`, **length 0**, and no `supported_versions` extension — so *every* conforming peer rejects it. Confirmed three independent ways: `curl.exe` (libcurl with Schannel) prints `schannel: TLS 1.3 not supported on Windows prior to 11`; curl's unpinned handshake against a TLS1.3-only server offered only `[303 302 301]`; and `HKLM\...\SCHANNEL\Protocols\TLS 1.3` does not exist (Win10 19044 LTSC needs an admin opt-in DWORD). `schannel.NewClientContext(TLS12,TLS13)` **succeeds**, so it is not credential acquisition. Remediation needs an **elevated registry write**, outside this session's scope. **The TLS 1.3 requirement was not weakened.** |
| `common/windivert` | 5 | `BLOCKED_EXTERNAL` | `IsAdmin=False`, `BUILTIN\Administrators` is *"Group used for deny only"*, Mandatory Label = Medium; all five fail with `windivert: open SCM: Access is denied.` The other **20** windivert tests PASS. |
| `common/tlsspoof` | 3 | `BLOCKED_EXTERNAL` | same SCM denial through `tls_spoof`; the 6 unix tests are `NOT_RUN` **by build constraint** (`linux || darwin`), which is a different state from blocked. |

### I.5 A real coverage hole, filled

`common/tlsspoof` had **zero unprivileged tests on any platform**, so the package was a single
undifferentiated red. Six tests were added over `buildFakeClientHello`, which is pure and carries real
invariants: empty-SNI refusal; exactly one well-formed handshake record; fits one TCP segment
(**297 bytes** measured against a 1460 limit); no post-quantum hybrid key share while x25519 is still
offered; SNI round-trips and two SNIs differ; ALPN is `h2, http/1.1`. The segment-size assertion is
what makes the file worth having: removing `CurvePreferences` compiles and pushes it to **1521 bytes**.

### I.6 An intermittent failure found, analysed, and deliberately NOT widened

`common/trafficsched::TestAdmittedRateMatchesTheConfiguredRate` failed **1 of 2** full scans (the second
run was 79 PASS / 4 FAIL), then passed 10/10 plain and under `-race`.

The mechanism, worked out from the test's own arithmetic rather than from the number:
`coarseRate > 0.85 × configured` is algebraically `excess < 0.1765 × imposedPeriod` = **5.52 ms**, and
the test's own design comment assumes a pace excess of 1.4–1.5 ms plus one `paceTick` of 1 ms. The host
measured **5.84 ms** — 0.32 ms over, a rate 0.88 % below the bound. That is **Windows timer
granularity under a loaded box**, not a product rate error and not a wrong clock: the measurement is
real and the bound encodes a host assumption.

**No band was widened and no `flaky` label was applied.** The coarse bound is *deliberately* the flat,
independent check that the fine derived bound is excused from, so deriving it too would be exactly the
weakening the order forbids. It is recorded as a **host-bound known flake** with its mechanism and pass
ceiling, the same family as the renamed route scheduler test, and it is called out by name wherever the
final scan reports it.

### I.7 `go vet ./...` is exit 1, pre-existing, and every gate in CI knows it

Three findings, none introduced by this round: `daemon/managed_service.go:75` and
`experimental/libbox/debug.go:11` are **deliberate nil-dereference crash triggers**
(`*(*int)(unsafe.Pointer(uintptr(0))) = 0`) for the debug crash command, and
`experimental/boxdd/authenticode_windows.go:95` is a Win32 syscall pointer pattern. **Every CI vet gate
uses explicit package lists that exclude `daemon` and `experimental`**; `./...` is deliberately not the
gate. The crash triggers were **not** rewritten into a Go nil-deref: that would change a SIGSEGV into a
recoverable panic, which is a behaviour change to a debug facility in exchange for a diagnostic nobody
gates on. The per-package exit codes are what this report states.

---

## J. Cross-platform, ABI and product boundaries

```text
windows/amd64   CGO_ENABLED=1  go build -tags "$TAGS" ./...  EXIT=0
linux/amd64     CGO_ENABLED=0  go build -tags "$TAGS" ./...  EXIT=0   (needs -ldflags=-checklinkname=0,
                                                                       which release/LDFLAGS supplies and
                                                                       every release recipe passes)
linux/arm64     CGO_ENABLED=0  go build -tags "$TAGS" ./...  EXIT=0
darwin/arm64    CGO_ENABLED=0  go build -tags "$TAGS" ./...  EXIT=0
freebsd/amd64   CGO_ENABLED=0  go build -tags "$TAGS" ./...  EXIT=1   (experimental/libbox only)
freebsd/amd64                  go build -tags "$TAGS" ./cmd/sing-box   EXIT=0
```

Two qualifications, both measured, neither a regression:

- **linux/\* and freebsd need `-ldflags=-checklinkname=0`.** Without it linux fails at link in
  `experimental/boxdd` (`invalid reference to runtime/pprof.parseProcSelfMaps`) — a command omission,
  not a product defect, and the flag is what the release recipes pass. `release/LDFLAGS` carries it,
  and this round used that file rather than a remembered flag.
- **FreeBSD `./...` fails only in `experimental/libbox`**, whose six missing symbols are all defined
  under `//go:build darwin || linux || windows`. libbox was never a FreeBSD target; the real FreeBSD
  product builds, and CI's own package list passes on freebsd/amd64.

### J.1 The tag layering is real, and one profile cannot be built here at all

The order says not to assume every tag set is simultaneously available. Measured, per profile:

| Tag file | Built here | What CI uses it for |
|---|---|---|
| `release/DEFAULT_BUILD_TAGS_OTHERS` | **windows/amd64 exit 0, linux/amd64 exit 0, linux/arm64 exit 0, darwin/arm64 exit 0** | `verify.yml`, `server-linux-amd64.yml`, `interop-xray.yml` (which says in its own comment that it wants the WIRE profile, not cronet), and `windows-core-amd64.yml`'s `upstream-baseline` probe |
| `release/DEFAULT_BUILD_TAGS_WINDOWS` (`with_naive_outbound` + `with_purego`) | **windows/amd64 exit 0** | `windows-core-amd64.yml`'s `fork-windows` release profile — i.e. the tag set the shipped Windows product is built with |
| `release/DEFAULT_BUILD_TAGS` (`with_naive_outbound`, the Darwin profile) | **exit 1, and it cannot be built here** | `client-macos.yml`, and two `verify.yml` steps |

The third one fails for an environmental reason and the failure is precise:
`github.com/sagernet/cronet-go/all` → `cronet-go/lib/linux_amd64` (and `lib/darwin_arm64`)
**contain no Go files in this module cache** — those are the prebuilt cronet static libraries, fetched
as CI artifacts, and they are not present on this machine. CI knows this and says so in
`verify.yml`'s own comment: *"DEFAULT_BUILD_TAGS (the Darwin profile) is deliberately NOT used here: it
carries with_naive_outbound, and no Linux product links cronet."* So it is `BLOCKED_EXTERNAL`, not a
regression, and it is the seventh entry in §M.

**libbox ABI: 383 exported symbols, 0 added, 0 removed.** The artifact pair at
`C:\Deepseek\内核\abi_*.txt` was found to be a **same-run snapshot** (byte-identical, written 182 ms
apart) and therefore cannot by itself establish cross-round stability; it is attributed to
`017fac4e9900e9b6c7e84b6aa9b5a822f7841858` with corroboration. This round supplies the missing
cross-SHA leg (`017fac4e → 686c937`), and `box.go`'s new method cannot move the surface because no
libbox source imports the root package. The authoritative in-repo gate is
`scripts/ci/check-libbox-abi.sh`, which needs the client submodules and `gobind` and was **not run**.

**Product boundaries preserved, verified by re-running them, not by assertion:**

- **HY2 / ChromeParrot**: `protocol/hysteria2` green, including
  `TestConfiguredInitialPacketSizeIsDiscardedUnderChromeParrot` — with ChromeParrot on, a configured
  1232 is discarded and the first datagram is **1250**. No default fingerprint or ChromeParrot file was
  touched.
- **MTU**: `common/dialer` green, including the 1232 UDP ceiling for a 1280-byte inner tunnel and
  `TestACeilingIsAConsumerContractNotAWireGuarantee`.
- **DNS-only network change does not reset the whole network**, `NXDOMAIN`, **L0/Direct/UoT**: untouched
  and green in the packages that own them.
- **`go.mod`/`go.sum`: no diff.** No pinned fork was edited; no fingerprint changed; no new dependency.

The order's §0.2 names six pinned policies to PRESERVE. All six were located by their own artifacts and
re-run green, so "preserved" is a measurement rather than an absence of edits:

| Pinned policy | Where it is pinned | Result |
|---|---|---|
| quic-go first packet **1250** under ChromeParrot | `protocol/hysteria2/chrome_parrot_first_datagram_test.go` (+ `common/dialer/path_mtu_test.go` stating the 1250 → 1298-over-IPv6 arithmetic) | green |
| narrow IPv6 **underlay budget** | `protocol/masque/endpoint.go:302` folds `MinimumIPv6TunnelMTU` into `boundedRequired`; asserted in `mtu_budget_test.go` | green |
| **`mtu < 1280` refused for IPv6** | `protocol/masque/mtu_validation_test.go::TestMTUBelowTheIPv6MinimumIsRefusedForIPv6`, with `TestMTUBelowTheIPv6MinimumIsKeptForIPv4Only` as the legitimate-negative control | green |
| **DNS-only network change does not reset** the whole network | `route/dns_only_change_is_not_a_network_transition_test.go`, `dns/dns_environment_generation_test.go` | green |
| **48 h H3 backoff cap** | `transport/http/http3_transport_test.go::TestHTTP3BrokenBackoffCap` | green |
| `sing` fork **>64 KiB buffer** bound | `common/bufio/geometry_test.go` — the pool sizes are `[64, 65536]` or `MaxPooledBufferSize`, and a `BufferSize` outside that set makes every allocation fall out of the pool | green |

**Not run, and not claimed:** real iOS/`NWPathMonitor` radio switching, real Wi-Fi roam, real handover,
WARP over a real path, Apple signing, and any Apple/macOS/Windows client UI. The client repositories
were not touched.

---

## K. Performance and cost

Where a change could plausibly cost something, it was measured with the same input and the same build
tags, and no single-run wobble is presented as a result.

| Change | Measurement |
|---|---|
| HTTP/3 outcome guard (2 atomics per **attempt**, never per packet) | `BenchmarkHTTP3OutcomeClaim` **5.5 ns/op** disabled vs **9.7 ns/op** enabled, 0 B/op, 0 allocs/op, 3 runs each and the ranges do **not** overlap. The end-to-end `BenchmarkHTTP3DialDecision` ranges **do** overlap (469–536 vs 544–590 ns/op), so it cannot resolve two atomic operations and **no cost or improvement is claimed from it**. |
| WG rebind claim-withholder | no allocation added on the rebind path; two extra context observations per rebind |
| FakeIP issuance ledger | one interval per generation measured, cap **1024** generations, publish is a single atomic pointer load on the read path. **Not benchmarked** — the read is one atomic load and one interval scan; no measurement is claimed beyond the interval count. |
| Box status surface | `BenchmarkSnapshotStatus` / `BenchmarkSnapshotStatusParallel` exist in the package and are unchanged by this round; **no before/after figure is claimed** |
| leak censuses | `route` and `wireguard` censuses are O(goroutines) with a 1 MiB stack buffer, taken a bounded number of times per test, never in production code |

No cross-package lock was added, no per-packet logging, and no lock was introduced into any dial or
copy loop by this round.

### K.1 What "high traffic" means for this round's changes, and what covers it

The order's §10.3 asks that concurrent TCP, UDP/UoT, IPv4/IPv6 and Close be covered before a resource
fix is called safe. Stated precisely rather than claimed wholesale:

- **Nothing this round touched is on a per-packet path.** The H3 change is two atomics per connection
  *attempt*; the FakeIP ledger is one atomic pointer load plus an interval scan per connection *match*
  (not per packet); the Box status surface is not on the data path at all and starts no goroutine and
  arms no timer; the WG change adds two context observations per *rebind*.
- **The concurrency coverage that exists** is `common/trafficsched`'s contention suite —
  `TestContentionColdStart`, `TestContentionSteadyState`, `TestContentionHighVersusHigh`,
  `TestNeitherLaneStarvesWhenBothAreBusy`, `TestSchedulerSurvivesConcurrentFlowChurn`,
  `TestClosingAFlowReleasesItAndItsSlot`, `TestPacedSchedulerLeavesNoGoroutineBehind` — plus four
  benchmarks (`BenchmarkCopyLoopTax`, `BenchmarkPacketGateTax`, `BenchmarkStreamWriteTax`,
  `BenchmarkStreamWriteBufferTax`). All green, including under `-count=3` (319 s).
- **What is NOT separately measured here**: a concurrent TCP+UDP/UoT+IPv4+IPv6+Close load test written
  for this round. It was not needed to justify a change that adds no per-packet work, and inventing one
  to tick a box would have been a measurement of the test rather than of the product. Said plainly here
  so the absence is not mistaken for coverage.

---

## L. Regression protection

### L.1 A false READY in an exported API, found and fixed by the integrator

The order flags `ValidateRoots` standing alone against a missing detour. It is a **real defect**, and
`Report.Reachable` documents the *stronger* question — *"an unknown hop does NOT count as reachable"*.
Measured at the baseline with `exit.detour = "ghost"`:

```text
roots=[exit] nodes=[exit(exit pos=0 exit=false)] failures=[] reachable=true err=<nil>
```

The node correctly refuses to claim an exit — the walk reported `routeTruncated` — and the report still
called the route proven usable. `Report.Err()` is what a caller gates a start on, so both answered the
opposite of what they document.

Why the product does not already catch it, and why that is not a defence: `adapter/outbound`'s
start-order lint rejects `dependency[tag] not found for outbound[tag]` **before** it runs the dry run,
so the one shipped caller is protected by the *order of two checks* rather than by this function. The
previous round declined to fix it on the grounds that "adding a hop for the missing tag would
double-report the same defect at the manager level" — a valid objection which this fix does not trigger,
because it adds a **Failure** and not a hop.

The signal is exact rather than a heuristic: `numberRoute` sets `Exit = complete && index ==
len(route)-1`, and `Hops` passes `complete == false` for exactly the truncation case. The hop that
declared the unresolvable tag is named when it can be, read through the same `lookupDependency` the
enumeration used. A root that produced no node at all is deliberately left alone — that belongs to the
group's own `Start`. Reverse-break: the assertion was **RED on unmodified code first**, by assertion and
not by compile error, and a discriminating control keeps the same fixture with the detour resolving
reachable.

### L.2 Every new guard has a mutation that is RED by assertion

| Guard | Mutation | Result |
|---|---|---|
| FIP-01 proof-based refusal | remove the branch | 4 rows RED, synthetic address captured on the wire |
| FIP-01 is not a range block | brute-force the range | the A7 positives go RED (**the load-bearing compatibility break**) |
| FakeIP reverse mapping | disable `route.go`'s store-backed mapping | 3 e2e tests RED with wire messages |
| WG result ownership | `rebindOutcome` → `return rebindErr` | 5 tests RED by assertion |
| daemon service context | `ContextWithDefaultRegistry` → `ExtendContext` | RED: `actual: (*oomkiller.Recorder)(nil)` |
| H3 verdict ordering | guard body → `return true` | 4 RED, control stays green |
| `Client.Close` closed state | drop `closed.Store(true)` | 1 RED |
| Box status wiring | delete `Disconnect` (5 RED) / restore `walk` mutex (1) / default as committed (3, through the **real config loader**) / delete `New`'s wiring (whole surface) | all RED by assertion |
| `PathStatus.Failure` ownership | cache the `*HopFailure` | RED: `expected "middle", actual "clobbered"` |
| group single-flight census | defeat the guard | RED: `101 is not less than or equal to 2` |
| power coalesced notification | deliver the remembered state | RED: *"reported a state that is OVER"* |
| sniff leak census | one leaked goroutine in `PeekStream` | **both** lifecycle tests RED |
| `ValidateRoots` truncation | remove the check | RED at baseline |
| `tlsspoof` ClientHello contract | remove `CurvePreferences` | 2 of 6 RED (`1521 > 1460`) |

Every mutation was reverted and hash-verified; the reverts are visible in the tree
(`git diff` empty on each mutated production file).

### L.3 Four more defects, found only by running the order's own gate verbatim

The round's own full scan is `-count=1`, so it cannot see a test that breaks when repeated, and it runs
one package set at a time, so it cannot see an instrument confounded by other processes. The order's
§16 gate is `-race -count=3` over nine packages **in parallel**, and running exactly that — rather than
an approximation of it — found four defects that nothing else had:

1. **`route/agentf_census_instrument_attack_test.go` could not survive `-count>1`.** Its injected worker
   was held by a **package-level** channel closed by a `defer`. Repetition 1 passed and closed the gate;
   repetition 2's worker exited immediately, the baseline stopped moving, the assertion failed on a
   state the test itself had created, and the deferred close then **panicked** with
   `close of closed channel`, taking the rest of the package's repetitions with it. MEASURED:
   `-count=3` passed once, failed once, panicked; `-count=1` was green. Fixed by creating the gate per
   invocation and releasing it through a `sync.Once`, plus a settled-baseline read so a worker released
   by a previous repetition cannot be counted as this one's.
2. **`common/sniff/agentf_census_slack_attack_test.go` had the same shape, and worse: its
   `agentFLeakGate` was dead state.** Every leak already had its own per-size channel; nothing but the
   `defer` ever touched the package-level one. Dead state that can only panic is deleted, not guarded.
3. **The same file measured a predicate that no longer exists.** It evaluated
   `sniffGoroutines() > before+4` — the slack it had found, which was then repaired. Leaving it would
   have left a probe asserting `require.False(fired)` for leak sizes 1–3 forever while describing
   nothing. It is repointed rather than deleted, because the *method* is what makes it worth keeping,
   and against the live predicate the sweep now reads: leak 1 → **FIRED**, 2 → **FIRED**, 3 → **FIRED**,
   4 → **FIRED**. A four-point sensitivity sweep of the instrument that replaced the blind spot.
4. **`transport/wireguard`'s pause assertion was confounded by a machine-wide resource.**
   `TestPauseWakeCyclesInterleavedWithRebindsKeepOneSocket` failed at cycle 0 with *"a network pause must
   RELEASE the socket"*. The fixtures bind an **ephemeral** port, and the OS port table is
   machine-wide — the parallel gate runs nine test processes at once, so a port the endpoint just
   released can be handed to another process before the probe runs. 55942 is inside the Windows dynamic
   range. What was ruled out, by measurement rather than argument: isolated `-count=1`/`-count=3`/
   `-race -count=1`/`-race -count=3` PASS; whole package `-race -count=3` ×3 PASS; `-race -count=20`
   under sixteen concurrent CPU burners PASS; only the nine-package parallel gate failed.
   **Pinning the port was the obvious fix and is wrong here** — this test's rebind half asserts the port
   *moved*, which is the ephemeral branch releasing through `IpcSet("listen_port=0")`, so a fixed port
   makes a real contract unsatisfiable. The instrument changed instead:
   `closeBindLocked` calls `bind.Close()` and then waits `netc.stopping.Wait()` for the receive
   goroutines **before `Down()` returns**, so the synchronous claim the pause makes is stated exactly by
   the device-owned socket census, which no other process can move. The test now asserts
   `socketCensus == 0` **immediately**, and the port table is kept as corroboration through
   `requirePortReleasedByTheEndpoint`, which fails only when the endpoint holds more than one socket's
   worth of receivers — i.e. exactly when a socket leaked. Reverse-break: withholding `wgDevice.Down()`
   from `onPauseUpdated` compiles and is **RED BY ASSERTION** with `Should be zero, but was 2`, so the
   new witness is at least as strong as the one it replaces.

The order's gate is now green, twice in a row, in full:
`common/physicalpath`, `protocol/group`, `route`, `dns`, `common/dialer`, `transport/wireguard`,
`protocol/wireguard`, `common/httpclient`, `e2e` — all `ok`, exit 0.

### L.3b Four more, found by repeating that gate and by the adversary's re-test

The gate is not a formality: running it repeatedly, and having the adversary re-test the fixes made from
its own findings, produced four more defects. Three of them were **mine**.

5. **`common/sniff` — the two-half predicate had a blind lifetime.** After the adversary showed that
   `require.Never` is non-deterministic (testify starts its condition with a bare `go checkCond()` and
   re-arms the ticker only after a result arrives), the leak assertion became two halves: a calibrated
   `> before+1` and a primary "returns to baseline". The adversary then measured that **neither** sees a
   goroutine that outlives the sniff call and then exits by itself:
   `MEASURED one worker left behind for 400ms: secondary fired=false, primary passed=true`. The
   calibrated half tolerates one transient frame; the primary half is satisfied by the eventual return.
   But "must not leave a goroutine behind" is a statement about the moment the call **returns**, and no
   window tests that. Both lifecycle loops now assert the census **at that moment, per iteration**, read
   on the test goroutine so that no callback correction applies. Reverse-break: a self-terminating leak
   (`time.Sleep(50ms)` then exit) is RED BY ASSERTION at `iteration 0`, where both window halves pass.
6. **`adapter` — the ledger's ceiling was unexported, so its loss was invisible.** MEASURED: once the cap
   is reached the oldest record is dropped and its address answers exactly as one that was never issued
   (`'evicted after the cap' and 'never issued' both answer (invalid IP, false)`). No third *refusal*
   behaviour is available — refusing without proof is the blanket block the contract forbids — but a
   caller could not even compute "saturated" without hardcoding 1024. `MaxIssuanceGenerations` is now
   exported with the measured loss in its doc.
7. **The adversary's own frame-shape probe had a data race.** `TestAgentFFrameShapeNever` captured its
   reading in a plain `var inside int` written on testify's condition goroutine and read on the test
   goroutine — and testify's overlapping ticks mean two condition goroutines can write it. `-race
   -count=3` reported `DATA RACE`. The readings are now atomic. The instrument that found the
   instability found its own author's mistake, which is worth recording as such.
8. **The adversary's group sensitivity control could be cancelled by other tests.** It compared a peak
   against a baseline taken beforehand; inside the full package MEASURED `baseline=4, peak=5`, because
   three goroutines left by earlier tests were alive when the baseline was read and exited while the four
   injected workers were held, so the difference cancelled. It now identifies **its own** workers by a
   named frame and asserts the package predicate is a superset of that count — a direction other tests'
   goroutines can only make larger. Its release assertion needed the same treatment for the same reason,
   and had to be polled from a plain loop rather than from `require.Eventually`, because a reading taken
   inside a testify callback carries that callback's own frame.

**One thing that looked like a defect and is not.** A `-count=3` sweep reported `protocol/masque`
timing out at 600 s. It is not a hang: the package's suite legitimately takes **423.587 s** for a single
run in the full scan, and my sweep's timeout was simply too short. Recorded because "the package is slow"
and "the package hangs" are different facts and only the first is true.

### L.3c The same defect class, one more time — and it was caught by the final scan

The pattern this round kept meeting is an instrument that measures **the process** rather than the thing
it names. Four instances were found by running the gate; the **final full scan caught a fifth**, in the
adversary's own frame-shape controls:

```text
MEASURED shape=require.Never with nothing leaked: before=20 inside=20
"20" is not greater than or equal to "21"
```

Those controls compared a reading taken inside a testify condition against a baseline read on the test
goroutine beforehand. Inside the full package twenty goroutines naming `common/sniff_test` were alive at
the baseline — left by the tests that ran before — and enough exited inside the 60 ms window to cancel
the callback's own frame exactly. **It passed in isolation (`before=1 inside=2`) and failed in the
package.** The assertions are now scoped to the condition closure's own frame, which no other test's
goroutines can enter, and the process-wide difference is reported beside them as an observation rather
than asserted as a proof. `TestAgentFNestedHelperOverCorrects` needed the same treatment in a different
shape: it now takes both readings back to back inside the same callback, so the helper's extra frame is
a difference rather than a comparison against a moving baseline.

The lesson is worth stating because it recurred five times: **a test that passes alone and fails in the
package is not flaky — it is measuring the process.** Every one of these was fixed by asking what the
instrument is actually counting, and none by widening a tolerance.

### L.4 Instruments, not assertions about instruments

Three instruments were found to be incapable of failing and were rebuilt with calibrating controls, and
two more were scoped or corrected: the `route` census predicate (frame boundary + scope test +
sensitivity control), the `wireguard` census (scoped by receiver address, `0 → 60 → 0`), the
`sniff` census (exact, with a one-goroutine control), the `group` worker census (deterministic window),
and the churn test's "reversible" wording (now states it is about the manager's own goroutines).

The existing legal/rejected configuration baselines are untouched: the whole `test/contract` tree is in
the final scan, `adapter/outbound`'s dry run and lint are behaviourally unchanged for the manager path,
and `protocol/group`'s and `common/physicalpath`'s own suites are green.

---

## M. Delivery boundaries — what this repository cannot safely resolve

Each item says **why**, and what would be needed. Nothing here is a bug that could have been fixed.

1. **Schannel TLS 1.3 (`common/tls` ×3).** Needs an elevated registry write
   (`HKLM\...\SCHANNEL\Protocols\TLS 1.3` → `Enabled=1`, `DisabledByDefault=0`) or a Windows 11 machine.
   Not fixable from this session, and the TLS 1.3 requirement must not be weakened to hide it.
2. **WinDivert driver (`common/windivert` ×5, `common/tlsspoof` ×3).** Needs administrator rights and
   the driver installed. The 20 unprivileged windivert tests and the 6 new unprivileged tlsspoof tests
   pass; the driver-bound cases cannot be simulated without pretending.
3. **WG rebind interruption.** `wireguard-go`'s reopen path takes no context — proven by reflection on
   the stdlib signature and by a test showing an already-cancelled context still runs the hook. Closing
   it requires a `BindUpdate` variant that accepts a context, i.e. a **pinned-dependency change**, which
   the standing rules forbid. Claimed as a bounded revocation latency, not as atomic cancellation.
4. **Cross-process FakeIP attribution.** Without durable state a fresh process cannot prove it issued an
   address. `cache_file`'s existing `fakeip_address` bucket does carry the data, and this round reads it
   through the retired-generation metadata rather than inventing a format — but only when
   `store_fakeip` is enabled, and enabling cross-process sharing by default is a **product decision**,
   not a guard. Recorded as an explicit tested boundary (`C5`).
5. **`Registration.Acknowledge()` / `Stale()` have no production caller.** A transport that rebuilds is
   never recorded as current by the coordinator. This is a coordinator-integration gap rather than
   D7-02, with no observed failure attached; changing it means choosing new coordinator semantics, which
   is a design decision and not a repair.
6. **`common/trafficsched` rate bound.** Host timer granularity, analysed in §I.6. Either it stays a
   documented host-bound flake, or the coarse flat bound stops being the independent check — and that
   is a deliberate weakening, so it is left alone.
7. **`go vet ./...` exit 1.** Pre-existing, in two deliberate crash triggers and one Win32 pointer
   pattern, and not a CI gate. "Fixing" it would change a SIGSEGV into a recoverable panic in a debug
   facility — a behaviour change bought with a diagnostic nobody gates on.
8. **Real Apple / WARP / phone-radio acceptance.** No Apple hardware, no WARP endpoint, no radio. These
   stay `NOT_RUN_EXTERNAL_DEVICE`; the offline equivalents were run and their scope is stated.
9. **Client-side wiring.** The `Status` accessor exists; no UI anywhere reads it, and the client
   repositories were not touched. That is the intended boundary of this round, not an omission.
10. **`common/tls`'s historical wording in the order is factually wrong** and must not be carried
    forward: the failure is a malformed record layer, not "an unexpected record".
11. **The `release/DEFAULT_BUILD_TAGS` (Darwin/naive) profile cannot be built on this machine.**
    `cronet-go/lib/{linux_amd64,darwin_arm64}` carry **no Go files** in the module cache — the prebuilt
    cronet static libraries are fetched as CI artifacts and are absent here — so every target fails at
    `imports github.com/sagernet/cronet-go/all`. The other two profiles build, including the
    `DEFAULT_BUILD_TAGS_WINDOWS` set the shipped Windows product actually uses. Resolving it needs the
    cronet artifact download step from CI, which is a network/CI action and not a code change. See §J.1.
12. **F's post-integration adversarial round was re-run on the shipped SHA** rather than on the
    intermediate tree the first pass used, because §15 requires the final HEAD and §15.1 requires
    re-testing the fixes made from F's own findings. Its result is the last thing appended to this
    report; where it found something, the fix and its mutation are recorded in the same place.

---

## N. Final release verdict

```text
FINAL_CODE_SHA                    = 666470cbe70e734240bd51d547e00b4b950eb8b1
ORIGIN_TESTING                    = the tip of this commit; `git rev-parse HEAD` ==
                                    `git rev-parse origin/testing` (ordinary fast-forward, §A)
ALL_NEW_COMMITS_SKIP_CI           = YES (checked one by one; 42/42)
OTHER_REPOS_TOUCHED               = NO
ORIGINAL_DIRTY_WORKTREE_UNTOUCHED = YES (hash-backed, §A.1)
GO_MOD_GO_SUM                     = UNCHANGED
LIBBOX_ABI                        = 383 symbols, 0 added, 0 removed
A_FIP_HISTORIC_ADDRESS            = FIXED_VERIFIED, with two explicit boundaries (C4 unmeasured entry
                                    paths; C5 the no-ledger/common path) and one now-observable bound
                                    (the 1024-generation ceiling, §L.3b)
B_WG_REBIND                       = FIXED_VERIFIED for result ownership;
                                    BLOCKED_DEPENDENCY_LIMITATION_WITH_EVIDENCE for interruption
C_REAL_CONNECTION_CHURN           = VERIFIED_WITH_SCOPE (real ALPN h3 handshake named, 25 real
                                    transitions, THREE product defects fixed — two in `transport/http`,
                                    one of them found only by the fresh adversary after the first fix had
                                    been reviewed — and every matrix row now resolved except the
                                    real-device ones)
D_BOX_STATUS_INTEGRATION          = LANDED_VERIFIED
E_PLATFORM_TEST_MATRIX            = EXPLICIT_PASS_FAIL_BLOCKED
F_INDEPENDENT_ADVERSARIAL_DEBUG   = COMPLETED_AFTER_INTEGRATION (two adversaries: the first over five
                                    rounds with two retractions of its own findings, the second fresh and
                                    independent over the four areas the first did not reach; 3 further
                                    defects found in already-reviewed work, all fixed and all
                                    reverse-broken)
FULL_TEST_COVERAGE                = REACHED_MODULE_END (171 reporting packages, 84 with tests,
                                    7071 distinct tests, 0 build failures)
FULL_TEST_RESULT                  = COMPLETED_WITH_FAILURES (81 ok / 3 FAIL; the 11 failing test names
                                    are byte-identical to the historical set)
FULL_TEST_SHA_MATCH               = IDENTICAL_CODE_TREE_DOCUMENT_ONLY_TIP (scan at 666470cbe; the tip
                                    adds docs/fork/ only, so no test file and no production file differs)
CI_REMOTE                         = OBSERVED, NOT_RUN_BY_REQUEST (0 runs triggered across every push;
                                    85 [skip ci] commits -> 0 runs measured historically)
RELEASE                           = NOT_READY
```

### N.1 Why `NOT_READY`, and the two states being distinguished

This is **not** "no new bugs were found, therefore ready". It is the opposite: three product defects
were found and fixed this round (the FakeIP escape, the HTTP/3 verdict ordering, the truncated-route
false READY), a fourth was hardened, three instruments that could not fail were rebuilt, and a real
coverage hole was filled. The code is in the strongest state any round has left it in.

`NOT_READY` is about the **other** state, and the order is explicit that the two must not be merged:

- **Local code closure: ACHIEVED.** Everything this repository can verify about itself — every fix with
  a RED-then-GREEN, every guard with a mutation that is RED by assertion, the full scan at a frozen SHA,
  the five-platform build matrix, the ABI, and an independent adversary that attacked all of it — is
  done and green.
- **Real-device signed release acceptance: NOT ACHIEVED, and not achievable here.** No Apple hardware,
  no WARP endpoint, no admin rights, no Windows 11, no FreeBSD libbox target, and no decision from the
  user about `store_fakeip` as a cross-process capability.

`RELEASE=READY` would require, at minimum: the three `BLOCKED_*` conditions cleared or formally accepted
as product limits; a real-device pass over the rows marked `NOT_RUN_EXTERNAL_DEVICE`; and a product
decision on the C5 boundary — whether a fresh process should be able to prove historic FakeIP issuance,
which is a decision about durable state and not about code quality.

Nothing in this report is a substitute for those, and no claim in it was written to make the verdict
look better than the evidence.
