# v0.1.6 second-round correction and integration — ledger

Companion to `docs/fork/v016-five-workstream-final-report.md`, which covers the first round. This
file records the round that reviewed that work and corrected it. Read this one for the current state.

```text
ROUND_BASE            e201b5addb02876c493922f5a541ba4ebb68bcfb
ROUND_HEAD            3ddd1bac717627b6f783e5857293ad6fdabd97b7
ORIGIN_TESTING        3ddd1bac717627b6f783e5857293ad6fdabd97b7   (local == origin)
COMMITS_THIS_ROUND    15
COMMITS_THIS_SESSION  32  (8e6c0a96..3ddd1bac)
MISSING_SKIP_CI       0   (verified on every commit in the whole session range, not only the tip)
GITHUB_ACTIONS        NOT_RUN, NOT_DISPATCHED, NOT_RE-ENABLED (no `gh`, no API access)
TAGS                  636, unchanged; none created
REMOTE_HEADS          1 (`testing`); no branch, PR or Release created
ORIGINAL_WORKTREE     UNTOUCHED: C:\src\sing-box at 8d78dcdd, dirty clients/desktop still dirty
```

---

## 1. The two defects that had to be found by measurement, not by reading

### 1.1 PATH-01 — the physical hop order was BACKWARDS

`Path.Hops` was documented as PACKET order with `Hops[0]` nearest this device, and `Build` produced
the dependency descent, which is the opposite. `Exit()` returned the entry and any consumer would have
named a healthy hop as the broken one.

The first-round reasoning was "`X.detour = Y` means X consumes Y, so the packet reaches X first". That
is the CONFIGURATION nesting and it is false for the packet path, for a reason the proxy convention
makes decisive: a SOCKS/HTTP outbound uses its dialer to reach its **OWN SERVER**, not the user's
target (`sing/protocol/socks/client.go:162` dials `c.serverAddr`; the target travels in the request).
So `exit.detour = entry` means exit's server dial is CARRIED BY entry, and the device enters ENTRY
first.

Decided from the wire, not from the same lines that produced the error:
`common/dialer/detour_wire_order_test.go` builds the dialer with the real `NewDetour`, substitutes a
recording peer, and records which hop is entered and in what order:

```text
exit.detour = entry                  -> the entry outbound is entered FIRST
c.detour = b, b.detour = a           -> b first, then a
no detour                            -> the outbound itself, and the address the caller named
```

The recorder keeps the hop's TAG as well as the address it was asked for. That is what makes the
observation conclusive: an address alone cannot separate "the entry was reached and asked to carry a
connection to the exit's server" from "the device dialled the exit directly", and that distinction is
the whole question. An earlier version of the test asserted the address alone and FAILED against
correct code - recorded here because it is the same mistake in miniature.

Fix: `reversePacketOrder` at the single point where the walk's output becomes a `Path`, which also
renumbers `Hop.Position`, reverses `ControlPath`, and remaps `Unknown.Position`. `Path.Entry()` added.

Nine existing tests pinned the old order and FAILED when the reversal landed, which is what makes the
change load-bearing. Two were renamed because they asserted the opposite of their own names.

### 1.2 START-01 — a startup dry run that FALSELY REJECTED legal configurations

`requiredNetworksFor` unioned `Network()` over every outbound in the configuration and handed that
union to every root. One TCP+UDP outbound anywhere therefore made every other root - and every hop of
every chain beneath it - responsible for UDP. Two independent inflations in one call:

1. an unrelated outbound's capability leaked into every root;
2. the union also read GROUPS, whose `Network()` before Start is an optimistic blanket
   (`Selector.Network()` returns both networks while nothing is selected).

PROVEN PRE-EXISTING with an old-red comparison against `8e6c0a96`: **nine configurations start there
and were refused at `b75b69b9`.** The clearest single proof is a two-outbound case where each outbound
is refused for the OTHER's network.

The requirement is now three separate facts: what the ROUTES proved reaches a root (new
`EnablePhysicalPathDelivery`, additive); failing that, what the root's own reachable objects advertise
at position 0; and per node, a DEPENDENCY hop carries the consumer's transport rather than the business
network, so its requirement is left UNVERIFIED rather than invented. A group that filters members by
network (FlowAware / URLTestGroup, both checked against their implementations) is refused only when NO
member can carry a delivered network; a Selector, which does not filter, keeps the stricter rule, so
the existing refusal of an unusable unselected member is byte-identical.

| direction | configurations |
|---|---|
| relaxed (started at 8e6c0a96, refused by the dry run) | 9, proven with the old-red comparison |
| newly refused, with migration guidance | 2 (a rule whose network condition names a leaf that cannot carry it; a network-filtering group whose NO member can carry it) |
| unchanged | missing member and declared cycle keep the start-order sort's own message |

### 1.3 The de-duplication reported the wrong unit

`Manager` recorded a failure's LEAF TAG, so once one root reported a leaf, no later root could report
against it. MEASURED through a real `box.Start`: for a configuration whose two routing rules both
deliver udp to one tcp-only leaf, the leaf-keyed key reported **one line, `outbound/tcp-only`, naming
NEITHER route**; the root-keyed key reports **two lines, `outbound/A -> A -> tcp-only` and
`outbound/B -> B -> tcp-only`**. `Failure.Root` is what tells an operator which entry point to repair.

Two intermediate attempts are recorded in the code rather than discarded, because both were measured
wrong: widening to (route, leaf, hop) emitted one defect twice for a group and its member, and gating
the covered-root skip on the `optional` flag only (which is set only on entries the MANAGER appends)
left a declared group validated a second time.

---

## 2. PhysicalPath model — hardened by two concurrent workstreams

`PATH-02` (per-walk state): `Resolver` carried `network` and `decisions` and `Build` wrote both, so one
Resolver could not serve two walks. The decisive reproduction is NOT the `-race` report: two walks
ordered by channel handoffs are happens-before ordered, the detector is silent, and the walk is still
answered with the other walk's network. Fixed with a per-call `walkScope` (a value, with an inline
identity-keyed decision record so the common walk allocates nothing extra); `With*` became
copy-on-write; the `Snapshot` is frozen at construction; one `PathNode` per (node, route).

CONFIRMED CLOSED, because a concurrent workstream hit it independently: that workstream reported a
`-race` failure at `Build` vs `Build.func2`. At `3ddd1bac` there are **zero writes** to any `Resolver`
field outside construction (`grep 'resolver\.(network|decisions|nodeBudget)\s*='` is empty), the walk
state lives on `walkScope`, and the type documents a concurrency contract. The workstream's own mutex
is therefore redundant; it is harmless and was left in place rather than rewritten without its author.

`PATH-03` (diamond): `Hops` de-duplicated nodes by identity across ROUTES, so a legal diamond lost the
second route's contract. Now one node per route, with per-route `RequiredNetworks`, position and
`IsCurrent`; cycle detection still uses the current descent only. A node budget refuses loudly rather
than truncating silently.

---

## 3. MTU — all four protocols decided

| item | state |
|---|---|
| MTU-02 TUIC | wired and MEASURED on the wire: 1232 -> 1232 bytes, 1300 -> 1300. TUIC reaches quic-go through the same `ApplyQUICOptions` as HY2 but never sets `ChromeParrot`, so unlike HY2 the clamp DOES reach the wire |
| MTU-03 WireGuard | overhead established from the pinned source (16 header + 16 tag inside the inner IP packet; the 8-byte "encapsulating" prefix is re-sliced away), budget table asserted per row; 1408 -> 1328/1348 inner budget, not 1360. New `PortEncapOverheadProvider` capability so a QUIC protocol over WG sizes correctly. **WIRE SIZE NOT_MEASURED**, with both harnesses built, both blocked, and the blocking cause recorded rather than worked around |
| MTU-04 MASQUE | outer `InitialPacketSize` clamped by a proven detour capacity, 1200 floor refused. HONEST NO-OP: 1331 already fits every ceiling this tree can publish, so it closes an unenforced assumption rather than changing behaviour today |
| HY2 | unchanged from round one: the clamp reaches the wire only with ChromeParrot OFF, because the pinned quic-go replaces the configured value with 1250 |

---

## 4. STATUS-01/02 — read-only per-hop status

New `common/physicalpath/status.go`. No new timer, probe, periodic scan or goroutine per hop: every fact
is READ from optional interfaces on objects that already exist. Order comes from `Entry()` / `Exit()` /
`Hop.Position` only. "Constructed successfully" is never presented as "the peer is reachable" -
readiness is a separate axis from lifecycle state, and a hop that reports nothing is UNKNOWN plus a
reason. Error attribution names the hop, the PHASE and the path order; redaction covers URL userinfo,
Authorization headers including the scheme, key=value secrets, PEM bodies and uuid. First-failure
selection is by packet order, not severity.

That workstream's mutation testing found a gap in its OWN tests and closed it: reversing `firstFailure`
to report the LAST failing hop passed everything, because every fixture had exactly one failure. A
two-failure fixture was added and the identical mutation re-run to confirm it now fails. A mutation
that is MISSED and then made CAUGHT is worth more than a mutation that was never run.

---

## 5. COPY-01 and the exit-verdict audit

`docs/fork/v016-copy-audit-and-verdict-scope.md`. Measured, not modelled: a 14-row table of every
copy/retention on the byte-moving paths, plus `-benchmem` allocation numbers explicitly labelled as
allocation measurements and NOT as wall-clock claims. The decisive scope fact: the byte-moving engine
lives in the read-only `sing` fork, so this repository decides which engine call is made and with what
ownership, not the copy itself.

Measured: **`kernel_bypass` / `kernel_splice` / `zero-extra-copy` exist NOWHERE in the tree.** They are
not knobs. No API and no config level was invented to make the instruction fit.

One real defect found and fixed: `common/httpclient`'s per-authority HTTP/3 verdict - which sends every
later request for that authority to the H2 fallback for 5 minutes, doubling to 48h - was armed by ANY
failed attempt, including one the CALLER ended. A client's own shutdown could therefore arm an outage.
Three call sites now go through `recordH3AttemptFailure`, which refuses to arm when the request's
context is done, matching three in-tree precedents.

The other three verdict subsystems were audited and found sound, with the guard tests named: the native
bypass is per-flow with a live policy re-read and refuses any chain of length != 1; the URLTest store is
scoped to (tag, probe target) and a closed hop cannot write; `physicalpath.Reachable()`/`Exit()` have no
production consumer that overclaims.

---

## 6. Honest limits

1. **The full sweep was NOT run to completion on this machine at the final SHA.** Every package
   touched by this round was run and is green, and `-race` is green over `common/physicalpath`,
   `common/dialer`, `common/httpclient`, `protocol/tuic`, `adapter/outbound`, `route` and the root
   package. `FULL_TEST_STATUS` is therefore `NOT_RUN_TO_COMPLETION`, and a serial sweep at the final
   SHA was started as this round closed.
2. **MEASURED, serially, at the baseline `8e6c0a96` (`go test -p 1 ./...`, so load-induced flakes
   cannot hide):**

   ```text
   FAIL  common/tls                (3 TLS 1.3 Windows cases)
   FAIL  common/tlsspoof           (3 spoofer integration cases)
   FAIL  common/urltest            (4 cases)
   FAIL  common/windivert          (5 driver integration cases)
   FAIL  experimental/clashapi     (2 cases)
   FAIL  experimental/libbox       (1 case)
   FAIL  protocol/shadowtls        (TestShadowTLSRealRefusedDialIsAFault)
   FAIL  transport/http            (5400.042s - it HUNG, 90 minutes, until the timeout)
   ```

   Two facts follow, and both matter more than the list.

   **The baseline does not complete a full test run on this machine at all.** `transport/http` hangs
   for ninety minutes, so `go test -p 1 ./...` never reaches the packages ordered after it. The
   attribution for those is therefore bounded by that hang, which is stated rather than glossed.

   **Both failures that PREVENTED completion are fixed in this session.** The `transport/http` hang is
   the `loopbackDialer` defect: it dialled a connected UDP socket for EVERY network, and `net.DialUDP`
   to a port nobody listens on SUCCEEDS, so the HTTP/1 fallback received a working "connection" and
   blocked in `ReadResponse` with no deadline. The `protocol/shadowtls` failure is the assertion
   against `syscall.ECONNREFUSED`, which is false on Windows (a TCP dial returns WSAECONNREFUSED,
   10061) and whose message is LOCALIZED by the OS. Both are fixed, so this round's tree is the first
   in which `transport/http` runs to completion here - `ok 16.7s`, and `ok 18.4s` under `-race`.

   The six remaining packages are identical at both SHAs. Two apparent regressions in `common/dialer`
   and `common/power` appeared only in a PARALLEL sweep and BOTH PASS in isolation at the final SHA;
   those are deadline-bound tests that flake under load, which is a robustness observation about those
   tests rather than a regression from this work, and the serial baseline confirms they pass there.
3. **`PathNode.RequiredNetworks` is still write-only.** It is populated by `leaves.go` and read
   nowhere; the function parameter was authoritative. The START-01 fix does not rely on it, and its doc
   comment is actively wrong until the owner wires or deletes it.
4. **`Selector.References()` lies before Start** - it returns the first listed member rather than the
   configured `default` - so `HopCheck.Current` can mislabel. Diagnostic-only, no error text depends on
   it.
5. **A WireGuard listener never binds its reserved `listen_port`** (probe-proven: the port was free
   after both endpoints started). Separate from MTU, affects any listener, not fixed.
6. **A nil-dialer panic** in `transport/wireguard.ClientBind.connect` is reachable from any embedder
   (not from a configuration). Reported, not fixed.
7. **Apple/Darwin paths: STATIC ownership review only.** No Apple runtime PASS is claimed anywhere.
8. **No CI run, no interop, no WARP, no carrier, no platform build matrix.** `[skip ci]` suppresses
   push runs by design and this environment has no API access, so `REMOTE_ACTIONS_OBSERVED` is
   `NOT_QUERYABLE` rather than `0`.

## 7. Product decisions left to the owner

1. A hard ceiling that ChromeParrot cannot override needs a change to the pinned `quic-go`.
2. A floor or explicit refusal for WireGuard `mtu` below the IPv6 minimum, instead of a per-flow
   "unsupported".
3. Whether the WireGuard nested-tunnel derivation should be automatic.
4. A second sing-fork finding: `BufferedVectorisedWriter` allocates unpooled above 64KiB - the one
   genuinely avoidable per-write allocation found, and it is inside the read-only dependency.
5. `common/httpclient`'s 48h HTTP/3 cap is reachable only by failures CONCURRENT inside one window,
   because an expired entry is deleted on read. The comment reads like a doubling ladder; the code is
   a concurrency-amplified one.

---

## 8. Closing answers

```text
ORIGIN_TESTING_SHA=3ddd1bac717627b6f783e5857293ad6fdabd97b7
LOCAL_HEAD_SHA=3ddd1bac717627b6f783e5857293ad6fdabd97b7
LOCAL_EQUALS_ORIGIN=YES
NEW_COMMITS_THIS_ROUND=15
ALL_COMMITS_SKIP_CI=YES
GITHUB_ACTIONS_DISPATCHED=NO
REMOTE_ACTIONS_OBSERVED=NOT_QUERYABLE
OTHER_REPOS_TOUCHED=NO
ORIGINAL_DIRTY_WORKTREE_UNTOUCHED=YES
PHYSICAL_PATH_WIRE_ORDER_STATUS=FIXED_AND_VERIFIED (was backwards; decided by the dial path)
STARTUP_COMPAT_STATUS=FIXED (9 configurations relaxed; 2 newly refused with migration guidance)
DESTINATION_DNS_OWNERSHIP_STATUS=READY (SOCKS TCP / SOCKS UDP / UoT / HTTP CONNECT)
PHYSICALPATH_OBSERVABILITY_STATUS=DELIVERED_READ_ONLY (per-hop status, no new timers or probes)
HY2_TUIC_WG_MTU_STATUS=HY2 wired with a measured ChromeParrot limit; TUIC wired and MEASURED on the
                       wire; WG budget from source with the wire size NOT_MEASURED; MASQUE wired (no-op)
ZERO_COPY_STATUS=COPY-01 AUDITED with measured allocation numbers; kernel_bypass/kernel_splice do not
                 exist in this tree; no optimisation claimed as a system-wide win
FULL_TEST_STATUS=NOT_RUN_TO_COMPLETION (every touched package green and raced; the serial
                 baseline does not complete at all, and the two failures that stopped it are
                 fixed here)
RACE_STATUS=PASS on every changed package
CODE_CORRECTNESS=two P0 defects found by measurement and fixed, four more reported with evidence
RELEASE_STATUS=NOT_READY
```
