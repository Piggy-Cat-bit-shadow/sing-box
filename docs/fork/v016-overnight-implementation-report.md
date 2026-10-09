# v0.1.6 overnight implementation report

**This document is the authoritative handoff for the session that produced it.** It records what was
actually built, tested and pushed, what was NOT built, and the exact state a continuation starts from.
Nothing here is projected forward as done.

---

## A. Repository / Git

```text
working repository        Piggy-Cat-bit-shadow/sing-box
branch                    testing (pushed to directly; no other remote branch created)
START / BASELINE_SHA      4bbc59484ca3e473f938b908c9c6f4cbc7233a3c   (live origin/testing at start)
FINAL_SHA                 adf5d286241e22b2479d9e36cb8a82be2a944f6e
origin/testing after push adf5d286241e22b2479d9e36cb8a82be2a944f6e
local == origin           YES
final SHA tested          YES (the test runs below were performed at this commit's tree)
original worktree         UNTOUCHED. C:\src\sing-box stayed at 8d78dcdd with its dirty
                          clients/desktop submodule pointer; every write happened in a
                          detached worktree at C:\Deepseek\内核\work
tags                      636 (unchanged; none created)
force push / reset        never used
other repos               never written: satelite-one, Apple, Windows Delphi, quic-go,
                          sing-quic, sing-tun, sing, LX
```

Commit list, in push order:

```text
874b9a2b  clashmode: make the persisted mode converge on the accepted one
a123864b  dns: make the policy epoch own the cache commit, not only the check
08479fe3  tun: write down the L0 boundary's semantics and pin its four mutations
f0b29904  test(masque): pin the inner IPv6 fragment path at a 1280-byte tunnel MTU
adf5d286  feat(path): let a declared downstream hop own destination DNS
```

Toolchain: `go1.26.8 windows/amd64` from `C:\src\_toolchain\goroot`, `git 2.56.0.windows.2` from
`C:\src\MinGit`. The race detector was enabled with `CGO_ENABLED=1` and the MinGW gcc found at
`C:\Users\Jie\AppData\Local\Temp\jiejie-tools\mingw\mingw64\bin` (gcc 16.2.0). Build tags always read
from `release/DEFAULT_BUILD_TAGS_OTHERS`, never hard-coded.

---

## B. Task matrix

| Gate | Item | Status | Commit | Evidence |
|---|---|---|---|---|
| G0 | Baseline forensics, isolated worktree | DONE_TESTED | — | live SHA, dirty set, worktree list recorded |
| G1 | Clash mode persistence linearization | DONE_TESTED | `874b9a2b` | `-race -count=30`; 2 mutations RED, 2 recorded NOT-RED |
| G2 | DNS policy epoch → cache commit | DONE_TESTED | `a123864b` | deterministic interleaving; 2 mutations RED |
| G3 | L0 boundary, four reverse-breaks | DONE_TESTED | `08479fe3` | all four mutations RED; tests/comments only |
| G4 | HY2 / MASQUE inner IPv6 at MTU 1280 | DONE_TESTED (local) | `f0b29904` | both families measured; 1 module mutation RED |
| G4 | ChromeParrot product choice | PRODUCT_TRADEOFF | — | mechanism measured, choice deliberately not made |
| G5 | Destination DNS ownership (SOCKS wire) | DONE_TESTED | `adf5d286` | real SOCKS5 server, ATYP asserted; 2 mutations RED |
| G5 | HTTP CONNECT wire ownership | **NOT IMPLEMENTED** | — | see J |
| G5 | UDP ASSOCIATE / UoT wire ownership | PARTIAL | `adf5d286` | branch taken and fails closed; wire form not asserted |
| G6 | PhysicalPath / ControlPath internal model | **NOT IMPLEMENTED** | — | see J |
| G6 | Start-time all-reachable-leaf dry-run | **NOT IMPLEMENTED** | — | see J |
| G7 | Per-hop status, error ownership, MTU reasons | **NOT IMPLEMENTED** | — | see J |
| G7 | Lifecycle / generation integration tests | **NOT IMPLEMENTED** | — | see J |
| G8 | Cross-platform build matrix | **NOT RUN** | — | see J |
| G8 | Composite box-level E2E | **NOT RUN** | — | see J |
| G8 | Full `go test ./...` sweep | **NOT RUN** | — | see J |
| G8 | CI at FINAL_SHA | CI_NOT_RUN | — | Actions state not checked this session |
| G8 | Real Xray / WARP interop | BLOCKED_DEPENDENCY | — | no reference binary, no capture environment |

---

## C. Confirmed findings

### C-1 — Clash mode could persist a mode the user had already left (two defects, not one)

*Production path*: `PATCH /configs` → `experimental/clashapi/configs.go` → `clashmode.Manager.SetMode`;
and `daemon/started_service.go` → the same. `Start` restores through `CacheFile.LoadMode`.

*Defect A*: the ticket that orders persistence was claimed AFTER `updateAccess` was released, so a
switch that published first could take a higher ticket by being descheduled.

*Defect B* (the one that mattered): even with the ticket claimed correctly, "check the ticket, then
write" is a check-then-act on a mutable value. A switch parked between the check and the write could
commit its value after a newer switch had committed its own.

*Old behaviour / RED*: `runtime="Direct" persisted="Global" write order=[Direct Global]`.

*Root cause and constraint*: the write must not be serialised by `updateAccess`, because that lock is
what keeps a slow disk from stalling mode publication, and `Mode()` must stay a lock-free atomic load
on the connection routing path.

*Real bug, not a model risk*: the next process start restores a mode the user had already moved away
from, which is a user-visible wrong state.

### C-2 — A DNS answer authorised before a policy clear could be recorded after it

*Production path*: `dns/client.go finishExchange` → `stateMutationAllowed` → `storeCache` /
`storeNXDomain`, against `dns/router.go ClearCache` (reached from `clashmode.Manager.SetMode` and from
`POST /dns/flush`).

*Old behaviour / RED*: the epoch check authorises the write; `ClearCache` then advances the epoch and
purges; the authorised write lands afterwards and is live under the new epoch. The new policy is then
answered by the server the switch moved away from, for the rest of the entry's TTL.

*Root cause*: the epoch is a value to compare, not an ordering primitive. Re-checking it before the
write is still two steps.

*Second instance, different cache*: `Router.recordReverseMappingFrom` purged by `ClearCache` but
guarded only by the NETWORK generation, which a policy switch does not advance.

### C-3 — L0 has no missing contract; the four mutations are the finding

*No production change.* The four intended reverse-breaks all turn existing tests red (see E). The
finding is that the L0 boundary's semantics were only half-written down, so the contract is now stated
in `JudgeFlow` (order, what each step may decide, the three verdicts that are confused, and the
consequence for configuration writers).

### C-4 — A 1280-byte inner IPv6 MTU cannot carry the payload ChromeParrot forces

*Measured at the IP layer this session* (see E). `ChromeParrot=true` forces a 1250-byte UDP payload;
the inner IPv6 budget at MTU 1280 is 1232; the stack splits the packet into 1280 + 74 bytes. The same
payload FITS IPv4 (1278 bytes). The fragmentation itself is correct RFC 8200 work, including the RFC
791 multiple-of-8 snapping that makes the first IPv4 fragment 1276 rather than 1280.

*What remains unproven*: that any real path carries or drops those fragments. That is a property of
the path, not of this code, and no test on this host decides it.

### C-5 — A downstream SOCKS5 hop was resolving the user's destination

*Production path*: `protocol/socks/outbound.go DialContext` → `h.client.DialContext` with the domain
intact → SOCKS5 `ATYP=DOMAIN` on the wire.

*Old behaviour*: sing-box deliberately sent the domain. `TestSOCKS5StillSendsTheDomain` pinned it, with
the reasoning that a single-hop proxy's resolver picks the better CDN edge. That reasoning is right for
a single hop and wrong for a downstream hop, and the configuration had no way to say which one it was.

*Fix*: an explicit declaration, not a heuristic. See D.

---

## D. Production design

### D-1 Clash mode persistence

```text
SetMode:
  updateAccess.Lock()
      same-mode check, m.mode.Store(newMode), sequence := claimSequence()   <- ONE step
  updateAccess.Unlock()
  hooks ...  dnsRouter.ClearCache() ... persistMode(sequence)

persistMode(sequence):
  if current ticket != sequence: return            (cheap, avoids queueing for a doomed write)
  persistAccess.Lock()                             (the WRITE GATE)
  loop:
      if current ticket != sequence: return        (the re-read that is load-bearing)
      currentMode := m.Mode()
      StoreMode(currentMode)                       (write what the gate OBSERVES)
      if current ticket == sequence: return        (converged)
      sequence = current ticket                    (a switch landed; adopt and write again)
  persistAccess.Unlock()
```

Locks: `updateAccess` (control plane: publication, ticket, hook list) and `persistAccess` (write gate).
`Mode()` takes neither. Lock order is always `updateAccess` → `persistAccess`; `restorePersistedMode`
follows it too, which is why it takes them in that order.

*Why the loop and not a skip*: the first version skipped a superseded write, on the theory that the
newer switch would write. That is wrong — the newer switch can run entirely while the older one is
already inside the backend, find the gate busy, and return. MEASURED during development:
`runtime="Direct" persisted="Global"` with the skip rule.

*Measured limitation, recorded in the source*: with the gate and the loop in place, moving the ticket
claim after the unlock is NOT observable through the manager's contract (mutation reports NOT-RED).
The claim position is kept as required-by-construction and defence in depth, NOT as the field that
closes the defect. The gate is that field.

*Failure*: a refused write leaves the backend holding an older value and logs it. The next switch
writes again. A failed write is never reported as success.

### D-2 DNS policy-epoch commit ownership

```text
adapter.PolicyStoreGuard {
    PolicyStoreEpoch() uint64
    StoreUnderPolicy(commit func())
}

dns/policyStoreGuard  (rwmutex + a pointer to the Router)
  ClearCache:  Lock() ... advance epoch, client.ClearCache, platform clear, reverse purge ... Unlock()
  commit:      RLock() ... epoch check + cache write ... RUnlock()

dns/client.go commitCacheState:
  if policyStoreGuard == nil: commit()          (no policy concept: behaviour unchanged)
  else: policyStoreGuard.StoreUnderPolicy(commit)
```

Result: the commit is entirely before the clear — and the purge removes what it wrote — or entirely
after it, in which case the in-guard epoch read fails and nothing is written. No third ordering.

The optimistic background refresh goes through the same commit path, and now captures a policy epoch at
all (it previously captured only the network generation).

The reverse mapping is the same window on a different cache and is closed differently, because
`ClearCache` already purges it under `dnsEnvironmentAccess`: one additional epoch comparison inside that
existing critical section is sufficient there.

Lock order (documented at the field): `policyStoreGuard` is a leaf. Only the commit path and
`ClearCache` take it; the commit holds nothing else inside, and `ClearCache` takes it as its outermost
acquisition, so the cache internals, the DNS cache backend and `dnsEnvironmentAccess` are always
acquired under it.

*What it deliberately does not do*: wait for in-flight queries, cancel them, or make a clear a barrier
they must pass. Only a commit takes the read side, and only for one cache insert. `TestAPureFlush…` and
`TestAnInFlightAnswer…` keep their existing contracts.

### D-3 HY2 / MASQUE MTU and the ChromeParrot choice

Three sizes, kept separate:

```text
inner IP MTU          1280   the tunnel's own MTU
inner UDP budget      1232   IPv6 (1280-40-8);  1252 IPv4 (1280-20-8)
outer QUIC initial    1250   what the pinned quic-go forces under ChromeParrot
```

Measured inner fragmentation at MTU 1280 (see E for the full matrix). Fragment payload is snapped to a
multiple of 8 per RFC 791, so the first IPv4 fragment carries 1256, not 1260.

*Decision*: `PRODUCT_TRADEOFF`, and the choice was NOT made. Reasons, stated so the next session does
not have to re-derive them:

* The prompt permits a local compatibility fix ONLY on a provably 1280-hard-capacity inner IPv6
  detour. Nothing in this kernel can prove that for an arbitrary detour graph: the outer transport's
  effective capacity is not knowable at configuration time, and guessing would silently change the
  network fingerprint of connections that did not need it.
* The two changes that WOULD be mechanically simple — forcing `initial_packet_size: 1232` in the outer
  configuration, or globally disabling ChromeParrot — are exactly the pseudo-fixes the prompt forbids:
  the first is discarded by the pinned quic-go under ChromeParrot, the second changes a fingerprint.

*Workaround available to the user, not applied by default*: `disable_chrome_parrot: true` with
`initial_packet_size: 1232` on the affected HY2 outbound. This is a visible fingerprint change and is
the user's decision.

### D-4 Destination DNS ownership

```text
option.DialerOptions.DestinationDNSOwnership   (json "destination_dns_ownership", default false)

protocol/socks Outbound:
  resolveDestinationForDownstream(ctx, destination):
      not declared, or destination is an address -> (nil, false, nil)   unchanged path
      declared and resolvable                    -> (addresses, true, nil)
      declared, error / empty / no router        -> ERROR, fail closed
  owned -> N.DialSerial(ctx', h.client, network, destination, addresses)
           ctx' carries OriginDestination = destination, DestinationAddresses = addresses,
           and Destination stays the DOMAIN
```

Why an explicit declaration rather than position detection: a SOCKS outbound's config cannot see
whether another outbound's `detour` points at it, and guessing from the graph would be a heuristic at
the wrong layer. The declaration says what the config author knows.

Node DNS vs destination DNS: only the destination is owned. The proxy server's hostname keeps
`domain_resolver` and the ordinary dial path, untouched.

---

## E. Tests and reverse-break

All reverse-breaks were run in a disposable copy of the tree, and the driver verifies the tree is
re-synced before every mutation and restored byte-identically after (a stale scratch tree produced one
false NOT-RED during development, which is why the driver now re-syncs). Nothing mutated was ever
committed. The driver is `C:\Deepseek\内核\mutate.py`; module-level mutations copy the dependency with a
temporary `replace` in a copy of go.mod and verify the module cache entry was not modified.

### Clash mode (`experimental/clashmode`)

| Mutation | Result | Tests that caught it |
|---|---|---|
| ticket re-read moved out of the write gate | RED | `TestOlderStoreParkedBeforeCommitCannotOverwriteANewerSwitch`, `TestASupersededSwitchStillLeavesTheBackendOnTheAcceptedMode` |
| write gate removed entirely | **NOT-RED** | recorded as a limitation: the gate and the loop are both needed, and removing only the gate still converges for these schedules |
| ticket claimed after the unlock | **NOT-RED** | recorded in the source as a measured limitation of the harness |

New tests: the pre-commit barrier reproduction, the superseded-store convergence case, a claim-order
clamp, a restore round trip, `Start` racing a switch, hook re-entry, transient store failure, a
literal-address destination case, and 200-round switch storms (pair and three-way).

The stub was rewritten as the prompt required: it parks BEFORE it commits, with separate `entered` and
`commits` channels, so "the call was reached" and "the value landed" are distinguishable. The previous
stub wrote first and then waited, which could not show the difference.

### DNS (`dns`)

| Mutation | Result | Tests that caught it |
|---|---|---|
| commit run outside the guard | RED | `TestAnAnswerAuthorisedBeforeTheClearIsNotRecordedAfterIt` |
| reverse-mapping policy comparison removed | RED | `TestAReverseMappingLearnedUnderTheOldPolicyIsNotPublishedAfterTheClear` |

The window test reads the ordering from a closed channel (`did the clear finish while the commit was
frozen`), not from a duration; the 200 ms wait is the channel that decides which of the two real
orderings occurred. The epoch is asserted to have advanced, so the guard cannot be inert.

Two mistakes were made and fixed while building this test, recorded because they are the failures a
later reader would repeat: a pre-check seam cannot expose a check-then-act race (the check then simply
re-reads the new epoch and refuses), and an in-guard seam cannot produce a clear that finishes.

### L0 (`protocol/tun`)

| Mutation | Result |
|---|---|
| steps 2-3 (configured hijack, by-port) moved below the route sets | RED — `TestDNSHijackBeatsRouteExcludeAddressSet`, `TestDNSHijackByPortBeatsRouteExclude`, `TestDNSHijackByPortTCPBeatsRouteExclude`, `TestDNSHijackByPortBeatsRouteAddressSetMiss`, `TestDNSHijackAddressBeatsRouteAddressSetMiss`, `TestDNSHijackByPortWorksForIPv6`, `TestJudgeFlowDNSPrecedenceTruthTable` |
| FakeIP guard removed from the route sets | RED — `TestFakeIPIsNotBypassedByRouteAddressSet`, `TestFakeIPIsNotBypassedByRouteExcludeAddressSet`, `TestMappedFakeIPIsStillGuardedFromTheRouteSets` |
| an authoritative route-set hit continues into the router | RED — `TestL0HitReport`, `TestL0CannotExpressAnythingButAddresses`, `TestL0AuthoritativeIPPolicyWinsBeforeReverseMapping` |
| the router becomes unconditional (standing in for "a configured `domain_resolver` blocks every bypass") | RED — the same three plus `TestL0DoesNotDiscardProcessOrProtocolRulesOnTheNonL0Branch` |

`PRODUCTION_CHANGED = NO` for this item: comments only.

### HY2 / MASQUE inner IP (`transport/device`)

Measured, both families, MTU 1280:

```text
IPv6 (budget 1232)
  1231 -> 1 packet  1279  next header 17 (UDP)
  1232 -> 1 packet  1280  next header 17          exactly fits
  1233 -> 2 packets 1280 (1232 carried) + 57 (9 carried)
  1250 -> 2 packets 1280 + 74
  1280 -> 2 packets
IPv4 (budget 1252)
  1250 -> 1 packet  1278
  1252 -> 1 packet  1280                          exactly fits
  1253 -> 2 packets 1276 (1256 carried) + 25 (5 carried)
```

Fragment headers are parsed out of the written bytes: next header UDP, offsets continuing where the
previous fragment ended, more-fragments set on every fragment but the last, one shared identification
per datagram, and a reassembly total equal to the original IP payload (which is the UDP header plus the
UDP payload — counting the UDP header twice is an easy and silent way to overstate the overhead by 8
bytes, and that mistake was made and corrected here).

| Mutation | Result |
|---|---|
| IPv6 fragment header dropped from the fragment budget | RED — `TestInnerIPv6FragmentationAtTunnelMTU`, `TestTheChromeParrotPayloadDoesNotFitInnerIPv6` |

Not run: the "emit the packet unfragmented" and "widen the transmit threshold" mutations (their anchors
were not applied before the session ended).

### Destination DNS ownership (`protocol/socks`)

Wire-level: a real SOCKS5 server on loopback decodes the CONNECT request; the assertions are on the
ATYP byte and the address in it, not on metadata.

| Mutation | Result | Tests that caught it |
|---|---|---|
| a resolution failure silently falls through to the peer | RED | `TestOwnershipFailsClosedWhenResolutionFails`, `TestOwnershipFailsClosedWhenResolutionIsEmpty` |
| the ownership flag ignored, so the domain is sent anyway | RED | `TestWithoutOwnershipTheDomainStillTravels` |

Test list: `TestDownstreamOwnedDestinationIsSentAsAnAddress`,
`TestDownstreamOwnedDestinationIsSentAsAnIPv6Address`,
`TestWithoutOwnershipTheDomainStillTravels`, `TestOwnershipFailsClosedWhenResolutionFails`,
`TestOwnershipFailsClosedWhenResolutionIsEmpty`, `TestOwnershipLeavesAnAddressDestinationAlone`,
`TestThePacketPathOwnsTheDestination`, `TestMissingRouterFailsClosed`.

`NO OTHER DATA PATH WAS SUBSTITUTED FOR THIS`: the HTTP CONNECT outbound is a separate implementation
and is NOT covered by these tests. See J.

### Race runs performed at the final tree

```text
go test -race -count=30   ./experimental/clashmode/                              ok
go test -race -count=2    -tags "$TAGS" ./experimental/clashmode/... ./route/rule/...   ok
go test -race -count=1    -tags "$TAGS" ./dns/... ./experimental/clashmode/... ./route/rule/...  ok (was -count=3)
go test -race -count=2    -tags "$TAGS" . ./route/... ./protocol/tun/... ./adapter/...   ok
go test -count=1          -tags "$TAGS" ./dns/... ./transport/device/... ./protocol/hysteria2/... ./protocol/masque/... ./transport/masque/...   ok
go test -race -count=1    -tags "$TAGS" ./protocol/socks/... ./common/dialer/... ./route/rule/...   ok
```

---

## F. Performance

| Change | Hot path | Cost |
|---|---|---|
| Clash mode | `Mode()` — one connection routing read per `clash_mode` rule | unchanged: one atomic load, no lock |
| Clash mode | persistence | one extra mutex acquisition per accepted switch (control plane only) |
| DNS | cache commit, once per upstream exchange | one `RWMutex.RLock` around the epoch check plus the cache insert. No allocation, no per-packet work, no new goroutine or timer |
| DNS | `ClearCache` | now takes the write side, so it waits for commits already inside a cache insert. Bounded by one insert, and only commits — a cache hit, an error or a disabled cache never takes the guard |
| L0 | none | comments only |
| Destination DNS | none | the branch is taken only when the option is declared, and then only once per connection, replacing a path that was already doing nothing |

No benchmark A/B was run. For the DNS guard the added work is a reader-lock acquire/release pair on a
path that performs a DNS round trip, so an A/B was judged not to be the informative instrument; a
before/after allocation count was NOT measured and is reported as not measured rather than asserted.

---

## G. CI / interop / platforms

```text
same-SHA CI            CI_NOT_RUN. Actions state was not queried this session; no workflow,
                       workflow_dispatch or repository setting was touched.
Xray reference interop BLOCKED_DEPENDENCY: no reference binary and no second instance available
WARP / IPv6 capture    REAL_NETWORK_NOT_RUN: no credentials and no capture environment
platform builds        NOT_RUN (see J)
real-device soak       NOT_RUN
```

---

## H. The six questions

1. **Can two SetMode calls still leave the persisted mode behind the runtime mode?**
   Not through the two windows this session closed. The ordering is now owned by the write gate, with
   the epoch observed from inside it and the write repeated until nothing newer replaced it. Evidence:
   the parked-commit barrier test, the superseded-store test, 200-round storms, and the mutation that
   moves the ticket re-read out of the gate turning both barrier tests RED.
   *Residual*: with the gate and loop in place, the ticket claim POSITION is not observable through the
   contract (mutation NOT-RED). That is stated in the source, not hidden.

2. **Can an old exchange refill the cache after a completed ClearCache?**
   No, for both positive and negative entries, because the epoch check and the store are one step with
   respect to the clear. NXDOMAIN widening is inside the same guarded commit, so it inherits the
   property. Evidence: `TestAnAnswerAuthorisedBeforeTheClearIsNotRecordedAfterIt` (the clear completes
   while the commit is frozen; the entry is absent afterwards; the new policy asks its own server; a
   current-epoch answer IS still cached, as the positive control) plus the unguarded-commit mutation RED.
   The reverse mapping is closed by an epoch comparison inside the lock `ClearCache` already purges
   under, and its mutation is RED.
   *Not covered*: NXDOMAIN under the guard specifically was not driven through the frozen-commit
   interleaving — the existing negative-cache tests cover the surrounding semantics only.

3. **Does a configured DNS hijack still precede L0 and the router?**
   Yes, and so does FakeIP protection. All four mutations RED, production verdicts unchanged
   (`PRODUCTION_CHANGED = NO` for this item).

4. **When FakeIP, L0-authoritative IP policy and router DNS-derived domain policy conflict, which wins?**
   Configured DNS hijack first, then FakeIP protection, then the authoritative L0 route sets, then the
   router. The L0 branch terminates evaluation with `Router` call count 0 — a deliberate,
   user-authorised policy override, now written down in `JudgeFlow` along with its consequence for
   configuration writers.

5. **How large is the UDP payload HY2 actually sends, and what IPv6 fragments come out at inner MTU 1280?**
   `ChromeParrot=true` forces 1250 bytes at the socket (measured by tools already present). At inner MTU
   1280 the complete IPv6 packet is 1298 bytes and the stack emits two IPv6 fragments: 1280 bytes
   carrying 1232, and 74 bytes carrying 42, with a shared identification, RFC 8200 fragment headers, and
   offsets continuing correctly. IPv4 carries the same payload unfragmented at 1278.

6. **Were ChromeParrot, the QUIC dependency, the Android `release` pull or any client repo changed?**
   No. No dependency was repointed, no fingerprint default was altered, no client repository was touched.
   The remaining decision is isolated as `PRODUCT_TRADEOFF` with its mechanism measured and the
   workaround named, and the reasons the automatic fix was NOT taken are recorded in D-3.

---

## I. Verdicts

```text
CLASH_MODE_PERSISTENCE_STATUS     = READY
DNS_POLICY_CACHE_COMMIT_STATUS    = READY (for the exact and NXDOMAIN paths inside the guarded commit;
                                    see H-2 for the explicitly uncovered case)
DIRECT_FAST_PATH_BOUNDARY_STATUS  = READY
HY2_MASQUE_IPV6_MTU_STATUS        = PRODUCT_TRADEOFF
PHYSICAL_PATH_CORE_STATUS         = NOT_READY
DESTINATION_DNS_OWNERSHIP_STATUS  = NOT_READY  (SOCKS done at wire level; HTTP CONNECT and the UDP
                                                wire form are not)
PHYSICAL_PATH_LIFECYCLE_STATUS    = NOT_READY
DEV_INTEGRATION_STATUS            = PARTIAL
CI_STATUS                         = CI_NOT_RUN
RELEASE_STATUS                    = NOT_READY
```

`docs/fork/v016-final-release-verdict.md` was NOT modified and stays `NOT-READY`.

---

## J. Exact remaining work

Each item: the single remaining root cause, the affected path, what was already tried, the missing
dependency, and the smallest next step. Order is by value.

### J-1 PhysicalPath / ControlPath internal model — NOT IMPLEMENTED

*Remaining root cause*: no first-class representation exists. `adapter.InboundContext.OutboundChain`
is a list of tags; nothing walks the resolved `detour` / `endpoint` / group graph into packet order, and
`protocol/chain` does not exist in this fork (it is LX's, and was deliberately not copied).

*Affected paths*: `common/dialer/detour.go` (`NewDialer`, `DetachedDialer`), `adapter/outbound/manager.go`,
`box.go`, `protocol/group/*`, `protocol/masque`, `protocol/socks`, `protocol/http`.

*Already established this session*: the direction question is answerable — a config `detour` X→Y means
Y is the dependency and X the consumer, so packet order is consumer → dependency, i.e. `#0` is the
outbound the flow's routing rule selected and `#N` is the last dependency reached.

*Next step*: a new `common/physicalpath` package with
`Build(root adapter.Outbound, selection SelectionSnapshot) (PhysicalPath, error)`, no io, no dials,
`Hops []Hop` in packet order, each hop `{Position, DeclaredTag, ResolvedLeaf, Type, IsEndpoint,
IsGroup, ControlOwner}`. Tests: 1-hop direct, 2-hop, 3-hop, group→leaf, nested group, group+detour,
endpoint leaf. The reverse-break is the prompt's own: record the control group as a physical hop and
require the test to be RED.

### J-2 Start-time all-reachable-leaf dry-run — NOT IMPLEMENTED

*Remaining root cause*: nothing enumerates reachable leaves. `protocol/group` materialises the SELECTED
member; the other members are never checked for constructibility at `Start`.

*Next step*: a read-only enumerator over the group graph (`ReachableLeaves(outbound) []LeafRef`,
attempting no dial and consuming no rotation cursor), then a `Start` stage that runs the J-1 builder
for every reachable leaf and fails with the full hop/tag chain. The cursor question must be pinned by a
test: a preview must not advance a round-robin cursor.

*Compatibility risk to check first*: `TestCrossKindDNSCycleIsRefusedAtStartup` and
`box_lifecycle*_test.go` already pin parts of the existing validation; read them before adding strictness
so existing valid configurations are not rejected.

### J-3 Per-hop status and error ownership — NOT IMPLEMENTED

*Next step*: after J-1/J-2, a read-only snapshot provider (`PhysicalPathStatus`) returning hops with
`state`, `selected_leaf`, `last_error`, `generation`, and a three-layer MTU block
(`inner_ip`, `inner_udp_ipv6`, `outer_quic_initial`) whose values are read from the real leaves and
reported `UNKNOWN` with a reason where the kernel cannot know them. No per-hop probe, no timer, no log
formatting on a hot path.

### J-4 HTTP CONNECT destination DNS ownership — NOT IMPLEMENTED, and it is the largest remaining
ownership gap

*Remaining root cause*: `protocol/http/outbound.go` writes its own authority string and does not go
through `protocol/socks`. The option added this session is read only by the SOCKS outbound, so an HTTP
CONNECT downstream hop STILL sends a hostname.

*Next step*: apply the same `resolveDestinationForDownstream` shape there, with the same fail-closed
rules and the same metadata pairing, and add a wire test against a real loopback HTTP proxy that decodes
the `CONNECT authority:port` line including the IPv6 bracket form. Do NOT assert "the string does not
contain the domain" — that passes for the wrong reasons.

*Missing dependency*: none. This is offline work.

### J-5 UDP ASSOCIATE / UoT wire form — PARTIAL

*What is done*: the packet path takes the ownership branch and fails closed (tested).

*Remaining root cause*: asserting the wire form needs a SOCKS5 server that answers UDP ASSOCIATE with a
usable relay port, because the client builds the request from the reply. The fixture used this session
answers CONNECT only, and the two attempts to reuse it produced `unexpected command 3` and a relay
address of `0.0.0.0` — reported rather than worked around.

*Next step*: extend the fake server to answer `05 00 00 01 <addr> <port>` with a real bound port, then
assert the request's ATYP and that per-datagram destinations in the UoT header are addresses too.

### J-6 Lifecycle / generation integration tests — NOT IMPLEMENTED

*Next step*: `group switch` vs `PhysicalPath` snapshot consistency, one-flow-one-member under
preview+commit, bounded whole-flow failover not multiplied by nesting, and close-order tests. Reuse
`box_lifecycle*_test.go` and `box_cross_kind_cycle_test.go` rather than writing a parallel harness.

### J-7 Cross-platform build matrix — NOT RUN

```text
linux/amd64    NOT_RUN
windows/amd64  NOT_RUN
darwin/arm64   NOT_RUN
android/arm64  NOT_RUN
```

*Next step*: `GOOS=<os> GOARCH=<arch> CGO_ENABLED=0 go build ./...` for each, plus the repository's
existing release profile for the minimal and full registries, recording the real exit code per target.
The Windows/darwin/Android results must be reported per target and never as one "builds" claim.

### J-8 Full test sweep and E2E — NOT RUN

*Next step*: `go test ./...` and a same-SHA comparison against the baseline for any failure, so
`PRE_EXISTING` is established rather than assumed. Then one box-level E2E:
`MemoryTun/mixed inbound → DNS Router → entry outbound → fake SOCKS5 → loopback echo`, asserting the
router's decision against the captured ATYP.

### J-9 External gates

```text
CI at FINAL_SHA      Actions state was not queried; if it is still disabled (HTTP 422), record it and
                     leave CI_NOT_RUN. Do not change repository settings to make it green.
Xray interop         needs a reference binary and a second endpoint.
WARP / IPv6 carrier  needs credentials and a capture environment; this is what would decide whether the
                     measured IPv6 fragmentation is carried or dropped.
ChromeParrot         a product decision: accept a local fingerprint change on a constrained IPv6
                     detour, authorise a patch to the pinned quic-go fork, or leave it as measured.
```

### J-10 One note on the mutation driver

`C:\Deepseek\内核\mutate.py` re-syncs a fresh copy of the tree before every mutation. This matters: the
first version reused one scratch tree, and a mutation reported NOT-RED because the tests in the scratch
tree were the previous mutation's. Any continuation should keep that behaviour, and should keep the
rule that a mutation is never applied to the real worktree.

Module-level mutations (G4) copy the dependency into the scratch tree and point a copy of `go.mod` at
it, then verify both that `go.mod` is byte-identical afterwards and that the module cache entry was not
modified. The module cache is read-only on this machine, and an overlay could not be used because
`go` refuses to overlay files under `GOMODCACHE`.
