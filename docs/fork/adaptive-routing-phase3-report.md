# Phase 3 report — adaptive routing and resilience

Engineering record for the routing/recovery layer: live dial failure feedback and bounded failover,
DNS transport groups, and the MASQUE adaptive fallback. The model is `adaptive-routing-phase3.md`.

## 1. Baseline and final state

| | |
| --- | --- |
| Branch | `testing` |
| Baseline HEAD | `2b47425dd` — end of the protocol compatibility phase |
| Toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`) |
| Dependency forks | `Piggy-Cat-bit-shadow/sing-tun` (040), `Piggy-Cat-bit-shadow/gvisor` (048) — untoched |
| New forks / new dependencies / new `replace` directives | **none** |
| Reference | `Leadaxe/sing-box-lx` at `a97658c1` (`v1.14.2-lx.12`) |

## 2. Summary

| Item | Status | Regression coverage | Generation behaviour | Known limitations |
| --- | --- | --- | --- | --- |
| Live dial failure classifier | implemented | 18-case table incl. wrapped errors; refused/reset/cancel neutral | n/a | none |
| Live failure feedback (penalty) | implemented | below-threshold order unchanged; threshold engages the filter | table carries the epoch; a foreign epoch is ignored and replaced | never live-verified |
| Bounded one-alternate retry | implemented | 10-member all-failing pool makes exactly 2 attempts; same caller ctx | n/a | `ListenPacket` never retried, by design |
| Proof-of-life recovery | implemented | a later success clears the record and the member competes again | n/a | none |
| Penalty TTL (2m) | implemented | expires with no timer having run | lazy comparison | reference has none; added deliberately |
| Forced-retest valve | implemented | throttle measured from the end of the previous run; CAS collapses concurrent runs | n/a | the real health round is not asserted, only the throttle |
| `round_robin` preserved | implemented | rotation order unchanged when healthy | n/a | — |
| `consistent_hashing` preserved | implemented | same key → same member when healthy; one demoted member does **not** remap every key | n/a | — |
| `sticky_sessions` preserved | implemented | live flow never migrated; the pin moves only after a fallback succeeds | n/a | — |
| Traffic-class / pool isolation | implemented (structural) | failover stays inside the configured list; nested failover stays inside the nested list | n/a | a loadbalance nested under a non-capability group gets no route-level failover |
| DNS group `stable` | implemented | sticky reuse; rescue fan on failure; a recovered ex-member is not auto-returned | `Reset()` clears records + current, bumps a private gen | no live upstream |
| DNS group `fastest` | implemented | cold start elects once; win expiry re-elects; a winner error erases its wins | as above | no live upstream |
| DNS group `parallel` | implemented | fans every query, mints no wins | as above | no live upstream |
| DNS single-flight election | implemented | a burst of 8 concurrent queries performs exactly one fan (deterministic) | as above | — |
| DNS all-dirty anti-storm | implemented | one attempt, **no fan**, in every mode incl. `parallel` | as above | — |
| DNS winner/error TTL | implemented | error TTL returns a member to clean, lazily | lazy | — |
| DNS cycle + missing member | **already covered by the existing manager** | nested group starts; a cycle is rejected with `circular server dependency` | n/a | detected at start, which is config time for `sing-box run` |
| DNS synthetic-member exclusion | implemented | `fakeip`/`hosts` rejected at Start | n/a | criterion re-derived from the registered types |
| MASQUE bounded H3 window | implemented | window expiry falls back while the caller is alive; expiry is remembered; caller cancel is neutral; refusal path unchanged | window is per-dial; the verdict memory is cleared on a network change | no live peer |
| MASQUE remembered verdict | **already generation-scoped** | verdict is time-bounded (5s→5min) and cleared by `RestartSession`/`Suspend` → `ResetConnections` | yes, via `InterfaceUpdated` | the tunnel's own generation-level assertion is a gap (below) |
| MASQUE UDP fragmentation (028) | implemented | the tunnel dialer options carry the default; an explicit `udp_fragment` still wins | n/a | the socket flag is not asserted; loopback cannot reproduce the MTU failure |
| Runtime lifecycle reuse | implemented | no second coordinator; all new state is `Close`-cancellable | uses the Phase 1.5 epoch | — |
| No-background-wake | preserved | Phase 1.5's probe-origin tests still pass | n/a | — |

## 3. LX lineage

| Item | Status | Why |
| --- | --- | --- |
| **TASK 054** URLTEST_PENALTY_FAILOVER | **ADAPTED** | The transferable core was taken: the path-dead classifier, `+1` penalty, exactly one alternate with a **re-run** of selection, proof-of-life-only recovery, a forced-retest valve throttled from the end of the run with a CAS. Two things were deliberately changed. (a) The reference keeps penalties **forever** and scopes them to nothing, and it classifies `ENETUNREACH`/`EHOSTUNREACH` as path-dead — so a Wi-Fi→cellular handover, which produces exactly those errors, permanently demotes every member dialled during it. Here the table is generation-scoped and TTL'd. (b) The reference attaches this to `type: urltest` because its base had no balancer; this fork already had a `loadbalance` group with its own strategies, so the layer was attached there and the strategies were left alone. |
| **FEATURE 007** URLTEST_BALANCE | **N/A** (design) + **ADAPTED** (lessons) | The feature's substance is LX's slot-pool: `balancer.pool` / `pool_tolerance` / `sticky_hash` and a `slot[hash(key)%pool]` binding. It exists because LX's base had no hashing ring at all, and LX's own journal records it as a *substitute* after rejecting jumphash and HRW. This fork already has `consistent_hashing` and `sticky_sessions`, so grafting a fixed slot pool on top would be a second, conflicting pinning mechanism. Not taken. What **was** taken is the feature's design lesson, recorded in its own journal: keep the selection policy in an explicit mode and the energy knob separate — never let "skip probes" imply "hold the node". `failover` as a *mode* is N/A here: the LoadBalance group already keeps a committed selection and only moves on evidence. |
| **FEATURE 013 / TASK 033** DNS_GROUP | **ADAPTED** | The record model, the three modes, the single `fan` primitive, the election single-flight flag, the all-dirty survival rule, the lazy-TTL design and the `maxRecords` cap were ported. Four things were **not**: the `OutboundTag()` addition to `adapter.DNSTransport` (it exists only for the reference's observability stream, and widening a shared interface for a log line is not acceptable), `common/dnstrack` with its command/RPC/proto/libbox surface, `GroupState`/`MemberState`, and `lastRTT`. One reference behaviour was changed: fan losers are cancelled and a cancellation we caused is never recorded as a member failure — the reference let them run to completion and late-heal. |
| **TASK 018 / 035** DNS_QUERY_STREAM + OBSERVABILITY | **N/A** | The command-multiplex DNS query stream and the `GetDNSGroups` RPC are part of an observability subsystem explicitly out of scope for this phase. |
| **TASK 046** DNS_HIJACK_PACKET_LOOP_STALL | **ALREADY COVERED** (Phase 1) | The hijack-concurrency bound (`route/dns.go`, `dnsHijackConcurrency`) is in the tree with its own tests. Not bundled into the group port, as the reference's own spec says they are separate changes. |
| **FEATURE 009 / TASK 074** MASQUE auto | **ALREADY COVERED, differently** | The reference puts the H3/H2 decision in `protocol/masque` with a detached leg goroutine and a 3s wall-clock decision timer, preferring the leg that wins and remembering it. This fork's MASQUE builds on upstream 1.15 and the decision lives in `transport/http` as a sequential, bounded fallback governed by one sentinel (`ErrHTTP3Unavailable`), with `TunnelTransport` reported from the branch that succeeded. The reference's own spec **rejects happy-eyeballs** and accepts up to one zombie goroutine per process as the cost of detaching; the sequential form has neither. The genuinely missing piece was identified and fixed: the H3 attempt had **no window of its own**, so the fallback was unreachable against a blackholed UDP path. |
| **TASK 108** MASQUE_UNBOUNDED_WAITS | **ALREADY COVERED** + one **FIXED** | Of the three hazards: (1) *irreversible H2 win* — the fork's verdict is time-bounded (`http3Broken` 5s doubling to a 5min cap, cleared on success) and cleared on a network change by `InterfaceUpdated` → `RestartSession`/`Suspend` → `ResetConnections`, which is strictly stronger than the reference (whose `autoNetwork` has no generation check and no bound, and whose H3 is never re-probed while the remembered H2 keeps succeeding — an acknowledged open item there). (2) *H2 `Close()` behind a stuck writer* — structurally absent: this fork does not hand-roll HTTP/2 framing, and `clientStreamConn.Close` takes no lock. (3) *context-free H3 `ReadResponse`* — already bound via `context.AfterFunc` → `CancelRead`/`CancelWrite`, pinned by the existing retry-boundary tests. The one thing the reference had that this fork did not was the **bounded H3 attempt**, which is what makes (1)'s fallback reachable at all; that is now implemented. |
| **TASK 028** NESTED_TUNNEL_UDP_FRAGMENT | **APPLICABLE → FIXED** (MASQUE half only) | This was a real, unabsorbed defect, not a test-only item. `common/dialer` forbids IP fragmentation by default; the MASQUE tunnel's dialer was built without refusing that default, so the QUIC UDP socket was DF-forced and an over-MTU datagram died silently. The AWG half (`protocol/wireguard/endpoint.go`) and the AWG-over-AWG end-to-end stand are **N/A here** — this fork's `wireguard` endpoint is not the reference's, and the reference's own note is that loopback cannot reproduce the failure anyway. |
| **TASK 107 / 110** MASQUE upstream comparison | **N/A** | Comparison documents, not changes. |

One **correction to a previous phase's documentation**, found while doing this audit and fixed in
both places: `docs/fork/runtime-lifecycle-phase1.5-report.md` and the comment in
`common/httpclient/managed_transport_reset_test.go` attributed the MASQUE tunnel's H3-verdict reset to
`ManagedTransport.Reset`. The tunnel does **not** use `common/httpclient` — it builds a
`transport/http.Client` directly, and its verdict is cleared by `RestartSession`/`Suspend` →
`ResetConnections()`. Same outcome on the same transition, wrong component; the code was correct, the
prose was not.

## 4. Validation

| Check | Result |
| --- | --- |
| `gofmt -l cmd include option protocol route service transport common dns adapter box.go` | clean |
| `go mod tidy -diff` | clean |
| `go test -tags <release> ./...` | **61 packages ok** |
| `common/tlsfragment` (3 tests) | pre-existing, environment: no external network |
| `experimental/libbox` | pre-existing: test-binary-only `runtime.fwdSig` link error under `badlinkname` |
| `-race` on `protocol/group`, `route`, `adapter`, `dns/…`, `protocol/masque`, `transport/http`, `common/httpclient`, `common/runtimecoord` | all ok |
| New test counts | LoadBalance failover 18 + 8 route-level; DNS group 26 (34 with subtests); MASQUE 5 + 5 |

**One flake was found and fixed rather than tolerated.** `TestFastestColdStartElectsOnceUnderConcurrency`
passed in isolation and failed in one full-suite run: it parked *every* member call until a barrier,
so its exact call-count assertion could be evaluated against a burst that had not fully formed under
load. It now parks only each member's **first** call (the election fan), which keeps the fan
concurrent with the burst while making the count timing-independent. Verified over six consecutive
runs.

## 5. Performance counters

| Property | How it is bounded |
| --- | --- |
| 10 members, all dials failing | exactly **2** dial attempts, asserted |
| 8 concurrent DNS queries at cold start | exactly **1** election fan, asserted deterministically |
| DNS with every member dirty | exactly **1** attempt and **no** fan, in every mode, asserted |
| Penalty state when idle | one atomic pointer read; no timer, no goroutine, no lock |
| DNS record memory on a dead network | capped at 64 entries per member, asserted |
| 10 `ResetNetwork` calls | no MASQUE full rebuild storm: the verdict clear is idempotent and the pool teardown is deferred |

New polling goroutines added: **none**. New timers added: **none** (the H3 window is a
`context.WithTimeout` inside a dial, and the retest valve is a CAS plus a timestamp).

## 6. Build matrix

| Target | Result |
| --- | --- |
| main release binary | builds |
| linux/amd64, darwin/arm64, windows/amd64 | builds (with the pre-existing `with_naive_outbound` cronet and Windows `badlinkname` exclusions) |
| darwin/arm64 `with_low_memory` | builds |
| android/arm64 libbox `with_gvisor` | builds |
| `with_xhttp` / `with_xhttp` + `with_quic` | unchanged from Phase 2 — the Phase 2 suites and the build-tag invariants still pass |
| existing tripwires | `verify-upstream-assumptions.sh` PASS; 040 and 048 fork guards PASS (both forks untouched) |

## 7. Dependencies

**None changed.** No new module, no new `replace`, no fork. `go mod tidy -diff` is clean and both
dependency forks are byte-identical to the previous phase.

## 8. Documentation

- `docs/fork/adaptive-routing-phase3.md` — the model.
- `docs/fork/adaptive-routing-phase3-report.md` — this file.
- `docs/fork/load-balance.md` — updated for the always-on failover policy.
- `docs/fork/runtime-lifecycle-phase1.5-report.md` — the attribution correction above.

## 9. Git

Seven logical commits on `testing`. The final HEAD and the remote sync state are reported in the
session summary, because this file is written before the push. `clients/apple`,
`build-screens-doc.py` and `capture-screens.sh` are never staged.

## 10. Unresolved risks

1. **Nothing here is live-verified.** No Xray server, no DNS upstream, no real network handover, no
   device. Every claim is from in-process tests. This is the largest caveat in the phase.
2. **The DF/fragmentation fix is not reproduced end to end.** Loopback's MTU is large enough that the
   leg never over-sizes, which is the reference's own recorded reason for not being able to test it
   either. The test pins the default being set; it does not pin the socket flag.
3. **Two route paths deliberately bypass failover**: a flow with more than one candidate address, and
   a member implementing `ConnectionHandler`. Both preserve one-member-per-flow at the cost of not
   failing over there.
4. **A loadbalance nested under a non-capability group** gets no route-level failover; only its
   selection runs. Nested failover *is* covered when a capability group is a member of another
   capability group.
5. **`preMatchFlow`'s committing resolution dials the leaf directly**, so failover is bypassed for a
   `PreMatchFlow` verdict.
6. **The forced-retest valve's real health round is not asserted** — only its throttle. Its call into
   a live `URLTestGroup` round is therefore unverified.
7. **`metadata.OutboundChain` still names the primary attempt after a successful fallback.** Trackers
   have already run by then, so a successful failover is slightly misattributed in connection
   metadata.
8. **The DNS group has no parsed-config end-to-end test.** That a group is accepted as `dns.final` or
   named by a rule is structural (registry registration, tag lookup, and `Dependencies()` keeping the
   members referenced) and was reviewed, but not exercised through a parsed configuration.
9. **The DNS group has no live-upstream verification**, and the reference's own live evidence is a
   single loopback test.
10. **The MASQUE tunnel has no generation-level assertion of its own.** The verdict reset is covered
    at the `transport/http` and `ManagedTransport` levels; a test that drives the tunnel endpoint's
    own HTTP client through an epoch advance and asserts the H3 verdict is cleared is still owed.
11. **Penalty state is keyed by member tag and is not destination-aware.** One blocked destination
    hit insistently by a client can demote a member for every flow. The reference accepts the same
    ambiguity by owner decision, and deduplicating by destination would need a per-destination table
    this phase did not introduce.

## 11. Recommended next step

The highest-value follow-up is item 10 combined with item 1: a local stand that drives a real
`box.New`/`Start` through a simulated generation advance with a MASQUE endpoint and a DNS group
configured, asserting the verdict resets, no probe storm occurs, and the goroutine count returns to
baseline. That would convert several "unit tested" rows in §2 into "combination tested", and it is the
only path from here to "live interoperable".
