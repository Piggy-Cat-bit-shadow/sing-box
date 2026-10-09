# Phase 3 residual sweep (§10–§12)

Baseline `17b176a18`, branch `fix/residual-sweep`. Method per §10: LX and the previous rounds are
treated as a corpus of *proven failure modes*, never as patches to copy, and every candidate is
first re-asked "is this still reachable in the current tree" (§10.1) before it is classified.

| | |
| --- | --- |
| toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`), `TAGS=$(cat release/DEFAULT_BUILD_TAGS)` |
| suite at baseline | `go test -count=1 -tags "$TAGS" ./...` → **74 ok, 0 FAIL** |
| race at baseline | `-race` on the §21.2 packages → **11/11 ok, no data race** |
| builds | tagged **EXIT 0**, untagged **EXIT 0** |

## §10.1 — prior findings re-checked against the current tree

Not re-audited; each was confirmed *closed* (or re-scoped) before anything else was looked at.

| Prior finding | Current state | Evidence |
| --- | --- | --- |
| A network transition does not invalidate an in-flight blackholed dial | **fixed** | `route/dial_setup.go` — the per-generation `dialSetupGate`, advanced by `Reclaim`; ownership transfers at establishment. Commit `d8b190f76` |
| DNS-transport ↔ outbound cross-kind cycle validated by neither manager | **fixed** | `adapter/outbound/cross_kind_cycle.go` + real-config tests in `box_cross_kind_cycle_test.go` (both the refusing and the still-starts direction) |
| `common/trafficcontrol` connection-list race had no test | **covered** | `common/trafficcontrol/manager_race_test.go`, 512 trackers, exact-total equality under `-race` |
| sing-tun 040: the system stack's accept loop dies on one accept error | **fixed, in the dependency** | the `replace` in `go.mod` pins `sync/go-stack-plus-040-and-race`, and the comment records the red probe. Verified by reading the pin, not by assuming the earlier note |
| WireGuard sniffed as uTP | **fixed** | `common/sniff/wireguard.go`, `packet_sniffer_wireguard_order_test.go` |
| `runtime routing cycle`, `interrupt` ABBA, Tailscale 111, gRPC `service_name` | **closed** (detailed in `lx-residual-bug-sweep.md`) | not re-derived |
| `TestHTTP1PacketUp` flaky under `-count=60` | **reproduced and fixed** — see R2 | it was *not* reproducible at `-count=60`; it needed `-count=200` |

## Findings

Each entry carries §11's fields. Severity is the release's own vocabulary (P2 = proven, root-caused,
bounded fix; P3 = local, clear behaviour, regression, low risk).

---

### R1 — Five `utls.fingerprint` names cannot complete a REALITY handshake against a current reference

| | |
| --- | --- |
| **failure mode** | the client's ClientHello carries no `X25519MLKEM768` share, so a REALITY reference at or after Xray v26.9.8 does not authenticate it, answers with the camouflage site, and the client reports a verification failure indistinguishable from a wrong public key |
| **current reachability** | **REAL.** `fingerprint: firefox`, `safari`, `edge`, `ios`, `qq` with a REALITY outbound; also `random`, whose draw is hybrid-less 4 times in 5. Measured end to end against a real Xray v26.9.30 |
| **root cause** | the pinned `metacubex/utls v1.8.7` resolves those names to pre-ML-KEM presets (Firefox 120, Safari 16.0, Edge 85, iOS 14, QQBrowser 11.1). The three upstream commits that add Firefox 148 and Safari 26.3 (`fc716b2`+`ddebe39`, `aa6edf4`) are not in the pin, not in `v1.8.8` (newest release), and only in `v1.9.0-mod-meta`, which is a 175-commit rebase |
| **current protection** | `reality.key_share: hybrid` refuses such a fingerprint with a named error instead of silently downgrading — but the DEFAULT (`key_share` absent) silently fails. `common/tls/reality_fingerprint_register_test.go` now classifies every accepted name and pins the incompatible set |
| **action** | **FIX** — minimal fork prepared and verified; landing is an owner action (no push from this worktree). Scope honestly re-measured as five names, not the two §13 named |
| **regression** | `common/tls/reality_fingerprint_register_test.go` (3 tests, exhaustive by construction); live scenarios `reality-firefox`/`reality-safari` in `test/interop` |

Detail, evidence and the fork patch: [`utls-fingerprint-decision.md`](utls-fingerprint-decision.md),
`docs/fork/utls-firefox148-safari263.patch`.

---

### R2 — `TestHTTP1PacketUp` asserted a schedule, not a property (flaky gate on the XHTTP transport)

| | |
| --- | --- |
| **failure mode** | the gate fails on a schedule that is correct HTTP, so a correct build reports red. It is the transport this fork ADDED, so a flake here is read as an XHTTP regression |
| **current reachability** | **REAL and reproduced 3 times.** `-count=200` failed twice; an instrumented run caught it at iteration 12 with the schedule `[POST@A, GET@A(close=true), POST@B, POST@B]` → "2 connections for 3 POSTs" |
| **root cause** | the dial dispatches the download GET from its own goroutine, and the first `Write` races it into the same `http.Transport` pool. When the POST wins, the GET reuses the POST's connection, and because the GET is *correctly* sent with `Connection: close` the transport retires that connection, so the remaining POSTs legitimately need a second one. The assertion ("all three POSTs on one TCP connection") is only true of the other ordering |
| **current protection** | none: the test raced at ~1 in 200. It is not a product defect — every request succeeded, no bytes were lost, and a real reference withholds the GET response until the first uplink packet, which is the ordering the test now waits for |
| **action** | **FIX (TEST-ONLY)** — the assertion is unchanged; the precondition is made deterministic (`server.waitRequests(t, 1)` before the first write), and the comment records the losing schedule and why it says nothing about reuse |
| **regression** | the same test: `-count=300` ok (old code failed at ~200), `-count=60 -race` ok |

**Red-check, both directions.** Old code, `-count=200`: `--- FAIL: TestHTTP1PacketUp (0.06s)` /
`upload POSTs did not reuse the connection: 127.0.0.1:52019 vs 127.0.0.1:52018`. And the gate still
detects the failure it exists for: making the stub answer POSTs with `Connection: close` — so no
keep-alive reuse is possible — fails it deterministically on every iteration, which is what proves
the fix removed the race rather than the assertion.

---

### R3 — `metadata.OutboundChain` names the failed primary after a successful failover

| | |
| --- | --- |
| **failure mode** | the connection listing (Clash API `chains`, libbox) attributes a live connection to the member that failed, not the alternate that carries it |
| **current reachability** | **REAL but diagnostics-only.** Any `loadbalance`/`urltest` flow that fails over |
| **root cause** | `protocol/group/loadbalance_failover.go` moves the flow and logs it, but nothing republishes the chain; and the tracker snapshot is taken *before* the dial both in the pre-match path (`route/route.go`'s `metadataCopy := *metadata` → `result.NewTracker`) and in `RouteConnection` (`tracker.RoutedConnection` wraps the connection before the outbound dials), so patching the group's metadata would not reach either reader |
| **current protection** | `metadata.RouteOutbound` and the group's own `Info` log name the move. The class is "wrong label", never wrong routing: the alternate really is used |
| **action** | **DEFER** to 0.1.7. It is not local: making the chain correct needs the publish model to say what a chain names when attempts differ, and to move the tracker snapshot after the dial — a route/failover change, not the local edit §12's P3 requires |
| **regression** | none; recorded, not pinned |

---

### R4 — two `ReclaimReason` values are unreachable from production code

| | |
| --- | --- |
| **failure mode** | none — a policy row nothing can select |
| **current reachability** | `ReclaimIdle` and `ReclaimShutdown` are passed only by tests (`route/conn_reclaim_test.go`, `route/dial_governor_test.go`); production passes only `ReclaimNetworkTransition` and `ReclaimDeadPath` (`route/network.go`) |
| **root cause** | the reason type is deliberately wider than the current call sites: the comment records that the distinctions are kept explicit rather than implied by which method a caller happened to use |
| **current protection** | n/a — no failure mode follows |
| **action** | **DEFER** (cleanup, not a fix; removing rows during a freeze is churn) |
| **regression** | the existing tests exercise both rows |

---

## Checked and clean (no finding)

Recorded so the next sweep does not redo the work; each was examined for a concrete failure mode and
none was found.

| Area | What was checked |
| --- | --- |
| `-race` on the §21.2 package list | `common/sniff`, `route`, `route/rule`, `common/interrupt`, `protocol/group`, `protocol/tun`, `transport/http`, `transport/v2rayxhttp`, `transport/wireguard`, `experimental/libbox`, `common/power` → 11/11 ok, no `DATA RACE` |
| `go vet -tags "$TAGS" ./...` | two findings, both intentional: `daemon/managed_service.go` and `experimental/libbox/debug.go` dereference a nil pointer on purpose, behind a debug gate, as crash-trigger probes |
| `common/listener/listener_tcp.go` accept loop | temporary errors back off (5 ms doubling to 1 s) and a fatal error closes the listener explicitly — not the sing-tun-040 shape |
| `route/conn_reclaim.go` drain + sweep | `sweepTimer` re-arm is guarded by `closed`, `stopDrainSweep` runs before `CloseAll`, and a kernel-owned (spliced) connection is deliberately never drained by a transition; the `idleFor` "cannot be proven idle" answer is the right one, and the never-used-UDP-flow leak it replaced is pinned by tests |
| `protocol/group/urltest.go` forced-retest worker | the 1 ms sleep is a bounded handoff wait off the traffic path, with a comment naming why it is not a spin |
| `common/power/governor.go`, `box_lifecycle.go` | state machine and reuse epoch read; no unbounded wait, no resurrection after Close, and the Apple "display on is not an unlock" asymmetry is implemented as documented |
| `test/interop` validation suite | re-run offline after the fingerprint axis was added; scenario matrix, JSON shape and parser round trip all pass |

## Counts

**FIX 1** (R1 — dependency; landing owner-gated) · **FIX (TEST-ONLY) 1** (R2) · **DEFER 2**
(R3, R4) · **N/A** for everything in "checked and clean".

No P2/P3 item from §12's "must not be added" list was touched: no new protocol, transport, config
model, API redesign, UI feature, module replacement, or speculative abstraction.
