# Jiejie MASQUE — Architecture Freeze and Dataplane Audit

This is the audit companion to `docs/JIEJIE-MASQUE-PERFORMANCE.md`, which holds the raw
measurements. This document states the frozen boundaries, the correctness gate that had to pass
before any measurement, the decisions taken, and what is deliberately left alone.

## HEAD

| | |
|---|---|
| `CORRECT_BASE_HEAD` | `0fadfc021` — confirmed clean, pushed, `origin/testing` in sync |
| Performance commits | `b5a25edd8`, `0127eee90`, `864c0048b`, `fad8101c5`, `d2f645df4` |
| Host | Apple M1, 8 cores, 8 GB, Darwin arm64 |
| Go | go1.25.5 |
| quic-go | v0.61.0-sing-box-mod.7 |

No `git reset --hard`, no `git clean -fdx`, no force push. The tree was clean at the start and
`origin/testing` was identical to HEAD, so the baseline is the previously pushed correctness fix.

## Architecture Boundaries (frozen)

| Module | Owns | Explicitly does NOT own |
|---|---|---|
| `protocol/masque` | sing-box endpoint integration, user option wiring, inner target resolution, immutable `DNS_ASSIGN` policy, PREF64 state, bootstrap policy, route/capability compilation | QUIC implementation, TLS implementation, H3 request stream lifecycle, congestion control implementation, raw UDP framing, DNS UDP/TCP protocol implementation |
| `transport/masque` | CONNECT-IP session, capsule encode/decode, ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT, IP packet ingress/egress, H3 Datagram use, capsule fallback, session lifecycle, packet ownership, MTU/PTB behaviour | server hostname DNS, global sing-box DNS policy, QUIC candidate selection internals, HTTP origin validation, generic H3 HTTP lifecycle |
| `transport/http` | HTTP/1, HTTP/2, HTTP/3, CONNECT semantics, CONNECT-UDP / Extended CONNECT, QUIC connection creation, TLS, congestion control, H3 `ClientConn` ownership, request stream semantics, ordinary HTTP request lifecycle | MASQUE packet or session policy |
| `DNS_ASSIGN` | immutable configuration + policy | a second DNS engine — execution reuses the native sing-box transports |
| same-H3 DoH | optional fast path | an architectural foundation, and never a reason to dial |
| `PREF64` | independent state | DNS64 synthesis |
| Bootstrap | MASQUE server discovery | `DNS_ASSIGN`, PREF64, same-H3 DoH — it knows none of them |

**Violations: NONE.**

Two places where a boundary was at risk this round, and how it was resolved:

- **The receive path's last allocation.** Removing it (~32 ns/packet) would have required narrowing
  `ClientHandler.WriteInboundBuffers`, which is the boundary to `transport/device` where both device
  implementations batch *runs* of packets. Not narrowed. See REJECT #4.
- **`packetAddresses`.** It calls `sing-tun` for header validation rather than reimplementing it,
  and was left as-is at 3–5 ns with 0 allocations rather than duplicating validation to save ~2 ns.

MASQUE hands `transport/http` a candidate ordering policy and nothing else. It never duplicates
`DialEarly`, TLS config, QUIC config, congestion control or `ClientConn` ownership — verified by
reading `bootstrap_race.go`'s `dialOne`, which takes the transport's own closure and states why.

## Correctness Gate

All five contracts passed on `0fadfc021` **before** any performance work, and again after.

| Contract | Evidence | Result |
|---|---|---|
| A. HTTP/3 proxy CONNECT | 200 → client writes → server receives → server writes → client receives, against a real quic-go HTTP/3 server | **PASS** |
| B. CONNECT-IP | 200 → capsule write → server receives → ADDRESS_ASSIGN → Ready | **PASS** |
| C. same-H3 DoH | tunnel stays alive; `RoundTripExistingHTTP3`; server-side connection count asserted `== 1` | **PASS** |
| D. generic H3 | GET / POST / body / non-2xx / cancellation / abandoned body | **PASS** |
| E. shared transport | Naive, `protocol/http`, `common/httpclient` | **PASS** |

Repeat stability: the lifecycle tests (`TestHTTP3CONNECTRemainsWritableAfter200`,
`TestHTTP3CONNECTIsBidirectional`, `TestTunnelAndDoHShareOneConnection`,
`TestSessionShutdownUnblocksABlockedWriter`, `TestIngressBufferOutlivesReceiveDatagram`) ran
**×20 consecutive** with no failure.

The tunnel tests write real payload after the 200 and read it back. A test that stops at the 200
passes against the broken code, so that rule is permanent.

## Optimization Experiments

| # | Name | Measured result | Decision |
|---|---|---|---|
| 1 | Per-packet `errors.As` allocation in `writePackets` | per-packet allocs 1 → **0**; batch-of-16 33 → 17 (−48%); B/op −10.0%; ns/op −8.6% (p=0.000) | **KEEP** |
| 2 | Binary-search route matcher | 16 routes −49%, 64 routes −80% (both p≤0.001); flat in route count; unchanged at 1 route | **KEEP** |
| 3 | Learned datagram ceiling (oversize) | oversize costs 400–690 ns / 6 allocs vs ~140 ns / 2. Rejected: quic-go's `maxPayloadSizeEstimate` only ever RISES, so a ratchet-down ceiling would permanently refuse packets the connection could later carry | **REJECT** |
| 4 | Per-session scratch slice for the device hand-off | 65 ns/2 allocs → 33 ns/1 alloc (~32 ns/packet). Rejected as a **data race**: `run()` starts `loopDatagram` alongside `loopCapsule`, and both call `handlePacket`. Also a boundary change | **REJECT** |
| 5 | `RoutesContain` micro-rewrite (hoist family check) | ~25% at 64 routes but noise at 16; adds a branch per route. Superseded by #2 | **REJECT** |
| 6 | Datagram capability re-check per packet | already decided once at session construction from SETTINGS | **NO CHANGE** |
| 7 | Racer orchestration benchmark | not honestly measurable without a real QUIC connection; once per connection; not a hot path | **NO CHANGE** |
| 8 | `packetAddresses` rewrite | 3–5 ns, 0 allocs; the suspected redundancy is a 2 ns call owned by `sing-tun` | **NO CHANGE** |
| 9 | DNS transport caching / per-query `NewUDPRaw` | not profiled as a hotspot; a cache would add lifetime, refcount and stale-socket complexity for no measured gain | **NO CHANGE** |
| 10 | Connection setup latency instrumentation | would measure the test machine's scheduler on loopback, not the protocol | **NOT DONE** |

Experiments 3, 4, 5 and 6 are recorded with their figures so the decisions are revisitable with
numbers rather than re-argued.

## Where the packet path stands

With the benchmark fixture removed, **no function in `transport/masque` appears in the outbound CPU
profile at all**:

| Path | Cost | Allocations |
|---|---|---|
| Outbound, 1400 B, fixture removed | **57–63 ns/op**, 22–24 GB/s | **0** |
| Outbound, 1280 B, full benchmark | ~129 ns/op | 2 (fixture's pooled acquisition) |
| Inbound, 1400 B | 54–70 ns/op, 12–26 GB/s | 2 (wrapper + device-slice) |

CPU is `runtime.kevent` (scheduler/syscall), `runtime.scanobject` (GC) and `runtime.madvise`.
Concurrent ingress and egress are **flat across 1/4/16 workers**, which is the evidence that
neither path takes a lock.

This is the task's stop condition: the hot path is dominated by quic-go and the kernel, so
optimisation ends here rather than continuing into complexity that would not show up in a profile.

## Locks

| Lock | Protects | Packet path | Contention |
|---|---|---|---|
| `Client.access` | session pointer, ready state | one acquisition per **call**, not per packet | none measured |
| `clientSession.access` | configuration writes | **no** — atomic snapshot read | n/a |
| `session.writeAccess` | capsule stream writes | only when capsules are used | none on the datagram path |
| `http3ClientImpl.access` | connection pointer / creation | **no** — not held for a request's lifetime | n/a |

Hot-path locks: **0 before, 0 after**.

## Goroutines and timers

One active session: the connection/session loop, the datagram receive loop when datagrams are
negotiated, and whatever quic-go owns. No goroutine per packet, per DoH query or per capsule.

No timer is created on either packet path — the only timers are the Happy Eyeballs fallback delay
and reconnect backoff, both per connection. `context.WithCancel` is not called per packet.

## Binary

| | Bytes |
|---|---|
| Before (`0fadfc021`, client tags) | 65,585,458 |
| After | 65,586,178 |
| Delta | **+720** (+0.001%) |

Unexpected dependencies: **NONE**. No module added, no feature re-added, no build-tag change, and
the Server Minimal graph is unchanged.

## Production

- Config modified: **NO** — SHA-256 `d2e3abf153195ae1cb9c3e84784839172ac09add0c89c5d19d46b72b27ebd09f`,
  identical before and after.
- `sing-box check` against the production config: **exit 0**.
- Production VPS contacted: **NO**. No SSH, no restart, no binary replacement, no `iperf`.

## Remaining Bottlenecks

Ordered by impact, with ownership stated:

1. **quic-go packet protection and framing** — dominant per-packet cost, inside the library. Not
   addressable here, and deliberately not worked around (§98: do not rebuild QUIC batching above
   quic-go).
2. **Kernel UDP + scheduler** — `runtime.kevent` in every profile.
3. **Inbound one-element slice** (~32 ns/packet) — measured, rejected for concurrency and boundary
   reasons. Revisit only if the `ClientHandler` contract changes.
4. **`buf.Buffer` wrapper allocation** (56 B/packet both directions) — upstream
   `sing/common/buf` design.
5. **`packetAddresses`** (3–5 ns) — near the floor for validating an IP header.

## Remaining Scope Boundaries

Endpoint-local `DNS_ASSIGN` only. PREF64 is state-only. No DoT, no DoQ, no DNS64 synthesis, no
global VPN DNS, no search-domain OS integration, no same-H2 DoH, no ECH, no cross-origin H3
coalescing, no new CLI, no new dashboard API, no new protocol option, no new server feature.

Feature development is stopped. This work reopens only for a production P0/P1 bug, a measurable
performance regression, an upstream API break, a substantive draft/RFC change, or a new production
requirement from the user.
