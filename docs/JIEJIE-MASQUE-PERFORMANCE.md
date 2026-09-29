# MASQUE performance

Measurements for the MASQUE data plane. Every number here was produced by a
benchmark in this repository, on the machine named in each section. Anything not
measured is labelled **NOT TESTED** rather than estimated.

Environment for every measurement in this document unless stated otherwise:

```text
host   Apple M1, darwin/arm64
go     go1.25.5 darwin/arm64
quic   github.com/sagernet/quic-go v0.61.0-sing-box-mod.7
```

Method: `benchstat` where a before/after comparison is claimed, with the sample
count recorded. A change is only described as an improvement if `benchstat` reports
a statistically significant delta.

Sections 7-9 were added in the performance-hardening round based on `0fadfc021`
(Apple M1, `-count 10` for the headline comparisons). Section 3 was REVISED in that
round: it previously concluded the linear route scan should stay, based on helper
benchmarks that measured the scan without measuring the packet-path budget it was
spent from. Both the original numbers and the reason for the change are kept there.

This round also produced a full boundary and bottleneck audit in
`docs/JIEJIE-MASQUE-PERFORMANCE-AUDIT.md`.

## Re-verification, 2026-09-28 (commit e07ffdb2b + this cycle)

Every headline number below was re-measured on the same host and Go version, at a
later commit, to check that the recorded deltas still hold rather than having been
captured once and carried forward. The benchmarks themselves are unchanged.

```text
claim                        recorded    re-measured    verdict
IngressBuffer geomean         -56.69%      -56.5%       VERIFIED
  /64B                        -47.13%      -47.0%       VERIFIED
  /256B                       -50.16%      -51.1%       VERIFIED
  /1280B                      -62.01%      -64.4%       VERIFIED
  /1400B                      -64.84%      -61.1%       VERIFIED
SessionConfigRead             -95.25%      -95.56%      VERIFIED
  mutex read (uncontended)     94.065n      91.935n     VERIFIED
  atomic snapshot read          4.472n       4.082n     VERIFIED
  mutex read (contended)      105-112n      105.500n    VERIFIED
```

Method: `go test -bench -benchmem -benchtime 200000x -count 10` per size for the
buffer comparison, `-benchtime 2000000x -count 8` for the session reads; medians
compared directly (`benchstat` was not usable in this environment, so the medians
and the geomean of the per-size ratios are reported rather than a p-value). The
per-size deltas agree with the recorded ones within run-to-run variance, so the
recorded numbers were not stale.

**The throughput line below (+163% / +184%) is derived from the same `ns/op` run
and is MICRO-benchmark throughput** - it is not a real-network measurement and must
not be read as one. No real-socket or real-VPS throughput figure is claimed
anywhere in this document.

---

## 1. HTTP/3 datagram ingress: the per-packet copy

### What the code did

`transport/masque/session.go`, `loopDatagram`:

```go
datagram, err := s.datagrams.ReceiveDatagram(s.ctx)
...
headroom := s.packetHeadroom()
buffer := buf.NewSize(headroom + len(datagram) - contextLength)
buffer.Resize(headroom, 0)
common.Must1(buffer.Write(datagram[contextLength:]))
s.handler.handlePacket(buffer)
```

Every received datagram was copied into a freshly acquired pooled buffer, on top of
the copy quic-go had already performed:

```text
quic-go ReceiveDatagram   (make + copy inside datagram_queue.HandleDatagramFrame)
        ↓  []byte
DecodeVarint
        ↓
buf.NewSize               (pool acquisition)
buffer.Write(payload)     ← full-packet memcpy, the cost removed here
        ↓
TUN / MASQUE consumer
```

### Ownership analysis

Before removing the copy, the ownership question had to be answered from the pinned
quic-go source rather than assumed, because wrapping a transport-owned scratch
buffer would be a use-after-free:

```go
// datagram_queue.go
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
    data := make([]byte, len(f.Data))
    copy(data, f.Data)
    h.rcvQueue = append(h.rcvQueue, data)
}
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
    data := h.rcvQueue[0]
    h.rcvQueue = h.rcvQueue[1:]
    return data, nil
}
```

So the returned slice is an **independent per-datagram allocation**, the receive
queue drops its own reference before returning, and the backing array is never
reused. Ownership is transferred to the caller.

| question | answer |
|---|---|
| who creates it | quic-go, `make` + `copy` per datagram |
| who holds it | the session, from `ReceiveDatagram` returning |
| who releases it | whoever consumes the buffer calls `Release()` |
| when invalid | never by quic-go; the array is not recycled while alive |
| async use | permitted — the allocation outlives the transport's reference |

`buf.As` wraps it as an **UNMANAGED** buffer, so `Release()` cannot return quic-go's
memory to sing's pool. A managed buffer here would let a later `buf.Get` hand the
same bytes to an unrelated code path: memory corruption, not a leak.

This is the same verified pattern `transport/http/capsule.go` already used for the
CONNECT-UDP ingress. The MASQUE session path had simply not been updated to match.

### Result

`BenchmarkIngressBufferCopy` vs `BenchmarkIngressBufferWrap`,
`benchstat`, `-benchtime 200000x -count 10`:

```text
                      │  copy (old)  │        wrap (new)        │
IngressBuffer/64B-8     35.65n ± 49%   18.84n ±  1%  -47.13% (p=0.000 n=10)
IngressBuffer/256B-8    38.23n ±  5%   19.05n ±  4%  -50.16% (p=0.000 n=10)
IngressBuffer/1280B-8   51.91n ±  1%   19.72n ±  4%  -62.01% (p=0.000 n=10)
IngressBuffer/1400B-8   53.87n ±  3%   18.94n ±  5%  -64.84% (p=0.000 n=10)
geomean                 44.18n         19.14n         -56.69%
```

Throughput at the MTU-sized payloads, same run:

```text
IngressBuffer/1280B-8   22.96Gi ± 1%   60.45Gi ± 4%   +163.23%
IngressBuffer/1400B-8   24.20Gi ± 3%   68.85Gi ± 5%   +184.45%
```

`B/op` and `allocs/op` are **unchanged** at 64 B/op and 1 alloc/op: the
`*buf.Buffer` header is still allocated in both strategies. What was removed is the
pool acquisition and the memcpy, not the header. Stating this plainly matters — a
reader who expected allocs/op to drop would otherwise conclude the change did
nothing.

### A benchmark that was wrong, and was fixed

The first version of these benchmarks drove the whole session per iteration. It
reported **19 allocs/op for both** strategies, because roughly 2 µs of fixture setup
— goroutine creation, channel handoff, session construction — swamped a ~35 ns
difference.

That benchmark is kept as `BenchmarkDatagramIngressEndToEnd`, but only as an
integration guard that the real path still runs. The comparison above is a direct
A/B with no harness in the way. This is recorded because the failure mode is easy
to repeat: a benchmark that measures the harness cannot measure the change.

### Tests

`transport/masque/ingress_ownership_test.go` covers the ownership rules the change
depends on:

| test | invariant |
|---|---|
| `TestIngressBufferIsUnmanaged` | `Release()` does not pool quic-go memory |
| `TestIngressStripsOnlyTheContextID` | payload delivered byte for byte |
| `TestIngressBufferOutlivesReceiveDatagram` | ownership transfer survives a replayed source |
| `TestIngressAsyncUseIsSafe` | buffers valid after the ingress loop exits |
| `TestIngressBareContextIDIsSkipped` | a lone context ID is malformed, not an empty packet |
| `TestIngressMalformedFramesAreSkipped` | bad frames skipped; session survives |
| `TestIngressCloseDuringReceiveIsClean` | cancellation ends the loop, delivers nothing extra |
| `TestIngressConcurrentReceiveDeliversExactlyOnce` | no aliasing under concurrent receive |
| `TestIngressReleaseDoesNotRecycleQuicGoMemory` | pool churn cannot hand quic-go's pages back out |

`TestIngressBufferIsUnmanaged` was written to assert `Managed()`, which does not
exist in the sing API. It now asserts the observable behaviour instead: an
UNMANAGED `Release()` leaves the struct intact, while a MANAGED `Release()` zeroes
it. The contrast against `buf.NewSize` is what stops the assertion being vacuous.

`TestIngressBareContextIDIsSkipped` corrected a wrong assumption of mine rather than
a bug. I wrote it expecting a bare `{0x00}` datagram to be delivered as an empty
packet. It is not: `DecodeVarint` consumes the byte and reports
`contextLength == 1`, so the pre-existing guard `len(datagram) == contextLength`
skips it. Verified unchanged from the previous revision
(`git show HEAD:transport/masque/session.go` carries the identical guard). The
behaviour is defensible — RFC 9297 requires a context ID *and* a payload, so a lone
context ID is malformed — and the test now pins it as deliberate.

---

## 2. Session state on the packet hot path

### What the code did

Configuration is written **rarely** (on an ADDRESS_ASSIGN or ROUTE_ADVERTISEMENT
capsule) and read on **every packet**:

```go
// TX, once per packet batch
current.access.Lock()
configuration := current.configuration
ready := current.ready
current.access.Unlock()

// RX, once per received packet — the hottest read in the tunnel
s.access.Lock()
configuration := s.configuration
s.access.Unlock()
```

### Measured before changing it

A mutex fast path is only a few nanoseconds, so the replacement was measured before
being written:

```text
BenchmarkSessionConfigRead   sec/op
  mutex read                  94.065n ± 7%
  atomic snapshot read         4.472n ± 103%
  vs base                    -95.25% (p=0.000 n=8)
```

`B/op` and `allocs/op` are 0 for both.

The contended variant measured 105–112 ns/op — the **same** as uncontended. So the
cost is fast-path overhead rather than futex traffic. That is why this is worth
doing even though a single tunnel has little lock contention, and it is the honest
framing: this is not a contention fix.

### Result

An immutable `sessionState` published behind `atomic.Pointer`:

| | |
|---|---|
| creator | `publishStateLocked`, always under `access` |
| holder | any reader via `loadState`, never blocking |
| released | never; GC'd once unreferenced |
| invalid | never; a snapshot is not mutated after publication |
| async | safe by construction — a loaded snapshot is a complete value |

`access` is **kept** for the write side and for the compare-then-publish sequences,
so read-decide-write logic stays atomic against other writers. Only the read side
became lock-free.

The invariant that makes a shallow `Configuration` copy sufficient: writers always
**assign whole values**, never append into a slice a previous snapshot published. An
append could write into an array a concurrent reader is still reading.

### Tests

| test | invariant |
|---|---|
| `TestSessionSnapshotDoesNotAliasPublishedSlices` | no shared backing array across snapshots, over sizes that do and do not force reallocation |
| `TestSessionSnapshotReadIsConsistentUnderConcurrentPublish` | no torn field pairs (never `ready` with no addresses) |
| `TestSessionSnapshotIsLockFreeOnThePacketPath` | `loadState` does not block while `access` is held |

---

## 3. Route containment: helper cost, then the real path, and a matcher

This section originally concluded that the linear scan stays. That conclusion was reached from the
HELPER measurements below, which are correct but answer a narrower question than they appear to:
they measure the scan in isolation, so they understate its share of a real packet.

Both sets of numbers are kept, because the change from "leave it" to "compile a matcher" is exactly
the kind of revision that should be traceable.

### The helper measurement (unchanged, still valid)

`RoutesContain`, `prefixesContain` and `rangesContain` are linear scans built on
`slices.ContainsFunc`. Benchmarked at 1/4/16/64/256 entries, measuring both a hit
(in the **last** entry, the worst case for early exit) and a miss (full scan),
`-benchtime 2000000x -count 3`:

```text
RoutesContain      hit      miss   │  prefixesContain   hit       miss
  1 route         10.4n    10.5n   │   1 prefix        5.4n      6.1n
  4 routes        38.0n    40.1n   │   4 prefixes     17.2n     27.8n
 16 routes       153.9n   146.7n   │  16 prefixes     68.6n     82.8n
 64 routes       583.3n   571.0n   │  64 prefixes    256.8n    274.7n
256 routes      2311.1n  2274.4n   │ 256 prefixes    991.6n   1007.0n
```

`0 B/op` and `0 allocs/op` at every size. Growth is ~8.8 ns per `AddressRange`
entry and ~3.9 ns per prefix — cleanly linear.

Read alone, this says the cost is 10–40 ns for a realistic advertisement, against a
~1280-byte packet whose remaining processing looks far larger. On that basis the
earlier decision was to keep the scan.

### What the real path showed

`BenchmarkDataplaneOutboundRouteCounts` measures `Client.WritePacketBuffers` — the
actual production entry point — with the packet addressed INSIDE THE LAST range so
the scan cannot exit early. 1280-byte packet, batch of 1, `-count 8`:

```text
routes      linear scan (before)     binary-search matcher (after)
    1            ~140 ns                     ~145 ns      unchanged
    4            ~406 ns                     ~152 ns      -63% (p=0.001)
   16            ~315 ns                     ~155 ns      -49% (p=0.000)
   64            ~813 ns                     ~162 ns      -80% (p=0.000)
```

The isolated scan is 154 ns at 16 routes, which is real CPU time — against a total
packet path of only ~140 ns at one route, so the scan was not 10–40 ns of a large
budget, it was most of a small one. The helper benchmark could not show that,
because it never measured the budget it was being spent from.

Sixteen routes is not a contrived figure: a default route plus split-tunnel prefixes
reaches it, and a peer splitting a /8 into per-site ranges passes it easily.

### Decision: a compiled matcher replaces the scan on the packet path

`routeMatcher` (in `transport/masque/route_matcher.go`) splits the ranges by address
family, sorts each family by start address, and finds the candidate by binary search.
It is **flat** in the route count where the scan is linear, so the win grows exactly
where the scan hurt, and at one route it is indistinguishable from the scan.

It is compiled when a snapshot is PUBLISHED — at capsule handling or session
construction — never on the packet path, because a capsule arrives rarely and a
packet arrives constantly. It rides in `sessionState`, so the packet path still takes
one lock-free snapshot read.

### The subtlety that nearly shipped a bug

Binary search finds the LAST range starting at or below the address. With overlapping
ranges whose `Protocol` differs, that is **not** what a first-match scan returns, and
the two genuinely disagree — a prototype failed exactly this case (a UDP range
containing a TCP range, queried for UDP).

That input cannot come from a parsed advertisement: `parseRoutes` rejects overlapping
ranges per RFC 9484 §4.2.1, including the cross-protocol case that the ordering check
alone misses. The matcher does not rely on that silently: when the candidate contains
the address but does not permit the protocol, it falls back to the linear scan, which
costs nothing on the common path and keeps the answer correct for a range set that did
not come through `parseRoutes`.

Removing that fallback fails `TestRouteMatcherFallsBackOnAnOverlappingSet`.

### How the decision is kept reversible

`RoutesContain` is retained as the reference implementation, and
`TestRouteMatcherAgreesWithTheLinearScan` checks the matcher against it over 5 route-set
shapes x 21 addresses x 6 protocols. Stating the property against the scan rather than
against literal booleans means the routing RULES can change and the matcher is still
required to follow.

The helper benchmarks stay in `transport/masque/route_bench_test.go`.

---

## 4. Client QUIC congestion control

The HTTP/3 client config covered stream windows, keepalive, idle timeout, PMTU
discovery and initial packet size, but offered no congestion control selection, and
no client path called `SetCongestionControl`.

Added `quic_congestion_control` on `QUICOptions`, accepting exactly
`default` / `cubic` / `bbr` / `reno`:

```json
{
  "type": "masque-client",
  "quic_congestion_control": "bbr"
}
```

Installed by `ApplyClientCongestionControl` immediately after the QUIC handshake and
before the HTTP/3 client conn opens any stream, so not one packet is sent under the
default sender when an alternative is configured.

**Unset keeps quic-go's own sender.** Upstream sing-box, quic-go/masque-go and
quic-go/connect-ip-go all leave the client congestion control alone, so defaulting
to BBR would change wire behaviour against every reference with nothing in the
configuration to show it. Unset resolves to a `nil` factory rather than to a CUBIC
factory, so "explicitly CUBIC" and "left to the library" stay different statements
even though the library default is CUBIC today.

Validation is exact and case-sensitive: `"BBR"` and `" bbr"` are configuration
errors, because silently accepting them would make a typo look like it worked.
Verified end to end — `sing-box check` accepts `bbr` and rejects `cubik` at load
with `unknown quic congestion control: cubik`.

### What was NOT measured

Which algorithm is **faster** on a real path is **NOT TESTED**. That requires a VPS
and a controlled network, and a comparison across stable/clean, high-RTT and
lossy paths. The option is a configuration switch, not a performance claim.

---

## 5. Network transitions

`InterfaceUpdated` calls `RestartSession`, which cancels the current session and
resets HTTP connections; `Suspend`/`Resume` handle sleep and wake. Reconnection uses
exponential backoff from 1 s to 60 s, reset to 1 s whenever a session was
established or an interruption was requested rather than failed.

Existing coverage in `transport/masque/` exercises session shutdown, blocked-writer
release, repeated shutdown without goroutine accumulation, and buffer release on
every path.

### What was NOT tested

Real macOS Wi-Fi→Ethernet→hotspot transitions, sleep/wake, and rapid successive
interface changes against a live server are **NOT TESTED** here — they need a macOS
host with a live MASQUE peer and the ability to toggle interfaces. The cancellation
and teardown logic is covered by unit tests; the storm-and-backoff behaviour under
real transitions is not.

No reconnect storm or double-restart issue was found by inspection, but inspection
is not measurement, so this is listed as an open verification item rather than a
clean bill of health.

---

## 6. Preserved hardening

The following were present before this work and are unchanged; they are listed so a
future refactor does not quietly drop them:

- source-address anti-forgery on the tunnel ingress
- CONNECT-IP hardening, including the IPv4 IHL bounds fix
- capsule count and length bounds (`MaxCapsuleLength`, entry-count limits)
- setup-window datagram ownership: early datagrams are held and released correctly
- bounded backpressure on the outbound queue, with drop-and-release
- packet-too-big handling, including session ownership and MTU clamping
- route overlap validation and ordering enforcement on ROUTE_ADVERTISEMENT
- `Server.Contains` own-address guard
- zero-copy H3 ingress on the server side (`transport/http/capsule.go`)
- batch path and packet timeout pinning
- fuzzing coverage for capsules and IP packets
- two-phase establishment and QUIC/H3 error classification

---

## 7. Outbound packet path: the per-packet allocation (this round)

`session.writePackets` allocated once per **successfully sent** packet, for a reason
invisible in review:

```go
var tooLarge *transportHTTP.DatagramTooLargeError
switch {
case err == nil:
case errors.As(err, &tooLarge):
```

`errors.As` takes the ADDRESS of its target, so the compiler must assume the pointer
outlives the call and moves the variable to the heap on every iteration — including the
iterations where `err` is nil and the call is never reached. Escape analysis reports
`moved to heap: tooLarge`, and a memory profile of the packet path showed it as the only
allocation attributable to this package.

The fix splits the nil case out of the function that contains `errors.As`, because Go
hoists that allocation to FUNCTION ENTRY: a function that merely CONTAINS an `errors.As`
pays for it even when the call is unreachable. The direct type assertion answers the case
that actually occurs, and `errors.As` remains in the chain for a WRAPPED too-large error,
so classification is unchanged.

`-benchtime 200000x -count 10`, 1280-byte packet:

```text
                        before      after
per-packet allocs          1           0
batch-of-16 allocs        33          17
B/op (batch of 16)      1251        1126     -10.0%
ns/op (batch of 1)     140.7       128.6      -8.6%  (p=0.000)
```

The residual allocs/op belong to the benchmark fixture's pooled buffer acquisition, not to
the packet path: with the fixture removed the path is **57–63 ns/op and 0 allocs/op**.

Two contracts are pinned, and both are mutation-verified — injecting a payload `copy`
moves allocs/op from 1 to 2, and reintroducing the unconditional `errors.As` moves the
classifier from 0 to 1. An earlier version of the allocation test compared B/op between two
packet sizes and could NOT fail, because the batch is reused and the pool is already
drained; the comment records that experiment so the wrong version is not reintroduced.

---

## 8. Receive path, and two optimisations that were rejected

### The receive path's remaining allocations

Two per packet: the `*buf.Buffer` wrapper (56 B, which the API forces onto the heap as soon
as a caller holds a pointer) and a one-element `[]*buf.Buffer` built for the
`ClientHandler` hand-off.

Reusing that slice measures **65 ns / 2 allocs → 33 ns / 1 alloc**, about 32 ns per received
packet, and the tempting fix is a per-session scratch slice.

**REJECTED**, for a reason not visible from `loopDatagram`: that loop IS single-goroutine,
but `session.run` starts it in its own goroutine and then occupies the calling goroutine with
`loopCapsule` — and the capsule loop also calls `handlePacket`, for packets a peer sends as
DATAGRAM capsules. A shared mutable slice is a **data race**, and one that would appear only
when a peer used both mechanisms at once. A `sync.Pool` would trade the allocation for a lock
on the receive path, which is worse.

The second reason is scope: `ClientHandler.WriteInboundBuffers` is the boundary to
`transport/device`, and both device implementations batch RUNS of packets through it.
Narrowing it to suit one caller would push a per-packet concern into a shared product
interface.

The constraint is noted at `loopDatagram` itself, so the argument is attached to the code
that creates it. No bespoke test was added: a race of that shape is caught by
`go test -race`, which runs over this package in CI.

### Learned datagram ceiling for oversize packets

An oversize packet costs a failed `SendDatagram` before its ICMP Packet Too Big: **400–690 ns
and 6 allocations** against ~140 ns and 2 for a normal packet, with `sendattempts/op` fixed at
1.0. A session-local ceiling that short-circuits packets above a learned maximum is the
obvious fix.

**REJECTED** because the premise does not hold. quic-go computes its limit as

```text
min(peerMaxDatagramFrameSize, maxPayloadSizeEstimate)
```

and `maxPayloadSizeEstimate` is an atomic that is only ever RAISED as path MTU discovery
succeeds (`connection.go` stores it only when the new estimate is larger). "Too large" is
therefore a transient statement about the current estimate, not a stable property of the
connection. A ceiling that only ratchets down would latch a temporary reduction and
permanently refuse packets the connection could carry once PMTU recovered — trading a correct,
self-healing path for a fast, permanently-degraded one, on a condition a correctly configured
tunnel does not produce at all.

### Datagram capability: NO CHANGE

`sendattempts/op` of 1.0 is measured only for a state the protocol makes unreachable — a
transport that reports itself datagram-capable and then refuses every send. `newSession`
caches the `DatagramStream` once, at construction, from the peer's SETTINGS
(`DatagramsEnabled()`), so a session either has a usable datagram path or never touches one.
The benchmark is kept so the cost of the hypothetical would become visible if the capability
ever became dynamic.

### Racer orchestration: NO BENCHMARK

It cannot be measured honestly without a real QUIC connection: `awaitHandshake` calls
`quicConn.HandshakeComplete()` and `quicConn.Context()`, so a stub connector cannot stand in —
a fake `*quic.Conn` is a nil dereference, which is what the first attempt at this benchmark
found. A real one would measure quic-go's handshake rather than this package's orchestration,
and the racer runs once per connection rather than per packet.

What IS measurable is the ordering helper: **38 ns / 1 allocation** for the common dual-stack
pair, 1.2 µs / 11 allocations for 64 candidates.

---

## 9. Where the packet path actually stands

With the benchmark fixture removed, the CPU profile of the outbound path contains **no function
from `transport/masque` at all**:

```text
outbound, 1400B, fixture removed:   57-63 ns/op, 0 allocs/op, 22-24 GB/s
  runtime.kevent        50.0%     (scheduler / syscall)
  runtime.scanobject    25.0%     (GC)
  runtime.usleep        25.0%

inbound, 1400B:                     54-70 ns/op, 2 allocs/op
  runtime.kevent        50.0%
  packetAddresses       12.5%     (3-5 ns measured directly, 0 allocs)
  runtime.madvise       12.5%
```

Concurrent ingress and egress are flat across 1, 4 and 16 workers (~216 ns and ~210–246 ns
respectively), which is the evidence that neither path takes a lock.

**The packet hot path is already dominated by quic-go and the kernel.** No function in this
package appears in the outbound profile; the inbound path's only per-packet costs are the
buffer wrapper the API requires and a slice the device interface requires. Per the task's stop
condition, this is where optimisation ends rather than where it continues.

---

## 10. Convergence round: metadata, queueing and allocation

The zero-copy work (§8-9) removed the payload copies. This round attacked what remained:
per-packet metadata, the send-queue hand-off, and ownership bookkeeping.

### 10.1 Per-packet frame metadata: one allocation, retained by design

`wire.DatagramFrame` is heap-allocated per datagram. Two reductions were possible and one was
taken.

**Taken: the owner no longer costs a closure.** `SendDatagramOwned` originally stored the
release callback as a method value, `f.SetRelease(owner.Release)`. A method value on an interface
receiver boxes into a heap closure -- escape analysis reports
`owner.Release escapes to heap` -- at 16 bytes per datagram. Storing the interface directly
costs two words inside a frame the queue already holds:

| | allocs | bytes |
|---|---|---|
| bound method value | 16 / 8 frames | 512 B/op |
| stored interface | 8 / 8 frames | 384 B/op |

That is **2 allocs, 64 B per packet -> 1 alloc, 48 B per packet**.

**NOT taken: pooling the frame itself, and this is a correctness decision rather than a
performance one.** `DatagramFrame.Release()` fires during packet serialization, when the payload
is copied into the outgoing buffer. The frame, however, is still referenced long after that:

```text
packet_packer.go:740        pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
packet_packer.go:1045-1055  copied into shortHeaderPacket.Frames
sent_packet_handler.go:346  p.Frames = frames          <- retained in flight
sent_packet_handler.go:552  putPacket(p.packet)        <- only dropped on ACK
ackhandler/packet.go:59-63  p.Frames = nil
```

Datagram frames carry no `Handler`, so `OnAcked`/`OnLost` are no-ops -- the frame is *useless*
after send, but it is not *unreferenced*. Recycling it at `Release()` would hand a live frame
back to a pool while `sentPacketHandler` still holds it, and a later `getFrame()` could rewrite
`Data`/`owner` underneath the ack handler. The existing ownership tests compare payload bytes
across the boundary, so they would not catch it.

Payload lifetime is not frame lifetime. The allocation stays.

### 10.2 Batch enqueue: -5% to -14.5%, and the measurement that decided it

**The batch size was measured before anything was built.** sing-tun's dispatch stage flushes a
whole burst at once, and the production config omits `stack`, which resolves to the Go engine
(`sing-tun/stack.go:52`) where `Flush()` runs once per event-loop turn over up to
`goReadBatch = 64` frames. Modelling frames-per-turn over 200k turns:

| scenario | mean batch | >= 2 |
|---|---|---|
| small reads, single flow | 3.6 | 95.6% |
| moderate reads, shared TUN | 4.0 | 89.4% |
| saturated single flow | 57 | 100% |

Batches are overwhelmingly >= 2, so the work was justified. Per packet, `datagramQueue.Add` did
one lock and one scheduling signal; those are now charged once per batch.

| batch | before | after | delta | p |
|---|---|---|---|---|
| 1 | 239.1n | 226.6n | (unchanged path) | -- |
| 2 | 267.8n | 272.0n | ~ | 0.382 |
| 4 | 342.9n | 325.2n | **-5.13%** | 0.001 |
| 8 | 475.5n | 435.5n | **-8.42%** | 0.000 |
| 16 | 757.0n | 666.4n | **-11.96%** | 0.000 |
| 32 | 1.259µ | 1.076µ | **-14.54%** | 0.000 |

A batch of one keeps the original per-packet loop, because the transport charges the same fixed
cost either way.

**The false start is the instructive part.** The first version allocated a scratch slice per
batch. At 32 B/op that single allocation cost ~40 ns against the ~13 ns/packet the batch
reclaims, and the result was that batch=2 was **46% slower**. Both the session and the transport
adapter now reuse their scratch slices, giving 0 B/op and 0 allocs/op. A batch API is only worth
having if assembling the batch is free.

### 10.3 What was measured and deliberately NOT changed

**Inbound packet-sized allocation: NO CHANGE.** `HandleDatagramFrame` does
`make([]byte, len(f.Data))`, measured at **168 ns / 1280 B / 1 alloc**, against **35 ns** for a
pooled variant. The pool is 4.8x faster, so cost is not the objection -- safety is.

`ReceiveDatagram(ctx) ([]byte, error)` returns a slice that sing-box wraps with **unmanaged**
`buf.As` and hands to the device, where `processInboundBuffers` passes `packetBuffer.Bytes()`
into an **asynchronous** return path. A pooled buffer would be recycled while the device still
holds it, overwriting a packet queued for transmission. Removing the allocation needs an owned
*receive* API so the pool learns when the consumer is done -- a new lifecycle contract, not a
change to this function.

**Oversize / `DatagramTooLarge` learned ceiling: REJECTED.** The cost is real (~316 ns and 6
allocs versus ~106 ns and 2), but quic-go computes its limit as
`min(peerMaxDatagramFrameSize, maxPayloadSizeEstimate)` and the estimate is **raise-only**
(`connection.go:2169`: `if maxPayloadSize > current`). "Too large" is therefore a transient
statement about the current estimate, not a stable property. A ceiling that ratchets down would
latch a temporary reduction and permanently refuse packets the connection could carry once PMTU
recovered -- trading a self-healing path for a permanently degraded one.

**Lock-free queueing: not attempted.** Mutex and block profiles at 1/4/16 senders show no
contention inside `writePackets`; the delay is `Client.activeSession`'s access mutex and the
benchmark fixture's own sink lock. The batch path takes no lock of its own.

### 10.4 Long-run allocation

1,000,000 packets through both paths:

```text
PER-PACKET : totalAlloc=72087368 (72.1 B/packet) heapDelta=32536  numGC=21
BATCHED    : totalAlloc=72068104 (72.1 B/packet) heapDelta=11928  numGC=21
```

The heap does not grow with packet count. Total allocation is identical in both modes, and that
72 B/packet is the **fixture** constructing pooled buffers -- with the fixture excluded the
dataplane path is **0.00 allocs/op**. Batching reduces time, not allocation, and this is recorded
as such rather than presented as a memory win.
