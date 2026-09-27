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

## 3. Route containment: measured, and deliberately not changed

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

### Decision: the linear scan stays

A real CONNECT-IP client advertises a handful of ranges: a default route, or a small
set of corporate prefixes. The realistic cost is therefore **10–40 ns per packet**,
against a ~1280-byte packet whose remaining processing is orders of magnitude
larger.

Replacing it with an IPv4/IPv6 split, a prefix trie or a BART would be real
complexity — a new data structure plus a new invariant to maintain on every route
update — bought with no measurable gain on any realistic configuration. The
256-route case at 2.3 µs is the only point where a trie would clearly pay, and
nothing suggests a deployment advertises that many ranges.

The benchmarks and a correctness test at every size are kept in
`transport/masque/route_bench_test.go`, so the decision is reversible with data: if
a large-route configuration ever appears, the baseline is already in the tree.

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
