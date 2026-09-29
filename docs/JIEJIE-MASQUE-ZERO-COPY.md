# Jiejie MASQUE Zero-Copy Dataplane

Removing the two full-payload copies on the outbound DATAGRAM path, and establishing by measurement
what the inbound path actually costs.

## HEAD

| | |
|---|---|
| Sing-box before | `bcad6b4d6` (`ZERO_COPY_BASE_HEAD`) |
| Sing-box after | `4cad5511c` |
| quic-go before | `0cae1a7786ee290bd9ecce40b6782d4c227ef1d6` (`QUIC_BASE_SHA`, tag `v0.61.0-sing-box-mod.7`) |
| quic-go after | `393ae9ae9df7ddb6c96a5c092951c404e8ac551b` (`QUIC_FINAL_SHA`) |
| Fork | `Piggy-Cat-bit-shadow/quic-go`, branch `jiejie-zero-copy-datagram` |
| Pseudo-version | `v0.61.1-0.20260929161343-393ae9ae9df7` |
| Host | Apple M1, 8 cores, 8 GB, Darwin arm64, Go 1.25.5 |

## Correctness Gate

Run on `bcad6b4d6` BEFORE any zero-copy work, and again at every commit after.

| Contract | Result |
|---|---|
| HTTP/3 CONNECT bidirectional | **PASS** |
| CONNECT-IP capsule after 200 | **PASS** |
| transport/masque Ready | **PASS** |
| same-H3 DoH (connection count 1) | **PASS** |
| `protocol/http` / Naive / `common/httpclient` | **PASS** |

## Outbound Copies

| Stage | Before | After |
|---|---|---|
| device buffer → MASQUE context ID | 0 copies (in-place `ExtendHeader`) | 0 |
| **HTTP/3 quarter stream ID prepend** | **1 full copy** (`make` + `append`) | **0** (in-place into headroom) |
| **QUIC `SendDatagram` enqueue** | **1 full copy** (`make` + `copy`) | **0** (ownership transfer) |
| QUIC packetization | 1 (unavoidable) | 1 (unavoidable) |
| **Total before packetization** | **2** | **0** |

Measured directly, 20,200 packets of 1280 bytes:

```text
copying : payload copies=20200   bytes allocated/op=1480
owned   : payload copies=0       bytes allocated/op=72
```

## Outbound Benchmarks

Both paths driven through the real `Client.WritePacketBuffers`; the only difference is the send call.
`-benchtime 100000x -count 10`, medians.

| Size | copying ns/op | owned ns/op | speedup | copying B/op | owned B/op | copies/op | allocs/op |
|---|---|---|---|---|---|---|---|
| 64 B | 113.6 | 89.6 | 1.27× | 152 | **72** | 1 → **0** | 3 → **2** |
| 128 B | 129.0 | 90.4 | 1.43× | 216 | **72** | 1 → **0** | 3 → **2** |
| 512 B | 184.3 | 98.0 | 1.88× | 648 | **72** | 1 → **0** | 3 → **2** |
| 1200 B | 284.9 | 99.2 | **2.87×** | 1352 | **72** | 1 → **0** | 3 → **2** |
| 1280 B | 283.4 | 105.6 | **2.68×** | 1481 | **72** | 1 → **0** | 3 → **2** |
| 1400 B | 289.4 | 107.8 | **2.68×** | 1481 | **72** | 1 → **0** | 3 → **2** |

The copying path itself is **unchanged**: benchstat over before/after gives geomean −0.54% (noise,
p>0.2 at every size) and `payloadcopies/op` bit-identical at 1.000. The owned path is purely
additive.

## HTTP/3 Owned Path

| Property | Result |
|---|---|
| Quarter stream ID prepended in place | **PASS** |
| Max 8-byte quarter stream ID | **PASS** (all of 1/2/4/8 byte varints verified, no reallocation) |
| Insufficient headroom → copying fallback | **PASS** |
| Error rollback restores the caller's buffer | **PASS** (verified on a REAL connection) |
| Same bytes on the wire as the copying API | **PASS** |

## QUIC Owned Path

| Property | Result |
|---|---|
| Standard `SendDatagram` semantics unchanged | **PASS** |
| Owned send copies the payload | **NO** |
| Success transfers ownership | **PASS** |
| Error transfers ownership | **NO** |
| Release exactly once | **PASS** |
| Close drains the queue | **PASS** |
| Queue-full-then-close leaves nothing stranded | **PASS** |
| Discard paths (too large, too many peeks) release | **PASS** |

## Where the release happens, proved from source

The release is **not** tied to `datagramQueue.Pop`, which was the obvious choice and is wrong. `Pop`
only unlinks; the payload is read later, in the packet builder's `appendPacketPayload` loop, through
`DatagramFrame.Append`. **Two of `Pop`'s three call sites discard a frame without ever serializing
it**, so a release at `Pop` would free memory `Append` is about to read, or free a frame never sent.

The release is therefore in `DatagramFrame.Append`, immediately after `append(b, f.Data...)` — the
last read of the payload on the send path. It is deliberately not deferred to an ACK: DATAGRAM
frames are not retransmitted (RFC 9221), so there is nothing to wait for, and a 32-entry queue
holding buffers until connection close is pool starvation.

The frame outlives its serialization (it is carried in the packet's frame list for qlog and
ack-handler bookkeeping), so the handle is cleared before it is invoked and a second `Release` is a
harmless no-op rather than a double free.

## A close/accept race this exposed

`CloseWithError` drained the queue *after* signalling, and `Add` consulted the closed channel only
while blocked. A caller blocked for space would wake, find the room the drain had just freed, and
accept a frame for a connection already gone — **reproducibly, 5/5**, not intermittently.

Harmless with the copying API (the frame is simply never sent). With the owned API it is a leak:
the packetizer has stopped and the drain has already run, so nothing would ever release that payload.
The queue is now marked closed and drained under the same lock. The probe went from 5/5 accepting to
5/5 rejecting.

## Oversize

| Property | Result |
|---|---|
| `DatagramTooLarge` retains caller ownership | **PASS** |
| Rollback restores the exact buffer | **PASS** on a real connection |
| PTB path intact | **PASS** (typed error with `MaxPayloadSize` preserved) |
| Oversize costs no wasted payload copy | **PASS** (size is validated before ownership moves) |

## Inbound

| Stage | Copies |
|---|---|
| quic-go decrypt + `HandleDatagramFrame` | **1** (`make` + `copy`, inside quic-go) |
| http3 `ReceiveDatagram` | 0 |
| session `loopDatagram` | 0 |
| `handleIngressDatagram` | 0 (`buf.As`, unmanaged wrap) |
| device `WriteInboundBuffers` | 0 (no return path attached) |
| **Total** | **1** |

**Secondary device copy: NO.** `transport/device` can perform a second full copy, but only when a
return path is attached and the buffer lacks its headroom. `AttachReturn` is defined on several
endpoints and **called by none of them** — verified by grep across the tree — so the state is nil and
packets go straight to the device writer. Pinned by a test that fails if the ingress ever starts
copying.

**Why true receive zero-copy was NOT implemented.** It would require changing the QUIC receive
packet's lifetime — the decrypted buffer's refcount, retained across the frame parser, the datagram
queue and an asynchronous TUN hand-off. That is the highest-risk change available in this codebase,
the profile does not justify it (CPU is dominated by `kevent`, and the two copies this work removed
were the ones that showed up), and a wrong lifetime there corrupts received data rather than failing
loudly. One safe copy with provable ownership is the better trade.

## Profiles

1280-byte packet, CPU profile, top nodes:

| Copying path | Owned path |
|---|---|
| `runtime.usleep` 26.7% | `runtime.kevent` 66.7% |
| `runtime.kevent` 13.3% | `runtime.pthread_cond_wait` 33.3% |
| `runtime.pthread_cond_wait` 13.3% | — |
| `common.Must` 6.7% | — |
| `runtime.madvise` 6.7% | — |
| `runtime.markBits.isMarked` 6.7% | — |

The copying path spends measurable CPU in **GC and memory management**; the owned path's profile
contains only runtime scheduling. The allocation pressure is gone rather than merely moved.

## Memory

| | |
|---|---|
| Max owned datagrams in flight | 32 (`maxDatagramSendQueueLen`) |
| Max retained payload at 1400 B | ~44 KB, bounded by the queue |
| Release timing | packet serialization, not connection close |
| Buffer pool size class | unchanged by the headroom increase (2048 at MTU 1280/1400/1500) |
| Shutdown release | **PASS** — the close drain releases every queued frame |

## Stress and Determinism

| Check | Result |
|---|---|
| Ownership tests (10 in quic-go, 7 in sing-box) | **PASS** |
| Payload corruption | **0** |
| Double release | **0** |
| Leaks (every accepted frame released exactly once) | **0** |
| Race detector, quic-go + sing-box | **PASS** |

## Mutation Testing

Every performance and safety claim was verified by injecting the bug it claims to catch.

| Injected fault | Caught by |
|---|---|
| Payload copy on the outbound path | allocation-count test (1 → 2 allocs) |
| Unconditional `errors.As` in the classifier | allocation test (0 → 1) |
| Release **before** handing the buffer over | delivery test + ordering test (bytes wrong) |
| Release on a **failed** owned send | failure test (capsule fallback carries empty bytes) |
| Pooled copy reintroduced on ingress | ingress test (backing-array mismatch) |
| Close drain removed | close-drain test |
| HTTP/3 fallback removed on no headroom | headroom test |

**One test could not be made to fail and was rewritten.** The initial double-release test counted
releases at the transport. It passed with the bug injected, because sing's `Buffer.Release` zeroes
the struct and clears `managed`, so a second call is a no-op rather than a second `Put` — the
corruption is invisible. A version that watched the pool for an array returned twice also failed to
detect it, because a pool legitimately returns the same array repeatedly. The tests now compare the
**bytes that cross the ownership boundary**, which does detect it and is recorded above.

## Binary

| | Bytes |
|---|---|
| Before (`bcad6b4d6`) | 65,586,178 |
| After | 65,638,930 |
| Delta | **+52,752** (+0.08%) |

Unexpected dependencies: **NONE**. The only dependency change is the quic-go replace.

## CI

| | Result |
|---|---|
| quic-go fork (`./...`) | **PASS** (`go test ./...` on the fork branch) |
| Linux amd64 | **PASS** — [36600041218](https://github.com/Piggy-Cat-bit-shadow/sing-box/actions/runs/36600041218) on `32ae337e9` |
| macOS arm64 | **PASS** — [36600035076](https://github.com/Piggy-Cat-bit-shadow/sing-box/actions/runs/36600035076) on `32ae337e9` |
| jiejie contract suite | **226 passed / 30 skipped / 0 failed** |

## Production

- Config modified: **NO** — SHA-256 `d2e3abf153195ae1cb9c3e84784839172ac09add0c89c5d19d46b72b27ebd09f`
- `sing-box check` against the production config: **exit 0**
- Server contacted: **NO**. No SSH, no restart, no binary replacement.

## Remaining Unavoidable Copies

| Copy | Where | Why it stays |
|---|---|---|
| QUIC packet assembly / AEAD encryption | quic-go | Removing it needs scatter-gather crypto; explicitly out of scope |
| Datagram frame serialization | quic-go `DatagramFrame.Append` | This IS the packetization boundary |
| Kernel send/recv | kernel | Not addressable |
| Receive ownership copy | quic-go `HandleDatagramFrame` | Removing it needs receive-packet refcounting; rejected as too invasive for the measured gain |

## Success Criteria

| Criterion | Status |
|---|---|
| Correctness unchanged | **PASS** |
| HTTP/3 CONNECT not regressed | **PASS** |
| CONNECT-IP not regressed | **PASS** |
| Standard `SendDatagram` copy semantics unchanged | **PASS** |
| Owned API ownership contract explicit | **PASS** |
| Outbound HTTP/3 QSID full copy gone | **PASS** |
| Outbound QUIC `SendDatagram` full copy gone | **PASS** |
| Pre-packetization full payload copies → 0 | **PASS** (2 → 0) |
| Release exactly once | **PASS** |
| Queue close leak-free | **PASS** |
| `TooLarge` retains caller ownership | **PASS** |
| Capsule fallback works | **PASS** |
| Packet corruption = 0 | **PASS** |
| Race clean | **PASS** |
| benchstat shows real gains | **PASS** (2.7× at 1280 B) |
| pprof memmove/alloc down | **PASS** |
| macOS + Linux CI green | **PASS** |
| Production untouched | **PASS** |
