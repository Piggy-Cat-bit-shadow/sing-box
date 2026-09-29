# Jiejie NaiveProxy: Go dataplane hardening

Async buffer-lifetime correctness between Go and Cronet, plus the two measured copies removed from
the Naive outbound dataplane.

## HEAD

| | |
|---|---|
| sing-box before | `dd8b19aa5` (`SING_BASE_HEAD`) |
| sing-box after | `751b6b7f8` (code at `f45db770e`, CI-verified) |
| cronet-go before | `d83f1a1c6e7f392c865651229778748e1037dc7d` (`CRONET_BASE_SHA`, branch `fix/naive-codec-parity`) |
| cronet-go after | `8c68ce89873c976b33ac62a3fd3128064d34e0a7` (`CRONET_FINAL_SHA`) |
| cronet-go branch | `jiejie-naive-zero-copy` (fork of `Piggy-Cat-bit-shadow/cronet-go`) |
| Pseudo-version | `v0.0.1-143.0.7499.109-2.0.20260929202119-8c68ce89873c` |

The pinned revision was **not** on the default branch. `main` does not contain it; it is the tip of
`fix/naive-codec-parity`, which is `main` plus the ten Naive codec-parity commits. The work branch
was created from that exact revision, so the base is the code sing-box actually compiles against.

## Build

```text
Go              go1.25.5 (root), go1.25.4 (cronet-go)
OS/arch         darwin/arm64, Apple M1, 8 cores, 8 GB
CGO             the production path; purego also verified
tags            with_quic,with_utls,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0
```

## Data Path

| | H2 | H3 |
|---|---|---|
| upload | `naiveConn.WriteBuffer` via the pooled copy buffer | same (Cronet/Chromium QUIC underneath) |
| download | `naiveConn.Read` into the caller's buffer | same |

The Go layer is identical for both; H2 and H3 differ only inside Chromium. No benchmark in this
document claims an H2 or H3 throughput number, because the end-to-end transfer tests cannot run in
this environment (see NOT TESTED).

## Buffer Lifetime

| Question | Answer |
|---|---|
| Does native retain the WRITE pointer? | **YES** — `on_write_completed` is "invoked when all data passed to `bidirectional_stream_write()` is sent" and receives the pointer back |
| Does native retain the READ pointer? | **YES** — native writes into it and reports completion through `on_read_completed` |
| Pinning required? | **YES** |
| Implemented | `pinnedBuffer` in `BidirectionalConn`, used by `Read` and `Write` |
| Unpin event | `OnReadCompleted` / `OnWriteCompleted`; `terminate` as the terminal safety net |
| Cancel/Close safety | **PASS** |

Both facts are taken from the vendored `include/bidirectional_stream_c.h`, not inferred. The full
reading is in `ASYNC_BUFFER_LIFETIME.md` on the fork branch.

### The defect

`Read` and `Write` returned before the completion callback in two cases — on deadline and on
`Close` — handing the caller a buffer that native code might still be reading or writing. The
collector was free to reclaim that array as soon as the caller stopped referencing it.

### Why the unpin is in the callback rather than at return

The header guarantees that `on_succeeded`, `on_failed` and `on_canceled` are each terminal: "Once
invoked, no further callback methods will be invoked." That is the first point at which the window
is provably closed, so it is where the reference is dropped. `terminate` is reached only from those
callbacks, from `OnReadCompleted`'s end-of-stream path (already unpinned), or from a local `Start`
failure where nothing was in flight, so unpinning there is safe and idempotent.

### Concurrency

`pin` runs on the caller's goroutine and `release` on the engine network thread. The header
serialises callbacks with respect to *each other* but says nothing about the caller's goroutine, so
`pinnedBuffer` carries a mutex. Removing it makes `TestPinnedBufferConcurrentPinAndRelease` report
two data races, so the lock is load-bearing rather than defensive.

Implemented once in `BidirectionalConn`, which both the cgo and purego bridges share.

## Copy Count

Normal bulk upload:

| Stage | Copies |
|---|---|
| source → pooled buffer | **0** — the copy loop calls `source.ReadBuffer(buffer)`, reading directly into the pooled buffer sized from the destination's geometry |
| Naive header + padding | **0** — `ExtendHeader(3)` and `WriteZeroN(padding)` write into the buffer's own headroom |
| Go → Cronet | **0** — pointer and length handed to `bidirectional_stream_write` |
| Cronet native | **not measured** — no native profile was taken (see below) |
| **Go-layer full payload copies** | **0** |

Normal bulk download:

| Stage | Copies |
|---|---|
| Cronet → Go buffer | **0** — `readWithPadding` reads into the caller's slice; only the 3-byte header uses a temporary |
| padding parse | **0** — `rw.SkipN` skips, which is not a payload copy |
| route handoff | **0** — the buffer is written onward, not copied |

First payload of a sniffed connection: **0 on the compatible path, 1 on the fallback** (measured
below).

## Padding Geometry

| | Value |
|---|---|
| front | 3 |
| payload | 65278 |
| rear | 255 |
| total | 65536 |
| reference parity | **PASS** (all vectors, including the ceiling and short-write cases) |

Unchanged by this work. Nothing in this round touched the framing.

## Early Buffer Growth

Before, the upload copy loop used the small default buffer until 512000 cumulative bytes. The
inbound Naive writer had opted into early growth; the **outbound** one never had.

| | Before | After |
|---|---|---|
| `cronet.NaiveConn` | no capability | `EarlyCopyBufferGrowth() bool` → true |
| upload copy geometry | default until 512000 B | destination geometry from the first transfer |

**Decision: KEEP.** The mechanism already existed and was generic; the outbound writer simply never
declared it. The change is 8 lines plus a comment, and it removes the warm-up window in which every
upload write is framed through the allocating path. The unwrap chain was verified rather than
assumed: `trackedNaiveConn` → `Upstream()` → `*naiveConn`, asserted by a test.

**NOT TESTED:** the throughput effect of this change, because it requires a live transfer.

## Cached Payload

The sniffed first payload was delivered with a bare `Write([]byte)` in both the copy loop and
`kickWriteHandshake`, discarding the pooled buffer's geometry and forcing the framing writer to
build a new frame buffer.

`writeCachedBuffer` now hands the buffer over when the destination's own advertised geometry allows
it, and falls back otherwise.

Measured, `-benchtime 20000x -count 8`, medians:

| Payload | copying | buffer | speedup | B/op | allocs/op |
|---|---|---|---|---|---|
| 64 B | 470 ns | **214 ns** | **2.19×** | 64 → **0** | 1 → **0** |
| 1400 B | 482 ns | **216 ns** | **2.23×** | 64 → **0** | 1 → **0** |
| 16 KiB | 796 ns | **215 ns** | **3.71×** | 67 → **0** | 1 → **0** |
| 64 KiB | 1926 ns | 1899 ns | 1.01× | 139 | 2 |

Zero-copy when geometry compatible: **YES**. Fallback: **PASS** (verified by mutation — removing
the three geometry checks fails all three fallback cases).

The 64 KiB row is not a regression: 65536 exceeds `maxPaddingPayload` (65278), so **both** paths
fall through to `writeChunked`. That is the reference ceiling working as designed, and it is why the
correct geometry is a ~64 KiB *frame*, not a 64 KiB payload.

## Pinning Cost

Six tests, `-race` clean. The pin itself is two `runtime.Pinner` calls per operation with no
allocation: `sync.Mutex` lock/unlock plus `Pin`/`Unpin`.

| | |
|---|---|
| 32K / 64K ns/op | **NOT MEASURED** — a meaningful figure needs the native write path, which does not complete in this environment |
| allocs/op | **0** added by the pinning (the lock and Pinner are fields; `TestPinnedBuffer*` runs at 0 allocs) |

Per the task's own rule, a correctness fix may cost a small amount; this one is expected to be
sub-microsecond per operation and is not claimed to be free.

## Bidirectional Control Path

| Component | Finding | Change |
|---|---|---|
| write semaphore | `chan struct{}` guard, one writer at a time | **NO CHANGE** — not profiled as a hotspot |
| read semaphore | same shape | **NO CHANGE** |
| access mutex | held only across the native call setup | **NO CHANGE** |
| callback map | `sync.RWMutex` + `map[uintptr]` per callback | **NO CHANGE** — see below |

The callback map was **not** profiled as a hotspot, and the task's rule is explicit: if profile does
not show it, do not touch it. Optimising it without a native profile would be trading a
well-understood lifecycle for an unmeasured gain. **NO CHANGE.**

No lock-free work was attempted. One uncontended mutex is cheap next to a network I/O operation.

## Profiles

**NOT TAKEN.** The Go profiles this task asks for are all downstream of a completing transfer, and
no transfer completes in this environment. The one profile-relevant fact that *is* established is
structural rather than sampled: the Go layer's per-write allocation count is 0, so there is no
per-packet allocation to find in a profile.

## Benchmarks

Cached first payload — the full table is above. Framing paths from the existing suite:

```text
BenchmarkPaddingWriteFramed     444 ns   1 alloc   64 B/op    (in place)
BenchmarkPaddingWriteChunked   5236 ns   4 allocs  262 B/op   (copying fallback)
BenchmarkPaddingWriteUnpadded    12.7 ns 0 allocs    0 B/op   (padding window closed)
BenchmarkPaddingWriteRaw         83.4 ns 1 alloc    64 B/op   (post-padding)
```

The framed/chunked difference is the cost the geometry-compatible hand-off avoids.

## Concurrency

1 / 4 / 8 / 16 streams: **NOT MEASURED** (needs live transfers). The callback map and the engine
count were left unchanged, so no concurrency regression is introduced by this work.

## Memory

**NOT MEASURED** (needs live streams). No buffer pool, no pinned pool and no per-connection
retention was added: each pin is scoped to one in-flight operation and released by its completion
callback, so the steady-state retention is one buffer per direction per connection — the same as
before, now explicitly held by a `runtime.Pinner` instead of implicitly by the caller's slice.

## Native Cronet

| Question | Answer |
|---|---|
| Profiled | **NO** |
| Packet-sized memcpy observed | **NOT MEASURED** |
| Chromium bottleneck identified | **NO** |
| Native code changed | **NO** |

The native profile was not taken because it requires a live transfer. Per the task's stop condition,
Chromium internals must not be touched until a native profile proves they are the bottleneck — and
no such profile exists. **NO CHANGE to native code.**

## Failed Experiments

| # | Experiment | Result | Decision |
|---|---|---|---|
| 1 | `runtime.Pinner` for async read/write buffers | Contract-verified against the vendored header; 6 tests; race-clean; removing the lock produces 2 data races | **KEEP** (correctness) |
| 2 | `EarlyCopyBufferGrowth` on the outbound writer | The generic mechanism already existed; the writer had not declared it. 8 lines. Unwrap chain verified by test | **KEEP** |
| 3 | Geometry-compatible cached-buffer handoff | 2.2× at 64 B / 1400 B, 3.7× at 16 KiB, 0 allocations; mutation-verified fallback | **KEEP** |
| 4 | Pin-free "just use `runtime.KeepAlive`" | Rejected before implementation: `KeepAlive` orders one point against a finalizer and does not retain an object across an async window | **REJECT** |
| 5 | `C.malloc` + memcpy to sidestep pinning | Rejected before implementation: it is legal, but it re-creates the full payload copy the dataplane exists to avoid | **REJECT** |
| 6 | `sync.Mutex` replacing the write semaphore | **NOT ATTEMPTED** — the semaphore was not profiled as a hotspot, and changing it without measurement trades a known-correct serialisation for an unmeasured gain | **NO CHANGE** |
| 7 | Callback-map optimisation (sync.Map / sharding / annotation) | **NOT ATTEMPTED** — not profiled as a hotspot; the task's ordering puts it sixth, and touching a correct destroy/callback lifecycle for no measured gain is the wrong trade | **NO CHANGE** |
| 8 | Bigger copy buffer (128 KiB / 1 MiB) | **NOT ATTEMPTED** — the reference geometry is a ~64 KiB frame, and the measured 64 KiB case shows a larger payload does not fit in place at all | **NO CHANGE** |
| 9 | Async `WriteBuffer` returning early | **NOT ATTEMPTED** — the pinned API allows only one outstanding write per stream, and returning early would break error attribution, backpressure and handshake-failure semantics | **NO CHANGE** |
| 10 | True native zero-copy (avoid the Chromium-internal copy) | **NOT ATTEMPTED** — requires a native profile to justify, which this environment cannot produce | **NO CHANGE** |

## Regression

| Check | Result |
|---|---|
| padding vectors / reference parity | **PASS** |
| short write | **PASS** |
| DNS bridge | **PASS** (untouched) |
| reserved headers | **PASS** (untouched) |
| lifecycle | **PASS** |
| cancel/destroy | **PASS** |
| H2 / H3 | **PASS** (codec unchanged) |
| full client-profile suite | **PASS**, exit 0 |
| race (`route`, `protocol/naive`) | **PASS** |
| race (cronet-go root, purego) | **PASS** |
| registry audit | **PASS** — Naive outbound linked, server-only H3 absent, MASQUE intact |

## CI

| | Result |
|---|---|
| cronet-go | **NOT DISPATCHABLE** — `naive-build.yml` triggers on `main`/`dev` only and is not on the default branch, so it cannot run for this branch. Its locally reproducible steps were run instead: root package tests under `with_purego` (**66 passed**), race clean, cgo and purego builds clean, `gofmt` clean |
| macOS arm64 | **PASS** — [36627610199](https://github.com/Piggy-Cat-bit-shadow/sing-box/actions/runs/36627610199) on `f45db770e` |
| Linux amd64 | **PASS** — [36627615972](https://github.com/Piggy-Cat-bit-shadow/sing-box/actions/runs/36627615972) on `f45db770e` |

## Binary

| | Bytes |
|---|---|
| Before (`dd8b19aa5`) | 65,638,930 |
| After | 65,639,698 |
| Delta | **+768** (+0.001%) |

Unexpected dependencies: **NONE**. Module count unchanged at 191; the only `go.sum` change is for
cronet-go itself.

## Production

- Config modified: **NO** — SHA-256 `d2e3abf153195ae1cb9c3e84784839172ac09add0c89c5d19d46b72b27ebd09f`
- `sing-box check` against the production config: **exit 0**
- Production server contacted: **NO**. No SSH, no restart, no binary replacement. The user's running
  production sing-box process was left untouched.

## Remaining Unavoidable Copies

| Copy | Where | Why it stays |
|---|---|---|
| HTTP/2 or HTTP/3 frame construction | Chromium | Inside the transport; not Go-layer, and not touched without a native profile |
| TLS record / QUIC packetisation / AEAD output | Chromium | Cryptographic output; unavoidable |
| Kernel socket buffers | kernel | Not addressable |
| `writeFrame`'s allocating path | Naive codec | The CORRECTNESS fallback for a payload that cannot be framed in place. Kept deliberately: an external caller may hand `WriteBuffer` a buffer of any size, and 64 KiB+ payloads genuinely do not fit the reference ceiling |
| `Write([]byte)` framing | Naive codec | A bare slice carries no headroom or ownership, so the first frames must build their own buffer. This is the legacy API's honest cost, not a fast-path failure |

## Success Criteria

| Criterion | Status |
|---|---|
| Normal bulk `WriteBuffer` framing: 0 full payload copies | **PASS** |
| Go → Cronet async memory lifetime formally safe | **PASS** |
| Cronet read → Go buffer formally safe | **PASS** |
| Naive outbound reaches correct 64K geometry early | **PASS** (effect on throughput NOT TESTED) |
| Cached first payload avoids the copy path when geometry fits | **PASS** (2.2×–3.7×) |
| `Write([]byte)` stays compatible | **PASS** (unchanged) |
| Padding reference parity 100% | **PASS** |
| No UAF / leak / double release in callback, close, cancel | **PASS** (contract-verified + tests) |
| Go pprof shows memmove/malloc/callback reduction, or a clear conclusion | **PARTIAL** — allocations measured at 0 per write; no sampled profile possible here |
| H2 and H3 do not regress | **PASS** (codec and transport unchanged) |
| macOS arm64 production build green | **PASS** |
| Production config and server untouched | **PASS** |

## NOT TESTED, and why

The following were **not** measured, and are reported as such rather than estimated:

- end-to-end H2/H3 transfer throughput and latency, at any size or concurrency;
- CPU, allocation, mutex and block profiles of a live transfer;
- pin/unpin cost per write at 32K and 64K;
- RSS, heap, goroutine and FD counts at 1/8/16 streams;
- the effect of early buffer growth on real upload throughput;
- any native (Chromium) profile.

All of them require a completed Cronet transfer. **This environment cannot complete one**: the
integration tests that need real data flow (`TestNaiveLargeTransfer`, `TestNaiveCustomDialer`) time
out on an **unmodified** cronet-go base, while `TestNaiveDialError` passes — so the engine starts
and the failure handling works, but a loopback exchange does not complete. That was verified at the
base revision before any change was made, so it is a pre-existing environment limitation rather than
a regression.

The end-to-end behaviour therefore rests on contract verification against the vendored C header plus
the unit-level tests, which is stated plainly rather than papered over.
