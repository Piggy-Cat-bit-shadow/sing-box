# MASQUE performance round — blocked dependency phases

This note records the phases of the MASQUE data-path optimization round that could not be
completed, the exact reason, and what would unblock each one. It exists so the gaps are
not mistaken for work that was skipped or, worse, silently assumed done.

## The blocker, stated once

Phases 4, 7, 9, 10 and 11 all require editing a module this repository does not own:

| Module | Pinned version | Writable fork available? |
| --- | --- | --- |
| `github.com/sagernet/sing` | `v0.9.6-0.20260922013359-4ca3bebe0b8e` | **No** |
| `github.com/sagernet/quic-go` | `v0.61.0-sing-box-mod.7` | **No** |

Checks performed:

```text
go.mod                     -> no replace directive for either module
git remote -v              -> origin (sing-box), upstream (SagerNet/sing-box); no fork remote
Piggy-Cat-bit-shadow/sing     -> repository not found
Piggy-Cat-bit-shadow/sing-tun -> repository not found
Piggy-Cat-bit-shadow/sing-quic-> repository not found
Piggy-Cat-bit-shadow/quic-go  -> EXISTS, but see below
```

`Piggy-Cat-bit-shadow/quic-go` **does** exist, on branch `jiejie-masque-stable`
(`beb42da71a55a1a45ef8794b29afcd6657b15f51`). It is **not usable for this task**: its
`go.mod` declares `module github.com/metacubex/quic-go`, so it is a fork of
**metacubex/quic-go**, a different project from the pinned `sagernet/quic-go`. Pinning it
would replace sing-box's entire QUIC implementation rather than apply a targeted change,
and it would invalidate the pinned reference interop evidence (masque-go and connect-ip-go
are built against the sagernet QUIC stack).

The task prohibits both alternatives: no vendoring, and no local `/tmp` replace. So the
correct outcome for these phases is **BLOCKED**, not a workaround.

## Phase 4 — preserve batching through the timeout wrappers

**Status: DONE.**

### What was broken

`route/conn.go` wraps every packet connection in `canceler.NewPacketConn` for the UDP idle
timeout. sing's `TimerPacketConn` and `TimeoutPacketConn` implemented only
`ReadPacket`/`WritePacket`, so both connected batch capabilities became invisible the
moment the wrapper was applied:

```text
http3PacketConn   -> offered connected batch read/write
canceler wrapper  -> both dropped
bufio.CopyPacket  -> fell back to one packet at a time
```

The connection still worked, so nothing failed; the batching implemented on the tunnel was
simply unreachable in production.

### The dependency change

| Item | Value |
| --- | --- |
| fork | `github.com/Piggy-Cat-bit-shadow/sing` |
| base | `4ca3bebe0b8e96d07d031dce9f311b7675c2d8d9` (the revision already required) |
| branch | `fix/packet-batch-timeout` |
| `SING_PATCH_SHA` | `c0ee76200ae31ec90fd9a28506f42d33ce1fe32b` |
| replace | `github.com/sagernet/sing => github.com/Piggy-Cat-bit-shadow/sing v0.9.6-0.20260926122709-c0ee76200ae3` |

The fork keeps `module github.com/sagernet/sing` and is pinned by commit, not by a branch.
Every non-`replace` line of `go.mod` is byte-identical to before, so nothing else moved and
`quic-go` is untouched. `go.sum` gained exactly the fork's two lines. There is no vendoring
and no local path replacement.

The dependency was verified by its CODE, not by the text of `go.mod`:
`go list -m -json` reports the `Replace` at that version, and the resolved module directory
was inspected to confirm all four new creators are present.

### Wrapper types changed

| Wrapper | Branch selected when | Now forwards |
| --- | --- | --- |
| `TimerPacketConn` | the connection cannot take a read deadline (the HTTP/3 connection) | connected batch read + write |
| `TimeoutPacketConn` | the connection accepts a read deadline (a real UDP socket) | connected batch read + write |

Both are fixed. Only fixing one would leave the other half of production broken, so they
are separate implementations with separate tests.

Activity accounting is preserved and recorded **once per batch**, not once per packet, and
keyed on the call succeeding rather than on payload bytes - a batch of zero-length UDP
datagrams is ordinary RFC 9298 traffic and must not look idle. `TimeoutPacketConn` keeps
its own deadline-and-liveness loop rather than copying the timer variant. Nothing is
released on either side, because the inner readers and writers differ in their buffer
ownership contracts.

### Tests

| Test | Covers |
| --- | --- |
| `TestTimerPacketConnPreservesConnectedBatchCapabilities` | timer branch, read + write, options forwarded |
| `TestTimeoutPacketConnPreservesConnectedBatchCapabilities` | timeout branch, read + write |
| `TestTimeoutWrapperDoesNotInventBatchCapabilities` | false when the inner connection has none, both branches |
| `TestTimeoutWrapperKeepsTheOrdinaryPacketPathUsable` | `WritePacket`, `Upstream` unchanged |
| `TestTimeoutWrapperSetTimeoutStillApplies` | `SetTimeout` after the wrapper exists |
| `TestCopyPacketSelectsTheConnectedBatchPathThroughTheTimeoutWrapper` | the real `bufio.CopyPacket` selects batch |
| `TestCopyPacketKeepsTheOrdinaryFallbackWithoutBatchSupport` | control: no capability, per-packet route |
| `TestConnectUDPTimeoutRulesProduceTheExpectedBranchTimeout` | 443 -> QUIC/30s, 53 -> DNS/10s, from the real tables |
| `TestConnectUDPBatchSurvivesTheRealDerivedTimeout` | both ports, both branches |
| `TestConnectUDPNATWrappersForwardBothBatchCapabilities` | the NAT wrappers are not a second blocker |
| `TestConnectUDPUploadDirectionBatchesFully` | the direction that is fixed, end to end |

In sing itself (`common/canceler/packet_batch_test.go`): branch selection, both directions
on both wrappers, batch sizes 1/2/8/16/64, zero-length datagrams, read and write failure
propagation, `SetTimeout` after the waiter exists, bidirectional activity keeping a session
alive, genuine idle expiry still firing, close releasing a pending read, concurrent read
and write under `-race`, and no double release.

Load-bearing: pointing the replace back at the unfixed upstream makes all four capability
and copy-path tests fail, including the copy-path test with its intended message that the
capability was visible but unused.

### Actual production path

```text
client -> target:
  http3PacketConn (source)
    -> canceler.NewPacketConn (timeout wrapper, batch READ preserved)
    -> bufio.CopyPacket
    -> NAT wrappers (batch WRITE preserved)
    -> connected UDP target

target -> client:
  connected UDP target -> NAT wrappers (batch READ preserved)
    -> bufio.CopyPacket
    -> canceler wrapper (batch WRITE preserved)
    -> http3PacketConn
```

Every wrapper on both directions forwards both capabilities; no additional wrapper blocker
was found. The NAT wrappers forward batch read through `nat_wait.go` and batch write
through `nat.go`, which is a different file from the one an earlier inspection looked at -
the test is what corrected that.

### Linux syscall runtime

**CONFIRMED for `sendmmsg`.** Measured on Linux aarch64 with `strace -f`, running the real
socket test with one batch of 16 packets through the wrapper:

```text
sendmmsg(7, [{msg_hdr={...{iov_base="batch-syscall-probe", iov_len=19}, ...}], 16, 0)
```

One `sendmmsg` call carrying 16 iovecs, with zero `sendto` calls. The batch writer in
effect was `*canceler.timeoutConnectedPacketBatchWriter`, this change's own wrapper.

The same test against the UNFIXED upstream sing fails at the capability assertion with
`sendmmsg: 0`, so the batching was genuinely lost before the fix rather than merely
untested.

`recvmmsg` is **NOT-TESTED**: the test drives the write direction, and the read direction
over a real socket was not traced. `UDP_SEGMENT`/GSO is **NOT-TESTED** and is a separate
phase, not claimed here.

### Benchmark

Same-process A/B on an Apple M1 (darwin/arm64), 2000 iterations per case. The pair that
describes this change is `timeout-batch` against `fallback-per-packet`; the route taken is
recorded by counters (`batches`, `single-writes`) rather than inferred from timing.

| Payload | Batch | timeout-batch | fallback-per-packet | Packets per batch |
| --- | --- | --- | --- | --- |
| 1200B | 64 | 7141 ns/op | 8356 ns/op | 1 vs 0 |
| 1200B | 32 | 4374 ns/op | 4942 ns/op | 1 vs 0 |
| 64B | 64 | 5862 ns/op | 7261 ns/op | 1 vs 0 |
| 64B | 32 | 3857 ns/op | 5082 ns/op | 1 vs 0 |

This is the CPU cost of the copy loop and the wrapper, and the per-packet call count. It is
**not** a throughput claim: it involves no system call, no NIC and no VPS, so no end-to-end
speedup is derived from it. It is darwin/arm64 and is not presented as a Linux/amd64 VPS
measurement.

### Scope

Phase 4 only. Phases 7, 9, 10 and 11 remain as recorded below; nothing else was changed.

## Phase 7 — batch HTTP Datagram enqueue in quic-go

**Status: BLOCKED.** `quic-go`'s `datagramQueue.Add` takes `sendMx` and calls `hasData()`
per datagram, and the queue is capped at `maxDatagramSendQueueLen` (32). A CONNECT-UDP
batch write currently issues one `SendDatagram` per packet, so a 64-datagram batch means 64
separate lock/wake cycles.

The intended shape is a `TrySendDatagramBatch(payloads) (accepted int, err error)` that
takes the lock once, inserts as much as fits, and signals once - returning `accepted` rather
than blocking forever when the queue is full, so the MASQUE copy goroutine can drop the
remainder under UDP semantics. Standard `SendDatagram` must keep its existing blocking
behaviour.

Unblocked by: a writable fork of `github.com/sagernet/quic-go`.

## Phase 9 — Linux UDP GRO on the outer QUIC socket

**Status: BLOCKED for GRO; the rest already exists.** Audited in the pinned quic-go:

| Capability | Present? |
| --- | --- |
| UDP socket buffer tuning | yes |
| `ReadBatch` with Linux `batchSize` | yes (`batchSize = 8`) |
| QUIC send GSO | yes (`sys_conn_helper_linux.go`) |
| GSO failure fallback | yes (`isGSOError`: `EIO` / `EINVAL`, plus `EMSGSIZE` handling) |
| **UDP GRO receive** | **no** |

So the only genuine gap is GRO, which needs `UDP_GRO` on the socket, parsing the
`UDP_GRO` ancillary data to recover the segment size, and splitting the aggregate back
into independent logical datagrams while preserving each one's remote address, packet
info, ECN and OOB metadata - a change inside quic-go's socket layer, not in sing-box.
Deliberately not attempted here, because feeding an aggregate to the QUIC parser as one
datagram would be a correctness break, and no partial version of GRO is safe.

Unblocked by: a writable fork of `github.com/sagernet/quic-go`.

## Phase 10 — batch size A/B

**Status: BLOCKED.** `batchSize = 8` is a constant inside quic-go
(`sys_conn_helper_linux.go`), so it cannot be varied from this repository at all - not even
for a benchmark. Comparing 8 / 16 / 32 would require building three quic-go variants.

The production host for this measurement must be **linux/amd64**; this development machine
is darwin, where the syscall batch path is a different implementation
(`sys_conn_msgx_darwin.go`). A darwin result would not transfer to the VPS, so no batch-size
claim is made. If it is later measured and the result is unstable, the value stays 8.

Related measurement note, recorded because it bounds what any batch-size result could
claim: MASQUE UDP datagrams here are typically ~1200 bytes, and a 64-datagram batch already
exceeds a single GSO burst, so the ceiling is more likely to be GSO segmentation than the
receive batch size.

## Phase 11 — reduce packet-batch metadata clearing

**Status: BLOCKED.** The code in question is
`sing/common/bufio/packet_batch_mmsg.go` (`clear(iovecs)` / `clear(msgvec)`) and
`packet_batch_offload_linux.go` (`reset()` clearing the whole message capacity), with live
slots re-initialised afterwards. Removing the redundant `memset` means proving that no
unused slot is ever read by the syscall - which needs the change plus a Linux test that
varies batch sizes (64, 1, 32, 3, 16, 2, 64, 1) and asserts destination, payload, GSO
grouping and the absence of stale `sockaddr` / control-message / iovec state. Both the edit
and the test belong to `sing`, which has no writable fork here.

## Summary

| Phase | Status | Needs |
| --- | --- | --- |
| 4 | **DONE** | writable `sagernet/sing` — see the Phase 4 section |
| 7 | BLOCKED | writable `sagernet/quic-go` |
| 9 (GRO) | BLOCKED | writable `sagernet/quic-go` |
| 9 (GSO, batching, buffers) | already present | - |
| 10 | BLOCKED | writable `sagernet/quic-go` + a linux/amd64 host |
| 11 | BLOCKED | writable `sagernet/sing` |
| 13 (sharding) | DEFERRED | evidence that one core is the ceiling |

Nothing in this list was worked around, vendored or faked, and no dependency was silently
swapped.
