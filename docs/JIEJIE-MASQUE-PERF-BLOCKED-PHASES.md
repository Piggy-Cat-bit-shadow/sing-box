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

**Status: BLOCKED.** The loss is measured, not assumed:
`transport/http/batch_through_timeout_test.go` asserts that the bare connection offers both
connected batch capabilities and that `canceler.NewPacketConn` drops both. The test fails
when the dependency starts forwarding, which turns this note into a signal.

`route/conn.go` wraps every packet connection in `canceler.NewPacketConn` for the UDP idle
timeout. sing's `TimerPacketConn` and `TimeoutPacketConn` implement only
`ReadPacket`/`WritePacket`, so:

```text
http3PacketConn   -> offers connected batch read/write
canceler wrapper  -> both invisible
bufio.CopyPacket  -> falls back to one packet at a time
```

The connection still works, so nothing fails; the tunnel is simply slower than the batch
work above makes possible.

What a fix must do, and what it must not:

- forward `CreateConnectedPacketBatchReadWaiter` / `CreateConnectedPacketBatchWriter`
  through the wrapper, AND
- keep activity accounting at **once per batch**, not once per packet. A per-packet
  `Update()` would negate the point of batching.

Marking the wrapper `ReaderReplaceable`/`WriterReplaceable` to make the resolver skip it is
**not** a fix: it would bypass the timeout tracking the wrapper exists for, which is a
behavioural regression in exchange for speed.

Unblocked by: a writable fork of `github.com/sagernet/sing` (or the change landing
upstream) plus a `replace` pinned to a specific commit.

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
| 4 | BLOCKED | writable `sagernet/sing` |
| 7 | BLOCKED | writable `sagernet/quic-go` |
| 9 (GRO) | BLOCKED | writable `sagernet/quic-go` |
| 9 (GSO, batching, buffers) | already present | - |
| 10 | BLOCKED | writable `sagernet/quic-go` + a linux/amd64 host |
| 11 | BLOCKED | writable `sagernet/sing` |
| 13 (sharding) | DEFERRED | evidence that one core is the ceiling |

Nothing in this list was worked around, vendored or faked, and no dependency was silently
swapped.
