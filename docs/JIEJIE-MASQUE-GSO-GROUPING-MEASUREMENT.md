# Linux target-side UDP GSO grouping — measurement and decision

## Question

sing's `syscallPacketBatchOffload.send`
(`sing/common/bufio/packet_batch_offload_linux.go`) groups equal-sized datagrams into one
`sendmmsg` element carrying a `UDP_SEGMENT` control message. A reference implementation
applies a **minimum segment size (~512 bytes)** on the theory that for small datagrams
`sendmmsg` already amortises the syscall, so the GSO metadata/planning work is pure added
CPU.

This asked whether that threshold should be adopted here. It was **not** adopted, and the
reason is that measurement on this stack **disproves the premise**.

## How it was measured

Real Linux, not a derivation. The host is darwin, where sing's GSO path does not compile
at all (`packet_batch_offload_linux.go` is `linux || netbsd`), so the work ran in an
existing `limactl` VM:

| | |
| --- | --- |
| Kernel | Linux 6.8.0-139-generic, aarch64 |
| CPUs | 4 vCPU |
| Go | go1.25.5 linux/arm64 |
| Socket | connected `AF_INET` `SOCK_DGRAM` on loopback, receiver queue 8 MiB |
| Syscall | real `SYS_SENDMMSG`, the same raw call sing makes |
| Layout | sing's exact mmsghdr/iovec/`UDP_SEGMENT` construction |

The grouping **planner** is a transcription of sing's rule (same 64-segment cap, same
65507-byte cap, same "a shorter datagram ends the run" break) because the original is
unexported and linux-only and therefore cannot be driven from a test. The **syscall path is
not** re-implemented, so the kernel-side cost is measured for real.

Reproducible harness, kept in-tree:
`transport/http/linux_udp_gso_bench_test.go` (`//go:build linux`).

```sh
go test -tags with_quic -run '^$' -bench BenchmarkLinuxGSOGroupingVsSendmmsgOnly \
  -benchtime 3000x ./transport/http/
```

### First: proof the measurement is of real GSO

`TestLinuxGSOPreservesDatagramBoundaries` asserts that **one** `mmsghdr` element carrying
`UDP_SEGMENT(600)` is accepted and the receiver gets exactly **64 separate 600-byte
datagrams**. Without this, a kernel that silently ignored `UDP_SEGMENT` would make a
"GSO is faster" result meaningless. It passes.

## Result

Batch of 64 datagrams, median of 3000 iterations, `ns/op` for the whole batch:

| payload | sendmmsg only | sendmmsg + GSO | speedup |
| --- | --- | --- | --- |
| 64 B | 37,108 | 9,607 | **3.9×** |
| 128 B | 35,856 | 9,391 | **3.8×** |
| 256 B | 35,635 | 10,210 | **3.5×** |
| 512 B | 36,443 | 9,824 | **3.7×** |
| 800 B | 39,654 | 12,381 | **3.2×** |
| 1200 B | 42,507 | 13,282 | **3.2×** |
| 1350 B | 38,988 | 14,032 | **2.8×** |

**GSO wins at every size, including 64 bytes.** The gain is *largest* at the smallest
payload — the opposite of the hypothesis. The mechanism is visible in the shape: the
`sendmmsg`-only cost is roughly flat (~36µs) because it is dominated by the per-element
syscall work of 64 elements, while GSO calls `sendmmsg` with **one** element, so the cost
tracks the bytes copied rather than the element count.

### The planning cost, isolated

`TestLinuxGSOPlanningCostIsNegligible` measures the grouping decision with **no syscall**,
which is what the hypothesis is actually about:

```
planning for 64 x 64-byte datagrams: 556 ns per batch, 8 ns per datagram
```

So planning costs **~8 ns/datagram** while the syscall saving at 64 bytes is
~430 ns/datagram. The planning cost is roughly **2%** of the gain - not a reason to add a
threshold.

### When grouping FAILS, the cost is noise

The case that could genuinely justify a threshold is a shape where grouping does not
happen and GSO bookkeeping is pure overhead. Adversarial mixed-size patterns, measured
separately (3 runs):

| pattern | groups formed | delta vs sendmmsg-only |
| --- | --- | --- |
| descending 1350→64 | 8 | −1.3% / −1.6% / −2.6% |
| ascending 64→1350 | 16 (**no grouping**) | 0% (identical path) |
| alternating 64/1350 | 17 | −0.9% |
| pseudo-random 64–1350 | 43 | −0.1% / +3.2% / +2.5% |

When grouping is impossible the code takes the `messageCount == len(messages)` fast path
and issues the *same* `sendmmsg` as the non-GSO variant, so the "0%" is structural, not a
measurement. The random case varies **±3% across runs**, which is noise. There is no
measurable penalty.

## Decision: NO threshold added

No minimum GSO segment size was added, because:

1. GSO is faster at every payload size tested, **including 64 bytes** and including
   batches of only 2 datagrams.
2. Planning costs ~8 ns/datagram against a ~430 ns/datagram saving at the size the
   threshold would have excluded.
3. When grouping fails, the existing `messageCount == len(messages)` fast path already
   degenerates to a plain `sendmmsg`, so the downside the threshold protects against does
   not exist. The implementation already contains the right optimisation.

Adding a ~512-byte threshold here would therefore have **removed a 3.9× improvement at
64 bytes** in exchange for protecting against a cost that measurement shows is not there.
This is exactly why the reference's number was not copied.

## Honest scope

- **Loopback only.** The kernel performs segmentation in software on loopback, so these
  numbers isolate **syscall + planning** cost, which is what the hypothesis is about. A
  physical NIC adds driver-side savings that can only favour GSO further, so the
  conclusion is not weakened - but the absolute figures are not WAN or NIC throughput
  numbers and are not presented as such.
- **aarch64 guest.** The production target is linux/amd64. The *direction* of the result
  follows from the element-count mechanism (1 vs 64 `sendmmsg` elements), which is
  architecture-independent, but the exact ratios are from this guest.
- **No end-to-end throughput claim.** This measures one syscall in isolation, not tunnel
  throughput. Nothing here supports a "% faster tunnel" statement.
- Only the **target-side** connected UDP socket is covered. That is where sing's GSO
  grouping lives; the outer QUIC socket's send path is quic-go's and is separate (and its
  GRO gap is recorded in `JIEJIE-MASQUE-PERF-BLOCKED-PHASES.md`).
