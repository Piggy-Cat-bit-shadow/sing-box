# Native bypass trace

What `tun.ActionBypass` actually does to a packet, established by running the pinned sing-tun rather
than by reading a verdict.

**The finding: in TUN mode it does nothing.** `ActionBypass` is handled identically to
`ActionAccept` by all three TUN stacks, so a flow the router marks as bypassable is still terminated
in userspace. The verdict is honoured by exactly one transport — Linux `auto_redirect` through
nfqueue — and the TUN route sets bypass by installing OS routes, not by returning a verdict at all.

---

## Why this document exists

The Direct Offload work assumed that returning `tun.ActionBypass` from `JudgeFlow` makes the platform
carry the connection. Nothing had checked that at the data plane: the existing tests asserted on the
verdict, and a verdict is not a packet path. One of them said so in its own comment —
*"The verdict is what the TUN stack acts on"* — and that sentence was the unverified assumption.

Two experiments now check it, and both run without a device, root or a kernel route:

| Experiment | File | What it drives |
| --- | --- | --- |
| Dispatcher trace | [`protocol/tun/native_bypass_dispatcher_test.go`](../../protocol/tun/native_bypass_dispatcher_test.go) | `tun.NewForwardDispatcher` directly — the layer all three TUN stacks share |
| Stack trace | [`protocol/tun/native_bypass_trace_test.go`](../../protocol/tun/native_bypass_trace_test.go) | the real `go` stack end to end, over sing-tun's in-memory TUN |

The stack trace injects real, checksummed packets into the real stack and watches where they go: the
Handler being called back means the connection was terminated in userspace; the application's own SYN
appearing on the platform-facing queue would mean it was handed back out for the OS to route.

---

## What the trace found

### The shared layer

`ForwardStage.Dispatch` returns **whether the dispatcher consumed the packet**. Consumed means the
packet was forwarded into a `Port`, rejected or dropped. Not consumed means it continues into the
stack, which is the userspace path in every TUN stack.

| Verdict | Consumed | Tracker created |
| --- | --- | --- |
| `ActionAccept` | no | no |
| **`ActionBypass`** | **no** | **no** |
| `ActionFlow` (with a `Port`) | yes | yes |
| `ActionBypass` + a `Port` | yes — sing-tun rewrites it to `ActionFlow` | yes |
| `ActionReject` / `ActionDrop` | yes | — |

`ActionAccept` and `ActionBypass` are indistinguishable on every observable the dispatcher has: the
same consumption, the same number of `JudgeFlow` calls, the same absence of a tracker.

An accept entry is not a no-op — it caches the verdict (so the flow is judged once), refreshes an idle
deadline per packet, is removed on a TCP RST, and expires on timeout. It simply has no flow object,
so there is nothing for `CountForward`, `CountReverse`, `FlowEstablished` or `CloseFlow` to attach to.

### The go stack (the default)

| Verdict | Where the packet goes |
| --- | --- |
| `ActionAccept` | `handleTCPSyn` → new userspace `GoConn` → `Handler.NewConnectionEx` |
| **`ActionBypass`** | **the same** |

The only packets written out toward the platform are the ones the userspace endpoint generates — the
SYN-ACK and the RST. The application's SYN is never handed back, and `NewTracker` on the verdict is
never called.

### The other two stacks, from the code

- **`gvisor`**: `TCPForwarder.Forward` switches on the verdict and honours exactly `ActionReject` and
  `ActionDrop`; everything else, `ActionBypass` included, becomes `Handler.NewConnectionEx`. It calls
  `JudgeFlow` a **second** time for a flow the dispatcher has already judged.
- **`system`**: `processIPv4` → not consumed → `processIPv4TCP` rewrites the packet to the local NAT
  listener and writes it back, where `acceptLoop` calls `Handler.NewConnectionEx`. A verdict that is
  not consumed is a packet that goes to userspace.

Neither has a behavioural test here because neither can be driven over the in-memory TUN: the gvisor
stack reads through the real device, and the system stack needs its local listener. The code paths are
short and single-entry, and the shared dispatcher they both call is covered above.

### UDP, which is the interesting case

The accept entry carries the verdict into the UDP path, so a `NewTracker` offered on `ActionBypass`
**is** created for UDP — and attached to the **userspace** packet connection, a `*tun.GoPacketConn`.
Tracking works precisely because the flow did not bypass. The datagram still goes to the UDP NAT.

### Where a bypass really happens

| Mechanism | Honours `ActionBypass` | How |
| --- | --- | --- |
| Linux `auto_redirect` (nfqueue) | **yes** | `NfRepeat` with the output mark, so the packet leaves by its original path |
| TUN, `go` / `gvisor` / `system` | no | falls through to the userspace stack |
| TUN route sets (L0) | not involved | the OS routes those addresses away from the TUN; no packet reaches a verdict |

---

## What the verdict costs, and what it does not

The first version of this document claimed an eligible flow "pays one extra rule evaluation". That was
wrong, and the measurement is in `route/bypass_capability_cost_test.go`: the pre-match verdict is
discarded for a direct TCP or UDP flow whichever verdict it is, because the direct outbound answers
`PreMatchContinue` for both networks and there is no `tun.Port` for them. The stack terminates the
connection in userspace and the router routes it from scratch in every case.

Measured per flow through the public entry point:

| Configuration | Cost |
| --- | --- |
| eligible (a bypass verdict is produced) | 224 ns, 240 B, 7 allocs |
| ordinary (the decision declines) | 129 ns, 48 B, 2 allocs |

The difference was entirely one debug line whose arguments were built before the logger decided the
level was off. With that gated, both configurations are 135 ns, 48 B, 2 allocs — which is also the
answer to whether the decision should be gated on the caller's ability to honour it: there is nothing
left to save, and no observable difference to preserve.

## What this means for tracked native bypass

The round's premise was that a native path exists and only its observability is missing. The premise
is wrong in the stronger direction: the native path does not exist in TUN mode, and the tracker
question cannot be asked until it does.

If it were implemented — a generic "hand this packet back to the platform" action in sing-tun, which
is a real change to three stacks and a fourth dependency fork — observability would still not follow:

- **Reverse accounting would be impossible, not merely missing.** Once the OS owns the connection, the
  reply is delivered to the application socket by the OS's own connection tracking and never
  re-enters sing-tun. The dispatcher's return path confirms the shape of the problem from the other
  side: `classifyReturn` finds a reverse flow through the NAT entries that only a `Port` creates, and
  an accept entry creates none.
- **Forced close would be impossible.** There is no userspace object to close; the connection belongs
  to the OS.
- **TCP state could only be half-observed**: the forward SYN/FIN/RST is visible, the reverse half is
  not, so "established" and "graceful close" would be guesses.

That is a dashboard contract with wrong download counts, a close button that does nothing, and a
lifecycle that reports states it cannot see. It is worse than the tracker blocker it would replace.

### The mechanism would also have to be sound, and it is not obviously so

"Hand the packet back to the platform" means writing it to the TUN device, which injects it into the
OS as a packet **received from the tunnel**. The OS then routes it by its own table — and the table is
what sent the packet into the tunnel in the first place. Unless the destination is excluded from the
tunnel's routes, the packet is routed straight back into the tunnel and the flow loops.

The `system` stack's writeback is safe for a reason worth noticing: it rewrites the packet's
destination to a synthesised local address (`inet4NextAddress:natPort`) that no tunnel route covers,
so the OS delivers it locally to the NAT listener. A bypass writeback would have to keep the real
destination, which is exactly the case that loops.

A sound verdict-based bypass therefore needs the routing decision to differ for the bypassed packet —
per-destination route exclusion, which is precisely the mechanism L0 already uses, or a mark-based
rule on Linux. This is a design hazard rather than a measured result: proving which platforms loop
requires a real TUN device with routing control, which needs root and is not part of this repository's
automated tests. It is recorded here as the first thing a real-TUN harness should answer.

**Verdict: NATIVE TRACKER BRIDGE REJECTED.** The tracker guard stays. See the Direct Offload document
for what the eligibility decision is still worth, which is its effect in Linux redirect mode.
