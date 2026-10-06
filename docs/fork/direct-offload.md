# Direct Offload

Letting a connection that is provably equivalent to a plain `connect(2)` be carried by the platform's
own routing instead of by a userspace copy loop.

**This is a fork extension in the sense that matters for expections, and in one that does not.** The
eligibility rules are stricter than upstream's, so a configuration that offloads here also loads in
official sing-box — but it will not offload there, because the profile described below does not exist
upstream. The observable behaviour of a connection is meant to be identical either way; what differs
is where the bytes are copied.

---

## The rule

    SEMANTIC EQUIVALENCE, NOT CONFIG EMPTINESS

A dial option disqualifies a flow only if the userspace path would **actually apply it to that flow**.
An option the flow never reaches is not a reason to refuse.

The difference is not academic. The shipped topology declares exactly one direct outbound:

```json
{ "type": "direct", "tag": "direct", "domain_resolver": "local-agh" }
```

Comparing that configuration against an empty one refused **every** flow through it, including the
literal-IP flows that never consult a resolver. Comparing the semantics refuses only the flows that
would.

---

## Two layers, two questions

The decision is a conjunction, and the split matters because the dangerous mistakes live on one side
each.

| Layer | Question | Owner |
| --- | --- | --- |
| Router | May this **flow** skip the userspace path, given its inbound, its sniffed domain, its FakeIP state, its trackers and its rule verdict? | [`route/route.go`](../route/route.go) — `canFastBypass` |
| Dialer profile | Would this **socket configuration** be reproduced by the platform's own connect, for this flow? | [`common/dialer/profile.go`](../common/dialer/profile.go) — `SocketSemantics` |

Neither re-implements the other. The router knows about inbounds, rules and FakeIP; the profile knows
about socket options, binds, marks and resolution. A profile that tried to answer the policy question
would have to guess at metadata it cannot see, and a router that re-read dial options would be a
second interpretation of them.

---

## What is classified, and where the classification came from

The classification was read off [`common/dialer/default.go`](../common/dialer/default.go) and
`resolve.go`, which is where each field is actually applied — not off the field names.

| Scope | Options | Why |
| --- | --- | --- |
| Always | `detour`, `bind_interface`, `inet4/6_bind_address`, `bind_address_no_port`, `protect_path`, `routing_mark`, `netns`, `connect_timeout`, `network_strategy`, `network_type`, `fallback_network_type`, `fallback_delay` | A bind, a mark, a namespace, a dial deadline or interface selection. None can be reproduced by the platform performing the connect. |
| TCP only | `tcp_fast_open`, `tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive`, `tcp_keep_alive_interval` | Applied to the TCP dialer. A UDP flow through the same outbound is still exactly a plain connect. |
| UDP only | `reuse_addr`, `udp source port`, `udp_fragment` | `reuse_addr` reaches `listenConfig` — the UDP listener — and never `dialer.Control`. `udp_fragment` is a datagram socket option. |
| Resolution only | `domain_resolver`, `domain_strategy` | Only consulted when a name is resolved. See the exception below. |
| Ignored | `udp_fragment_default` | The direct constructor sets it. It is not an operator statement, and treating it as one would refuse every direct outbound in this fork. |

### The exception that is easy to get wrong

A **hard single-family** strategy (`ipv4_only`, `ipv6_only`) filters the *literal* destination too:
the dial path applies it to the original attempt, not only to resolved candidates. A profile that
stopped at "a literal needs no resolver" would bypass a connection the userspace path would have
refused to dial.

So the effective strategy is asked of the live dialer, and only a *restriction* counts —
`prefer_ipv4` is a preference and permits everything.

---

## Failing closed, twice

A newly added `DialerOptions` field must not be able to make a bypass **safe** by default.

1. **At runtime.** A field that is set but absent from the classification table produces
   `BlockerUnclassified`, so the omission costs a missed optimisation rather than a discarded socket
   semantic.
2. **In review.** `TestEveryDialerOptionIsClassified` reflects over the options struct and fails until
   every field is classified, with the scope meanings printed in the failure message. The table may
   also not name a field that no longer exists, so a rename cannot leave a stale entry behind.

---

## Which layers exist, and where a bypass actually happens

| Layer | What carries the bytes | Per-byte cost to this process | Where it is honoured |
| --- | --- | --- | --- |
| L0 | The TUN's own route sets (`route_address_set` / `route_exclude_address_set`) | zero | **everywhere**, by installing OS routes |
| L1 | The router's semantic bypass — this document | zero **only in redirect mode** | Linux `auto_redirect` (nfqueue) |
| L2 | Userspace copy with a kernel socket pair (splice / `sendfile`) | two syscalls per chunk | every TUN stack |
| L3 | Userspace copy through buffers | a copy plus two syscalls per chunk | every TUN stack |

**L1 does not bypass in TUN mode, and that is a limitation of the pinned sing-tun rather than of the
decision this document describes.** `tun.ActionBypass` is honoured by the Linux nfqueue handler, where
it maps to `NfRepeat` with the output mark and the packet leaves by its original path. In all three
TUN stacks — `go`, `gvisor` and `system` — it is handled identically to `ActionAccept`: the dispatcher
installs an accept entry, does not consume the packet, and the stack terminates the connection in
userspace and calls the Handler back. The header of
[native-bypass-trace.md](native-bypass-trace.md) records the trace and the experiments that establish
it.

**Re-verified at sing-tun `v0.9.7-0.20261006124248-d769a7080ca2`**, the revision this fork pins after
absorbing upstream `a4331b8d` ("Rework forward NAT with UDP mapping and fragment support"). That
upstream work reworks forward NAT — UDP mapping/filtering options, a kernel port-selection and
reservation protocol (`tun.PortWithSelectorRange` / `tun.PortWithSelectorReservation`, reached through
the new `UpstreamPort()` chain), fragmentation — and leaves the handling of an `ActionBypass` verdict
alone: the merge changed nothing in how any of the three TUN stacks treats it. The claim above is
therefore unchanged, and it is held there by the same behavioural tripwires rather than by reading
the new revision: `TestANewTrackerOnABypassIsNeverCreated` and `TestABypassFlowIsNeverCounted`
(`protocol/tun`), plus the dispatcher trace this paragraph cites, all pass against the new pin.

So for a TUN client the eligibility decision in this document has **no data-plane effect**: a flow it
marks as bypassable is still proxied in userspace. What it does have is a real effect in Linux
redirect mode.

It is worth being precise about what it does *not* cost, because the first version of this document
claimed one extra rule evaluation and that was wrong. The pre-match verdict is discarded for a direct
TCP or UDP flow whichever verdict it is: the direct outbound answers `PreMatchContinue` for both
networks, there is no `tun.Port` for them, so the stack terminates the connection in userspace and the
router routes it from scratch — the same for a flow the decision allowed, a flow it refused, and a
flow it never considered. The decision's own cost is 15–17 ns and zero allocations either way.

The one cost it *did* have is fixed: the eligible path logged a debug line whose arguments were built
before the logger decided the level was off, which measured at five allocations and about 95 ns per
eligible flow — more than the decision itself, on exactly the flows the feature targets. The message
is now built only when it will be emitted.

**L0 is not "the router, then a bypass".** It runs *before* the router, so it decides with an address
and nothing else. It cannot express a domain, a process or a protocol condition, and it must not be
used to compile a `DIRECT` rule into a route set unless that rule is already authoritative and
IP-only. Its bypass is implemented by installing routes that keep the traffic out of the TUN at all,
which is why it works regardless of what any verdict means.

### L0's one boundary: FakeIP

Because L0 runs first, a FakeIP address — a placeholder this process minted, with no route in the
platform's table and a domain that only the router can recover — would be handed to the OS and
black-holed. Two ordinary configurations reach that:

- `route_address_set` configured: every destination **outside** the set bypasses.
- `route_exclude_address_set` that happens to cover the FakeIP range; `198.18.0.0/15` sits inside
  several broadly written sets.

`JudgeFlow` therefore falls through to the router for a FakeIP destination, at the cost of two prefix
comparisons on a path that already does radix lookups, once per flow rather than per packet, skipped
entirely when no FakeIP transport is configured.

### DNS stays first

The order in `JudgeFlow` is: configured DNS address, DNS by port, the route sets, the router. Direct
Offload does not change it, and a DNS query must reach the DNS router rather than the direct path —
that ordering is what keeps DNS-based ad filtering working. This makes **no claim** about detecting
DoH, DoT or DoQ traffic, and it does not block UDP/443 to intercept QUIC.

---

## What is measured

### Hit rate

The numbers below are the router's verdicts, at the real pre-match entry point, over a model flow mix
(the weights are a model of a desktop proxy's traffic; the per-shape verdicts are exact). They are
**decision** hit rates: read them together with the section above, which says that in TUN mode a
bypassable verdict does not translate into a bypassed flow.

| Flow shape | Weight | minimal | dashboard-enabled |
| --- | --- | --- | --- |
| literal IPv4 TCP | 55 | allowed | refused: tracker |
| literal IPv6 TCP | 15 | allowed | refused: tracker |
| literal IPv4 UDP | 15 | allowed | refused: tracker |
| sniffed domain TCP | 8 | refused: sniffed domain | refused: sniffed domain |
| FakeIP TCP | 5 | refused: FakeIP | refused: FakeIP |
| connected UDP | 2 | refused: UDPConnect | refused: UDPConnect |
| **total** | **100** | **3/6 shapes, 85% of weight** | **0/6 shapes** |

The model-weight row is the decision's coverage, not a data-plane result, and in TUN mode the
data-plane result for L1 is **0% in both columns** - see
[native-bypass-trace.md](native-bypass-trace.md).

**The dashboard number is the finding.** The tracker guard is absolute: it refuses on the *existence*
of a tracker, not on what the tracker would record, so attaching the Clash API or a dashboard
disables L1 for every flow. That is the correct first-round choice — silently losing connection
statistics is not an acceptable optimisation — but it means the L1 gain is real only for setups
without an API. The remedy, if it is ever worth it, is a native accounting bridge, which is a separate
project.

L0, measured where it lives:

| Configuration | L0 hits |
| --- | --- |
| no route sets | 0/4 shapes |
| `route_address_set: 10/8` | 2/4 shapes |
| `route_exclude_address_set: 198.16/12` | 1/4 shapes |
| FakeIP, any configuration | never |

### Cost

From `route/direct_offload_bench_test.go`, on an Apple M1:

| | Cost |
| --- | --- |
| Decision, all conditions pass (L1's per-flow cost where it is honoured) | 14–41 ns, **0 allocs** |
| Decision, refused by one of the cheap conditions | ~5–11 ns, 0 allocs |
| The outbound profile alone | 5.3 ns, 0 allocs |
| **Flow setup, bypassed** | **119 ns, 0 allocs** |
| **Flow setup, userspace** | **1461 ns, 2856 B, 26 allocs** |
| TCP copy, kernel socket pair (L2) | 4742 / 5001 MB/s for 4 / 32 MiB |
| TCP copy, userspace buffers (L3) | 3952 / 5567 MB/s for 4 / 32 MiB |
| UDP per datagram (1400 B) | ~66 ns, 1 alloc |

Two things follow.

**Where a bypass is honoured, it saves about 1.3 µs and 26 allocations per flow, and every byte
thereafter** — the difference between the two setup rows is what L1 avoids creating, and the per-byte
row is what it avoids paying. In TUN mode the first row is not what actually happens: the flow still
pays the second.

**L2 and L3 are indistinguishable here, and that is not a defect in the benchmark.** Loopback is the
friendliest possible case for a userspace copy and the least favourable for a zero-copy one: nothing
crosses a bus either way. Each benchmark asserts which of the two paths it is measuring — the kernel
one hides nothing and the userspace one hides `ReadFrom` — so they cannot silently converge, and the
honest reading is that **both userspace layers pay a copy** and the distance that matters on a real
NIC is the syscall count and the bus traffic, which this rig does not reproduce. Where a bypass is
honoured, its per-byte cost to this process is zero, which is not a claim about bytes per second.

The decision asserts 0 allocs/op as a **test**, not only as a benchmark, so a regression fails the
suite instead of waiting for someone to read a number.

---

## Scope

Offload applies to a TUN inbound, TCP or UDP, a literal destination, a single-outbound chain whose
leaf implements `adapter.BypassableOutbound`, and a flow that survives every eligibility condition.
Everything else keeps the behaviour it had.

Not in this round, deliberately:

- **Tracker accounting on the native path.** A tracker refuses, as above.
- **Outbound chains.** A group introduces selection, lifecycle and accounting semantics of its own,
  and "the selected leaf happens to be direct" does not make those equivalent.
- **UDPConnect.** Connection-oriented UDP has its own socket and NAT semantics.
- **Traffic class.** A native direct flow is outside the upload scheduler's managed domain by
  construction, so `traffic_class` neither grants nor withholds an offload.

---

## Verifying a deployment

Attribution is available where a refusal matters; it is not on the data path.

- `route.BypassVerdict` names the router condition that refused.
- `(*direct.Outbound).BypassBlockers` names the socket-level reason set behind the outbound's
  `CanBypass`, including the ambient network policy and the self-address guard.

Both are diagnostics. Nothing logs per flow, and the decision itself builds no strings.
