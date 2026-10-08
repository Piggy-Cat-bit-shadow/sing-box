# Load balance outbound group

A fork-only outbound type that distributes **new flows** over its members and keeps each flow
on the member it was given.

```json
{
  "type": "loadbalance",
  "tag": "proxy",
  "outbounds": ["hy2", "tuic", "masque", "naive"],
  "strategy": "round_robin"
}
```

A configuration using `type: loadbalance` **cannot be loaded by official sing-box**. It is
this fork's own type, registered by this fork's registry; upstream has no such outbound and
does not silently ignore it — it fails to decode.

## What it is

Per-flow outbound load distribution at the **control plane**. The group chooses a member when
a flow is routed and then gets out of the way: the flow is carried by that member's own data
plane, with the member's own connection, buffering, splice and counters.

```text
flow A -> HY2
flow B -> TUIC
flow C -> MASQUE
flow D -> Naive
flow E -> HY2
```

## What it is not

Not bonding, not striping, not packet-level switching, not multipath, not a session pool, and
not a throughput multiplier. One flow is one member for the flow's whole life; two flows to the
same destination may take different members, and one flow never takes two.

It is also not a way to exceed the capacity of the underlying link. Four members behind one
1 Gbps uplink still deliver 1 Gbps; what the group changes is which member a new flow uses.

## Strategies

| `strategy` | A new flow goes to |
| --- | --- |
| `round_robin` (default) | the next member in rotation |
| `consistent_hashing` | the member the flow's destination identity hashes to |
| `sticky_sessions` | the member the flow's source+destination pair was pinned to, for a bounded time |

The first strategy is the default here, which is a deliberate divergence from Clash-derived
clients, where hashing is the default. Hashing on the destination sends every flow to one site
to one member — for a client whose traffic concentrates on a few sites, that is the opposite of
what the group is for. A configuration that wants the hashing behaviour states it.

### Destination identity (`consistent_hashing`)

The key is, in order of preference:

1. the **registrable domain** (`a.b.example.com` → `example.com`, via the public suffix list),
   lowercased and with a trailing dot removed;
2. the **literal address** the flow is addressed to, canonicalised (a v4-mapped IPv6 address is
   the same destination as its four-byte form);
3. the first resolved address, only when the destination carries no name and no address.

Port, network and source are not part of the key. A domain is preferred over an address so that
a DNS answer that changes family — AAAA on one connection, A on the next — does not move an
affinity that is defined on the name.

The hash is jump consistent hash over the member list, so adding or removing a member moves
about one key in `n` and leaves the rest where they were. The bucket space is the member list,
**not** the currently healthy subset: a member failing must not re-map the flows that were not
pointing at it.

### Affinity lifetime (`sticky_sessions`)

Ten minutes, at most 1000 pins, evicted oldest-first. Expiry is evaluated when a key is read and
the table is swept on insert, so the cache owns no timer and no goroutine. A pin is a
preference, not a promise: if the pinned member is no longer a candidate, the pin is replaced
rather than honoured, and the replacement is pinned in its place.

## Health

Set `url` (and optionally `expected_status`) to make candidate selection health-aware:

```json
{
  "type": "loadbalance",
  "tag": "proxy",
  "outbounds": ["hy2", "tuic"],
  "url": "https://www.gstatic.com/generate_204",
  "interval": "3m"
}
```

The measurements are the **same ones a `urltest` group maintains**, keyed by the member's real
leaf tag and the measurement scope (URL + accepted statuses). Two consequences follow, and both
are intended:

- a member that a failed check removed from the health store is not a candidate here either;
- a loadbalance group and a urltest group configured with the same URL over the same members
  share one body of evidence, so neither can select on a number the other disagrees with.

With no `url`, nothing measures the members and every member stays a candidate: an absent
health entry cannot mean "dead" when nothing ever looked.

With a `url`, a member is a candidate only while it has current evidence — **except** when no
member has any, in which case health filtering is suspended for that selection and the group
falls back to the members that can carry the network. Otherwise a group whose probe target is
unreachable, or whose first check has not finished, would answer every flow with its first
member, which is the degeneration this feature exists to avoid.

When every member is unhealthy the group still answers with a member that can carry the flow.
Refusing would turn a slow or misconfigured probe into an outage.

## Live dial failure feedback and failover

A probe result is evidence about a node; it is not the only evidence. When failover is enabled, a
member a check marked healthy that then fails real traffic is fed back into selection, and the
flow that failed it is retried against one alternate.

Failover is **opt-in** and off by default:

```json
{
  "type": "loadbalance",
  "tag": "proxy",
  "outbounds": ["hy2", "tuic"],
  "strategy": "round_robin",
  "failover": true
}
```

This is a compatibility guarantee, not a tuning knob. Before the option existed the group made
exactly one dial attempt per flow and never recorded a failure; an upgrade must not silently
rewrite "a timeout reports an error" into "a timeout dials another member". With the field absent
the group does not even advertise the failover capability, so the route path resolves and dials it
through the code that existed before the feature — one attempt, no penalty, no retry.

When enabled, a successful first dial is still the end of the story: one flow, one attempt, no
second-guessing. `round_robin`, `consistent_hashing` and `sticky_sessions` are unchanged in the
normal case; the retry is a replacement for a dead path, not a second selection policy.

### Two classifiers, not one errno

A failure is asked two different questions, and they have deliberately different answers, because
the two situations below produce an *identical* final error:

```text
client -> member endpoint      OK
member -> blocked destination  timeout
```

Treating that timeout as "the member is dead" would demote a healthy member for every destination
a client retries. So the flow-level and member-level decisions are separate:

**Retry the flow** (`RetryThisFlow`) — "would this flow have a chance on another member?" This one
is relatively permissive; the flow's alternate is bounded, and nothing has been delivered yet.

| Failure | Retried? |
| --- | --- |
| timeout (`context.DeadlineExceeded`, `os.ErrDeadlineExceeded`, any `net.Error` with `Timeout()`, `ETIMEDOUT`) | yes |
| unreachable (`ENETUNREACH`, `EHOSTUNREACH`, `EADDRNOTAVAIL`, `ENETDOWN`) | yes |
| endpoint refused (`ECONNREFUSED`) | yes — another member's endpoint may be listening |
| caller cancelled (`context.Canceled`), closed by this process (`net.ErrClosed`) | no |
| reset (`ECONNRESET`), `io.EOF`, anything unclassified | no |

**Penalise the member globally** (`PenalizeMemberGlobally`) — "is this member's own first hop
broken?" This one is conservative, and it is the reason the split exists.

| Failure | Penalty? |
| --- | --- |
| `ECONNREFUSED` on a proxying member | yes — the member's own listener refused, before any proxying |
| `EHOSTUNREACH`, `ENETUNREACH` on a proxying member | yes — the member's own route is gone |
| **any timeout** | **no** — a first-hop timeout and a destination-side timeout are the same error |
| `EADDRNOTAVAIL`, `ENETDOWN` | no — local interface state that every member shares |
| `ECONNRESET`, `io.EOF` | no — possibly the remote destination answering and closing |
| anything on a `direct` or `block` member | no — that member dials the *destination*, so the errno describes the target |

The dial stack carries no stage tag: this fork's proxy outbounds return their first-hop transport
error unwrapped, and a destination-side failure is reported in band, on the connection. The one
structural fact available is the member's own kind, which is why a `direct` or `block` member never
earns a global penalty. Where evidence cannot justify a global verdict, the flow still gets its
retry and the ledger stays empty. The practical consequence is that a member which *blackholes*
rather than refusing is not demoted by live traffic; only a health probe retires it.

**Penalty.** One counter per member. At `3` the member is *demoted*: it leaves the primary
rotation. Demotion never deletes health evidence and never interrupts an existing connection. A
demoted member is still an alternate, which is how it earns proof of life: **a successful dial
clears its count to zero**, and nothing else does.

**Failure filter.** While a member is at or above the threshold, candidates are ranked by penalty
count and then by measured latency, and the demoted member is skipped. Below the threshold the
order is configuration order and latency is not consulted, so a group that has not failed a dial
distributes exactly as it always did. With `consistent_hashing` the bucket space is never
reordered — a demoted member only takes its own keys out, via the existing key-stepping, so one
member failing does not re-map every destination.

**Two corrections over the reference implementation.** First, the ledger is scoped to the
**network generation** published by the runtime coordinator: a penalty recorded in generation N
does not demote a member in generation N+1. On a Wi-Fi→cellular handover every member dialled
during the transition can return an unreachable error, and a permanent penalty would demote the
whole group afterwards. Second, a record **expires** after a short TTL, evaluated lazily at
selection time — no timer, no sweeper goroutine. This is safe because demotion is not exclusion:
an expired record makes the member a candidate again, and it can only clear itself for real by
carrying a connection.

**Bounded retry — one budget for the whole flow.** On a failure worth retrying the group re-runs
its own selection with the failed member excluded and dials **one** alternate. The budget belongs
to the user *flow*, not to a group call: a chain such as `outer -> inner` spends **one** alternate
in total, so two dial attempts for the entire chain, no matter how deeply it nests. A per-group
bound would multiply — `outer #1 -> inner #1, inner #2; outer alternate -> inner #3, inner #4` —
so the budget is carried in the context, created by the outermost capability dial and consumed by
every nested one. It owns no lock, no goroutine and no timer, and it is not spent on an attempt
that never starts: a failure that is not retryable, a caller whose deadline has already gone, or a
selection that can name nobody returns before the counter moves.

The retry runs on the caller's context, so it shares the remaining deadline. If the alternate also
fails, the **original** error is returned: that is the failure of the member the group chose. A
successful fallback moves the selection (the rotation, or the sticky pin) and is logged.

The retry lives behind the optional `adapter.FailoverOutboundGroup` capability, which the route
path asks the matched outbound for and which a group only advertises when its configuration opted
in. Every other group type, and every group that did not opt in, resolves and dials exactly as
before.

## Network compatibility

A member is only ever given a flow it can carry. A TCP-only member never receives a UDP flow,
even when it is the rotation's turn. `Network()` reports the union of the members' networks, so
a parent group considers this group for both, and the per-flow check inside selection is what
refuses the individual member.

## Nested groups

The group may contain other groups and may be contained by them. The chain is resolved once per
flow:

```text
selector -> loadbalance -> urltest -> hysteria2
```

Each group makes its own decision for the chain exactly once, and the leaf that results is the
member that is dialed, recorded on the flow and reported by the API. Cycle detection is the
existing start-time dependency check: a configuration that describes a loop is refused when it
loads, not when a flow walks into it.

## Flow semantics

- **TCP**: one decision per connection, before the connection exists. Selecting again is not
  possible for that flow: the chain is frozen and handed to the connection manager.
- **UDP**: one decision per session — per packet connection, not per datagram. Every datagram of
  a session leaves through the member the session was given, which is what keeps NAT mappings,
  QUIC connection IDs and DNS transaction state coherent.
- **Pre-match preview**: the pre-match path resolves the same chain to decide whether a flow can
  be given a port, and that resolution is a *preview*: it moves no rotation and writes no pin. A
  verdict that commits the flow (a flow-capable port) performs its own committing resolution, so
  such a flow also consumes exactly one decision.

## Control plane

`type` is reported as `LoadBalance` and the member list is reported in full. **No current
member is reported**: the group has none, because the member is a property of the flow. The
Clash API omits `now` for this group (as Clash-derived clients do), and the native API reports
an empty `selected`; both still list the group and its members, so a dashboard can present it
without being told a member it is not using.

A connection's recorded chain is the chain the flow took, member included, so the active
connections list shows which member carries which flow rather than only the group.

The group is not selectable: the selection endpoints refuse it rather than pretending to move a
choice that belongs to each flow.

## Traffic class

`traffic_class` works as everywhere else in this fork: the resolved chain is scanned outermost to
leaf, the first explicit policy wins, and an explicit `default` suppresses automatic detection
for the whole chain. Because the class is resolved from the chain the flow actually took, two
flows through one group on different members can carry different classes, and a group-level
policy remains the outermost statement.

## Direct offload

The group does **not** implement the bypass capability. Even with direct members, an eligible
flow stays in userspace: the choice of member is itself policy, and the fork's fast path
requires a single-element chain. Nothing about this feature loosens that.

## Known limitations

- **Failover is TCP only, and only on the route path.** `ListenPacket` is never retried: a
  packet connection is one session, and re-opening it on another member would change the source
  address underneath NAT, QUIC and DNS. A packet-capable member that owns the whole connection
  (`adapter.ConnectionHandler`) is also not retried, because it never returns a connection to
  this layer. A group reached through another group — a selector over a loadbalance group — is
  not the matched outbound, so the capability is not consulted for it.
- **A flow that fails over has already been described.** Trackers receive the resolved chain,
  which names the attempt that was made. A successful fallback is logged and moves the group's
  selection, but the chain recorded for that flow is not rewritten.
- **A flow with more than one candidate address is not failed over and is not re-selected.**
  The connection manager dials each candidate address through the same dialer, so a group that
  owned the dial would make a fresh choice per address and one flow could take two members. Such
  a flow keeps the old single-member behaviour. A member that itself races addresses (`direct`)
  is likewise dialled serially per address through this group, because the group owns the
  attempt sequence.
- **No weights.** A member listed twice receives a proportional share and is warned about at
  start; there is no weight field.
- **No `hash-key: in-user`.** The reference implementation's optional key decorator, which hashes
  the authenticated inbound user instead of the destination, is not ported. The default keys are
  the ones this feature is specified on; the decorator can be added later without changing them.
- **No providers or health from an external source.** Members are configuration tags.
- **The dashboard rendering of a group without `now` has not been verified against a specific
  Clash dashboard**, only against the API shape the reference implementation produces.
