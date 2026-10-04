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

- **No failover on a failed dial.** The route path dials the chosen leaf itself, so this group
  never sees that dial and cannot know whether the failure happened before any application byte
  was delivered — the only point at which a retry is safe. The group therefore returns the error
  the member returned. (Clash-derived clients achieve their implicit failover from a generic
  retry wrapper above the group, which sing-box does not have; a retry here would be reachable on
  the detour path and silently absent on the route path.)
- **No weights.** A member listed twice receives a proportional share and is warned about at
  start; there is no weight field.
- **No `hash-key: in-user`.** The reference implementation's optional key decorator, which hashes
  the authenticated inbound user instead of the destination, is not ported. The default keys are
  the ones this feature is specified on; the decorator can be added later without changing them.
- **No providers or health from an external source.** Members are configuration tags.
- **The dashboard rendering of a group without `now` has not been verified against a specific
  Clash dashboard**, only against the API shape the reference implementation produces.
