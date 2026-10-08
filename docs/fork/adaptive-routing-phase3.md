# Adaptive routing and resilience (Phase 3)

How a routing decision reacts to reality: live dial failures, DNS transport selection, and the
MASQUE H3/H2 choice — all under the network-generation and shutdown rules Phase 1.5 established.

The engineering record (per-item status, LX lineage, validation, limitations) is
`adaptive-routing-phase3-report.md`.

## 1. Scope, and what was deliberately not replaced

This phase adds a **resilience layer**, not new algorithms.

| Kept exactly as it was | Added around it |
| --- | --- |
| `round_robin`, `consistent_hashing`, `sticky_sessions`, the affinity map, the round-robin cursor, health filtering via the shared URLTest history | live dial failure feedback, one bounded alternate retry, penalty TTL + generation scoping, a forced-retest valve |
| The three-strategy LoadBalance selection semantics | a candidate **failure filter** that only engages at a threshold and never reorders the hash bucket space |
| The existing DNS transport architecture and its `ResetNetwork` generation barrier | a `group` DNS transport with three modes and an anti-storm survival path |
| MASQUE's own lifecycle (`Start`/`Close`/`Suspend`/`Resume`/`RestartSession`, one reconnect loop, backoff) and its capsule layer | a bounded H3 establishment window so the existing H2 fallback is reachable; UDP fragmentation on the tunnel's own leg |

No second coordinator was created. Everything here uses the Phase 1.5
`common/runtimecoord.Coordinator` epoch, or a private `Reset()`-driven generation where the resource
already had one (the DNS group), and everything is cancelled by `Close`.

## 2. Selection pipeline

The order is load-bearing: **failure filtering happens inside the candidate domain, never instead of
it.**

```text
traffic class / route rule
      │  selects WHICH group (this is where an "AI pool" is expressed: a group whose
      │  member list IS the pool)
      ▼
candidate domain = the group's own published member list
      │
      ▼
algorithm: round_robin | consistent_hashing | sticky_sessions
      │
      ▼
health filter (shared URLTest evidence; "no entry" is not "dead")
      │
      ▼
failure filter (engage only at the penalty threshold; demotion removes
      │         candidacy, it never reorders the hash space)
      ▼
dial ──path-dead failure──▶ penalty + re-run the WHOLE selection excluding the
                            failed member ──▶ one alternate dial
```

Two consequences worth stating:

- **Failover can never leave the permitted pool**, because the group only knows its own members. A
  nested group's failover stays inside the nested group. This is structural, and it is asserted
  rather than assumed.
- **A retry re-runs selection.** It is not `index++`: sticky pinning, hashing, health and the failure
  filter all participate, so the alternate is the *next best permitted* member.

## 3. Failure classification

Small and deliberately explicit. `errors.Is`/`errors.As`, so a wrapped error is classified by cause.

| Verdict | Errors |
| --- | --- |
| **PATH DEAD** → one penalty, one alternate | `context.DeadlineExceeded`, `os.ErrDeadlineExceeded`, `syscall.EHOSTUNREACH`, `syscall.ENETUNREACH`, `syscall.ETIMEDOUT`, any `net.Error` with `Timeout()` |
| **NEUTRAL** → no penalty, no retry | `nil`, `context.Canceled`, `syscall.ECONNREFUSED`, `syscall.ECONNRESET`, anything else |

Three decisions in that table:

- **A refused connection is not a dead path.** `ECONNREFUSED`/`ECONNRESET` means the node *answered* —
  the node carried the flow and the destination refused it. Penalising the node for that would
  demote a healthy exit because a website was down.
- **A caller cancel is a local lifecycle event.** It is not evidence about the node, and retrying for
  a caller who has left is work nobody is waiting for. `Box.Close` arrives the same way, because
  `Close` cancels the group's own context.
- **Unreachability IS path-dead** — which is exactly why the state below is generation-scoped. See §5.

## 4. Live feedback and bounded retry

A probe that succeeded ten seconds ago says nothing about the dial happening now. The live dial is
therefore a first-class signal, not a fallback to the probe's opinion.

- On a path-dead failure the member's penalty count is incremented, and **nothing else changes**:
  below the threshold the selection order, rotation and latency ranking are byte-for-byte what they
  were before this phase existed.
- The retry re-runs selection with the failed member excluded and dials **exactly one** alternate.
  At most **two dial attempts per call**, whatever the pool size — a ten-member pool where every dial
  fails still makes two attempts, not ten.
- The retry uses the **caller's remaining context**. It never manufactures a fresh timeout, or a
  failover could outlive the deadline the caller asked for.
- The **original** error is what the caller sees if the alternate also fails. The alternate's failure
  is recorded, but it is not the story the caller needs.
- A successful dial is **proof of life** and clears the member's record, so a recovered member
  competes normally again.
- `ListenPacket` is never retried: a packet connection is one session, and retrying would change the
  source address underneath NAT, QUIC and DNS.

The forced-retest valve (a health round when a member crosses the threshold) is throttled to once per
two minutes, measured from the **end** of the previous round, with a CAS collapsing concurrent runs.
It exists so a demoted member can earn proof of life without a probe storm.

## 5. Generation semantics — the one place this diverges from the reference on purpose

Penalty state carries the network epoch it was recorded in and expires.

The reference classifies `ENETUNREACH`/`EHOSTUNREACH` as path-dead and keeps penalties **forever**
(only a successful dial clears them), scoped to nothing. On a Wi-Fi → cellular handover those errors
are produced by the transition itself, and every member dialled during it collects a permanent
penalty — so the group can arrive on the new network already believing most of its members are dead,
with only a probe to recover them.

So here:

- a penalty table whose `generation` is not the coordinator's current epoch is **ignored wholesale**
  and replaced on the next write, so a failure on one network cannot demote a member on another;
- a short **TTL** (2 minutes) is compared lazily at selection time. No timer, no sweeper, no
  goroutine — and it is safe precisely because a demoted member is still dialable as an alternate, so
  it can earn proof of life rather than needing the clock to forgive it.

## 6. Sticky and hash behaviour under failure

The rule is: **failure changes candidacy, never topology.**

- **`consistent_hashing`** — the bucket space is the configured member list and is never reordered by
  health or penalty. Demotion only removes a member from candidacy, and the existing key-stepping
  finds the next permitted bucket. So one demoted member does not remap every flow; the flows that
  hashed to *it* move, and everything else keeps its member. When it recovers, its keys return to it.
- **`sticky_sessions`** — a live flow is never migrated. The affinity pin moves only when a fallback
  succeeds, so the *next* flow from that source takes the working member while an established
  connection finishes where it is.
- **`round_robin`** — the cursor advances only on a committed selection, exactly as before. A
  demotion changes which member a slot resolves to, not the rotation.

## 7. Traffic-class isolation

In this fork a traffic class is a **flow property** (used by the dial governor for priority), and the
"AI pool" restriction is expressed by **route rules selecting a different group** whose member list is
the pool. Isolation is therefore structural rather than a predicate that could be forgotten:

- failover runs inside a group, and a group can only return its own members;
- a nested group's failover stays inside that nested group;
- there is no path from a group's retry into a member it was not configured with.

This is asserted by tests rather than left as an argument. Nothing in LoadBalance inspects a traffic
class, and nothing should: a filter that must be *checked* is weaker than a candidate set that cannot
contain the wrong member in the first place.

## 8. DNS group transports

A new DNS server type, `group`, usable anywhere a server tag is (`dns.final`, rules, another group's
`servers`).

**There are no server states.** No down/up, no backoff, no health machine. Each member instead carries
two **tables of expiring timestamps** — errors and wins — and `CLEAN` means "zero live errors":

| Field | Default | Meaning |
| --- | --- | --- |
| `mode` | `stable` | `stable` \| `fastest` \| `parallel` |
| `error_ttl` | 2m | how long a failure keeps a member out of the clean set |
| `win_ttl` | 5m | how long a win keeps a member preferred (fastest only; elsewhere a warning) |

| Mode | Behaviour |
| --- | --- |
| `stable` | Keep the current member while it is clean; otherwise pick a random clean member and make it current. Fans only as a **rescue** when the chosen member's exchange fails. Writes no wins. This is the mode that keeps radio wake and connection count down: a proven member is reused, not re-raced. |
| `fastest` | Among clean members prefer the most live wins; tie broken by stickiness then randomness. With no live win anywhere, **this query** runs the election fan; the first success mints a win and becomes current. |
| `parallel` | No target: fan over all clean members on every query, mint no wins, never set current. |

**The record model is the anti-storm design.** TTL expiry is evaluated lazily on read, so there are no
timers anywhere; a failure also erases that member's wins, and a success erases its errors (and is
explicitly not a win). Record lists are capped at 64 entries per member, because beyond that the
counts are indistinguishable for selection and the cap is what bounds memory on a dead network where
every query adds an error.

### Election, and why a burst is not a stampede

Only the `fastest` election is serialised — by a flag cleared when the fan completes, including on the
abandoned path, so a caller's cancellation cannot leak it. A concurrent query inside the election
window goes to a random clean member and is marked provisional, so it cannot overwrite `current`.
Fifty simultaneous queries at `win_ttl` expiry therefore produce **one** fan, not fifty.

### All dirty

When no member is clean, the group makes **exactly one attempt** against the least dirty member
(fewest live errors → oldest last error → random) and **never fans**, in every mode including
`parallel`. This is the rule that stops a disconnected network from turning 100 queries × 4 upstreams
into 400 connection attempts.

A survival success heals that member back to clean, and stickiness then holds it; a survival failure
records an error, so rotation by oldest error emerges naturally without any counter.

## 9. MASQUE adaptive fallback

The version fallback already existed and was **unreachable in the failure it was written for**: a peer
whose UDP path is silently blackholed (dropped, not refused) made the QUIC handshake wait for the
caller's whole dial budget, and only then did the code try HTTP/2 — by which point the caller had
given up. The node looked like "does not work over UDP" rather than "fell back".

So the H3 attempt now gets its own bounded window inside one dial (`http3EstablishTimeout`, 3s, a var
because tests shrink it), which resolves to the earlier of the window and the caller's deadline. Three
properties make it safe:

- **An expired window is still a failed attempt**, so it marks H3 broken exactly as a refusal does —
  the window is paid once per backoff period, not once per connection.
- **A caller cancel is neutral.** If the caller's context is already done, the dial returns that error
  and does **not** start an H2 fallback: nobody is waiting, and it is not evidence about H3.
- **An immediate refusal behaves exactly as before**, and a non-availability error is still returned
  rather than swallowed into a fallback.

The remembered verdict was already **generation-scoped and time-bounded**: the H3-broken memory backs
off from 5s to a 5-minute cap and is cleared on success, and the MASQUE endpoint's
`InterfaceUpdated` → `RestartSession` → `ResetConnections` clears it on a network change. This phase
corrects the record on that point (see the report) rather than changing it.

**The tunnel's UDP leg may now fragment.** `common/dialer` forbids IP fragmentation by default, which
is right for a general-purpose socket and wrong for a socket whose payload sits deliberately near the
path MTU: encapsulation adds tens of bytes, so an over-size datagram dies *silently* — locally as
`EMSGSIZE`, or on the path as a DF drop whose ICMP PTU never returns. The symptom is "this node does
not work" while a direct node through the same detour is fine. This is a default, not a coercion: an
explicit `udp_fragment` still wins.

## 10. No-background-wake interaction

Inherited unchanged from Phase 1.5 and respected by everything here:

- A periodic health round is marked as background work and cannot wake a suspended expensive
  endpoint; it fails with `ErrResourceSuspended`, which the health layer treats as "not measured"
  rather than "unhealthy".
- A group whose members are idle marks them **unknown**, not dead. The LoadBalance health filter
  already reads "no entry" as "not evidence", and the penalty layer never engages from a probe that
  never happened.
- The DNS group's fan is demand-driven: it runs because a query arrived, never on a timer.
- A manual test is demand in the product sense and may wake things.

## 11. Shutdown

Every piece of new state is `Close`-cancellable, and none of it can wake up after a close:

- the DNS group cancels its run context and merges it with each request's context, so either lifetime
  can end a probe;
- the LoadBalance penalty table is an immutable snapshot behind an atomic pointer — there is nothing
  to stop and nothing that can fire later;
- the retest valve is a CAS plus a timestamp, not a timer;
- the MASQUE H3 window is a `context.WithTimeout` derived from the caller's context;
- `http3EstablishTimeout` expiry never outlives the dial that created it.

## 12. Performance

The goal of this phase is *fewer* pointless probes, not more:

- **No new polling anywhere.** No per-second scan of members, no per-node timer. Penalty expiry and
  DNS TTLs are lazy timestamp comparisons; the only timers are the ones that already existed.
- **The idle path is unchanged.** A group that has never failed reads one atomic pointer; a
  below-threshold record costs one clock read and no lock; the coordinator lock is taken only when an
  unexpired record is actually at the threshold.
- **Bounded work per failure**: one penalty write (copy-on-write) and at most one extra dial.
- **Bounded work per DNS burst**: one election fan per window, one attempt when everything is dirty.
- **Bounded memory**: penalty entries are per member, DNS records are capped at 64 per member.

## 13. Limitations

Recorded here and in the report so nothing is implied by omission:

- **No live-node verification.** No Xray server, DNS upstream or real handover was available in this
  environment; every claim is from in-process tests.
- **The DF/fragmentation fix is not reproduced end to end.** Loopback cannot reproduce it — its MTU is
  large enough that the leg never over-sizes — so the test pins the default being set, not the socket
  flag.
- **Two route-path paths bypass failover on purpose**: a flow with more than one candidate address,
  and a member implementing `ConnectionHandler`. Both exist to keep one flow on one member.
- **A loadbalance nested under a non-capability group** gets no route-level failover; only its
  selection runs.
- **The forced-retest valve's real health round is not asserted**, only its throttle.
- `metadata.OutboundChain` still names the primary attempt after a successful fallback.
