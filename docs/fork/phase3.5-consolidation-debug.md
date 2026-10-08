# Phase 3.5 — consolidation, red-team and integration

What was fixed, what was found, and what is still owed. The engineering record — including the
blockers list, which is the first section there for a reason — is
`phase3.5-consolidation-debug-report.md`.

## 1. What this phase is

Not new features. The previous three phases built a runtime lifecycle, REALITY compatibility, VLESS
application-layer encryption, an XHTTP transport, and a routing/recovery layer. This phase asks
whether that whole is actually correct under error injection, restart, network change, cancellation,
background wake and concurrent close — and treats each previously-recorded limitation as a work item
rather than as an excuse.

The working rule throughout: **an error must be classified by ownership, not by its value.** A local
cancellation and a remote path failure can arrive as the same `context.DeadlineExceeded`, and they
demand opposite responses. Every fix in this phase is an instance of that rule.

## 2. Failure ownership

The taxonomy everything now conforms to.

```text
CALLER
    context.Canceled, a caller deadline, a user stop
LOCAL LIFECYCLE
    Box.Close, group Close, resource suspended, a local stream close, a fan loser we cancelled
FIRST-HOP / MEMBER PATH
    the member's own endpoint refused / unreachable / handshake timeout
DESTINATION
    the remote proxy reported that the target refused, reset or timed out
PROTOCOL
    REALITY verify failure, an XHTTP status mismatch, an H2/H3 framing error, an encryption record error
NETWORK TRANSITION
    ENETUNREACH / EHOSTUNREACH produced by a handover rather than by a member
```

| Consumer | CALLER | LOCAL | FIRST-HOP | DESTINATION | PROTOCOL | TRANSITION |
| --- | --- | --- | --- | --- | --- | --- |
| LoadBalance **retry this flow** | no | no | yes | sometimes | no | yes |
| LoadBalance **global member penalty** | no | no | yes (refused/unreachable only) | **no** | no | yes, generation-scoped |
| DNS group error record | no | no | yes | — | yes | yes |
| DNS group sub-deadline | — | no (it is the group's own detector) | yes | — | — | — |
| XHTTP/H3 verdict | no | no | yes | — | yes | yes, cleared by reset |
| WG recovery trigger | no | no | yes | — | yes | yes, generation-scoped |
| Breaker failure count | no | **no** | yes | yes | yes | yes |

The three rows in bold are the ones that were wrong before this phase.

## 3. The two classifiers, verbatim

One errno table used to answer two different questions, which is how a healthy member gets demoted
for a destination that is down. They are now separate.

```text
RetryThisFlow(err)                 permissive, flow-level
  RETRY   timeouts (context.DeadlineExceeded, os.ErrDeadlineExceeded, net.Error.Timeout(), ETIMEDOUT);
          kernel path errors (EHOSTUNREACH, ENETUNREACH, EADDRNOTAVAIL, ENETDOWN); ECONNREFUSED
  NO      nil, context.Canceled, net.ErrClosed, ECONNRESET, io.EOF, anything unclassified

PenalizeMemberGlobally(member, err)   conservative, member-level
  PENALTY ECONNREFUSED, EHOSTUNREACH, ENETUNREACH — and only when the member's dial is NOT the
          destination dial (a direct/block member's error describes the target, not the member)
  NO      any timeout at any layer; EADDRNOTAVAIL/ENETDOWN (a local interface, shared by every
          member); ECONNRESET/io.EOF; context.Canceled; anything unclassified; anything from a
          direct/block member
```

**A timeout never earns a global penalty.** This is the deliberate consequence of an investigation
finding that this repo's dial stack carries no machine-checkable stage information: a proxy outbound
returns its first-hop error unwrapped, a destination failure the remote proxy reports arrives *in
band on the connection* rather than as the dial error, and `common/dialer`'s wrapping names
interfaces and addresses rather than stages. So `client → proxy timeout` and `proxy → blocked
destination timeout` are literally the same error at the call site.

Where the evidence cannot distinguish the two, the code prefers **retrying the flow** over guessing
that the member is broken. The cost is honest and recorded: a member that blackholes is retried but
not demoted by live traffic, so only the probe retires it.

## 4. Recovery ownership: the lease

Recovery ownership used to be a bare `pending bool`, which had two defects at once.

```text
grant for generation N      pending = true
publish N+1                 pending = false     (bookkeeping reset)
grant for N+1               pending = true
the N rebind finishes       pending = false     <- clears what N+1 owns
```

The ABA let a third trigger in while the new generation's recovery was still running, and — worse —
publishing a generation only reset bookkeeping, so the comment claiming the old rebind was cancelled
described nothing any code did. A rebind blocked in a dial observes its **context** or nothing.

Ownership is now a lease with an identity: `BeginRebind` returns one carrying its id, its generation
and a context; a generation change or a close marks the old lease expired and cancels its context;
`Complete` releases the registration only if that lease is still the owner, so a late completion from
a superseded generation is a no-op rather than an amnesty. The coordinator's own context is a
structural backstop underneath. No goroutine, no timer — it is a field and a `context.WithCancel`.

## 5. One budget per flow

Each failover-capable group had its own "one alternate", so a nested chain reached four or more dials
and multiplied with depth. An attempt state carrying one remaining alternate now travels in the
context, created by the outermost capability dial and consumed by every nested one:
**1 primary + at most 1 alternate for the entire chain, whatever the nesting.**

The alternate is charged only at the moment the dial is about to happen, so a non-retryable failure,
a spent budget, an already-exhausted deadline, or a selection that names nobody all leave it intact.
No global, no lock, no goroutine, no timer.

## 6. Opt-in compatibility

Failover was always on, which meant a config that never asked for it silently changed behaviour from
`A timed out → return the error` to `A timed out → automatically dial B`. That is not an acceptable
default for an upgrade.

A new `failover` boolean on the loadbalance group, default **false**, restores the old semantics. The
gating is behavioural rather than internal: an unopted group is routed through the **pre-capability**
path — the route path resolves and dials the leaf with the same committing walk it always used, with
no preview and no shim — not merely a retry that happens to make one attempt. A migration test decodes
the *same config text* with and without the field and asserts one dial and zero penalties versus two
dials and one penalty.

## 7. Generation-owned DNS election

The `fastest` election was a bare bool. `Reset()` bumped the generation and cleared the records but
left it set, so while an old network's election fan was still unwinding, a query on the new network
could only take the provisional-random path: a lockout whose length was the old fan's, on a network
that no longer existed.

It is now a token carrying its generation and an id. `Reset` invalidates it **by construction** rather
than by clearing it, and a slow old collector can only release its own token. No timer, no goroutine,
no resident machinery beyond a sequence counter, and the single-flight property is preserved within a
generation.

## 8. WireGuard: the early trigger

The recovery worker was started only when a session was already **stale**. A handshake entering its
series is not stale — it becomes stale when the settle window expires, and the code that makes that
decision lives *inside* the worker. So with no worker nobody made the decision, and the early trigger
could only fire as a side effect of some other peer having given up first.

The visible consequence is exactly the failure the trigger exists to remove: a node wakes, its
handshake retries into the dead 5-tuple, and the user waits for the full give-up cycle.

The worker is now started for a handshake in progress as well, which is safe because its loop already
returns as soon as nothing is stale **and** nothing is handshaking, so a handshake that completes
before the window costs one goroutine for its duration and nothing afterwards.

## 9. Strict H3 no-fallback

`disable_version_fallback` was checked *after* the failure was classified, and the classification said
"an expired attempt window is not a failure to report, just try HTTP/2". So a strict configuration
fell back on window expiry — and also armed the H3-broken memory, which made the *next* dial skip H3
and go to HTTP/2 as well.

Strict mode is now checked before classification and covers every way H3 can fail: immediate refusal,
an ordinary error, and window expiry. Nothing is armed on that path either, because arming the memory
is itself a fallback. This matters because the switch is a user-facing option on two config surfaces
(the MASQUE client and the plain HTTP outbound), so "strict" has to mean strict.

## 10. Compatibility summary

| Surface | Before this phase | After |
| --- | --- | --- |
| `loadbalance` with no `failover` field | failover was silently always-on | exactly the pre-failover behaviour: one dial, no penalty, no retry |
| `loadbalance.failover` | did not exist | opt-in bounded failover, default false; a non-boolean is rejected at decode |
| `type: xhttp` in a config file | **rejected** — "unknown transport type" | loads, with the whole option block |
| `tls.reality.key_share` | new in phase 2 | unchanged |
| `vless.encryption` | new in phase 2 | unchanged |
| `disable_version_fallback: true` | fell back on H3 window expiry | strict for every H3 failure mode |
| DNS `group` | new in phase 3 | modes and TTLs unchanged; ownership fixed |
| Everything else | | **no change** |

## 11. Performance and resource behaviour

The rule is that a fix may not buy stability with resident background work.

```text
new permanent goroutines     0
new permanent timers         0
idle CPU cost                ~0   (penalty/idempotency state is one atomic pointer read)
per-transition cost          one epoch publication + N registration notifications; no sweep, no rebuild storm
per-dial added work          two error classifications, one boolean context lookup
new resident state           one lease field, one election token, one attempt-state context value
```

Bounded work, asserted rather than argued:

| Property | Bound |
| --- | --- |
| a 10-member pool with every dial failing | 2 dial attempts |
| nested failover, two or three levels | still 2 dial attempts for the whole flow |
| 8 / 32 / 128 concurrent DNS queries at cold start | exactly one election fan per generation |
| DNS with every member dirty | one attempt, no fan, in every mode |
| DNS record memory on a dead network | capped per member |
| an idle resource's penalty state | one atomic pointer read, no lock, no timer |
| penalty expiry, DNS TTLs, the retest valve | lazy timestamp comparison, or a CAS plus a timestamp |

## 12. Limitations and what is still owed

Full list in the report. The two that matter most:

- **The live half of the reference interop stand has never been run.** There is no Xray binary and no
  external network in this environment. It was driven to a real socket against a stand-in that
  listens and speaks nothing, which proves the gate, the generated configs, the box construction and
  the artifact capture work — and nothing about any wire format.
- **Apple/NetworkExtension and Android are statically and in-process verified only.** No device
  validation has happened.
