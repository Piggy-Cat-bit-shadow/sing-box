# Runtime lifecycle (Phase 1.5)

How a network-bound resource in this fork behaves after the network changes, after its path dies, and
while the device is idle — and, just as importantly, what it must **not** be woken by.

This phase exists because every expensive resource (a WireGuard UDP socket, a MASQUE H3 session, a
DNS connection pool) was answering those questions on its own, and the answers did not agree. The
foundation below centralises only the decisions that must be shared. Protocol state stays in the
protocol.

## 1. What already existed

Nothing here replaces the existing lifecycle. The pieces a reader must know before touching this
code:

| Layer | What it owns | Where |
| --- | --- | --- |
| `adapter.Lifecycle` / `adapter.Scope` | construction → initialize → start → post-start → close, child scopes, reverse-order cleanup, start/stop timeouts | `adapter/lifecycle.go` |
| Network reset epoch | a monotonic counter advanced as the **first** statement of every reset | `route/network.go` (`NetworkResetGeneration`) |
| Transition state | whether the network is settled, read together with the epoch as one observation | `NetworkTransitionSnapshot` |
| Dial ownership guard | "was this connection produced for the current network" — captured at start, checked at hand-over | `common/dialer/default.go` (`captureEpoch` / `stillCurrentEpoch`) |
| Idle determination | which on-demand endpoints stay expensive, and the device-pause gate | `route/reference.go` (`ReferenceManager.update`, `applyKeepIdle`) |
| Wake/pause authority | how much background work is permitted right now | `common/power` (`Governor.Allow`) |
| Memory authority | OOM thresholds, the aggressive reset, and the idle-memory release | `service/oomkiller` |

Two of these deserve to be stated because they are the reason this phase is small:

**Real traffic and generated traffic are already distinguishable structurally.**
`Router.RouteConnectionEx` / `RoutePacketConnectionEx` are reached by a flow the *device* asked for;
a URLTest probe and a DNS query dial their outbound or their transport directly and never arrive
there. `route/route.go`'s `observeTraffic` is wired to that boundary. This is not a heuristic and
must not be replaced by one.

**The dial ownership guard already exists.** `captureEpoch` returns a closure that answers "is this
operation still owned by the network it started on", including the DURING-transition case. New code
must reuse it rather than add a second epoch.

## 2. The problem, precisely

Three failures, each observed independently:

1. **A dead path is permanent.** After sleep/wake or a Wi-Fi↔cellular handover the per-flow state on
   the path (NAT mapping, or a DPI classification) is gone, but a WireGuard peer keeps retrying
   handshakes into the same 5-tuple until the handshake cycle gives up — and then keeps doing so.
   The endpoint is configured, the device is up, and it never connects again. Nothing reopens the
   socket. LX 041 calls this "the node went bad" and the only user-visible cure is a reconnect.
2. **Recovery has no owner and no bound.** `ResetNetwork` fans out to every endpoint, inbound and
   outbound, and each decides alone what to do. A burst of resets is a burst of work, and a
   background probe is indistinguishable from demand at the point where a suspended endpoint decides
   whether to wake.
3. **Stale work can come back.** An operation started before a reset can finish after it. The dial
   layer rejects such a connection when it is handed over, but nothing cancels it earlier, and
   resources with their own pools (DNS, HTTP) relied on `Reset` alone.

## 3. Invariants

These are the rules the implementation must satisfy. Each has a regression test named in the report.

| # | Invariant |
| --- | --- |
| 1 | **Close wins.** Once an owner's scope closes, no rebind, wake, retry, trim or recovery worker may recreate a resource. Cancellation is observed; nothing outlives its generation. |
| 2 | **The network epoch is monotonic and single.** An operation knows the generation it started in; a result from generation N is never published as a live resource after N+1 began. Reuse `captureEpoch`. |
| 3 | **Transition ≠ stable.** An operation that *started* during a transition is not a stable result even after the commit. Reuse `NetworkTransitionSnapshot`. |
| 4 | **Background work does not wake an idle resource.** A periodic health check, a DNS maintenance dial or a statistics refresh must not spin up a suspended tunnel engine. Demand is what wakes it. |
| 5 | **Stale ≠ dead.** A resource that belongs to the previous network is retired lazily. Existing flows may finish; new work must not be routed onto it; the rebuild happens at the next demand, not eagerly for every resource at once. |
| 6 | **No unbounded waits.** Every recovery step (dial, rebind, connect, handshake wait) carries a deadline and observes cancellation. |
| 7 | **One logical recovery at a time.** Concurrent triggers — a network change, a handshake give-up, a wake, a manual reset — coalesce into one rebind per resource per window. |
| 8 | **No callback under a dangerous lock.** The coordinator holds its lock for state only; protocol callbacks, dials and closes run with it released. |

## 4. The capability model

Centralising these decisions must not force every outbound to grow empty methods. The existing
pattern in this tree is an **optional capability interface**, asserted where it is needed:

```go
// already present, reused as-is
adapter.IdleConnectionKeeper   // SetKeepIdleConnections(bool), CloseIdleConnections()
adapter.InterfaceUpdateListener
adapter.OnDemandEndpoint       // OnDemand() bool, SetKeepIdleConnections(bool)
adapter.NetworkResetCounter    // NetworkResetGeneration()
adapter.NetworkTransitionSnapshotter
```

Phase 1.5 adds exactly one small interface, for resources that want help with *when* to recover:

```go
// A resource that can reopen its network binding after its path died. Implemented by WireGuard;
// MASQUE and the DNS/HTTP pools keep their own lifetime and are handled by their existing Reset.
type Rebindable interface {
    RebindStale(ctx context.Context, reason RebindReason) error
}
```

and one sentinel, which is what lets a probe fail without penalty:

```go
// Returned when a resource is intentionally suspended and the caller is background work. It is not
// a health signal: callers that record health must exempt it.
var ErrResourceSuspended
```

## 5. Event ordering and the coordinator

```text
network reset ──▶ NetworkManager.ResetNetwork
                    │ epoch advanced FIRST (existing)
                    ├─▶ connection reclaim (existing)
                    ├─▶ InterfaceUpdated fan-out (existing, deferred while paused)
                    └─▶ Router.ResetNetwork (existing: http client epochs, DNS transports, caches)
                              │
                              ▼
                   runtimecoord.Coordinator.Advance(epoch)
                              │
                    publish to registered resources (per-resource, coalesced)
                              │
              resource decides: mark stale now, rebuild on next demand
```

The coordinator owns **only**: registration, epoch publication, cancellation, coalescing and the
debounce window. It never dials, never closes a socket, never touches protocol state, and holds no
per-resource state beyond the registration and a timer.

Registration is bound to the owner's `Scope`: a resource registers during `Start` and unregisters in
the cleanup it receives. A closed scope's registration is gone before a later reset can call it.

### Debounce

One logical rebind per resource per window (`RekeyAttemptTime`, 90 s — the same window the handshake
retry cycle uses), shared by every trigger. A burst arrives as one rebind. The window resets when
the reason is a **new network generation** and the last rebind belonged to the previous one, so a
genuine new failure is never swallowed by an old window; it does not reset for repeated
same-generation triggers.

## 6. WireGuard (LX 041)

Two triggers live in-tree; a third already exists as the wake path.

1. **Give-up (safety net).** The handshake retry cycle exhausts (`device/timers.go`, ~90 s of
   retries under demand). The peer's session state moves to `Expired` (or `None` when it has no key
   material), which is delivered through `Device.SetSessionStateFunc`.
2. **Early, on a provably dead session.** A handshake that has been in progress for
   `earlyRebindDelay` (15 s) without reaching `Established`. The device publishes
   `PeerSessionHandshake` when the retry series starts and `PeerSessionEstablished` when it
   succeeds, so "still handshaking after 15 s" is the same evidence the give-up cycle would produce,
   read earlier. A rekey on a healthy tunnel also publishes `Handshake` briefly; if it completes, the
   flag is cleared and nothing happens. This is the trigger that collapses the field-reported 0–90 s
   window a user sees as "the node is dead".
3. **Nudge.** The consumer says "the device just woke". This fork already routes
   `Wake()`/`WakeNow()` → `PauseManager.DeviceWake()`, so trigger 3 needs no new API — only a
   callback registration. It is deliberately a SEPARATE callback (`onDeviceWake`) from the existing
   `onPauseUpdated`: `EventDeviceWake` means the device woke (the field case LX 041 is about), while
   `EventNetworkWake` means the routing environment returned, and conflating them would either miss
   the device wake or rebind on every network change twice. The nudge applies the same stale
   predicate and skips a suspended endpoint.

A successful handshake clears the stale flag, so a recovery that worked is not retried. The worker
is created lazily on the first give-up and exits when no peer is stale and none is handshaking, so
a healthy, sleeping or closed endpoint has no goroutine, no timer and no traffic.

Contract, all three:

- **The port moves only when it may.** `listen_port` unset → the socket is reopened with a fresh
  ephemeral port (the point of the fix: a new 5-tuple). `listen_port` pinned → the same port is
  reused, and the log says recovery was limited. The user's configuration is never silently changed.
- **Passive.** No timer, goroutine, traffic or allocation while healthy, asleep or closed. The
  callback records state; the worker only exists while a rebind is scheduled.
- **A sleeping endpoint is marked stale, not woken.** Trigger 1/2 cannot fire while a device is
  down (the retry cycle is not running), and trigger 3 skips suspended/idle/not-started endpoints.
- **`Close` cancels.** `Close` sets a flag under the same lock the worker reads and runs the
  registration's removal, so a scheduled rebind cannot resurrect the device. Tested for both the
  "scheduled but not started" and the "in flight" shapes.
- **The callback never calls back into `Device`.** `SetSessionStateFunc` is delivered under the
  peer's session-state lock, so `sessionStateChanged` records primitives, takes only its own lock,
  and nudges a non-blocking channel.
- **`IpcGet`/`IpcSet` are called outside the endpoint's own lock.** The rebind holds no endpoint lock
  while calling into the device, which is the shape of the self-deadlock this transport already paid
  for once (`Start` does the same, for the same reason).

## 7. MASQUE

Unchanged lifetime (`Suspend`/`Resume`/`RestartSession`, one `loop()` goroutine, exponential
backoff). Phase 1.5 verifies and pins three properties, and fixes what is missing:

- a stuck `ReadResponse` is cancelled by the dial context (`context.AfterFunc` → `CancelRead` /
  `CancelWrite`), so a peer that completes the QUIC handshake and never answers CONNECT does not
  park a build;
- the remembered HTTP/3 preference cannot outlive the transport epoch: `ManagedTransport.Reset`
  swaps the epoch, so the new `http.Client` starts with no broken-H3 memory;
- `Suspend`/`Resume`/`RestartSession` cannot stack reconnect workers — a racing dial is discarded.
  This is now assertable rather than intended: `Client.ActiveLoops()` reports the loop count, and the
  lifecycle test drives 20 rounds of restart/suspend/resume and requires it to stay at one.

Nothing in the MASQUE client needed changing for the network-generation model: the transport epoch
replacement (`ManagedTransport.Reset`) already discards the remembered H3 verdict, and the H3 CONNECT
wait was already cancelled by the dial context (`context.AfterFunc` → `CancelRead`/`CancelWrite`).
Both are now pinned by regression tests rather than left as an audit conclusion.

## 8. DNS

No architecture change, and no change was needed. The generation barrier already exists and is
stronger than a pool reset: `dns.Router.ResetNetwork` advances the generation **first**, then resets
every transport, so a response captured before the reset cannot be stored after it. `ConnPool.Reset`
swaps state and closes the old connections outside the lock. The hazards LX 108 named each already
have a named test:

| Hazard | Pinned by |
| --- | --- |
| a dial started before a reset is handed out afterwards | `TestDialStartedBeforeResetIsNotHandedOut` |
| an idle connection is reused after a reset | `TestIdleConnectionIsNotReusedAfterReset` |
| a connection from a replaced state is re-pooled | `TestReleaseOfAConnectionFromAReplacedStateIsNotPooled` |
| the serial pool drops connections on reset | `TestSerialPoolResetDropsConnections` |
| one reset advances exactly one epoch | `TestGenerationAdvancesOnlyOncePerReset` |
| a late response is not recorded | `TestLateResponseAfterResetIsNotRecorded` |

Phase 1.5 contributes the other half: idle DNS and HTTP pools are now part of the **memory-trim**
path (see below), which they previously were not.

## 9. Memory pressure

`service/oomkiller` already owns the policy: thresholds decide when memory is a problem, and the
aggressive path (`NetworkManager.ReleaseMemory`) is a full reset plus idle-connection close. That
aggressive path is deliberate for a true OOM. What was missing is the **progressive** pass — release
what is cheap to release when memory is elevated but not critical, without going near active flows
and without triggering any reconnect:

```text
elevated           → CloseIdleConnections across outbounds + DNS transports, drop caches
                     (never: rebuild, wake, or touch a resource carrying traffic)
threshold crossed  → existing aggressive ReleaseMemory
```

The trim path is: close idle pools, purge caches, release scratch buffers. It must **reduce memory
only** — if a trim can cause a dial, it is not a trim.

What is wired now:

```
oomkiller.adaptiveTimer.releaseIdleMemory   (memory elevated, below the trigger)
    └─▶ NetworkManager.TrimMemory(ctx)
            ├─▶ Router.TrimIdleResources() ─▶ ReferenceManager.TrimIdleResources()
            │        ├─ outbound idle connections (IdleConnectionKeeper)
            │        └─ DNS transport connections  ← these were previously left out
            ├─ endpoint idle connections
            └─ outbound idle connections
    └─▶ runtimeDebug.FreeOSMemory()

threshold / growth-rate crossed      (the existing aggressive path, unchanged)
    └─▶ NetworkManager.ReleaseMemory(ctx)  = ResetNetwork + close idle
```

`Reset` and `Trim` are deliberately different methods on the manager and on the router, and two tests
assert the difference: a trim must not advance the network generation, and `ReleaseMemory` must.

## 10. Shutdown

`Scope.Close` runs cleanups in reverse registration order. A resource registered after the
coordinator is therefore unregistered before the coordinator stops, and the coordinator's own stop is
registered early enough to run last. Nothing needs to be added to `Box.Close`.

## 11. Known limitations

- A pinned `listen_port` cannot heal by changing the 5-tuple. Recovery then only reopens the socket;
  if the intermediate device has pinned the flow, that is not enough. This is the honest limit of an
  in-tree fix and is logged when it applies.
- Trigger 1/2 depend on `Device.SetSessionStateFunc`, whose callback contract forbids calling back
  into `Device`. Proactive re-initiation with **zero** pending demand is therefore not reachable
  through the pin's public API; both real scenarios are demand-driven, so the next packet initiates
  on the fresh socket.
- Platform lifecycle (foreground/background, NetworkExtension memory limits) stays where it already
  is. No new platform API is added.

## 12. Future integration (XHTTP, Naive, QUIC)

When a new transport arrives it should:

1. register with the coordinator during `Start` and unregister in the cleanup it is handed;
2. capture the dial ownership guard at the start of any operation that produces a reusable resource,
   and refuse to publish a result that began in a previous generation or during a transition;
3. return `adapter.ErrResourceSuspended` rather than waking a suspended resource when the caller is
   background work;
4. keep its own protocol state. The coordinator carries no protocol knowledge, and a transport that
   adds a state to the coordinator is a design error.
