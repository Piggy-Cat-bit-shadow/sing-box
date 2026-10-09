# Post-wake reuse: the freshness epoch

What this fork does about reusable state that survives a sleep, and why it is neither of the two
obvious answers.

## The defect this closes

An Apple packet tunnel that is paused and then resumed on the SAME interface has no network
transition. Nothing in the network epoch moves, so every pooled resource that existed before the
sleep is still "current", and the first flow after the resume is offered one of them. If the path
died while the device was asleep - a carrier NAT mapping expired, a Wi-Fi station entry was dropped,
a server-side idle timeout fired, a stateful firewall forgot the flow - the socket is not closed and
does not report an error. It blackholes. The write succeeds into the local buffer, the retransmission
timer runs, and the user watches a spinner for seconds that no configured timeout is short enough to
cut.

That is the shape the Telegram report has: spinning, slow images, a long first packet, on the same
Wi-Fi or the same cellular interface, most often after the screen has been off.

## Why not "close the pool when the screen goes off"

`CommandServer.Pause` used to call `CloseIdleConnections()` the moment the device paused. It is a
correctness-first answer and it is the wrong trade, because "the screen went off" is not "the
connection is dead":

- a glance at the lock screen, a notification dismissed, a photo taken - each of these is a pause,
  and each of them would throw away DNS, TCP, TLS and QUIC state that the next second of use needs
  back;
- the unlock then pays for a burst of handshakes at exactly the moment a person is waiting;
- a phone in a pocket for five minutes and one in a pocket for five seconds cost the same, which is
  the definition of a policy that is not measuring anything.

So the pause releases nothing. It changes what is permitted (see `power-governor.md`), and the reuse
question is answered where it can actually be answered: at the resume, with a measured sleep
duration.

## Why not "wake means reuse everything"

Because the sleep is exactly when a resource stops being verifiable. Nothing probed it, nothing wrote
to it, and the middle of the path - the part this process does not own - may have forgotten it. A
resume that hands the pre-sleep socket to the first request is betting the user's first impression on
an untested assumption.

## Why not "wake means reset the network"

`ResetNetwork` tears down every transport and every ownership epoch. Using it for a resume would:

- kill active flows - a call, an upload, a download, a hotspot client;
- reconnect everything at once, which is the wake storm the power policy exists to prevent;
- spend the radio on handshakes for resources nobody asked for;
- make the sleep boundary indistinguishable from a real handover, so the network epoch would stop
  meaning what it means.

A hard reset stays reserved for a real network transition.

## The four kinds of reusable state, and who owns each

The action a boundary may take is decided by what a resource IS, not by which protocol it belongs to,
so the classification comes first and the owners are then listed against it.

| state | how it is identified | what a resume boundary may do |
|---|---|---|
| **active flow** | a stream/request with bytes in flight: a call, an upload, a hotspot client, a response body mid-read | nothing. It keeps its connection, on every path. |
| **active session** | a multiplexed connection that has work on it but may also be handed MORE work: a mux session with a live stream, an XHTTP pooled connection with `openUsage > 0` | refuse NEW work on it, keep the work already on it, tear it down when the last stream leaves. This is `adapter.ReuseSuspect`, and it exists because an open stream is not proof of liveness - it can be open and silent across a sleep. |
| **idle reusable resource** | a pooled connection or session with no user at all: an HTTP pool entry with no in-flight request, a mux session whose last stream ended, a QUIC session with `streams == 0`, a DNS transport's parked socket, an XHTTP connection with `openUsage == 0` | retired, once the policy says the sleep was long enough. The next demand dials a fresh path; nothing dials on its own. |
| **network-bound transport** | WireGuard, MASQUE, OpenVPN, OpenConnect, the Tailscale endpoint, the Cronet engine | untouched by the reuse boundary, and not reachable from it. These are tunnels, not pools: their keep-idle method suspends the tunnel itself, which is a much larger action than dropping a socket, and resuming one would be a dial with no demand behind it. Their liveness belongs to their own protocol (the WireGuard rebind nudge, MASQUE's keepalive). |

The owners, as they exist in the tree. Every one of these was read rather than assumed, and the
"boundary action" column is what the reference manager's walk actually calls on it:

| owner | what it holds | boundary action |
|---|---|---|
| `common/httpclient.Manager` | every pooled transport behind provider refresh, remote rule sets, the dashboard and the API: `http1Transport`, `http2Transport`, `http2FallbackTransport`, `http3Transport`, `http3FallbackTransport`, and `appleTransport` (URLSession) | idle-only release per transport (`Manager.CloseIdleConnections`), reached by the walk's `adapter.IdleConnectionReleaser` assertion — NOT by `adapter.IdleConnectionKeeper`, which it does not implement; see residual risk 4. The Apple one retires the old `NSURLSession` and installs a new one, so an in-flight request finishes on the session it started on. |
| `transport/v2rayxhttp` (XMUX) | one pooled HTTP connection per session | `RetireSuspect`: idle connections closed, busy ones refused new streams and torn down on the last release. Also `CloseIdleConnections` for the trim. |
| `protocol/vless` | the transport above, plus the optional `sing-mux` dialer | forwards `RetireSuspect` to a transport that has it; forwards `CloseIdleConnections` to both. |
| `transport/v2raygrpclite`, `v2rayhttp`, `v2rayquic` | their own connection pools | idle-only release. They have no session that mixes active and new work, so the idle release is the whole answer. |
| `dns/transport` (`tcp`, `tls`, `https`, `quic`, `udp`, `multiplexer`) | parked sockets and QUIC sessions | idle-only release, plus `SetKeepIdleConnections` for eligibility. |
| `protocol/anytls`, `hysteria`, `hysteria2`, `tuic`, `trojan`, `vmess`, `shadowsocks`, `snell`, `ssh` | their protocol sessions | idle-only release. |
| `protocol/tailscale` | the tailcat node | idle-only release, which waits for the goroutine it cancels - under its own lock and with no lock of the walk held. |
| `sing-mux` (dependency) | sessions, each with a stream count | idle-only release. It has no no-new-stream state, so a session with a live stream still takes new streams: **KNOWN LIMITATION**, see the residual risks. |
| `protocol/naive` (Cronet) | Chromium's socket pool, not this tree's | none available. `CloseAllConnections` is all-or-nothing and is reserved for a real network change. **KNOWN LIMITATION**, see the residual risks. |
| the on-demand endpoints: `protocol/wireguard`, `masque`, `openvpn`, `openconnect`, `tailscale/endpoint.go` | the tunnel itself | `SetKeepIdleConnections` only, reached from the eligibility pass (the device level) and not from the boundary walk. They implement no `CloseIdleConnections`, so the boundary cannot suspend or resume them. |

`Box.CloseIdleConnections` and the DEEP_IDLE transition both use the idle-only walk
(`ReferenceManager.retireIdleResources`); the resume boundary uses the stronger walk
(`retireSuspectResources`), which applies the idle release AND the drain. The trim path deliberately
never drains: a memory pass that made the next request dial a different connection would be a
reconnect trigger.

## The two epochs, and why they are not one

```
network epoch   (common/runtimecoord.Coordinator)
    a REAL transition: Wi-Fi -> cellular, a default interface change, an environment change
    action: reset - every transport and every ownership epoch
    monotonic, published to every registered network-bound resource

reuse epoch     (common/power.Governor)
    a sleep boundary on an unchanged network
    action: distrust - retire IDLE reusable resources, keep active flows, dial nothing
    monotonic, published to the reference manager, which owns the pools
```

They are deliberately separate because they answer different questions and their correct actions are
different in kind. Collapsing them either resets on every resume (a storm) or keeps a blackholed
socket after a handover (the bug this document is about).

The device axis is a third thing again, and the resume is not a device wake:

```
device paused / device wake   -> the LEVEL: is the device usable, may speculative work run
sleep started / resumed       -> the EDGE: how long was the sleep, is reusable state still current
```

On iOS the platform resumes the extension for every push and background task while the phone is
still locked, so a resume must not release health checks, probes or provider refreshes. It does
however prove that time passed, which is all the reuse epoch needs.

The four Apple facts that carry those two axes, and the one asymmetry in the mapping - a display
turning on publishes the edge and NOT the level, while an unlock publishes both - are in
`box_lifecycle.go`, which is also where the reasoning for it lives.
`docs/fork/apple-screen-state-observer.md` covers the client half: the patch that reports the two
facts, and what it deliberately does not do.

## The pause/wake chain, with the file each step lives in

```
NEPacketTunnelProvider.sleep()            clients/apple/Library/Network/ExtensionProvider.swift
  -> commandServer.pause()                experimental/libbox/command_server.go  Pause()
     -> Box.DeviceSlept()                 box.go -> box_lifecycle.go  slept()
        -> Governor.SleepStarted()        common/power/governor.go              (records the instant)
        -> PauseManager.DevicePause()     github.com/sagernet/sing/service/pause (the LEVEL)
           -> pause.EventDevicePaused
              -> applyPauseEvent          box.go
                 -> Governor.SleepStarted()  (idempotent: the same sleep is not measured twice)
                 -> Governor.DevicePaused()  (the LEVEL: QUIESCENT, DeepIdle timer armed)
              -> ReferenceManager callback   route/reference.go Start()
                 -> SetKeepIdleConnections(false) on on-demand endpoints only

NEPacketTunnelProvider.wake()             clients/apple/Library/Network/ExtensionProvider.swift
  -> commandServer.wake()                 experimental/libbox/command_server.go  Wake()
     -> Box.DeviceResumed()               box.go -> box_lifecycle.go  resumed()
        -> Governor.Resumed()             common/power/governor.go   (the EDGE and nothing else)
           -> measures the sleep on the WALL clock
           -> advances the reuse epoch and publishes the verdict
              -> ReferenceManager.onReuseBoundary   route/reference.go
                 -> retireSuspectResources()          route/reference.go
                    -> adapter.ReuseSuspect.RetireSuspect() where a pool has it
                       (transport/v2rayxhttp: refuse new streams, keep live ones)
                    -> CloseIdleConnections() on every other keeper reachable from the
                       outbound manager, the DNS transports and the HTTP client service

displayStatus / lockstate                 Library/Network/ScreenStateObserver.swift (client patch)
  -> commandServer.recordScreenState(on)  experimental/libbox/command_server.go
     -> Box.ScreenStateChanged(on)        box.go -> box_lifecycle.go  screenState()
        off -> slept()   (edge + level, as above)
        on  -> resumed() (the EDGE only: a push notification lights the lock screen)
  -> commandServer.recordLockState(locked)
     -> Box.LockStateChanged(locked)      box.go -> box_lifecycle.go  lockState()
        locked   -> slept()              (edge + level)
        unlocked -> woke()               (the EDGE, then the LEVEL: the only release)

commandServer.wakeNow()                   the dedicated host event (Android's Doze exit, an
                                          explicit user-present fact, an embedder)
  -> Box.DeviceWoke() -> box_lifecycle.go  woke()
     -> Governor.Resumed() then PauseManager.DeviceWake()
        -> pause.EventDeviceWake -> applyPauseEvent -> Governor.Resumed (no-op) + DeviceWake
```

Three properties of that chain are load-bearing, and all three were missing before this work:

1. **The level is latched and the edge is not.** On Apple nothing but an unlock lifts the device
   pause, so `PauseManager.DevicePause()` is a no-op after the first sleep. A governor driven by the
   level would measure the first sleep of the process and trust every later one; that is why
   `SleepStarted`/`Resumed` exist as edges, and why every Apple fact publishes one.
2. **The verdict is published before the release.** `woke` publishes the reuse edge and then moves the
   level, so a pool that predates the sleep has already been retired when the speculative work it
   releases starts to dial.
3. **A display turning on is not an unlock, and an unlock is not a resume.** The two are separate facts
   with separate consequences; collapsing them either runs URLTests for a pocketed phone or leaves the
   tunnel without liveness for the life of the process.

## The policy

All of it is in `common/power.Policy.ReuseFreshness`, and nowhere else:

| sleep | verdict | what happens |
|---|---|---|
| `< SuspectAfter` (5s) | `keep` | nothing. The epoch does not move and no observer runs: the connection a person is about to use again is still pooled. |
| `>= SuspectAfter` (5s) | `suspect` | the epoch advances and the verdict is published. Pools are kept by policy: the middle band is a published state, not an action, because churning a pool a short sleep usually survives costs a handshake for no correctness gain. |
| `>= RetireAfter` (15s) | `retire` | the epoch advances and idle reusable resources are retired, so the next demand dials a path that is known to be new. Active flows are untouched and nothing dials. |
| unmeasurable | `retire` | a backwards wall clock (NTP, a manual change) is not evidence of a short sleep. The strict verdict is the safe one. |

The values are **provisional tuning, not measured optima**, and the asymmetry behind them is what to
keep in mind when changing them: retiring an idle pool costs one handshake the next demand would have
paid anyway, while keeping a dead one costs the multi-second stall this whole stream exists to
remove.

One measurement detail that is not cosmetic: the sleep is measured on the **wall clock**, with the
monotonic reading stripped (`time.Time.Round(0)`). Go's monotonic clock on darwin is
`mach_absolute_time`, which does not advance while the device is asleep, so a monotonic subtraction
would report a five hour sleep as a few milliseconds.

## What the retire is, and what it is not

`ReferenceManager.retireIdleResources` is the one walk over the core's reusable pools. Its contract:

- it reaches every outbound, every DNS transport, and (for the future) any endpoint that implements
  `adapter.IdleConnectionKeeper`;
- it can only close a resource with no active user traffic, and it can never dial - that is a
  property of the keepers, and it is what every new keeper has to establish before it is added;
- it does not reach the on-demand tunnels today, because they implement `SetKeepIdleConnections` (a
  suspend/resume of the tunnel itself) and not `CloseIdleConnections`. Resuming them at a resume
  would be a dial with no demand behind it, which is forbidden.

## Locking, blocking and Close ordering

The boundary runs on whichever goroutine observed the resume - on iOS that is the platform's own
callback thread - so the locking has to be stated rather than assumed.

- **The governor's lock is not held while an observer runs.** `flushNotifications` reads what is owed
  under `access`, releases it, and only then calls the observers. An observer that reads the governor
  (which the reference manager's does, indirectly, on later boundaries) therefore cannot deadlock
  against a transition, and there is a test that would hang rather than pass if that changed:
  `common/power.TestReuseObserverRunsWithTheGovernorUnlocked`.
- **No lock of this work is held across the walk.** `ReferenceManager.retireIdleResources` takes no
  lock of its own: it reads the manager lists from the service context and calls each keeper. The
  reference manager's `closed` flag is an atomic, not a lock.
- **Each keeper's `CloseIdleConnections` is expected to be bounded and to take only its own lock.**
  That is the contract the walk is built on, and it is the pre-existing contract: `Box.CloseIdleConnections`
  already reached the same keepers from the DEEP_IDLE path and from teardown. The one implementation
  that waits for anything is the Tailscale tailcat node, which waits for a goroutine it has just
  cancelled (`tailcat_node.go`, `meowWait.Wait()`), under its own lock and with no lock of ours held.
  Every other keeper closes what it has already detached from its pool, or arms a deferred close on a
  busy connection and returns.
- **The retire is synchronous on purpose.** Deferring it to a goroutine would let a flow that arrives
  in the first milliseconds after a resume dial into a pool that had not been retired yet - which is
  the exact race this exists to close. The work is bounded, and the alternative is not a latency
  trade but a correctness hole.
- **Close wins.** `ReferenceManager.closed` is set by a cleanup registered last in `Start`, so it runs
  first at teardown: a boundary already in flight becomes a no-op before the pools it would reach are
  torn down. The governor is closed before the scope that owns the manager, and every publishing entry
  point checks its own closed flag, so no boundary can be *started* after teardown either.

## Residual risks, stated rather than assumed away

1. **A multiplexed session is DRAINED, not closed.** This was the first residual risk and it is now
   closed where it can be. `adapter.ReuseSuspect` is the capability "no new work on what you hold now,
   while the work already on you finishes"; the reference manager's boundary walk calls it in addition
   to the idle release, and `transport/v2rayxhttp` implements it: a pooled XHTTP connection that
   predates the boundary is refused new streams, keeps the streams already on it, and is torn down
   when the last one leaves. An open stream is deliberately not treated as proof that the path
   survived - it can be open and silent across a sleep - which is why draining rather than reuse is
   the boundary's answer. The limits of the claim are exact: `sing-mux` is an external module with no
   no-new-stream state (below), and a stream that was handed a connection in the window between the
   boundary and the drain is unaffected, because killing it is the thing this must never do.
2. **The sing-mux pool cannot drain.** `github.com/sagernet/sing-mux` (root `go.mod`) exposes
   `SetKeepIdleConnections` and `CloseIdleConnections`; the latter releases only sessions whose
   stream count is zero (`client.go`, `releaseStream` keeps a session while `streams > 0`), and
   `selectSession` hands out any session still in the list. There is no no-new-stream state and no
   hook that would let this tree express one from outside, so a mux session carrying a live stream can
   still take a new stream. Closing it instead would break the live stream, and forking the module for
   one method is out of scope for this work. Recorded as a KNOWN LIMITATION with the code path above.
3. **The Cronet engine cannot participate.** `protocol/naive` drives a Cronet engine whose only
   connection operation is `CloseAllConnections` (`cronet-go`, `engine_cgo.go`), which tears down
   in-flight requests as well; `InterfaceUpdated` already uses it for a real network change, which is
   the action it is correct for. There is no idle-only or no-new-stream API in the pinned module, the
   isolation key that selects Chromium's pool is written per request from the configured concurrency
   and is not mutable after construction, and this tree has no pool of its own to drain - the naive
   outbound is one CONNECT per flow. So naive is deliberately not a keeper: the only two actions
   available are "retire everything including live requests" (forbidden) and "do nothing" (what
   happens today, and the safe one). A fix needs an idle-only API from `cronet-go`.
4. **The HTTP client service pools now participate — but they did not, for one commit.** The intent
   was right and the implementation was wrong in a way nothing could see.
   `common/httpclient.Manager.CloseIdleConnections` releases the idle connections of every transport
   it owns without replacing any of them (that distinction is what separates it from `ResetNetwork`,
   and it is pinned by a test), and the reference manager's walk reaches the manager through
   `adapter.HTTPClientManager`. What the walk then did was assert
   `httpClientManager.(adapter.IdleConnectionKeeper)` — the BUNDLED capability, whose other half is
   `SetKeepIdleConnections` — and `*httpclient.Manager` has never implemented
   `SetKeepIdleConnections`. The assertion therefore failed at run time, on every boundary and on
   every walk, and the fourth owner of reusable state stayed exactly as unreachable as it had been
   before the method was written. Nothing said so: there is no compile error for a failed type
   assertion, the walk reported `retired` without it, and `TestTheBoundaryReachesTheHTTPClientService`
   passed against a fake that implemented both halves, so it could not distinguish the real manager
   from the fake standing in for it.

   Closed by splitting the capability rather than by widening the manager:
   `adapter.IdleConnectionReleaser` is `CloseIdleConnections` on its own, `IdleConnectionKeeper`
   embeds it, and the retire walks assert the releaser because releasing idle resources is the only
   thing they call. `route/reusable_owner_inventory_test.go` pins both directions — the reflection
   assertion that `*httpclient.Manager` is a releaser and is NOT a keeper, and
   `TestTheWalkReachesTheRealHTTPClientManager`, which drives the real manager through both walks and
   returns 0 instead of 1 on the old assertion. That second test is the one that would have caught
   this; it did not exist because the fake was written first.

   The general lesson is worth keeping, because this file has now recorded two closures that were not
   closures: **an interface assertion in a walk is an untested claim unless the walk is driven with
   the real type.** `common/httpclient` is the only owner reached that way; the other three are
   reached through manager lists, which the fakes do exercise.
5. **A client that reports no lock fact keeps its pause.** The core releases the device level on an
   unlock and on an explicit host event only; it does not guess. See
   `docs/fork/apple-screen-state-observer.md` for the patch, the public-API fallback if the Darwin
   notifications ever stop being posted, and the reasoning for not using a timer.
6. **macOS never enters the device axis.** `CommandServer.Pause` returns for anything that is not
   Android or iOS, so a Mac that sleeps has no pause and therefore no reuse boundary. The mechanism
   here is platform-agnostic; what is missing is a Darwin client that reports the sleep and a wake
   that lifts it.

## Device validation runbook

The code is wired and logic-tested; the following cannot be established without a device, and each
item names what to observe rather than what to hope for.

### 1. The publication chain is alive

Debug logs at a resume:

```
reuse: epoch 1, sleep 47.2s, retiring idle connections of 6 reusable pool(s); active flows untouched
```

- `sleep` must be the real screen-off duration. If it reads milliseconds for a five minute lock, the
  wall-clock measurement has been broken (see above).
- One line per sleep, not one per push: a repeated resume inside one locked period must not log
  again. If it does, the edge coalescing is wrong and a pocketed phone will churn its pool.
- No line at all for a sub-five-second pause, and only the `suspect` line between five and fifteen
  seconds.

### 2. A/B: is stale reuse the variable

This is the prompt's conviction experiment, and it stays a device experiment because it needs the
real middle of the path:

- A. temporarily restore `CommandServer.Pause -> Box.CloseIdleConnections()` (`DIAGNOSTIC ONLY`, never
  shipped) and repeat the Telegram matrix. If the stalls disappear, stale reuse is confirmed as a
  main cause.
- B. temporarily set the wake stagger to zero and repeat. If A helps and B does not, the pool is the
  variable and the probe delay is not; if both help, stale reuse and delayed liveness detection are
  both present.

### 3. The matrix

| scenario | sleep | network | expected |
|---|---:|---|---|
| Telegram foreground, open 10 uncached images | 15s | Wi-Fi | no stale stall; one fresh path per flow is acceptable |
| same | 60s | Wi-Fi | no multi-second stall; the epoch must have retired the pool |
| same | 5min | Wi-Fi | fresh dials, but no spinner |
| same | 60s | cellular | same as Wi-Fi |
| Telegram background, push, then foreground | 60s | Wi-Fi | first image loads without a blackhole wait |
| Safari first paint | 60s | Wi-Fi | no abnormal stall |
| WeChat images | 60s | Wi-Fi | no blackhole wait |
| long download | sleep/wake | Wi-Fi | the transfer is NOT interrupted, and its connection is not torn down |
| voice/video call | sleep/wake | Wi-Fi | the call does not drop |
| hotspot | screen off | Wi-Fi/cellular | forwarding does not stop because a pool was cleared |
| cold start after first sleep | — | — | health checks, provider refresh and statistics resume (see the device-axis note below) |

### 4. The device axis: the latch is closed in the core, and the client patch is in this repository

The device axis used to be a latch: the pause manager's device axis is a LEVEL, `Wake()` never moved
it on iOS (correctly - a resume is not a wake), and the only method that lifted it (`wakeNow()`) had
no caller in the pinned client. That is fixed on both sides now, and the two halves are separate
concerns:

- **The core** owns the mapping from every Apple fact to the two axes, in `box_lifecycle.go`. A
  display turning off and a device locking pause the axis and start a sleep measurement; a display
  turning on and a resume publish the reuse edge and move NOTHING else; an UNLOCK is the one fact that
  lifts the pause. `experimental/libbox/command_server.go` routes `RecordScreenState` and
  `RecordLockState` into it on iOS, so the facts the client already reports are sufficient and the
  client decides nothing.
- **The client** needs one file to report those facts at all. `ScreenStateObserver.swift` exists on
  the same repository's `dev` branch and is absent from the pinned iOS revision, so the patch that
  ports it is `docs/fork/apple-screen-state-observer.patch`, together with the install sites and the
  one deliberate deviation from the `dev` copy: see `docs/fork/apple-screen-state-observer.md`.

Why a display turning on must NOT be treated as an unlock is the point of the whole discrimination:
on iOS a push notification lights the lock screen, so a display-on that released the pause would run
health checks, URLTests and provider refreshes for a phone in a pocket - §3.3's wake storm - while an
unlock that did not release it would leave the tunnel without liveness for the rest of the process's
life. There is no timer that can tell those two apart, and none is used: a platform that reports no
unlock fact keeps its pause, and that is stated as a limitation rather than papered over.

What is still a device item: whether iOS delivers those two Darwin notifications on a given build,
and what the user-visible effect is. See the runbook entry below.

### 5. Device validation for the device axis

Observable at a real unlock, and none of it can be established without a device:

- the client logs neither of the two notification names, so the check is on the core's own line:
  `reuse: epoch N, sleep <duration>, retiring idle connections of N reusable pool(s)` must appear once
  per unlock after a long lock, and the `sleep` must be the real screen-off duration.
- a health check must run after an unlock and must NOT run at a push that only lit the lock screen.
  The control for the second half is a phone left locked with notifications arriving: no
  `reuse:` line and no maintenance while the display keeps coming back on.
- the level itself: `Governor.State()` must leave QUIESCENT after an unlock, which is observable as
  remote rule sets updating again and as the statistics cache being written again - both were
  permanently suppressed by the latch, and both are silent failures rather than errors.

## Tests that pin this

| claim | test |
|---|---|
| a sleep shorter than the policy keeps everything, and no observer runs | `common/power.TestReuseKeepsEveryResourceForAShortSleep` |
| the bands are the policy's, with the measured duration | `common/power.TestReuseBandsAreThePolicy` |
| one sleep is one measurement and one boundary, however many resumes follow | `common/power.TestOneBoundaryPerSleepAndOneMeasurementPerSleep` |
| the epoch is a monotonic generation | `common/power.TestReuseEpochIsMonotonicUnderConcurrency` |
| the epoch survives a hundred cycles and leaks nothing | `common/power.TestReuseBoundaryStressCycles` |
| a network transition is not a reuse boundary, and does not consume one | `common/power.TestNetworkWakeIsNotAReuseBoundary` |
| the platform mapping publishes both axes, in the right order | `box.TestApplyPauseEventPublishesTheReuseEdges` |
| a stale idle resource is not handed to the next demand | `route.TestTheDemandAfterTheBoundaryGetsAFreshPath`, `v2rayxhttp.TestWakeRetireHandsTheNextStreamAFreshConnection` |
| a live flow is not killed by the boundary | `route.TestReuseBoundaryRetiresIdlePoolsAndPreservesLiveStreams`, `v2rayxhttp.TestWakeRetireKeepsALiveStreamAndItsConnection` |
| a boundary with no demand dials nothing | `route.TestAShortSleepDoesNotTouchThePool`, `v2rayxhttp.TestWakeRetireWithNoDemandOpensNothing` |
| Close wins, and a late boundary is a no-op | `route.TestAClosedManagerIgnoresALateBoundary`, `common/power.TestCloseMakesResumeAResurrectionSafeNoOp` |

### The Apple device axis, and the draining capability

| claim | test |
|---|---|
| a sleep/resume pair is one boundary, and the level is held | `box.TestASleepAndResumePairIsOneBoundaryAndTheLevelIsHeld` |
| a display-on publishes the edge and does NOT release the level; an unlock does | `box.TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn` |
| one sleep is one measurement and one level transition, however many facts report it | `box.TestOneSleepProducesOneLevelTransitionHoweverManyFactsReportIt` |
| every cycle is paired, over a hundred of them | `box.TestEverySleepCycleIsPairedAcrossOneHundredCycles` |
| the bands are the policy's, and an unknown sleep is the strict verdict | `box.TestTheBridgeUsesThePolicyBandsAndNothingElse` |
| a fact with no sleep on record publishes nothing | `box.TestAFactWithoutASleepPublishesNothing` |
| Close wins over a late Apple fact | `box.TestCloseWinsOverALateAppleFact` |
| the bridge is safe under concurrent facts | `box.TestTheBridgeIsSafeUnderConcurrentFacts` |
| a hundred cycles leak nothing and leave no boundary unpaired | `box.TestOneHundredSleepWakeCyclesLeakNothingAndLeaveNoBoundaryUnpaired` |
| a hundred network transitions neither publish nor consume a device boundary | `box.TestOneHundredNetworkTransitionsDoNotConsumeOrPublishADeviceBoundary` |
| no resurrection after Close, under facts and under load | `box.TestNoResurrectionAfterClose`, `box.TestTheBridgeUnderConcurrentLifecyclesAndTeardown` |
| the walk asks a drainable pool for the stronger action | `route.TestTheBoundaryDrainsAPoolThatCanRefuseNewWork` |
| a pool that cannot drain still gets the idle release | `route.TestTheBoundaryStillRetiresAPoolThatCannotDrain` |
| the HTTP client service is reachable by every pass | `route.TestTheBoundaryReachesTheHTTPClientService` |
| the suspect band drains nothing | `route.TestTheSuspectBandDrainsNothing` |
| a drained session keeps its stream and refuses new ones | `v2rayxhttp.TestRetireSuspectDrainsABusyConnectionAndKeepsItsStream` |
| a trim is still not a reconnect trigger | `v2rayxhttp.TestATrimStillLeavesABusyConnectionPooled` |
| the transport's capability reaches the pool | `v2rayxhttp.TestTheAdapterCapabilitiesReachThePool` |
| the manager's idle release does not replace a transport | `httpclient.TestCloseIdleConnectionsRetiresEveryManagedTransportWithoutReplacingIt` |
| every Apple fact maps to the right axis | `box_lifecycle.go` (the table in the file header), pinned by the four tests above |
