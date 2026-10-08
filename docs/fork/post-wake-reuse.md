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

## The three lifecycles

| lifecycle | examples | what a resume may do to it |
|---|---|---|
| **active flow** | a TCP stream with bytes in flight, a call, an upload, a hotspot client | nothing. It keeps its connection. Every keeper closes only what has no active user. |
| **idle reusable connection** | an HTTP/2 pool entry with no request, a mux session whose last stream ended, a QUIC session with `streams == 0`, a DNS transport's parked socket | retired once the policy says the sleep was long enough. The next demand dials a fresh path; nothing dials on its own. |
| **network-bound transport** | WireGuard, MASQUE, OpenVPN, OpenConnect, the Tailscale endpoint, the Cronet engine | untouched by the reuse boundary. These are tunnels, not pools: their keep-idle method suspends the tunnel itself, and their liveness belongs to their own protocol (the WireGuard rebind nudge, MASQUE's keepalive). |

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

## The pause/wake chain, with the file each step lives in

```
NEPacketTunnelProvider.sleep()            clients/apple/Library/Network/ExtensionProvider.swift
  -> commandServer.pause()                experimental/libbox/command_server.go  Pause()
     -> Box.DeviceSlept()                 box.go                                (the reuse EDGE)
        -> Governor.SleepStarted()        common/power/governor.go              (records the instant)
     -> PauseManager.DevicePause()        github.com/sagernet/sing/service/pause
        -> pause.EventDevicePaused
           -> applyPauseEvent             box.go
              -> Governor.SleepStarted()  (idempotent: the same sleep is not measured twice)
              -> Governor.DevicePaused()  (the LEVEL: QUIESCENT, DeepIdle timer armed)
           -> ReferenceManager callback   route/reference.go Start()
              -> SetKeepIdleConnections(false) on on-demand endpoints only

NEPacketTunnelProvider.wake()             clients/apple/Library/Network/ExtensionProvider.swift
  -> commandServer.wake()                 experimental/libbox/command_server.go  Wake()
     -> Box.DeviceResumed()               box.go                                (the reuse EDGE)
        -> Governor.Resumed()             common/power/governor.go
           -> measures the sleep on the WALL clock
           -> advances the reuse epoch and publishes the verdict
              -> ReferenceManager.onReuseBoundary  route/reference.go
                 -> retireIdleResources()           route/reference.go
                    -> CloseIdleConnections() on every keeper reachable from the
                       outbound manager and the DNS transport manager

commandServer.wakeNow()                   (the screen-state observer on the client's dev branch,
                                           and every Android wake)
  -> PauseManager.DeviceWake() -> pause.EventDeviceWake
     -> applyPauseEvent -> Governor.Resumed() + Governor.DeviceWake()
```

Two properties of that chain are load-bearing and were both missing before this change:

1. **The level is latched and the edge is not.** On the shipped Apple client nothing lifts the
   device pause, so `PauseManager.DevicePause()` is a no-op after the first sleep. A governor driven
   by the level would measure the first sleep of the process and trust every later one; that is why
   `SleepStarted`/`Resumed` exist as edges and why `Pause()` publishes the edge directly.
2. **The verdict is published before the release.** `applyPauseEvent` publishes the reuse edge and
   then the level, so a pool that predates the sleep has already been retired when speculative work
   is released.

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

1. **A multiplexed session with a live stream still accepts new streams.** sing-mux and the XHTTP
   XMUX pool both expose only `CloseIdleConnections` and `Close`; neither has a draining or
   no-new-stream state, and forking the module is out of scope for this work. So a session that
   carries an active stream survives the boundary - it must, or the stream would lose its transport -
   and a new stream may still be multiplexed onto it. The case that was reported and reproduced (an
   idle session handed to the first flow after a wake) is closed. Both facts are pinned by tests, so
   a future draining API cannot be adopted silently: `TestASessionWithALiveStreamStillAcceptsNewStreams_KnownLimitation`.
2. **The Cronet engine cannot participate.** `protocol/naive` drives a Cronet engine whose only
   connection operation is `CloseAllConnections`, which tears down in-flight requests as well. Using
   it at a resume would break an active flow, so naive is deliberately not a keeper. A fix needs an
   idle-only API from `cronet-go`, which the pinned module does not expose.
3. **The HTTP client service pools are not retired at a resume.** `common/httpclient.Manager` exposes
   `ResetNetwork` (the reset-shaped pass, reached from a real transition) and each transport has
   `CloseIdleConnections`, but the manager is not reachable from the reference walk. These pools serve
   provider refresh, the dashboard, remote rule sets and the like - speculative work that is staggered
   after a wake anyway - so the gap is latency rather than correctness. Closing it needs one method on
   `adapter.HTTPClientManager`.
4. **macOS never enters the device axis.** `CommandServer.Pause` returns for anything that is not
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

### 4. Known device-axis item: nothing lifts the device pause on the shipped iOS client

Evidence, all in-tree:

- `experimental/libbox/command_server.go`: `Wake()` lifts the pause only for Android; for every other
  platform it publishes the reuse edge and returns.
- The Apple client pinned by this repository (`clients/apple` at `ddf444e`, branch `ipad-upstream-ui`)
  has no caller of `wakeNow()`. The screen-state observer that used to call it exists only on the
  client's `dev` branch (commit `f8ad6d0`, `Library/Network/ScreenStateObserver.swift`), and
  `clients/apple/docs/HAKO-OWNERSHIP.md` still lists it as owned.

Consequence: `PauseManager.DevicePause()` is entered once and never left, so
`Governor.State()` stays QUIESCENT and then DEEP_IDLE for the life of the process. Speculative work
(health checks, URLTest, provider refresh, statistics) never resumes, and the DEEP_IDLE pool release
can fire again every time real traffic lifts the state back to QUIESCENT and the deadline expires -
which is "close the pool every two minutes while the phone is being used", the behaviour the power
work set out to remove.

The reuse fix does not depend on this (it is edge-driven, which is the point of `SleepStarted`), but
the two interact: on this client the pause is a latch, and the pool release is then driven by
traffic gaps rather than by sleep. The client-side fix is the twelve-line observer from `f8ad6d0`
(display-on -> `recordScreenState(true)` + `wakeNow()`), and it belongs in the Apple client, which
this work stream does not own. Validate it by observing `power: device wake`-shaped log lines and by
checking that a health check runs after an unlock.

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
