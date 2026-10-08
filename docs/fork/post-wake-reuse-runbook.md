# Post-wake reuse: device runbook

The reuse fix is wired and logic-tested in the tree; what follows cannot be established without a
real device, a real carrier or a real access point. Each item says what to collect and what reading
means what, so a session on a phone produces a verdict rather than an impression.

Policy and design: `post-wake-reuse.md`. Power governor: `power-governor.md`.

## 0. Preparation

- Build a debug build with the debug log level enabled (the reference manager logs its boundaries at
  debug, so a release build will show nothing).
- Keep the power report enabled (`sPowerReportEnabled`), because it is the only place that already
  counts the things §24 of the brief asks for: connections opened, DNS queries, sleep/wake and
  screen/lock events, and the idle gaps between traffic.
- For every scenario record: the first-packet time of the first request after the unlock, the first
  image's time, the time to load ten uncached images, whether a spinner appeared, and any 2s/5s/10s
  stall.
- Do not change the policy thresholds from one run to the next. If a run needs a different threshold,
  record it: the defaults are `SuspectAfter = 5s`, `RetireAfter = 15s`.

## 1. The publication chain is alive (do this first)

Grep the log for the reuse lines.

| what you should see | what it proves | what it means if you do not |
|---|---|---|
| `reuse: epoch N, sleep 47.2s, retiring idle connections of K reusable pool(s)` once per lock/unlock that lasted at least 15s | the sleep edge, the measurement, the verdict and the retire walk all ran | if there is no line at all: the client is not publishing a resume (`CommandServer.Wake`), or the platform is not publishing a sleep |
| `sleep` equal to the real screen-off duration | the wall clock was used, not the monotonic clock that stops while the device sleeps | a `sleep` in the milliseconds for a five minute lock means the wall-clock measurement has been broken |
| exactly one line per sleep, however many pushes arrived | the edge coalescing works | repeated lines mean a pocketed phone will churn its pool, which is the power regression this design exists to avoid |
| nothing for a sub-5s pause, and only the `suspect` line between 5s and 15s | the short-sleep band is preserved | a retire line for a 2s pause means the low-power benefit has been lost |

Also confirm the device axis is still separate: after an unlock, `power: device wake`-shaped state
transitions and a health check should appear. If they never appear, see §5.

## 2. Experiment A - is stale reuse the variable (diagnostic only)

Never ship this. In `experimental/libbox/command_server.go`, make `Pause()` call
`instance.Box().CloseIdleConnections()` before `instance.PauseManager().DevicePause()`, mark the
patch `DIAGNOSTIC ONLY`, and repeat the Telegram matrix below.

- Stalls disappear or drop sharply with the patch: stale reuse is a main cause of the reported
  symptom, and the reuse epoch is the fix that removes it without the patch's cost.
- No change: the stall is not (only) stale idle reuse. Continue with §3 rather than tightening the
  policy.

Measure the cost of the diagnostic patch too, because it is the behaviour the fix must beat: count
TCP/TLS/QUIC handshakes and DNS queries in the first 10 seconds after an unlock, with and without
the patch. The patch should show a burst; the shipped fix should show at most one fresh connection
per flow that actually arrived.

## 3. Experiment B - is the wake stagger the variable (diagnostic only)

Set `power.Policy.WakeStagger` to all-zero for one build and repeat the matrix.

| A helps | B helps | conclusion |
|---|---|---|
| yes | no | stale reusable state is the cause; the fix here is the right one |
| yes | yes | stale reuse AND delayed liveness detection; the stagger is not a substitute for the epoch, but the health/probe classification is worth a separate look |
| no | yes | the problem is wake recovery, not reuse: look at liveness/probe classification, not this policy |
| no | no | the problem is elsewhere: an active-but-dead long-lived connection, a UDP mapping, a TUN flow, Telegram's own persistent connection, the DNS path, or a network transition. Do not tighten this policy to compensate. |

## 4. The matrix

| scenario | sleep | network | expected |
|---|---:|---|---|
| Telegram foreground, ten uncached images | 15s | Wi-Fi | no stale stall; fresh handshakes are acceptable |
| same | 60s | Wi-Fi | no multi-second stall |
| same | 5min | Wi-Fi | fresh dials, no spinner |
| same | 60s | cellular | same as Wi-Fi |
| Telegram background, push, then foreground | 60s | Wi-Fi | first image without a blackhole wait |
| Safari first paint | 60s | Wi-Fi | no abnormal stall |
| WeChat images | 60s | Wi-Fi | no blackhole wait |
| long download across a sleep | sleep/wake | Wi-Fi | transfer NOT interrupted |
| voice or video call | sleep/wake | Wi-Fi | call does not drop |
| hotspot client | screen off | Wi-Fi/cellular | forwarding continues |
| Wi-Fi to cellular handover | — | transition | the network epoch still resets: transports are rebuilt, active flows are re-dialled by their applications, and the reuse epoch is NOT what handled it |

Pass/fail is not "it felt fast": record the four numbers per row, and mark a row failed when any of
them shows a multi-second stall that the same row shows without the sleep.

## 5. Device-axis item: nothing lifts the pause on the shipped iOS client

Check this before interpreting anything else, because it changes what the other readings mean.

- Evidence in-tree: `CommandServer.Wake()` lifts the pause only for Android
  (`experimental/libbox/command_server.go`), and the pinned Apple client
  (`clients/apple` @ `ddf444e`, branch `ipad-upstream-ui`) never calls `wakeNow()`. The screen-state
  observer that did call it exists only on the client's `dev` branch (`f8ad6d0`,
  `Library/Network/ScreenStateObserver.swift`), while `clients/apple/docs/HAKO-OWNERSHIP.md` lists it
  as owned.
- Observe: after the first screen-off, does a health check / URLTest / provider refresh ever run
  again while the phone is being used? If the answer is never, the device pause is latched.
- Consequence: speculative work stays off for the life of the process, and the DEEP_IDLE pool release
  fires again every time real traffic lifts the state to QUIESCENT and two minutes pass - "close the
  pool while the phone is in use", which is the behaviour the power work set out to remove.
- Fix belongs in the Apple client: restore the twelve-line display-status observer (record the screen
  fact and call `wakeNow()`), or report the screen fact through `PlatformEvents.SetScreenOn`. Then
  re-check that a health check runs after an unlock and that the app does not sleep the device's
  speculative work permanently.

## 6. Device-only items that stay device-only

| item | why it cannot be settled in the tree | what to observe |
|---|---|---|
| real jetsam behaviour | whether iOS kills this extension, and at what footprint, is the system's decision; the memory policy's job here is only to make the process smaller when asked (`runtimecoord` trim levels, `service/oomkiller`). See `power-timer-audit.md` and the memory-policy tests for the logic side. | that a `TrimMemory` pass closes pools with no active user and cannot dial; that a kill and restart does not resurrect a retired pool (a fresh Box has a fresh reference manager and a fresh epoch, and the pool is empty by construction) |
| real radio handover | a Wi-Fi to cellular handover cannot be produced in a unit test, and the middle of the path is what fails | the network epoch resets (transports rebuilt), the reuse epoch does not move for it, active flows are not torn down by the reuse path, and after the handover the first flow dials fresh |
| carrier NAT expiry during a long sleep | the mapping lifetime belongs to the carrier | after a sleep longer than `RetireAfter`, no flow is offered a pre-sleep connection; the `retiring idle connections of K` line proves the pools were released, and the first-packet time proves the fresh path was usable |
| whether a live multiplex session should be drained | sing-mux and the XHTTP pool expose no draining operation, so this is a module question rather than a policy one | whether a high-latency stream survives a sleep when it shares a session with a newly opened stream. If it does not, the case for a draining API is made; see the limitation test |

## 7. What a good run looks like

```
power: device pause
reuse: epoch 7, sleep 63.4s, retiring idle connections of 9 reusable pool(s); active flows untouched
network: generation unchanged (same environment)
```

and, on the phone: the first image after the unlock loads without a spinner, ten uncached images load
in the same time as they do without a sleep, and the first 10 seconds after the unlock show no burst
of handshakes beyond the flows that actually asked for one.
