# Apple screen-state / lifecycle — the acceptance state, and what is left for a device

Scope: the final wiring of the Apple screen-state observer against the core's device axis, as §8 and
§9 of the v0.1.6 hardening brief define it. This file is the record of what is PROVEN on this host,
what is deliberately NOT done, and what needs a device.

It is written after re-checking every claim against the sources at baseline
`17b176a18d6c4e814bef72ff2cd54a5e794ab696`, because two of the four items the previous round
recorded as closed were not.

## 1. The client half, at the two revisions that matter

Two Apple revisions exist and they are not the same thing.

| | pinned gitlink | owner's working tree | fork branch head |
|---|---|---|---|
| revision | `5911580a6366da78e6b4b5b4459596e5a2cf1eb4` | `816600ab3f2823ab5de1da66e36433ef3a21fc10` | `8599039f6cd41dad6bdf975066b300725da08668` |
| where | `git ls-tree HEAD clients/apple` | the owner's checkout | `Piggy-Cat-bit-shadow/sing-box-for-apple`, branch `fix/libbox-stringbox-callsites`, tag `libbox-stringbox-abi-1` |
| parent of the fork head | — | — | `816600ab3` (exactly the owner's head) |
| `ScreenStateObserver.swift` | absent | absent | **absent** |
| the StringBox call-site migration | **absent** | **absent** | present |
| the `BridgeServiceSession` implementer | returns `String` | returns `String` | returns `String` |

Measured with `scripts/ci/probe-accessors.py` (347 Swift sources walked in each case):

```
pinned  5911580a : scanned 347  violations 18  (call sites; 0 migrated)
current 816600ab3: scanned 347  violations 18  (call sites; 0 migrated)
fork    8599039  : scanned 347  violations  1  (call sites 0; 1 implementer)
fixed*           : scanned 347  violations  0
```

\* `816600ab3` + `docs/fork/apple-stringbox-callsites.patch` (= the fork commit)
+ `docs/fork/apple-bridge-session-implementer.patch`.

The 18 call-site violations are, per owner, exactly:

| owner.method | sites | files |
|---|---:|---|
| `BridgeSession.Name` | 5 | `HelperService/RootHelperService.swift:334,336`; `JailbreakDaemon/IOSRootHelperService.swift:188,190`; `Library/Network/BridgeTunTracker.swift:52` |
| `RoutePrefix.Address` | 6 | `Library/Network/ExtensionPlatformInterface.swift:65,77,95,121,132,150` |
| `RoutePrefix.Mask` | 3 | `Library/Network/ExtensionPlatformInterface.swift:66,77,95` |
| `DeprecatedNote.Message` | 3 | `ApplicationLibrary/Views/Abstract/GlobalChecksModifier.swift:207,216,224` |
| `TunOptions.GetHTTPProxyServer` | 1 | `Library/Network/ExtensionPlatformInterface.swift:176` |

The numbers are identical at both revisions: neither the pin nor the owner's head carries any of the
migration, and `TunOptions.GetDNSMode` is the single accessor that was already migrated at both
(`ExtensionPlatformInterface.swift:47`, `options.getDNSMode()!.value`).

### 1.1 The fork commit is the call sites only, and the brief's description of it is wrong

The work order states that `8599039` "contains TWO things: the StringBox `.value` call-site migration
… AND the screen-state observer". It contains **one**:

```
$ git -C <fork> show --stat 8599039
 .../Views/Abstract/GlobalChecksModifier.swift |  6 +++---
 HelperService/RootHelperService.swift         |  4 ++--
 JailbreakDaemon/IOSRootHelperService.swift    |  4 ++--
 Library/Network/BridgeTunTracker.swift        |  2 +-
 Library/Network/ExtensionPlatformInterface.swift | 16 ++++++++--------
 5 files changed, 16 insertions(+), 16 deletions(-)
```

`8599039`'s diff is byte-identical to `docs/fork/apple-stringbox-callsites.patch` (modulo `index`
lines). There is no `Library/Network/ScreenStateObserver.swift` in it. The observer exists **only**
as `docs/fork/apple-screen-state-observer.patch` (sha256
`51504470cc178360d7bff509fa52ab6d009940ee74069d9f7558d2a6d49e166a`, re-verified) and is on no remote.
Both the branch and the tag resolve on the fork to `8599039`, so the tag does not carry it either.

The observer patch applies cleanly to all three revisions (`git apply --check` exits 0 at
`5911580a`, `816600ab3` and `8599039`), and it touches a disjoint file set from the migration, so the
two can be applied in either order.

### 1.2 The migration is incomplete for Apple in the same way it was incomplete for Android

This is the finding the previous round did not check, and the previous round's own Android analysis
says it should have. From `docs/fork/android-abi-migration-closure.md:149`:

> **One implementer, not a caller.** `BridgeSession` is a bound Go **interface**, so the platform also
> implements it.

Apple's implementer is `BridgeServiceSession`, in `Library/Network/ExtensionPlatformInterface.swift`
under `#if os(macOS) || JAILBREAK`, and it declares:

```swift
private class BridgeServiceSession: NSObject, LibboxBridgeSessionProtocol {
    func name() -> String { tunName }
```

Go declares `BridgeSession.Name() *StringBox` (`experimental/libbox/platform.go:70`); the ObjC
protocol that generates is not a guess — `gobind -lang=objc` on this tree, with the prefix the Apple
framework actually uses (the package name `libbox` supplies it, which is why the client says
`LibboxBridgeSessionProtocol` and `LibboxNewBridgeService` rather than `LibboxLibbox…`):

```objc
@protocol LibboxBridgeSession <NSObject>
- (LibboxStringBox* _Nullable)name;
```

so the Swift requirement is `func name() -> LibboxStringBox?`, and a `String` witness does not satisfy
it. Reproduced with a standalone reduction on this host (Swift 6.4, `swiftc -typecheck`):

```
$ swiftc -typecheck red.swift
red.swift:9:13: error: type 'BridgeServiceSession' does not conform to protocol 'LibboxBridgeSessionProtocol'
 7 |     func name() -> LibboxStringBox?
   |          `- note: protocol requires function 'name()' with type '() -> LibboxStringBox?'
11 |     func name() -> String { tunName }
   |          `- note: candidate has non-matching type '() -> String'
```

with the fix (`docs/fork/apple-bridge-session-implementer.patch`):

```
$ swiftc -typecheck green.swift && swiftc -o green green.swift && ./green
typecheck OK
GREEN: optional witness conforms and round-trips the value
```

The return type must be the optional `LibboxStringBox?`, not a bare `LibboxStringBox` — a
non-optional witness does **not** satisfy the requirement either, which was also compiled and checked.

Why nothing caught it: the type is inside `#if os(macOS) || JAILBREAK`. The iOS App Store
configuration never compiles the file, and the iOS build the release gate runs is green. The macOS
client (`scripts/ci/build-macos-client.sh`) and the jailbreak build do compile it. **No Apple build
was produced on this host** — there is no `Libbox.xcframework` here and no Xcode target was compiled
— so this is established by the generated protocol, the reduced compiler run above, and
`git apply --check`, not by building the app.

### 1.3 The gate now scans implementers, because a call-site scan structurally cannot

`scripts/ci/probe-accessors.py` gained an implementer scan (`kind: "implementer"`): it finds a type
that conforms to a bound Go interface named in the contract, then requires its declaration of the
migrated method to name the box. `scripts/ci/check-libbox-abi.sh` renders it and its header documents
it as layer 4b. Verified on both clients:

```
RED   android fc21909d (unfixed) : scanned 309  violations 8   (7 call + 1 implementer)
GREEN android ec61030d (the pin) : scanned 309  violations 0
RED   apple   816600ab3          : scanned 347  violations 19  (18 call + 1 implementer)
GREEN apple   816600ab3 + both patches : scanned 347  violations 0
```

The call-site findings are byte-identical before and after the change (verified by diffing the old
and new probes' output on the same tree), so nothing was loosened to make the new check fit.

One caution about the gate's own constants: `VERIFIED_APPLE_SHA` is still `5911580a`, which carries
**none** of the migration. That is intentional and is now commented in the script — a run against it
PASSes layer 5 (the pin is what it says it is) and FAILs layer 4 (the code is not migrated), which is
the honest reading. The integrator must move the constant and the superproject gitlink together, to a
fork head that contains both patches, once that head exists.

## 2. §8.2 lifecycle requirements against the prepared observer

The observer patch is small and each §8.2 clause maps to a specific line of it.

| §8.2 requirement | how the patch satisfies it |
|---|---|
| created at a suitable point in the PacketTunnel lifecycle | `ExtensionProvider.swift`, immediately after `writeMessage("(packet-tunnel): Here I stand")`, guarded by `if let commandServer` |
| holds the command server | `ScreenStateObserver.init(commandServer: LibboxCommandServer)` stores it in the notify handlers' closure |
| cancels the notify token on stop/teardown | `screenStateObserver?.cancel()` → `notify_cancel(displayToken)` and `notify_cancel(lockToken)`, in the `#if os(iOS)` stop path |
| reload must not leak multiple observers | the property is assigned, not appended; `cancel()` runs before the new one is created on a restart |
| extension restart must not produce duplicate listeners | the old observer is cancelled and dropped before the new one is installed |
| tvOS must not enable it | `#if os(iOS)` on the file, the property and the call site |
| macOS must not take the iOS private path | same `#if os(iOS)`; `notify_register_dispatch` is never reached on macOS |

**DEVICE-ONLY**: the last three columns are source-level facts, not observations. "the token was
actually cancelled", "a restart produced one listener and not two" and "tvOS did not register" need a
running extension; see the runbook in §6.

### 2.1 §8.3 — LX's old power policy is not copied, and the check is exact

The three things §8.3 forbids, and where each is absent:

* **a fixed sleep timer** — there is no timer anywhere in the path. `box_lifecycle.go`'s file comment
  states why: a timer cannot distinguish a locked phone from an unlocked one, so it either releases
  speculation for a locked device or fails to release it for an unlocked one. Everything that looks
  like a duration is `common/power.Policy`, which is a *classification* of a measured sleep, not a
  countdown that ends it.
* **clearing connections the instant the screen goes off** — `CommandServer.Pause` used to call
  `CloseIdleConnections()`; it no longer does, and the comment there records the removal. A display
  going off publishes the sleep edge and the level pause only; the pool release is at DEEP_IDLE
  (`DeepIdleAfter = 2m` of no real traffic) or at a reuse boundary that the policy classifies as a
  retire (≥ `RetireAfter = 15s`).
* **a duplicate pause/wake state machine** — the observer publishes two facts and owns no state.
  `RecordScreenState`/`RecordLockState` route into the same `box_lifecycle.go` bridge as the
  NetworkExtension overrides, and the coalescing is the governor's.

The observer also does NOT put `screen off → pause()` in itself, which §8.1 asks for explicitly: the
sleep entry stays with the NE lifecycle, and the observer's display handler only calls
`recordScreenState(state == 1)`. That is the same call the NE path makes, so the two agree by
construction.

## 3. §9 acceptance matrix

Every case below names the core behaviour, the test that pins it, and whether it is testable on this
host. "DEVICE-ONLY" means exactly that: no core test can stand in for it, and no claim is made.

### Case A — a short screen-off

`亮屏 → 息屏几秒 → 再亮屏` / screen on → a few seconds off → screen on again.

* **What the core does.** `displayStatus off` → `CommandServer.RecordScreenState(false)`
  (`experimental/libbox/command_server.go:363`) → `Box.ScreenStateChanged(false)` (`box.go:1029`) →
  `lifecycle.screenState(false)` (`box_lifecycle.go:144`) → `slept()`: `Governor.SleepStarted()` then
  `PauseManager.DevicePause()`. `displayStatus on` → `screenState(true)` → `resumed()`:
  `Governor.Resumed()` and nothing else.
* **No pool rebuild, no reconnect storm.** The measured sleep is classified by
  `power.Policy.ReuseFreshness.Classify`; the shipping `SuspectAfter` is 5 s and `RetireAfter` is
  15 s, so a "few seconds" pause is `ReuseKeep`: no boundary is published, the epoch does not move,
  and no pool is touched. Pinned by `TestTheBridgeUsesThePolicyBandsAndNothingElse`
  (`box_lifecycle_test.go:295`, "a two-second pause retired something") and
  `TestAShortSleepDoesNotTouchThePool` (`route/reference_reuse_test.go:295`).
* **"screen-on 后 pause 正确解除" — via the lock fact, not the display fact.** A real screen-on by a
  person is accompanied by an unlock, and `lockstate == 0` is the fact that releases the level:
  `RecordLockState(false)` → `lockState(false)` → `woke()` → `Resumed()` then `DeviceWake()`. Pinned
  by `TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn` (`box_lifecycle_test.go:155`),
  which asserts the display-on fact does NOT lift the level and the unlock does, and that the release
  is staggered (health check 5 s, statistics 10 s, provider refresh 15 s).
* **What this does not cover.** A display that goes off and on again *without* the device ever
  locking leaves the level paused until the next unlock. That is the designed trade (§4) and it is
  not observable in a core test — it is a statement about what iOS posts.
* **DEVICE-ONLY**: the observation itself — that a "few seconds" screen-off produces no DNS/TLS/QUIC
  handshake burst and that the first flow after it is not stalled. Procedure in §6.

### Case B — a long lock

* **What the core does.** `lockstate == 1` → `RecordLockState(true)` (`command_server.go:387`) →
  `slept()`. QUIESCENT allows `HealthCheck` and `NetworkProbe` and suppresses `Statistics` and
  `ProviderRefresh` (`power.DefaultPolicy`, `governor.go:263`); after `DeepIdleAfter` with no real
  flow, DEEP_IDLE allows nothing (`DeepIdle: Allow{}`).
* **Deep idle is entered, and idle resources are trimmed.** `Box`'s observer
  (`box.go:707`) releases the idle walk on the DEEP_IDLE transition. Pinned by
  `TestDeepIdleAfterSilenceStopsEverything` (`common/power/governor_test.go:53`),
  `TestTransientTrafficPostponesDeepIdle` (`governor_idle_deadline_test.go:25`) and
  `TestReuseBoundaryRetiresIdlePoolsAndPreservesLiveStreams`
  (`route/reference_reuse_test.go:241`).
* **No speculative probe, no background wake storm.** `Allow()` returns the policy's table and
  nothing speculative is allowed in DEEP_IDLE. Provider refresh is gated at its consumer
  (`route/rule/rule_set_updater.go:73`, `WaitProviderRefresh`); URLTest's ticker is registered with
  `pause.RegisterTicker` (`protocol/group/urltest.go:613`), which stops the ticker on
  `EventDevicePaused`/`EventNetworkPause`, and `urltest.go:301` refuses a run while the device is
  paused. Pinned by `TestDevicePauseSuppressesOnlySpeculativeWork`
  (`governor_test.go:39`), `TestDeepIdleAfterSilenceStopsEverything`, and
  `TestWaitProviderRefreshWaitsForTheDevice` (`governor_test.go:318`).
* **First real flow after the unlock recovers quickly.** The wake is staggered rather than
  instantaneous, and the boundary has already retired what nobody was using, so the first demand
  dials a path that is known to be new. Pinned by `TestTheDemandAfterTheBoundaryGetsAFreshPath`
  (`route/reference_reuse_test.go:275`) and `TestWakeReleasesCategoriesInStages`
  (`governor_test.go:237`).
* **DEVICE-ONLY**: that iOS holds the lock fact for the whole lock, that the extension is not
  suspended by the OS in a way that loses the measurement, and the wall-clock recovery of the first
  flow.

### Case C — an iOS push / background wake with the screen still off

* **What the core does.** `wake()` → `CommandServer.Wake()` (`command_server.go:308`) → the
  non-Android branch → `Box.DeviceResumed()` (`box.go:1007`) → `resumed()`; **`DeviceWake()` is not
  called.** `WakeNow()` (`command_server.go:336`) is a separate entry point and the NE `wake()`
  override does not reach it.
* **No `DeviceWake()`, no provider refresh, no speculative work.** Pinned by
  `TestASleepAndResumePairIsOneBoundaryAndTheLevelIsHeld` (`box_lifecycle_test.go:115`), which
  asserts `manager.IsDevicePaused()` is still true after the resume, the governor is still QUIESCENT,
  and `governor.Allow().ProviderRefresh` is false; and by `TestDeviceWakeAloneIsNotABoundary`
  (`common/power/governor_reuse_test.go:239`).
* **`DeviceResumed()` as a reuse boundary** is exactly what the resume publishes: one boundary per
  sleep, classified by the policy. `TestOneSleepProducesOneLevelTransitionHoweverManyFactsReportIt`
  (`box_lifecycle_test.go:212`) pins that the four facts of one screen-off coalesce to one level
  transition and one boundary, and `TestTheBridgePublishesBothAxes`
  (`governor_reuse_test.go:217`) pins the two axes separately.
* **DEVICE-ONLY**: that a push actually reaches the extension as `wake()` without a lock-state or
  display-state change, which is the entire premise of the asymmetry.

### Case D — a real screen-on

* **What the core offers.** `CommandServer.WakeNow()` → `Box.DeviceWoke()` (`box.go:1020`) →
  `woke()` (`box_lifecycle.go:127`): `Governor.Resumed()` **then** `PauseManager.DeviceWake()`. The
  order is load-bearing — the reuse verdict is published before the level moves, so the work the
  release permits dials a path known to be new. Pinned by
  `TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn` (through the same `woke()` path
  from `lockState(false)`) and `TestAFactWithoutASleepPublishesNothing` (`box_lifecycle_test.go:347`)
  for the `woke()` call reached directly.
* **What the shipped client does.** The observer does **not** call `wakeNow()` on display-on; it
  calls `recordScreenState(true)`, and the level is released by `lockstate == 0`. See §4: this is
  deliberate and it is the one place the shipped code and §8.1's literal snippet disagree.
* **DEVICE-ONLY**: the end-to-end `screen on → wakeNow → DeviceWake` chain as §9 D words it. On this
  client the equivalent chain is `screen on → recordScreenState(true)` (edge) plus
  `unlock → recordLockState(false) → DeviceWake` (level).

### Case E — hotspot

`iPhone 开热点 → 屏幕关闭较久 → 热点客户端继续存在`.

Three requirements, and they are not equally testable.

1. **"不要把仍有真实流量的连接当 idle trim" — testable, and it holds.**
   `ReferenceManager.retireIdleResources` and `retireSuspectResources` can only call
   `CloseIdleConnections` (and, where a pool implements it, `RetireSuspect`), and the contract every
   keeper is held to is "close only what has no active user traffic, and never dial". That is now
   asserted against the real types in `route/reusable_owner_inventory_test.go` rather than only
   against fakes, including the four pools that document it: `common/httpclient.Manager` (idle-only,
   and see §5.1), `transport/v2rayxhttp` (drains busy sessions), the HTTP/2/gRPC/QUIC pools
   (idle-only), and the DNS transports. `TestReuseBoundaryRetiresIdlePoolsAndPreservesLiveStreams`
   and `TestTheBoundaryDrainsAPoolThatCanRefuseNewWork` pin the two actions.
2. **"不要因为 pause 错误释放热点必须的活跃 path" — this is a real, narrow risk and it is a
   deliberate policy, not a defect.** The device level suspends on-demand tunnels:
   `route/reference.go`'s eligibility pass computes
   `keep: referencedOutbounds[endpoint.Tag()] && !devicePaused` for every `adapter.OnDemandEndpoint`,
   so a screen-off calls `SetKeepIdleConnections(false)` on a WireGuard / MASQUE / OpenVPN /
   OpenConnect / Tailscale endpoint that is *in the active routing set*, whether or not it is
   carrying traffic. What that does is a suspend of the tunnel itself:
   `transport/wireguard/endpoint.go:378` → `wgDevice.Down()`,
   `protocol/tailscale/endpoint.go:665` → `WantRunning: false`,
   `protocol/masque/client.go:513`, `protocol/openvpn/client.go:683`,
   `protocol/openconnect/client.go:504` → `client.Suspend()`.
   The recovery path exists and is demand-driven: `transport/wireguard/endpoint.go:357`
   (`resumeForCaller`) wakes a suspended endpoint for a real flow and refuses to for a background
   probe; the other four call `Resume()` in `waitReady`.
   **This is not changed here.** §8.3 forbids inventing policy, the suspend is the pre-existing power
   behaviour this stream inherited (introduced by `4aaa2372c`/`7d597e56a`, before the screen-state
   work), and "should a device pause suspend a tunnel that is carrying hotspot traffic" is a policy
   question whose answer depends on measurements this host cannot take. It is written down rather
   than silently re-decided.
3. **"不要出现手机自身 tunnel 看起来活着，但热点设备断网" — NOT testable here, and the evidence
   that is missing is specific.** The whole case rests on a fact that is not in this repository and
   cannot be derived from it: **whether Personal Hotspot traffic from a tethered client enters the
   NEPacketTunnelProvider's utun at all**, and if it does, on which interface it arrives and whether
   the phone's own flows and the tethered flows are distinguishable to the core. Apple's own
   documentation and the field reports disagree across iOS versions and across the "Maximize
   Compatibility" switch, and this tree does not read the hotspot interface anywhere (the only
   in-tree references are `docs/configuration/shared/neighbor.md`, which is macOS Internet Sharing,
   and the Android `neighbor` docs). No core change can be justified, implemented or tested without
   that measurement; see §6 for how to take it.

## 4. §8.1's `wakeNow()` and the one deliberate divergence

§8.1's snippet is:

```
状态变化时：
recordScreenState(state == 1)
if screen on:
    wakeNow()
```

§9 D says the same thing in one line: `screen on → wakeNow → DeviceWake`.

The prepared observer implements the first line and not the `if`. It calls `wakeNow()` nowhere, and
the level is released by `lockstate == 0`. The reasons are in the policy itself, not in taste:

* §8's own opening rationale — the paragraph that explains why `Wake()` must not lift the pause on
  iOS — says the reason is that an iOS wake may be a push, a background task or a brief extension
  wake. A push **lights the lock screen**, so a display-on fires for exactly the case that rationale
  excludes. Calling `wakeNow()` there re-introduces the wake storm the whole asymmetry exists to
  prevent: URLTest, provider refresh and health checks released for a phone in a pocket, and a
  DEEP_IDLE-to-ACTIVE ramp per notification.
* §8.3 forbids the policy that shape ("和当前 power governor 冲突的 policy"). A display-on that lifts
  the level is a second, weaker definition of "the device is usable" competing with the lock fact.
* `lockstate` is already posted on the same private-notification bus, from the same observer, and it
  is the platform's own statement that a person presented a credential. The display-on fact still
  does real work: it publishes the reuse edge, which is what makes the first flow after the sleep
  dial a path known to be new.

The residual, stated rather than hidden: a display that turns off and on again without the device
ever locking leaves the level paused until the next unlock. On iOS the display going off is
accompanied by the lock screen engaging, so this is a narrow window (the passcode-grace /
no-passcode configurations), and the cost is that speculation stays suppressed — the safe direction.

`CommandServer.WakeNow()` remains public and tested-by-construction for a client that wants it; a
client that wires it to a *user-present* signal the platform confirms is free to do so. Nothing here
removes it.

## 5. What was closable in the core, re-checked rather than inherited

### 5.1 `common/httpclient.Manager` — was NOT closed; **now closed**

The previous round recorded this as closed and it was not. `Manager.CloseIdleConnections` exists
(`common/httpclient/manager.go:192`) and does the right thing, but the walk reached it by asserting
`httpClientManager.(adapter.IdleConnectionKeeper)`, and `*httpclient.Manager` has never implemented
`SetKeepIdleConnections`. A failed type assertion is not a compile error, so the fourth owner of
reusable state stayed unreachable on every walk, and the test that was supposed to cover it
(`TestTheBoundaryReachesTheHTTPClientService`) used a fake that implemented both halves.

Closed by splitting the capability instead of widening the manager:

* `adapter.IdleConnectionReleaser` = `CloseIdleConnections` alone (`adapter/outbound.go`);
  `IdleConnectionKeeper` embeds it, so every existing implementer is unchanged.
* `route/reference.go`'s `retireIdleResources` and `retireSuspectTarget` assert the releaser,
  because releasing idle resources is the only thing they call. The **eligibility** pass
  (`update()`/`applyKeepIdle`) still requires the full keeper, because it is the pass that asks the
  eligibility question, and so does `route/network.go`'s own transition path
  (`SetKeepIdleConnections` on a network pause).
* The same substitution is applied to the two memory walks in `route/network.go`
  (`TrimMemory`, `ReleaseMemory`): they too call `CloseIdleConnections` and nothing else. They do not
  walk the HTTP client service, so the defect was inert there, but leaving one retire walk asserting
  a capability it never uses is how the first one was missed.
* `route/reusable_owner_inventory_test.go:134` `TestTheWalkReachesTheRealHTTPClientManager` drives the
  **real** manager through both walks.

Red-check, same test, old assertion restored:

```
--- FAIL: TestTheWalkReachesTheRealHTTPClientManager (0.00s)
    Error: Not equal: expected: 1  actual: 0
    Messages: the trim walk did not reach the real *httpclient.Manager, so Box.CloseIdleConnections,
              the DEEP_IDLE release and the memory pass all left the pools behind provider refresh,
              remote rule sets, the dashboard and the API untouched
```

and with the fix, `ok github.com/sagernet/sing-box/route`.

### 5.2 XMUX — closed, verified

`transport/v2rayxhttp/client.go:319-340` implements `adapter.ReuseSuspect` and forwards it to
`xmuxManager.RetireSuspect` (`transport/v2rayxhttp/xmux.go`), which detaches every pooled connection,
closes the idle ones and marks busy ones draining so they are torn down when their last stream
leaves. `retireSuspectTarget` applies the drain **before** the idle release. Pinned by
`TestTheBoundaryDrainsAPoolThatCanRefuseNewWork` (`route/reference_drain_test.go:121`) and
`TestTheBoundaryStillRetiresAPoolThatCannotDrain` (`:151`).

### 5.3 `sing-mux` — still dependency-level; verified, not assumed

`github.com/sagernet/sing-mux v0.3.10-0.20260929204512-caf09fe32475`. Its entire public surface on the
client is `DialContext`, `ListenPacket`, `Reset`, `SetKeepIdleConnections`, `CloseIdleConnections`,
`Close` (`client.go:96,120,304,314,321,340`). There is no no-new-stream state and no hook to express
one from outside:

* `client.go:194 selectSession(sessions []*clientSession)` hands out any session still in the list,
  with no drained/excluded flag to read;
* `client.go:224 releaseStream(session, keepSession)` keeps a session alive while `streams > 0`, which
  is the idle-only semantics and nothing more;
* `client.go:314 SetKeepIdleConnections` is the eligibility half only.

Closing the session instead would drop the live stream it carries, which is the one thing a boundary
must not do. A fix needs an upstream API; forking the module for one method is out of scope
(no new dependency fork). **Recorded as a KNOWN LIMITATION with the exact file:function above.**

### 5.4 `naive` / Cronet — still dependency-level; verified, not assumed

`protocol/naive/outbound.go` implements neither `SetKeepIdleConnections` nor `CloseIdleConnections`;
its only connection-level action is `h.client.CloseAllConnections()` at `outbound.go:284`, called
from `InterfaceUpdated` — a real network change, which is what it is correct for. The pinned engine
`github.com/Piggy-Cat-bit-shadow/cronet-go@v0.0.1-143.0.7499.109-2.0.20260929202119-8c68ce89873c`
exposes on `NaiveClient` exactly `Start`, `Engine`, `CloseAllConnections`, `DialEarly`, `DialContext`,
`ListenPacket`, `Close` (`naive_client.go:258,541,548,557,617,633,637`) — no idle-only and no
no-new-stream API. The pool is Chromium's, not this tree's, so there is nothing local to drain.
**KNOWN LIMITATION, file:function above; a fix needs an idle-only API from `cronet-go`.**

### 5.5 The on-demand tunnels — still `SetKeepIdleConnections` only; now asserted

`protocol/wireguard.Endpoint`, `protocol/masque.ClientEndpoint`, `protocol/openvpn.ClientEndpoint`,
`protocol/openconnect.Endpoint` and `protocol/tailscale.Endpoint` implement
`adapter.OnDemandEndpoint.SetKeepIdleConnections` and **not** `CloseIdleConnections`, which is what
keeps them unreachable from the retire walks while leaving them drivable by the device level.
Previously this was prose in a comment; it is now a two-sided assertion for the four untagged types
in `route/reusable_owner_inventory_test.go:56`
(`TestTheOnDemandTunnelsAreReachableOnlyFromTheEligibilityPass`). The fifth, the Tailscale endpoint,
is behind `with_tailscale` — see §7 for that limit.

## 6. Device runbook

Everything below is DEVICE-ONLY. Each item names what to collect and what pass and fail look like, so
a run produces evidence rather than an impression.

### 6.0 Before anything: is the publication chain alive

Log level `debug`. One screen-off and screen-on, then grep the extension log for:

```
reuse: epoch <n>, sleep <d>, retiring idle connections of <k> reusable pool(s); active flows untouched
reuse: epoch <n>, sleep <d>, reusable state suspect; pools kept by policy
```

* **PASS**: an epoch line appears after an unlock and the epoch increases by one per sleep; a sleep
  under 5 s produces no line at all.
* **FAIL**: no epoch line ever (the level is latched), or one line per notification (the coalescing is
  broken).

### 6.1 Case A — short screen-off

1. Foreground an app that has been used (so its DNS/TLS/QUIC entries exist), e.g. Telegram with a few
   chats opened.
2. Lock, wait 3 s, unlock. Repeat 10×.
3. Collect: the epoch lines (expect none for each 3 s lock), and a packet capture or the connection
   list before/after.

**PASS**: no new handshakes attributable to the lock, no `reuse:` line, and the first request after
each unlock completes without a multi-second stall.
**FAIL**: a burst of DNS/TLS handshakes at each unlock, or a `reuse:` line for a 3 s sleep.

### 6.2 Case B — long lock

1. Lock for 10 minutes with no traffic.
2. Collect the log across the lock, plus `memory` and connection counts at minute 0/5/10.

**PASS**: DEEP_IDLE is entered once (`DeepIdleAfter` = 2 min), exactly one pool-retire line, no
provider refresh and no URLTest run in the window, and the first flow after the unlock recovers
without a blackhole wait.
**FAIL**: repeated DEEP_IDLE entries, any URLTest/probe/refresh in the window, or a stalled first
flow.

### 6.3 Case C — push / background wake, screen off

1. Lock the device. Send a push that wakes the app (a message notification is enough).
2. Collect the log for the window between the push and the next unlock, with timestamps.

**PASS**: no `wakeNow`, no `DeviceWake`, no provider-refresh or URLTest line; at most one `reuse:`
line for the sleep; the level (`IsDevicePaused`) is still true at the next log line.
**FAIL**: any of URLTest / provider refresh / a full health-check sweep in that window.

### 6.4 Case D — real screen-on

1. From a locked screen, unlock normally.
2. Collect the log around the unlock.

**PASS**: a `lockstate == 0` fact arrives, `DeviceWake` fires once, and the release is staggered —
health check first (≈5 s), statistics at ≈10 s, provider refresh at ≈15 s — not all at once.
**FAIL**: no `DeviceWake` at all (latched level), or everything released in the same instant.

### 6.5 Case E — hotspot

The measurement that decides the whole case, and it must be taken first:

1. Start Personal Hotspot. Start the tunnel. Connect one tethered client and generate steady traffic
   (a download).
2. On the phone, capture on the utun **and** on the bridge interface for the hotspot
   (`ifconfig`/`rvictls -s` over USB from a Mac, or a sysdiagnose `pktap` capture).
3. Answer one question: **do the tethered client's packets appear in the NEPacketTunnelProvider's
   utun?** Record the capture, the interface names, the iOS version and the "Maximize Compatibility"
   setting.
4. Only if they do: lock the phone for 5 minutes while the download continues, then re-measure.

**PASS** (given step 3 is yes): the download survives the lock; the phone's own tunnel reports
healthy; the tethered client does not lose its path.
**FAIL**: the download stalls at the moment of the lock, or the tethered client is blackholed while
the phone's own traffic is fine.

If step 3 is no — the hotspot bypasses the tunnel — then Case E is out of scope for this core and the
requirement belongs to the platform, which is a finding in itself and should be recorded in
`docs/fork/post-wake-reuse-runbook.md`.

### 6.6 §8.2 observer hygiene

* Restart the tunnel 8× and, at each start, confirm exactly one display-state and one lock-state
  notification is delivered (add a temporary counter in a debug build, or observe duplicate
  `recordScreenState` calls in the log). **FAIL**: 2× per restart.
* Stop the tunnel and confirm no further `recordScreenState`/`recordLockState` reaches the core
  (`CommandServer.Close` makes them no-ops, but the token must be cancelled too).
* Run the tvOS target and confirm `ScreenStateObserver` is not compiled in.
* Build and run the macOS client and confirm it does not use `notify_register_dispatch`.

## 7. What could not be established on this host

1. **Any Apple compile.** No `Libbox.xcframework` was generated and no Xcode target was built. §1.2
   is established by the generated ObjC protocol, a standalone `swiftc -typecheck` reduction of the
   exact witness shape, and `git apply --check` — not by compiling the client.
2. **The observer in a running extension.** §2's table is a source-level mapping.
3. **All of §9 A–E as observations.** §3 says per case which half is pinned by a test and which half
   is device-only; §6 is the procedure.
4. **The Tailscale endpoint's capability assertion.** The type only exists under `with_tailscale`, so
   it is not in the untagged inventory test. Its source is read
   (`protocol/tailscale/endpoint.go:630`, `SetKeepIdleConnections` and no `CloseIdleConnections`) and
   it is covered by inspection, not by the test. Adding a tagged test file is possible; it was not
   done, and that is stated rather than implied.
5. **The hotspot packet path.** §3 Case E, item 3. This is the single missing measurement that blocks
   any change to the on-demand suspend policy.
6. **Cross-compiling the whole tagged tree to iOS, Linux and Windows fails on the baseline, before any
   of this work.** `go build -tags "$TAGS" ./...` with `GOOS=ios`, `GOOS=linux` or `GOOS=windows`
   stops at `github.com/sagernet/cronet-go/lib/<platform>: build constraints exclude all Go files`,
   reached through `experimental/libbox` → `include` → `protocol/naive` → `cronet-go/all`. It was
   reproduced with every change stashed (`git stash -u`, clean tree), so it is not a regression;
   `GOOS=darwin GOARCH=arm64` succeeds. The changed packages cross-build for `darwin/arm64`,
   `ios/arm64`, `linux/amd64` and `windows/amd64`, because none of them imports `protocol/naive`; §8
   has the output.
7. **`go mod tidy -diff` is clean (`exit 0`, empty output) on the baseline and after this work.** It
   reports a delta only when a tagged `go build`/`go test` has run first, which adds `/go.mod` hashes
   for tag-only modules that tidy then prunes — pre-existing toolchain behaviour, not a dependency
   change. `git checkout -- go.sum` restores it and the commit carries no `go.sum` change.

## 8. The verification run, as it was executed

Host: darwin/arm64, `GOTOOLCHAIN=go1.25.5`, `TAGS=$(cat release/DEFAULT_BUILD_TAGS)`.

Builds:

```
$ go build -tags "$TAGS" ./...       exit 0   (host darwin/arm64)
$ go build ./...                     exit 0   (host darwin/arm64, untagged)
$ GOOS=darwin  GOARCH=arm64 go build -tags "$TAGS" ./route/... ./adapter/... ./common/httpclient/... \
      ./common/power/... ./transport/v2rayxhttp/... ./experimental/libbox/...    exit 0
$ GOOS=ios     GOARCH=arm64  ... (same package list)                               exit 1  [pre-existing, see §7.6]
$ GOOS=linux   GOARCH=amd64  ... (same package list)                               exit 1  [pre-existing, see §7.6]
$ GOOS=windows GOARCH=amd64  ... (same package list)                               exit 1  [pre-existing, see §7.6]
```

The three failures are identical at the baseline with every change stashed and come from
`experimental/libbox` → `include` → `protocol/naive` → `cronet-go/all`; the changed packages
(`route`, `adapter`, `common/httpclient`, `common/power`, `transport/v2rayxhttp`, and the root
package) do not import it. To show that directly, the same four targets were built for the changed
packages **without** `experimental/libbox`:

```
$ for spec in "darwin arm64" "ios arm64" "linux amd64" "windows amd64"; do
      set -- $spec
      GOOS=$1 GOARCH=$2 go build -tags "$TAGS" \
        ./route/... ./adapter/... ./common/httpclient/... ./common/power/... \
        ./transport/v2rayxhttp/... .
  done
GOOS=darwin   GOARCH=arm64    exit 0
GOOS=ios      GOARCH=arm64    exit 0
GOOS=linux    GOARCH=amd64    exit 0
GOOS=windows  GOARCH=amd64    exit 0
```

The whole tagged suite, which is the release gate:

```
$ go test -count=1 -tags "$TAGS" ./...
FULL_EXIT=0   ok=74   FAIL=0   packages with no test files=95
```

No failure to classify: there were none.

`gofmt -l` over the changed trees prints nothing. `go mod tidy -diff` exits 0 with empty output.
The commit carries no `go.sum` change.

Race, on every package this work touches:

```
$ go test -count=1 -tags "$TAGS" -race ./route/... ./adapter/... ./common/httpclient/... \
      ./common/power/... . ./experimental/libbox/... ./transport/v2rayxhttp/...
ok  github.com/sagernet/sing-box/route                        8.831s
ok  github.com/sagernet/sing-box/route/rule                   1.456s
ok  github.com/sagernet/sing-box/adapter                      1.374s
ok  github.com/sagernet/sing-box/adapter/outbound             1.719s
ok  github.com/sagernet/sing-box/common/httpclient            3.594s
ok  github.com/sagernet/sing-box/common/power                 4.373s
ok  github.com/sagernet/sing-box                              2.838s
ok  github.com/sagernet/sing-box/experimental/libbox          3.048s
ok  github.com/sagernet/sing-box/transport/v2rayxhttp         3.886s
RACE_EXIT=0
```

The new tests, twenty times each under the race detector:

```
$ go test -count=20 -tags "$TAGS" -race -run '<the three new tests>' -v ./route/
  20 --- PASS: TestTheOnDemandTunnelsAreReachableOnlyFromTheEligibilityPass (0.00s)
  20 --- PASS: TestTheReusableOwnersTheWalkIsDocumentedToReachKeepTheirCapabilities (0.00s)
  20 --- PASS: TestTheWalkReachesTheRealHTTPClientManager (0.00s)
ok  github.com/sagernet/sing-box/route  2.611s
```

The stress run — 100 sleep/wake cycles and 100 network transitions, with the goroutine count logged
before and after rather than only asserted, plus the no-resurrection phase:

```
$ go test -count=1 -tags "$TAGS" -race -v -run '<the four stress tests>' .
=== RUN   TestOneHundredSleepWakeCyclesLeakNothingAndLeaveNoBoundaryUnpaired
    box_lifecycle_stress_test.go:76: goroutines: 2 before the sleep/wake cycles, 2 after
--- PASS: TestOneHundredSleepWakeCyclesLeakNothingAndLeaveNoBoundaryUnpaired (0.00s)
=== RUN   TestOneHundredNetworkTransitionsDoNotConsumeOrPublishADeviceBoundary
    box_lifecycle_stress_test.go:120: goroutines: 2 before the network transitions, 2 after
--- PASS: TestOneHundredNetworkTransitionsDoNotConsumeOrPublishADeviceBoundary (0.00s)
=== RUN   TestNoResurrectionAfterClose
    box_lifecycle_stress_test.go:172: goroutines: 2 before the post-Close facts, 2 after
--- PASS: TestNoResurrectionAfterClose (0.00s)
=== RUN   TestTheBridgeUnderConcurrentLifecyclesAndTeardown
    box_lifecycle_stress_test.go:213: goroutines: 2 before concurrent facts and a teardown, 2 after
--- PASS: TestTheBridgeUnderConcurrentLifecyclesAndTeardown (0.01s)
ok  github.com/sagernet/sing-box  2.222s
```

The 100 cycles assert one boundary per cycle with the epoch equal to the cycle number, one level
pause and one level wake per cycle — i.e. the three facts of each transition coalesce and nothing is
left unpaired. The 100 transitions assert that a network transition neither publishes nor consumes a
device boundary. The no-resurrection phase asserts that a fact arriving after `Close` is a counted
no-op that reaches no pool. The `t.Logf` in `requireGoroutinesReturnTo` is the only change to an
existing test in this work; no assertion was weakened, and the helper's `Eventually` bound is
unchanged.
