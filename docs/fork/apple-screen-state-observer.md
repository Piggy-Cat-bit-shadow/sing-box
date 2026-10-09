# The Apple screen-state observer, and the device axis it unlatches

What this repository cannot do from the Go side, what it now does from the Go side, and the exact
patch the Apple client needs.

## The state before this change, verified against the pinned sources

The Apple device axis had no publisher. Concretely:

- `PauseManager.DevicePause()` is a LEVEL, and the Apple lifecycle enters it once. `CommandServer.Wake()`
  publishes the reuse EDGE and does not touch the level, which is correct: on iOS the extension is
  resumed for every push and background task while the phone is still locked.
- The only method that lifted the level was `CommandServer.WakeNow()`, and nothing in the client
  called it. `clients/apple` is a gitlink (`git ls-tree HEAD clients/apple`), and the revision it
  pins has no `Library/Network/ScreenStateObserver.swift`: this was re-checked against
  `git ls-tree HEAD clients/apple` → `5911580a6366da78e6b4b5b4459596e5a2cf1eb4`, and against the
  newest revision of the same branch (`6b1e54a92`), where the path is also absent (HTTP 404 from
  `raw.githubusercontent.com/.../<sha>/Library/Network/ScreenStateObserver.swift`).
- The SAME repository's `dev` branch, which is the macOS source this fork builds, HAS the file at
  `d1224bb5081b3df5d0ecc55b1bd3d72ea6c60628` and at `f8ad6d0`, and installs it from
  `ExtensionProvider.startTunnel` under `#if os(iOS)`.

So the observer is not lost work to be re-invented: it exists, in the same repository, on the branch
the same repository builds for the other platform, gated to iOS, and 32 lines long. The iOS branch
simply forked before it landed.

Consequence of the latch, all in-tree (this is what the patch removes):

- `Governor.State()` stayed QUIESCENT and then DEEP_IDLE for the life of the process.
- `route/rule/rule_set_updater.go` blocks in `WaitProviderRefresh` forever, so remote rule sets and
  the rule-set refresh never run again after the first sleep.
- `service/ssmapi/server.go` suppresses its cache save forever.
- The DEEP_IDLE pool release re-fired on every traffic gap, which is "close the pool while the phone
  is being used" - the behaviour the power work set out to remove.

## The Go half: `box_lifecycle.go`

The core now owns the mapping from every Apple fact to the two axes, in one place with the ordering
and dedup argument written down (`box_lifecycle.go`, reached through `Box.DeviceSlept`,
`Box.DeviceResumed`, `Box.DeviceWoke`, `Box.ScreenStateChanged`, `Box.LockStateChanged`):

| Apple fact | reuse EDGE | device LEVEL |
|---|---|---|
| `sleep()` | sleep started | pause |
| `wake()` | resume (boundary) | — unchanged |
| `displayStatus` → off | sleep started | pause |
| `displayStatus` → on | resume (boundary) | — unchanged |
| `lockstate` → locked | sleep started | pause |
| `lockstate` → unlocked | resume (boundary) | **wake** |
| `wakeNow()` (host event) | resume (boundary) | **wake** |

Two properties fall out of that table, and both are the point:

1. **A display turning on is not an unlock.** iOS lights the lock screen for a push notification, for
   raise-to-wake, and for a notification dismissed without unlocking. Releasing the level for any of
   those is the wake storm §3.3 forbids, so a display-on publishes only the reuse edge — which is
   still exactly what the reuse epoch needs, because a display that came back proves the sleep ended.
2. **The unlock is the only fact that releases the level.** It is the platform saying a person is
   using the device, it arrives once per unlock, and the governor coalesces repeats and staggers the
   release (health check 5s, statistics 10s, provider refresh 15s).

The core is therefore complete at the boundary, and the client patch is a *fact publisher* and
nothing more: it does not decide anything, and a client that publishes only the lock fact still gets
a correct device axis in both directions.

## What the client patch is

`docs/fork/apple-screen-state-observer.patch`, against the pinned iOS revision. It has three hunks in
`Library/Network/ExtensionProvider.swift` plus one new file. It touches no branding, no signing, no
Team ID, no Bundle ID, no App Group and no entitlement, and it needs no Xcode project change:
`Library` is a `PBXFileSystemSynchronizedRootGroup` in `sing-box.xcodeproj/project.pbxproj`, so a new
`.swift` file in `Library/Network/` is compiled into the `Library.framework` the `Extension` target
already links. `import notify` needs no package dependency either: the project references no package
by that name, and `notify_register_dispatch` / `notify_get_state` / `notify_cancel` come from the
Darwin `notify` system module.

```
Library/Network/ScreenStateObserver.swift        new file
Library/Network/ExtensionProvider.swift:29       + private var screenStateObserver (inside #if os(iOS))
Library/Network/ExtensionProvider.swift:216      + install it after startService() succeeds
Library/Network/ExtensionProvider.swift:313      + cancel it in stopTunnel
```

Anchor handles: line numbers are from the generated diff against
`5911580a6366da78e6b4b5b4459596e5a2cf1eb4`; the patch itself anchors on surrounding text, so it
applies by content and fails closed if the client moves.

### The one deliberate deviation from the `dev` copy

The observer on `dev` calls `commandServer.wakeNow()` on display-on, i.e. it treats a display turning
on as a device wake. This patch does not, for the reason in the table above: on iOS a push
notification lights the lock screen, so that call releases health checks, URLTests and provider
refreshes for a phone in a pocket — precisely the sequence §3.3 requires must NOT release the pause.
With the Go mapping in place the call is also unnecessary: `recordScreenState(true)` already
publishes the reuse boundary, and `recordLockState(false)` is the unlock that releases the level.

That is the entire difference:

```
-$            if state == 1 {
-$                commandServer.wakeNow()
-$            }
```

Verification of the patch, run here against a fresh copy of the pinned file:

```
git apply --check -v docs/fork/apple-screen-state-observer.patch
Checking patch Library/Network/ExtensionProvider.swift...
Checking patch Library/Network/ScreenStateObserver.swift...
APPLY-CHECK: OK
```

SHA256 of the patch: `51504470cc178360d7bff509fa52ab6d009940ee74069d9f7558d2a6d49e166a`.

SHA256 of the files it produces:

```
796b41bc3dc1718519fa53227dc8defa80480dc7656140894dc8b217ca6c7b4a  Library/Network/ExtensionProvider.swift
33d388e9073ae1d92e4f86420a2918330d08c36741b7db0dcfc7f151e7f3ae0f  Library/Network/ScreenStateObserver.swift
```

## How the integrator lands it

The iOS source is this repository's submodule, so either of these is a single-owner change:

1. commit the patch on the client fork (`Piggy-Cat-bit-shadow/sing-box-for-apple`) on top of the
   pinned iOS commit, push it, and move `clients/apple`'s gitlink to the new commit; or
2. apply it as a fourth build-time overlay in `scripts/ci/prepare-apple-client.sh`, next to the
   compatibility, branding and entitlement overlays, which already exist for exactly this kind of
   pinned-client adaptation and already fail closed when an anchor disappears.

Either way the parent records one revision and the client keeps its own history; the patch file stays
in this repository either way, because it is what the next repin has to be checked against.

## Limitations, stated rather than assumed away

1. **The notification names are not public API.** `com.apple.iokit.hid.displayStatus` and
   `com.apple.springboard.lockstate` are Darwin notification names, not Apple-documented interfaces.
   This fork ships an UNSIGNED IPA that the user signs locally (see `docs/fork/RC-CERTIFICATE.md`), so
   no App Review static analysis is involved; that is a property of the distribution model and not a
   claim that the names are supported. If a future iOS stops posting them, the observer's `init`
   registers and never fires: the reuse epoch keeps working (it is edge-driven), and the level latches
   again.
2. **The public-API fallback, if that happens.** The app process can observe
   `UIApplication.didBecomeActiveNotification` (public, no entitlement) and forward the fact to the
   extension over the existing `handleAppMessage` channel; the extension then calls
   `commandServer.wakeNow()`, which is the dedicated host event the core already provides. The Go
   side needs no change for that: `WakeNow()` publishes the reuse verdict and then releases the level.
   It was not chosen as the primary mechanism because `handleAppMessage` in the pinned client decodes
   a single `ExtensionStartOptions` message and would have to grow a second message shape, and because
   it only fires when the app itself is brought forward.
3. **Neither the observer nor this core change is device-verified here.** There is no simulator
   runtime and no iOS device in this environment. What is proven is the Go mapping (deterministic
   tests over the real pause manager), the compile-level client integration (the patch applies, the
   new file is in a synchronized group, no dependency or project change is needed), and the
   notification names' existence in the same repository's shipped iOS-gated code. Whether iOS
   actually delivers the two notifications on a given build, and what the user-visible effect is,
   remains a device item - see the runbook in `docs/fork/post-wake-reuse.md`.
4. **A client that publishes nothing still latches.** No timer is used and none should be: no timer
   can tell a locked phone from an unlocked one, so it would either release speculation for the
   pocketed phone or fail to release it for the unlocked one. The dependency is stated here instead of
   being hidden behind a guess.
