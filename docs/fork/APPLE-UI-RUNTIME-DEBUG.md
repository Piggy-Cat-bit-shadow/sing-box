# Apple UI runtime debug runbook

The UI round was audited statically and its navigation *mapping* is covered by an executed harness.
Nothing here is settled by that: this is the runtime pass, and it is written as a sequence of commands
so that it is a short scripted procedure rather than an afternoon of clicking.

Everything below is runnable on this machine. Where a step needs a device or a simulator runtime, it
says so; where a step is only possible in the Xcode UI, it says that too, rather than implying a
command exists.

## 0. What is already in the code for this

`HakoUITrace` (DEBUG only, compiled out of Release) prints one line per navigation transition to the
unified log:

```text
[UI] primary home -> tools source=HakoPrimaryShell.primarySelection
[UI] child tools nil -> logs source=HakoPrimaryShell.applySelectedRoute
[UI] child-unchanged tools/logs source=HakoPrimaryShell.applySelectedRoute
[UI] child-dismiss tools/logs source=HakoPrimaryShell.childDestination
[UI] selection logs for tools source=HakoPrimaryShell.onChange(selection)
[UI] settings-requested remoteControl source=MainView.onReceive(navigateToSettingsPage)
[UI] settings-apply remoteControl push=true clear=true source=SettingView.applyPendingSettingsPage
[UI] selection settings desktop source=MainView.onChangeCompat(selection)
[UI] path-push remoteControl source=MainView.onChangeCompat(selection)
```

It records names and states, never a profile, an address or a command-client payload, and it is called
from state changes, never from `body`.

Accessibility identifiers exist on the interaction nodes a test has to press, and nowhere else:

```text
hako.tab.home  hako.tab.tools  hako.tab.more      (the three primaries)
hako.home.logs  hako.home.groups  hako.home.connections   (the Home shortcuts)
```

## 1. macOS — run the real app

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
cd clients/apple

# Build Debug SFM. DISABLE_SWIFTLINT=1 avoids the package plugin's bundled SourceKitten, which
# resolves sourcekitd through xcode-select (CommandLineTools) and aborts.
DISABLE_SWIFTLINT=1 xcodebuild -project sing-box.xcodeproj -scheme SFM -configuration Debug \
  -destination 'generic/platform=macOS' -derivedDataPath /tmp/dd-mac \
  -skipPackagePluginValidation -skipMacroValidation CODE_SIGNING_ALLOWED=NO build

app=/tmp/dd-mac/Build/Products/Debug/SFM.app     # confirm the name in Build/Products/Debug

# Start a trace capture in one terminal:
log stream --style compact --predicate 'category == "ui"' > /tmp/ui-trace.log

# Launch with the Main Thread Checker inserted, which is what Xcode's diagnostic does:
DYLD_INSERT_LIBRARIES="$(xcode-select -p)/usr/lib/libMainThreadChecker.dylib" \
  "$app/Contents/MacOS/SFM" > /tmp/sfm-stdout.log 2>&1 &
```

`libMainThreadChecker.dylib` may live elsewhere in a given Xcode; if the path is wrong the launch fails
loudly and the alternative is the scheme's Diagnostics tab, which enables the same library. Do not
proceed with a "checker not loaded" warning uncorrected - a checker that silently is not running is
worse than none.

Then drive the app. Either interact with it, or drive the state machine through the deep link:

```bash
open -a "$app" 'sing-box://...'      # whatever scheme the app registers; SFI/MainView.onOpenURL
```

### What to watch, in this order

```bash
grep -c "primary" /tmp/ui-trace.log          # every tab switch
grep "child" /tmp/ui-trace.log               # every push, dismissal and unchanged re-arm
grep "settings-" /tmp/ui-trace.log           # the notification path
```

Runtime issues to treat as failures (§I):

```text
Publishing changes from background threads is not allowed
Modifying state during view update, this will cause undefined behavior
Main Thread Checker: UI API called on a background thread
NavigationLink is presenting a value of type ... but there is no matching navigationDestination
Attempt to present ... which is already presenting
Invalid frame dimension (negative or non-finite)
```

Capture them from the stdout log and from `log stream --predicate 'senderImagePath contains "SFM"'`:

```bash
grep -E "Publishing changes|Modifying state|Main Thread Checker|already presenting|Invalid frame" \
  /tmp/sfm-stdout.log
```

## 2. macOS — the state table to exercise

Each row is an interaction and the trace lines it must produce. The last column is the invariant that
must hold afterwards: **the visible page equals the `NavigationPage` state**.

| # | action | expected trace | invariant |
|---|---|---|---|
| 1 | cold launch | `selection dashboard` once | Home visible, no child armed |
| 2 | tap `hako.home.logs` | `child tools nil -> logs` then `selection logs for tools` | Logs visible with a back button |
| 3 | back | `child-dismiss tools/logs`, then `child tools logs -> nil` | Tools root visible, selection `.tools` |
| 4 | Logs, then Home, then Tools | `primary tools -> home`, `primary home -> tools` | Logs visible again on Tools |
| 5 | Logs, interactive swipe back | `child-dismiss tools/logs` | selection `.tools`, not `.logs` |
| 6 | Tools root, Home, Tools | no `child` line (nothing was armed) | Tools root visible, no push |
| 7 | tap the current tab twice | one `primary` line or none; no `child` line | no stack reset |
| 8 | tap `hako.home.logs` twice | one `child nil -> logs`, then `child-unchanged` | one back button, not two |
| 9 | rapid Home / Tools / More | one `primary` line per actual change | final visible page matches the last line |
| 10 | Logs open while the tunnel starts | no `child` line from the status change | Logs stays visible and updates |
| 11 | deep link to Logs before Tools ever appeared | `child tools nil -> logs` on first appearance | Logs visible |
| 12 | settings notification before More ever appeared | `settings-requested`, then `settings-apply push=true` | Remote Control visible once |

Any row where the trace shows the transition but the screen does not, or the screen moves without a
trace line, is the bug this round exists to find. Record it with the trace excerpt.

## 3. macOS — one tap, one action (§H)

The trace makes double-firing visible. For each of Start/Stop, a profile switch, Groups, Connections,
Logs, the three report lists and Remote Control:

```text
one tap   -> exactly one action line, and at most one navigation or presentation line
two taps  -> the second must be a no-op (child-unchanged) or be refused while in transition
```

Start/Stop specifically: the accessory must not accept a second tap while `!profile.status.isSwitchable`
or `coordinator.reasserting` - the gate is on the whole Home page, so a second tap produces no line.

## 4. macOS — view hierarchy and layout (§J)

`Debug View Hierarchy` is Xcode-only; open the app from Xcode and use it. What to look for, at narrow,
normal and very wide window widths, in Chinese and English, Light and Dark, default and the largest
Dynamic Type:

```text
one scroll view per page (a nested one shows as two scroll indicators or a clipped inner scroll)
no zero-size views left in the hierarchy by a conditional that collapsed
the detail column centred and inset, nothing clipped at the maximum width
the bottom accessory not overlapping content and not doubled
sheet backgrounds not layered over a second sheet
```

Screenshots for the record:

```bash
screencapture -x /tmp/sfm-narrow.png      # after resizing; one per width and appearance
```

## 5. iOS — simulator (layout, navigation, locale, Dynamic Type)

```bash
xcrun simctl list runtimes                 # the runtime being downloaded
xcrun simctl list devices available
xcrun simctl boot "iPhone 16"              # or whichever device the runtime provides
open -a Simulator

# Build and install.
xcodebuild -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 16' -derivedDataPath /tmp/dd-ios-sim \
  -skipPackagePluginValidation -skipMacroValidation CODE_SIGNING_ALLOWED=NO build
xcrun simctl install booted /tmp/dd-ios-sim/Build/Products/Debug-iphonesimulator/JiejieBox.app

# Trace + console.
xcrun simctl spawn booted log stream --style compact --predicate 'category == "ui"' > /tmp/ios-trace.log

# Launch, in each appearance / text size / language combination.
xcrun simctl ui booted appearance dark
xcrun simctl ui booted content_size accessibility-extra-extra-extra-large
xcrun simctl launch --console-pty booted io.nekohasekai.sfamt -AppleLanguages '(zh-Hans)'
```

The NetworkExtension does not run in the simulator: the tunnel rows will show a disconnected service.
That is expected and is not evidence either way - the tunnel items are device items (§K).

Cases 1-12 above apply unchanged to the simulator; the trace predicate and the invariants are the same.
Layout items from §4 apply too, with the simulator's device sizes instead of resizing.

## 6. iOS — physical device (the NetworkExtension items)

```bash
xcrun devicectl list devices                 # an iPhone must appear as connected
xcrun xctrace list devices | head            # the same list, other tool

# Build for the device with development signing, install and launch with the console attached.
xcodebuild -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS,id=<device-udid>' -derivedDataPath /tmp/dd-ios-device \
  -allowProvisioningUpdates build
xcrun devicectl device install app --device <device-udid> \
  /tmp/dd-ios-device/Build/Products/Debug-iphoneos/JiejieBox.app
xcrun devicectl device process launch --console --device <device-udid> io.nekohasekai.sfamt
```

Then, at least five times (§K):

```text
[ ] Start -> Connecting -> Connected; the accessory changes once and shows no duplicate control
[ ] the Home connected cards appear without leaving the page
[ ] Groups and Connections become reachable per their conditions
[ ] Stop -> the accessory returns to the start control
[ ] no control can be tapped twice into two actions while switching
[ ] the UI never shows Connected before the tunnel reports it, and never stays Connecting after it
[ ] background the app and return: the page and the state are what they were
[ ] change Wi-Fi/cellular with the tunnel up if the device allows it, and watch Reasserting
```

Record one trace excerpt per cycle, and the exact same commands' output for the report.

## 7. Instruments (§L)

```bash
xcrun xctrace list templates

xcrun xctrace record --template 'Hangs' --time-limit 2m --output /tmp/sfm-hangs.trace \
  --launch -- "$app/Contents/MacOS/SFM"
xcrun xctrace record --template 'Leaks' --time-limit 2m --output /tmp/sfm-leaks.trace \
  --launch -- "$app/Contents/MacOS/SFM"
xcrun xctrace record --template 'Time Profiler' --time-limit 2m --output /tmp/sfm-time.trace \
  --launch -- "$app/Contents/MacOS/SFM"
```

The session to record, identically for all three: launch, visit each primary, open and close Groups,
open and close Connections, open Settings and one settings page, return to Home, idle.

What counts as a finding, and what does not:

```text
FINDING   a hang longer than ~250ms while the app is idle
FINDING   a view or view model retained after its page was dismissed
FINDING   task or subscription count that grows monotonically across the session
FINDING   CPU above a few percent while nothing is happening on screen
NOT       a difference of a few percent in scroll or layout cost between two builds
```

## 8. XCUITest — the automated form of the table (§G)

A minimal UI test target is the next step, and the identifiers above exist so that it can be written
without touching the pages again. The cases are rows 1-12 plus the one-tap-one-action set:

```swift
let app = XCUIApplication()
app.launch()
app.buttons["hako.home.logs"].tap()            // row 2
app.navigationBars.buttons.element(boundBy: 0).tap()   // row 3
app.tabBars.buttons["hako.tab.tools"].tap()    // rows 4, 6
```

The target must be added to `project.pbxproj`, which the parent's branding overlay also rewrites - so
it is done as its own step, verified by building it, rather than hand-edited blind. Until then, the
table above is executed by hand with the trace as the record of what happened.

## 9. What goes in the report

```text
macOS
  launched:                 YES/NO          app path, pid, uptime
  interaction run:          PASS/FAIL       the table rows attempted, with the trace excerpt
  runtime warnings:         none / list     the exact strings, and the path that produced each
  view hierarchy issues:    none / list
  Instruments findings:     none / list     template, duration, what was observed

iOS
  simulator:                runtime, device, cases run
  physical device:          udid, iOS version, build, cases run
  NetworkExtension:         start/stop cycles, what the UI showed at each step
  runtime warnings:         none / list

Navigation
  HakoPrimaryShell:  PASS/FAIL   (rows 1-12)
  deep links:        PASS/FAIL
  notifications:     PASS/FAIL
  sheets:            PASS/FAIL

Automated tests
  XCTest:    the harness (already executed) + any new unit tests
  XCUITest:  added / not added, and why

Real bugs found      <reproduction> -> <fix> -> <the trace that shows it fixed>
Still manual-only    <the rows that could not be automated and why>
```

## 10. Order of work

1. macOS launch + trace + warnings + table (no device or simulator needed).
2. macOS Instruments session.
3. Simulator: layout, locale, Dynamic Type, the same table.
4. Physical device: the NetworkExtension life cycle.
5. XCUITest target, if the pbxproj step verifies cleanly.
6. Fix anything the above finds, with a reproduction first - and never by lengthening a delay.

## 11. What the first execution of this runbook established

### The client did not build against this fork's libbox at all

Two independent gaps, both in `clients/apple`, both now fixed there:

- `LibboxPlatformInterfaceProtocol` gained `usePlatformAutoRedirect()` and
  `createAutoRedirect(_:handler:)` in the core while the client still declared the older member set.
  The app failed at `Library/Network/ExtensionPlatformInterface.swift` with "does not conform".
- `ExtensionProvider` calls `LibboxPromotePowerReportDraft()`, which no revision of this core
  exports (`PromoteOOMDraft` exists, the power twin was never added).

`scripts/ci/prepare-apple-client.sh` fills both gaps as a build-time overlay, which is why the
failure is invisible in CI and appears the moment anyone builds the client directly. The client now
declares both itself, so it builds standalone - and, because the overlay's own "already applied"
guard keys on `usePlatformAutoRedirect()`, the parent's prepare step now recognises a client that
needs nothing from it.

The Libbox checked into both repositories was also stale: it predated the protocol members and the
`PromotePowerReportDraft` call. `scripts/ci/build-apple-libbox.sh` rebuilds it from this tree.

Two consequences worth recording:

- A local Libbox build needs `gomobile`/`gobind` from `github.com/sagernet/gomobile@v0.1.13`, not
  upstream `golang.org/x/mobile`, and needs `DEVELOPER_DIR` set: `xcode-select -p` answers
  `/Library/Developer/CommandLineTools` on this machine, and gomobile refuses to run without Xcode.
- An interrupted libbox build leaves `build/ios-arm64` etc. behind and the next run fails with
  "Libbox.objc.h: file exists". Those directories are gitignored build products; removing them is
  the fix.

After the client fix, **`scripts/ci/test-apple-signing.sh` reports 2 failures** on
`could not apply the overlay; skipping its assertions`. That is the same overlay: the test tries to
apply it to the now-complete client and the guard refuses. The publish suite - the flow that
actually produces a TestFlight build - is 86/0. Reconcile the signing test with the client before
treating that suite as a gate again.

### The trace was written to a level nobody can read

`HakoUITrace` logged with `Logger.debug`, and `log stream` does not deliver debug-level messages
from another process. Measured with a two-line control program: `debug` produced nothing,
`notice` produced the line. The instrument now logs at `notice`. Without this the runbook below
would have appeared to pass while the trace stayed empty, and an empty trace is indistinguishable
from "no state changed yet" - which is why `MacLibrary/MainView.onAppear` now logs one anchor line
per launch.

### The trace is confirmed working at runtime

The desktop client was built, signed and launched, and the unified log produced the anchor line:

```text
[UI] root-appear selection=0 remote=false source=MacLibrary.MainView.onAppear
```

So the whole chain - compile under `#if DEBUG`, `Logger.notice`, the `ui` category, `log stream`
with `--predicate 'category == "ui"'` - is proven end to end on a real launch. An operator
following section 1 will see output.

Note `selection=0`: `NavigationPage` is an `Int`-backed enum, so the transition lines print raw
values (`logs`, `tools` and `settings` are `2`, `3` and `4`). Mapping them to names is a readability
change, not a correctness one, and is deliberately left until a run does it.

### Why the app does not stay up here, and what that is not

The app renders, logs its anchor line, and then exits at `Database.swift:72`
(`SQLite error 23: authorization denied`) because it cannot write to its App Group container. That
is an environment fact, traced to three separate causes, none of them the client:

- The container belongs to a different signing identity than the certificate on this machine. The
  installed provisioning profiles are for team `TAFD7BAGYZ` and App Group
  `group.top.jiejie12131.jiejiebox`; the app is built for `io.nekohasekai.sfamt` and
  `group.io.nekohasekai.sfamt`, for which no profile exists here. Writing to the group container is
  refused for any process without that entitlement, including the shell (`touch` inside
  `~/Library/Group Containers/group.io.nekohasekai.sfamt/...` returns "Operation not permitted").
- Signing it *with* `com.apple.security.app-sandbox` but without a profile hangs at startup: a
  `sample` shows the main thread parked in `_libsecinit_appsandbox` -> `_xpc_pipe_routine` ->
  `mach_msg`, waiting on the sandbox daemon for a container it will never grant. That is the shape
  to recognise if the app "launches and does nothing".
- Signing it *without* the sandbox entitlement removes the hang, and the anchor line appears, but
  the container write is still refused, so the process still exits at the database step.

To run the table, build and sign the way the publish flow does - a real team, a profile carrying the
App Group, and matching bundle identifiers. On this machine that means building with
`APPLE_TEAM_ID=TAFD7BAGYZ APPLE_BASE_BUNDLE_ID=top.jiejie12131.jiejiebox APPLE_APP_GROUP_ID=group.top.jiejie12131.jiejiebox`,
for which profiles already exist.

### What still needs a real run

- A simulator or device run. The simulator on this machine cannot boot: all devices fail with
  `SimLaunchHostService.RequestError code=4 / Failed to start launchd_sim`. The log shows the
  runtime disk image mounting and `SimLaunchHost` loading `liblaunch_sim.dylib` successfully, after
  which the `launchd_sim` stub itself trips `EXC_BREAKPOINT` (SIGTRAP) in `dyld_sim`'s `start_sim`.
  `/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app` is also absent from this
  Xcode installation. Nothing in the client is implicated; the destination is unusable.
- The macOS interaction table itself. A window can be created in this session (`NSWindow`
  `makeKeyAndOrderFront` reports `visible=1`), so rendering is not the obstacle - handling the
  clicks is. There is no accessibility control (`osascript` blocks on permission) and
  `screencapture` reports "could not create image from display", so the rows cannot be driven from
  here even once the app stays up.

