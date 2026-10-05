# Hako UI Migration Phase 2 — handoff notes for the next agent

Written at the point the Mac client was taken out of scope and the iOS round was handed
over for debugging. Everything below is either verified on this machine or explicitly
marked as not.

---

## 1. Where the work lives

```text
parent repo   /Users/jie/Desktop/其他文件/JiejieBox-0.1.2-release
              branch testing, remote origin https://github.com/Piggy-Cat-bit-shadow/sing-box.git
              NOTE: the session workspace is /Users/jie/Desktop/其他文件/sing-box, which is EMPTY.
              The checkout that exists is the one above.

apple client  clients/apple  (submodule, remote .../sing-box-for-apple.git)
              branch origin/hako-ui, detached at the parent's gitlink
```

Commits made this round, in `clients/apple`, on top of `1b26865`:

```text
ccea921  refactor(ui): consolidate the Hako design system and rebuild the page scaffolds
619e5d1  refactor(ui): migrate the remaining pages, the workspaces and the desktop shell
3d3229c  fix(ui): make the shell, the chrome and the pages survive an actual UI test run
1a5337b  test(ui): make the navigation suite pass, and say why each case is written the way it is
```

Nothing is pushed. The parent's gitlink has **not** been updated — `git submodule status`
in the parent still reports `1b26865`, so the three commits above are only in the
submodule's working repository. Decide whether to push before updating the gitlink.

### New files (the design system this round added)

```text
ApplicationLibrary/Views/HakoStyle/HakoScaffold.swift   the five page shells, the circular
                                                        navigation controls, the action
                                                        capsule and toolbar action, the
                                                        bottom search, the segmented tabs,
                                                        the shared chrome modifier
ApplicationLibrary/Views/HakoStyle/HakoData.swift       the record-shaped rows settings rows
                                                        were being forced into: data card,
                                                        data row, badges, metric stack,
                                                        summary card, proxy group/member
                                                        rows, action tile
SFIUITests/HakoSnapshotUITests.swift                    drives and captures the manual's
                                                        snapshot list
```

`Libbox.xcframework` inside `clients/apple` is **untracked/gitignored**. A simulator slice
was merged into it on this machine (see §4); it affects no commit.

---

## 2. macOS is out of scope — what that means in the code

The user's instruction: stop working on the Mac client and leave it as it was.

What is already true of the code as committed:

- `MacLibrary/` was **reverted to `1b26865` verbatim** during the round, then the revert
  was cancelled on the user's instruction. The commits therefore still contain the Mac
  shell work: `MacLibrary/SidebarView.swift` (unified sidebar, `Session`/`Utilities`
  grouping, localized titles) and `MacLibrary/MainView.swift` (token-derived sidebar and
  detail widths, window floor). **These are unverified: the macOS app cannot be run on
  this machine (§5), so nobody has seen them.**
- The shared pages present their new (Hako) implementation on **all** platforms, including
  macOS: `SettingView`, `ToolsView`, `CoreView`, `PacketTunnelView`, `OnDemandRulesView`,
  `ProfileOverrideView`, `SponsorsView`, the three report lists, `GroupListView`,
  `ConnectionListView`, `ConnectionView`, `NewProfileMenuView`.
- `ActiveDashboardView` presents `HakoHomeView` on macOS as well as iOS; macOS no longer
  uses `OverviewView` (which is still present for tvOS).

If the next step is to genuinely freeze macOS at its original behaviour, the mechanical
form that was started and then cancelled is: put each of those files' original content in
an `#else` branch of `#if os(iOS)` and keep the new content in the `#if` branch, for the
14 shared page files listed above. `git show 1b26865:<path>` is the original. The split
was applied once and reverted; it compiled on both platforms for the files that were
split, so the approach is sound.

Design-system files (`HakoTheme`, `HakoSurface`, `HakoRow`, `HakoCard`, `HakoStatus`,
`HakoScaffold`, `HakoData`) are shared and additive; they change macOS rendering only
where a macOS page uses them, which after the reverted Mac shell is limited to the shared
pages above.

---

## 3. What the round actually changed, and why

### Design system

`HakoTheme` gained the tokens the pages were each inventing: navigation control diameter
and glyph size, action capsule metrics, toggle row floor, segmented tab height, a font-role
scale, surface and divider opacities, card inner padding, navigation header height, bottom
search metrics, root tab clearance. `HakoProductPalette` gained `selected`, `expanded` and
`control` fills and answers by surface role. `HakoRow` gained the manual's row vocabulary
(navigation, toggle, destructive, selection, metric) on one shared `HakoRowBody`.
`HakoData` is new. `HakoScaffold` is new.

### The double chevron, fixed at the component boundary

A `NavigationLink` inside a `Form` gets the platform's disclosure indicator — **on iOS as
well as on the desktop** — and `HakoDestinationRow` drew its own on top, so affected rows
rendered `>>`. The rule is now "the container declares whether it draws indicators":
`FormView` declares that it does, the painted scaffolds declare that they do not, and the
value travels in `\.hakoContainerDrawsDisclosure`. Nothing is hidden with an opacity.

### One global bottom bar (iOS P0)

`HakoPrimaryShell`'s accessory slot is **gone**, not merely unused: it was floating a
runtime status pill with its own start control above the tab bar, so the app had two
stacked global bars. Runtime state and the start control are now Home's first card; remote
state is a toolbar chip that also owns disconnect.

### Root tab only at root (iOS P0)

A pushed page hides the tab bar. The rule lives in `HakoNavigationChrome` — which every
detail page wears — rather than in the shell alone, because a page pushed by a
`NavigationLink` never went through the shell. `hakoHidesRootTabBarForDetail()` is the same
rule for the two pages that still own their own form. iOS 16+ only: on iOS 15 there is no
SwiftUI way to hide an enclosing `TabView`'s bar and reaching into `UITabBarController`
would be an untestable hack.

### Information architecture (iOS)

- Home: session + start/stop, profile, mode, shortcuts, traffic, runtime. The kernel's
  figures are all still there; they are no longer the page's skeleton.
- More: `Connection` / `Application` / `Core and Data` / `Remote and Configuration` /
  `Support`, a subtitle on every row.
- Tools: `Current Session` / `Endpoints` / `Network Tools` / `Diagnostics`. The `Debug`
  section is gone — `Taiwan Flag Available` was a readout of whether the device's font
  renders a flag, which the client does need for its network-permission flow
  (`SFI/ApplicationDelegate.swift:130`) but which no user came to Tools to see. The check
  and `DeviceCensorship` remain; only the row is gone.
- Packet Tunnel: the titles were the NetworkExtension property names and each row pasted
  the framework's documentation plus its own saturated `Apple Documentation` link, one of
  them reading "No documentation." The switches write the same preferences with the same
  polarity; the page names each option in the user's terms and links Apple's reference
  once, at the end. **Polarity was deliberately NOT inverted** even though the manual's
  wording is positive ("Include APNs") while the stored preferences are negative
  (`exclude_apns` defaults to true): inverting would change what an existing user sees
  without changing what they get, and hidden a default.
- Proxies and Activity became workspaces: fixed bottom search that filters without
  touching what the core reported, a summary card, test-all and expand-all, an expandable
  group header that shows strategy/selected member/count while collapsed. Activity has no
  "requests" lens: this core does not record requests and a tab with nothing behind it is
  a fake page (`RulesOverviewView` in the reference has no counterpart here either).
- Config centre: the add-configuration sheet is the modal scaffold with action tiles.

### Legacy residue

| item | where | disposition |
|---|---|---|
| `includeAllNetworks`, `excludeAPNs`, `excludeCellularServices`, `excludeLocalNetworks`, `enforceRoutes`, `excludeDeviceCommunication` | `PacketTunnelView` titles and footnotes | replaced with user titles + short footnotes |
| six repeated `Apple Documentation` links | `PacketTunnelView` | one link at the end |
| `Taiwan Flag Available` + `Section("Debug")` | `ToolsView` | removed from the UI; the check remains in code |
| `Section("Tailscale") { "Ghostty Configuration" }` | `MacAppView` | `Section("Terminal") { "Terminal Appearance" }` |
| `"You can customize the terminal appearance by editing the Ghostty Configuration in App Settings."` | `TailscaleSSHPromptView` | points at More → Client Settings → Terminal Appearance |
| `Label("Overview")`, section caption `"Dashboard"` | `MacLibrary/SidebarView` | unified sidebar, localized (this is in the Mac work, out of scope) |
| `navigationTitle("App")` | `MacAppView` | "Client Settings" |
| `"Dashboard Items"` | dashboard card sheet (4 sites) | "Home Cards" |
| `NavigationPage.title` `.dashboard` → "Dashboard", `.settings` → "Settings" | all platforms | → "Home" and "More", matching the tab bar |
| `Variant.screenshotDisconnectedTunnel` | new | `SCREENSHOT_STATE=disconnected` fixture, for snapshots |

Localization: 108 new keys with `zh-Hans` and `zh-Hant`, covering every string this round
introduced and the tab/section/page names that were English under a Chinese locale. The
catalogue's `fa` and `ru` slots are untouched (no translations invented for them).

---

## 4. Environment: how to build, run and test

`xcode-select -p` answers `/Library/Developer/CommandLineTools` on this machine, so
**every** Xcode command needs `DEVELOPER_DIR`:

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
cd /Users/jie/Desktop/其他文件/JiejieBox-0.1.2-release/clients/apple
```

Xcode 27.0 (27A266a). Only iOS 27.0 runtime. `iPhone 18 Pro Max`
(`D5F2B38E-F921-47A6-AF80-89843EAB0A7F`) exists and boots. `fastlane` is not installed.

### macOS: compiles, cannot be run

```bash
DISABLE_SWIFTLINT=1 xcodebuild -project sing-box.xcodeproj -scheme SFM -configuration Debug \
  -destination 'generic/platform=macOS' -derivedDataPath /tmp/dd-mac \
  -skipPackagePluginValidation -skipMacroValidation CODE_SIGNING_ALLOWED=NO build      # ✅ passes
```

Launching `/tmp/dd-mac/Build/Products/Debug/sing-box.app` dies at
`Library/Database.swift:72` (`SQLite error 23: authorization denied`): the App Group
container `~/Library/Group Containers/group.io.nekohasekai.sfamt` is not readable or
writable by this user or by the shell (`ls` and `touch` both return "Operation not
permitted", even for a directory owned by `jie`), because macOS binds group-container
ownership to the signing identity and its provisioning profile. Both candidate
identifiers behave the same. **The macOS UI cannot be verified on this machine**, which is
the strongest reason macOS should not be in scope.

### iOS device: compiles

```bash
DISABLE_SWIFTLINT=1 xcodebuild -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'generic/platform=iOS' -derivedDataPath /tmp/dd-ios-dev \
  -skipPackagePluginValidation -skipMacroValidation CODE_SIGNING_ALLOWED=NO build      # ✅ passes
```

`build-for-testing` with the same flags compiles the UI-test bundles ✅.

### iOS simulator: needs a simulator Libbox slice, then it works

The checked-in `Libbox.xcframework` has **no simulator slice** (`ios-arm64` and
`macos-arm64_x86_64` only), so a plain simulator build fails with
`no library for this platform was found`. A simulator framework was built on this machine
with the parent's own tooling and merged into `clients/apple/Libbox.xcframework`, which is
untracked so nothing was committed:

```bash
cd /Users/jie/Desktop/其他文件/JiejieBox-0.1.2-release
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export PATH="$(go env GOPATH)/bin:$PATH"
gomobile init                      # first time only
GOPROXY="file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct" \
  go run ./cmd/internal/build_libbox -target apple -platform iossimulator
# then copy Libbox.xcframework/ios-arm64_x86_64-simulator into
#   clients/apple/Libbox.xcframework/ and add its AvailableLibraries entry to that
#   xcframework's Info.plist (plutil -convert json|xml1 round-trip; it is XML, not JSON)
```

`gomobile`/`gobind` v0.1.13 were installed into `~/go/bin` and the module cache by this
round. The parent's `scripts/ci/build-apple-libbox.sh` deliberately builds only
`ios,macos` — its comment says the pinned cronet ships no `ios_amd64_simulator` library —
but `iossimulator` built successfully here, so that comment is at least stale.

### The app must be signed for the simulator, or it crashes at launch

`CODE_SIGNING_ALLOWED=NO` strips entitlements, so `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`
returns nil and the app dies immediately at `Library/FilePath.swift:10`. Build with ad-hoc
signing and the identifiers the entitlements reference:

```bash
DISABLE_SWIFTLINT=1 xcodebuild build -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro Max,OS=27.0' \
  -derivedDataPath /tmp/dd-ios-signed \
  -skipPackagePluginValidation -skipMacroValidation \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=YES \
  APP_GROUP_IDENTIFIER=group.io.nekohasekai.sfamt BASE_PACKAGE_IDENTIFIER=io.nekohasekai.sfamt

xcrun simctl install booted /tmp/dd-ios-signed/Build/Products/Debug-iphonesimulator/sing-box.app
xcrun simctl launch booted io.nekohasekai.sfamt -FASTLANE_SNAPSHOT YES
xcrun simctl io booted screenshot /tmp/shot.png
```

This works and was used to confirm Home renders in Chinese with one bottom bar, single
chevrons and the new session card.

### Running the UI tests

```bash
DISABLE_SWIFTLINT=1 xcodebuild test -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS Simulator,id=D5F2B38E-F921-47A6-AF80-89843EAB0A7F' \
  -derivedDataPath /tmp/dd-ios-signed \
  -only-testing:SFIUITests/HakoNavigationUITests \
  -parallel-testing-enabled NO \
  -skipPackagePluginValidation -skipMacroValidation \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=YES \
  APP_GROUP_IDENTIFIER=group.io.nekohasekai.sfamt BASE_PACKAGE_IDENTIFIER=io.nekohasekai.sfamt
```

Two things that will otherwise waste an hour each:

- **`-parallel-testing-enabled NO`.** The scheme marks the suite `parallelizable="YES"`,
  so Xcode clones the destination; on this host cloning failed with *"Device was allocated
  but was stuck in creation state"* after a previous run. Serial is slower but reliable.
- **Expect a ~600 s stall after the tests finish**, in
  `IDETestOperationsObserverDebug: Failure collecting diagnostics from simulator`. The
  results are already written by then; do not read the stall as a hang. `grep` the output
  for `Test Case` rather than waiting for the process to be interesting.

Snapshots:

```bash
mkdir -p /tmp/sfi-shots
# add TEST_RUNNER_SCREENSHOTS_DIR=/tmp/sfi-shots to the command above and run
# -only-testing:SFIUITests/HakoSnapshotUITests
```

---

## 5. Test status at handoff — the iOS navigation suite is green

**`SFIUITests/HakoNavigationUITests`: 16 tests, 0 failures**, on `iPhone 18 Pro Max` /
iOS 27.0, run serially with ad-hoc signing and the app-group identifiers. Command in §4.
This is the first time the suite has ever passed; it had never been executed.

```text
testRootTabOrderIsStable                                  the shell has three roots, Home first
testRootTabIsReachableOnEveryRoot                          the bar is on Home, Tools and More
testPushingADetailHidesTheRootTabAndPoppingRestoresIt      hidden in detail, restored on pop
testEveryMoreDestinationOpens                              all five More pages push, tab hidden,
                                                           a way back exists, popping returns
testHomeToLogsPushesAndBackReturnsToTools
testDeepLinkToLogsBeforeToolsWasEverShown
testSelectingAChildTwicePushesOnce
testTappingTheCurrentTabPushesNothing
testAPoppedPageDoesNotComeBack
testRapidTabSwitchingEndsOnTheLastTab
testColdLaunchLandsOnHomeWithoutAChild
testGroupsAndConnectionsSheetsOpenAndClose
testActivityWorkspaceOffersSearch
testProxyWorkspaceSearches
testNavigableRowsDrawExactlyOneIndicator                   icon well + exactly one chevron
testTunnelPageShowsUserTitlesAndNoRawPropertyNames         the row's label names the option in
                                                           the user's terms and contains no
                                                           NetworkExtension property name
```

### Three real defects the first execution found

1. **The root tab bar leaked into every pushed page except the shell's own child.** Any
   `NavigationLink` push — every settings page, every report — kept the bar. Fixed by moving
   the rule into the shared chrome.
2. **The tab bar's accessibility identifiers never reached the tab items**, so the tests
   could not find a tab and had been written against an assumption nothing had tested.
3. **A `NavigationLink` inside a `Form` double-chevrons on iOS**, not only on the desktop;
   `>>` was on every legacy settings page. Fixed at the container.

### Eight wrong assumptions in the tests themselves

Worth reading before adding more, because each one cost a run or two:

- Launched without the deterministic fixture, so there were no profiles and none of the
  pages existed. Now `-FASTLANE_SNAPSHOT YES` plus a pinned language — a label assertion
  against a simulator whose locale happens to be Chinese measures the locale.
- `app.navigationBars.buttons.element(boundBy: 0)` is any button, and Home has a trailing
  menu, so it reported a pushed child on a cold launch. Now the shared controls'
  identifiers, and **every** "has it appeared" assertion waits: a push animates, and the
  loop over the More destinations failed on `app` in one run and `core` in the next, which
  is a race rather than a missing control.
- `app.sheets.firstMatch` never exists on this release, so the sheet test could only fail.
  It asserts the workspace's search field instead.
- Searching the proxy list for `Auto` legitimately keeps the first fixture group, which
  contains a member called `auto`. The test uses `Tokyo` and then checks that clearing the
  search restores every group — which is also the assertion that the filter never mutated
  the data.
- A `HakoToggleRow` is one combined accessibility element, so its title is its *label*, not
  a `staticText`.
- The bottom search field's clear control is its sibling, not its descendant.
- A row's image count is 2 (icon well + one indicator), not ≤ 1; `>>` would make 3.
- A tab cannot be switched from a detail page any more, because the bar is hidden there by
  design. `testLeavingToolsAndReturningKeepsLogs` asserted the old behaviour and is now
  `testAPoppedPageDoesNotComeBack`.

### Still never executed

`SFIUITests/HakoSnapshotUITests` compiles and its navigation paths are the ones the passing
suite uses, but it has **not been run**. Run it and look at the PNGs:

```bash
mkdir -p /tmp/sfi-shots
# add TEST_RUNNER_SCREENSHOTS_DIR=/tmp/sfi-shots and
#   -only-testing:SFIUITests/HakoSnapshotUITests
```

Expect the same ~600 s diagnostic stall after the tests finish (§4). Two of its cases are
weak and should be rewritten: `test30ReportInboxEmpty` does not actually open a report
inbox, and `test50AddConfiguration` looks for an `"Add"` button that may not be the profile
card's `+`.

### One manual run worth keeping

The simulator run that confirmed the client renders at all:

```bash
xcrun simctl launch booted io.nekohasekai.sfamt -FASTLANE_SNAPSHOT YES
xcrun simctl io booted screenshot /tmp/home.png
```

Home came back in Chinese: 首页 title, the session card with 已启动 and a runtime, 配置, 模式,
and the shortcuts 代理 / 连接 / 日志 each with a single chevron — and exactly one bottom bar,
the tab bar. That single screenshot is the evidence for four of the round's P0 items
(root tab is the only global bottom layer, no double chevron, Chinese locale, Home's new
order). The other pages still have no picture.

## 6. Known gaps, in the order I would attack them

1. **Decide macOS's fate.** Either freeze it (the `#if os(iOS)` split in §2) or accept it
   as unverified. As committed it carries visible changes nobody has seen.
2. **Run `HakoSnapshotUITests` and look at the images** (§5). It has never been executed,
   and two of its cases are weak as written.
3. **`OverviewView` on iOS is now dead code** (only tvOS uses it). Either delete it or
   confirm the intent.
4. **Magic radii outside the theme** remain, mostly in editor and terminal chrome that this
   round did not touch: `Abstract/ViewModifiers.swift` (8/12), `ProfileSelectorButton` (12),
   `CardManagementSheet`/`ProfilePickerSheet` (16), `EditorToolbarView` (8/12),
   `TerminalSessionContentView` (10/12). Each is a control rather than a card, so the
   right token is probably `HakoTheme.Radius.control`, but nothing is verified.
5. **`UITests/` is an orphan target** — three Swift files, including the only
   `XCTAttachment` screenshot test in the repo, in a synchronized group attached to no
   target. They never compile. Adopt or delete.
6. **No committed snapshot baselines.** `snapshot()` writes PNGs; there is no
   reference-image comparison anywhere, so "snapshots pass" currently means "the capture
   did not throw".
7. **iOS 15 is still a deployment target** and is untestable here. The tab bar cannot be
   hidden on it (documented in the code). Consider raising the floor to iOS 16.
8. **`scripts/ci/prepare-apple-client.sh`** asserts the submodule HEAD equals the parent's
   gitlink and applies build-time overlays. Now that the client builds standalone, the
   overlay's "already applied" guard recognises a complete client; the parent's
   `test-apple-signing.sh` was already reported as 2 failures for that reason before this
   round.
9. **tvOS** is untouched and now shares less with iOS than before (the shared pages present
   their iOS implementation on tvOS in several places, since I gated only where a page
   needed it). Nothing on tvOS has been built or run this round. `SFT` compiles? Not
   verified — do not assume.

---

## 7. Things that are load-bearing and easy to break

- **`HakoPlatformLayout.containerDrawsDisclosureIndicator`** and the
  `\.hakoContainerDrawsDisclosure` environment value. `FormView` sets it true; the painted
  scaffolds set it false. A new container that does not declare itself will double-chevron
  on iOS.
- **`HakoPrimaryShell` has no accessory slot on purpose.** Re-adding one re-creates the two
  stacked global bars the manual's P0 forbids.
- **`HakoNavigationChrome` owns three things at once** — the title treatment, the leading
  control and the tab-bar rule. A page that hides the system back button without wearing it
  will have no way back.
- **`ScreenshotLocalization.applyIfNeeded()` is never called by the iOS app**
  (`SFM/Application.swift` and `SFT/Application.swift` call it). iOS localization in the
  snapshots relies on `-AppleLanguages` from the helper. That is pre-existing.
- The localizable catalogue is **sorted alphabetically** with a trailing newline; the
  additions were written that way to keep diffs reviewable.
