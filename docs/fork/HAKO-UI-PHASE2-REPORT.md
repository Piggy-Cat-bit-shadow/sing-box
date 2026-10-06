# Hako UI Migration Phase 2 — iOS report

Scope of this round, per the owner's instruction: **iOS only**. The macOS client was
explicitly taken out of scope ("停止开发 mac 的客户端"), so nothing here was verified on
macOS and the Mac cross-comparison section of the brief was deliberately not executed.

---

## 0. Verdict

**NOT READY.**

The design system now traces to the reference source rather than to a description of it,
the reference app builds and runs on this simulator, and **both** iOS suites pass — the
navigation suite 16/16 and the snapshot suite 13/13, 29 tests in all, with 12 screens
captured. Two of the defects fixed in the latest round were found only by running the
snapshot suite, one of which had made an entire page invisible while its accessibility
tree looked correct.

Still open: the config centre, the report read views, the Activity lens structure, Dynamic
Type, the dark-mode pass, the parent gitlink, and the macOS client (out of scope by
instruction). §6 lists exactly what is open.

---

## 1. Reference cross-comparison

### 1.1 Reference and environment

| item | value |
| --- | --- |
| repository | `https://github.com/TokenPLS/Hako-Client` |
| canonical commit | `62aa2f2fedffd46c245d5a87d2258c24bef3cd82` |
| reference workspace | `~/Hako-UI-Reference/Hako-Client` (read-only in intent; see 1.5) |
| kernel / adapter | `TokenPLS/Hako@7ea70d15`, `TokenPLS/Hako-Adapter@6a47cf91` (public, pinned by `Dependencies.lock.json`) |
| UI package | `apple/HakoClientUI` — **present in the repo**, 150 Swift files |
| reference iOS app in the simulator | **yes** — built, installed as `com.hakoref.hako` (display name "Clash"), launched, navigated, screenshotted |
| reference macOS app | **not built** — macOS is out of scope this round |
| reference tvOS app | not built |
| our app, same simulator | `io.nekohasekai.sfamt`, installed and launched alongside |

The earlier rounds' audit could not find `HakoClientUI` because it reads the repository
through the GitHub API, where the full tree response is truncated before the alphabetically
later paths. A `git clone` has it. Every token and component claim in this report was
re-read from that source, and the values already in `HakoTheme.swift` were confirmed
identical rather than re-derived.

### 1.2 How the reference was made to run

```bash
# Go 1.26.6 is pinned by the kernel's bind module and must exist as a real toolchain.
go install golang.org/dl/go1.26.6@latest && go1.26.6 download

cd ~/Hako-UI-Reference/Hako-Client
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export PATH="$(go env GOPATH)/bin:$PATH"
python3 scripts/bootstrap.py                 # builds Hako.xcframework, all five slices
python3 scripts/configure.py --bundle-base com.hakoref.hako
xcodebuild build -project apple/HakoClient/HakoClient.xcodeproj -scheme HakoClient \
  -configuration Debug -destination 'platform=iOS Simulator,id=D5F2B38E-…' \
  -derivedDataPath /tmp/dd-hakoref CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=YES
xcrun simctl install booted /tmp/dd-hakoref/Build/Products/Debug-iphonesimulator/HakoClient.app
```

No signing certificate was needed. `bootstrap.py` verifies the SDK's provenance against the
pinned revision before it is used.

### 1.3 Navigating the reference without a test target

The reference has no UI-test target, so it was driven two ways:

- **Deep links.** It registers `clash`, `clashmeta`, `flclash` and `hako`, and
  `HakoSystemRoute` accepts `hako://open/<home|utilities|more|proxies|profiles|logs|…>`.
  `xcrun simctl openurl` raises a one-time "Open in Clash?" confirmation if the app is not
  running; **if the app is already in the foreground the route is delivered with no
  prompt**, which makes the capture script deterministic:

  ```bash
  xcrun simctl launch booted com.hakoref.hako; sleep 6
  xcrun simctl openurl booted "hako://open/utilities"; sleep 5
  xcrun simctl io booted screenshot ~/hako-ui-compare/reference/utilities.png
  ```

- **The Xcode MCP device-interaction tools** for the two pages no deep link reaches
  (More → On Demand, More → Tunnel), which a skill-loaded subagent drove by tap.

Capture harness: `~/hako-ui-compare/shoot.sh`; images in `~/hako-ui-compare/reference/`
and `~/hako-ui-compare/ours/`.

### 1.4 Screens actually compared

Reference images: `home`, `utilities`, `more`, `proxies`, `profiles`, `logs`,
`04-ondemand`, `05-tunnel`. Ours: `dashboard`, `tools`, `settings`, `logs`, plus the
simulator captures taken while fixing the row tint.

| Reference screen | Our screen | Shared design pattern | Deviation found | Status |
| --- | --- | --- | --- | --- |
| Home (compact root) | Home (`dashboard`) | painted sections on a `ScrollView`; card radius 26; 20pt page inset; no large title | ours had a system **large** title and forced dark; reference shows an inline/absent heading | title fixed (`hakoInlineNavigationTitle`); light-appearance fixture added for comparison |
| Utilities | Tools | caption (gray, not uppercase) + painted card; icon well + title + subtitle + single chevron; inset dividers; 62.7pt row floor | ours had footnotes the reference does not; row titles were **accent blue**; section 3 named "Diagnostics"; "STUN Test" | footnotes removed; tint fixed; renamed "Runtime & Reports" and "STUN & NAT" |
| More | More (`settings`) | same, with a subtitle on every row | group vocabulary was ours, not the reference's | renamed to Connection Behaviour / App Settings / Core Settings |
| Proxies (sheet) | Proxies (`GroupListView`) | `[✕] … [action capsule]`; group card with title, strategy · selected, count + fold; member rows with a leading selection mark and a trailing test glyph; **pinned bottom search capsule** | ours had a left-aligned custom strip, an ungrouped action row, and no sheet search after the first pass removed it | actions grouped in a `ControlGroup`; sheet search restored as a drawn capsule |
| Activity | Connections / Logs | searchable live list; lens strip pinned to the top | — (see 1.6) | `hakoPinnedTopBar` adopted for the strip; system search adopted |
| On Demand | On Demand | system grouped `Form`: white inset cards, system toggles, gray section captions, `编辑` + `+` in the bar | ours painted its own cards inside the system's | settings scaffolds are now `Form`-based (see 2.2) |
| Tunnel | Tunnel | same | ours showed raw NetworkExtension property names | already fixed in the previous round; re-verified by UI test |
| Profiles | (profile picker sheet) | sheet + close control + list | not migrated | open |
| Logs | Logs | plain reading surface, no chrome of its own beyond the back control | ours had no shared chrome at all | shared chrome adopted |

### 1.5 Reference repository modifications

`python3 scripts/configure.py --bundle-base com.hakoref.hako` rewrites the bundle-identifier
family and regenerates the Xcode project. `git status` in the reference workspace therefore
shows exactly three modified tracked files:

```text
 M apple/HakoClient/Shared/HakoAppIdentifiers.swift
 M apple/HakoClient/project.yml
 M apple/HakoClientKit/Sources/HakoClientKit/HakoClientKitIdentifiers.swift
```

No source, component, token, string or asset was changed to accommodate our app, and the
build products (`.build/`, `Hako.xcframework`) are untracked. `git checkout .` in that
workspace restores it.

### 1.6 Where we deliberately differ from the reference

| area | reference | ours | why |
| --- | --- | --- | --- |
| Root tab bar on a pushed page | **stays visible** (On Demand and Tunnel both show it; the only `.toolbar(.hidden, for: .tabBar)` in the whole package is on Activity's bottom-search branch) | **hidden** | The manual states this as a P0 three times (§11, §16) and puts it in the completion gate (§92: "Root tab 仅 root 可见"). It is the one place where the owner's specification and the reference disagree, and the specification wins. Cost recorded: with the bar hidden, a tab can no longer be switched from a detail page, so the previous round's "open Logs, visit Home, come back to Logs" scenario is unreachable through the UI; the test that asserted it is now `testAPoppedPageDoesNotComeBack`. |
| Back and close controls | plain system controls; no drawn circle. On iOS 26 the **system** back button renders as a circular glass disc, which is what the manual's `[圆形返回]` diagram describes | plain system controls with our identifiers (the drawn disc was removed) | A drawn disc had to re-earn the hit target, Dynamic Type scaling, focus and the interactive swipe-back gesture. The manual's diagram is satisfied by the system's own control on the current system. |
| Activity lenses | three lenses: connections, requests, logs | two pages, no requests lens | This core records no requests. A lens with nothing behind it is a fake page, which §20 forbids. |
| Diagnostics | "Diagnostics Inbox" is one destination that opens a report list | the three report types are rows in the Runtime & Reports section | We have no single inbox page; the three managers are separate. Creating an inbox page is a product change, not a UI one. |
| Runtime / Providers | "Core Runtime" and "Providers" destinations | absent | No such pages exist in this client, and inventing them would be fabricating pages. Our Core page (version, data size, working directory) sits in More instead. |

### 1.7 Defects the reference comparison found that the brief had not named

1. **Every `NavigationLink` row title rendered in accent blue.** Measured rather than
   judged: the title pixels were `(0, 136, 255)` on ours and `(0, 0, 0)` on the reference.
   The cause is that a `NavigationLink`'s default button style tints its whole label, and
   the row's own `.foregroundStyle(.primary)` is applied *below* it. The reference passes an
   explicit `HakoPushRowButtonStyle` to every push row; `FormNavigationLink` now does too.
   This was invisible to source reading — both implementations look correct.
2. **Our settings pages painted a card inside the system's card.** `HakoMacSettingsFormContainer`
   is one `Form` on both platforms, differing only by `.formStyle(.grouped)`, and its
   sections are real `Section`s. Ours used a single painted-card section component for root
   pages and settings pages alike.
3. **The reference's root pages have no system large title.** They draw their own heading or
   none; the tab bar names the page.
4. **`Layout.resolvedDestinationRowIconSize`** — 26 on the desktop, 29 on touch, resolved
   once. We used 29 everywhere, so a divider inset on the desktop disagreed with the icon
   well beside it.
5. **`HakoEmptyState` has no tinted icon well and no accent colour** — a bare `.largeTitle`
   symbol in secondary with 40pt vertical padding. Ours was a 41pt tinted rounded square,
   which reads as a notification rather than as an absence.
6. **A sheet's workspace search is a drawn capsule**, while a pushed page's is the system
   field. Both exist in the reference; we had assumed one mechanism for both.
7. **`HakoSheetCloseButton` is a plain icon-only `xmark`** in `.cancellationAction` with
   identifier `sheet.close`, not a drawn disc.

### 1.7a Defects the first snapshot run found (second pass)

8. **An empty pinned top bar took the whole page.** `HakoWorkspaceScaffold` pinned a strip
   to the top of every workspace with `safeAreaBar(edge: .top)`. The proxy sheet has no
   strip, so it pinned an `EmptyView` — and the bar still took its slot, leaving the scroll
   view below it with no height. The sheet rendered its chrome, its search field, its action
   capsule and nothing else: no summary, no group cards, not even the empty state.
   **The accessibility tree still contained the rows**, which is why the navigation suite
   passed while the page was blank: `testProxyWorkspaceSearches` asserts that a group
   *exists*, not that it is on screen. That is a real limit of an accessibility assertion,
   and the reason the snapshot pass exists beside it. Pinning is now a property of the
   initializer.
9. **The Activity workspace used the system search field in a sheet**, where there is no
   bottom bar for it to live in. It draws the same capsule the proxy sheet does, which is
   also what the reference's proxy sheet does; `.system` remains for a page pushed inside a
   tab.
10. **The profile card's add control had no accessibility label and no identifier** — an
    icon-only button VoiceOver could not name (§70/§71), and the reason the snapshot harness
    could not reach the add-configuration sheet. Now labelled, identified, and its target is
    at least 44pt.
11. **The fixture passed capitalized proxy type strings**, which the core's display-type
    mapping does not recognise, so every member of every snapshot read "Unknown" — a fixture
    that made the pages it exists to photograph look wrong.
12. **Tapping a mode row did not move the selection.** Found by making the mode selection an
    assertion rather than an impression. The legacy card this client used held the choice in
    `@State` and sent it to the core afterwards; the replacement read the core's *published*
    mode. With the tunnel stopped the core cannot report a mode back, so the row never moved:
    the page looked broken and the tap looked ignored. The choice is held locally first and
    reconciled with the core's published value, which is what the card did.
13. **No modal in the client had a close control.** `NavigationSheet` is the container all
    eight modals are built on, and on iOS it was a `NavigationStack` with a title: a sheet
    could only be dismissed by dragging it down. The manual's modal chrome is a close on the
    leading side, a centred title and the page's own actions on the trailing side; the
    reference uses an icon-only `xmark` in that slot. The control now lives in the container
    so it cannot be forgotten, and all eight modals gain it at once.
14. **The configuration centre's add control lived on a different screen.** Adding a
    configuration was only reachable from the Home profile card, so a user already looking at
    their configurations had to close the centre to add one. Add, update-all and edit are one
    action capsule in the centre now.
15. **A remote configuration being fetched reported nothing.** The row disabled itself and
    hid its menu, so a slow download looked like a row that had stopped responding. The row
    now carries a progress indicator - the manual's configuration card carries progress and
    expiry, and that was the progress half. Update-all is new as well.
16. **An unreadable configuration was reported in a blocking alert.** The reference reports
    it where it stands — its Home shows the page name, a prominent retry button and the reason
    in the warning colour above the first card — and the cards still draw. Ours raised an
    alert that hid them, for a condition the user had not caused. The distinction is now
    explicit and is the reference's: a condition the client *found* is reported in place; a
    failure the user *caused* by an action still alerts.
17. **The proxy workspace did not survive accessibility text sizes.** None of it had been
    looked at at `accessibility-extra-extra-extra-large`, and three layouts failed there: the
    summary card's figures stayed in three columns and broke the word "Groups" in half around
    its own cell; a per-member test control took a third of the row's width, so the member the
    row exists to name rendered as `se...er2`; and the group header's `SELECTOR · SERVER`
    middle-truncated into `SEL...VER`, which is neither word. All three are a layout that works
    at four columns of body text and not at three columns of display text.
18. **The report list's footnote contradicted the list.** "You will receive a report when a
    crash occurs." is the empty page's explanation, and it was drawn under a list that had a
    report in it — saying the opposite of what the reader could see. It is now the empty
    state's alone.
19. **A test failed under load and passed alone.** A full run of 35 cases on a loaded machine
    failed to reach the More page's On Demand row within 15 seconds — a row the navigation
    suite had reached moments earlier in the same run. The case passed on its own immediately
    after. The cause was in the tests, not the app: the snapshot suite waited 15 seconds where
    the navigation suite waits 30 for the identical operation. A test that fails under load is
    a defect in the test.
20. **Two report archives could not be written to.** The crash archive had a public writer and
    its out-of-memory and power siblings had only a directory and a scan, so nothing but the
    app's own watchdog could put a report in them — which is why their pages had never been
    seen and why the archive layout was written out three times, twice of them read-only.
    `ReportArchive.writeArtifact` owns the layout now and all three archives use it.
21. **A read view listed two of its own files by filename.** The power report showed
    `timeline.jsonl` and `events.jsonl` while every other row used a name a person can read.
    That is the "no raw internal keys" gate item, inside a read view rather than a settings
    row, and it is the kind of thing only looking finds.
22. **Two pages never wore the shared navigation chrome.** `NetworkQualityView` and
    `STUNTestView` used `.navigationTitle` where every sibling uses `hakoNavigationChrome` - and
    that modifier is what hides the root tab bar on a pushed page, so **the tab bar stayed
    visible on two detail pages**. That is the manual's P0 rule, and the one place the report
    argues against the reference, so it was being broken on the two pages no test walked. The
    STUN page also still called itself "STUN Test" while the row that opens it says "STUN & NAT".
    Both had no accessibility identifier, which is why nothing had ever walked them.
23. **Three names for one flow, and a page that named itself.** The configuration flow's sheet
    said "Add Configuration", its tile said "Create Manually", and the page it opened said
    "New Profile" — with "Profile" being the vocabulary this migration replaced everywhere else.
    The page stops naming itself now: its presenters do. It also had never worn the shared
    chrome, so it carried the platform's back control, which no audit could address — the same
    gap the network-quality and STUN pages had.
24. **A labelled form field could not stack.** `FormItem` was a function returning an `HStack`
    with the title at `lineLimit(1)`, because it shares that line with the control. At the
    accessibility sizes the editor's "Name" sat beside its own "Required" placeholder with no room
    between them, and a longer label — "File Path", "Profile Name" — had nowhere to go but
    truncation. `FormPicker` was already stacking its value under its label, so the same kind of
    row was laid out two different ways. It is a view now, so it can read the text size, and every
    `FormItem` in the client stacks at once because it is the shared component.
25. **A stray disclosure indicator from a false equivalence.** The add-configuration modal drew
    a chevron at the trailing edge of its three action tiles. It was not the tile's: the hidden
    `NavigationLink` that pushes the manual editor was attached to `HakoModalScaffold`'s
    *content*, and that scaffold wraps its content in a `Form` - so the link was a row, and the
    platform gives a row that navigates a disclosure indicator. Two attempts failed by treating
    "inside the modal" and "outside the form" as the same thing. Attached to the scaffold's own
    result, it is outside the form and the indicator is gone.
26. **The remote-connection alert showed the Go RPC stack to the reader.** Failing to reach a
    remote server raised an alert whose message was a human sentence with the transport's own
    account appended — `rpc error: code = Unavailable desc = "error reading server prefix: read
    tcp 172.19.0.1:63956->192.168.1.20:9090: read: connection reset by peer"`. The sentence stays;
    the rest is the RPC stack talking to itself and goes to the log. This is the "no raw internal
    keys" gate item reached through an error message rather than a settings row, and it is the
    third time a raw internal string has been found in user-facing text.
27. **The Activity workspace never observed the object that owns its state.** `ConnectionDataModel`
    owns `isLoading` and the connection list, and the workspace read both *through* the view model
    — which the view does observe — so the model's changes invalidated nothing. The page rendered
    its initial state and kept it: with the tunnel stopped it showed a spinner forever and the
    empty state below it was unreachable, and a live connection list would not have appeared
    either. This is the defect that took three attempts, and the first two were guesses; only
    instrumenting the path showed that the flag *was* being cleared while the view went on
    rendering it.
28. **One number, stated two ways.** Home's proxy row said "Proxy groups" — its zero fallback —
    while the proxy sheet said two. The groups were fabricated inside `GroupListViewModel` in
    screenshot mode while the client every other page reads had none, so the two pages were
    reading different fixtures rather than one being stale. The fixture lives in the client now,
    and `test17HomeAgreesWithTheProxySheet` asserts the agreement rather than either page — a
    single-page assertion cannot see this class, because both pages were individually correct
    about their own data.
29. **Forty-eight user-visible strings were never catalogued.** Reported from screenshots: the
    Core page's footnotes read English in a Chinese interface. They were passed as
    `LocalizedStringKey` literals, so they *would* have localised - they were simply absent from
    the catalogue and SwiftUI falls back to the key. Sweeping every prose literal against the
    catalogue found 48: footnotes, empty-state titles and messages, report errors, OpenConnect
    errors, profile-update messages. The same sweep found six orphaned Apple-documentation
    paragraphs, removed with the property-name keys beside them.
30. **The On Demand page said one sentence twice.** Its section footnote was the *selected mode's
    own description*, which is already the subtitle of the selected row - so the footnote repeated
    it and cost a line of height under a card whose rows each explain themselves. That section has
    no footnote now. This came out of the same screenshots and is the one genuine spacing defect
    in them: a duplication rather than a measurement.
31. **An activity row's route lost the rule that chose it.** The manual's §44 names four ways a
    dense data row must not fail, and this was one of them, found by seeding its nine cases. A
    route is one string composed in reading order — the outbound chain, then the rule, then the
    inbound — and it was middle-truncated on one line, so a long chain pushed the rule into the
    middle and the middle is what a middle truncation drops: `proxy-b / proxy-a...IP,CN` names
    neither the rule nor which part was lost. It truncates at the end over two lines now.
30. **The icon well's glyph overflowed its tile at accessibility text sizes.** The tile is a
    fixed 29pt (26 on the desktop) while the glyph inherited the row's Dynamic Type body
    font, which at `accessibility-extra-extra-extra-large` is larger than the tile: the
    network-tool, proxy and report rows had their own labels half-covered by their icons.
    A fixed-size mark cannot scale with the text around it. `HakoIconWell` now derives the
    glyph from the tile and clamps Dynamic Type for a caller-supplied one.

### 1.7b The presentation table (manual §47)

The manual asks for a table of every destination's presentation class, because the failure it
is guarding against is a set of same-level features that each happen to present differently -
one pushed, one a sheet, one replacing the root, with no rule. This client's rule is
centralised rather than per page:

- **A page is a `NavigationPage`.** `HakoPrimaryRoute` splits it into the primary that owns it
  and whether it is that primary's **root** or a **child pushed on top of it**
  (`isHakoPrimaryRoot`). Nothing else decides push-versus-root.
- **The tab bar is visible only on a primary root**, because the rule lives in
  `HakoNavigationChrome`, which every detail page wears.
- **A sheet is a sheet on iOS and macOS and a `fullScreenCover` on tvOS**, decided once in
  `ViewModifiers.swift` rather than at each call site.
- **Every modal carries a close control**, because it lives in `NavigationSheet`, the
  container all eight are built on.
- **A workspace presented as a sheet draws its own search field**; a page pushed inside a tab
  uses the system's, which has a bottom bar to live in.

| destination | root owner | class | tab visible | bottom search | top actions |
| --- | --- | --- | --- | --- | --- |
| Home | home primary **root** | tab root | yes | no | overflow menu |
| Tools | tools primary **root** | tab root | yes | no | — |
| More | more primary **root** | tab root | yes | no | — |
| Logs | tools **child** | pushed | no | no | clear |
| Proxies | Home, sheet | sheet (large) | no | drawn capsule | test-all, expand-all |
| Activity | Home, sheet | sheet (large) | no | drawn capsule | test-all, expand-all |
| On Demand | more primary | pushed by value | no | no | add |
| Tunnel · Profile Override · Core · Client Settings · Remote Control · Sponsors | more primary | pushed by value | no | no | — |
| Configuration centre | Home profile card | sheet (large) | no | no | update-all, add, edit |
| Add configuration | configuration centre | sheet (medium) | no | no | — |
| Edit profile · Card management · QR · QRS · share/export · SSH · Taildrop · auth URL | the page that needs them | sheet (medium) | no | no | — |
| Network Quality · STUN & NAT · report lists and details | tools | pushed | no | no | detail: share |
| *tvOS, everything above* | — | `fullScreenCover` | — | — | — |

Two things in this table were checked because they looked like the manual's exact failure, and
both turned out to be handled:

1. **Logs is reachable two ways** - a row on Home and a row in Tools - and Home's sets
   `selection = .logs`, which reads like the page replacing the root. It does not: `logs` is
   declared a **child of the Tools primary**, and `HakoPrimaryRoute(.logs)` resolves to
   `(primary: .tools, child: .logs)`, so both routes end in the same pushed page. The comment
   that made it look otherwise is a pre-shell one that `HakoPrimaryRoute` superseded.
2. **`HakoHomeActions` and the workspace sheet wrappers appeared to be dead code**, since
   nothing in `ApplicationLibrary` populates the environment value or constructs
   `GroupsSheetContent`. They are constructed in `SFI/MainView.swift`, which is where they
   belong: the root view owns presentation state, so the shell does not have to thread
   callbacks through every view between itself and the page that starts the navigation.

### 1.8 Evidence

- **Vision / screenshots**: `~/hako-ui-compare/reference/*.png` (8 screens) and
  `~/hako-ui-compare/ours/*.png`; the tint defect and its fix are evidenced by pixel
  sampling of the same row in both apps, quoted above.
- **Structure (source)**: `HakoTheme` token-by-token; `HakoProductPageSection` vs
  `HakoSection`; `HakoPresentationPolicy` (compactTouch → bottomTabs/compact,
  regularTouch|desktop → fixedSidebar/regular, television → focus); `HakoRootSidebarGroup`
  and `HakoRootDestination` (primary / session / configuration / hub / footer);
  `HakoUtilitiesCatalog` and `HakoMoreCatalog` section-by-section;
  `HakoActivityPageView.hakoWorkspaceSearch`; `HakoFullWidthSegmentedPicker.underlineTabs`;
  `HakoPushRowButtonStyle`; `HakoEmptyState`; `HakoSheetCloseButton`;
  `HakoRegularDetailLayout` (`chevron.backward`).
- **Interaction**: `xcrun simctl openurl hako://open/<dest>` on the running reference;
  MCP device taps for On Demand and Tunnel; `xcrun simctl` launches and screenshots for ours.

---

## 2. What the round changed

### 2.1 The design system, re-derived

`HakoTheme` gained `Layout.resolvedDestinationRowIconSize` and the font-role scale the
pages were each inventing; `HakoSurface` gained `selected`/`expanded`/`control` fills and
answers by surface role; `HakoRow` gained the manual's row vocabulary on one shared
`HakoRowBody`; `HakoData` is new (record-shaped rows); `HakoScaffold` is new (five shells,
the circular-control replacement, the action group, the pinned top bar, the system search
adapter).

Tokens that were already present were **confirmed identical** to
`HakoClientUI/Design/HakoTheme.swift`, not re-estimated: spacing 4/8/12/10/16/24; hit target
44; icon 29 (26 macOS); row target 62.7; radius control 8 / icon 9 / card 26 / groupedSection
26 / glass 24; card horizontal inset 20; sidebar 220; detail inset 56 and max width 1120.

### 2.2 The two section systems

The single most consequential correction. The reference has a painted section for root and
workspace pages (`HakoProductPageSection`, inside `HakoProductRootPage`'s `ScrollView`) and
a real `Section` for settings pages (`HakoSection`, inside a `Form`). Ours had one painted
component used everywhere, so every settings page drew a card inside the card the system was
already drawing.

- `HakoPageSection` — painted, used by Home, Tools, the More root, the workspaces.
- `HakoSettingsSection` — a real `Section`, used by On Demand, Tunnel, Core, Profile
  Override, Sponsors, the add-configuration modal and the report pages.
- `HakoScaffoldBody` is now a `Form` on both platforms, differing only by the macOS-only
  `.formStyle(.grouped)` — which is what the reference's `HakoMacSettingsFormContainer` does.
- `HakoSettingsDivider` was deleted rather than left as a no-op, and its calls in the
  form-based pages were removed.

### 2.3 The one global bottom bar (P0)

`HakoPrimaryShell`'s accessory slot is gone, not merely unused: it floated a runtime status
pill with its own start control above the tab bar, so the app had two stacked global bars.
Runtime state and the start control are Home's first card; remote state is a toolbar chip
that also owns disconnect.

### 2.4 Root tab visibility (P0)

A pushed page hides the tab bar. The rule lives in `HakoNavigationChrome`, which every
detail page wears, rather than in the shell alone — a page pushed by a `NavigationLink`
never went through the shell, so every settings page and report kept the bar. iOS 16+ only;
on iOS 15 there is no SwiftUI way to hide an enclosing `TabView`'s bar.

### 2.5 The double chevron

A `NavigationLink` inside a `Form` gets the platform's disclosure indicator **on iOS as well
as on the desktop**, and `HakoDestinationRow` drew its own on top, so affected rows rendered
`>>`. The rule is now "the container declares whether it draws indicators":
`FormView` and the form-based scaffolds declare that they do, the painted scaffolds declare
that they do not, and the value travels in `\.hakoContainerDrawsDisclosure`.

### 2.6 Information architecture

- **Home**: session + start/stop, profile, mode, shortcuts, traffic, runtime.
- **More**: Connection Behaviour / App Settings / Core Settings / Remote and Configuration /
  Support, a subtitle on every row, and About as its own section.
- **Tools**: Current Session / Network Tools / Runtime & Reports. The `Debug` section is
  gone — `Taiwan Flag Available` was a readout of whether the device's font renders a flag,
  which the client does need for its network-permission flow
  (`SFI/ApplicationDelegate.swift:130`) but which no user came to Tools to see.
- **Tunnel**: the titles were NetworkExtension property names; each row pasted the
  framework's documentation and its own `Apple Documentation` link, one of them reading
  "No documentation." The switches write the same preferences with the same polarity.
  Polarity was **not** inverted even though the manual's wording is positive: inverting
  would change what an existing user sees without changing what they get.
- **Home**: the outbound mode is a painted section of selection rows where the chosen row
  carries the reason the mode exists, as the reference presents it - not a segmented control.
  The legacy `DashboardCardView` that drew a second card inside this page's card, its
  hand-built tab bar, and the `GeometryReader`/`PreferenceKey`/menu machinery that existed to
  decide whether its labels fitted are all gone from this page. `ClashModeCard` itself
  remains for the remote dashboard and the focus platform's overview.
- **The activity rows under load**: the manual's §44 cases — a long domain, an IPv6 literal, a
  Chinese rule, an English rule, a long outbound chain, several badges, a large value, zero
  bytes, KB/MB/GB — seeded at the display layer, asserted on screen and captured. The route
  truncation defect above came out of it.
- **The report pages**: all three kinds - crash, out-of-memory and power - archived by the
  fixture through their archives' own writers, listed with their date, origin and unread badge,
  and read as a page that names the artifacts actually present on disk (Metadata, Crash Report,
  Go Crash Log, Configuration; Metadata, Configuration, Log; Metadata, Energy Timeline, Power
  Events, Log) with share and delete in one action capsule.
- **Home's failure state**: an unreadable configuration is reported by the page's own
  `HakoInlineNotice` - the page name, a prominent retry and the reason in the warning colour
  above the first card - with every other card still drawn and reachable. A condition the
  client found is not allowed to take the screen; a failure the user caused by an action
  still alerts.
- **The configuration centre**: the manual's modal chrome - close, centred title, and one
  action capsule holding update-all, add and edit - over a list of configurations whose cards
  carry their type, their last-updated time and a progress indicator while a remote one is
  fetched. Adding is reachable from the centre itself rather than only from the Home card.
- **Proxies / Activity**: workspaces with a pinned strip where there is one, a search field
  appropriate to how the page is presented, a summary card, test-all and expand-all, and a
  group header composed from the reference's card presentation: the group's name over one
  uppercase line of strategy and selection (`SELECTOR · SERVER`), the member count and the
  fold chevron together on the trailing side, and the group test as a control of its own —
  folding and testing are separate taps on purpose, so a group is not folded when the user
  meant to test it. A selected member is marked by a tinted surface and a 3pt bar down its
  leading edge (`HakoProxyMemberCard`), not by a checkmark that moves from column to column
  in a grid, and members carry their own testing state so a sweep over 137 nodes shows
  progress on the rows it is working through.

### 2.7 Legacy residue removed

| item | where |
| --- | --- |
| `includeAllNetworks`, `excludeAPNs`, `excludeCellularServices`, `excludeLocalNetworks`, `enforceRoutes`, `excludeDeviceCommunication` | Tunnel titles and footnotes |
| six repeated `Apple Documentation` links | Tunnel |
| `Section("Debug")` + `Taiwan Flag Available` | Tools |
| `Section("Tailscale") { "Ghostty Configuration" }` | now `Section("Terminal") { "Terminal Appearance" }` |
| "You can customize the terminal appearance by editing the Ghostty Configuration in App Settings." | points at More → Client Settings → Terminal Appearance |
| `navigationTitle("App")` | "Client Settings" |
| `"Dashboard Items"` (4 sites) | "Home Cards" |
| `.dashboard` → "Dashboard", `.settings` → "Settings" | "Home", "More" |
| unreferenced components | `HakoPrimaryPage`, `HakoSegmentedTabs`, `HakoRouteSummaryRow`, `HakoSettingsDivider`, `HakoActionCapsule`, `HakoCircularControlLabel` |

Localization: 112 keys with `zh-Hans` and `zh-Hant`. The catalogue's `fa` and `ru` slots are
untouched — no translations were invented for languages I cannot read.

---

## 3. Verification

### 3.1 Builds

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer     # or rely on xcode-select
cd /Users/jie/Desktop/其他文件/JiejieBox-0.1.2-release/clients/apple

# iOS device
DISABLE_SWIFTLINT=1 xcodebuild -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'generic/platform=iOS' -derivedDataPath /tmp/dd-ios-dev \
  -skipPackagePluginValidation -skipMacroValidation CODE_SIGNING_ALLOWED=NO build     # ✅

# iOS simulator (needs the simulator Libbox slice and entitlements; see §4)
DISABLE_SWIFTLINT=1 xcodebuild build -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS Simulator,name=iPhone 18 Pro Max,OS=27.0' \
  -derivedDataPath /tmp/dd-ios-signed -skipPackagePluginValidation -skipMacroValidation \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=YES \
  APP_GROUP_IDENTIFIER=group.io.nekohasekai.sfamt BASE_PACKAGE_IDENTIFIER=io.nekohasekai.sfamt build  # ✅
```

The app installs and launches; screenshots are in `~/hako-ui-compare/ours/`.

### 3.2 Behaviour — both suites, **29 tests, 0 failures**

```bash
xcodebuild test -project sing-box.xcodeproj -scheme SFI -configuration Debug \
  -destination 'platform=iOS Simulator,id=D5F2B38E-F921-47A6-AF80-89843EAB0A7F' \
  -derivedDataPath /tmp/dd-ios-signed -parallel-testing-enabled NO \
  -only-testing:SFIUITests/HakoNavigationUITests \
  -only-testing:SFIUITests/HakoSnapshotUITests \
  -skipPackagePluginValidation -skipMacroValidation \
  CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=YES \
  APP_GROUP_IDENTIFIER=group.io.nekohasekai.sfamt BASE_PACKAGE_IDENTIFIER=io.nekohasekai.sfamt
# Executed 29 tests, with 0 failures
```

`HakoNavigationUITests` — **16/16**. This suite had never been executed before this round;
its first run found three client defects and eight wrong assumptions in itself.

```text
root tab order and reachability · detail hides the tab and popping restores it ·
every More destination pushes with a way back and no root tab ·
the proxy sheet's drawn search filters and restores · the activity search field exists ·
one disclosure indicator per navigable row · the tunnel page's row labels carry no raw
property name · Logs push/pop, cold launch, deep link, double-push, current-tab, rapid switch
```

`HakoSnapshotUITests` — **17/17**, and it is the manual's §77/§78 coverage rather than a
marketing capture: Home, Home with an unreadable configuration, the outbound mode, Tools,
More, More scrolled to its end, Logs, On Demand, Tunnel, Core, Client Settings, the report
inbox's empty state, the configuration centre, Proxies collapsed, Proxies filtered, Activity,
the add-configuration sheet and the add flow reached from the centre itself.

It also carries a case that exists because a full run once failed on it: `test21OnDemand`
passed alone and failed in a 35-case run, which is what turned a 15-second wait into the
30 seconds the navigation suite already used.

It can also start the app in a named fixture state
(`SCREENSHOT_STATE=profileError`) and it archives a crash report through the archive's own
writer, which is how the failure path and the report pages are photographed at all: a page that
exists only when something has gone wrong is a page nobody has looked at. The archived report
carries a `.hako-fixture` marker and `scanCrashReports` skips a marked report outside a
screenshot run, so no developer's own simulator shows a crash that did not happen.

Two of its cases assert rather than photograph, because they are the two things the manual
names that a screenshot cannot establish: `test13MoreScrolledToBottom` asks whether the last
row of the longest root page is still `isHittable` after scrolling to the end - a floating bar
covering it leaves the row present in the tree and untappable, which an existence check cannot
see - and `test14OutboundModeSelection` selects a mode and asks the row to report itself
selected. It drives each page the way a user reaches it, so a page that
cannot be reached by tapping what the test taps fails here.

**Where the images land:** the fastlane default, `~/Library/Caches/tools.fastlane/screenshots/`,
as `<device>-<name>.png`. `TEST_RUNNER_SCREENSHOTS_DIR` did **not** reach the runner on this
setup; `SIMULATOR_HOST_HOME` is what the helper consults. Copy them out after a run.

### 3.2a Appearance and text size

The simulator's own controls are the way to vary these, and they reach the app without a
rebuild:

```bash
xcrun simctl ui booted appearance light                       # or dark
xcrun simctl ui booted content_size accessibility-extra-extra-extra-large
# ... capture ...
xcrun simctl ui booted content_size large                     # restore
```

Note that the fixture forces dark unless `SCREENSHOT_APPEARANCE=light` is set, so a light
capture needs both.

The settings pages were the last surface audited at accessibility sizes and they needed no
change: a toggle row keeps its toggle aligned to the title with the subtitle wrapping beneath
it, and a selection row keeps its mark on the trailing side. That is worth recording as a
result rather than as an absence - the three defects the workspace had were specific to a
multi-column layout, and this client's settings pages were already a single column.

### 3.2a The defect class this report found four times

Four defects share a shape that reading the source does not reveal: **a view that renders its
initial state and keeps it.** The proxy sheet rendered nothing at all (an empty pinned bar took
the scroll area); the Activity workspace rendered a spinner that had already been cleared (it did
not observe the object owning the flag); Home's counts never moved (same, through `environments`);
and two pages disagreed about one number (two fixtures). Each was found by looking at a rendered
page and asking why it did not match what the code said, and each was invisible to a per-page
assertion because the page was self-consistent.

The generalisation worth keeping: for every page, ask **what would make this change** - and then
check that the view observes it.

### 3.2b The fourth non-discriminating assertion

Four assertions in this migration have failed for the same reason, and it is worth naming
because it is a shape rather than an accident: **the assertion did not control its
precondition.**

| assertion | why it did not discriminate |
| --- | --- |
| a back control exists after tapping a report row | the report *list* is pushed too, so it wears one whether or not the tap navigated |
| a mode row reports itself selected after a tap | true of the state being left as well as the state being entered |
| the More page's last row `isHittable` | the row is below the fold, so it is false until something scrolls to it |
| `test21OnDemand` reaches a row in 15 seconds | the sibling suite waits 30 for the identical step; under load 15 is a coin toss |

Each was written as a check on the app and turned out to be a check on nothing. The pattern to
look for is an assertion whose expected value is also the expected value of doing nothing.

### 3.3 Runtime logs

```bash
xcrun simctl launch --console-pty booted io.nekohasekai.sfamt -FASTLANE_SNAPSHOT YES
```

Clean launch: `Here I stand`, `setup background task success`, `started profile server`,
`started report transfer server`, no faults. The `SCREENSHOT_*` fixture variables and the
`-FASTLANE_SNAPSHOT` argument are the only launch-time inputs.

### 3.4 Vision

Screenshots of the reference and of ours for the same page, compared by eye and by pixel
sampling. The one measured comparison that changed code is in §1.7 item 1.

---

## 4. Two environment facts worth keeping

1. **`SCREENSHOT_PAGE` is an environment variable, not a launch argument.** Passing
   `-SCREENSHOT_PAGE settings` sets a user default and the app ignores it, silently
   capturing Home. Use `SIMCTL_CHILD_SCREENSHOT_PAGE=settings xcrun simctl launch …`.
2. **`clients/apple`'s `Libbox.xcframework` has no simulator slice** as checked in, and the
   app dies at launch under `CODE_SIGNING_ALLOWED=NO` because
   `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` returns nil without
   entitlements (`Library/FilePath.swift:10`). A simulator framework was built with the
   parent's own tooling — `go run ./cmd/internal/build_libbox -target apple -platform
   iossimulator`, which the parent's `scripts/ci/build-apple-libbox.sh` deliberately omits —
   and merged into the untracked `clients/apple/Libbox.xcframework`. Nothing was committed
   for it.

---

## 5. Reproducing the comparison

```bash
# reference
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
cd ~/Hako-UI-Reference/Hako-Client
python3 scripts/bootstrap.py && python3 scripts/configure.py --bundle-base com.hakoref.hako
xcodebuild build -project apple/HakoClient/HakoClient.xcodeproj -scheme HakoClient \
  -configuration Debug -destination 'platform=iOS Simulator,id=D5F2B38E-…' \
  -derivedDataPath /tmp/dd-hakoref CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=YES
xcrun simctl install booted /tmp/dd-hakoref/Build/Products/Debug-iphonesimulator/HakoClient.app

# both apps' screens
~/hako-ui-compare/shoot.sh com.hakoref.hako ~/hako-ui-compare/reference/tools.png hako://open/utilities
```

---

## 5a. The completion gate, item by item

The manual's iOS gate is seventeen conditions (§92). Each is listed with the evidence that
satisfies it, or with what is missing. "Asserted" means a test fails if it stops being true.

| # | gate item | state | evidence |
| --- | --- | --- | --- |
| 1 | Root pages unified | done | Home, Tools and More are all `HakoRootScaffold` + `HakoPageSection`; captured |
| 2 | Root tab visible only on a root | **asserted** | `testPushingADetailHidesTheRootTabAndPoppingRestoresIt`, `testRootTabIsReachableOnEveryRoot` |
| 3 | No stacked global status bar | done | the shell's accessory slot was removed, not left unused |
| 4 | Home follows the Hako hierarchy | done | session · profile · outbound mode · shortcuts · traffic · runtime; captured |
| 5 | Tools/More grouped, every row subtitled | done | captured in both appearances; `testEveryMoreDestinationOpens` |
| 6 | Secondary pages on one scaffold | done | `HakoNavigationChrome` on every detail page — three pages that were missing it are fixed (§1.7a 22, 23); the settings pages are one `Form` |
| 7 | Proxies/Activity are complete workspaces | done, with one lens each | pinned chrome, search, actions, summary card, data rows; the Activity workspace's state is observed and it resolves (§1.7a 27). The manual's three lenses are two here and the reason is §6 |
| 8 | Config centre consistent | partial | chrome, progress, expiry and update-all done; the segmented libraries are not built, deliberately (§6) |
| 9 | Reports consistent | **asserted** | all three report kinds are archived by the fixture through their archives' own writers, so every list has a row and every read view has real files behind it; `test32`, `test34` and `test36` open each and assert on the artifacts |
| 10 | No raw internal keys | **asserted** | `testNoRawInternalKeysOnAnyPage` walks 3 roots + 7 destinations; `testTunnelPageShowsUserTitlesAndNoRawPropertyNames` |
| 11 | No unrelated brand residue | **asserted** | same sweep, plus `SFM`/`SFMExtension`/`Ghostty Configuration`/`Clash Mode` removed |
| 12 | No double chevron | **asserted** | `testNavigableRowsDrawExactlyOneIndicator` |
| 13 | Search safe-area correct | asserted in part | `testProxyWorkspaceSearches`, `testActivityWorkspaceOffersSearch`; the sheet capsule uses `safeAreaInset` |
| 14 | Every button works | **asserted for the navigation surface** | `testEveryNavigableRowOpensSomething` walks all 15 navigable rows on the three roots and asserts each opens something and comes back; the snapshot suite drives each page's own controls. Not audited: controls that only act on live network or tunnel state |
| 15 | Deep navigation works | **asserted** | `testDeepLinkToLogsBeforeToolsWasEverShown` |
| 16 | Dynamic Type acceptable | done for the pages a fixture reaches | audited at `accessibility-extra-extra-extra-large` on Home, Tools, More, Proxies, Activity, the configuration centre, the settings pages and the configuration editor; five defects found and fixed (§1.7a 17, 18, 24), and the settings pages needed none |
| 17 | Snapshots pass | done | 17/17, 18 screens, `~/hako-ui-compare/` |

Seven of the seventeen are now assertions rather than impressions. The remaining gaps are
named in §6, and they are now gaps in *coverage* rather than in the work: #9 closed when the
fixture learned to archive a report, and #14 remains partially audited in the honest direction
- every page's controls are driven by the snapshot suite, but there has been no exhaustive
audit of controls that no fixture reaches.

## 5a. Spacing, measured against the reference

Reported from screenshots of the running app, so it was measured rather than eyeballed - and the
first attempt at measuring was wrong, which is worth recording. A hand-cropped screen region put
our page inset at 27% larger than the reference's, which would have sent me looking for a bug in
a constant that is correct. Finding the screen bounds by the canvas colour instead of by eye, and
validating the method against a capture whose numbers were already known, gave this:

| measurement | reference | ours (capture) | ours (user's screenshots) |
| --- | --- | --- | --- |
| page inset, left/right | 20.0pt | 20.0pt | 19.8pt |
| card width | 400.0pt | 400.0pt | 400.4pt |
| gap between section cards | 47.7pt | 47.7pt | 47.7pt |
| row height, with subtitle | 62.7pt | 62.7pt | 63.1pt |

**The root pages agree with the reference exactly, to a tenth of a point.** The settings pages
agree on those figures too; what differs there is structure, not spacing:

```text
reference (Tunnel)                     this client (Tunnel)
[caption: 强制路由]                     [caption: Routing]
[card: 强制路由        toggle]  50pt    [card: 强制路由 + explanation   toggle]  63pt
[footnote: 如果是，…]                    [card: 包括所有网络 + explanation toggle]  63pt
[caption: 包括所有网络]                  [card: 包括本地网络 + explanation toggle]  63pt
[card: 包括所有网络     toggle]  50pt    …
```

One card per setting with the explanation as that card's footnote, against one card per group
with each row carrying its own. The second is taller per row and the first repeats a caption for
every setting; neither is a spacing error, and the tokens are the same in both.

## 5b. What §44 taught about testing dense data

The manual's list of values to test is the reason this defect was findable at all: without a
fixture that puts a long chain *and* a rule in the same row, the truncation that drops the rule
looks like ordinary truncation. The generalisable form is that **a composed string has an order,
and truncating it is not order-neutral** — a middle truncation on `a · b · c` can delete `b`, and
the reader cannot tell that anything is missing.

## 6. What is open

In the order I would attack it:

1. **The reference's other proxies presentations.** The reference has three: the system
   `List` (its default, and what the deep-linked screenshot shows), the card/accordion
   presentation this client now matches, and a horizontal group-tab strip. Ours is the card
   one, per the manual. Its "Ungrouped" card has no counterpart yet, because this client's
   group list does not model ungrouped outbounds.
2. **The config centre.** The reference's `HakoProductModal` (720pt, header 56, close glyph
   32, content inset 85) and its profile collection pages were not migrated. Our
   `ProfilePickerSheet` is still the previous round's.
4. **The configuration centre's segmented libraries have no counterpart here.** This client
   keeps no separate node or rule store, and a tab onto nothing would be a page invented to
   fill a diagram. Everything else about the centre is done.
   *Corrected:* an earlier version of this list said the row "still draws its own card with
   its own insets rather than the shared row language". That was wrong, and checking it was
   cheaper than acting on it. On iOS the row lives in a system `List` with the platform's own
   card, which is the same idiom as this client's settings pages and the same idiom the
   reference uses for its own sheet. What the file does contain is two non-token surfaces -
   `Color.secondary.opacity(0.2)` with a radius of 16 on the focus platform, and
   `NSColor.controlBackgroundColor` on the desktop - and both are inside platform branches
   this round does not touch. The general finding is worth keeping: the token set is not
   enforced where a legacy platform branch draws its own surface by hand.
5. **The stray disclosure indicator** on the add-configuration modal's tile row is still
   there and still only partly understood - see §1.7a 4 below and the comment in
   `NewProfileMenuView`.
6. **Dynamic Type** was audited on Home, Tools, More, Proxies, Activity and the
   configuration centre and found one defect, which is
   fixed, along with the three the workspaces had (§1.7a items 17, 18). Not audited: the
   report pages and the editors, which no fixture reaches.
   **Light mode** was compared against the light reference for Home, Tools, More and Logs
   (`~/hako-ui-compare/ours-light/`). The surfaces, the card radius, the page inset and the
   muted captions agree; the differences it produced were content and order, not colour, and
   the ones worth acting on are in §1.7a. The snapshot suite still captures dark, because the
   fixture forces it: light captures are made with
   `xcrun simctl ui booted appearance light` plus `SCREENSHOT_APPEARANCE=light`.
7. **The Activity lens structure, with the reason it is not additive, now read from the manual
   rather than from memory.** §45 asks for 連接 / 請求 / 日志 with "selected underline" and, in its
   own test list, **search scope and sort scope** — which confirms each lens owns its own search
   and sort, so a strip routes the workspace's search binding and its action capsule per lens
   rather than adding a control. §43 also names components this client does not all have:
   `HakoRouteSummaryRow` was deleted as unreferenced in an early round, and `HakoMetricText` is
   this client's `HakoMetricStack`.
   The original note follows: The manual asks for
   連接 / 請求 / 日志 lenses in one workspace. Investigating it properly changed the estimate:
   the lenses do not share their search or their actions — the connections lens searches
   connections through the workspace's drawn field, while the logs lens owns a `.searchable`,
   a pause control, a clear control and a menu — so a strip is not a strip, it is routing the
   workspace's search binding and its action capsule per lens. On top of that, one of the
   manual's three lenses has no data behind it at all: this core records no requests. The
   right shape is a lens-aware workspace, and it is a search-and-actions refactor rather than
   an added control.
10. **Remote-control mode is still two products in one, and that is now a known unknown rather
    than an unnoticed one.** `RemoteDashboardView` draws the legacy card grid, and configuring
    remote control replaces the Hako Home with it. The fixture can enter the mode now
    (`SCREENSHOT_STATE=remote`), but the grid renders only while *connected*, and on a failed
    connect the app falls back to the local Hako Home — so seeing the grid needs a reachable
    remote server, which is a fixture this client does not have. Migrating it is not mechanical:
    `HakoHomeView` reads the local `ExtensionProfile` for its session card, and remote mode has
    no local profile, so it needs a remote-aware session card rather than a substitution.
11. **`OverviewView` is dead on iOS** — only tvOS uses it.
12. **tvOS has not been built or run** this round and shares less with iOS than before.
13. **The parent gitlink is not updated.** Twenty-three submodule commits are local and
   unpushed; the parent still records `1b26865`.
14. **The macOS client is untouched but unverified** — see the handoff document
   (`docs/fork/HAKO-UI-PHASE2-HANDOFF.md`), which also lists the macOS items that the
   earlier rounds left in place.
