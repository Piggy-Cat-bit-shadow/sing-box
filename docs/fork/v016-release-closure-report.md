# v0.1.6 release closure — final report

Baseline `151c5ad71` → **FINAL `e610e7660`**, `local == origin/testing`, ordinary pushes only. No tag,
no Release, no signing. Agents worked in **isolated worktrees**; the integrator cherry-picked with `-x`.

## Deliverables actually built

| Object | Artifact | Status |
| --- | --- | --- |
| Go core | tagged + untagged CLI | **exit 0 / exit 0** |
| Go core | `go test -count=1 -tags TAG ./...` | **76 ok / 0 FAIL** |
| **`satelite-one` (shipping app)** | **release APK, unsigned** | **BUILD SUCCESSFUL**, 0 Kotlin errors, 95/95 tests, provenance gate green |
| Apple | `Libbox.xcframework` 349 MB (ios-arm64 + macos-arm64_x86_64) | **built**, 17m01s |
| Apple | unsigned iPhoneOS arm64 binary | **produced**, 70,126,536 B, `codesign`: not signed at all |
| Standard SFA | GUI APK | **FAIL — 4 errors, 2 causes, neither migration-related** |

### satelite-one — the shipping Android product: **PASS on build and provenance**

`./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease` → BUILD SUCCESSFUL,
`grep -c '^e: '` = **0**, 95/95 unit tests, the app's own `verifyCoreProvenance` OK. Release APK
arm64-v8a **29,532,055 B** (sha256 `3a46d824…`), x86_64 31,418,798 B, correctly **unsigned**.

The core is proved by **bytes, not intent**: the APK's `lib/arm64-v8a/libbox.so` is 80,164,656 B,
identical to the fresh AAR's. The chain pin → provenance → `libbox.so` → APK all name one SHA, with
negative controls that make the check non-vacuous — the old pin fails, and a re-pinned app carrying the
**old** AAR fails the byte search.

**Runtime is NOT claimed.** No device or emulator was booted, so VPNService start/stop, real proxy
traffic, Doze and network-switch behaviour are unverified.

### The two Android gates are separate, and both were measured separately

**`satelite-one` shares NEITHER of standard SFA's gaps**: it *implements*
`createAutoRedirect`/`usePlatformAutoRedirect` and never calls `promotePowerReportDraft`. This is the
distinction the work order insisted on, and it is the reason one gate's red does not condemn the other.

Standard SFA still fails with the same 4 errors and 2 causes as the previous round, both **pre-existing
client staleness** and neither migration-related: `promotePowerReportDraft` exists in **no** AAR
(0 hits repo-wide, 0 across all 156 generated Java files), while `createAutoRedirect` **does** exist in
the core and the new AAR and the client never implemented it. **The migration's own StringBox errors
are gone.** Standard SFA is a non-shipping compatibility target this round.

## uTLS — the first protocol P0 — closed for two fingerprints

The fork now exists (`Piggy-Cat-bit-shadow/utls @ 6c3e08ed4`, branch + tag) carrying exactly three
upstream commits, pinned in **both** modules. `fingerprint: firefox` and `safari` produced greetings
with no X25519MLKEM768 share, which a current reference rejects with the same message a wrong public
key produces — so the symptom points nowhere near the cause. The same scenarios pass against an older
reference with the identical tree, which is what proves the requirement moved.

**A version bump is not an alternative**, and that is worth recording because it is the obvious first
idea: `v1.8.8`, the newest release, still builds Firefox/120 and Safari/16.0. The change exists only on
a 175-commit rebase, which is not something to absorb during a freeze.

The register was **updated, not loosened** — and its last assertion is a **count**, because `random` is
a probability and the count *is* that probability. It moved 4 → 2 when the fork landed, and it is
deliberately not something a future edit can quietly relax.

**Scope, stated honestly:** this repairs firefox and safari only. `edge`, `ios` and `qq` have the same
missing share and **no upstream preset fixes them in any revision**; `random` still loses two draws in
five. `fingerprint: chrome` is the workaround.

## Apple ABI verified at the artifact, not the source

A committed re-runnable probe (`scripts/ci/apple-abi-probe.sh`) compiles the patched call-site shapes,
the **implementer witness**, and `ScreenStateObserver.swift` **verbatim** against the real shipped
framework: **GREEN 0 errors** for iOS and macOS, **RED 15 errors** for every pre-migration shape, and it
**links and runs** on the macOS slice (`LibboxVersion()` → `0.0.0-v0.1-0fbca8546`).

That closes the gap that misled an earlier round: a **source sweep is not verification**, and the
implementer half — the one no call-site scan can find — is now compiler-checked.

## Findings that changed decisions

- **§12 initial state is not implemented** (Apple). Measured on Darwin notify: registration never
  delivers a state that already exists, though `notify_get_state` has it — so a tunnel that starts
  already locked never enters the device pause until the next transition, leaving health checks and
  provider refreshes permitted on a phone in a pocket. Direction is "assumed active", not a false
  boundary and not a wake storm. The core dedup it depends on is already proven, so no core change is
  needed; a fix patch is prepared and compiler-verified.
- **A new upstream defect**: the iOS framework slice links only with `-dead_strip` — the pinned
  prebuilt cronet-go `ios_arm64` archive references `MessagePumpKqueue::InitializeFeatures()` without
  defining it, while macOS defines 54 such symbols. Not fixable here (no new dependency fork).
- **A documented misdiagnosis corrected**: the repo claimed the iOS cross-compile fails on cronet-go.
  It does not — it is `CGO_ENABLED=0` off-host dropping the cgo file. With cgo on, it compiles.
- **The work order's own snapshots were stale on both Android rows**: `satelite-one` `main` is
  `f83e8745d`, not `fb606bf19995`, and its `coreCommit` was **40 commits behind** the frozen revision.
- **`release-apk.yml` fetches the pinned SHA from source**, so dev CI floating on `testing` HEAD never
  proved the release pin: `satelite-one CI PASS ≠ release core pin PASS`.

## Blocked, precisely

- **Apple product IPA / macOS DMG**: `BLOCKED: missing Apple client source tree at 2b23330d`. Signing is
  **not** the blocker (`APPLE_SIGNING_MODE` already defaults to unsigned). GitHub was unreachable, the
  submodule is unpopulated, and the shared object store was out of scope. Read-only access to
  `.git/modules/clients/apple` is the single unblock for both.
- **Runtime acceptance**: needs an AVD/device. Not claimed.
- **The uTLS pin's CI resolvability**: `proxy.golang.org` is unreachable from this sandbox and the
  local build used the module cache. The fork is public so it is CI-resolvable, but it deserves one
  green CI run on a network that can reach the proxy.

## A false signal reported rather than hidden

An early satelite test run showed `FAIL` plus 6 `gofmt` hits. The cause was that round's own
`build_libbox` writing generated Go into the gitignored `build/` directory that `go test ./...` walks.
Clean re-run: 76 ok / 0 FAIL, empty gofmt, tracked tree never changed. Recorded because "I re-ran it and
it was green" is exactly how a real failure gets buried. The same instinct caught a `common/urltest`
wall-clock assertion failing at load 99.31 and passing 5/5 in isolation — reported as
environment-induced, **neither as a pass nor as a regression**.

## Version-description correction

Earlier reports stamped `c7a1ef193` (3 commits behind) and `429265376` (25 behind) as FINAL. Those are
**stage code tips**, not HEAD. Resolved in
[v016-release-integration-ledger.md](docs/fork/v016-release-integration-ledger.md) rather than left in
prose.

## Verdict: **NOT-READY**, and the remaining items are named

The kernel is green, the shipping Android APK genuinely builds and carries a byte-verified core, the
Apple framework builds and its ABI is compiler-verified against the real header, and the first protocol
P0 is closed for the two fingerprints that were proven broken.

**Not ready because**: the Apple product builds (IPA/DMG) are blocked on a source tree that could not be
fetched; standard SFA still fails with two pre-existing client gaps; `edge`/`ios`/`qq` REALITY
fingerprints remain a proven, named, unfixed gap; and **no acceptance pass has been run against a single
frozen SHA** — the existing Actions evidence spans several, and stitching it into one verdict is what
the work order forbids.

Nothing here was signed, tagged, released, or forced.

## Addendum: an intermittent failure found during final verification

The final full-suite run reported failures in `common/trafficsched` — the rate shaper:
`TestNeitherLaneStarvesWhenBothAreBusy`, `TestPacedModeShapesFromTheFirstWrite`,
`TestOversizedWriteIsChargedNotExempted`, `TestAdmittedRateMatchesTheConfiguredRate`.

They are **not** reported as green and **not** reported as a regression, because neither claim is
supported yet:

- **In isolation they pass 3/3**, 107s each, at load 13.
- They failed inside `go test ./...` at **load 56**, where the suite runs packages in parallel.

So the honest statement is: these are **timing-sensitive tests that fail under full-suite parallelism
on a loaded host**. That is a real flaky-gate problem — the project's own rule is that a wall-clock
assertion measures the machine and not the algorithm — and it needs the same treatment the rest of
this package got earlier: assert conserved accounting quantities rather than elapsed time.

It is recorded here rather than filed away because a suite that is green only when nothing else is
running is not a gate. It was **not** introduced by this round's changes: nothing in this round
touches `common/trafficsched`, and its only relationship to this round is that the round's own builds
made the host busy enough to expose it.

A second contamination source is worth recording with it: an earlier run counted 74 ok instead of 76
because a `build/` directory of gomobile-generated Go had been left in the repository root by the
Android artifact build, and `go test ./...` walks it. Removing it restored 76. The tracked tree was
never modified, and the same trap was hit and reported independently by the Android agent — which is
why it is written down instead of silently cleaned.
