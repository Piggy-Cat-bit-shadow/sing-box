# v0.1.6 — the satelite-one Android release gate

Scope: Phase A (re-measure the baseline) and Phase D 5.1/5.2/5.3 (the two Android
paths, kept separate) of the v0.1.6 final-closure work order.

This file is deliberately named after the shipping app rather than "android", because
the single most damaging mistake available in this area is to treat three different
objects as one. They are separated in §1 and never merged again below.

Worktree: `/tmp/v16-satelite`, branch `fix/satelite-release`, base
`0fbca85462689c1ea72f7f1af511540ff873aeba`.

## Result at a glance

| Gate | Object | Status |
|---|---|---|
| Core builds + tests | core | **PASS** — tagged/untagged build exit 0; `go test -tags` 76 ok / 0 FAIL |
| `libbox.aar` from the frozen core | core | **PASS** — 117,460,338 B, 4 ABIs, provenance = frozen SHA |
| **satelite-one GUI APK** | object 1 | **PASS (build + provenance)** — release APK 29,532,055 B unsigned; 0 Kotlin errors; 95/95 unit tests. **Runtime UNVERIFIED (no device).** |
| Re-pin applied to satelite-one | object 1 | **BLOCKED on a core push** — patch ready, `git apply --check` proven, not pushed §7 |
| **Standard SFA GUI APK** | object 2 | **FAIL — 4 Kotlin errors, 2 pre-existing causes, neither migration-related** §8 |

`CORE_AAR_PASS != satelite-one_APK_PASS != SFA_GUI_APK_PASS`. Android is **not** all
green, and neither client's result is offered as evidence about the other.

---

## 1. The three "Android" objects

| # | Object | Identity | Role |
|---|---|---|---|
| 1 | **`satelite-one`** | `Piggy-Cat-bit-shadow/satelite-one`, branch `main` = `f83e8745d05ee1cf7de06425da63c8669a7ef27c` | **The shipping Android app.** Primary delivery target. Not the submodule. |
| 2 | **Standard SFA** | `clients/android` gitlink = `ec61030d3df74f3e7c39ab848c8996008ecd386a` from `Piggy-Cat-bit-shadow/sing-box-for-android` | A different GUI and a *separate* ABI acceptance object. |
| 3 | **The core's own `libbox.aar`** | built here from `0fbca85462689c1ea72f7f1af511540ff873aeba` | The artifact 1 and 2 both consume. |

`CORE_AAR_PASS != satelite-one_APK_PASS != SFA_GUI_APK_PASS`, and neither app's CI
result is evidence about the other. Every claim in §5 is labelled with the object it
belongs to.

---

## 2. Re-measured baseline, and where the work order's snapshot was stale

The work order says to update its snapshot rather than trust it. Six values moved.

### 2.1 Corrections

| Work order says | Measured | Evidence |
|---|---|---|
| core `testing` known `151c5ad71e7818312b93b6748847f3aa2d6bdd9f` | That is **`origin/testing`**. Local `testing` has advanced two commits to **`0fbca85462689c1ea72f7f1af511540ff873aeba`** | `git rev-parse origin/testing`, `git rev-parse testing` |
| — | `0fbca8546` is **not on any remote ref**; the GitHub API returns `422 No commit found` | `gh api repos/.../commits/0fbca8546…` |
| satelite-one `main = fb606bf19995...` | Actual `main` = **`f83e8745d05ee1cf7de06425da63c8669a7ef27c`**, six commits later. `fb606bf19995b1007ec09d23cf85377f899e5866` is an ancestor | `gh api repos/.../satelite-one/commits/main`; `git merge-base --is-ancestor fb606bf f83e874` |
| CI run `37896120432` green | True, but **historical**. Run `37905031280` is green on `f83e8745d` (2026-10-09T08:27:10Z) | `gh api repos/.../actions/runs` |
| `coreCommit=c35faabf...`, `versionName=0.5.10` | Confirmed exactly. `c35faabf4` is **40 commits behind** the frozen revision | `git rev-list --count c35faabf..testing` |
| Report FINAL was `c7a1ef193`, later HEAD `151c5ad71` | `v0.1.6-closure-report.md:3` still claims FINAL `c7a1ef193` with `local == origin/testing`. `c7a1ef193` is **3 commits behind** HEAD, so that description is stale. `final-closure-report.md:3` claims FINAL `429265376`, **25 commits behind** | `git rev-list --count X..HEAD` |

Both closure reports' "FINAL" SHAs are historical checkpoints, not HEAD. Neither
should be quoted as the current revision.

### 2.2 Values that did hold

* `clients/apple` gitlink `2b23330d489b9f6b45e98f903f458842e8961594` — matches.
* `clients/android` gitlink `ec61030d3df74f3e7c39ab848c8996008ecd386a` — matches. The
  fork commit's own message confirms it closed the three StringBox
  implementer/extension-receiver sites.
* `clients/desktop` gitlink `32f915ba595601dbc2dd346c33fe9fedd3e72979`.

### 2.3 Toolchain and modules

| Item | Value |
|---|---|
| Go | `go1.25.5` (matches root `go.mod` `go 1.25.5`) |
| Root module | `github.com/sagernet/sing-box`, `go 1.25.5` |
| Test module | `test`, `go 1.25.5`, 36 `replace` directives |
| Tags | `release/DEFAULT_BUILD_TAGS` — 16 tags, `badlinkname` last |
| Android SDK | `~/Library/Android/sdk`: platforms `android-21/24/36/37.1`, build-tools `36.0.0`, NDK `28.0.13004108`, cmdline-tools |
| JDK | Oracle `17.0.2` (the version `build_shared.checkJavaVersion` demands) |
| Gradle | `9.7.0`, already unpacked in `~/.gradle/wrapper/dists`; `gradle` is not on `PATH`, both projects' wrappers are used |
| `gomobile`/`gobind` | present in `~/go/bin` |

Nothing needed for the Android work was missing.

### 2.4 satelite-one release configuration

`version.properties` is the single version definition (`versionCode=16`,
`versionName=0.5.10`, `coreCommit=…`), read by `app/build.gradle.kts`, the Settings
"version" row, and the tag check in CI. Tags exist through `v0.5.10`.

Two workflows, and the distinction is the whole point of §3:

* `.github/workflows/android-ci.yml` — dev. **Follows `testing` HEAD** via
  `git ls-remote`. Green here says the app compiles against whatever the core looked
  like at that moment. It is **not** evidence that the release pin is correct.
* `.github/workflows/release-apk.yml` — release, on `v*` tag or manual dry run.
  **Pins** the core from `version.properties`.

---

## 3. How the shipping APK obtains its core

This decides everything else, so it was established before any build.

**satelite-one does not consume a prebuilt AAR artifact from GitHub, and does not
vendor the core as a module. It builds `libbox.aar` from core source at CI time, at
the revision pinned in `version.properties`.**

The chain, from `app/build.gradle.kts` and `release-apk.yml`:

1. `release-apk.yml` reads `coreCommit` from `version.properties` and requires it to
   match `^[0-9a-f]{40}$`.
2. **Fetchability gate** — `git fetch --depth 1 origin $CORE_SHA` against
   `Piggy-Cat-bit-shadow/sing-box`. `git ls-remote` lists ref *tips* only, so it
   cannot confirm an ancestor commit; fetching the SHA is the real existence check.
   **A pin that is not on the remote fails the release job here.**
3. `go run ./cmd/internal/build_libbox -target android` in that checkout, with
   `SING_BOX_BUILD_VERSION=$SHA` and `SING_BOX_BUILD_COMMIT=$SHA`, then copies
   `libbox.aar` + `libbox.provenance` into `app/libs/`.
4. `.github/scripts/check_core_provenance.py` validates the pair.
5. Gradle's own `verifyCoreProvenance` task byte-searches `libbox.so` inside the AAR
   for the revision the APK is about to advertise, and **fails the build on mismatch**
   rather than warning.
6. `assembleRelease` — ABI splits `arm64-v8a` + `x86_64`, `isUniversalApk = false`.

Locally the same shape holds with `app/libs/libbox.aar` as a plain file dependency
(`implementation(files("libs/libbox.aar"))`, conditional on existence), which is
gitignored and therefore always a build product, never a checked-in blob.

**The consequence that governs the rest of this round:** `coreCommit` is a promise
about a *future fetch*. Pinning it to a revision that is not on the remote produces a
release job that fails at step 2; pinning it to the wrong revision produces a green
build of the wrong core. Both are checked in §4.

---

## 4. The re-pin

### 4.1 Exact change

`c35faabf4` is the core the 0.5.10 release was cut from. It predates this round's ABI
migration and the uTLS hybrid-share pin, so rebuilding the release tag would have
produced a different core than this round froze — the non-reproducible-tag failure the
pin exists to prevent.

```
diff --git a/version.properties b/version.properties
index 4d9dc04..7fbb302 100644
--- a/version.properties
+++ b/version.properties
@@ -13,4 +13,4 @@ versionName=0.5.10
 # 开发用 CI(.github/workflows/android-ci.yml) 仍然跟随 testing HEAD。
 #
 # 发版前把这个值更新为要发布的内核 commit, 并与 app 一起提交。
-coreCommit=c35faabf402a4da93b8c31cdfad941b8b1528ffc
+coreCommit=0fbca85462689c1ea72f7f1af511540ff873aeba
```

**One line.** `versionCode` and `versionName` keep the existing 0.5.10 strategy — the
app's own version is not bumped and no app tag is created. In satelite-one's terms the
change is a single atomic property edit, which is how the project's own release
instructions describe it.

Commit in the satelite-one clone: **`a966aca4978c5c0795f5754e239d7c221edb0b91`**, branch
`fix/release-core-pin`, parent `f83e8745d05ee1cf7de06425da63c8669a7ef27c`.

### 4.2 Why a patch and not a pushed commit

The core worktree is forbidden to write `clients/android` or `clients/apple`, and this
round's constraints forbid pushing, tagging and releasing. satelite-one was therefore
re-pinned in a **local clone** (`/tmp/v16-satelite/.work/satelite-one`, cloned from the
read-only reference at `/tmp/satelite-one`), and the change is delivered as a
deterministic patch for the integrator. The work order allows exactly this fallback; it
does not allow calling an unintegrated GUI a PASS, and §5.1 does not do so.

Note on transports: `github.com` git-over-HTTPS is **unreachable** from this
environment (connection timeout), while `api.github.com` works. Remote facts above were
therefore read through the API, and the SFA source was fetched as an API tarball.

### 4.3 Patch artifacts

| File | SHA256 |
|---|---|
| `docs/fork/patches/satelite-one-core-pin-0fbca8546.diff` (plain `git apply`) | `25bf2c583e9c24027da37ccad421049dafab0ae9162d4cbd0b74a71069b88805` |
| `docs/fork/patches/satelite-one-core-pin-0fbca8546.patch` (`git am`) | `268ca6e2ee1782c0331b9cdf387c3ad315825f74724e5e6f2fc68a43457c902f` |

The `.diff` is byte-deterministic for a given base tree. The `.patch` additionally
carries the commit date, so its hash is tied to when it was produced.

**`git apply --check` proof**, against a pristine export of satelite-one `main`:

```
--- git apply --check (plain diff) ---
APPLY_CHECK_DIFF=OK
--- git apply --check (format-patch) ---
APPLY_CHECK_PATCH=OK
--- git am --3way ---
Applying: fix(release): pin the core to the frozen v0.1.6 revision
--- result ---
coreCommit=0fbca85462689c1ea72f7f1af511540ff873aeba
```

### 4.4 Verification script

`scripts/ci/check-satelite-one-core-pin.py` asserts that the four places carrying the
same fact agree: the pin the workflow will fetch, the producer's provenance record, the
bytes inside the packaged `libbox.so`, and the bytes inside the shipped APK. The app's
own gates already cover provenance-vs-BuildConfig; this covers the cross-artifact
question those cannot — *is the revision the workflow will fetch the revision these
artifacts contain.*

Negative results are real, not assumed — this is what makes the PASS meaningful:

```
# 1. the pre-existing pin vs the frozen revision — must FAIL
FAIL  version.properties pins the frozen core revision — pinned c35faabf402a…, frozen revision is 0fbca8546268…
EXIT=1

# 2. the re-pinned clone — must PASS
PASS  version.properties pins the frozen core revision — 0fbca85462689c1ea72f7f1af511540ff873aeba
EXIT=0

# 3. re-pinned app + the OLD AAR — cross-artifact must FAIL
FAIL  libbox.provenance names the frozen revision — commit=c35faabf4…, frozen revision is 0fbca8546268…
FAIL  packaged libbox.so contains the frozen revision — no libbox.so in …/libbox.aar contains 0fbca854…
EXIT=1
```

Test 3 is the tamper check the work order asks for: swapping in the previous AAR is
**detected**, because the byte search genuinely discriminates. The same control was run
against the previously-built APK: `FAIL — no entry of …apk contains 0fbca854…`.

---

## 5. What was actually built

### 5.1 Core — object 3

```
$ export GOTOOLCHAIN=go1.25.5; TAGS=$(cat release/DEFAULT_BUILD_TAGS)
$ go build -tags "$TAGS" ./...      # EXIT_TAGGED=0
$ go build ./...                    # EXIT_UNTAGGED=0
$ go test -count=1 -tags "$TAGS" ./...   # GOTEST_EXIT=0
ok  …  76 packages ok, 0 FAIL
$ gofmt -l .                        # (empty)
$ go mod tidy -diff                 # (empty, exit 0)
```

**A contamination note, recorded because it produced a false signal first.** An earlier
run of the same suite reported `FAIL` and `gofmt -l` listed six files. Both were caused
by this round's own concurrent `build_libbox` run: `gomobile bind` writes generated Go
into `build/<arch>/libbox/` in the repository root, and `go test ./...` walks it. That
directory is gitignored (`.gitignore:15 /build/`). After the AAR build finished the
generated tree was removed and the suite re-run cleanly, giving **76 ok / 0 FAIL** and
an empty `gofmt -l`. The tracked tree was never modified — `git status --short` showed
only intended untracked files throughout. The first result was an artifact of two Go
builds sharing one directory, not a core defect; it is reported rather than dropped
because "I re-ran it and it was green" is exactly the reasoning that hides real
failures.

### 5.2 `libbox.aar` — object 3

```
$ SING_BOX_BUILD_VERSION=0fbca85462689c1ea72f7f1af511540ff873aeba \
  SING_BOX_BUILD_COMMIT=0fbca85462689c1ea72f7f1af511540ff873aeba \
    go run ./cmd/internal/build_libbox -target android
AAR_BUILD_EXIT=0    # wrote libbox.provenance (commit=0fbca854… version=0fbca854…)
```

| Artifact | Size (B) | SHA256 |
|---|---|---|
| `libbox.aar` | 117,460,338 | `02c28683c724652e66e74489d57af58bdfb907fba579de6c0705c600ffa0e255` |
| `libbox-legacy.aar` | 96,946,267 | `c4c1687ecfda2e506ee02f0ef0ba005fd64636ed399fbc7c1095e2973ce2061e` |

Packaged ABIs, with the sizes the APK must then carry:

```
jni/armeabi-v7a/libbox.so   72,232,920
jni/arm64-v8a/libbox.so     80,164,656
jni/x86/libbox.so           77,835,072
jni/x86_64/libbox.so        84,508,544
classes.jar                    237,860
```

`libbox.provenance` records `commit=0fbca85462689c1ea72f7f1af511540ff873aeba` and
`version=0fbca85462689c1ea72f7f1af511540ff873aeba` — identical, which is what the
release path produces and what makes the APK's own gate exact rather than tag-tolerant.
Each variant also records its resolved tags, so "does this AAR contain capability X" is
answerable without re-deriving tag composition.

### 5.3 satelite-one GUI APK — **object 1** ✅

Fresh clone, no incremental state, fresh AAR, the project's own wrapper:

```
$ ./gradlew --no-daemon --console=plain \
    :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease
BUILD SUCCESSFUL in 10m 57s
99 actionable tasks: 99 executed
APK_BUILD_EXIT=0
$ grep -c '^e: ' <unfiltered log>
0
```

The app's own gate ran and passed:

```
> Task :app:verifyCoreProvenance
verifyCoreProvenance: OK — packaged libbox carries the advertised core identity '0fbca85462689c1ea72f7f1af511540ff873aeba'
```

Unit tests: **95 tests, 0 failures, 0 errors, 0 skipped** across 10 test classes.

| APK | Size (B) | SHA256 |
|---|---|---|
| `satelite-one-arm64-v8a-debug.apk` | 52,160,539 | `bab3d74727f7a9ffa5901d1c3621031ba05f7bda9237e04e9c62916125343130` |
| `satelite-one-x86_64-debug.apk` | 54,467,618 | `22fd27b67531fa469467575c5240b17aeca1fd074d0c8807aac5ecc1e4710bb9` |
| `satelite-one-arm64-v8a-release.apk` | 29,532,055 | `3a46d824d390ea78973e49b366f4cf780af683593e44f98d5633d2caf749a851` |
| `satelite-one-x86_64-release.apk` | 31,418,798 | `25d88a4402448834848003caa305a095aab249f41c147ba0640d8f66b869572c` |

**Signing state**, verified with `apksigner`, because "release" and "signed" are not the
same question:

* release: `DOES NOT VERIFY — ERROR: Missing META-INF/MANIFEST.MF` → **unsigned**, as
  required. No signing material was created or used.
* debug: `CN=Android Debug` → AGP's standard debug key, expected for a debug variant.

**The packaged core is the fresh one, proved by size rather than by intent:**

```
release/arm64-v8a : lib/arm64-v8a/libbox.so  80,164,656  == AAR jni/arm64-v8a/libbox.so
release/x86_64    : lib/x86_64/libbox.so     84,508,544  == AAR jni/x86_64/libbox.so
```

The full chain then verifies end to end:

```
PASS  version.properties pins the frozen core revision — 0fbca85462689c1ea72f7f1af511540ff873aeba
PASS  libbox.provenance names the frozen revision — commit=0fbca854… version=0fbca854…
PASS  packaged libbox.so contains the frozen revision — ABIs: arm64-v8a, armeabi-v7a, x86, x86_64
PASS  APK contains the frozen revision — 29,532,055 B, arm64-v8a present
```

**Stated honestly:** this is a build-and-provenance PASS. It is not a runtime
acceptance. No emulator or device was booted, so VPNService start/stop, real proxy
traffic, Doze/network-switch wake behaviour and the runtime callback path are
**not** verified here. Those need a device and are not claimed.

---

## 6. The two Android gates, stated separately

### Gate A — satelite-one (object 1): release APK builds

**Status: PASS for build + provenance; runtime UNVERIFIED (no device).**

Evidence: §5.3 — `assembleRelease` exit 0, 0 Kotlin errors, 95/95 unit tests, app's own
`verifyCoreProvenance` OK, unsigned release APKs produced, packaged `libbox.so` sizes
match the fresh AAR, cross-artifact chain PASS.

Not claimed: the release **workflow** has not been executed, because its fetchability
gate requires the frozen core SHA to be on the remote and it is not yet (§7).

### Gate B — standard SFA (object 2): GUI APK does **not** build

**Status: FAIL — 4 Kotlin errors, 2 causes, neither migration-related.**
Reproduced independently; details and classification in §8.

The two gates are independent in both directions. satelite-one's green build is not
evidence about SFA, and SFA's four errors do not qualify satelite-one's PASS. Both were
measured on the same fresh AAR, in separate trees, with separate evidence.

---

## 7. What could not be done, and the exact missing prerequisite

| Item | Status | Missing prerequisite |
|---|---|---|
| Push the re-pin to `satelite-one` | **BLOCKED by round constraints** | The constraints forbid pushing/tagging/releasing. Delivered as patch `a966aca…` (§4.3) for the integrator. |
| `release-apk.yml` end-to-end | **BLOCKED on a core push** | `0fbca8546` is not on `Piggy-Cat-bit-shadow/sing-box` (API: `422 No commit found`). The workflow's "Verify pinned core revision is fetchable" step fetches that exact SHA and will fail until core `testing` is pushed. **This is an integrator action, and it is a hard prerequisite for the re-pin to take effect — not a defect in the pin.** |
| Fetchability check in §4.4 | SKIP locally | Same cause, plus git-over-HTTPS to `github.com` is unreachable from this environment. The check is implemented (`--remote`) and runs wherever git transport works. |
| Runtime acceptance (VPNService, real traffic, Doze) | **NEEDS A DEVICE/EMULATOR** | An AVD or physical device. Not attempted, not claimed. |
| App-side ABI contract test / lint beyond `lintVitalRelease` | Not run as a separate gate | `:app:lintVitalRelease` ran as part of `assembleRelease`. A full `:app:lint` is available but was not a stated acceptance object for this round. |

One dependency worth flagging for whoever runs the release workflow: this round's uTLS
work pins `github.com/metacubex/utls => github.com/Piggy-Cat-bit-shadow/utls
v1.8.8-0.20261009084700-6c3e08ed4c4d`. The fork is public, so CI can resolve it from
the module proxy — but that is a new external fetch on the release path, and
`proxy.golang.org` is itself unreachable from this sandbox (the local build used the
existing module cache). Worth one green CI run on a network that can reach the proxy.

---

## 8. Gate B — standard SFA, reproduced and classified

Object 2 only. Nothing here is evidence about satelite-one.

`clients/android` is pinned at `ec61030d3df74f3e7c39ab848c8996008ecd386a`. The
submodules are uninitialised in this worktree, and git-over-HTTPS to `github.com` is
unreachable, so the source was fetched at that exact revision through
`api.github.com`'s tarball endpoint — with the AAR that this round's core produced.

```
$ gradle :app:assembleOtherDebug --no-daemon --console=plain
> Task :app:compileOtherDebugKotlin FAILED
BUILD FAILED in 7m 28s
SFA_BUILD_EXIT=1
$ grep -c '^e: ' <unfiltered log>
4
```

The four errors, verbatim:

```
e: …/bg/BoxService.kt:113:16 Unresolved reference 'promotePowerReportDraft'.
e: …/bg/BoxService.kt:309:20 Unresolved reference 'promotePowerReportDraft'.
e: …/bg/ProxyService.kt:7:1   Class 'ProxyService' is not abstract and does not implement abstract members:
                              fun createAutoRedirect(options: ByteArray!, handler: AutoRedirectHandler!): AutoRedirectSession!
                              fun usePlatformAutoRedirect(): Boolean
e: …/bg/VPNService.kt:20:1    Class 'VPNService' is not abstract and does not implement abstract members:
                              fun createAutoRedirect(options: ByteArray!, handler: AutoRedirectHandler!): AutoRedirectSession!
                              fun usePlatformAutoRedirect(): Boolean
```

**The previous round's finding still holds, and its classification is confirmed** —
four errors, two causes, and neither is the ABI migration.

### 8.1 `promotePowerReportDraft` ×2 — pre-existing client staleness (draft API that never landed)

Two independent checks, both negative:

* **The core does not export it and never did.** `grep -rn 'PromotePowerReportDraft'
  --include='*.go' .` → **0 hits** repository-wide. It exists in no AAR, past or
  present.
* **The new AAR does not carry it.** `grep -rn 'promotePowerReportDraft'` across all
  **156** gomobile-generated Java files → **0 hits**.

The client's calls sit immediately beside ones that *do* resolve, which is what makes
this look like a merge artefact rather than a design gap:

```
Libbox.promoteOOMDraft()          // BoxService.kt:112 — resolves; core has it
Libbox.promotePowerReportDraft()  // BoxService.kt:113 — does NOT resolve
```

`experimental/libbox/oom_report.go:263` exports `PromoteOOMDraft()` and
`oom_report.go:268` `PromoteOOMDraftAt()`. The power-report stream does export
`DiscardPowerReportDraft()` (`power_report.go:46`) but has no promote counterpart. The
client is calling a promotion API this core has never had.

### 8.2 `createAutoRedirect` / `usePlatformAutoRedirect` ×2 — pre-existing client staleness (client behind the interface)

The direction is the opposite of 8.1, and the evidence is direct:

* **The core exports them.** `experimental/libbox/platform.go:33-34` declares
  `UsePlatformAutoRedirect() bool` and `CreateAutoRedirect(options []byte, handler
  AutoRedirectHandler) (AutoRedirectSession, error)`, wrapped at `service.go:360-369`
  and stubbed at `config.go:203-207`.
* **The new AAR carries them**, read straight out of this build's generated bindings:
  `PlatformInterface.java:17` and `:36`.
* **The client never implements them.** `grep -rn -E 'createAutoRedirect|
  usePlatformAutoRedirect' app/src` at `ec61030d3` → **0 hits**.

`PlatformInterfaceWrapper : PlatformInterface` (`PlatformInterfaceWrapper.kt:46`) is the
interface `ProxyService` and `VPNService` satisfy, so the two unimplemented members
surface as "not abstract and does not implement abstract members" on both classes. At
this revision the client is stale against an older libbox.

### 8.3 The migration half of SFA is closed

Zero StringBox errors appear in the log
(`grep -c -E "StringBox|Return type of 'fun name\(\)|Argument type mismatch"` → **0**).
The three implementer/extension-receiver sites that `ec61030d3` was cut to fix are
gone; the build now stops only on the two unrelated gaps above. Reporting SFA's APK as
"blocked by the ABI migration" would be false, and so would reporting it as "built".

### 8.4 SFA gate verdict

`NON-SHIPPING COMPAT — APK does not build, for two causes that belong to other
changes.` Per the work order this does **not** make satelite-one's shipping APK fail.
It also does not make Android "ALL GREEN", and this report does not say that.

Not attempted here, and named so the gap is explicit: SFA's `play`/`otherLegacy`
variants, its JVM tests, lint, and the ABI-scanner destruction tests §5.2.4 asks for
(delete a real implementer, inject an old method call, mis-pin) were not run. The
satelite-one verifier in §4.4 carries negative controls of that shape, but they cover
object 1, not object 2.
