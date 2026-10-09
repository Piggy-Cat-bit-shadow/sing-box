# v0.1.6 release integration ledger

Phase A of the release-closure work order. Every value here was **measured at the time of writing**,
not copied from the work order — two of the work order's own snapshots were already stale, which is
the reason this ledger exists.

## Core

| | |
| --- | --- |
| Repository | `Piggy-Cat-bit-shadow/sing-box` (`origin`), `upstream` = `SagerNet/sing-box` |
| Branch | `testing` |
| Go toolchain | `go1.25.5` (`GOTOOLCHAIN` pinned) |
| Build tags | `release/DEFAULT_BUILD_TAGS` |
| `go build -tags TAG ./...` | **exit 0** |
| `go build ./...` (untagged) | **exit 0** |
| `go test -count=1 -tags TAG ./...` | **76 ok / 0 FAIL** |

## Fork pins

| Module | Pin |
| --- | --- |
| `sing` | `Piggy-Cat-bit-shadow/sing v0.9.6-0.20261008194531-3af46fe99d3b` |
| `sing-tun` | `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27` |
| **`utls`** | `Piggy-Cat-bit-shadow/utls v1.8.8-0.20261009084700-6c3e08ed4c4d` — **new this round**, in root and `test/` |
| `quic-go`, `cronet-go` | matched across root and `test/` (34/34 replaces verified by the guard) |

## Clients

### Apple

| | |
| --- | --- |
| Fork | `Piggy-Cat-bit-shadow/sing-box-for-apple` (writable) |
| **Consumed gitlink** | **`2b23330d489b9f6b45e98f903f458842e8961594`** — consumed this round |
| Was | `5911580a6366da78e6b4b5b4459596e5a2cf1eb4` |
| Owner working tree | `816600ab3` (their own branch; **not modified**, `2b23330d4` is built directly on it) |
| Carries | StringBox call sites incl. the **implementer**, plus the screen-state observer |
| Gate expectation | `VERIFIED_APPLE_SHA` moved to `2b23330d4` |

### Android — **two distinct objects, never interchangeable**

**1. `satelite-one` — the actual shipping app.**

| | |
| --- | --- |
| Repository | `Piggy-Cat-bit-shadow/satelite-one` (fork of `zn0wii/satelite-one`, writable), default `main` |
| **Actual HEAD** | **`f83e874`** — the work order's snapshot said `fb606bf19995`, i.e. **stale** |
| `versionCode` / `versionName` | `16` / `0.5.10` |
| **`coreCommit`** | **`c35faabf402a4da93b8c31cdfad941b8b1528ffc`** — **stale**, to be re-pinned to the frozen core |
| Core source | `version.properties` is the single version definition; release must pin the core SHA so one tag maps to one core, while dev CI follows `testing` HEAD |

**2. Standard SFA — the compatibility submodule.**

| | |
| --- | --- |
| Repository | `Piggy-Cat-bit-shadow/sing-box-for-android` (created this round; the submodule's upstream was `SagerNet/sing-box-for-android`, **not writable**) |
| Gitlink | `ec61030d3df74f3e7c39ab848c8996008ecd386a` |
| Carries | the StringBox call sites **including the implementer** that no call-site scan can find |

The work order's rule, recorded so it is not lost: **do not present standard SFA's build errors as
`satelite-one`'s, and do not let `satelite-one`'s CI stand in for SFA compatibility.**

## Deliverable gates (per the work order's table)

**Historical observation** — the "status" column below is what was true when this ledger was written,
at the revision named above. It is not rewritten here. The later, measured artifact facts are added in
the next subsection rather than in place, so that neither record overwrites the other.

| Object | Artifact | Status |
| --- | --- | --- |
| Go core | tagged + untagged CLI | **built, both exit 0** |
| Apple iOS/iPadOS | `Libbox.xcframework` + **unsigned** build | *in progress this round* |
| Apple macOS | libbox + **unsigned** app/DMG | *in progress this round* |
| **`satelite-one`** | installable **APK** + `libbox.aar` | *in progress this round* |
| Standard SFA | AAR + its GUI APK | separate gate; known SFA errors do **not** substitute |

### Artifact status as later measured — additive, `artifact_status` axis

The rows above read *in progress this round* while older reports already contain an unsigned APK and a
built framework. Both statements are true at different times: *in progress* is the state at this
ledger's writing revision, and the table below is the state actually reached, with a digest where one
was recorded. `behavior_status` is stated separately because an artifact is not a runtime proof.

`observed_at_sha` for every row below: **`0fbca85462689c1ea72f7f1af511540ff873aeba`**, which is
**18 commits before** the integration tip `ef83b8681` — so none of these digests belongs to the current
integration tip, and **no artifact exists at `ef83b8681`**.

| Object | `artifact_status` | `behavior_status` | Evidence |
| --- | --- | --- | --- |
| Apple iOS/iPadOS | `Libbox.xcframework` **built**, unsigned, 349 MB (ios-arm64 + macos-arm64_x86_64); no full-tree sha256 recorded, so it is not re-verifiable from the tree | `not_tested` (ABI probe is a compile-time check, not a device run) | `apple-artifact-verification.md` |
| Apple iOS/iPadOS device binary | unsigned iPhoneOS arm64 binary produced, 70,126,536 B, `codesign`: not signed at all | `not_tested` | `v016-release-closure-report.md` |
| Apple macOS / IPA / DMG | **`absent`** — blocked on the Apple client source tree at `2b23330d4` | `blocked` | `v016-release-closure-report.md` |
| **`satelite-one`** | **`sha256 3a46d824d390ea78973e49b366f4cf780af683593e44f98d5633d2caf749a851`** (release APK, arm64-v8a, 29,532,055 B, **unsigned**) | `not_tested` — **runtime is NOT claimed**; no device or emulator was booted | `v016-satelite-release.md` |
| Core `libbox.aar` | **`sha256 02c28683c724652e66e74489d57af58bdfb907fba579de6c0705c600ffa0e255`** (117,460,338 B, 4 ABIs) | n/a | `v016-satelite-release.md` |
| Standard SFA GUI APK | `absent` — build FAILS (4 Kotlin errors, 2 pre-existing client causes, neither migration-related) | `fail` | `v016-release-closure-report.md` |

The work order's rule still binds: **do not present standard SFA's build errors as `satelite-one`'s,
and do not let `satelite-one`'s CI stand in for SFA compatibility.**


## Version-description correction

`v0.1.6-closure-report.md` and `final-closure-report.md` stamp the stage FINAL as `c7a1ef193`, while the
branch HEAD is later — the documentation commits that followed are part of the same stage. The
**code** tip of that round is `c7a1ef193`; the stage's final SHA is whatever `testing` resolves to when
the round closes, and this ledger is the place that discrepancy is resolved rather than left in prose.

## Cross-SHA evidence rule

Existing Actions evidence spans several SHAs (`Verify 37840121267`, `Android Core ARM64 37837674951`,
`Release dry-run 37836475099`, `Xray interop 37823950876`). Per the work order these are **historical
evidence**, not one acceptance of one SHA, and must not be stitched into a single verdict. The release
gate is one acceptance pass against one frozen SHA.
