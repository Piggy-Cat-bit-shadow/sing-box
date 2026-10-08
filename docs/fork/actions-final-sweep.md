# Final CI / Actions sweep

## Executive status

| | |
| --- | --- |
| Final HEAD | `8548c9d43` (Android workflow fixes) → reported HEAD below |
| Workflows on the fork | **8** (7 pre-existing + 1 added) |
| Triggered by a push | **2** — `Verify`, and the new `Android Core ARM64` |
| Manual dispatch only | 6 — Linux, macOS, Windows, Apple, Release, Reference interop |
| Green | `Verify` (GREEN AFTER FIX) · 6 manual workflows **NOT RUN** |
| Android ARM64 | **RED — 4 distinct root causes, retry budget reached** |
| Reproducible red elsewhere | 0 known |

**This is not an all-green report and does not claim to be.** `ALL CURRENT ACTIONS GREEN` would be
false: the Android workflow is red, and six workflows were never executed in this environment.

## The single most important finding

`gh run list` in this checkout **resolves to the parent repository** (`SagerNet/sing-box`) unless
`--repo` is passed, because the local `upstream` remote is present. The first run listing therefore
showed thirty upstream runs and **zero** of this fork's. Every subsequent query used
`--repo Piggy-Cat-bit-shadow/sing-box`.

That matters beyond bookkeeping: it means a sweep can look like it is reading CI results while
reading somebody else's.

## Workflow matrix

| Workflow | Trigger | Last result at HEAD | Notes |
| --- | --- | --- | --- |
| Verify | push, PR, dispatch | **GREEN AFTER FIX** | see P001 |
| Android Core ARM64 | push (paths), dispatch | **RED** | new; see P002–P005 |
| Linux amd64 | dispatch | not run | |
| Windows amd64 core | dispatch | not run | has historical failures upstream-side |
| macOS arm64 | dispatch | not run | |
| Apple client | dispatch | not run | needs signing credentials |
| Release | dispatch | not run | needs a tag |
| Reference interop (Xray) | dispatch | not run | needs an Xray binary |

## Problem ledger

### P001 — Verify failed on the pinned-upstream assumptions step · FOUND → FIXED

| | |
| --- | --- |
| Workflow | Verify (runs `37780364616`, `37769283387`) |
| Symptom | `FAIL: cannot locate the pinned gVisor source to check its handshake guard.` |
| Severity | high — the only push-triggered gate was red and it went unnoticed |
| Root cause | the Phase-1 gVisor tripwire required the pinned gVisor module in the module cache; CI never downloads it, so the check failed for an environmental reason |
| Classification | **C. CI CONFIG BUG** |
| Fix | the check no longer exists — the gVisor retirement deleted the dependency edge, and the tripwire was **inverted** into a hard "gVisor must not ship" invariant |
| Verification | 5 consecutive `Verify` successes after the retirement (`37796412838`, `37789241981`, `37781337663`, `37781284694`, `a15acd85e`) |
| Status | **GREEN AFTER FIX** |
| Attribution | **INTRODUCED THIS SERIES** (Phase 1), fixed in Phase 3.6 |

Worth stating plainly: **two of my own commits failed CI and I did not notice.** Nothing in the
workflow went red *loudly* enough, and I was reading local `verify-upstream-assumptions.sh` output —
which passed, because locally the module cache is populated. Local green is not CI green.

### P002 — `android-actions/setup-android@v3` fails inside itself · attempt 1

| | |
| --- | --- |
| Run | `37803539824` |
| Symptom | `Warning: Failed to find package 'tools'` → `Error: The process '.../sdkmanager' failed with exit code 1` |
| Root cause | the action runs `sdkmanager "tools"` during setup; the `tools` package is no longer published in the SDK repository |
| Classification | **D. TOOLCHAIN / DEPENDENCY** |
| Fix | removed the action; the runner image already ships cmdline-tools and a populated SDK. The SDK root is resolved from the environment with a fallback, `sdkmanager` is located explicitly and the step fails loudly with the directory listing if absent, and only the NDK is installed |
| Attribution | **EXTERNAL** (third-party action vs current SDK repo) |

### P003 — the NDK install fails on its own pipe · attempt 2

| | |
| --- | --- |
| Run | `37803880267` |
| Symptom | `yes: standard output: Broken pipe` → exit 1 |
| Root cause | `yes \| sdkmanager` under `set -o pipefail`: `yes` gets EPIPE the moment sdkmanager exits, so the pipeline reports failure for a **successful** install |
| Classification | **C. CI CONFIG BUG** (mine) |
| Fix | `</dev/null` instead of `yes \|`, plus the explicit directory check that was already there to prove the install happened |
| Attribution | **INTRODUCED THIS SERIES** |

### P004 — gomobile `@latest` requires Go 1.26, toolchain download 404s · attempt 3

| | |
| --- | --- |
| Run | `37804268663` |
| Symptom | `golang.org/x/mobile@v0.0.0-20260908204917 requires go >= 1.26.0; switching to go1.26.9` → `verifying module: ... 404 Not Found` |
| Root cause | `go install golang.org/x/mobile/cmd/gomobile@latest` resolves to a revision whose `go` directive exceeds the pinned toolchain; `GOTOOLCHAIN` then tries to fetch `go1.26.9` as a module and **that version does not exist on the proxy** |
| Classification | **D. TOOLCHAIN / DEPENDENCY** |
| Required fix | **pin `golang.org/x/mobile` to a version whose `go` directive is ≤ 1.25.5** instead of `@latest`, which is also what reproducibility demands |
| Blocked by | this environment has **no module-proxy access** (`proxy.golang.org` unreachable), so a compatible version cannot be resolved from here. `go list -m -versions golang.org/x/mobile` needs the network |
| Attribution | **EXTERNAL / ENVIRONMENT** |
| Status | **BLOCKED-EXTERNAL** |

### P005 — the Android workflow builds a shape the product may not ship · design note

`cmd/internal/build_libbox` writes to whatever paths it uses; the workflow discovers
`libbox*.aar` and `libbox.provenance` by `find` because the exact output location was not
confirmed from a real run. That is a guess in the verification step, and it should be replaced by the
builder's actual output paths once a build completes end to end.

### P006 — a doc contradicted the shipped code · FOUND → FIXED

| | |
| --- | --- |
| Symptom | `mobile-parity-android-report.md` said Android did not ship `with_low_memory` while `cmd/internal/build_libbox/main.go` shipped it |
| Root cause | a broad `git add cmd/internal/build_libbox/` swept a concurrent agent's in-flight edits into an unrelated commit, so the code moved ahead of the document describing it |
| Classification | **C** (process/commit hygiene) |
| Fix | the document now carries the measured case; the correction is stated in the document rather than silently edited away |
| Attribution | **INTRODUCED THIS SERIES** |

This is the same class of mistake as P002 and P003: the failure was not in the product, it was in the
tooling around it. Three of four Android failures and this one were plumbing.

## Retry ledger

| Problem | Attempts | Reruns without a change | Outcome |
| --- | --- | --- | --- |
| P001 Verify | 0 (fixed by an unrelated structural change) | 0 | GREEN AFTER FIX |
| P002 setup-android | 1 | 0 | superseded by attempt 2 |
| P003 pipefail | 1 | 0 | superseded by attempt 3 |
| P004 gomobile pin | 1 | 0 | **BLOCKED-EXTERNAL**, stopped |

**No workflow was re-run without a code change.** Every attempt above carried a written hypothesis and
a diff; the retry budget was reached at P004 and the workflow was frozen with its evidence rather than
spun again.

## What this sweep actually established

1. The fork's push-triggered gate is `Verify`, and it now passes.
2. The Android target had **no CI at all** before this stage, and now has a workflow that builds
   through the product's own builder with the product's own tag resolver.
3. Every Android failure so far has been in CI plumbing or in an external action — **none of them has
   yet reached the question "does the Android core build"**. That is the honest state of P004's
   blocker: the workflow is not proven, it is merely less broken than it was.
4. Six of eight workflows are manual-dispatch and were never run here.

## Remaining risks / what would unblock

**P004 (BLOCKED-EXTERNAL).** The next step is exact: run
`go list -m -versions golang.org/x/mobile` somewhere with proxy access, pick the newest version whose
`.mod` has `go 1.25` or lower, and pin both `gomobile` and `gobind` to it in the workflow — then the
`GOTOOLCHAIN` fetch of `go1.26.9` disappears and the build proceeds to the actual compile. Nothing else
in the workflow is known-broken; attempts 1 and 2 are fixed.

**Not run at all (6 workflows).** Recorded as not-run rather than green. Apple and Release additionally
need credentials this environment does not have (`BLOCKED-SECRET`), and the interop workflow needs an
Xray binary (`BLOCKED-EXTERNAL`).

**P005.** The artifact discovery uses `find`; replace with the builder's real output paths after one
successful end-to-end run.

## Method notes kept for next time

- Always pass `--repo` to `gh`; without it the parent repository's runs are what you read.
- Local green is not CI green: `verify-upstream-assumptions.sh` passed locally and failed in CI for
  two commits, because the local module cache is populated and CI's is not.
- Never `git add <directory>` while other agents are working in it.
