# v0.1.6 release-candidate manifest — **`not frozen yet`**

**Status: NOT FROZEN.** No release candidate exists. Every field below is deliberately unset.

This is the **only** document in which a release-candidate (RC) SHA may be declared, and the only place
a single acceptance pass against a single SHA may be recorded. Every other document — including
[`v016-release-closure-report.md`](v016-release-closure-report.md),
[`v016-release-integration-ledger.md`](v016-release-integration-ledger.md) and
[`upstream-sync-handoff.md`](upstream-sync-handoff.md) — records **historical stage tips and
integration coordinates**, which are not release SHAs.

## Why this file is empty

The stage tips (`c7a1ef193`, `429265376`, `e610e7660`, `912ed1efa`), the verified integration tip
(`ef83b8681`) and the artifact-build coordinate (`0fbca8546`) all exist and are all real. None of them
is a release candidate, because:

- no CI run exists at the integration tip (`ef83b8681`) or at the phase-A start (`912ed1efa`); the
  newest run on the fork is at `e2d7ac1be`, **59 commits** behind;
- no artifact exists at the integration tip; the recorded digests were produced at `0fbca8546`;
- **corrected in the supplemental round:** the Apple product **does** build at the pinned client
  revision (`2b23330d4`) — `xcodebuild -scheme SFI -sdk iphoneos … CODE_SIGNING_ALLOWED=NO` and
  `-scheme SFM -sdk macosx …` both return `BUILD SUCCEEDED`, exit 0. The earlier note in this file said
  IPA/DMG were blocked on the client source tree; that was wrong. They are `absent` because no
  packaging or signing decision has been taken — signing is by policy a local user action — not because
  the source does not compile. See `v016-supplemental-closure-report.md` §D;
- no acceptance pass has been run against a single frozen SHA.

Freezing a candidate is an **act**, not an edit: it requires a real SHA that has been built, tested and
recorded. Writing one in advance would be inventing a fact.

## Manifest — to be filled exactly once, at freeze time

| Field | Value | How it must be produced |
| --- | --- | --- |
| `release_candidate_core_sha` | **not frozen yet** | `git rev-parse` of the frozen revision; must resolve from the remote, not merely locally |
| `frozen_at_utc` | **not frozen yet** | the UTC instant the freeze was performed |
| `frozen_by` | **not frozen yet** | the integrator who froze it |
| `phase_a_start_sha` | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` | already verified; recorded here for traceability only, **not** as the candidate |
| `integration_final_sha` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` | already verified; recorded here for traceability only, **not** as the candidate |
| `acceptance_ci_run` | **not frozen yet** | the URL **and** the run id of one completed run at `release_candidate_core_sha`; a run at any other SHA is not admissible |
| `acceptance_ci_conclusion` | **not frozen yet** | the real conclusion string; `success` is not assumed |
| `behavior_status` | **not frozen yet** | `tested` / `fail` / `blocked` / `not_tested` — per the fact model in `upstream-sync-handoff.md` §0 |
| `artifact_status` | **not frozen yet** | an actual `sha256` per shippable artifact, or `absent`, or `blocked` |

## Rules that bind the freeze

1. **No SHA, run id or PASS may be invented.** A field may only be filled from a command output that is
   pasted next to it in the same commit, or it stays `not frozen yet`.
2. **One acceptance, one SHA.** Evidence from several SHAs may be cited as history; it may not be
   stitched into a single acceptance.
3. **The freeze is gated.** `scripts/ci/verify-fork-handoff.sh` must exit `0` on the freeze commit, and
   the verdict in [`v016-final-release-verdict.md`](v016-final-release-verdict.md) may not move to
   `RELEASE-READY` while a single row above is `not frozen yet`.
4. **A freeze is reversible only by a new freeze.** Superseded values are kept in a dated history table
   below; they are never overwritten in place.

## Freeze history

| # | `release_candidate_core_sha` | `frozen_at_utc` | acceptance CI run | outcome |
| --- | --- | --- | --- | --- |
| — | *(none — never frozen)* | — | — | — |

---

## Post-supplemental integration tip — **not a release candidate**

The supplemental round (S01–S08, Row 15, Row 39, plus the `docs/schema.json` debt) is integrated on
branch `integrate/v016-final`. Its tip is recorded here for traceability **only**, and deliberately
**not** as `release_candidate_core_sha`:

| Field | Value |
| --- | --- |
| `post_supplemental_integration_tip` | branch `integrate/v016-final` on `Piggy-Cat-bit-shadow/sing-box`; the tip is whatever `git rev-parse origin/integrate/v016-final` returns — a branch tip can move, so no literal SHA is written here |
| `is_release_candidate` | **no** |
| `acceptance_ci_run` | **none** — no GitHub Actions run exists at this tip, so the manifest's own admission rule is not satisfied |
| `device_status` | not run; the user explicitly directed that no simulator testing be performed |
| `artifact_status` | `absent` at this tip. The measured digests in `v016-supplemental-closure.json` were produced at `ef83b8681` (Apple framework) and `c35faabf4` (Android); the Android `version.properties` `coreCommit` has deliberately **not** been moved to this tip, because the order requires that update to happen only after the Core freeze |
| `local_verification` | 21+ integrated commits; `-race` green over `./protocol/tun/... ./protocol/masque/... ./protocol/group/... ./route/... ./adapter/...`; tagged full-suite runs 76 ok/0 FAIL (S01 tree, load 17–24) and 77 ok/1 FAIL (integration, load 710, the one failure being the pre-existing `transport/masque` complexity gate) |
| `known_open` | the uTLS fingerprint matrix and the Xray/REALITY reference matrix were not started; the cronet iOS archive rebuild is `BLOCKED_TOOLCHAIN`; `transport/masque TestTheOwnershipScanIsLinearHereToo` is a pre-existing load-sensitive gate |

**Verdict: `NOT-READY`.** The software-controllable items of both orders that were reachable in this
environment are done and evidenced; what remains is external (CI execution, device runs, the cronet
build pipeline) or explicitly out of this round's scope (uTLS/reference matrices). No tag, Release or
signature was created.
