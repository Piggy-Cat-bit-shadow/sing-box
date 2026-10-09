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
- the Apple product builds (IPA/DMG) are `absent` — blocked on the client source tree at `2b23330d4`;
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
