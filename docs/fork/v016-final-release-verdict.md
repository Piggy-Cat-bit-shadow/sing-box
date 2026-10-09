# v0.1.6 final release verdict — **`VERDICT: NOT-READY`**

<!-- release-verdict: NOT-READY -->

**VERDICT: NOT-READY.**

No release-ready claim has been made, and none may be made from this document while the gate below
fails. The machine-readable marker on the line above is the only claim the gate reads; the prose in
this file is explanation and can never satisfy or trip it. This file exists so the claim has exactly
one home and one precondition.

## The gate

The marker may only be changed to the ready value after this exact command exits `0` **and** its output
is pasted into the same commit that changes the marker:

```sh
sh scripts/ci/verify-fork-handoff.sh
```

The same command is the enforcement, not a suggestion: the validator reads the marker and **fails** if
it says the release is ready while

- any `final_*_sha` / `integration_final_sha` field in
  [`upstream-sync-handoff.json`](upstream-sync-handoff.json) is null although the handoff claims the
  integration is complete;
- any recorded coordinate is not resolvable from the remote (a local-only object is not evidence);
- the Markdown twin and the JSON twin disagree on the phase-A SHA;
- the release-candidate manifest is still `not frozen yet`;
- `current_candidate_core_sha` is null.

So a false ready-claim cannot be pushed without the check turning red in the same run.

## Why NOT-READY, in facts

| Fact | Value |
| --- | --- |
| Verified integration tip (`origin/testing`) | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` |
| CI runs at the integration tip | **0** (`gh run list --commit ef83b8681…` returned `[]`) |
| Newest CI run on the fork | `e2d7ac1be`, **59 commits** behind the integration tip |
| Artifacts at the integration tip | **none**; every recorded digest was built at `0fbca8546` |
| Apple IPA / macOS DMG | **absent** — blocked on the client source tree at `2b23330d4` |
| Release candidate | **not frozen** — [`v016-release-candidate-manifest.md`](v016-release-candidate-manifest.md) |
| Single-SHA acceptance pass | **has not been run** |
| Behaviour-unvalidated rows (rows 22/23/45) | `code_status` semantic/semantic/exact but `behavior_status` `not_tested`/`not_tested`/`blocked` |
| RuleSet `IncRef`/`DecRef` lifetime (S01) | **open** — see [`lifecycle-scope-resource-ledger.md`](lifecycle-scope-resource-ledger.md) P0-L01 |

## What would change the verdict

1. Freeze one core SHA and record it in the release-candidate manifest.
2. Get one completed CI run **at that SHA** and paste its run id, URL and real conclusion.
3. Produce and digest the shippable artifacts at that SHA (or record them `absent`/`blocked` and keep
   the verdict NOT-READY).
4. Run `sh scripts/ci/verify-fork-handoff.sh` and paste the passing output.

Until all four hold, the honest verdict stays **NOT-READY**. Nothing here is tagged, released or
signed.
