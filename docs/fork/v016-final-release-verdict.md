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
| Apple IPA / macOS DMG | see **Corrections** below — the client source **does** build at the pinned revision; the packages are `absent` because no packaging or signing decision has been taken |
| Release candidate | **not frozen** — [`v016-release-candidate-manifest.md`](v016-release-candidate-manifest.md) |
| Single-SHA acceptance pass | **has not been run** |
| Behaviour-unvalidated rows (rows 22/23/45) | `code_status` semantic/semantic/exact but `behavior_status` `not_tested`/`not_tested`/`blocked` |
| RuleSet `IncRef`/`DecRef` lifetime (S01) | see **Corrections** below — the reference pairing is no longer open on this branch |

## Corrections to superseded statements in this file

This file is a dated verdict and its prose is kept as written, because a verdict that is silently
edited is not a record. Two rows above were right when they were written and are wrong now. They are
corrected here instead of being rewritten in place, and the correction is limited to the kernel
repository: **no client repository is read, built, checked out or modified for this statement.**

| Superseded statement | Correction | Evidence |
| --- | --- | --- |
| "Apple IPA / macOS DMG — **absent** — blocked on the client source tree at `2b23330d4`" | The client source is **not** blocked: it builds at the pinned revision (`xcodebuild -scheme SFI -sdk iphoneos … CODE_SIGNING_ALLOWED=NO` and `-scheme SFM -sdk macosx …` both returned `BUILD SUCCEEDED`, exit 0). The packages are `absent` because no packaging or signing decision has been taken, and signing is by policy a local user action. **The earlier report has been corrected. Client acceptance is not in scope for the kernel hardening round that added this correction.** | `v016-supplemental-closure-report.md` §D |
| "RuleSet `IncRef`/`DecRef` lifetime (S01) — **open**" | On this branch the TUN route-set reference pairing is closed: `protocol/tun/inbound.go` pairs `acquireRouteSetRef` with `releaseRouteSets`, keeps the unregister-callback-before-`DecRef` invariant, and is pinned by real Local/RemoteRuleSet cleanup tests plus reverse mutations (`protocol/tun/ruleset_refs_test.go`). The ledger entry this row pointed at describes the state before the S01 work landed. | `protocol/tun/inbound.go`, `protocol/tun/ruleset_refs_test.go` |

Neither correction moves the verdict. The marker above stays `NOT-READY` for the reasons in the first
table, none of which either correction touches.

## What a run against an integration branch proves, and what it does not

`sh scripts/ci/verify-fork-handoff.sh --candidate-branch <ref>` resolves a candidate that is still on
an integration branch, which the default `testing` coordinate cannot do without pushing `testing` —
and pushing `testing` to make a validator green is never the answer. That flag produces a **candidate**
verification. It is not a release acceptance, and a passing run with it must never be quoted as one.

The release acceptance is a different instrument:
`sh scripts/ci/verify-release-acceptance.sh --candidate-sha <full-sha> --snapshot <dir>`, which
requires a completed, successful Actions run **at that exact SHA**, with every required job successful
and every declared artifact present with its recorded digest. It fails closed: not being able to read
the evidence is a failure, not a pass.

## Distinguishing the SHAs, because they are not interchangeable

| Coordinate | What it is | How it may be used |
| --- | --- | --- |
| candidate code SHA | a frozen code object that CI actually ran | the only thing a release ref may point at if the rule is "the released commit must have been tested" |
| evidence/report commit SHA | the later commit that records the run id | documentation. Its own tree was never tested, so it is **not** the tested candidate and must never be presented as one |
| integration branch tip SHA | where the code lives before a freeze | a build coordinate, not a tested one |
| `testing` release tip SHA | what a release is cut from | unchanged by any of this |

Writing a run id into the repository necessarily produces a **new** commit, so "all evidence shares
the HEAD SHA" and "the run id is recorded in the tree" cannot both hold for one commit. The resolution
this round adopts is the first row: freeze the candidate, run CI at it, record the run id in a later
evidence commit, and cut from the frozen candidate — never from the evidence commit.

## What would change the verdict

1. Freeze one core SHA and record it in the release-candidate manifest.
2. Get one completed CI run **at that SHA** and paste its run id, URL and real conclusion.
3. Produce and digest the shippable artifacts at that SHA (or record them `absent`/`blocked` and keep
   the verdict NOT-READY).
4. Run `sh scripts/ci/verify-fork-handoff.sh` and paste the passing output.

Until all four hold, the honest verdict stays **NOT-READY**. Nothing here is tagged, released or
signed.
