# v0.1.6 branch cleanup ledger

**What this document is.** The per-commit proof that each of the ten theme branches published on
`Piggy-Cat-bit-shadow/sing-box` has its work in the integration line, so that the branches are safe to
delete. It exists because `git branch --merged` is NOT that proof: the theme branches were largely
integrated by `cherry-pick -x`, which rewrites the commit id, so `testing` does not contain their
commits as ancestors even though it contains their changes.

**What it is not.** It is not a claim that the branches are worthless, and it is not a licence to delete
anything that failed to map. A branch whose every unique commit is mapped below is `SAFE_TO_DELETE`; a
branch with an `UNMAPPED` commit is not, and stays.

## The measurement

Read from the remote at the start of this round with `git ls-remote --heads origin`; every SHA below is
the live remote value, not a recalled one.

| Ref | SHA |
| --- | --- |
| `testing` | `ef83b86819c97cbe58b0397dc74af6aca5f1859d` |
| `integrate/v016-final` | `96fd0263c1be4b683bb99d6a14a369974cc13220` |
| `fix/v016-core-final-hardening-20261009` | `41365e123a7e21c9eaaa9f3d4ecceb34fac3fd76` (at round start) |

Ancestry, re-verified with git rather than assumed:

```
origin/testing (ef83b8681)
  └─ 30 commits → origin/integrate/v016-final (96fd0263c)
                       └─ 7 commits → origin/fix/v016-core-final-hardening-20261009 (41365e123)
```

`git merge-base --is-ancestor origin/testing origin/integrate/v016-final` → yes.
`git merge-base --is-ancestor origin/integrate/v016-final origin/fix/v016-core-final-hardening-20261009`
→ yes. `git rev-list --count origin/testing..origin/fix/...` → **37** at round start.

## How each unique commit was mapped

Three kinds of evidence are accepted, in this order of strength:

1. **`ANCESTOR`** — the commit itself is an ancestor of the target. Nothing to argue.
2. **`TRAILER`** — a commit in the target carries the `(cherry picked from commit <sha>)` trailer for it.
3. **`PATCH-ID`** — a commit in the target has the same `git patch-id --stable`. This is what identifies
   a cherry-pick whose trailer was lost.

A commit matching none of the three is **`UNMAPPED`** and its branch is not deletable on this evidence.

The mapping is produced by a script, not by eye. One measurement error in it is worth recording because
it changed a verdict: the first version computed a single commit's patch-id by piping its diff into
`git patch-id` and taking field 1, which yields the patch-id of the DIFF rather than the mapping from a
target commit to its own id. That marked `fix/autoredirect-output-mark` as unmapped when it is
integrated. The script now builds one patch-id index for the whole target range and looks commits up in
it.

## The ten branches

| Branch | Remote HEAD | Unique commits vs `ef83b8681` | Verdict |
| --- | --- | --- | --- |
| `ci/apple-abi-provenance` | `73462a4cd21b0b9a3dd243c91970a12181382514` | 3 | `SAFE_TO_DELETE` |
| `docs/handoff-reconciliation` | `47f49fcd7ebcc3538ac15263fa4568b2f6592db4` | 7 | `SAFE_TO_DELETE` |
| `fix/autoredirect-output-mark` | `8139f01d7758cbfba4cf6a36183b13bc9b635568` | 1 | `SAFE_TO_DELETE` — see the note below |
| `fix/row15-dns-generation` | `bcf2e1c49559dfec4a62fdbfb50fd520efa3b294` | 3 | `SAFE_TO_DELETE` |
| `fix/row39-nested-groups` | `b51c6a00c082f68c71323730596642eb691bb045` | 2 | `SAFE_TO_DELETE` |
| `fix/tun-ruleset-refs` | `b361df879e557f701139d89cd62fbf2b57c31345` | 1 | `SAFE_TO_DELETE` |
| `test/dialer-race-deterministic-gate` | `beb1b9e724d85672d6fc07b7f7c9ec48ea57502e` | 6 | `SAFE_TO_DELETE` |
| `test/dns-race-deterministic-gate` | `6abe49165d3bc8bdae5fc04283eaeaa589d3b775` | 5 | `SAFE_TO_DELETE` |
| `test/scope-close-boundary` | `3c5c84b08bd8f65a4439365f0b472175e1b64d0b` | 2 | `SAFE_TO_DELETE` |
| `test/urltest-deterministic-gate` | `827eb52587f9880a3396ec42cafd16b0be9e6227` | 4 | `SAFE_TO_DELETE` |

Every unique commit of every branch is listed below with its evidence. `→` names the commit in the
target that carries it.

### `ci/apple-abi-provenance` — 3 commits, all `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `8351c15128db` | ci(apple): tie the ABI witnesses to the real client declarations | `2f9ef7d8dad0` |
| `5c2528a744e4` | ci(apple): sweep the pinned revision for unmigrated call sites too | `668b76a2ad3f` |
| `73462a4cd21b` | ci(cronet): gate the iOS archive for undefined base:: symbols | `0dfc5e462167` |

### `docs/handoff-reconciliation` — 7 commits, all `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `f7784bb13df6` | docs(fork): reconcile phase-A integrated SHAs and handoff status | `a1093c1ba5f0` |
| `6433fca0dbcb` | docs(fork): add the next-round baseline snapshot | `2cabac19ac82` |
| `6a7b3f233a20` | ci(verify): gate the fork handoff on remotely resolvable SHAs | `d26d990a24b9` |
| `b592da582c52` | docs(fork): mark historical stage tips and add the release-candidate manifest | `94e86823dc47` |
| `ef2d0c01f341` | docs(fork): reconcile the delivery-gate row and rows 22/23/45 across twins | `5d6eb65723de` |
| `98ea14181ca6` | docs(fork): split P0-L01 into callback ownership and the RuleSet ref lifetime | `4ff87bf2817c` |
| `47f49fcd7ebc` | docs(fork): pin PHASE_B_START to the reconciliation tree tip | `7e3d0c2ad30b` |

### `fix/autoredirect-output-mark` — 1 commit, `UNMAPPED` by the automated tests, resolved by hand

| Old SHA | Subject | Evidence |
| --- | --- | --- |
| `8139f01d7758` | fix(route): make the auto-redirect output mark claim race-free and releasable | no trailer, not an ancestor, patch-id `8c4660bc759d304e8cbef4ff00c9661c461450d9` does not match |

**Resolved: the change IS present.** `cc0bc57763bf` in the target carries the identical subject, the
identical file list and the identical per-file line counts (5 files, 587 insertions, 27 deletions), and
its message documents the same three defects. The two diffs are not textually equal, and the reason is
legitimate rather than a discrepancy: `fix/tun-ruleset-refs` was integrated in between and rewrote the
surrounding region of `protocol/tun/inbound.go` (`routeAddressSet` and `releaseRouteSetCallbacks`
became `routeRuleSetRefs`, `acquireRouteSetRef` and `releaseRouteSets`), so the hunk headers and some
context lines differ while the change does not.

Rather than argue that from the diff, the CAPABILITY was checked in the trees. All four markers the
commit introduced are present and identical in the target:

| Marker | Target |
| --- | --- |
| `NetworkManager` claim is a flag plus an atomic mark, not the mark value | `route/network.go:58` `autoRedirectMarkClaimed bool`, `:59` `autoRedirectOutputMark atomic.Uint32` |
| the claim and the store are one critical section | `route/network.go:483-487` |
| `ReleaseAutoRedirectOutputMark` matched against the claim | `route/network.go:503-511` |
| the claim is released from the TUN teardown | `protocol/tun/inbound.go:119-120` (`autoRedirectMarkReleaser`), `:823-824` |
| the three test files exist | `route/auto_redirect_output_mark_test.go`, `protocol/tun/auto_redirect_mark_discard_test.go`, `protocol/tun/auto_redirect_mark_release_test.go` |

`git diff 8139f01d:route/network.go cc0bc577:route/network.go` is **empty**: that file is byte-identical
at the two commits. The one file whose content does differ is `protocol/tun/inbound.go`, and it differs
because of the later `fix/tun-ruleset-refs` work described above, not because anything from this commit
is missing. The behavioural evidence is `route/auto_redirect_output_mark_test.go`, which pins the claim,
the release, the same-value re-claim and the exclusivity of `mark = 0`, and passes on the target.

### `fix/row15-dns-generation` — 3 commits, all `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `63ed7fdad2d3` | fix(dns): give a DNS-only environment change its own generation | `ffec0df1f45f` |
| `5f4459bf4aa2` | refactor(dns): make the Darwin DNS reader's platform calls injectable | `1f02bb323372` |
| `bcf2e1c49559` | test(route): pin that a DNS-only change is not a network transition | `4b8a372abcb1` |

### `fix/row39-nested-groups` — 2 commits, both `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `8ed06a07a7a7` | fix(route): report a cyclic outbound group chain instead of walking it forever | `e12e4f3df77d` |
| `b51c6a00c082` | test(group): pin nested group resolution, attribution and interruption | `35dd509e704a` |

### `fix/tun-ruleset-refs` — 1 commit, `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `b361df879e55` | fix(tun): release the rule-set references the TUN inbound acquires | `b4ec89e56b62` |

### `test/dialer-race-deterministic-gate` — 6 commits, all `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `ee4b93c59081` | test(urltest): bound cold-path assertions by the measured warm-up | `f5b2f8c5dbb2` |
| `00fe439a51da` | test(trafficsched): derive the rate bound from the measured pace excess | `c1c6469c260d` |
| `779a7ea5d945` | build(libbox): run gomobile in an isolated working directory | `de6cc6644d9a` |
| `827eb52587f9` | test(ci): fail on generated packages polluting the module enumeration | `ffe51ca44d6c` |
| `6abe49165d3b` | test(dns): assert the race ordering as events, not as wall-clock bounds | `c274afc47c7f` |
| `beb1b9e724d8` | test(dialer): stop racing the grace window, and put the cadence out of reach | `8091b17e83ac` |

`test/dns-race-deterministic-gate` and `test/urltest-deterministic-gate` are strict prefixes of this
branch's history; their unique commits are the same list truncated, all `TRAILER`, mapped as above.

### `test/scope-close-boundary` — 2 commits, both `TRAILER`

| Old SHA | Subject | Integrated as |
| --- | --- | --- |
| `f67e0066ee85` | test(adapter): pin what Scope.Close does and does not wait for | `4541d002ee19` |
| `3c5c84b08bd8` | fix(masque,tun): release resources acquired after Scope.Close returned | `c3b4f5677a43` |

**Total: 34 unique commits across the ten branches, all accounted for.**

## Deletion procedure, and what was required before each step

Only after `origin/testing == SOURCE_SHA` holds on the live remote. For each branch, immediately before
its deletion:

1. `git ls-remote` is re-read and the branch's HEAD must equal the value recorded in this ledger. A
   different value means someone else pushed, and the branch is skipped and reported.
2. For `integrate/v016-final` and `fix/v016-core-final-hardening-20261009`:
   `git merge-base --is-ancestor origin/<branch> origin/testing` must pass.
3. For the ten theme branches: the mapping above must be complete, with no `UNMAPPED` entry.
4. `testing` is never in the deletion list.

Deletions are performed one branch at a time with the remote refs re-read between them; any drift stops
the sequence. If a deletion is refused, the branch is kept and the refusal is recorded rather than
worked around - no permission change and no branch-protection change was made or will be.

## What deleting a theme branch does and does not lose

The original commits remain reachable through this repository's reflog and through GitHub's
`refs/pull`/dangling-object retention for a period, but that is not the reason deletion is safe. The
reason is the mapping above: every unique change has a corresponding commit in the integration line,
named here by SHA. The ledger is the record of that correspondence, and it is committed BEFORE any
deletion.

## Ledger status

Branch mapping: **complete, 34/34 mapped.**

### Executed

`origin/testing` was fast-forwarded from `ef83b86819c97cbe58b0397dc74af6aca5f1859d` to
`fdd56c0e0edd6ee4026124c4755be06e04e4b62f` - a fast-forward, verified with
`git merge-base --is-ancestor` against the LIVE remote immediately before the push, with 42 commits
gained and none lost. The remote reported `ef83b868..fdd56c0e` (not a forced update).

Each branch was then re-checked against the live remote and deleted one at a time. All ten live HEADs
equalled the values recorded above, so there was no drift. Result:

| # | Branch | Live HEAD at deletion | Outcome |
| --- | --- | --- | --- |
| 1 | `ci/apple-abi-provenance` | `73462a4cd21b` | DELETED |
| 2 | `docs/handoff-reconciliation` | `47f49fcd7ebc` | DELETED |
| 3 | `fix/autoredirect-output-mark` | `8139f01d7758` | DELETED (the manual case above) |
| 4 | `fix/row15-dns-generation` | `bcf2e1c49559` | DELETED |
| 5 | `fix/row39-nested-groups` | `b51c6a00c082` | DELETED |
| 6 | `fix/tun-ruleset-refs` | `b361df879e55` | DELETED |
| 7 | `test/dialer-race-deterministic-gate` | `beb1b9e724d8` | DELETED |
| 8 | `test/dns-race-deterministic-gate` | `6abe49165d3b` | DELETED |
| 9 | `test/scope-close-boundary` | `3c5c84b08bd8` | DELETED |
| 10 | `test/urltest-deterministic-gate` | `827eb52587f9` | DELETED |

`deleted=10 skipped=0 refused=0`. Nothing was skipped for drift and nothing was refused, so no branch
had to be kept for either reason.

`integrate/v016-final` was deleted as well, after its own precondition was checked the same way:
`git rev-list --count testing..integrate/v016-final` was **0** and `integrate/v016-final..testing` was
**0** - it was not merely superseded, it was exactly contained - and its live SHA was the recorded
`96fd0263c1be4b683bb99d6a14a369974cc13220`.

### After

```
fdd56c0e0edd6ee4026124c4755be06e04e4b62f  refs/heads/testing
fdd56c0e0edd6ee4026124c4755be06e04e4b62f  refs/heads/fix/v016-core-final-hardening-20261009
```

Thirteen remote branches became two, and there is exactly one long-term development line. The
`fix/...` branch is kept, at the same commit, as the named landing point for this round's candidate -
deleting it is a cosmetic step the user can take at any time, and keeping it costs nothing.

**No permission, branch-protection or repository setting was changed to make any deletion succeed.** A
refused deletion would have been kept and reported.

### What deleting them does and does not lose

The original commits remain reachable through this repository's reflog and through GitHub's retention
of dangling objects for a period, but that is not why deletion was safe. The reason is the mapping in
this document: every unique change has a corresponding commit in the integration line, named here by
SHA, and this ledger was committed **before** the first deletion.
