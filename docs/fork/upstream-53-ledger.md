# Upstream-53 adjudication ledger — every `SagerNet/sing-box testing` commit absent from this fork

Stage-1 inventory deliverable. **Read-only analysis**: no production code, test, workflow or
dependency was modified by this stage, and nothing was cherry-picked.

| | |
| --- | --- |
| Workspace | `/tmp/s1-up` (detached worktree, branch `docs/upstream-inventory`) |
| Fork revision analysed | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` (= `origin/testing`) |
| Upstream revision analysed | `6afeff4c0f7123b5782f888812e96b8c82c7b699` (= `upstream/testing`, `SagerNet/sing-box`) |
| Merge base | `7a3d4e4a8e71bd7fa824959efdb57b4f39738802` |
| Divergence | upstream-only **53**, fork-only **1469** |
| Upstream SHA moved during the run? | **No.** Re-fetched 2026-10-09; `git rev-parse upstream/testing` still `6afeff4c0f71…`, so the work order's frozen snapshot is still the live tip. |
| Raw evidence | `docs/fork/upstream53.tsv`, `presence-matrix.tsv`, `line-presence.tsv`, `tip-parity.tsv`, `patchid-match.tsv`, `missing-lines.txt`, `percommit-merged.tsv`, `percommit-different-files.txt`, `upstream-diffs/*.diff` |
| Probes | `docs/fork/applycheck.sh`, `line-presence.sh`, `tip-parity.sh`, `missing-lines.py` |

**What this ledger is.** The adjudication inventory another stage acts on: for all 53 upstream-only
commits, what the commit actually changes, whether the fork already has that behaviour and *where*,
what would be needed if not, which fork contracts are in the blast radius, and a P0-first action list.

**What it is not.** It is not `git rev-list` chasing zero-behind, and it is not a defect count. Read §1
before reading the table: **the 53 are not 53 features, and the fork is not 53 fixes behind.**

---

## 1. The headline fact: the 53 are a rebase, and almost all of it already landed

Measured, not asserted:

```
$ git log --reverse --format='%H%x09%aI%x09%cI%x09%s' origin/testing..upstream/testing
```

* **Every one of the 53 has a committer timestamp inside one 84-second window on 2026-10-09**:
  `2026-10-09T12:36:02+08:00` … `2026-10-09T12:37:26+08:00`. Not one commit has a committer date
  outside it.
* **The author dates span 2026-09-01 → 2026-10-09.** Only 3 of the 53 (rows 15, 16, 53) have
  author date == committer date; the other 50 carry an author date up to five weeks older.
* The parent of the first of the 53 is the merge base itself (`git rev-parse 6e3c86f51816^` →
  `7a3d4e4a`), so upstream replayed the whole set onto the shared base in that window.

So upstream rewrote a month of `testing` onto `7a3d4e4a` on 2026-10-09. The fork, which forked from
the *pre*-rewrite lineage, still carries the original commits — the fork's own copies of these same
subjects are committed `2026-09-23` … `2026-10-03` (e.g. `540fe7579`, `99412f03c`, `07512b109` all
`2026-10-02T18:00:09+08:00`).

Content-addressed proof, not subject matching — `git patch-id --stable` on each upstream commit
against the patch-ids of all 4242 fork-reachable commits:

```
$ git cherry -v origin/testing upstream/testing     # + = no equivalent in the fork, - = equivalent exists
+ 6e3c86f51816 …    (11 commits)
- …                 (42 commits)
```

| split | count | meaning |
| --- | --- | --- |
| **Re-committed work the fork already has** | **42 / 53** | an identical patch (same `patch-id`) is reachable from the fork tip |
| **No patch-identical precedent** | **11 / 53** | rows 01, 11, 12, 13, 14, 15, 16, 18, 51, 52, 53 |

Of those 11, **four are not code at all**: row 16 and row 53 are `Bump version` bookkeeping (client
gitlinks + `docs/changelog.md`), row 14 is a CI tag-expression edit in a workflow file this fork does
not have, and row 13 is a `sing-tun` version bump whose behaviour the fork's newer pin already
contains. The code-bearing remainder is 01, 11, 12, 15, 18, 51, 52 — and of *those*, row 51 is present
in full (452/452 added lines, absorbed by the fork's own merge `626542e5b`), rows 12 and 18 are
present in re-expressed form, row 11 is packaging the fork does not ship, row 01 is present in the
core and blocked in the client (§5.1), and **row 52 is the only row that is straightforwardly absent**
(and it is Stage 1's).

**Consequence for the next stage's size:** the work is not "port 53 commits". It is: one genuinely
missing behaviour that collides with a fork-owned dependency (row 15), one missing filter (row 52,
Stage 1), three dependency-pin decisions (rows 02, 13, 15), a handful of verification passes over rows
the fork re-implemented rather than copied (01, 12, 18, 20, 32, 39, 47), and one schema regeneration
(32). Everything else is already in the tree.

---

## 2. Git fact collection (work order §1.1), re-measured

Run in `/tmp/s1-up`; `origin` = `Piggy-Cat-bit-shadow/sing-box`, `upstream` = `SagerNet/sing-box`.

| command | result |
| --- | --- |
| `git status --porcelain=v1 -uall` | empty (clean worktree) |
| `git worktree list --porcelain` | `…/sing-box` (testing), `/private/tmp/s1-life` (fix/lifecycle-stage1), `/private/tmp/s1-up` (detached) |
| `git remote -v` | `origin git@…:Piggy-Cat-bit-shadow/sing-box.git`, `upstream https://github.com/SagerNet/sing-box.git` |
| `git rev-parse HEAD` | `912ed1efad265d8a8f56aaabcabc8f7b171c2baa` |
| `git fetch upstream testing` | no new objects; tip unchanged |
| `git rev-parse upstream/testing` | `6afeff4c0f7123b5782f888812e96b8c82c7b699` |
| `git merge-base origin/testing upstream/testing` | `7a3d4e4a8e71bd7fa824959efdb57b4f39738802` |
| `git rev-list --left-right --count origin/testing...upstream/testing` | `1469  53` |
| `git log --reverse --format='%H%x09%aI%x09%cI%x09%s' origin/testing..upstream/testing` | 53 rows → `docs/fork/upstream53.tsv` |
| `git diff --name-status origin/testing upstream/testing` | **A 6** (all `.github/workflows/*`), **D 940** (fork-only files), **M 220** |

Two facts worth carrying forward:

1. **The fork is not missing files.** Exactly six paths exist upstream and not in the fork, and all
   six are upstream's GitHub workflows, which the fork deliberately replaced with its own eight
   (`client-apple.yml`, `android-core-arm64.yml`, `interop-xray.yml`, `verify.yml`, …).
2. **Dependency parity is nearly complete.** `diff` of the two `go.mod`s (masks: `replace` lines and
   comments) leaves four rows: `sing-quic`, `sing-shadowsocks`, `sing-tun`, and `blake3`
   (direct in the fork, indirect upstream). Everything else — `cronet-go`, `sing-anytls`,
   `sing-usbip`, `quic-go`, `utls` — is at the same required version, with the fork adding audited
   `replace` directives on top.

---

## 3. Instruments, and what each one can and cannot prove

Four independent probes, all read-only, all reproducible from the scripts in `docs/fork/`:

| probe | question | output |
| --- | --- | --- |
| `applycheck.sh` | does each upstream hunk reverse-apply to the fork tip? | `presence-matrix.tsv` (722 rows: PRESENT / ABSENT / UNCLEAR) |
| `line-presence.sh` | are the commit's own added lines in the fork tip's file? | `line-presence.tsv` |
| `tip-parity.sh` | is the fork tip's file byte-identical to the upstream tip's file? | `tip-parity.tsv` (452 paths) |
| `missing-lines.py` | which added lines are absent after whitespace normalisation? | `missing-lines.txt` |
| `git patch-id --stable` | does an identical patch exist anywhere in the fork's history? | `patchid-match.tsv` |

**Limits, stated so the table is read correctly** (two of these were found by the probes failing on
their own first run, which is why they are written down):

* *A commit's own added line can be legitimately absent.* A later upstream commit in the same 53 may
  delete it. `tip-parity.tsv` is the control: a path that is byte-identical at both tips is at parity
  whatever `missing-lines.txt` says about an intermediate commit.
* *gofmt column alignment is not a difference.* The first `line-presence.sh` run reported 0/7 present
  for `transport/v2raygrpclite/conn.go` because macOS `awk` does not expand `\t` inside a bracket
  expression, and the second reported false gaps because struct-literal fields are aligned to
  different columns. `missing-lines.py` normalises internal whitespace; the residuals are then read
  by hand against the production file.
* *A file absent from both tips is not a gap.* 22 of the 452 paths are absent at *both* tips (files
  upstream itself later deleted, e.g. `transport/openvpn/device_stack.go`, and the fork-only
  `clients/*` gitlinks). They are reported `NEITHER` in `tip-parity.tsv`.
* *pathspec safety.* The first `tip-parity.sh` run `cd`-ed one level short, so every pathspec matched
  nothing and every path came back `IDENTICAL`. All three shell probes now resolve the repository root
  with `git rev-parse --show-toplevel`.

**Headline probe result:** of the 452 paths the 53 commits touch, **286 are byte-identical between the
fork tip and the upstream tip**, 143 differ (the fork's own evolution), 22 are transient, and 1
(`.github/workflows/build.yml`) exists only upstream.

---

## 4. The ledger — all 53 rows

Vocabulary (one and only one per row): `PATCH-EQUIVALENT`, `SEMANTIC-EQUIVALENT`, `PARTIAL`,
`MISSING`, `CONFLICT`, `NOT-APPLICABLE`, `BLOCKED`.

Evidence columns: `pid` = `patch-id`-identical fork commit (short SHA); `ac` = reverse-apply
PRESENT/files; `lp` = added lines present/total (whitespace-normalised); `tip` = paths byte-identical
to the upstream tip/total. Owner `A` = Phase-A/Stage-1 scope (lifecycle, Scope, resource ownership);
`B` = this inventory's scope.

| # | SHA | subject | area | owner | class | evidence |
| ---: | --- | --- | --- | --- | --- | --- |
| 01 | `6e3c86f51816` | Use screen state to end device pause on iOS | Apple/Power | A | **PARTIAL** | pid —; ac 2/5; lp 27/37; tip 2/5. Core present (`RecordScreenState`, `common/runtimecoord/platform_events.go`), client-side blocked (§5.1) |
| 02 | `f95aa6ac11d0` | Update dependencies | deps | B | **CONFLICT** | pid `540fe75798`; ac 0/2; lp 0/18; tip 0/2. Tree deliberately differs on 3 modules (§5.2) |
| 03 | `79fc394d671c` | documentation: Update Apple App Store link | docs/Apple | B | **NOT-APPLICABLE** | pid `99412f03cd`; the added line is present; file differs because the fork keeps its own Source/Releases links |
| 04 | `a0d775ea6610` | Fix zero UDP checksum | UDP/sing-tun | B | **SEMANTIC-EQUIVALENT** | pid `309434d3ca`; commit is a `sing-tun` bump only; the fork's base equals the upstream tip's `gtcpip/` byte-for-byte (§5.4) |
| 05 | `52f9bad034d2` | Fix protocol input validation | protocol/security | B | **SEMANTIC-EQUIVALENT** | pid `07512b1093`; ac 14/22; lp 124/164; tip 13/22. Guards present incl. the naive cached-conn behaviour, re-expressed (§5.5) |
| 06 | `bff5acf292d8` | Handle connected UDP EOF on BSD | UDP/BSD | B | **PATCH-EQUIVALENT** | pid `ff02d3d157`; `common/dialer/udp_conn.go` byte-identical at both tips; `default.go` 9/9 lines |
| 07 | `a364ff4794f0` | Remove unimplemented hot reload from managers | lifecycle | A | **SEMANTIC-EQUIVALENT** | pid `16c898a82f`; ac 8/18; lp 31/65. No `Reload(` remains in any `adapter/*/manager.go` (§5.7) |
| 08 | `a691a4402375` | Refactor lifecycle to scoped cleanup | lifecycle | A | **SEMANTIC-EQUIVALENT** | pid `813ddfa98a`; lp 1512/1584 (95.5 %); tip 58/115; `adapter/lifecycle.go` 72/72. Fork owns a stronger Scope (§5.8) |
| 09 | `f9fcb8964f0b` | Fix usage and cache files overwritten when loading fails | persistence | B | **PATCH-EQUIVALENT** | pid `9593bc1069`; lp 34/34; files are `service/ccm`, `service/ocm`, `service/ssmapi` (usage counters, not cachefile) |
| 10 | `02537831e188` | Move auto-redirect and bridge index out of constructors | lifecycle/resources | A | **SEMANTIC-EQUIVALENT** | pid `b93f56a7a0`; lp 38/57; tip 2/5. Fork's constructor path is the post-move shape (§5.10) |
| 11 | `67fb235ee802` | Add roothide package to iOS jailbreak release | Apple packaging | B | **NOT-APPLICABLE** | pid —; ac 0/3; patches `Makefile` + `build.yml`, neither shipping a jailbreak `.deb` in this fork (§5.11) |
| 12 | `80c11714105b` | tailscale: Fix SSH auth banners never sent | Tailscale/SSH | B | **SEMANTIC-EQUIVALENT** | pid —; lp 21/23; `SendAuthBanner` + pre-auth flow + rejected-path log all present (§5.12) |
| 13 | `194ebd18b64b` | tun: Fix inconsistent DNS mode behavior without auto_route | TUN/DNS | B | **CONFLICT** | pid —; docs-only in this repo + `sing-tun` bump to `…20261007151649`; fork's pin is `…20261007151655` (§5.13) |
| 14 | `1a773a425a8e` | Exclude USB/IP from legacy macOS build | macOS/build | B | **NOT-APPLICABLE** | pid —; touches only `.github/workflows/build.yml`, which the fork does not have |
| 15 | `78d44d52d959` | Reset network on DNS server changes | Apple/DNS | B | **CONFLICT** | pid —; ac 0/4; lp 24/85; tip 0/4. Behaviour genuinely absent *and* needs a `sing-tun` capability the fork's fork does not carry (§5.15) — **P0** |
| 16 | `7054cac51244` | Bump version (1.14.3) | version/docs | B | **NOT-APPLICABLE** | pid —; 3 gitlinks + changelog; adopting upstream's client revisions would regress the fork's clients |
| 17 | `9da9678bae29` | Format plural list options as arrays | schema/API | B | **PATCH-EQUIVALENT** | pid `978d12a7eb`; lp 223/223; tip 9/12 (remainder is fork option fields) |
| 18 | `3f7f7eb3c09d` | Implement fully functional auto redirect for Android | Android/TUN | B | **SEMANTIC-EQUIVALENT** | pid —; lp 625/670; tip 11/21. Platform auto-redirect present incl. `redirect_platform_linux.go`; field rename only (§5.18) |
| 19 | `457105107907` | Migrate anytls into our own library | AnyTLS/deps | B | **PATCH-EQUIVALENT** | pid `d541b8cb8b`; both trees require `sing-anytls v0.0.0-20260928104022-580984e4d8cb` verbatim |
| 20 | `e7399fd98147` | Load rule-sets through mmap on iOS | SRS/memory | B | **SEMANTIC-EQUIVALENT** | pid `ef89f5298c`; lp 818/831; tip 15/16. mmap present; the CIDR writer uses the fork's `Prefixable.Build` (§5.20) |
| 21 | `c7fe73c25710` | Buffer cache file writes | cache | B | **SEMANTIC-EQUIVALENT** | pid `5fa3d77095`; lp 472/485; tip 7/15. Fork has its own cachefile work on the same files |
| 22 | `efe4db93324b` | Close idle connections of unreferenced outbounds and DNS servers | idle/lifecycle | A | **PATCH-EQUIVALENT** | pid `fbf7738a92`; lp 10/14; the only absent line is a compile-time interface assertion the fork does not need |
| 23 | `17e950e74cc0` | Improve idle connection management | idle/lifecycle | A | **SEMANTIC-EQUIVALENT** | pid `4aaa2372cb`; lp 466/481; tip 16/26. The 4 absent lines are the `idleFlushed` shortcut; the fork uses `SetKeepIdleConnections` + the walk (§5.23) |
| 24 | `f3e721980c69` | Improve process search | process | B | **PATCH-EQUIVALENT** | pid `afbbb49b4d`; lp 135/137; tip 12/19 |
| 25 | `a4d994a0b0c9` | Report every process sharing a socket in Linux process search | Linux/process | B | **PATCH-EQUIVALENT** | pid `9b93694f66`; both paths byte-identical at both tips (tip 2/2) |
| 26 | `fd26ea8578f9` | Use screen state to end device pause on iOS (follow-up) | Apple/Power | A | **PATCH-EQUIVALENT** | pid `7d597e56af`; pure deletion of 5 lines from `route/reference.go`; no added lines to check |
| 27 | `7632cdab9aae` | Add go TUN stack | TUN/sing-tun | B | **SEMANTIC-EQUIVALENT** | pid `126a82483b`; lp 622/719; tip 11/27. Ported deliberately; `docs/fork/upstream-sync-2026-10.md` §7.2 records the hunk-by-hunk pass |
| 28 | `5f404b8c6f5c` | Remove dependency on gVisor | TUN/deps | B | **SEMANTIC-EQUIVALENT** | pid `f857f08147`; tip 34/66 + 11 transient. gVisor retired with hard gates (§5.28) |
| 29 | `10dabb8d1271` | Add tailcat support | Tailcat | B | **SEMANTIC-EQUIVALENT** | pid `fced86f1f1`; lp 2714/2725; tip 27/39; one `docs/schema.json` line outstanding |
| 30 | `9ba85a15fe6b` | Fix auto redirect DNS hijack to local address with iptables | Linux/TUN | B | **PATCH-EQUIVALENT** | pid `0273d2aa7a`; only `test/go.mod` differs (fork test-module pins) |
| 31 | `38b7a586b568` | Resolve Windows connection owners without scanning the TCP table | Windows/process | B | **PATCH-EQUIVALENT** | pid `18a29e58e8`; the single path is byte-identical at both tips |
| 32 | `d0698c55a8c9` | Validate IP addresses and prefixes in JSON schema | schema | B | **PARTIAL** | pid `f66b914616`; lp 268/284; tip 5/6. Runtime types identical (`*badoption.Prefixable`); `docs/schema.json` not regenerated (§5.32) |
| 33 | `8feb0ec263e5` | Fix DNS sniffer matching non-DNS packets | DNS/sniff | B | **PATCH-EQUIVALENT** | pid `47ce7ddee7`; lp 63/63; the sniffer path is byte-identical at both tips — the fork's sniff work is elsewhere (§6) |
| 34 | `6f6d43b12a33` | Fix Android auto-redirect routing | Android/TUN | B | **PATCH-EQUIVALENT** | pid `ab287d2fc4`; lp 3/3; `protocol/tun/inbound.go` differs as a whole (fork's own TUN inbound) but all three added lines are present |
| 35 | `1a6b6615c6e5` | Rewrite HTTP proxy protocol | HTTP/H1-H3 | B | **CONFLICT** | pid `deeeb09a2c`; lp 4392/4865; tip 23/49. The fork owns 84 files and 54 tests here against upstream's 20 — never apply wholesale (§5.35) |
| 36 | `46a897c5d123` | Fix FakeIP storage consistency with buffered cache file writes | FakeIP | B | **PATCH-EQUIVALENT** | pid `bf86de22ef`; lp 52/52; tip 1/4 |
| 37 | `e2a8d9c85e5a` | Add MASQUE support | MASQUE | B | **SEMANTIC-EQUIVALENT** | pid `e22cd54061`; lp 3937/4184; tip 19/53 + 9 transient. Fork's MASQUE is a superset (§5.37) |
| 38 | `1b226006e64d` | Add full certificate SHA-256 pinning for TLS | TLS/security | B | **PATCH-EQUIVALENT** | pid `3a7f1cc54e`; lp 521/521; tip 16/19 |
| 39 | `41ef639b548f` | Fix outbound group resolution and interruption for nested groups | group/URLTest | B | **PARTIAL** | pid `6231b40d7c`; lp 170/190; tip 3/13. `resolveOutbound` chain + `LoadURLTestHistory(RealTag(...))` absent; fork's group code differs (§5.39) — **P0** |
| 40 | `9a0ff4167579` | Fix HTTP/2 extended CONNECT with Go 1.27 | HTTP2/toolchain | B | **NOT-APPLICABLE** | pid `366fc15f38`; lp 90/93; the change is `//go:build go1.27` gated and the toolchain is `go1.25.5` (§5.40) |
| 41 | `7f7c7ae11a38` | Fix AnyTLS splitting UDP packets into multiple frames | AnyTLS | B | **PATCH-EQUIVALENT** | pid `5d3be1a8df`; both trees require the same `sing-anytls` revision |
| 42 | `e8d26b0f75e9` | Fix bridge forwarding with auto-redirect | Bridge/TUN | B | **SEMANTIC-EQUIVALENT** | pid `558e8d17cb`; lp 237/239; tip 3/9 |
| 43 | `9ea795798378` | Use Prefixable for ip_cidr rule options | routing/SRS | B | **PATCH-EQUIVALENT** | pid `c771ae6f08`; lp 60/60; tip 8/10 |
| 44 | `530e3aed7aac` | Add dns_server_address and dns_search_domain rule items | routing/DNS | B | **SEMANTIC-EQUIVALENT** | pid `3f8c58b85c`; lp 640/645; tip 14/24. Fields present; 4 lines in `dns/transport/dhcp` are the fork's variant |
| 45 | `c6d5bafa3630` | Fix on-demand endpoint resume | lifecycle/endpoint | A | **PATCH-EQUIVALENT** | pid `dd19d1cb6c`; lp 19/19; ac 5/5 PRESENT |
| 46 | `7c4516a570c0` | Remove shared field defaults from MASQUE docs | MASQUE/docs | B | **PATCH-EQUIVALENT** | pid `9aa7eab16a`; all 4 doc paths byte-identical at both tips |
| 47 | `1e157350b789` | Fix per-destination backpressure to endpoints | Tailscale/bridge | B | **SEMANTIC-EQUIVALENT** | pid `1479dafb71`; lp 445/544; tip 11/27. `UDPMapping`/`UDPFiltering`/`UDPNATMax`/`PacketFrontHeadroom`/`ICMPTimeout`/`InterfaceFinder` all present in the fork's VPN endpoints (§5.47) |
| 48 | `6ef3dbc61078` | Update naiveproxy to v154.0.8037.49-2 | Naive/deps | B | **PATCH-EQUIVALENT** | pid `5bd09951e4`; `.github/CRONET_GO_VERSION` identical (`4d18a60dc3a8…`); the fork adds an audited `replace` (§6) |
| 49 | `5802f1f71990` | Fix protocol input validation (follow-up) | SRS/AnyTLS | B | **PATCH-EQUIVALENT** | pid `f5f6a8d095`; lp 26/26 |
| 50 | `a2b0923e0187` | Fix Xcode build cache reuse across package updates | Apple/CI | B | **PARTIAL** | pid `900a9f5e29`; patches `.github/workflows/build.yml`, absent here; the fork's `client-apple.yml` caches Go modules only (§5.50) — CI-time only, no product impact |
| 51 | `df8e2edfd587` | Rework forward NAT with UDP mapping and fragment support | NAT/UDP | B | **SEMANTIC-EQUIVALENT** | pid —; lp 452/452; ac 24/24 PRESENT; absorbed by the fork's merge `626542e5b` |
| 52 | `69601481fd36` | Ignore closed and canceled errors in scope cleanup | lifecycle | A | **MISSING** | pid —; ac 0/1 ABSENT; lp 0/6; `adapter/lifecycle.go` differs from upstream exactly here (§5.52) |
| 53 | `6afeff4c0f71` | Bump version (1.15.0-alpha.11) | version/docs | B | **NOT-APPLICABLE** | pid —; `docs/changelog.md`; the fork versions itself and must not adopt upstream's release numbers |

Class totals: **PATCH-EQUIVALENT 20 · SEMANTIC-EQUIVALENT 18 · PARTIAL 4 · CONFLICT 4 · MISSING 1 ·
NOT-APPLICABLE 6.** No row is `BLOCKED` on external hardware — the device-only items are recorded as
PARTIAL with the device step named.

---

## 5. Row notes — the rows that are not simply "already there"

### 5.1 Row 01 — iOS screen state, core present, client blocked (`PARTIAL`, owner A)

`constant/os_not_tvos.go` and `constant/os_tvos.go` are byte-identical at both tips; the power-report
plumbing is present (`service/powerreport/record.go` 2/2, `recorder.go` 7/7). The 10 absent lines are
all in `experimental/libbox/command_server.go`, and they are upstream's *implementation* of the
mapping (`instance.Box().CloseIdleConnections()`, `instance.PauseManager().DevicePause()`,
`if !C.IsAndroid`). The fork implements the same policy one level up, in
`common/runtimecoord/platform_events.go` (screen axis + app-foreground axis, coalescing, statistics),
and its command server exposes `RecordScreenState` with the comment at
`experimental/libbox/command_server.go:344`. **The fork's own comment states the pinned Apple client
revision does not call it** (`docs/fork/apple-screen-state-observer.md`).

*What would resolve it:* a device run that proves the client sends the screen fact; without the client
there is nothing to adopt from this commit. Core side: no change needed.

### 5.2 Row 02 — "Update dependencies" is not one change but three pins (`CONFLICT`)

`git patch-id` says the fork applied this patch historically (`540fe75798`). The current tree
deliberately differs on exactly four lines — verified by diffing the two `go.mod`s:

| module | fork | upstream tip | fork's reason (from `go.mod` comments / `docs/fork/`) |
| --- | --- | --- | --- |
| `sing-quic` | `v0.7.2-0.20260929152029-258509488380` | `v0.7.2-0.20261002084117-75c3ac4fa12b` | fork `sing`/QUIC pairing |
| `sing-shadowsocks` | `v0.2.9-0.20260929152116-0a3456819ce7` | `v0.2.9-0.20260929204512-65740e0f0e3e` | same revision family |
| `sing-tun` | `v0.9.7-0.20261007151655-7539c9855f19` | `v0.9.7-0.20261009022811-5c2edb183cc9` | **replaced** by `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27` |
| `blake3` | direct require | indirect | fork promotes it (VLESS) |

*Blast radius:* every network path. *Rule for the next stage:* never take this commit as a unit; take
the modules one at a time, and for `sing-tun` read §5.15 first.

### 5.4 Row 04 — zero UDP checksum is a dependency fact, and the fork is at parity

The commit changes only `go.mod`/`go.sum`: it moves `sing-tun` to
`v0.9.7-0.20260928080829-8ab0e83967b4`. The fork's pin is 9 days newer, and — the decisive
comparison — `diff -rq` of the fork's sing-tun base against **upstream's final** revision
(`5c2edb183cc9`) differs in only four paths: `dnsinfo/`, `monitor_darwin.go`, `monitor_shared.go`,
`monitor_windows.go`. `gtcpip/` including `header/udp.go` and `checksum/` is identical. So whatever
upstream shipped for zero checksum, the fork has.

### 5.5 Row 05 — the naive cached-connection fix is re-expressed, not missing

`missing-lines.txt` reports 10 of 14 added lines in `protocol/naive/inbound.go` as absent, including
`bufio.NewCachedConn`. Read against production code, the fork does the same job differently:

* `protocol/naive/inbound.go:653` hijacks and wraps: `conn = &hijackedConn{Conn: conn, reader: bufferedReadWriter.Reader}`,
* `protocol/naive/inbound_conn.go:526` — `hijackedConn.Read` drains `c.reader` first and only then
  reads the socket, with `Upstream()` exposed so unwrappers still reach the real connection.

The surrounding comment names the reference (`klzgrad/forwardproxy`) and the fork's reason for the
reader-first form. Behaviourally that is the same contract the upstream fix protects: bytes the HTTP
server buffered past the CONNECT headers are delivered first. `protocol/tailscale/tailssh/server.go`
(3/3) and `common/sniff/quic.go` (4/4) are present too. *Residual risk:* none identified; a
first-packet test on the naive inbound would close it.

### 5.7 / 5.8 / 5.10 / 5.23 — the lifecycle rows are Stage 1's, and the fork evolved past them

* Row 07: no `func (m *Manager) Reload` and no `Reload(` call remains in `adapter/` — the fork's Scope
  refactor deleted the same machinery upstream deleted, plus the legacy file upstream also deleted
  (`adapter/lifecycle_legacy.go` is absent at both tips).
* Row 08: 1512/1584 added lines present, `adapter/lifecycle.go` 72/72, and 58 of 115 paths are still
  byte-identical to the upstream tip — the fork refactored further rather than diverging away.
* Row 10: the absent `protocol/tun/inbound.go` lines are the *pre*-move shape (`enableAutoRedirect`
  field, index allocation in `NewInbound`).
* Row 23: the absent 4 lines are the `idleFlushed` boolean + eager `CloseIdleConnections()` on device
  pause; the fork instead threads `devicePaused` into the reference walk
  (`route/reference.go:304,329,375-385`) and drives `SetKeepIdleConnections`, with a comment stating
  that `CloseIdleConnections` is reserved for DEEP_IDLE / pause / memory-pressure paths.

Stage 1 owns the verdict on these four; this ledger records that no upstream *behaviour* is missing
from them as far as reading, line-probing and tip-parity can tell.

### 5.11 Row 11 — roothide is packaging this fork does not ship (`NOT-APPLICABLE`)

The commit edits `Makefile` (a `ghr` upload line for `SFI-$VERSION-iphoneos-arm64e.deb`) and
`.github/workflows/build.yml` (copying the `arm64e` deb into `dist`). The fork has no `build.yml`, and
`Makefile` has no `build_ios_deb`/`upload_ios_deb` target: the fork's Apple products are built by
`client-apple.yml`/`client-macos.yml` and signed locally, not distributed as jailbreak `.deb`s.
*If the user ever ships a jailbroken build, this row becomes relevant; today nothing consumes it.*

### 5.12 Row 12 — Tailscale SSH banners are present (`SEMANTIC-EQUIVALENT`)

`protocol/tailscale/tailssh/server.go` carries `SendAuthBanner` (line 283), the pre-auth connection
flow (`preAuthConn`, lines 259-271), the rejected-path log (line 308) and the comment at line 321
explaining that `SendAuthBanner` is valid for the whole pre-auth phase. The two "absent" lines are
formatting variants of the same statements. *What would resolve it:* the authorisation/unauthorised
banner test the work order asks for; it is a test, not a port.

### 5.13 Row 13 — TUN DNS mode is a dependency change; the docs are the only local delta (`CONFLICT`)

Upstream moves `sing-tun` to `…20261007151649-0e9e4a586ece` and documents that `hijack` is the
default only with `auto_route`. The fork's pin `…20261007151655-7539c9855f19` is **six seconds newer
than upstream's post-image and 12 days newer than upstream's pre-image** (`0bdadeb4c934`), so the
behaviour is in the tree via the dependency; only the two doc paragraphs
(`docs/configuration/inbound/tun.md`, `tun.zh.md`) are not adopted. The conflict is mechanical: the
commit's own diff cannot be applied because the `go.mod` hunk would move the pin *backwards* relative
to the fork's base and would not touch the fork's `replace`.
*Action:* doc-only; fold into whichever commit next touches TUN docs.

### 5.15 Row 15 — the one genuinely missing behaviour, and it collides with the fork's sing-tun (`CONFLICT`, P0)

**What upstream does.** Two halves:

1. `dns/transport/local/systemconfig/source_darwin.go` — the inline cgo/private-libSystem dnsinfo
   reader (which is *exactly what the fork still has*, blob `e8bda7790` on both sides of the diff) is
   deleted and replaced by `github.com/sagernet/sing-tun/dnsinfo` (`Copy`, `Select`, `NewWatcher`).
2. `experimental/libbox/monitor.go` — `platformDefaultInterfaceMonitor` gains `defaultDNSServers`, a
   `dnsinfo.Watcher`, an `updateDNSServers` callback path, and DNS servers in the
   "did the default interface change?" comparison, so a DNS-server change **on an unchanged
   interface** fires every `DefaultInterfaceUpdateCallback`.

**What the fork has.** The reading half, inline and working: `changedLocked()` uses
`notify_register_check`/`notify_check` on `dns_configuration_notify_key` to invalidate the cached
system config (`dns/transport/local/systemconfig/source_darwin.go:159-208`). The DNS *verdict cache*
is already namespaced by DNS configuration as well: `adapter.DNSTransportWithEnvironment`
(`adapter/dns.go:146`), `local.Transport.Environment()` → `Config.Signature()` (servers + search +
ndots), `platformTransport.Environment()` → the default interface's `DNSServers`
(`experimental/libbox/dns.go:90`), consumed in `dns/client.go:381-450` as
`key = f(NetworkEnvironment(), transport.Environment())`.

**What the fork does not have.** The interface-monitor half. The fork's environment fingerprint is
built from gateways, Wi-Fi SSID and gateway hardware addresses only
(`route/network_environment.go:145-199`) — DNS servers and search domains are **not** in it. So a
DHCP renew, a system VPN, or a DNS-only reconfiguration on the same Wi-Fi moves the resolver
namespace but **not** the network epoch: `runtimecoord.Coordinator` does not advance, no
`DefaultInterfaceUpdateCallback` fires, and everything pinned to the epoch (dialer environment,
transport pins, endpoint resume logic) keeps describing the old network.

**Why it is a conflict, not a patch.** The upstream form requires `sing-tun/dnsinfo`, which the fork's
sing-tun **fork** does not carry: `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27`
is based on `7539c9855f19`, the revision *before* `dnsinfo/` was added. Blindly moving the pin to
`5c2edb183cc9` would drop the fork's four sing-tun changes (§6.1). And upstream's answer — reset the
whole network on a DNS change — is exactly what the work order forbids ("Apple DNS 变化不等于…
所有活跃连接都应结束"): the fork must move its *environment fingerprint* (or a narrower DNS
generation), not tear every flow down.

*Evidence of absence:* `git apply -R --check` fails on both files; `missing-lines.txt` shows 15/17
absent in `source_darwin.go` and 43/65 in `monitor.go`; `grep -n dnsinfo experimental/libbox/monitor.go`
matches nothing; `ls $GOMODCACHE/github.com/sagernet/sing-tun@…7539c9855f19/dnsinfo` → no such
directory.

### 5.18 Row 18 — Android auto-redirect is present; the "missing" lines are a field rename

`protocol/tun/inbound.go:280-300` reads `usePlatformAutoRedirect := platformInterface != nil &&
platformInterface.UsePlatformAutoRedirect()` and branches into `tun.NewAutoRedirect(...)`;
`protocol/tun/redirect_platform_linux.go` (upstream's own file, present) implements the platform path.
The absent lines are upstream's *struct field* `usePlatformAutoRedirect bool` and its later
`t.usePlatformAutoRedirect` reads; the fork computes the same fact as a local in `NewInbound`. The
fork additionally carries 13 TUN tests upstream does not have, including
`direct_fast_path_dns_test.go` and `dns_hijack_consumer_contract_test.go`. Android *client* parity
(satelite-one AAR/APK) lives outside this repository and is not adjudicated here.

### 5.20 Row 20 — mmap rule sets: present, with a different CIDR writer

`common/srs/binary.go` in the fork has `writeRuleItemCIDR(writer, itemType, value []*badoption.Prefixable, rawSet, mmap)`
and builds the set with `builder.AddPrefix(prefixable.Build(netip.Prefix{}))`. Upstream's version
takes `[]string` and branches `netip.ParsePrefix` → `netip.ParseAddr`. The fork's `Prefixable.Build`
normalises both forms, so the bare-address case is covered by construction rather than by a second
branch. 15 of 16 paths identical at both tips.

### 5.23 — see §5.7/5.8 block.

### 5.28 Row 28 — gVisor is retired *harder* than upstream

The fork removed `with_gvisor` from `release/DEFAULT_BUILD_TAGS` (its shipped tags now read
`with_quic,…,with_xhttp,badlinkname`), deleted the `replace` directive in favour of a retirement
record in `go.mod` (lines 322-331), and keeps `github.com/sagernet/gvisor … // indirect` in
`go.mod`/`test/go.mod` — which is upstream's own end state, because sing-tun still contains
`with_gvisor`-tagged packages. `docs/fork/upstream-sync-2026-10.md` §7.3 records the executed work and
the two gates that fail if it comes back. The 11 transient paths in `tip-parity.tsv` are the deleted
`device_stack.go`/`device*.go` files.

### 5.32 Row 32 — runtime validation is present, the generated schema is not (`PARTIAL`)

`option/rule.go:154,156`, `option/rule_dns.go`, `option/rule_set.go` declare
`badoption.Listable[*badoption.Prefixable]` — byte-identical to the upstream tip. The intermediate
`schema:"prefixable"` tags this commit added were **deleted again by a later upstream commit**
(`9ea795798378`), which is why the normalised line probe reports them missing at the tip. What is
genuinely different is `docs/schema.json`: the fork's copy is not regenerated from the current
generator, so a GUI that validates against it will not see the prefixable forms. `schema/generator.go`
matches 23/33 added lines.
*Action:* regenerate `docs/schema.json` in the commit that next touches the schema — the work order's
own rule applies: the schema is documentation, not the runtime guard.

### 5.35 Row 35 — the HTTP rewrite is a conflict by construction (`CONFLICT`)

Upstream's transport/http is 20 files; the fork's is **84 files including 54 tests**, with 121
fork-only commits touching the directory (CONNECT-UDP batching, HTTP/3 lifecycle/tracer/fallback
windows, capsule ownership, deferred activation, `client_h2_legacy.go`/`extended_connect_legacy.go`
compatibility shims). 23 of the 49 touched paths are byte-identical, and the added-line probe shows
4392/4865 present, so the fork is not behind on the feature — it is a different implementation with
its own verified edges. Two upstream files are absent at both tips
(`protocol/http/quic/inbound_init.go` — added here, deleted again by row 37; `transport/http/extended_connect.go`).
*Rule:* never apply this commit as a patch, and never "simplify" the fork's HTTP tree towards it. The
only useful work is a per-file diff hunt for edge fixes upstream made that the fork's tree lacks —
candidates from `percommit-different-files.txt` are `transport/http/client.go`,
`client_h3.go`, `connect_udp.go`, `capsule.go`, `server_conn.go`, `server_h2.go`, `forward.go`,
`reader.go`, `common/badhttp/badhttp.go`, `common/sniff/http.go`, `include/quic.go`,
`protocol/http/{inbound,outbound}.go`, `protocol/mixed/inbound.go`, `protocol/naive/inbound.go`.
The `include/quic.go` line (`_ "…/protocol/http/quic"`) must **not** be restored — the package is
gone upstream.

### 5.37 Row 37 — MASQUE is a superset

`protocol/masque` has 38 fork-only commits and `transport/masque` is present with the fork's own
session/headroom work; 9 paths are transient (upstream created and deleted them within the same 53).
The absent-line list is dominated by `docs/configuration/endpoint/masque-*.md` pages that upstream
adds for its own docs tree; the fork's docs live in `docs/configuration/endpoint/` as well, so the
useful subset is the doc text, not code.

### 5.39 Row 39 — nested-group resolution is the fork's weakest documented area (`PARTIAL`, P0)

Absent lines concentrate in `protocol/group/urltest.go` (`outbound = s.group.selectedOutboundTCP/UDP`,
`LoadURLTestHistory(RealTag(group, network))`, `s.group.Touch()`,
`interruptGroup.Add(closer, true)`) and `route/route.go` (`resolveOutbound(...)` chains for TCP/UDP
and inside `NewConnection`). The fork has 42 fork-only commits in `protocol/group` and its own
"active recovery" behaviour, but the two implementations are not the same algorithm, and only 3 of 13
paths are byte-identical.
*Evidence it is genuinely open:* this is the only P0 row where the fork's file differs on lines that
are *behavioural* rather than renamed or moved, and no fork document claims the nested-group case.
*What would resolve it:* a behavioural test that builds a nested selector→urltest→outbound chain,
interrupts the inner group and asserts which outbound serves the next flow — run against the fork's
implementation before deciding whether anything needs porting.

### 5.40 Row 40 — Go 1.27 gated, and this project is on 1.25.5

The commit is `//go:build go1.27 && !http2legacy && badlinkname` (and the matching negations) across
`transport/http/client.go`, `client_h2.go`, `extended_connect.go`, `tunnel_client.go`. With
`GOTOOLCHAIN=go1.25.5` those files compile the legacy branch, so the fix cannot be exercised here.
*Rule from the work order, unchanged:* do not move the toolchain to chase it. Revisit when the
release toolchain becomes 1.27; at that point this becomes a P1 with a real test (`H2 CONNECT-UDP`).

### 5.47 Row 47 — backpressure constructs are present; the "absent" lines were alignment

Verified by reading production files: `protocol/openvpn/client.go:132-136` has `ICMPTimeout`,
`UDPMapping: tun.NATMapping(options.UDPMapping)`, `UDPNATMax`, `InterfaceFinder`;
`protocol/openvpn/server.go:113,248` has the mapping options and
`serverOptions.IncomingPacketHeadroom`; `transport/masque/session.go` has `PacketHeadroom`
(line 49-55), the `datagramErrorTooLarge`/`MaxPayloadSize` classification (lines 388-422) and the
owned-datagram path (line 486). `transport/wireguard/device_stack.go` 13/15 and
`test/go.mod`/`go.sum` (fork test-module pins) account for the rest.

### 5.50 Row 50 — Apple CI caching, file absent, CI-time only (`PARTIAL`)

The commit patches `.github/workflows/build.yml`, which does not exist in the fork. The fork's
`.github/workflows/client-apple.yml` uses `cache: true` on `setup-go` and warms the Go module cache
(lines 94, 145, 217, 281, 464, 540) but has no Xcode `DerivedData`/`SourcePackages` cache key, which
is what the upstream commit is about. **No product impact**: unsigned local/CI build time only.

### 5.52 Row 52 — the one plainly absent row (`MISSING`, Stage 1)

`adapter/lifecycle.go` differs from upstream exactly and only here: 6 added lines absent, reverse-apply
ABSENT, and the file is otherwise the upstream tip's (this is also how the parent agent confirmed it
from the other direction — the fork matches upstream at `a691a440`, and upstream's only later commit
touching the file is this one). Stage 1 owns the fix; it must filter *expected* closed/cancelled
errors in scope cleanup without swallowing real failures, and the work order asks for the negative
half explicitly ("仅关闭上下文过滤，真实失败留存").

### 5.54 Resolution of the rows the reverse-apply probe left `UNCLEAR`

`applycheck.sh` reports `UNCLEAR` whenever a hunk neither applies nor reverse-applies cleanly — which
happens as soon as the fork edited any neighbouring line. The two later probes resolve almost all of
them, and the three rows the parent flagged are handled as follows (`unclear-resolved.tsv` pairs each
row's verdict with its normalised line count; `percommit-different-files.txt` names the differing
paths per commit):

| row | UNCLEAR files | resolved to | how |
| --- | ---: | --- | --- |
| `a691a4402375` (scoped cleanup, A) | 43 | `SEMANTIC-EQUIVALENT` — 58 of its 115 paths are still **byte-identical to the upstream tip**, and 1512/1584 added lines are present; the remaining differences are the fork's own further refactor (`adapter/lifecycle.go` 72/72) | `tip-parity.tsv` + `missing-lines.py`; residual files read by hand: `protocol/tun/inbound.go` 13/38, `protocol/tailscale/endpoint.go` 45/59, `service/oomkiller/service_darwin.go` 10/19, `route/network.go` 21/25 |
| `a364ff4794f0` (hot-reload removal, A) | 10 | `SEMANTIC-EQUIVALENT` — the deleted capability is absent from the fork by construction: no `Reload(` exists anywhere under `adapter/`, and `adapter/lifecycle_legacy.go` is gone at both tips | `grep -rn 'Reload(' adapter/` returns nothing; `tip-parity.tsv` marks the legacy file `NEITHER` |
| `41ef639b548f` (nested groups) | 8 | `PARTIAL` — this one does **not** resolve to equivalence: 9 behavioural lines remain absent in `protocol/group/urltest.go` and 5 in `route/route.go`, and tip parity is only 3/13 | `missing-lines.txt` (the exact lines are quoted in §5.39); resolution requires the behavioural nested-group test named in P0-1, not more diffing |

Rows where a residual `UNCLEAR` remains and no behavioural claim is made in §4: `e2a8d9c85e5a`
(34 files, MASQUE), `1a6b6615c6e5` (25, HTTP), `5f404b8c6f5c` (24, gVisor), `1e157350b789` (15,
backpressure), `7632cdab9aae` (8, Go TUN stack), `3f7f7eb3c09d` (9, Android auto-redirect). For each
of these, §5 records the construct that was read in the production file, and §7 lists the test that
would convert the read into a proof. Two of them (`1a6b6615c6e5`, `e2a8d9c85e5a`) are additionally
`CONFLICT`/superset rows where byte parity is the wrong question to ask.

---

## 6. Fork advantages that the next stage must not "sync away"

Recorded because the goal is semantic equivalence **with the fork's own advantages preserved**. Each
item below is a capability upstream does not have, in an area one or more of the 53 commits touch.

### 6.1 `sing-tun`: four changes on top of upstream, in the exact file upstream bumped

The fork replaces `sing-tun` with `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27`,
based on upstream `7539c9855f19`. `diff -rq` of the fork's revision against that base shows **exactly
six paths**: `FORK.md` (provenance), `README.md`, `stack_system.go` + `stack_system_accept_test.go`
(the LX 040 accept-loop self-heal: upstream's `acceptLoop` still returns on a bare
`listener.Accept()` error and permanently stops accepting), `stack_go.go` +
`stack_go_startclose_test.go` (Go-stack startup/close serialisation).
**Any sync of rows 02/13/15/18/27/28/47 that moves the `sing-tun` require without re-basing these
four changes destroys them, and `dnsinfo/` is precisely what row 15 needs from the newer revision.**
The correct move is a re-base of `8dde9c8cbe27` onto `5c2edb183cc9` in the sing-tun fork, then
root+`test/` pin parity — the same procedure `docs/fork/upstream-sync-2026-10.md` §7.1 used last time.

### 6.2 `runtimecoord` epoch machinery (rows 07, 08, 10, 22, 23, 45, 52)

`common/runtimecoord/coordinator.go` — `Epoch()`, `Advance()`, `GenerationChanged()`,
`Register(label)`, `RebindLease` with `BeginRebind`/`CompleteRebind`/`Expired`, `ScheduleRebind`,
`Acknowledge`, `WakeAllowsRebind`, `ContextWithProbeOrigin`, `MeasurementContext` — plus
`platform_events.go`'s two-axis (`screenOn`, `appForeground`) policy with coalescing and statistics.
Upstream has no equivalent: its device-pause policy is spread over `command_server.go` and
`pause.Manager`. Fork-only commits: 3 in `common/runtimecoord` after the merge base, plus the
`route/runtime_coordinator_integration_test.go` suite.

### 6.3 Network-environment fingerprint and DNS namespace isolation (rows 15, 44)

`route/network_environment.go` — a fingerprint over gateways/SSID/gateway-MAC with the transition
claimed under the same lock that publishes it (`beginTransition` before `stateAccess.Unlock`), plus
`adapter.DNSTransportWithEnvironment` and the `dns/client.go` cache key
`f(NetworkEnvironment(), transport.Environment())`. Upstream's DNS cache has no network dimension at
all. This is the fork's version of the "old verdict must not poison a new network" contract, and it is
what row 15 must extend rather than replace.

### 6.4 HTTP/3 CONNECT-UDP, batching and capsule ownership (rows 35, 37, 40, 47)

84 files vs upstream's 20, 54 tests, 121 fork-only commits: batch copy/timeout, owned-datagram
handoff, H3 fallback windows, stale-connection and lifecycle-trace tests, `capsule.go`,
`connect_udp_*`. The fork's own documents (`docs/fork/`) treat these as accepted behaviour.

### 6.5 Sniffer and direct-fast-path work (rows 33, 27, 42, 51)

12 fork-only commits in `common/sniff` (perf: QUIC frame summary instead of recording, connection-id
views, request-line pre-rejection before `net/http`, stream-retry decision from the round's failures)
and 28 in `protocol/tun` including `direct_fast_path_dns_test.go`,
`dns_hijack_consumer_contract_test.go`, `native_bypass_dispatcher_test.go`. The DNS sniffer *file*
happens to be byte-identical to upstream (row 33), which is the point: the fork's work is around it,
not inside it.

### 6.6 Audited dependency forks (rows 19, 41, 48, 02)

`replace` directives with provenance comments in `go.mod`: `sing` (`WriteOwnedBuffer`,
byteformats overflow rejection), `cronet-go` (whole module tree, not just the root — "the Go code was
the fork's and the .a files were upstream's" is quoted in the comment as the failure this prevents),
`quic-go`, `metacubex/utls` → `Piggy-Cat-bit-shadow/utls v1.8.8-0.20261009084700` (Firefox 148 /
Safari 26.3 hybrid share). `.github/CRONET_GO_VERSION` is identical to upstream's.

### 6.7 Retired gVisor with live gates (row 28)

`go.mod` lines 322-331 (retirement record instead of a replace) plus the two gates
(`cmd/internal/build_libbox/tag_policy_test.go::TestGVisorIsRetiredFromTheModuleGraph`,
`scripts/ci/verify-upstream-assumptions.sh`) and the inverted artifact tripwire.

### 6.8 Product-level facts that constrain any sync

`release/DEFAULT_BUILD_TAGS` carries `with_xhttp` (upstream does not) and no `tfogo_checklinkname0`;
`test/go.mod` is a separate module with its own fork pins (root/`test` parity is a standing rule);
`clients/*` are gitlinks to the fork's own clients, so rows 16/53's gitlink bumps are never adopted;
the fork has its own 8 workflows, so rows 11/14/50's workflow edits have no target.

---

## 7. Prioritised action list for the next stage

Ordered by the work order's own priority: reachable correctness first, no work to move a "behind"
number. Each item names the evidence that it is genuinely open, the blast radius, and the conflict.

**P0-1 · Row 39 — nested outbound-group resolution and interruption (verify, then port the edges).**
*Evidence open:* 9 behavioural lines absent in `protocol/group/urltest.go`
(`selectedOutboundTCP/UDP`, `LoadURLTestHistory(RealTag(group, network))`, `group.Touch()`,
`interruptGroup.Add(closer, true)`), 5 in `route/route.go` (`resolveOutbound` chains), tip parity 3/13.
*Blast radius:* every selector/urltest user; a wrong chain resolution mis-attributes traffic.
*Conflict:* yes — the fork's `protocol/group` has 42 fork-only commits and its own accepted active-recovery
logic; port only what a failing nested-group test proves missing.
*First step:* write the nested-chain interruption test against the fork's current code (no production edit).

**P0-2 · Row 15 — DNS-server-change detection on an unchanged interface (Apple + Windows).**
*Evidence open:* §5.15 — fingerprint excludes DNS; `monitor.go` has no DNS tracking; `sing-tun` fork has
no `dnsinfo/`.
*Blast radius:* DNS verdict reuse across a DNS reconfiguration (the exact regression the work order
names), Apple lifecycle coupling (an over-eager reset costs a handshake storm and heat).
*Conflict:* **yes, the sharpest one** — needs the newer `sing-tun` (which the fork replaces), and
upstream's whole-network-reset answer violates the fork's contract that a DNS change is not a wake/unlock.
*First step:* re-base the sing-tun fork onto `5c2edb183cc9` (keeping §6.1's four changes), then add DNS
servers/search domains to `recomputeNetworkEnvironment`'s `options` and prove, with the fork's own
generation test hook, that one reconfiguration produces exactly one epoch advance and no flow teardown.
Do **not** adopt `experimental/libbox/monitor.go` verbatim.

**P0-3 · Row 52 — filter expected closed/cancelled errors in scope cleanup (Stage 1 owns).**
*Evidence open:* reverse-apply ABSENT, 0/6 lines, `adapter/lifecycle.go`.
*Blast radius:* error reporting only — but the failure mode is silent: real cleanup failures would
either be logged as noise or, if over-filtered, disappear.
*Conflict:* none identified; the code is upstream's own.
*First step:* a test that provokes a genuine (non-context) cleanup failure and asserts it still surfaces.

**P1-1 · Row 02 — dependency decisions, one module at a time.** `sing-quic` and `sing-shadowsocks` are
pin decisions with the fork's `sing`/QUIC pairing in the blast radius; `sing-tun` is P0-2. Take them as
three separate, individually verified commits or not at all.

**P1-2 · Row 32 — regenerate `docs/schema.json`.** No runtime risk (the option types are already
prefixable); user-visible for schema-validating GUIs. Blast radius: docs only.

**P1-3 · Row 05 / 12 / 18 / 20 / 47 — verification passes, not ports.** Each has a production-side
re-implementation whose equivalence rests on a file read (§5.5, §5.12, §5.18, §5.20, §5.47). Convert
each into one behavioural test on the production object — first-packet on the naive inbound,
auth-banner on tailscale SSH, platform auto-redirect selection, SRS compile of a bare-IP `ip_cidr`,
UDP backpressure to an endpoint — so the next inventory does not have to re-derive them. **No test
double may implement a capability the production type does not** (the failure mode this project has
already paid for).

**P1-4 · Row 39's sibling — `docs/configuration/inbound/tun.*.md` (row 13) doc paragraphs.** Fold into
the next TUN-docs commit; the behaviour is already right.

**P2 · Rows 01, 11, 14, 16, 40, 50, 53 — no action.** 01: device/client-side item, core is done
(`DEVICE-ONLY` for the client half). 11/14/50: workflows and packaging the fork does not ship. 16/53:
version bookkeeping the fork must not adopt. 40: revisit on Go 1.27.

**Explicitly not to do:** do not `git merge`/`rebase` `upstream/testing`; do not apply row 35 or row 37
as patches; do not move the `sing-tun` require without §6.1; do not adopt upstream `clients/*`
gitlinks or release numbers; do not chase `git rev-list` to zero.

---

## 8. What could not be determined here, and what would resolve it

| # | undetermined | why | what resolves it |
| --- | --- | --- | --- |
| 01 | whether the fork's `RecordScreenState` is reachable end-to-end on a device | needs the pinned Apple client + a device; the repo cannot show it | a device run of the Apple client (out of this repository) |
| 12 | whether the auth/unauthorised banners actually appear on the wire | no Tailscale SSH reference peer here | an SSH client test against the fork's tailscale endpoint |
| 18 | Android platform auto-redirect end-to-end (VPNService + AAR + APK) | needs the Android product repo and a rooted device | the satelite-one gate; out of this repository |
| 19/41 | AnyTLS packet-boundary behaviour | both sides pin the same library revision, so the wire behaviour is a library question | a UDP-over-AnyTLS boundary test |
| 20 | mmap peak RSS on iOS | needs a device build | device measurement (the fork already has an iOS memory target) |
| 27 | whether every Go-TUN-stack hunk is *behaviourally* equivalent in `route/splice.go` (93/304 lines absent) | the fork's splice/offload implementation is a different shape; equivalence needs a datapath test, not a diff | the fork's `real_datapath_test.go` extended to the offload cases |
| 34 | whether the Android route-set behaviour (include/exclude address sets) matches upstream on a device | the commit's three added lines are present in the fork's own TUN inbound, but no Android runtime exists here | the Android route-set test matrix |
| 39 | which of the two nested-group algorithms is correct on interruption | requires the behavioural test in P0-1 | that test |
| 47, 51 | UDP NAT mapping/fragmentation semantics on a live datapath (mapping reuse, fragment reassembly, port exhaustion) | `go test` compiles this; it does not exercise it | a privileged Linux namespace test or a device capture |
| 40 | the Go 1.27 H2 extended-CONNECT path | toolchain is `go1.25.5` by project decision | re-evaluate when the release toolchain moves |
| — | `common/trafficsched` results inside `go test ./...` | see §9 | see §9 |

No row is `BLOCKED`: every open item has a named resolution step inside this repository except the
device-only ones, which are marked as such rather than guessed.

---

## 9. Verification performed by this stage

No production file was touched, so these are baseline confirmations, not regression checks. Both ran
in `/tmp/s1-up` at `912ed1efa` with `export GOTOOLCHAIN=go1.25.5`:

```
$ TAGS=$(cat release/DEFAULT_BUILD_TAGS)
$ go build -tags "$TAGS" ./...      # exit 0   18:24:05 → 18:26:21
$ go build ./...                    # exit 0   18:26:21 → 18:27:00
```

* tagged tags: `with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,with_xhttp,badlinkname`
* only linker warnings (`ld: warning: ignoring duplicate libraries: '-lobjc' / '-lresolv'`), no errors.
* **Load during the run: `41.66 57.66 55.73` before the tagged build, `22.29 44.35 50.66` after it,
  `25.60 42.40 49.65` after the untagged build.** The machine was heavily loaded by the parallel
  worktree throughout, which is why no full `go test ./...` verdict is claimed here.

**`common/trafficsched` policy (per the work order, restated so it is not misread):** failures in that
package inside `go test ./...` are a **known load-sensitive flake**, not a pass and not a regression.
It passes 3/3 in isolation at load 13 and fails inside `go test ./...` at load 56. This stage did not
run the suite at a load where its result would mean anything, and makes no claim either way.

**Equivalence-claim verification style.** Every "the fork has this" statement in §4/§5 rests on one of:
a `patch-id` match to a fork-reachable commit; a reverse-apply probe; a byte-comparison of the
production file at both tips; a whitespace-normalised line probe; or a read of the production file
(`grep`/`sed` on the fork tip, never on a test double). Dependency claims were verified against the
module cache contents of the exact revisions both sides pin, including
`diff -rq` of the fork's `sing-tun` base against upstream's final `sing-tun`.

---

## 10. Reproducing every number in this ledger

```bash
cd /tmp/s1-up && git fetch upstream testing
git rev-parse upstream/testing origin/testing
git merge-base origin/testing upstream/testing
git rev-list --left-right --count origin/testing...upstream/testing
git log --reverse --format='%H%x09%aI%x09%cI%x09%s' origin/testing..upstream/testing > docs/fork/upstream53.tsv
git cherry -v origin/testing upstream/testing                      # 11 '+', 42 '-'

bash   docs/fork/applycheck.sh    > docs/fork/presence-matrix.tsv   # 722 rows
bash   docs/fork/line-presence.sh > docs/fork/line-presence.tsv
cut -f2 docs/fork/line-presence.tsv | sort -u | bash docs/fork/tip-parity.sh > docs/fork/tip-parity.tsv
python3 docs/fork/missing-lines.py > docs/fork/missing-lines.txt

# per-commit patch-id against the whole fork history
git log --format='%H' origin/testing | while read c; do
  printf '%s\t%s\n' "$(git show "$c" | git patch-id --stable | head -1 | awk '{print $1}')" "$c"
done > /tmp/fork-patchids.tsv

# dependency truth
diff <(grep -v '^replace\|^\s*//' go.mod) <(git show 6afeff4c0f71:go.mod | grep -v '^replace\|^\s*//')
diff -rq "$GOMODCACHE/github.com/sagernet/sing-tun@v0.9.7-0.20261007151655-7539c9855f19" \
         "$GOMODCACHE/github.com/sagernet/sing-tun@v0.9.7-0.20261009022811-5c2edb183cc9"
```

Artifacts in `docs/fork/`: `upstream53.tsv`, `presence-matrix.tsv`, `line-presence.tsv`,
`tip-parity.tsv`, `patchid-match.tsv`, `missing-lines.txt`, `percommit-summary.txt`,
`percommit-merged.tsv`, `percommit-different-files.txt`, `existence.tsv`, `pins.txt`,
`unclear-resolved.tsv`, `upstream-diffs/<sha>.diff` (all 53), and the four probe scripts.
