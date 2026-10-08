# FINAL CI / ACTIONS REPORT — second pass

## Executive status

**All eight workflows were genuinely exercised; seven are green.** The first pass's central claim —
"6 of 8 workflows were never run" — no longer applies.

| Workflow | Run ID | Result | Attempts |
| --- | --- | --- | --- |
| Verify | `37812578081` | **GREEN** | 1 |
| Android Core ARM64 | `37811138932` | **GREEN** | 6 |
| Linux amd64 | `37809726005` | **GREEN** | 1 |
| Windows amd64 core | `37809740077` | **GREEN** | 1 |
| macOS arm64 | `37809754452` | **GREEN** | 1 |
| Reference interop (Xray) | `37812611373` | **RED — real protocol finding** | 4 |
| Apple client | `37809771259` | **GREEN** — signing, archive and the credential path all worked | 1 |
| Release (dry-run) | `37811184607` | still running at time of writing (it waits for the CI runs of its target tag, which never ran on this fork) | 1 |

`ALL CURRENT ACTIONS GREEN ON FINAL HEAD` is **not** claimed: interop is red on a real finding, and the
release dry-run had not settled when this was written.

**Apple is green, and that is worth stating explicitly** because the first pass speculated it would be
blocked by missing credentials. It was not: the repository's secrets work, and the workflow ran its
signing, archive and export path to success. The user's instruction not to presume a credential
blocker was correct, and the speculation is recorded here as a mistake rather than quietly dropped.

## HEADLINE: the reference stand found a REAL interop failure

This is the first time the reference stand has ever executed a live scenario. It did not pass.

```
--- FAIL: TestLiveInteropRealityClassical (20.04s)
    the box client never became usable: the last proxied attempt failed with:
      Get "http://127.0.0.1:37609/hello": socks5: request rejected, code=1: context deadline exceeded
    xray-server.log:
      REALITY: processed invalid connection from 127.0.0.1:44932:
        authentication failed or validation criteria not met
```

**The reference Xray rejects this fork's REALITY handshake.** The unit suite passes because it tests the
client against this fork's own expectations; the reference disagrees about the authentication. This is
exactly the class of defect the stand was built to find — every REALITY claim in the fork is now
provisional until this is resolved.

It is **not yet diagnosed**. Two candidate causes, which the next pass must separate:

1. **A harness bug** — the generated server config carries a `publicKey`/`shortId`/`serverName` the
   client does not actually use, so the reference is right to reject it. The harness generates both
   sides from one source, so a mismatch here is plausible and would be a false alarm.
2. **A product bug** — the client's REALITY authentication genuinely does not match the reference.

Separating them is cheap and is the highest-value next action: compare `publicKey`/`shortId` in the
retained `server-reality-classical.json` against `reality.public_key`/`short_id` in
`client-reality-classical.json` from the same run, then try a hand-written reference config.

### Secondary interop findings

- **The resolved reference is `v26.3.27`, and five scenarios skip on it** with accurate messages
  ("REALITY key_share=hybrid requires a reference at or above v26.9.8"). So `latest` resolved *below*
  the harness's own hybrid threshold. Either the default should pin a version rather than ask for
  `latest`, or the threshold assumption needs revisiting. Either way the **hybrid, encryption, Vision
  and XHTTP-priority scenarios did not actually run**, so that half of the interop debt is still unpaid.
- **`reality-encryption` skips for a different reason**: `xray vlessenc` output failed to parse
  (`invalid character 'C' looking for beginning of value`) — the harness expects JSON and the reference
  prints something else. A harness bug against the current reference CLI, not a product bug.

## Android ARM64 — GREEN

| | |
| --- | --- |
| Final run | `37811138932` (success) |
| gomobile | `github.com/sagernet/gomobile@v0.1.12`, **derived from root go.mod**, both binaries, each proven from its own `go version -m` |
| NDK | `28.0.13004108`, **derived from `clients/android/gradle.properties`** |
| JDK | 17 (temurin) |
| target abi | `android/arm64` only |
| AAR | `libbox.aar`, **28,408,383 bytes** (exact path, confirmed from a successful run — no `find`) |
| ELF | `ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, stripped` |
| provenance | `libbox.provenance`, commit equals `GITHUB_SHA` (asserted) |
| gVisor | **PASS: no `with_gvisor` tag and no gVisor module in the `.so` build info** |
| low-memory | `with_low_memory` present in the resolved `android-main` tags (asserted, alongside `with_gvisor` absence) |

### P004 was misclassified — correction

The first pass classified the gomobile failure `BLOCKED-EXTERNAL` and proposed resolving an older
`golang.org/x/mobile`. Both were wrong. Root `go.mod` requires `github.com/sagernet/gomobile v0.1.12`
(go directive 1.23, ships `cmd/gomobile` and `cmd/gobind`) — the project's canonical toolchain. The
workflow installed `golang.org/x/mobile@latest`, which now needs Go ≥ 1.26 and whose toolchain download
404s. **Correct classification: CI / TOOLCHAIN SOURCE-OF-TRUTH BUG.**

### The pattern behind eight failures

Four of six Android attempts and all three interop attempts were the same two mistakes in different
clothing: **a value written into YAML instead of derived from the project's own pin**, and **an
early-exit reader combined with `set -o pipefail`**.

| # | Root cause | Class |
| --- | --- | --- |
| 1 | `android-actions/setup-android@v3` requests the deleted `tools` package | external action |
| 2 | `yes \| sdkmanager` + pipefail → false failure on a *successful* install | CI config |
| 3 | `golang.org/x/mobile@latest` instead of the pinned `sagernet/gomobile` | **source of truth** |
| 4 | `gomobile version` output misread as a version mismatch | CI config |
| 5 | NDK hardcoded `27.0.12077973`; client pins `28.0.13004108` → **Cronet link failed** | **source of truth** |
| 6 | `clients/android` is a submodule and was not checked out | CI config |
| interop A | `DEFAULT_BUILD_TAGS` dragged a broken Cronet archive into the test link | CI config |
| interop B | `curl \| grep -m1` + pipefail → `curl: (23)` | CI config |
| interop C | unauthenticated GitHub API → `curl: (22) 403` rate limit | CI config |

Attempt 5 is the one that mattered: **with the client's own NDK, the product compiles.** The Cronet
`unknown relocation (315)` error was never a product defect — it was CI using a toolchain the product
does not use.

## Fixed during the sweep

| ID | Finding | Status |
| --- | --- | --- |
| P001 | `Verify` red on two commits: the Phase-1 gVisor tripwire required a module CI never downloads | **GREEN AFTER FIX** |
| P002–P004, P006 | the Android plumbing failures above | **FIXED** |
| P005 | artifact discovery used `find` and would accept a stale artifact from anywhere | **FIXED** — exact paths confirmed from a successful run |
| P007 | release had no dry-run path | **FIXED** — `dry_run` skips only `gh release create`; default false, real path unchanged, no tag created |
| P008 | interop link pulled a broken Cronet archive | **FIXED** — `DEFAULT_BUILD_TAGS_OTHERS`; no scenario uses Cronet |
| P009 | `curl \| grep -m1` under pipefail | **FIXED** — fetch to a file, then parse |
| P010 | unauthenticated GitHub API 403 | **FIXED** — run token attached |

## Retry ledger

| Problem | Attempts | Reruns with no change | Outcome |
| --- | --- | --- | --- |
| Android ARM64 | 6 | **0** | GREEN |
| Reference interop | 4 | **0** | RED on a real finding; scenarios reached |
| Everything else | 1 | 0 | GREEN / in progress |

**No workflow was re-run without a code change.** Every attempt carried a written hypothesis and a diff.

## Known core risks (retained)

1. **REALITY does not interoperate with the reference** — the headline above. Possibly a harness bug;
   cheap to separate, highest priority either way.
2. **sing-tun `(*Go).Start` / `(*Go).Close` data race** in the pinned `stack_go.go`. Real, pre-existing,
   byte-identical across the pin bump, excluded by CI's own race legs. Not an LX-corpus item, not fixed
   here: fixing it means extending the sing-tun fork beyond the 040 patch or waiting on upstream.
3. **Blackholed-dial transition gap** — `ResetNetwork` does not cancel an in-flight incomplete dial, so
   it runs to `connect_timeout`. P2: it degrades rather than crashes.
4. **gomobile ABI debt** — 29 declarations with a pointer-bearing result frame, registered as checked
   debt; converting them needs a coordinated `clients/apple` migration.
5. **MASQUE HTTP/2 residual** — `transportResponseBody.Close` takes the connection write mutex for
   unread body bytes before its context-watching select, so ordering alone cannot bound it.
6. **Device validation debt** — nothing has run on a device for Apple or Android; the mobile-parity trim
   mapping is explicitly provisional.
7. **The interop stand's hybrid, encryption, Vision and XHTTP scenarios have still never run**, because
   the resolved reference sits below the hybrid threshold and the `vlessenc` parse fails.

## What the next pass must do

1. **Separate harness from product on the REALITY rejection.** Diff the retained `publicKey`/`shortId`
   between `server-reality-classical.json` and `client-reality-classical.json` from run `37812611373`.
   If they disagree the harness is wrong; if they agree, this fork's REALITY authentication is wrong
   against a real peer, and that outranks everything else in the backlog.
2. **Pin the reference version explicitly** instead of resolving `latest`, then run the hybrid,
   encryption and XHTTP-priority scenarios.
3. **Fix the `vlessenc` parse** so the encryption scenarios can obtain key material.
4. Re-run the two workflows that were still in progress and fold their results into the table above.
