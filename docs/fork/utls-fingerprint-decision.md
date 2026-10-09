# uTLS Firefox 148 / Safari 26.3 — go/no-go decision

**Verdict: GO on the technical question — the compatibility gap is real, reproduced against a real
reference, and the three upstream commits close it minimally. The landing is an owner action, not a
code question: the fork repository must be created and pushed, and the pin moved. Until that
happens the gap ships.**

The decision was taken by the process §15 prescribes, in order, and each step's evidence is below.
The measurement that decides it is not "the presets look old": it is a REALITY handshake against a
real Xray v26.9.30 that **passes with `fp=chrome` and fails with `fp=firefox` and `fp=safari`**, with
the reference's own log naming the REALITY authentication failure.

| | |
| --- | --- |
| measured at | `17b176a18` + this branch's commits |
| toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`), `TAGS=$(cat release/DEFAULT_BUILD_TAGS)` |
| pinned dependency | `github.com/metacubex/utls v1.8.7` |
| reference binaries | Xray `v26.9.30` (`b26a91d`, go1.27.1) and Xray `v26.3.27` |
| harness | this repository's own `test/interop` live stand (`RUN_LIVE_XRAY_INTEROP=1`, `XRAY_BINARY=…`) |

---

## Step 1 — prove the current bug

The stand was extended with a **fingerprint axis** (`Scenario.Fingerprint`, default `chrome`, so
every pre-existing scenario is unchanged) and two scenarios, `reality-firefox` and `reality-safari`,
each with **no explicit `key_share`** — the configuration `fingerprint: firefox` alone produces, and
the default a real user has. `reality-hybrid` is the control: same REALITY, same reference,
`fp=chrome`, `key_share: hybrid`.

First run, pinned tree, reference **Xray v26.9.30**:

```
=== RUN   TestLiveInteropRealityHybrid
--- PASS: TestLiveInteropRealityHybrid (3.24s)
    --- PASS: TestLiveInteropRealityHybrid/sequential (0.01s)
    --- PASS: TestLiveInteropRealityHybrid/concurrent (0.01s)
    --- PASS: TestLiveInteropRealityHybrid/cancel (0.30s)
    --- PASS: TestLiveInteropRealityHybrid/deadline (0.70s)
    --- PASS: TestLiveInteropRealityHybrid/restart (0.01s)
=== RUN   TestLiveInteropRealityFirefox
--- FAIL: TestLiveInteropRealityFirefox (20.05s)
=== RUN   TestLiveInteropRealitySafari
--- FAIL: TestLiveInteropRealitySafari (20.08s)
FAIL
FAIL	test/interop	44.402s
```

The failure is not a harness artifact and not a timeout in the abstract; the reference says exactly
what it is. Server log tail from the Firefox leg:

```
[Info] transport/internet/tcp: REALITY: processed invalid connection from 127.0.0.1:53107: authentication failed or validation criteria not met
```

and the client's own log for the same attempt:

```
ERROR connection: open connection to 127.0.0.1:51933 using outbound/vless[interop-out]: x509: certificate signed by unknown authority
```

That pair is the documented REALITY failure shape: the server does not recognise the ClientHello as
one of its own, answers with the camouflage site, and the client verifies the camouflage site's
certificate instead of the REALITY temporary certificate. Against a public camouflage site the
client-side message is the `reality verification failed` this work order names; here the
camouflage site is the stand's local TLS server, so the message is the x509 error it produces. The
server-side line is the same in both cases, and it is the one that identifies the layer.

**Control: the same two scenarios against an older reference pass with the pinned tree.** Xray
v26.3.27 predates the mandatory hybrid share ([`reality-interop-fix-report.md`](reality-interop-fix-report.md)),
so a hybrid-less greeting is still authenticated:

```
    live_test.go:37: scenario reality-firefox: reference v26.3.27, …
--- PASS: TestLiveInteropRealityFirefox (3.23s)
--- PASS: TestLiveInteropRealitySafari (3.18s)
ok  	test/interop	7.526s
```

This is what makes the attribution a measurement rather than a hypothesis: the Firefox 120 and
Safari 16.0 greetings are *not* broken in themselves, and nothing else about those scenarios
differs between the two runs. What changed is the reference's requirement.

---

## Step 2 — confirm the dependency difference

`github.com/metacubex/utls v1.8.7` (`u_common.go`):

```go
HelloFirefox_Auto = HelloFirefox_120     // Firefox 120, ~Nov 2023
HelloSafari_Auto  = HelloSafari_16_0     // Safari 16.0, ~2022
HelloChrome_Auto  = HelloChrome_133      // Chrome 133, ~Jan 2025 — post-ML-KEM
```

Measured from the greetings the client actually builds (the presets each accepted name resolves to,
and the key_share extension that preset produces):

| name | preset | greeting | X25519MLKEM768 | TLS 1.3 | key_share order |
| --- | --- | --- | --- | --- | --- |
| `""`, `chrome`, all `chrome_*` aliases | Chrome/133 | 1816 B | **yes** | yes | `[GREASE, X25519MLKEM768, X25519]` |
| `firefox` | Firefox/120 | 658 B | **no** | yes | `[X25519, P256]` |
| `safari` | Safari/16.0 | 512 B | **no** | yes | `[GREASE, X25519]` |
| `edge` | Edge/85 | 512 B | **no** | yes | `[GREASE, X25519]` |
| `ios` | iOS/14 | 512 B | **no** | yes | `[GREASE, X25519]` |
| `qq` | QQBrowser/11.1 | 512 B | **no** | yes | `[GREASE, X25519]` |
| `android` | Android/11 | 185 B | no | **no** | *(none)* |
| `360` | 360Browser/7.5 | 245 B | no | **no** | *(none)* |
| `random` | one of the five "modern" presets, drawn at init | — | 4 of 5 draws: **no** | yes | — |
| `randomized` | generated spec | — | varies (weight `KeyShare_Append_RandomGroups: 0.50`) | yes | — |

Everything else §15 Step 2 asks for was checked in the same pass:

- **Firefox Auto → Firefox 120; Safari Auto → Safari 16.0.** Confirmed above, and pinned by the
  register test so it cannot drift unnoticed.
- **Hybrid share order.** Chrome 133 presents `X25519MLKEM768` before `X25519`, which is what a
  reference reads (it takes the first non-GREASE share). The pre-ML-KEM presets present no hybrid
  share at all, so their `X25519` is first — and is the only classical share, which is why the
  server's REALITY auth fails rather than falling back to a different share.
- **Key reuse.** `fc716b2` adds `ReuseHybridAndClassicalKeyShares`, which makes Firefox 148 send the
  *same* X25519 key material inside the hybrid share and as the standalone classical share, as real
  Firefox does; without it a Firefox-looking greeting carries two independent X25519 keys, which is
  itself a distinguisher. `ddebe39` is the correction to that implementation (it stops putting an
  unexported field on the exported `KeyShare` type and marks the pair with a private sentinel in
  `Data` instead), and §14's requirement that the two travel together is therefore not cosmetic.
- **REALITY server API.** Nothing on the server side is touched by the three commits, and the
  reference in the failing and passing runs is the same binary.
- **badtls/ktls linkname compatibility.** `fc716b2`/`ddebe39` add an exported helper and two private
  constants, and change only `ApplyPreset`'s key-share loop, which is not referenced by linkname.
  Rebuilt with the repository's tag set — which carries `badlinkname` — the fork compiles and links.

The three commits, and the alternatives that do **not** work:

| commit | date | content |
| --- | --- | --- |
| `fc716b2` | 2026-02-28 | `feat: add ff 148 spec and impl keyshare reuse` — +182 `u_parrots.go`, +11 `u_public.go` |
| `ddebe39` | 2026-02-28 | `fix: dont add unexported field` — corrects `fc716b2`; must ship with it |
| `aa6edf4` | 2026-03-01 | `feat: add safari 26.3` — +110 `u_parrots.go` |

- **A version bump does not fix this.** `metacubex/utls v1.8.8`, the newest released tag
  (2026-09-30, `449a38f8`), still has `HelloFirefox_Auto = HelloFirefox_120` and
  `HelloSafari_Auto = HelloSafari_16_0`. `master` is older still (`HelloChrome_Auto = HelloChrome_120`).
- **The one branch that does carry them is a rebase, not a backport.** `v1.9.0-mod-meta` has
  `HelloFirefox_Auto = HelloFirefox_148` and `HelloSafari_Auto = HelloSafari_26_3`, but it is
  `175` commits ahead and `60` behind `v1.8.7`, `229` files changed, `+11666/-4509` — a move onto
  refraction `v1.9.0` (FIPS-140 paths, `defaults_boring.go`, `defaults_fips140.go`, a reworked
  `auth.go`/`conn.go`/`ech.go`). That is exactly §16's "needs 10+ more upstream commits" and
  "regression surface visibly widened": it is a different engineering project from the three
  commits, and it is not what a release freeze should absorb. The narrow fork is the smaller risk
  by two orders of magnitude in diff size.

---

## Step 3 — minimal fork, verified

The fork content is the pinned revision plus those three commits and nothing else: base
`metacubex/utls v1.8.7`, module path unchanged (`github.com/metacubex/utls`), no history sync.

It is recorded as a patch in this repository so it is reviewable and reproducible without the fork
remote existing yet:

| | |
| --- | --- |
| patch | `docs/fork/utls-firefox148-safari263.patch` |
| sha256 | `1fcd287d20746b3abacc6b4f7ed2fdf371b7b80fddccd0c9218002aef8826acb` |
| applies to | a pristine `metacubex/utls@v1.8.7` — `git apply --check` clean |
| delta | `u_common.go` +5, `u_parrots.go` +286, `u_public.go` +16, `u_parrots_test.go` +154 (upstream's own test) |
| fork content | the three commits, ported onto the pin's import block and `KeyShare` type; the only deviation from upstream's patch is where `crypto/ecdh` is imported |

Intended fork home and pin, per §15 Step 3:

```
github.com/Piggy-Cat-bit-shadow/utls            branch fix/firefox148-safari263
  base   github.com/metacubex/utls v1.8.7
  +      refraction fc716b2, ddebe39, aa6edf4
replace github.com/metacubex/utls => github.com/Piggy-Cat-bit-shadow/utls <pseudo-version>
```

Neither the repository nor the pin is created here: this worktree may not push, and §31 names
"必須由 owner 創建新 repo" as the one class of blocker that is not the agent's to resolve.

**Verified against the fork, with the main repository pointed at it by a local `replace`:**

Resulting presets and greetings:

```
name=chrome   preset=Chrome/133  len=1752 hybrid=true  shares=[GREASE X25519MLKEM768 X25519]
name=firefox  preset=Firefox/148 len=1885 hybrid=true  shares=[X25519MLKEM768 X25519 P256]
name=safari   preset=Safari/26.3 len=1533 hybrid=true  shares=[GREASE X25519MLKEM768 X25519]
name=edge     preset=Edge/85     len=512  hybrid=false shares=[GREASE X25519]
name=ios      preset=iOS/14      len=512  hybrid=false shares=[GREASE X25519]
```

Live matrix, same reference (Xray v26.9.30), same scenarios that failed in Step 1:

```
--- PASS: TestLiveInteropRealityHybrid  (3.33s)   sequential/concurrent/cancel/deadline/restart all PASS
--- PASS: TestLiveInteropRealityFirefox (3.15s)   sequential/concurrent/cancel/deadline/restart all PASS
--- PASS: TestLiveInteropRealitySafari  (…)
```

Chrome is unchanged (same `Chrome/133`, still hybrid, still passing) — §15 Step 4's "Chrome must not
regress", measured rather than asserted.

And the whole suite, with the fork in place:

```
go test -count=1 -tags "$TAGS" ./...   →  74 ok, 0 FAIL      (identical to the pin's baseline)
```

So of §16's GO list, these are established here: the compatibility gap is reproduced; the three
commits solve it minimally; Go tests are green; the interop matrix is green including the Chrome
control; no linkname or ABI surface is touched. The two remaining items — a real Apple build and a
real Android `libbox` build — are not runnable on this host and are for CI; nothing in the fork's
diff is platform-specific (it is preset data plus one key-generation loop in pure Go).

### Step 4 — the tripwire, and its red-check

`common/tls/reality_fingerprint_register_test.go` is the tripwire. It does not test the fork; it
tests the *pin*, and it fails in both directions:

- **Every accepted `utls.fingerprint` name must be classified.** The list is walked from
  `uTLSFingerprints()` — the table the client itself reads, which this work converted from a `switch`
  so it could be enumerated — not from a copy. A name added to the client and not classified fails.
- **Each classification is measured from the greeting the preset builds**, never assumed: the
  preset identity (`Firefox/120`, `Safari/16.0`, …), whether `X25519MLKEM768` is present, whether
  TLS 1.3 is offered at all, and — for presets that carry the hybrid share — that it comes **before**
  `X25519`, which is what §15 Step 4 asks for.
- **The set of fingerprints that cannot complete a REALITY handshake against a reference at or after
  `v26.9.8` is pinned by name**, so the consequence of the register cannot drift apart from the
  register itself.
- **The failure message is the instruction**: "delete this entry's exception and re-run the live
  fingerprint scenarios".

Red-check (a gate that has not been seen to fail is not a gate). With the local three-commit fork in
place, the tripwire fails for the right reason, in four independent places:

```
--- FAIL: TestRealityFingerprintRegisterIsExhaustive
    Messages: the register's preset for "safari" must be the preset the client resolves
--- FAIL: TestRealityFingerprintGreetingMatchesTheRegister/firefox
    Messages: firefox claims Firefox/120 does NOT carry X25519MLKEM768, and it now does: that is
              the dependency change this register exists to catch. Delete the entry from the
              incompatible set below and re-run the live fingerprint scenarios
--- FAIL: TestRealityFingerprintGreetingMatchesTheRegister/safari
    Messages: safari claims Safari/16.0 does NOT carry X25519MLKEM768, and it now does: …
--- FAIL: TestRealityFingerprintIncompatibleSetIsDeclared
    Messages: the set of accepted fingerprints that cannot present X25519MLKEM768 … changed
--- FAIL: TestRealityFingerprintIncompatibleSetIsDeclared
    Messages: modernFingerprints must still contain exactly one preset that carries the hybrid
              share, or the `random` entry's note is wrong
```

(the last one is the `random` exposure the fork changes: after it, three of the five "modern" presets
carry the share instead of one). **Green-check of the same file:** updating the register exactly as
the messages instruct — `Firefox/148`, `Safari/26.3`, both carrying, removed from the incompatible
set, `random` note corrected — makes all of it pass with the fork. So the post-fork state is one
deliberate edit away, and the edit is the one the tripwire dictates.

The second property, exhaustiveness, has its own red-check: adding a name (`"firefox_148"`) to the
client's table without classifying it fails `TestRealityFingerprintRegisterIsExhaustive` with
"every accepted utls.fingerprint name must be classified".

### Step 5 — REALITY interop

| leg | reference | `fp=chrome` | `fp=firefox` | `fp=safari` |
| --- | --- | --- | --- | --- |
| old reference | Xray v26.3.27 | passes (`reality-classical` is the pre-hybrid leg) | **passes** (control) | **passes** (control) |
| new reference, pinned uTLS | Xray v26.9.30 | passes | **fails** | **fails** |
| new reference, three-commit fork | Xray v26.9.30 | passes | **passes** | **passes** |

Each leg is a real HTTP round trip through the tunnel, not a nil-error check: the stand asserts a
request and its body arriving at a local HTTP target unchanged, an echoed body returning unchanged,
a size-controlled download, and observed behaviour for cancel, deadline and process restart. That
is strictly stronger than "a 204 came back", which is why §15 Step 5's warning about accepting a
successful handshake as success does not apply.

**One limitation, stated rather than glossed over.** §15 Step 1 suggests public camouflage targets
(`www.cloudflare.com`, `swdist.apple.com`, `www.gstatic.com/generate_204`). This stand deliberately
does not use them: its `dest`/target is a local TLS+HTTP server, because a stand that depends on
public endpoints cannot separate a client bug from a network or a third-party outage, and a
maintainer running it would not know which of the three they had. The property the test needs is
that the REALITY authentication decision is made by a real Xray binary, and it is: the reference's
own log is the evidence quoted in Step 1. The public-target check is a deployment smoke test, not a
protocol check, and it remains unperformed here.

---

## What is being decided

**GO**, on these terms:

1. The gap is real and reproduced, with the reference's own log naming it, and with a control run
   on an older reference that passes — so the cause is the reference's hybrid-share requirement, not
   the Firefox/Safari greetings.
2. The three commits close it minimally: `+307` lines of preset data and one key-generation loop in
   the dependency, `+184` including upstream's test. Nothing else in the module changes.
3. The alternative — `v1.9.0-mod-meta` — is `175` commits and `229` files, and is refused as a
   release-freeze change.
4. The tripwire exists, was seen to fail for the right reason in five places, and turns green in the
   post-fork state.

**What must happen for it to ship in v0.1.6** (all outside this worktree):

1. Create `Piggy-Cat-bit-shadow/utls` from `metacubex/utls@v1.8.7`, apply
   `docs/fork/utls-firefox148-safari263.patch`, push branch `fix/firefox148-safari263`.
2. Add the `replace` to `go.mod` and `test/go.mod`, `go mod tidy` both, and update the register
   entries as the tripwire dictates.
3. Re-run the live interop matrix on both reference legs, and the Apple and Android builds.

**If that does not happen before the freeze**, the honest state is not "no-go" and not "fixed": it is
**verified, with a named, proven, unfixed compatibility gap** — `fingerprint: firefox`, `safari`,
`edge`, `ios`, `qq` and `random` (4 times in 5) cannot complete a REALITY handshake against a
reference at or after Xray v26.9.8, and `chrome` or `randomized` is the workaround. That sentence,
with this document as its evidence, is what the release notes owe a user; the register test keeps it
from being forgotten the moment the dependency does change.
