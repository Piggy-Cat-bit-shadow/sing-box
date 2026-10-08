# Upstream sync 2026-10 — Go TUN migration and gVisor retirement

Owner decision: follow the upstream TUN architecture and retire gVisor from shipped artifacts.

**Status: executed.** The Android gVisor retirement (stage B) was done first. The Go TUN stack
migration, the sing-tun 040 re-base, the legacy `stack` semantics and the gVisor dependency removal
(stages C–G) were subsequently executed; §7 records what was actually done and the evidence for it.
Sections §3 and §4 are kept as the state **at the time of writing** and are explicitly marked
superseded where they no longer describe the tree, because the reasoning in them is what the next
stage acted on and rewriting it would erase why the order was chosen.

One correction worth stating up front, because §3 asserted the opposite: the dependency edge was
**not** blocked on the Go TUN stack. At the point the PENDING branch was written, no file in
`protocol/tun` imported gVisor at all — the fork's own earlier gVisor removal had already deleted
that path. The only main-module importer was `cmd/ci-artifact-probe/probe_gvisor.go`, the phase-1
tripwire's own *positive control*, which existed to prove the fork pin. The edge the tripwire
reported as pending was being held open by the tripwire itself. §7 records the correction.

## 1. Baseline (read from the repositories, not assumed)

| | |
| --- | --- |
| FORK_BASELINE | `890bdc5bd967a25bd5dce2607c1398564e957942` — end of phase 3.5 |
| UPSTREAM_TIP | `fe92ab3e78a9bb7d448c155ef6906218e2ca5453` — `SagerNet/sing-box`, branch `testing` |
| MERGE_BASE | `b93f56a7a0469d8e5993b1369dfaf9225ac85814` — "Move auto-redirect and bridge index allocation out of constructors" |
| Upstream commits ahead of merge base | **39** |
| Fork commits ahead of merge base | 1355 |

Both TUN commits are present locally: `a1b01b415` "Add go TUN stack", `ede8d9acf` "Remove dependency
on gVisor". The upstream default branch is `testing`, not `main`; the previously-quoted tip was
re-confirmed rather than assumed.

## 2. Stage B — Android gVisor retirement (DONE)

`aaaefb00b` was a mixed-purpose commit. A mechanical `git revert -n` was attempted first, as the
brief requires, and it conflicted on `cmd/internal/build_libbox/main.go`; the resolution is semantic.

| Part of `aaaefb00b` | Decision | Why |
| --- | --- | --- |
| `androidTags = ["with_gvisor"]` and its two appends | **reverted** | this is the product decision, and the Android UI no longer depends on `mixed`/`gvisor` |
| `ReadTag()`: `SING_BOX_BUILD_VERSION` + short-commit fallback | **kept** | unrelated to gVisor; `ReadTag()` still has five callers including libbox provenance/version, and reverting it would regress build reliability to satisfy the shape of a SHA |

The tag composition has since moved into `ResolveBuildTags`, so the removal happened there and the
now-dead `androidTags` slice was deleted rather than left as an empty shell.

**Inverted invariant.** The Phase-1 tripwire asserted that Android *did* compile `with_gvisor` and
that the pinned gVisor was therefore the patched fork. That was correct while gVisor shipped. It is
now inverted rather than deleted, because deleting it would delete the only thing that notices the
exposure returning:

```
no shipped variant (android-main, android-legacy, apple) may compile with_gvisor
```

Every failure text says that re-enabling it needs a new product review and a restored, re-audited
LX 048. The check asks `ResolveBuildTags` — the same function the builders use — because a scan of
the profile tag files is what missed the original exposure.

**Artifact-level proof (stage L, partial).** A gVisor-free Android `c-archive` built with the
resolved tags contains **zero** `gvisor` entries in its module provenance:

```
GOOS=android GOARCH=arm64 go build -tags "$(cat release/DEFAULT_BUILD_TAGS | sed 's/,with_naive_outbound//')" \
    -buildmode=c-archive -o /tmp/libbox.a ./experimental/libbox/
go version -m /tmp/libbox.a | grep -c gvisor   # -> 0
```

The user-facing outcome is also asserted positively: `TestAndroidShipsWithoutGVisor` resolves the
Android variants and requires them to be non-empty (so the assertion is not vacuous) and gVisor-free.
**This is the evidence that a default Android build no longer needs gVisor to start a TUN.**

## 3. The blocker: gVisor cannot leave `go.mod` until the Go stack lands

> **SUPERSEDED — see §7.** This section described the state before the Go TUN stack landed, and the
> premise it rests on ("`protocol/tun` still contains a `with_gvisor`-tagged code path") was already
> false when it was written. It is kept because it is the reasoning the next stage was handed.

This is the finding that determines the order of the remaining stages, and it is why stages C and E
cannot be done in the sequence the brief suggests.

`protocol/tun` still contains a `with_gvisor`-tagged code path, so **the module graph requires
`github.com/sagernet/gvisor` regardless of whether any shipped profile names the tag.** Deleting the
`replace` directive or the `require` now would not compile that path, and deleting the path is
precisely what upstream `ede8d9a` does — *after* `a1b01b4`.

Upstream's own ordering is therefore:

```
a1b01b4 Add go TUN stack            -> the sing-tun own-stack implementation
ede8d9a Remove dependency on gVisor -> the gVisor code path is deleted, module graph drops it
```

So the honest current state is:

| Question | Answer |
| --- | --- |
| Does Android ship `with_gvisor`? | **No** |
| Does Apple ship `with_gvisor`? | **No** |
| Is the shipped exposure to LX 048 zero? | **Yes** |
| Is gVisor still a dependency edge in `go.mod`? | **Yes — PENDING**, removed by the Go TUN stack migration |
| Is the retired fork still wired in? | Yes, and the tripwire reports it as PENDING rather than failing |

The CI check reports `PENDING` and names the migration rather than failing, because failing would
make CI red for a correct mid-migration tree and train maintainers to ignore the check. The blast
radius of the defect is already closed; what remains is housekeeping that the next stage performs.
When `a1b01b4`+`ede8d9a` land, **that branch must become a hard failure** if the `replace` survives.

## 4. Stages NOT started

> **SUPERSEDED — see §7.** The table below is the state at the time of writing. C, D, E, F and G, and
> the `PENDING` conversion, were executed afterwards; H, J, K and P remain unstarted.

Listed explicitly so the gap is not mistaken for completion.

| Stage | Content | Status |
| --- | --- | --- |
| C (rest) | remove `github.com/sagernet/gvisor` from `go.mod`/`go.sum`, delete the `replace`, delete the `with_gvisor` tag from build profiles and Android tag composition | **BLOCKED on E** per §3 |
| D | legacy `stack` config semantics: explicit `gvisor`/`mixed` must fail clearly rather than silently selecting the Go stack; unset follows the new default | not started |
| E | adopt `a1b01b4` "Add go TUN stack" — semantic port, not a blind cherry-pick | not started |
| F | re-audit and rebase/recreate the sing-tun 040 fork onto the upstream Go-stack sing-tun revision; decide whether 040 is still load-bearing given `stack: system` reachability | not started; the current pin is `v0.0.0-20261008082323-1cd9bc2216df` |
| G | adopt `ede8d9a` "Remove dependency on gVisor" | not started |
| H | the four-commit TUN chain: `64124b78` Android auto-redirect, `b3f2f17d` auto-redirect routing, `3e21554d` DNS mode without `auto_route`, `bb2b9d92` forward NAT UDP mapping and fragments | not started; dependency graph not yet drawn |
| J | dedicated red-team of the new stack (TCP / UDP / DNS / Android matrices) | not started |
| K | resource and performance comparison, local repeatable benchmarks | not started |
| P | the full 39-commit `MERGE_BASE..UPSTREAM_TIP` audit | not started |

The reason is a single genuine hard blocker of the kind the brief permits stopping for: **removing
gVisor requires a high-risk dependency ABI migration** (the sing-tun revision bump that brings the
own-stack implementation), and doing the TUN migration halfway would leave the tree with a TUN path
that compiles but is not the one the config semantics describe. That is worse than an honest stop.

## 5. What the next stage must do first

1. **Diff the sing-tun revisions** — the current fork base against upstream's pin — and confirm
   whether `System.acceptLoop`'s unexpected-Accept failure (LX 040) still exists in the new
   revision. If it does and `stack: "system"` remains a shipped, reachable path, 040 is still
   load-bearing and must be rebased onto the new base as a **single-purpose** fork
   (`sync/go-stack-plus-040`) carrying only that patch plus its regression test — not a merge of the
   old tree. If the new default Go stack never reaches `stack_system.go` **and** `system` is no
   longer reachable, only then does 040 enter retirement review. "The default is no longer `system`"
   is not by itself a reason to drop a fix that is still reachable from config.
2. **Port `a1b01b4` semantically** onto this fork's `protocol/tun`, which is heavily modified — the
   DNS hijack isolation (LX 046), the in-flight cap, generation isolation, cache generation
   ownership, dual-stack racing, FakeIP mapped-v6 handling, `traffic_class`, the native bypass path,
   packet batch/copy capabilities and `TrimMemory` all have to survive, because none of them is
   invalidated by the stack underneath them changing.
3. **Then** delete the gVisor code path, the dependency, the replace and the tag, and turn the
   `PENDING` branch of the CI tripwire into a failure.
4. Only then the Android auto-redirect / DNS-mode / forward-NAT chain, and the rest of the 39-commit
   audit.

## 6. Preserved history

LX 048 is recorded in `docs/fork/lx-stability-audit-phase1.md` as **FIX → RETIRED**, with all four
facts: why it was fixed, which product decision turned it into a shipped risk, which later product
decision removed that risk, and that the fork remote is retained as engineering history. It is
retired because the **exposure** is gone, not because the finding was mistaken. The gVisor fork
remote `Piggy-Cat-bit-shadow/gvisor` is deliberately **not** deleted.

Nothing in phase 1 was rewritten.

## 7. Executed (second pass) — what actually changed

### 7.1 sing-tun: 040 re-based, not retired

| | |
| --- | --- |
| Old required version | `v0.9.7-0.20261006124248-d769a7080ca2`, replaced by `Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008082323-1cd9bc2216df` (`fix/acceptloop-selfheal` @ `1cd9bc2216df`) |
| New required version | `v0.9.7-0.20261007151655-7539c9855f19` — what upstream `testing` @ `fe92ab3e7` requires *and* what `a1b01b4` itself is written against (`a1b01b4` does not change sing-tun) |
| 040 at the new revision | **still present.** `stack_system.go`'s `acceptLoop` still does `conn, err := listener.Accept(); if err != nil { return }`. Every `SagerNet/sing-tun` branch (`dev`, `main`, `stable`, `dev-firewalld`, `draft-windows-auto-redirect`, `codex/propose-fix-for-docker-firewall-policy-bypass`) still returns bare. Upstream has not fixed it |
| Is `stack: "system"` reachable? | **Yes.** `option/tun.go` keeps `Stack string` (declared field, so still decoded; removed from the schema enum only) → `protocol/tun` `stack: options.Stack` → `tun.NewStack` → sing-tun `case "system": return NewSystem(...)`. Only `includeAllNetworks` rejects it |
| Action | new branch `sync/go-stack-plus-040`, base `7539c9855f19`, 040 code cherry-picked from `665fbe2`, plus its regression test and the provenance notice. Final SHA `46cfb7ff31fea7c2015b02f8126aae12af2baf4c`, pseudo-version `v0.0.0-20261008131128-46cfb7ff31fe` |
| Red/green | a behavioural probe written against the pre-fix API (`acceptLoop(listener, tcpNat)`) that injects one unexpected accept error and then offers a new connection fails on `7539c9855f19` ("the accept loop exited permanently…"); the four committed tests pass with the change |

### 7.2 `a1b01b4` semantic port

The tree already carried a semantic port of `a1b01b4` (the fork's own `Add go TUN stack` commits,
applied on each upstream sync). The second pass verified every hunk of the upstream commit against
the fork's tree and classified it; see the migration report rather than repeating the table here.
The outcome is that every hunk is either present unchanged or superseded by a stronger fork
implementation, and no upstream interface was allowed to replace a fork one.

### 7.3 gVisor dependency removal (stage C rest + G)

- `go.mod`: the `replace github.com/sagernet/gvisor => github.com/Piggy-Cat-bit-shadow/gvisor …`
  directive is deleted and replaced by a retirement record; the direct `require` is gone. `go mod
  tidy` leaves `github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1 // indirect`, which is
  exactly upstream's own end state — sing-tun still contains `with_gvisor`-tagged packages, so the
  module stays in the graph without being active.
- `cmd/ci-artifact-probe/probe_gvisor.go` is deleted. It was the last importer, and it existed to
  prove the now-retired fork pin; keeping it would have kept gVisor an active dependency purely to
  test a dependency that must not exist. The probe itself stays and now carries a negative assertion.
- The retired fork's remote is **not** deleted.
- Both `PENDING` branches became hard failures:
  `cmd/internal/build_libbox/tag_policy_test.go` (`TestGVisorIsRetiredFromTheModuleGraph`: no
  replace, no active require, no import anywhere in the module) and
  `scripts/ci/verify-upstream-assumptions.sh` (same, plus an artifact-level check: the probe linked
  with the shipped tag set must show no gVisor module and no `with_gvisor` tag in `go version -m`).
- 048 is FIX → **RETIRED** with the remote preserved, as recorded in
  `docs/fork/lx-stability-audit-phase1.md`.

### 7.4 Legacy `stack` semantics (stage D)

Final behaviour matches upstream 1.15: unset selects sing-tun's Go stack; `system` selects the
system stack; `gvisor` and `mixed` are still parsed and still reported as deprecated, and then fail
at stack construction with `gVisor is not included in this build, rebuild with -tags with_gvisor`
in a build without the tag — they are **never** mapped onto the Go stack. A genuinely unknown value
fails with `unknown stack: <value>`. Tests live in
`protocol/tun/legacy_stack_semantics_test.go` and cover unset, `go`, `system`, `gvisor`, `mixed` and
an unknown value, through the production constructor.

### 7.5 Still not started

Stages H, J, K and P from §4 are unchanged: the Android auto-redirect / DNS-mode / forward-NAT
chain, the dedicated red-team matrix, the resource/performance comparison, and the full 39-commit
`MERGE_BASE..UPSTREAM_TIP` audit.
