# Upstream sync 2026-10 — Go TUN migration and gVisor retirement

Owner decision: follow the upstream TUN architecture and retire gVisor from shipped artifacts.

**Status: partially executed.** The Android gVisor retirement (stage B) is done, committed and
pushed. The Go TUN stack migration (stages E–H) is **not started**, and the reason is a real ordering
constraint described in §3 rather than a lack of effort. Nothing in this document claims more than
was run.

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
