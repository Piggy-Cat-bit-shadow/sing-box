# Release-candidate final closure — acceptance report

**Base `fb51b5075` → FINAL `429265376`**, `local == origin/testing`, ordinary pushes only. No tag,
no Release, no signing. 14 commits. Three agents worked in **isolated worktrees** and each committed
on its own branch; the integrator cherry-picked with `-x` and never staged a shared tree (work order
§1.2 — the previous round was damaged twice by broad staging, once leaving HEAD unbuildable).

## The result that matters

| Command | Before | After |
| --- | --- | --- |
| `go build -tags "$TAGS" ./...` | **EXIT 1** | **EXIT 0** |
| `go build ./...` (untagged) | **EXIT 1**, 14 undefined symbols / 3 packages | **EXIT 0** |
| `go test -count=1 -tags "$TAGS" ./...` | 73 ok + 1 build failure | **74 ok, 0 FAIL** |

**The `experimental/libbox` link failure was never inherent.** It was reported as unfixable for
several rounds; it was a tag carrying a *linker-policy claim* into builds that cannot honour it.
`tfogo_checklinkname0` sat in `release/DEFAULT_BUILD_TAGS*` while `go build`/`go test ./...` link with
Go's default policy. The tag now travels with the flag (`cmd/internal/mobilebuildtags`,
`cmd/internal/build_boxdd`). Neither shipped CLI links libbox, so no product was affected. A computed
test derives the blocked-runtime-symbol set from the pinned toolchain's own `runtime` source instead
of a hand list — red-checked both ways.

The untagged build was not 3 missing symbols as recorded; the real count is **14 across 3 packages**.

## P0 findings

- **P0-A Android ABI**: the pinned client **did not compile** against a regenerated AAR. Three sites
  were missed, and they are two *layer types* the migration never modelled: an **implementer** of the
  bound Go interface (no call-site scan can see it) and an **extension receiver** (no dotted
  expression to match). Fixed in the fork; `.gitmodules` + gitlink + the gate's expected SHA moved.
  A clean-clone test proves the pair resolves. *Acceptance honesty: `libbox.aar` PASS, GUI APK **FAIL**
  — 4 errors from two **non-migration** causes (`promotePowerReportDraft` exists in no AAR;
  `createAutoRedirect` never implemented by the client).*
- **P0-B iOS wake chain**: the device axis was a **latch with no publisher**. `box_lifecycle.go` now
  owns the mapping, and the asymmetry is the fix — **a display turning on is not an unlock** (a push
  lights the lock screen), while `lockstate == 0` is the one fact that releases the level. No timer:
  no timer can tell a locked phone from an unlocked one. Also closed a second-order hole where every
  sleep after the first went unmeasured. Client patch (`docs/fork/apple-screen-state-observer.patch`,
  sha256 `51504470cc17…`) ports the observer from **the same repository's `dev` branch**, where it
  exists iOS-gated; `git apply --check` verified. Deliberately removes the display-on `wakeNow()`,
  which *is* the wake storm.
- **P0-C reuse**: two items recorded as unclosable **were closable**. `httpclient.Manager` idle-only
  retirement is now reachable from the boundary walk (and does not swap inner transports, unlike
  `ResetNetwork`), and XMUX is in-tree so real draining was implemented via a new
  `adapter.ReuseSuspect` capability — refusal atomic under the pool lock, teardown deferred to the
  last stream. sing-mux and naive/Cronet remain dependency-level, with file:function.
- **P0-D module parity**: `test/` built **upstream** `sing-tun` and a one-commit-behind `sing`. The
  old guard printed `PASSED` on that exact broken tree — the blind spot is now demonstrated by
  red-check. `PARITY_REPLACES` is **derived** from the toolchain's effective replaces (34 vs 3
  hand-listed), with an independent non-derived expectation so "dropped on both sides" also fails.
- **P0-F gates**: XHTTP was a string check; now compile-time `go list -deps` **plus** two runtime
  vless+xhttp cases. Red-checked: without the tag, 52/54 with both xhttp cases failing while the
  websocket control passes. `build-server.sh`'s stale claim was false in all three parts.

## Gate-fidelity problems the agents found in their own tools

Worth recording because each one *lied in the safe direction*: the first ABI gate was shell and
**reported PASS on the very call site it existed to catch**; a receiver-grouping error produced 4683
false violations; a filter silently skipped package-level records; and the gate could print
`SKIP: no Android client checkout` followed by `PASS: …verified across the client call sites`. It now
reports `PARTIAL` and never `PASS` with a skipped layer. One red-check *passed* when it should have
failed, which exposed a real coverage gap (tests drove the pool directly, bypassing
`Client.RetireSuspect`).

## Verification at the final SHA

`go build` tagged and untagged EXIT 0; full tagged suite **74 ok / 0 FAIL**; `-race` green on every
touched package; `-count=20 -race` on new tests; linux/windows/darwin cross-compiles EXIT 0;
`gofmt -l` clean; `go mod tidy -diff` clean in root, `test/` and `reference`. The 40 `test/`-module
failures are **not introduced** — proven by A/B against the base pins — and classified 23 no-Docker,
7 Linux-only, 6 no-peer, 4 pre-existing.

## Not done, and why

- **Apple gitlink not advanced.** The fix is pushed to the fork (`8599039f6`, branch + tag
  `libbox-stringbox-abi-1`, applies cleanly at `816600ab3`), but the owner has in-flight work in that
  submodule and it moved **twice** during this run. Advancing it is one command and is the owner's
  call.
- **Apple client carries none of the migration** at `816600ab3`: 7 `name()` + 6 `address()` +
  3 `mask()` + 3 `message()` + 1 `getHTTPProxyServer()` call sites, zero migrated. It will not compile
  against a rebuilt framework until the fork commit is picked up.
- **No Apple compile and no GUI APK** on this host; the Apple patch is apply-verified only.
- iOS Darwin notification names are not public API — not a support claim, and unverified without a
  device.
- No workflow was dispatched by the agents; dispatches and pushes stayed with the integrator.

## Final answer: can this be released?

**Not yet, and the blockers are small and named.** The kernel itself is in better shape than it has
been: both builds and the whole suite pass for the first time, and the failure that was written off
as inherent is gone. What remains is **cross-repository binding, not kernel correctness** — both
clients must pick up their StringBox call sites, and the Android APK still has four errors from two
unrelated, pre-existing gaps. Release after the two client revisions are pinned and one acceptance
run is executed against a single frozen SHA. Until then, no claim of "final SHA all green" is
supportable, because the existing Actions evidence spans four different SHAs.
