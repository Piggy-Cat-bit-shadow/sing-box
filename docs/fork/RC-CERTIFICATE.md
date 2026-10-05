# RC certificate

```text
Candidate           0bd28848a
origin/testing      0bd28848a  (equal)
Product commit      9e8fa9891 — the candidate adds only this file (docs/release: certify the RC)
Artifacts built at  af9abd043 — the delta to the candidate is docs and one sweep script, no
                    product code
Worktree            clean except ` m clients/apple` — the build-time compatibility overlay that
                    scripts/ci/prepare-apple-client.sh applies, which is never committed
sing                replace => github.com/Piggy-Cat-bit-shadow/sing v0.9.6-0.20261004070536-dc9f4ea02e02
                    (checkout dc9f4ea02e0249d2abd3c94c85c408dedd53d58a)
sing-tun            v0.9.7-0.20261002083955-3f8acd9da65b (unmodified, not forked)
Final Verify        run 37250304913 on 0bd28848a: GREEN (4m15s) — gofmt, pinned-upstream assumptions,
                    cronet provenance (pins), build matrix, race on the fork's own data paths,
                    race on the configuration surface
                    run 37249958134 on 9e8fa9891: GREEN (4m04s), the same steps
Apple client        clients/apple @ 117f3faaa1f451cc40e8c844b929823401b38910 on hako-ui, pushed to
                    the fork, and what the parent's gitlink records
```

## Verdict

```text
READY FOR RC PUBLISH
```

No known P0, no known P1, no remaining code blocker. What remains is device evidence that this
environment cannot produce (section "Test-evidence boundaries"), which is what an RC is for.

## Feature verdicts

**Load balance group — READY.** A sing-box-native outbound group, not a Clash compatibility layer:
an optional flow-aware capability on top of the unchanged `OutboundGroup` contract, so no existing
group or caller moved. Each new connection gets one member for its life; a UDP session gets one
member for the session, not per datagram; the pre-match preview consumes nothing and the branch whose
verdict owns the port performs its own committing resolution. Health reuses the urltest measurement
store and its scope, so a `loadbalance` and a `urltest` group with the same URL act on the same facts;
a member with no measurement is not treated as dead, and when nothing is known-good the filter is
suspended rather than degenerating to one member. The control plane does not fabricate a current
member (`now` is omitted). Ten mutations, all noticed.

**TCP splice diagnostics — COMPLETE.** `spliceConnection` records exactly one outcome per connection
at the point its decision is final: the caller's skip, a source that is not a TUN stream, every
target-side rejection the shared classifier can produce, a failure to forward buffered data, a
declined handover, and success. One atomic add per connection; no per-byte work, no allocation, no
logging on the path; `attempts == successes + sum(reasons)` per transport, checked by a test. Three
mutations red. What the tests cannot reach is stated in the file and in the device checklist:
success, `splice_rejected`, the source reader/writer mismatch and the cached-write failure are only
decided after a live `*tun.GoConn` exists, and that type can only be constructed inside sing-tun.

**Pre-match / full-match equivalence — COMPLETE, and it found a bug.** The two passes decided which
actions contribute route options, in two places, and disagreed about one case: a `bypass` action with
no outbound applied its options in pre-match and none in the full path. The pre-match behaviour was
wrong — a bypass without an outbound routes nothing — and its visible effect was that the rewrite
suppressed the bypass verdict, so the rule silently did nothing. The decision now lives in one
function that both passes call and that is the only caller of the field-level applier. The
equivalence tests compare a canonical policy snapshot for every field of the option struct (reflection
-checked, so a new field cannot pass unnoticed), for a combined case, and for both bypass directions,
observing the metadata through a following rule where the pass falls through and through the verdict
where it returns. Three mutations red.

**v4-mapped ingress boundary — COMPLETE.** The positive direction was already covered; the negative
one was not. NAT64 (`64:ff9b::/96`) and the deprecated IPv4-compatible form are pinned as *not*
mapped, on both ingress entry points and through the real packet path. Converting NAT64 to IPv4 turns
a routable IPv6 destination into a different IPv4 one and stops every rule written against the prefix
from matching; that mutation is red, and so is removing canonicalisation.

**DNS / FakeIP, dual stack, Direct, proxies, UDP, mux, network transition — no regression.** The load
balance group is called from `resolveOutbound`, after the DNS hijack, the FakeIP decision and the
route rules, so it cannot divert either; no file under `dns/`, `protocol/tun/`'s policy paths or the
FakeIP paths is changed by this release. The group returns a member's own connection, so splice
eligibility, packet batching, syscall unwrapping and counters are whatever the leaf has, and it never
becomes a data-plane wrapper.

## Verification

```text
Race            RACE=0 — ./route/... ./protocol/group/... ./protocol/tun/... ./adapter/...
                ./common/trafficsched/...
Build matrix    linux/amd64 OK, windows/amd64 OK, freebsd/amd64 OK, darwin/amd64 OK,
                darwin/arm64 OK, low_memory OK   (trafficclass, trafficsched, dialer, direct,
                tun, group, route, option, adapter, clashapi)
Full suite      go test ./... — all packages ok except one pre-existing failure:
                experimental/libbox's TEST BINARY does not link on this machine with Go 1.25.5
                ("invalid reference to runtime.fwdSig"). Reproduced at the baseline commit
                da1da013a with the same command, so it is not from this release; the package's
                library builds, and the Apple/Android artifacts are built through
                cmd/internal/build_libbox, which succeeds (below).
Mutation sweep  scripts/dev/release-mutation-sweep.sh — PASS, 18/18 mutations turn their named
                test red and green again (load balance 10, TCP splice 3, pre-match/full-match 3,
                mapped-address boundary 2)
Config          `sing-box check` accepts a configuration using the new group type; an unknown
                strategy is refused at check time and an unknown member at start, as designed
```

## Artifacts

```text
Apple (unsigned)   dist/apple/JiejieBox-unsigned.ipa   41,560,622 bytes
                   sha256 20002221c50b9d2d05ef11593f2d1dd2816079ac0ded94c637230f9ea95ce06a
                   dist/apple/SFM-unsigned.dmg         86,876,300 bytes
                   sha256 517baf46c569999a2787ed82f1a680053de99295181c88b421a4fd52c1084a9e
                   iOS and macOS: BUILD SUCCEEDED, exported, and NOT uploaded
Linux              dist/sing-box-linux-amd64            79,413,432 bytes
                   sha256 917086f2b5cc4641fa49f0b84cefd0e7204626e3769fc6c2741e2a78734900be
                   ELF 64-bit x86-64, statically linked, server profile
                   (DEFAULT_BUILD_TAGS_OTHERS)
```

The Apple artifacts were built at commit `af9abd043`; the only changes from there to the candidate are
`docs/fork/*.md` and `scripts/dev/release-mutation-sweep.sh`, so the product code in them is the
candidate's. `libbox: built from this repository` in the build log is the record that the framework
came from this working tree and not from a downloaded release.

## Cronet native archive provenance

```text
cronet provenance: PASS — the linked archives are the ones the release recorded
31 cronet-go modules in the resolved graph, every one of them replacing to the fork
```

The module paths stay upstream (`github.com/sagernet/cronet-go/...`) so imports need no rewriting,
and each of the 31 carries its own replace to the fork. A module path therefore proves nothing on its
own: the resolved replacement is the fact, and the gate fails if any module has no replace or
replaces elsewhere. Apple links five slices, recorded by size and SHA256 in
`release/cronet-provenance.txt`:

```text
github.com/sagernet/cronet-go/lib/darwin_amd64          libcronet.a  50,782,216  f747bb46b860…
github.com/sagernet/cronet-go/lib/darwin_arm64          libcronet.a  48,110,296  f680ff966fb7…
github.com/sagernet/cronet-go/lib/ios_amd64_simulator   libcronet.a  48,696,104  45e7a6924825…
github.com/sagernet/cronet-go/lib/ios_arm64             libcronet.a  46,280,672  6863693a72d4…
github.com/sagernet/cronet-go/lib/ios_arm64_simulator   libcronet.a  46,283,072  44cbf24e2b93…
```

Push CI checks the pins on every run; `scripts/release-apple.sh` passes `--require-archives`, so a
release cannot be cut without comparing the bytes.

## Configuration and schema

`option.LoadBalanceOutboundOptions` is decoded by the registry and `docs/schema.json` is regenerated
from it, so the schema and the decoder agree about `type`, `outbounds` (with tag references),
`strategy`, `url`, `expected_status`, `interval`, `tolerance` and `idle_timeout`. A configuration
that uses the type is **not** loadable by official sing-box, which `docs/fork/load-balance.md` states
plainly.

## Test-evidence boundaries

These are not code blockers; they are the reasons an RC exists rather than a release.

```text
Real Linux TUN        no root, no TUN device, no second interface on this machine; moreover the
                      Linux binary cannot be executed here (no qemu, and the docker CLI is present
                      with no daemon). Procedure: docs/fork/real-tun-validation.md and
                      docs/fork/RC-DEVICE-CHECKLIST.md
Apple real device     no signed artifacts (no Apple credentials in this environment) and no
                      simulator runtime, so no snapshot and no on-device NetworkExtension run
Splice outcomes       success / splice_rejected / source_reader_writer_mismatch / cached_write_failed
                      are only decidable after a live *tun.GoConn exists, which only sing-tun can
                      construct; they are read from the device log instead
libbox unit tests     the package's test binary does not link on this toolchain (pre-existing,
                      reproduced at the baseline); the library and the artifacts build
Signed artifacts      this environment builds UNSIGNED: APPLE_SIGNING_MODE defaults to unsigned and
                      no signing identity is configured. Packaging and compile are proven; the
                      entitlements, App Group and Network Extension are not exercised
```

## Exact commands after waking

Nothing below has been run. Replace the placeholders with real Apple values.

```bash
# 1. Sign, archive and export for TestFlight (this DOES upload):
export APPLE_TEAM_ID=... APPLE_BASE_BUNDLE_ID=... APPLE_APP_GROUP_ID=group....
./scripts/release-apple.sh testflight          # iOS and macOS into one App Record
#   or one platform at a time:
./scripts/release-apple.sh testflight-ios
./scripts/release-apple.sh testflight-macos

# 2. Or produce signed local artifacts without uploading:
./scripts/release-apple.sh development
./scripts/release-apple.sh development-ios
./scripts/release-apple.sh development-macos

# 3. Linux release artifact:
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
shasum -a 256 dist/sing-box-linux-amd64
```

A GitHub release is not prepared by this round: no tag was created and no release was drafted.
