# Release certificate

The evidence behind the current `testing` tree, what it covers, and what it does not.

A certificate that lists only what passes is a marketing document. Each row below says how the claim
was checked and on what, and the rows that are NOT verified say so.

## Verdict

    NOT READY FOR A STABLE MILESTONE

The two blockers are environmental rather than code defects, and neither can be closed from the
development environment:

1. **No real data plane has ever been exercised.** No TUN, no root, no Linux, no Apple
   NetworkExtension. L0 route exclusion, L2 splice, the flow table, DNS hijack on a real device,
   FakeIP on a real device and network transitions have zero executed evidence. Round 3 established
   what the pinned sing-tun does with a bypass verdict *in process*; that is not the same as a device.
2. **The Apple products are built and signed by a manual workflow that has not run against this
   tree.** The last green Apple run predates Rounds 2 and 3.

Everything else below is either verified here or named as outstanding.

## Verified in this environment

| Area | Evidence | Where |
| --- | --- | --- |
| Builds | linux/amd64, windows/amd64, freebsd/amd64, darwin/arm64+low_memory; the production darwin/arm64 binary builds with the default tag profile and reports its revision | `scripts/ci/verify-upstream-assumptions.sh`, `.github/workflows/verify.yml` |
| Race | `-race` green on the fork's own packages: trafficclass, trafficsched, dialer, direct, tun, route, option | CI step, and locally |
| Pinned-upstream assumptions | Fifteen tripwires, one of them new this round, plus the compile-time inventory | `scripts/ci/verify-upstream-assumptions.sh`, `docs/UPSTREAM-SYNC.md` |
| Direct semantics | Profile completeness, zero-value refusal, family-strategy exception, four-layer FakeIP guard, verdict attribution | `common/dialer`, `protocol/direct`, `protocol/tun`, `route` |
| Native bypass truth | Behavioural trace: `ActionBypass` is not honoured by any TUN stack, and a `NewTracker` on one is never called for TCP | `docs/fork/native-bypass-trace.md` |
| Fast-path cost | Eligibility 15-17 ns / 0 allocs; end-to-end pre-match 135 ns / 48 B / 2 allocs for both verdicts | `route/bypass_capability_cost_test.go` |
| Tracker lifecycle | 100 connections through the real binary: 100 rows while held, 0 after both ends close | `scripts/ci/measure-client-baseline.sh` |
| Memory shape | Two cycles of 100 connections: ~20-40 KB retained per live connection, +1.6 MiB between cycles (below the leak threshold), idle RSS ~43 MiB on macOS arm64 | same |
| Scheduler | Aggregate shaping, no over-admission, high-priority coverage, goroutine lifecycle, transition release | `common/trafficsched` |
| Traffic class | Per-flow classification, whole-token matching, lane mapping | `common/trafficclass`, `route` |
| MASQUE, Naive, protocols | Their packages' suites, in the affected-package run and in CI | CI |
| Config and schema | `route.traffic_scheduler` round-trips, absent stays byte-identical, `docs/schema.json` regenerated | `option` |
| Pinned dependency tree | Every module path cronet-go publishes is pinned to the fork, and the parity rule is a prefix rule so a new platform cannot be missed | `scripts/ci/check-go-module-integrity.sh` |
| v4-mapped policy comparisons | Four symptoms (DNS hijack, FakeIP guard, route sets, router metadata) asserted end to end through the real stack, with two mutations proving they bite | `protocol/tun/mapped_address_test.go`, `adapter/judge_flow_mapped_test.go` |

## Not verified

| Area | Why not | Procedure |
| --- | --- | --- |
| L0 route exclusion on a real OS | needs root and a routing table you can change | `docs/fork/real-tun-validation.md` §1 |
| L2 splice attempted/succeeded per flow | needs a real TUN; **and the TCP splice outcome is not instrumented** — `SpliceDiagnostics` covers UDP only | §2 |
| L2 versus L3 under latency and a bandwidth cap | needs netem, which needs root | §3 |
| Tracker correctness under L2 | needs §2 first | §4 |
| UDP on a real device | needs a real TUN | §5 |
| DNS and FakeIP on a real device, including the control | needs a real TUN | §6 |
| Network transitions | needs interfaces you can take down | §7 |
| Apple NetworkExtension | needs a signed build and a device | §8 |
| Startup and idle memory under a TUN client | the TUN stack, route mirror and flow table are not in the SOCKS baseline | §8 |

## Release blockers, exactly

1. **A real-TUN run of §1, §2, §4, §6 and §7**, on Linux with root, with the results recorded here.
   Until then the fork's central architectural claims about L0 and L2 are argued from code.
2. **The TCP splice instrumentation named in §2.** Without it the L2 question cannot be answered by
   measurement at all, and any performance comparison of splice against the generic copy would be an
   inference from throughput.
3. **An Apple manual validation run**, because that is the product environment and no CI can stand in
   for it.
4. **A green push-triggered `Verify` run** on the commit being released. Its first run failed and the
   failure was real: it was the first Linux build in this repository to link cronet, and the pin
   delivered upstream's archive, which does not link. That is fixed; the next run is what confirms the
   Linux link rather than a rerun until it passes.

## What is not a blocker

- **`ActionBypass` being inert in TUN mode.** It is documented, traced, and costs nothing measurable;
  the eligibility model that decides it is correct where it is honoured, which is Linux
  `auto_redirect`.
- **The absence of a native tracker bridge.** Rejected on evidence, with the reason recorded.
- **The fork's feature density.** Every feature listed above has a test surface and an owner in the
  upstream-sync inventory.
