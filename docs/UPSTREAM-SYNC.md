# Upstream sync

How to find out what an upstream update broke, before it breaks it in the field.

This fork carries a lot of local semantics — a traffic scheduler, a socket-semantics profile, a
fast-path eligibility model, MASQUE and Naive work, the Apple overlays. The risk that matters is not a
bug in any of them. It is that SagerNet/sing-box changes underneath an assumption one of them makes,
and the change is silent: the build still succeeds, the tests still pass, and a policy stops applying.

So every load-bearing assumption has an owner: a tripwire, a behavioural comparison, or the compiler.

---

## The gate

```sh
./scripts/ci/verify-upstream-assumptions.sh
```

It prints the pinned revisions, runs the tripwires, and lists the assumptions the compiler already
enforces. About fifteen seconds. It runs on every push to `testing` through `.github/workflows/verify.yml`,
which also builds this fork's packages for linux, windows, freebsd and darwin+low_memory, and runs
their race suite.

The artifact workflows (`client-apple`, `client-macos`, `server-linux-amd64`, `release`) stay manual
dispatch on purpose: they build, sign and upload, and a push should not pay twenty minutes for that.

---

## The inventory

Each row is an assumption, what would break if it stopped holding, and what notices.

| Assumption | What breaks if it changes | Enforced by |
| --- | --- | --- |
| Every `option.AbstractDialerOptions` field is classified for native bypass | A newly added dial option is treated as irrelevant, and the fast path discards a socket semantic the operator asked for | `common/dialer` — `TestEveryDialerOptionIsClassified`, plus `BlockerUnclassified` failing closed at runtime |
| A hard single-family resolver strategy filters the literal destination | The fast path bypasses a connection the userspace path would have refused to dial | `common/dialer` — `TestFamilyStrategyAppliesToALiteralAddress` |
| The profile's zero value refuses | An outbound constructed without a profile bypasses every flow it is asked about | `common/dialer` — `TestZeroProfileRefuses` |
| Every `RuleActionRouteOptions` field reaches the connection metadata | The fast path judges a connection that never had that option applied — no error, no log, the setting just stops applying | `route` — `TestEveryRouteOptionReachesTheMetadata` (behavioural, per field) and its reflection half |
| `tun.ActionBypass` is honoured by Linux auto_redirect and by no TUN stack | The Direct Offload scope, its documentation and its cost model are all derived from this | `protocol/tun` — `native_bypass_dispatcher_test.go`, `native_bypass_trace_test.go` |
| `ActionBypass` carrying a `Port` is rewritten to `ActionFlow` | A bypass silently becomes a userspace flow, which is how the Port bug reached production once already | `protocol/tun` — `TestBypassWithAPortBecomesAFlow`, `route` — `fast_bypass_verdict_test.go` |
| A `NewTracker` on an accept or bypass verdict is never called for TCP | Anything built on attaching a tracker to a bypass is built on nothing | `protocol/tun` — `TestANewTrackerOnABypassIsNeverCreated`, `TestABypassFlowIsNeverCounted` |
| The direct outbound answers `PreMatchContinue` for TCP and UDP | The cost model, and the claim that neither verdict carries a tracker | `route` — `TestBothConfigurationsReachTheSameVerdictAndTheSameWork` |
| `N.CalculateFrontHeadroom` sums the chain without checking `WriterReplaceable` | The upload gate's reported headroom is half of what the copy engine computes, so `WriteOwnedBuffer` bounds the wrong buffer | `common/trafficsched` — the gate contract matrix |
| `bufio.CreatePacketBatchWriter` is a direct type assertion | The gate stops forwarding it, and every managed UDP flow degrades to per-packet syscalls with no visible symptom in byte counts | `common/trafficsched` — the packet-batch tests, plus `route`'s real-UDP integration test |
| `bufio.WriteOwnedBuffer` treats the writer's own MTU as a hard ceiling | A gate that reports `math.MaxInt` makes the copy engine compute a negative buffer size | `common/trafficsched` — the MTU catastrophe test |
| `InitializeReadWaiter` returning false means "use the waiter, do not copy" | The copy engine's batch path is skipped and the packet fast path silently reverts | `common/trafficsched` — packet batch tests |
| A `replace` covers one module path, and cronet-go is a tree of modules | The fork's Go bindings are used with upstream's native archives: a pairing nothing built or tested, and on linux/amd64 one that does not link | `scripts/ci/check-go-module-integrity.sh` — the parity rule is a PREFIX rule, so a new `lib/<os>_<arch>` path demands a pin instead of being missed |
| A v4-mapped address is compared against four-byte policy | DNS hijack, the FakeIP guard, route sets and every rule matching a CIDR set fail open, silently | `protocol/tun` — `mapped_address_test.go` (four symptoms, end to end through the stack) and `adapter` — `judge_flow_mapped_test.go` |
| `tun.GoConn.Splice` requires socket-backed platform IO, and carries the counters | The spliced path stops counting, or stops being attempted, and L2 becomes L3 without saying so | compiler (the call site in `route/splice.go`), plus the splice diagnostics |

## The compile-time half

These are enforced by the build, which is stronger than a test: a signature change stops the fork
rather than changing its behaviour.

```
tun.FlowTracker / FlowHandle / FlowVerdict / Handler        protocol/tun, route
tun.ForwardDispatcher / ForwardStage / ForwardWriteback     protocol/tun tests
tun.GoConn.Splice and tun.SpliceOptions counters            route/splice.go
adapter.BypassableOutbound / ConnectionTracker / FlowOutbound
adapter.FakeIPStore.Contains, adapter.FakeIPTransport
option.DialerOptions, option.AbstractDialerOptions
```

## Procedure for an upstream bump

1. **Bump and build.** `go get` the new revision, then `go build ./...` for the tag profile. A
   failure here is the good case: it names the assumption.
2. **Run the gate.** `./scripts/ci/verify-upstream-assumptions.sh`. Read it as an inventory rather
   than a pass/fail: a tripwire that fails is telling you which paragraph of which document needs to
   be re-derived, and the failure messages say so.
3. **Read the diff of the pinned revision**, not of the fork. The four areas to prioritise are the
   ones where a change is silent by construction: `option/outbound.go` and `option/rule_action.go`
   (new fields the fork must classify), `common/dialer/default.go` (where a field acquires socket
   meaning), sing-tun's `flow_dispatch.go` and the TUN stacks (verdict handling), and the copy
   engine's capability probing.
4. **Re-derive, do not adjust.** If a tripwire fails because the capability changed, the documents and
   the cost models built on it are wrong, and relaxing the assertion would leave a claim nobody
   checked. Round 3 wrote this down for `ActionBypass` specifically; it applies to every row above.
5. **Check the module tree, not the module.** A fork pin that names only the repository root leaves
   every nested module — a published subpackage, a platform binary — resolving to upstream. Run
   `scripts/ci/check-go-module-integrity.sh` after any dependency bump: its parity rule discovers the
   replaced paths from the root `go.mod` rather than from a list, so a new one is caught rather than
   counted.
6. **Record the new revision** in the affected documents — `docs/fork/direct-offload.md` and
   `docs/fork/native-bypass-trace.md` both name the pinned sing-tun revision in their reasoning.

## What is deliberately not a tripwire

Source-text guards. A grep for a string in a dependency's source is a tripwire that fails when the
line moves and passes when the meaning changes, which is the wrong way round. Where a behavioural
assertion was not possible, this document says so in the row rather than adding a guard that looks
like coverage.
