# v0.1.6 final closure ledger

This is the current authoritative record. `v016-correction-round-ledger.md` covers the previous round;
`v016-five-workstream-final-report.md` covers the round before that. Read this one for the state now.

```text
LIVE_ORIGIN_SHA_AT_G0   bc7456db9d5f30c09ff5eb74866cc753f3a9eb8f
INTEGRATION_BASE        bc7456db9d5f30c09ff5eb74866cc753f3a9eb8f
FINAL_SHA               see the closing block, recorded after the last push
ORIGINAL_TREE_STATE     C:\src\sing-box at 8d78dcdd, clients/desktop dirty; NEVER written to
GO_VERSION / OS         go1.26.8 windows/amd64, CGO_ENABLED=1 for race runs
WORKFLOW_TRIGGER_AUDIT  verify.yml = push[testing, ALL paths]; android-core-arm64.yml =
                        push[testing, path-filtered]; the other seven are workflow_dispatch only.
                        `[skip ci]` covers push and pull_request and NOTHING else, which is why the
                        audit reads the `on:` of every file rather than trusting the token.
STATUS                  see the closing block
```

---

## 1. PATH-01 — `Hops` reported the OPPOSITE packet order from `Build`

`Build` reverses its walk; `leaves.go`'s enumeration did not. For the same topology:

```text
exit.detour = entry    Build.Hops = [entry, exit]    Hops()/Leaves() = [exit, entry]
```

So `Exit` meant the routing-selected hop in one API and the deepest underlay in the other, and
`Position` counted from opposite ends. `ValidateRoots` uses `Hops`, so `HopCheck.Position`,
`HopCheck.Exit` and `Failure.Hop` all inherited it.

Fixed by reversing each route ONCE, when it is complete, in `reverseRoute` - which also reverses each
node's physical chain and renumbers `Position` and `Exit`. Reversing inside the descent would flip each
suffix at every level and the result would depend on the depth; the first version of the fix did
exactly that and was replaced before it was ever committed.

`Exit` is now the LAST hop in packet order, which is the hop the routing selected - the same answer
`Path.Exit()` gives. Deliberately NOT "the node with no dependency": a route that ended at a dependency
which does not resolve has no routing-selected hop in it at all.

### 1.1 The requirement axis had to move with it, and that is a measurement

`nodeRequirementFor`, `advertisedNetworks` and `anyNodeCarries` all asked "did the business flow
arrive here" by testing `Position > 0`. `Position` counts from the hop nearest THIS DEVICE, and for a
route with a detour that hop is a DEPENDENCY.

MEASURED: applying the ordering change alone turned `TestUoTOverATCPonlyMiddleHopCarriesTheDatagram`
and two matrix rows red, because a legal TCP-only middle hop under a UoT outbound was then demanded the
BUSINESS network. Green again once the axis moved.

The axis is now a named predicate `businessEntry`, stated in terms of the node's OWN CHAIN rather than
an index: a node is where the flow arrives exactly when nothing was dialled THROUGH it, i.e.
`Position == len(PhysicalPath)-1`. That stays correct whichever end `Position` counts from.

`anyNodeCarries` gains the same filter, which closes a real MISS rather than a cosmetic one: it answered
"can any reachable node carry this network" over dependencies too, so a udp-carrying UNDERLAY would have
blessed a group whose exit is tcp-only. The task order flagged this exact case.

### 1.2 Two diamond tests keyed both routes on one tag

They asserted that `shared` was the leaf of BOTH routes, which was only possible while every route's
last node was its deepest dependency. Under packet order a route's leaf is the hop the routing
selected, which is a different object per route. The corrected tests assert route A's leaf is `middle`
and that `shared` is enumerated on route A as a NON-exit dependency at position 0 - a sharper statement
of the same property, and it now also pins that a dependency is not an exit.

## 2. PATH-02 — `ControlPath` was reversed with the physical order

The task order names three orders and the code was treating two as one:

```text
route selection order (ControlPath)   outer selector -> inner loadbalance -> selected leaf
physical wire order                   device -> underlay entry -> middle -> chosen proxy exit
dependency declaration order          chosen proxy exit -> middle -> underlay entry
```

`reversePacketOrder` reversed `ControlPath` too, applying a PHYSICAL correction to a CONTROL-plane
list. The selection sequence is root-to-leaf by construction and packet order does not change who
decided what; reporting it in wire order claims the innermost group decided first. `ControlPath` is no
longer reversed and its doc now says what it is, with `GroupsNamed` for a caller wanting only groups.

## 3. The urltest defect, and the suite that was correctly reporting it

**This is the headline of the round.** `common/urltest`'s six-ish failing cases had changing NAMES
between runs of the same commit, which read like flakiness. It is not flakiness and it is not the
test's fault.

Go's Windows monotonic clock is NOT QPC. `runtime·nanotime1` reads
`KUSER_SHARED_DATA.InterruptTime`, which the OS updates at clock interrupts. Measured on this host:

```text
QueryPerformanceCounter changed on 400000/400000 consecutive calls
time.Now() monotonic changed on      16/400000   (median positive delta 512.8us)
a warm keep-alive loopback HEAD round trip measured EXACTLY ZERO on 2581/3000 trials = 86.0%
```

So `durationToDelay(0)` reported the "no result" sentinel for measurements that SUCCEEDED, against the
field's own contract that a success is at least 1. Each failing test performs exactly one timed round
trip, so each fails independently at ~86% - which is the whole explanation for the varying sets.

**`experimental/clashapi` was not a clashapi bug.** Its two failures came from
`experimental/clashapi/proxies.go:351`, `if err != nil || delay == 0 { 503 "An error occurred in the
delay test" }` - a healthy node reported to the user as a failed probe. Proven by controlled isolation:
pristine base FAILs 5/5; copying ONLY `common/urltest/measure.go` (one file, 56 insertions) makes it
`ok 5/5`. One production change, two suites cured, and no change at all in `clashapi`.

Fixed in `common/urltest/measure.go`: a completed phase's elapsed time goes through
`elapsedOfCompletedPhase`/`minimumPhaseElapsed` so a success cannot emit the no-result sentinel.
`durationToDelay` keeps its exact prior semantics (so `TestDurationToDelay` is untouched) and the
failure paths still return `Delay == 0`, where 0 still means "no result".

## 4. WireGuard: `listen_port` never bound, and a nil-dialer panic

### 4.1 WG-01 — the port is not "never bound", it is bound from the wrong place at the wrong time

The previous round's hypothesis (`StdNetBind.Open`, or the fork's `BindUpdate` plumbing) is **refuted by
measurement**. `device.BindUpdate` returns without opening sockets while `!isUp()`, and the up
transition that opens them arrives on the tun device's event channel in ANOTHER GOROUTINE. So
`IpcSet`'s `listen_port` line ran first and did nothing, `Start` returned with the port still free, and -
worse - a genuinely OCCUPIED port failed the bind inside that goroutine, was logged and swallowed, and
the endpoint was published as ready with no socket.

Fixed in `transport/wireguard/endpoint.go`: `bindListenPort` brings the device up inside `Start` with
the error returned, re-applies a pinned port when the async transition raced the IPC line, then
verifies the device reports the configured port or fails closed. It deliberately does NOT substitute a
dialer; a non-listening dialer with `listen_port` is a capability-boundary failure.

17 real-socket tests, including occupancy immediately after `Start`, refusal matched against a locally
MEASURED errno, release on `Close`, `port=0` reporting the real held port, dual-stack, occupied-port
fail-closed, no socket leak, and a start/close race.

### 4.2 WG-02 — a process-fatal panic reachable from any embedder

Reproduced on the unfixed tree as a PANIC that kills the test binary:

```text
(*ClientBind).connect  client_bind.go:98  <- receive  client_bind.go:132
  <- device.RoutineReceiveIncoming  <- created by device.BindUpdate
```

plus `cannot create context from nil parent` for Send-before-Open and a nil `pause.Manager` deref.
Fixed with no API change: `Open`/`connect` return `os.ErrInvalid` for a nil dialer, the bind context is
created in the constructor, and nil logger/manager are tolerated.

### 4.3 MTU-01 — the wire framing was measured, not derived

Previously `NOT_MEASURED`. New harness with two real wireguard-go devices, a real handshake, an
injectable capture `Bind` on the sending side and the module's own `StdNetBind` on the receiving side,
sweeping every inner length 28..1408 one packet at a time:

```text
message = 16 + min(ceil16(inner), MTU) + 16     for all of them
max over the whole contract range = exactly MTU + 32
```

DECISION FROM THE MEASUREMENT: worst-case padding does NOT enter the conservative capacity, because
the padded plaintext is capped at the tunnel MTU - charging 15 more bytes would remove 15 bytes of
budget from every configuration for a case that cannot happen on top of the MTU.

Also: nested WireGuard is bounded by its detour's proven ceiling (an UNKNOWN detour is left alone,
never filled with 1280); `mtu < 1280` is treated as an IPv6-only prohibition, refused at construction
ONLY when an IPv6 address is configured, so legal IPv4-only low MTUs are kept. The mutation suite
includes the FORBIDDEN blanket floor, which goes red on the IPv4-only test - the tests distinguish the
correct rule from the prohibited one.

## 5. The six suites, attributed

| suite | classification | outcome |
|---|---|---|
| `common/urltest` | REAL_DEFECT (documented contract violated by a clock-resolution fact) | FIXED |
| `experimental/clashapi` | REAL_DEFECT, same root cause one layer down; clashapi itself is CORRECT | FIXED by the urltest change alone |
| `experimental/libbox` | TEST_FIXTURE_DEFECT (a fork-added test reached an upstream `!unix` stub that panics) | FIXED on the platform gate, not on the test |
| `common/tls` | BLOCKED_ENV | Schannel on this host has no TLS-1.3-over-TCP. Probe: with TLS 1.3 required, Schannel emits a **DTLS 1.2 record** (`16 fe fd ...`, 13-byte DTLS header, 197 bytes total) rather than a TLS record, and never offers `supported_versions`. The repo's own `disabledProtocolsMask` computes the correct bits, so the OS is the limit. NOT skipped, NOT relaxed |
| `common/tlsspoof` | BLOCKED_ENV | `windivert: open SCM: Access is denied`; the session is not elevated |
| `common/windivert` | BLOCKED_ENV | same precondition; all 19 NON-driver tests pass, so the package's pure logic is fully covered |

`common/dialer`'s `TestLiteralBothFailReturnsPromptly` is a genuine NON-DETERMINISTIC find, not a
timeout margin: under load the dial returned at 30.0009662s and 30.0164317s - EXACTLY the caller's own
30s deadline - while both attempts fail within 5ms. Returning precisely at the deadline means a
`select` on `ctx.Done()` decided the result because the completion signal was never delivered: a LOST
COMPLETION SIGNAL, narrowed to two arms (`dual_stack_scheduler.go:320-323`, `resolve.go:596-601`). It
could not be pinned further because an isolated replica of the same scenario passes 8/8 under the same
load - the trigger needs the full-package loaded run - and it was deliberately NOT guess-fixed.
`common/power` did not reproduce and is recorded as a maintenance note, not a bug.

## 5.1 The final serial sweep, and the one name that appeared

`go test -p 1 ./...` at the code candidate, 12 minutes, **REACHED_MODULE_END** - which the baseline
could never do, because `transport/http` hung for 90 minutes there.

```text
REMOVED from the failure list by this round:
  common/urltest            ok 7.259s    (was FAIL, 4-6 varying cases)
  experimental/clashapi     ok 0.684s    (was FAIL 2/2; fixed by the urltest change alone)
  experimental/libbox       ok 0.346s    (was FAIL)
  transport/http            ok 16.6s     (was HUNG 5400.042s at the baseline)
  protocol/shadowtls        ok 0.022s    (was FAIL)

REMAINING, all BLOCKED_ENV, identical case names at both SHAs:
  common/tls                3 cases   Schannel has no TLS-1.3-over-TCP on this host
  common/tlsspoof           3 cases   WinDivert -> SCM access denied, session not elevated
  common/windivert          5 cases   same precondition; 19 non-driver tests pass
```

`e2e`'s `TestRejectReplyCode` is the ONE name that appears in the final sweep and in no earlier list,
so it is attributed here rather than left as a loose end. MEASURED:

```text
final SHA, full e2e package, serial, 3 runs   ok / FAIL / ok       <- 1 of 3
final SHA, TestRejectReplyCode alone, 5 runs  ok ok ok ok ok        <- 5 of 5
round BASE bc7456db, same command, 4 runs     ok ok FAIL ok        <- 1 of 4
```

It is therefore **PRE-EXISTING and load-sensitive**, not a regression from this round: it fails in the
full package at the base with none of this round's changes present, and it passes in isolation every
time. It is the same class as `common/dialer`'s deadline-bound test - a suite whose fixtures interact
under a full-package run - and it is recorded rather than "fixed" by widening a bound, because the
assertion is not what is wrong.

## 5.2 MERGE-01 — the upstream absorption matrix

**Two corrections to the record first, because they are my errors and they cost the round time.**

1. An earlier round reported "LX was not read: this environment has no general internet access". That
   was **FALSE**. GitHub is reachable from this machine; I simply never tested it. LX was fetched and
   read this round, and the claim has been wrong in the repository since it was written.
2. I then made the opposite mistake and treated LX as a sync target. **It is not the upstream.** The
   upstream the task order names is `SagerNet/sing-box`. LX is only a comparison anchor for SPEC
   119/120/121.

```text
UPSTREAM              SagerNet/sing-box, remote `upstream`, tip 6afeff4c0 (2026-10-09)
MERGE_BASE            7a3d4e4a8e71bd7fa824959efdb57b4f39738802   (2026-09-06)
upstream side         53 commits
my side               1527 commits
git cherry            42 patch-equivalent / 11 genuinely new   (verified against origin/testing)
REAL_GAP              0
PARTIAL_IDEA          0
NEW COMMITS           none - nothing needed merging
```

**All 42 patch-equivalent commits have a fork commit on `testing` whose subject is upstream's
VERBATIM and whose date is the same day** (42/42, zero unmatched). The analysis did not stop at that:
every item within this round's scope was re-verified against the CODE at HEAD rather than trusted from
the `-` line. Three findings are worth recording because the fork is **stronger** than upstream, not
merely equal:

| upstream | fork's position |
|---|---|
| `80c117141` tailscale SSH auth banners | the fork has `authBannerSender` + `applyAction` (`protocol/tailscale/tailssh/server.go:282,324`) which **upstream does not have at all**, plus 5 controls upstream lacks |
| `69601481f` scope-cleanup errors | `adapter/lifecycle.go:196-208` *Expands* each cleanup before judging it (upstream does not), filters closed/cancelled, and adds a state machine so a second `Close` JOINS the first instead of reporting success early |
| `df8e2edfd` forward NAT + UDP mapping | the fork has no `reservation_windows.go` (the file upstream deletes) and instead owns `common/kernelports/pool.go` byte-identical to upstream's new file plus a 1049-line `backend_windows.go` carrying the fragment and embedded-ICMP handling |

Two of the 11 "new" commits are pure dependency bumps whose fix is already **carried by the pinned
module**: `194ebd18b` is `sing-tun/tun.go:134 DNSModeOrDefault()`, and `7f7c7ae11` is a
`sing-anytls` bump the fork is already **ahead** of. Both are `EXTERNAL_DEPENDENCY` by construction.

### The one genuine divergence — a product decision, not a gap

`78d44d52d` "Reset network on DNS server changes" is the single row where the fork is **deliberately
divergent**, and the divergence is documented in the fork's own code:

```text
dns/router.go:1266-1317   dnsGeneration = networkGeneration + observeDNSEnvironment
route/dns_only_change_is_not_a_network_transition_test.go   enforces it
```

The fork treats a DNS-only change as a **DNS**-generation change and never as a **network** transition,
because a network reset would tear down every QUIC/H2/MASQUE/voice session on a device whose network
never changed. Notably, upstream's own commit **deletes the same cgo `dnsinfo` reader** the fork uses
for the Darwin path - i.e. upstream converged on the fork's position from the other side.

If the intended policy is instead upstream's "a DNS change IS a network reset", it is one line of
wiring. It would contradict the fork's own test, so it is a decision for whoever owns
`dns/router.go`, and it is recorded in section 7 rather than changed here.

### LX, and the three SPECs

MEASURED: LX does **not** contain `transport/v2rayxhttp` and does **not** contain `common/physicalpath`
across its 1199 tracked files. The fork-only PhysicalPath model and the XHTTP transport the SPECs 119
and 121 discuss therefore have no LX counterpart to compare against, and there was never an LX patch
to absorb for them. SPEC 120 (MTU alignment) was addressed in this and the previous round by
measurement on the wire rather than by comparison.

The `lxref` remote was removed after this check: it is a comparison anchor, never a merge source, and
leaving it configured is what caused the misdirection in the first place.

## 5.3 DEBUG-04 — the build matrix and the shipped ABI

Both measured this round with `CGO_ENABLED=0` and the production tag set, building `./cmd/sing-box`:

```text
windows/amd64   exit=0
linux/amd64     exit=0
linux/arm64     exit=0
darwin/arm64    exit=0
freebsd/amd64   exit=0
```

`freebsd/amd64` is included deliberately: this round changed a build tag in
`experimental/libbox/link_flags_stub.go` (`!unix` -> `!unix && !windows`), and narrowing a tag is
exactly the change that can strand a platform. It compiles, and the earlier `freebsd` failure reported
by another workstream is in `daemon/`, from symbols unrelated to that change.

**The libbox ABI is unchanged.** Compared with `go doc -all ./experimental/libbox` between the round's
base `bc7456db` and the final tree:

```text
ABI IDENTICAL (383 exported symbols)
```

and the only files this round touched under `experimental/libbox/` are `link_flags_stub.go` and the
new `link_flags_windows.go`, both of which add UNEXPORTED platform plumbing only. That matters because
the Android and Apple clients are built against this surface, and a changed signature would break them
silently at link time rather than at review time.

## 6. Preserved and NOT re-done

The two earlier P0s (the original hop-direction reversal and the global network-union false
rejection) are NOT re-fixed; their old-red/new-green evidence stands and this round only closed the
cross-interface contract they left open. Also untouched: the SOCKS/HTTP/UoT DNS-ownership wire tests,
TUIC's measured 1232 datagram, `common/physicalpath/status.go`, the COPY-01 allocation audit, and the
`common/httpclient` caller-cancel verdict fix.

## 7. Product decisions left to the owner

1. **HY2 ChromeParrot is BLOCKED on the pinned `quic-go` fork.** `config.go:105-125` forces
   `initialPacketSize = 1250` whenever `ChromeParrot` is set, and no OTHER config field can lower the
   first flight while MTU discovery is inactive. So a proven 1232 ceiling is NOT effective there:
   `1250 + 48 = 1298` bytes over IPv6 on a 1280-byte path. The only in-repo lever is disabling
   ChromeParrot, which abandons the fingerprint, so it was not taken.
2. `mtu < 1280` with an IPv6 address is now REFUSED at construction. That rejects a configuration that
   used to start. Alternatives recorded and not taken: silently raising the MTU (reports capacity never
   configured) or a blanket floor (rejects legal IPv4-only tunnels).
3. A nested WireGuard endpoint with a provable detour capacity now shrinks its MTU (1408 inside a 1408
   tunnel becomes 1328). Intended and logged, but wire-visible.
4. `common/httpclient`'s 48h HTTP/3 cap is reachable only by failures CONCURRENT inside one window,
   because an expired entry is deleted on read. The comment reads like a doubling ladder; the code is
   a concurrency-amplified one.
5. **A DNS-only change: DNS generation or full network reset?** The fork treats it as DNS-only (`dns/router.go:1266-1317`, enforced by `route/dns_only_change_is_not_a_network_transition_test.go`); upstream `78d44d52d` treats it as a network transition. The fork's position avoids tearing down every QUIC/H2/MASQUE/voice session on a device whose network did not change, and upstream's own commit deletes the same cgo reader the fork uses. Confirm the policy.
6. The `sing` fork's `BufferedVectorisedWriter` allocates unpooled above 64KiB - the one genuinely
   avoidable per-write allocation found - and it is inside the read-only dependency.

## 8. Closing block

Recorded after the last push; see the git evidence in the session report for the exact values.

```text
PHYSICALPATH_ORDER_AND_CONTRACT = READY    (Build and Hops agree; ControlPath is the decision order)
STARTUP_COMPATIBILITY           = READY    (the nine relaxed configurations hold; the matrix is green)
DNS_OWNERSHIP_AND_L0            = READY    (unchanged from the earlier round, re-run green)
WIREGUARD_BIND_AND_LIFECYCLE    = READY    (port owned or Start fails; nil dialer fails closed)
MTU_PATH_BUDGET                 = PARTIAL  (WG measured; HY2 ChromeParrot BLOCKED on the pinned fork)
H3_FALLBACK                     = READY    (both memories fixed and re-run)
PER_HOP_STATUS                  = READY    (read-only, no new timers or goroutines)
COPY_PATH                       = MEASURED (COPY-01 audited with allocation numbers; no invented knob)
FULL_TEST_COVERAGE              = REACHED_MODULE_END
FULL_TEST_RESULT                = COMPLETED_WITH_FAILURES (3 BLOCKED_ENV suites)
FULL_TEST_SHA_MATCH             = IDENTICAL_CODE_TREE_DOCUMENT_ONLY_TIP
                                  (proven: git diff <tested>..<tip> -- '*.go' 'go.mod' 'go.sum'
                                   is EMPTY; the only added path is one docs/ file)
CI                              = NOT_RUN_BY_REQUEST
RELEASE                         = NOT_READY
```
