# v0.1.6 — COPY-01 copy/ownership audit, layer state, and exit-verdict scope

Base `524ea41e`. Worktree `C:\Deepseek\内核\wD`, detached, local commits only.
Environment: Go `go1.26.8 windows/amd64`, `CGO_ENABLED=1`, MinGW gcc, tags read from
`release/DEFAULT_BUILD_TAGS_OTHERS` (never hard-coded). No `gh`, no network, no remote run.

Two labels are used below and they mean exactly this:

- **MEASURED** — a number produced in this environment by the command quoted next to it.
- **STATIC** — read from the source, not executed here. Apple/Darwin appears only as STATIC.

Allocation numbers come from `-benchmem` (`B/op`, `allocs/op`). They are **allocation**
measurements. They are not wall-clock claims and must never be quoted as a system-wide
improvement; the throughput column is a property of this rig (loopback or in-memory endpoints)
and is labelled where it appears.

---

## 1. Where the bytes actually move (the COPY-01 table)

The fork's own data path is thin: the byte-moving engine is in the pinned, **read-only**
`sing` fork (`github.com/Piggy-Cat-bit-shadow/sing`, `common/bufio`, `common/buf`). This
repository decides *which* engine call is made, *with what ownership*, and *with what wrapper
in the way*. That split is the single most important fact in this audit: several findings below
are real, measured, and **cannot be changed here** without changing a dependency the task
forbids touching. They are recorded as such.

| # | Path | file:line | What is copied into what | Copies | Pooled / size | Provably avoidable? |
|---|---|---|---|---|---|---|
| 1 | TCP splice fast path | `route/splice.go` (`spliceConnection`), engine `sing/common/bufio/copy_direct.go` (`copyDirect`) | nothing through userspace: the kernel moves the bytes between two descriptors | 0 per byte | n/a | Already the optimisation. Eligible only when both ends are syscall-capable, replaceable, and share one upstream (`route/splice.go` unwrap chain). Guard tests: `route/splice_eligibility_test.go`, `route/scheduler_splice_target_test.go`, `route/tcp_splice_diagnostics_test.go`. |
| 2 | TCP userspace copy loop (the normal path) | `route/conn.go:701` → `bufio.CopyWithIncreateBuffer(copyWriter, source, increaseBufferAfter, bufio.DefaultBatchSize)` → `sing/common/bufio/copy.go:27` | kernel→pinned read buffer→kernel | 1 copy in, 1 copy out per byte; per *buffer*, not per packet | Pooled: `buf.DefaultAllocator` (`sing/common/buf/alloc.go`); buffer `buf.BufferSize` = **32 KiB** (`sing/common/buf/buffer_standard.go:6`) | Not avoidable for a pair the kernel cannot splice — the userspace buffer is the seam. Where it IS avoidable the engine already does it (row 1). |
| 3 | TCP copy buffer growth policy | `route/conn.go:479` (`connectionIncreaseBufferAfter`) | chooses the threshold, not a copy | — | default `512000` B (`sing/common/bufio/copy.go:18`); `earlyConnectionBufferIncreaseAfter` when the destination writer or the dialer opted in (`adapter.CopyBufferGrowthTuner` / `ConnectionCopyTuner`) | Policy, already fork-owned and already corrected once (the old version asked "is the inbound Naive?"). No change. |
| 4 | TCP copy with the traffic-class gate installed | `route/conn.go:392` (`uploadStreamGate`), `:410` (`gateWriter`) | a NON-replaceable gate in front of the destination makes the engine decline `copyDirect`, so an otherwise spliceable flow takes row 2 | adds row 2's 2 copies/byte to a flow that could have had 0 | n/a | By design and pinned: `route/scheduler_capability_audit_test.go`, `route/scheduler_gate_production_test.go`. The gate is skipped when BOTH ends are syscall-capable (`route/conn.go:396`), so the cost lands only where the kernel path was already gone. |
| 5 | UDP NAT session read/write | `route/conn.go:633-634` (`packetConnectionCopy`) → `route/conn.go:936` (`bufio.CopyPacketWithCounters`) → `sing/common/bufio/copy.go:464` (`copyPacketWithPool`) | one pooled packet buffer per datagram: `options.NewPacketBuffer()` → `source.ReadPacket(buffer)` → `destination.WritePacket(buffer, addr)` | 1 userspace copy per datagram (the read) | Pooled; `UDPBufferSize` = **16 KiB** (`sing/common/buf/buffer_standard.go:7`) | Inherent: a userspace NAT must own the datagram to rewrite/route it. |
| 6 | Batched UDP write (`writePacketWithPool`) | `sing/common/bufio/copy.go:502` (`options.Copy(packetBuffer.Buffer)`) | the batch path copies each packet buffer once more before `WritePacket` | +1 copy per datagram, batch path only | Pooled, sized to the datagram | Deliberate and required: the batch writer may hold the buffer across an asynchronous send, so the pooled buffer must not be lent across that boundary. This is the same rule `docs/fork/RC-CERTIFICATE.md` states. **Read-only dependency.** |
| 7 | Vectorised write that must fall back to one buffer | `sing/common/bufio/vectorised.go:86-103` (`BufferedVectorisedWriter.WriteVectorised`) | concatenates N buffers into one: `buf.NewSize(bufferLen)` (pooled) when ≤ 65535 B, else `make([]byte, bufferLen)` | 1 copy of the whole batch | Pooled for ≤64 KiB; **`make([]byte, bufferLen)` — UNPOOLED — above 64 KiB** | This is the one unpooled per-write allocation found. Avoidable by allocating from the pool and slicing, i.e. inside the read-only `sing` fork. **Reported, not changed.** |
| 8 | MASQUE DATAGRAM | `transport/http/owned_datagram.go`, `route/conn.go:556-626` (NAT packet-conn wrappers) | one owned buffer per outbound datagram; ownership transfers to the writer, and a failed send leaks rather than reuses it (`buffer.Leak()`, `sing .../copy.go:478`) | 1 buffer per datagram (plus row 6 on the batch path) | Pooled | The ownership rules are the point of that file; tests: `transport/http/owned_datagram_e2e_test.go`, `transport/http/early_datagram_ownership_test.go`. No change. |
| 9 | XHTTP / xmux | `transport/v2rayxhttp/conn.go`, `transport/v2rayxhttp/xmux.go` | stream bodies copied through the HTTP transport; the pool's breaker state is one atomic add per failure, not per byte | per stream write, not per packet | Pooled by the HTTP stack | No change; the verdict side of this file is audited in §4(d). |
| 10 | HY2 / QUIC payload | `protocol/hysteria2/outbound.go` (QUIC stream + datagram) | QUIC owns its own send buffers; the fork's contribution is the payload ceiling, not a copy | 0 fork-owned copies per byte | n/a | Not applicable. |
| 11 | DNS | `dns/transport/udp.go:148,161`, `tcp.go:132,145`, `https.go:219,247`, `quic/http3.go:220,248`, `client_truncate.go:21` | every transport packs the message into a pooled buffer with `PackBuffer(buffer.FreeBytes())` — no intermediate `[]byte` is produced | 1 pooled buffer per query and per response, encode writes straight into it | Pooled, sized to the message | Already the zero-extra-copy shape for this path. |
| 12 | Sniffing | `route/route.go:1168`, `:1244` (`sniffBuffer := buf.NewPacket()`) | the flow's first packet is copied into a pooled 16 KiB packet buffer for the sniffers | 1 per sniffed flow, not per packet | Pooled | Required: the sniffers need a stable view of the first packet after the NAT read buffer is returned. |
| 13 | FakeIP | `route/fakeip_conn.go:68-91,151-211` | only destination rewriting; the packet-buffer paths are pass-through (`ReadPacket`/`WritePacket` are delegated, batch variants rewrite the destination slice element in place) | 0 additional copies per packet | n/a | Nothing to remove. |
| 14 | Apple / Darwin transport | `common/httpclient/apple_transport_darwin.go:76-78,485` (`C.GoBytes`), `:260-363,505` (`C.free`) | STATIC ONLY: every C→Go buffer is copied with `C.GoBytes`; every Go→C allocation has a matching `C.free`; no Go pointer is retained by C | 1 copy in each direction per body | Not pooled (`C.malloc`/`GoBytes`) | Avoidable only with pinning/`unsafe.Pointer` across the C boundary, which the task forbids without device evidence. **STATIC ownership review only — no Apple runtime was executed, and no Apple PASS is claimed.** |

### Measured cost of rows 2 and 5

Engine call with the route layer's exact arguments (new benchmark,
`route/copy_engine_bench_test.go`), 4 MiB payload, in-memory endpoints:

```text
go test -run '^$' -bench BenchmarkRouteTCPCopyEngine -benchmem -benchtime=200ms -tags <tags> ./route/

BenchmarkRouteTCPCopyEngineBySize/64KiB     243 B/op     5 allocs/op
BenchmarkRouteTCPCopyEngineBySize/1024KiB  1847 B/op    28 allocs/op
BenchmarkRouteTCPCopyEngineBySize/4096KiB  5038 B/op    76 allocs/op
```

Read this as an allocation measurement: allocated **bytes** do not scale with the payload
(243 B → 5038 B for 64 KiB → 4 MiB), which is the signature of a pooled byte buffer; the
allocation **count** does scale (~1 small object of ≈66 B per ~54 KiB moved). Nothing here is a
throughput claim.

These are **steady-state** numbers, and the pool is what makes them small. The same 64 KiB case at
`-benchtime=1x`, i.e. with a cold pool, measures `35352 B/op, 10 allocs/op` — the 32 KiB buffer
itself plus its bookkeeping. So the buffer is genuinely pooled and genuinely allocated on first
use; a run that quoted only the cold number would overstate the cost, and one that quoted only the
warm number would hide where the memory comes from.

Existing packet benchmark, real engine (`bufio.CopyPacket`), 1400-byte datagrams:

```text
go test -run '^$' -bench BenchmarkDirectPacketCopyUserspace -benchmem -benchtime=3x -tags <tags> ./route/

1024packets   71976 B/op   1027 allocs/op   ~1 alloc per datagram
8192packets  530728 B/op   8195 allocs/op   ~1 alloc per datagram
```

Decision costs (unchanged, re-measured on this machine): bypass decision 0 allocs (allowed
~8.2 µs cold / ~233 ns refused), outbound profile ~100 ns 0 allocs, flow setup bypassed
1067 ns 0 allocs vs userspace 17200 ns 2 allocs.

### What this audit does NOT establish

- **No wall-clock improvement was made or claimed.** No production code changed for COPY-01.
- Rows 6 and 7 are real and measured **in the read-only `sing` fork**; changing them is a
  dependency change, which the task forbids. They are the correct next candidates if that
  permission is ever granted.
- Row 14 is STATIC. Darwin paths cannot be executed here.

---

## 2. The layer state (there are no `kernel_bypass` / `kernel_splice` / `zero-extra-copy` knobs)

Measured, not assumed:

```text
git grep -I -i -E "kernel_?bypass|kernel_?splice|zero[-_ ]extra[-_ ]copy|zerocopy|zero_copy"
  -> no match anywhere in the tree (source, option structs, docs, scripts)
git grep -I -n -E "\"(bypass|splice|offload|zero_copy|zero-copy)\"" -- option adapter docs/configuration
  -> no match
```

`ZERO_EXTRA_COPY_STATUS` exists only as a *status field* in
`docs/fork/v016-five-workstream-final-report.md:409` ("Z1–Z3 ZERO-EXTRA-COPY — NOT DONE",
`NOT_RUN`). It is a work item, not a configurable level. **No public API or config level was
invented to close that gap.**

What the fork really has is four layers, none of them a knob (`docs/fork/direct-offload.md:88`):

| Layer | Mechanism | Implemented | Documented | Tested |
|---|---|---|---|---|
| L0 | OS route sets (`route_address_set` / `route_exclude_address_set`), decided in `protocol/tun/inbound.go:947-1078` before the router | yes | `docs/fork/direct-offload.md`, `protocol/tun/direct_fast_path_dns_test.go` header | `protocol/tun/direct_offload_l0_report_test.go`, `protocol/tun/direct_fast_path_dns_test.go`, `protocol/tun/l0_authoritative_vs_reverse_mapping_test.go`, `protocol/tun/fakeip_bypass_boundary_test.go` |
| L1 | the router's semantic bypass: `route/route.go:751` `canFastBypass` (automatic) and the explicit `{"action":"bypass"}` rule (`route/route.go:548-567`) → `adapter.PreMatchBypass` → `tun.ActionBypass` | yes | `docs/fork/direct-offload.md` (whole file), `route/bypass_verdict.go` | `route/fast_bypass_test.go`, `route/fast_bypass_verdict_test.go`, `route/direct_offload_hits_test.go`, `route/bypass_capability_cost_test.go`, `protocol/direct/bypass_transition_test.go`, `protocol/direct/bypass_capability_test.go`, `route/direct_offload_bench_test.go` |
| L2 | kernel splice through `tun.GoConn.Splice` (`route/splice.go`), engine `sing/common/bufio/copy_direct*.go` | yes, in `route/splice.go` + read-only `sing` | `docs/fork/RC-CERTIFICATE.md`, `docs/ENGINEERING-NOTES.md` | `route/splice_eligibility_test.go`, `route/splice_socket_owner_test.go`, `route/scheduler_splice_target_test.go`, `route/tcp_splice_diagnostics_test.go` |
| L3 | the userspace copy loop (`route/conn.go:701`) | yes | same | `route/conn_cached_buffer_test.go`, `route/conn_increase_buffer_test.go` |

Documented-vs-implemented gaps found in this area, both **closed by the tree already** and
cross-checked here: (i) `docs/RELEASE-CERTIFICATE.md:49` once said the TCP splice outcome was
uninstrumented — it is instrumented now (`route/splice_diagnostics.go`, pinned by
`route/tcp_splice_diagnostics_test.go`); (ii) `docs/fork/direct-offload.md:97-104` states that
L1 is honoured only in Linux `auto_redirect` and that all three TUN stacks treat `ActionBypass`
exactly like `ActionAccept` — re-verified at the pinned sing-tun revision by
`protocol/tun/native_bypass_trace_test.go` and `protocol/tun/native_bypass_dispatcher_test.go`,
which fail loudly if that capability ever changes. No doc correction was needed.

---

## 3. Exit-verdict scope: where a verdict is recorded, read, and how far it reaches

The question behind this section: *a verdict must not be treated as proof of a peer's
reachability when it only proves that something was set up, and it must not outlive the
topology, generation or target it was about.*

### (a) Native bypass / Direct Fast Path — the highest-cost one. Audited, **no defect found**

| Question | Answer | Evidence |
|---|---|---|
| Where recorded | computed per flow, never stored: `route/route.go:751` `canFastBypass` returns `BypassVerdict`; the explicit rule action is a second producer at `route/route.go:548-567` | `route/bypass_verdict.go:20-44` (19 refusal reasons) |
| Where read | `route/route.go:913` (automatic) and `:557/:564/:566` (rule action) → `adapter.PreMatchResult{Action: PreMatchBypass}` → `adapter/router.go:113-131` → `tun.FlowVerdict{Action: tun.ActionBypass}` → sing-tun | `adapter/router.go:117-131` |
| Scoped to | the FLOW: inbound type, network, destination literal-ness, FakeIP, sniffed domain, candidate list, destination rewrite, UoT datagrams, UDPConnect, domain unmapping, timeout, trackers, chain length, outbound semantics — plus the **live** ambient network policy re-read on every call (`protocol/direct/outbound.go:326` → `common/dialer/profile.go:338-352`) and the self-address guard (`:327-332`) | `route/route.go:754-875` |
| Generation / topology change | recomputed per flow from live state; the only cached input, the process-lookup cache, is 200 ms LRU and is **purged** on a network change (`route/router.go:308-312`), and a transient miss fails closed (`route/process_cache.go:38-60`) | guards: `protocol/direct/bypass_transition_test.go:166` `TestBypassFollowsAnInterfaceUpdate`; `route/process_transient_miss_test.go` |
| Closed / replaced hop contributing | impossible by construction: `route/route.go:860` refuses any chain whose length ≠ 1 (`BypassRefusedOutboundChain`), so no group member — the only replaceable thing — can ever carry a bypass verdict | `route/route.go:855-871` |
| Partly-progressed dial counted as success | **there is no dial in this verdict at all.** It asserts "the platform's own connect is semantically equivalent for this flow", never "the peer answered". In TUN mode the consumer cannot turn it into a reachability claim either, because all three TUN stacks treat `ActionBypass` identically to `ActionAccept` (STATIC + pinned tests); in Linux `auto_redirect` the packet leaves by its original path and the reachability proof belongs to the OS | `docs/fork/direct-offload.md:88-118`, `protocol/tun/native_bypass_trace_test.go`, `protocol/tun/native_bypass_dispatcher_test.go`, `route/bypass_capability_cost_test.go` (asserts 0 allocs as a test) |

One honest limitation, unchanged from the product's own documentation: an explicit
`{"action":"bypass"}` rule is a *user instruction*, not a computed equivalence proof, and its
conditions (`route/route.go:548-567`: destination must be literal and unrewritten) are weaker than
`canFastBypass`'s. That is intentional — the user asked for that flow to leave — and it is
documented; it is recorded here so the two producers are never conflated.

### (b) URLTest / health store — audited, **no defect found**

| Question | Answer | Evidence |
|---|---|---|
| Where recorded | `protocol/group/urltest.go:1180-1188`: a successful measurement into `StoreHealthHistory` (selection) or `StoreDisplayHistory` (display only) — never both meanings from one layer | `common/urltest/urltest.go:167-184` |
| Where read | selection/skip: `protocol/group/urltest.go:1113` `LoadURLTestHistoryFor(tag, scope)`; display: `LoadURLTestHistory(tag)` and explicitly documented as *not for selection* | `common/urltest/urltest.go:103-142` |
| Scoped to | (tag, **probe target**). A result against a different target cannot be read as evidence about this one (`urltest.go:1111-1112`), and a manual probe can never become selection evidence (`StoreDisplayHistory`). It is **not** network-generation scoped, and that is deliberate: the freshness check bounds staleness by the group's interval (`urltest.go:1114`), and deleting evidence on a teardown was removed precisely because it moved selection on a network change (`urltest.go:1151-1168`) | `common/urltest/target.go:432` (`MeasurementScope`), `common/urltest/scope_test.go`, `common/urltest/delay_contract_test.go` |
| Closed / replaced hop contributing | a write after `Close` is refused (`closed` guard in every accessor, `urltest.go:133,158,176`); a member's failure is not attributed to the node unless a *health* check against *this* target failed, and `DeleteHealthHistory` removes exactly one (tag, target) | `protocol/group/urltest.go:1170-1175`, `common/urltest/urltest.go:186-200` |
| Partly-progressed dial counted as success | no: a measurement must reach the second request and match the expected status (`common/urltest/measure.go:305-306`), a request the caller's context ended is never turned into a fallback success (`measure.go:364-383`), and the four "this is about the core, not the node" cases (own teardown, caller cancellation, resource suspended, group context done) are all recorded as *not measured* rather than as failure | `protocol/group/urltest.go:1135-1175`; guards: `protocol/group/urltest_dial_failure_test.go`, `urltest_background_probe_test.go`, `urltest_context_test.go`, `urltest_android_lifecycle_test.go`, `common/urltest/measure_contract_test.go` |

### (c) `physicalpath` `Exit()` / `Entry()` / `Report.Reachable()` — audited, **no consumer overclaims**

STATIC, complete caller inventory:

```text
physicalpath.ValidateRoots -> adapter/outbound/manager.go:186,218,237   (start-time dry run)
physicalpath.Build         -> tests only (route/physicalpath_route_test.go, common/physicalpath/...)
Report.Reachable()         -> common/physicalpath/dryrun.go:133 (its own Err) — NO production caller
Path.Exit() / Path.Entry() -> tests only
```

So the only production consumer of the model is the start-time dry run, which dials nothing by
design and reports "unusable outbound path member(s)". It never reaches a UI, a status API or a
selection. `Reachable()` is structurally honest (an unknown node is not counted as reachable,
`dryrun.go:109-115`), and because **no consumer converts `Path.Exit()` or `Report.Reachable()`
into a reachability claim about a peer**, there is nothing here to fix. `Path.Exit()` also returns
`ok=false` while any unknown is present (`physicalpath.go:247-261`), which is the correct
fail-closed direction for a name that sounds like a verdict.

### (d) Per-connection backoff verdicts — **one real defect, fixed and proven**

The `transport/http` HTTP/3 memory was already linearised this session (one atomic state, one
escalation per failure event) and was not re-opened. `common/httpclient/http3_transport.go` has
its own per-authority memory, and it had a defect of exactly the shape this audit is about:

| Question | Answer |
|---|---|
| Where recorded | `common/httpclient/http3_transport.go` `recordH3AttemptFailure` (was: `markH3Broken` called inline from three failure sites) |
| Where read | `h3Broken(authority)` at the top of `roundTripHTTP3` — a live entry sends **every** later request for that authority to the H2 fallback |
| Scoped to | the **authority** (host:port), with a 5-minute first rung, doubling, 48 h cap. It does **not** need generation scoping: the memory lives inside the inner transport, and a network change replaces the inner transport (`route/router.go:305` → `common/httpclient/manager.go:159` → `ManagedTransport.Reset`), which is pinned by `common/httpclient/managed_transport_reset_test.go` |
| Closed / replaced hop contributing | no: a retired epoch's transport is discarded with its map (`managed_transport.go:176-189`); `CloseIdleConnections` deliberately keeps the verdict and says why (`managed_transport.go:142-174`) |
| Partly-progressed / caller-ended attempt counted as success | **this was the bug.** Every failed attempt armed the verdict, including an attempt the *caller* ended — a closed client, an abandoned DNS query, a refresh that lost its consumer, a shutdown. An attempt that only proves the caller left was being recorded as evidence about the server, and the entry it armed then moved that authority onto HTTP/2 for the length of the window |

Fix: the three call sites go through `recordH3AttemptFailure`, which requires the request's own
context to be still live and the error not to be a bare `context.Canceled`. Everything else stays
evidence (QUIC handshake timeout, stateless reset, version negotiation failure). The rule is the
one this tree already applies in the sibling implementations of the same decision — xmux's
"`context.Canceled` is neutral" (SPEC 094), the HTTP/3 CONNECT setup path, and
`common/urltest/measure.go:371-383` (`shouldFallbackSecondRequest`), whose comment states the rule
in the same order: *"The caller's context is consulted FIRST: a request that failed because the
context ended must be reported as ended, whatever error the HTTP layer wrapped it in."* The same
shape already appears in `common/httpclient/apple_transport_darwin.go:413`, which checks
`request.Context().Err()` before acting.

Tests (all in `common/httpclient`, `-tags` from `release/DEFAULT_BUILD_TAGS_OTHERS`):

```text
TestACallerCancellationDoesNotArmTheHTTP3Verdict        RED before the fix, GREEN after
TestAnAlreadyCancelledRequestDoesNotArmTheHTTP3Verdict  RED before the fix, GREEN after
TestAGenuineHTTP3FailureStillArmsTheVerdict             positive control, GREEN before and after
package: go test ./common/httpclient/  ok ; go test -race -count=2 ./common/httpclient/  ok
mutation: guards removed -> both negative tests RED ; file restored byte-identical
          (git hash-object == HEAD blob) -> GREEN again
```

**Not changed, deliberately** (product decisions, reported rather than taken):

- the 48 h cap, the 5-minute first rung and the doubling factor;
- the observation that `h3Broken` **deletes** an expired entry while `h3Broken` short-circuits the
  attempt while an entry is live — so a sequential client always restarts at the first rung and
  the 48 h cap is reachable only by concurrent failures inside one window. That is a documented
  ladder behaving differently from how a doubling ladder usually reads. Changing it would alter the
  product's retry profile, so it is recorded here, not touched.

---

## 4. NOT_MEASURED, with the exact command that would measure it

| Item | Why not measured here | Exact command that would |
|---|---|---|
| Apple / Darwin runtime (NetworkExtension memory budget, cronet transport, real TUN) | no macOS device, no signed extension in this environment | `GOOS=darwin GOARCH=arm64 go test -tags <tags> ./common/httpclient/...` on a macOS host, plus the device checklist in `docs/fork/RC-DEVICE-CHECKLIST.md` |
| L2 splice hit rate on a real NIC | needs a real TUN and Linux; loopback shows L2≈L3 (the fork's own doc says so) | `docs/fork/real-tun-validation.md` §2 procedure; mutation = make `GoConn.Splice` return false and compare the same numbers |
| Linux `splice`/`sendfile` syscall trace | Windows host, no Linux data plane | `strace -f -e trace=splice,sendfile,recvfrom,sendto ...` under the real-tun harness |
| Unpooled >64 KiB vectorised write (row 7) end-to-end | the allocation is inside the read-only `sing` fork | a benchmark in the `sing` fork calling `BufferedVectorisedWriter.WriteVectorised` with a >64 KiB batch |
| Per-hop MTU/status observability | STATUS-01/J-3 is not implemented in this tree; nothing to measure | implement `PhysicalPathStatus` first, then measure its cost off the packet path |

## 5. Files changed by this round

- `common/httpclient/http3_transport.go` — the fix above.
- `common/httpclient/http3_verdict_evidence_test.go` — the three tests.
- `route/copy_engine_bench_test.go` — measurement only (`BenchmarkRouteTCPCopyEngine*`), no
  production code, no memory-profile change.
- this document.

Nothing else. In particular no change to `go.mod`/`go.sum`, no change to any other repository, no
change to `common/physicalpath/*`, `adapter/outbound/manager.go`, `box.go` or
`common/physicalpath/dryrun.go` (owned by other workstreams), and no GitHub Actions workflow was
read-modify-written, triggered or re-enabled.
