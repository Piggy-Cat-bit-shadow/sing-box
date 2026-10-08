# LX Residual Bug Sweep

Treating `Leadaxe/sing-box-lx` as a corpus of proven failure modes rather than a patch source, and
asking of each one whether it is still reachable in this fork. The comparison is of **failure mode and
invariant**, never of whether a code line matches.

## Baseline

| | |
| --- | --- |
| sing-box initial HEAD | `1a920197d` (this sweep's own first commit; sweep began at `8eb2c5a4d`) |
| LX reference audited | `/tmp/lx-ref` — `Leadaxe/sing-box-lx` |
| upstream refs | `SagerNet/sing-box` `testing` @ `fe92ab3e7`; `SagerNet/sing-tun` @ `7539c9855f19` |
| toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`), `TAGS=$(cat release/DEFAULT_BUILD_TAGS)` |

## Method

Sources mined: LX SPECS/TASKS, FEATURES bug notes, changelogs, fix and follow-up commits, regression
tests, and **closed issues** (which carry the first wrong hypothesis, the intermediate workaround and
the final root cause — all three are evidence). For each candidate: what was the real root cause, what
class of failure was it, is it reachable *here*, has upstream fixed it, does this fork already cover it
more strongly, and can a deterministic regression be written.

The recurring shape worth naming, because it produced the two highest-value finds: **a fix that was
partially applied**. Not a fix that was never applied — a fix whose two halves live in different
accessors, or whose merge resolved against an older branch. Two instances are below.

## Matrix

| LX ID / issue | failure mode | current exposure | verdict | action | regression |
| --- | --- | --- | --- | --- | --- |
| **016** connection map race | fatal runtime throw (`concurrent map iteration and map write`) | **REAL.** `experimental/libbox/command_types.go` had no lock at all; `ApplyEvents` iterated `connectionMap` while writing it, `filtered` was refilled under `SortBy*`, and `Iterator()` returned the **live** slice | **FIX** | mutex + `filterStateLocked` split + iterator snapshot | `command_types_race_test.go` (3 tests, red-checked) |
| **108A** remembered H2 prison | H3 never retried | not exposed: verdict is time-bounded (5s→5min) and cleared by `ResetConnections()`; the reset test asserts the H3 client is actually **called** again | ALREADY COVERED | extended for the CONNECT-IP branch | `TestP14GenerationResetClearsTheH3Verdict`, `...CallerCancelDuringTunnelSetup...`, `...PinnedHTTP2ConfigNeverConstructsOrUsesHTTP3` |
| **108B** H2 `Close` behind a blocked writer | unbounded teardown | **REAL.** `clientStreamConn.Close()` closed the reader before cancelling the stream ctx; `transportResponseBody.Close` waits on `cs.donec`, closed by `cleanupWriteRequest` **under `cc.wmu`** — which the blocked writer holds | **FIX** | cancel the stream context before the reader | `TestH2TunnelCloseIsBoundedBehindABlockedWriter` (red→green) |
| **108C** H3 CONNECT response unbounded | dial hangs, tunnel-build mutex occupied | not exposed: `openConnectStream` registers `context.AfterFunc` to bound `ReadResponse` and calls `stopSetupCancel()` on success | TEST-ONLY | 3 tests incl. both red-checks | `client_h3_setup_context_test.go` |
| **038** gomobile ABI frame | fatal `bulkBarrierPreWrite: unaligned arguments` (a **throw**, not a panic) | shape present: 430 bound declarations, **29** with a pointer-bearing result frame. The frame is packed and only byte-aligned before Go 1.26 (cmd/cgo CL 692935) | **TEST-ONLY** + checked debt register | whole-surface AST tripwire; **no** signature changed (see below) | `gomobile_surface_test.go` (red-checked) |
| **078** WireGuard sniffed as uTP | misclassification → wrong routing | **REAL.** A 148-byte type-1 initiation (`01 00 00 00`) is claimed by `sniff.UTP` as `bittorrent`; upstream is byte-identical and unfixed | **FIX** | minimal structural sniffer, inserted immediately before `UTP` | `common/sniff/wireguard_test.go` + 2 route-level tests |
| **024** runtime routing cycle | fatal stack overflow | **REAL and constructible.** The Tailscale endpoint built its adapter with `nil` dependencies while dialing through `detour`; it declared the edge only in `References()`, which the topological sort does not read | **FIX** | declare the edge at construction (1 line) | `endpoint_detour_dependency_test.go` + `manager_cycle_test.go` + `selector_edge_test.go` |
| **084** interrupt ABBA deadlock | deadlock | primitive already correct: `common/interrupt` collects and removes under the lock and closes **after** | ALREADY COVERED | TEST-ONLY added (it had none) | `group_locking_test.go` (red-checked) |
| 091 §1 `udp_relay_mode` typo | silent wrong mode | `protocol/tuic/outbound.go` has a `default:` error | ALREADY COVERED | none | no tuic unit test in tree |
| 092 init error names only the index | unusable diagnostics | `box.go` includes `<type>[<tag>]` | ALREADY COVERED | none | LX-only guard |
| 111 tailscale control on port 80 | ~15 min offline behind DPI | `control_https.go` sets `TS_FORCE_NOISE_443` | ALREADY COVERED (independently implemented) | none | `control_https_test.go` |
| 029 detour resolved in the constructor | permanent frozen error | the egress cast is in `Start`, behind the topo barrier | ALREADY COVERED | none | `transport/wireguard/*` |
| 050/054/116 urltest ignores real dial failures | zombie round | different design: `clearSelectionFor` + `requestHealthRecheck` | ALREADY COVERED | none | 5 dedicated test files |
| 020 health check wakes an idle resource | background wake of an expensive endpoint | suspended members are skipped and `ErrResourceSuspended` is "not measured" | ALREADY COVERED | none | `urltest_background_probe_test.go` |
| 064 selector interrupt | dead on inbound | upstream 1.15 mechanism (`AttachConnection`) | ALREADY COVERED | none | `selector_interrupt_test.go` |
| 052 netstack TCP dial without a connect deadline | ~127s silent hang | mechanism absent: gVisor retired; the WG endpoint uses the Go stack | N/A | none | — |
| 030 `Box.Close` hangs with ~30 WG endpoints | shutdown delay | LX machinery absent (no `resumeMu`/wake ping); the router is registered after endpoints and `Scope.Close` walks in reverse, so the idle tick stops first | N/A | none | — |
| 007 / 112 AWG-over-WG, AWG graft | hang / broken direct path | no AWG in this tree | N/A | none | — |
| 113 `TS_DEBUG_ALWAYS_USE_DERP` socket leak | hung Close | debug env knob, not config-reachable | N/A | none | — |
| 099/058 nil `RemoteAddr()` panic | process kill | RPC absent; the class is contained by `daemon/server_recover.go` | N/A + class ALREADY COVERED | none | `server_recover.go` |
| 012 zombie ↓0 TCP stall | stall | LX itself never reproduced it on its own tip | DEFER | none | — |
| 028 nested-tunnel UDP fragment | silent MTU drop | `UDPFragmentDefault` is set for direct/resolved/MASQUE, not by the WG endpoint; reachability not established | DEFER | none | — |
| 093 `%2F` in multi-segment `service_name` | 404 vs Xray; the two transports disagree | `v2raygrpclite` escapes the whole name, `v2raygrpc` does not | DEFER → FUTURE | feature-shaped | — |
| 060 no auto `record_fragment` under detour | fingerprinting | `DialedThroughDetour` absent | DEFER → FUTURE | default-change | — |
| 039 report-archive rotation unbounded | disk growth | `experimental/libbox/report.go` | DEFER | not audited this round | — |

Counts: **FIX 4** (016, 108B, 024, 078) · **TEST-ONLY 3** (038, 108C, plus the covered-guard tests) ·
**ALREADY COVERED 9** · **DEFER 5** · **N/A 6**.

## The two partially-applied fixes

Both are the same shape and neither is in the LX corpus.

**LX 024 / Tailscale.** `protocol/tailscale/endpoint.go` dials every byte it emits through
`outboundDialer`, which resolves `detour`. It declared that edge only through `References()`. Two
accessors feed two different machines: `route/reference.go` reads `References()` for the idle-resource
walk, `adapter/outbound/manager.go` reads `Dependencies()` for the topological sort. Commit `fd9a076d2`
added `References()` and left the sort blind. Constructed empirically with the real mutation API
(config `endpoints:[{type:tailscale,tag:ts,detour:sel1}]` + `outbounds:[direct,{selector sel1,
outbounds:[direct,ts]}]`): the static graph is acyclic, so **start succeeds**, and the first
`SelectOutbound("ts")` then recurses `Selector → Endpoint → DetourDialer → Selector` to
`fatal error: stack overflow`, which is unrecoverable. Fixed at the point the edge is created rather
than with a per-dial guard.

**LX 016 / `Connections`.** Not a half-applied fix so much as an unsynchronized public type whose
documented usage is two goroutines: the command client's stream goroutine reaches `ApplyEvents`, and
the UI thread calls `Iterator`/`FilterState`/`SortBy*`. The map case is a runtime throw, so it kills
the process outright rather than reporting.

## New findings beyond the brief

1. **A network transition does not invalidate an in-flight blackholed dial.** Measured directly on the
   real Go stack: `ResetNetwork` re-emits the half-open flow's SYN-ACK instead of closing it, because
   the transition path drains only *tracked* connections and a dial that has not completed is not
   tracked. Such a dial therefore runs to `connect_timeout` or indefinitely. Fixing it needs a
   transition-cancelled dial context in `route/conn.go`. **Not fixed — reported**, because it is a
   production change to the packet path.
2. **The DNS-transport ↔ outbound cross-kind cycle is validated by neither manager.**
   `dns/transport_adapter.go` deliberately puts `detour` into `references` and only `domain_resolver`
   into `dependencies`, which is correct for transport-vs-transport ordering; a transport↔outbound
   cycle falls between the two managers. No deterministic repro was built, so it is recorded as an
   open item rather than a fix.
3. **Two guards had no tests at all**: the outbound startup cycle check (now covered) and the
   `common/trafficcontrol` connection-list race (still untested).
4. **This fork is ahead of LX** on control-plane panic containment (`daemon/server_recover.go`, which
   LX 099 needed), the interrupt primitive (LX 084's fix), and Tailscale 111.

## SPEC 038: why no signature was changed

The audit found 29 declarations whose result frame carries a Go pointer. Converting them is a
**coordinated two-repository migration**, not a local edit: the shipped Apple client calls
`options.getHTTPProxyServer()` and the change rewrites the generated ObjC method to return
`LibboxStringBox *`, so the signature and that call site must move in the same commit. Doing half of it
here would break the Apple build to remove a risk that is currently theoretical — and the audit could
not prove a device crash for any specific method on this toolchain (host probes never reached
`bulkBarrierPreWrite`). So the change was reverted and the entry registered as **checked debt**
instead: the tripwire fails on any NEW occurrence and fails if a registered entry is removed without
the signature being fixed, so the register can only shrink. Converting these belongs with the Apple
client migration.

The tripwire is platform-neutral (`go/parser` AST, including files excluded by the current build tags),
and its honest scope is the *shape*, not a reproduced crash: the packed frame is real and upstream's
Go 1.26 fix treats a bare-string result as alignment-sensitive, but whether a given frame lands off an
8-byte boundary depends on the platform C compiler's frame offset.

## Remaining risks

1. **The blackholed-dial transition gap (new finding 1)** is a real, unfixed P2: a dial that stalls
   before completing is not invalidated by a network change and runs to its connect timeout.
2. **29 gomobile declarations** remain un-migrated by design (checked debt).
3. **`108B` has a narrow residual inside `x/net/http2`**: `transportResponseBody.Close` takes `cc.wmu`
   to return connection-level flow control for buffered-but-unread body bytes *before* its
   ctx-watching select. Bounding it needs either discarding credit (which stalls every other stream on
   the shared connection) or a detached waiter on the same mutex. Documented in `stream_conn.go`.
4. **The DNS cross-kind cycle** is unproven either way.
5. **A structural-sniff residual**: a genuine 148-byte uTP `ST_DATA` with a zero extension byte and
   connection id `0x0000` is claimed as WireGuard (~1 in 2¹⁶). Inherent to a length+type+reserved rule
   without payload inspection.

## FUTURE CANDIDATES

Feature-shaped, deliberately skipped: LX 093 custom-path `service_name` plus the lite-vs-go gRPC
transport divergence it exposes; LX 060 auto `record_fragment` when a TLS outbound is dialed through a
detour; LX 116 `urltest mode: failover` / LX 054 penalty scoring; explicit netstack connect deadlines
if gVisor is ever re-enabled.

## Verification

`gofmt` clean · `go mod tidy -diff` clean · targeted `-race` green (`adapter/outbound`,
`common/interrupt`, `common/sniff`, `protocol/tailscale`, `protocol/group`, `transport/http`, `route`,
`protocol/tun`, `experimental/libbox`) · full `./...` with only the two known pre-existing failures
(`common/tlsfragment` external network, `experimental/libbox` test-binary `runtime.fwdSig`) · every fix
red-checked against its unfixed implementation.
