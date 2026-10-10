# v0.1.6 five-workstream closure report (K / L / Z / C / G)

This is the authoritative handoff for the session that produced it. It records what was built, tested
and pushed; what was measured; what was NOT done; and the exact state a continuation starts from.

---

## A. EXECUTIVE / REPOSITORY

```text
working repository        Piggy-Cat-bit-shadow/sing-box
branch                    testing (fast-forward pushes only; no other remote branch created)
SESSION_START_SHA         adf5d286241e22b2479d9e36cb8a82be2a944f6e  (last functional change of the
                                                                   previous session)
BASELINE at session start 8e6c0a965696d98280c5692810945926bc36d5e3  (live origin/testing)
LAST CODE SHA             see section J (recorded after the final push)
origin/testing            see section J
original worktree         UNTOUCHED: C:\src\sing-box stayed at 8d78dcdd with its dirty
                          clients/desktop gitlink
tags                      636, unchanged; none created
force push / reset        never used
other repositories        never written: satelite-one, Apple, Windows Delphi, quic-go,
                          sing-quic, sing-tun, sing, LX
[skip ci] compliance      VERIFIED for every commit by scripts/preflight (see section B)
```

Toolchain: `go1.26.8 windows/amd64` from `C:\src\_toolchain\goroot`; git 2.56.0 from `C:\src\MinGit`.
Race runs used `CGO_ENABLED=1` with the MinGW gcc at
`C:\Users\Jie\AppData\Local\Temp\jiejie-tools\mingw\mingw64\bin` (gcc 16.2.0). Build tags are always
read from `release/DEFAULT_BUILD_TAGS_OTHERS`, never hard-coded.

---

## B. G0 ACTIONS TRIGGER / ZERO-RUN

Re-read from the live tree at session start — not taken from the prompt:

```text
.github/workflows/verify.yml              on: push[branches: testing, ALL paths] + pull_request + workflow_dispatch
.github/workflows/android-core-arm64.yml  on: push[branches: testing, PATH-FILTERED] + workflow_dispatch
                                          paths: cmd/internal/**, experimental/libbox/**, protocol/**,
                                          route/**, dns/**, transport/**, service/**, common/**,
                                          adapter/**, option/**, constant/**, release/**, go.mod, go.sum
.github/workflows/client-apple.yml        on: workflow_dispatch only (+ inputs)
.github/workflows/client-macos.yml        on: workflow_dispatch only (+ inputs)
.github/workflows/client-desktop-windows.yml on: workflow_dispatch only
.github/workflows/server-linux-amd64.yml  on: workflow_dispatch only (+ inputs)
.github/workflows/windows-core-amd64.yml  on: workflow_dispatch only (+ inputs)
.github/workflows/interop-xray.yml        on: workflow_dispatch only (+ inputs)
.github/workflows/release.yml             on: workflow_dispatch only (+ inputs)
```

So a plain push to `testing` WOULD have started Verify (all paths) and the Android core build for the
paths this session touched. `[skip ci]` is the compliance mechanism.

Preflight actually run before every push (`C:\Deepseek\内核\push_preflight.py`, exercised and working):

1. `origin/testing` unchanged since the batch began (no remote drift, fast-forward still possible);
2. every commit in the batch carries the literal `[skip ci]`;
3. the TIP commit carries it (the tip is what a push evaluates);
4. no commit touches `go.mod` / `go.sum` (no unauthorised dependency repoint);
5. no commit message claims an Actions settings change.

**No workflow was executed, dispatched, re-run, or enabled/disabled at any point. No `gh` command was
run. No tag, Release, or release asset was created.**

```text
ACTIONS_RUN_STATUS = NOT_RUN   (hard requirement this session)
```

A post-push read-only check of the run list was NOT possible: this environment has no GitHub API access
and no `gh` CLI. The compliance argument therefore rests on the `[skip ci]` token plus a verified
preflight, not on observing an absence of runs — stated plainly rather than claimed.

---

## C. K1 DOWNSTREAM DESTINATION DNS OWNERSHIP

### C.1 The four wire paths

| Path | Status | Evidence |
|---|---|---|
| SOCKS5 TCP CONNECT | DONE_TESTED | `protocol/socks/outbound_destination_ownership_test.go` — a real loopback SOCKS5 server decodes the CONNECT request; authority assertions are on the ATYP byte |
| SOCKS UDP ASSOCIATE | DONE_TESTED | `protocol/socks/outbound_udp_ownership_test.go` — a real bound UDP relay socket decodes the RFC 1928 UDP request header |
| SOCKS `DialContext(UDP)` / UoT | DONE_TESTED (bug fixed) | see C.2 |
| HTTP CONNECT | DONE_TESTED | `protocol/http/outbound_connect_ownership_test.go` — a real loopback proxy parses the request with `http.ReadRequest`; the assertion is on the authority that parser produced |

### C.2 The bug the prompt predicted, confirmed and fixed

`SOCKS.Outbound.DialContext(UDP)` returned from INSIDE its switch:

```go
case N.NetworkUDP:
    if h.uotClient != nil {
        return h.uotClient.DialContext(ctx, network, destination)   // peer gets the NAME
    }
...
downstreamAddresses, owned, ownErr := h.resolveDestinationForDownstream(...)   // never reached
```

A UoT-configured outbound is the common shape for a residential downstream hop, because UDP through a
plain SOCKS proxy is unusable in practice without UoT — so the uncovered branch was the branch that
mattered. The stream path was covered and the packet path was not, and the asymmetry was invisible
because the switch read as presentation rather than as control flow.

Fixed by resolving ownership ONCE before the switch. `ListenPacket`'s separate copy of the logic is
gone; `ownedDestinationContext` is now the single metadata rule for all four entry points.

### C.3 The shared decision

`common/dialer/destination_ownership.go` holds `DestinationOwnership`, used by both `protocol/socks` and
`protocol/http`. Two protocols making the same decision from the same option is precisely how one of them
ends up enforcing ownership and the other not.

### C.4 Verified properties

- IPv4 → `ATYP=0x01` / `203.0.113.10:443`; IPv6 → `ATYP=0x04` / `[2001:db8::10]:443` (bracketed). An
  unbracketed `2001:db8::10:443` is not a valid authority and a proxy that parsed it would read a
  different port, which is why the assertion is on the exact string.
- **fail closed**, asserted on the PEER's side: after a refused or empty resolution the proxy must have
  received NOTHING. A build that logged an error and then sent `CONNECT example.com:443` would satisfy
  every assertion made on the returned error alone.
- **single-hop unchanged**: without the declaration the domain still travels, and nothing is resolved
  locally, for the stream and the packet paths alike.
- **original domain preserved**: `Destination` keeps the domain, `OriginDestination` and
  `DestinationAddresses` record the rewrite, so SNI, an application's Host header, sniffing, the tracker
  and diagnostics are unaffected.
- **node DNS vs destination DNS**: only the destination is owned. The proxy server's own hostname keeps
  `domain_resolver` and the ordinary dial path.
- **HTTP Host override is refused**, not half-honoured: with `headers.Host` set, the CONNECT authority is
  the operator's value and the destination travels nowhere, so ownership cannot be honoured. Refused
  before anything is sent, naming both halves of the conflict.
- **per-dial, not per-outbound**: each flow asks the local policy for ITS destination (a per-outbound
  cache would answer the second flow with the first one's address).
- **first-address rule** asserted on the wire, and the **port survives** the rewrite (four values).

### C.5 Reverse-breaks (disposable copies, never committed) — all RED

```text
socks: restore the UDP early return                     -> RED (TestUoTDialContextConsultsTheLocalPolicy,
                                                                TestUoTOwnershipFailsClosed)
socks: a resolution failure falls through to the peer   -> RED (both fail-closed tests)
socks: the ownership flag ignored                       -> RED (TestWithoutOwnershipTheDomainStillTravels)
http:  the ownership flag ignored                       -> RED
http:  a failed resolution falls through               -> RED
http:  the Host-override conflict ignored              -> RED
```

One honest note on the UoT test: the UoT target is written into the tunnelled REQUEST HEADER, not used as
a dial target, so a recording dialer observes only the UoT magic address (`sp.v2.udp-over-tcp.arpa`). The
first attempt at that test made exactly that mistake. The header bytes are now decoded through `net.Pipe`
by `TestTheUoTHeaderCarriesAnAddressNotADomain`.

`DESTINATION_DNS_OWNERSHIP_STATUS = READY` for SOCKS TCP / SOCKS UDP / UoT / HTTP CONNECT, each with
wire-level IP assertions, fail-closed, a single-hop control group, and an effective reverse-break.

---

## D. K2 / K3 PHYSICAL PATH — IMPLEMENTED AND TESTED

### D.1 The model

`common/physicalpath/` — `physicalpath.go` (`Hop`, `Path`, `PathNode`, `Snapshot`, `Resolver`, `Build`),
`leaves.go` (`Hops`, `Leaves`, cycle detection, panic containment), `dryrun.go` (`Declarations`,
`HopCheck`, `Failure`, `Report`, `ValidateRoots`).

Direction, PROVEN from the source rather than assumed — a configured `detour` is a DEPENDENCY edge, so
packet order is consumer-first:

```text
common/dialer/detour.go:61    init() resolves d.detour into Y
common/dialer/detour.go:85    DialContext returns dialer.DialContext(...)   X asks Y to dial
route/route.go:247/266        chain := []adapter.Outbound{outbound}; chain = append(chain, outbound)
route/route.go:899/956        leaf := chain[len(chain)-1]                  the exit is dialled last
```

> **CORRECTED after this report was written (`524ea41e`).** The reading below was the model's
> original one and it was WRONG about the packet path. A SOCKS/HTTP proxy outbound uses its detour
> dialer to reach its OWN SERVER (`sing/protocol/socks/client.go:162` dials `c.serverAddr`), so for
> `exit.detour = entry` the device enters ENTRY first. `Hops[0]` is the hop nearest this device — the
> DEEPEST DEPENDENCY — and the last element is the hop the routing selected. `Build` now reverses the
> walk's output to produce that, and `Path.Entry()` was added so a caller never has to work out which
> end is which. The direction was decided by observing the real `NewDetour` plumbing in
> `common/dialer/detour_wire_order_test.go`, not by re-reading the walk.

The walk descends the dependency graph root-first, which is the CONFIGURATION nesting order. That is
what `Hops` was originally reversed FROM; `ControlPath` is reversed with it so the two adjacent fields
do not describe the same path in opposite directions.

Read-only by construction: `Resolver` holds only a lookup func, a `Snapshot` and a network name — no
dialer, logger, context or clock in the type, so it cannot dial, log or time. No cloning (`require.Same`
on the reported object). No invented hop: `Path.Unknowns` carries `{Node, Position, Reason}` and
`Path.Exit()` returns false while any unknown is present.

No rotation is consumed. The enumeration reads each group's DECLARED membership (`All()` U
`Referrer.References()`), so it calls no selection function at all. Where `Build` needs a preview it calls
`Selected(network)`, which for all three real groups is side-effect free — `LoadBalance.Selected` reaches
`SelectForFlow(.., commit=false)`, which READS the cursor with `Load()` and advances it only when
committing.

### D.2 The Start-time dry run

Hooked into `adapter/outbound.Manager.Start` by EXTENDING it, not duplicating it. The pre-existing sort
was extracted as `lintOutbounds` with the start removed, so the dry run runs AFTER it and cannot replace
its more precise message, and the order it computed is passed to `startOutbounds` rather than
recomputed — no second sort that could disagree with the start.

Compatibility, attributed honestly. `EnablePhysicalPathValidation` is what turns the dry run on, and only
`box.New` calls it, so every existing fixture behaves exactly as before (`box_lifecycle*_test.go`,
`box_lifecycle_ordering_test.go`, `box_lifecycle_stress_test.go`, `box_cross_kind_cycle_test.go`,
`route/nested_chain_test.go`, `adapter/outbound/manager_cycle_test.go` all pass unchanged). Which check
refuses what:

| Case | Refused by |
|---|---|
| a member tag that names nothing | the PRE-EXISTING sort (it already read a group's member list through `Dependencies()`, so this failed Start before) |
| a declared cycle | the PRE-EXISTING sort, pinned by `TestStartupCycleCheckStillRunsBeforeTheDryRun` |
| a member that EXISTS and still cannot carry the flow | the DRY RUN only — the unselected-member case the sort cannot see |
| a declared `destination_dns_ownership` the type cannot honour | the DRY RUN |

The only newly-refused configuration is that last one, which is a fork-only option from this same cycle
whose previous behaviour was a silent leak of the destination name. No configuration that started before
is newly refused.

### D.3 A latent panic found and fixed

The start-order sort marks nodes started by TAG and stops when `len(started) == len(nodes)`. Two objects
under one tag satisfy that count with one unvisited, and the dependency-reporting code then dereferenced
the nil result: MEASURED as `invalid memory address or nil pointer dereference` inside `lintOutbounds`,
not an error. Reproduced in a disposable clone with prints (`len(outbounds)=3 len(started)=2`,
`currentOutbound nil=true`). Replaced by `duplicate outbound tag in the start graph: <tag>`, pinned by
`TestDuplicateMemberTagIsRefusedRatherThanCrashingTheSort`.

### D.4 Tests

53 new tests across `common/physicalpath`, `adapter/outbound`, `box_test` and `route`, the last of them
over the REAL `group.Selector` / `group.LoadBalance`. Coverage includes the direction matrix (1/2/3-hop,
outbound->endpoint, MASQUE endpoint leaf, selector->leaf, selector->loadbalance->leaf, nested group,
group+detour), `ControlPath != PhysicalPath`, hop `#0` being the real nearest entry, "the reported leaf IS
the selected leaf IS the dialled leaf", two flows advancing a real cursor EXACTLY twice with a diagnostic
walk in between, unknown-never-invented, multi-error hop/tag attribution, cycle and cross-kind cycle
reporting, and the start-time cases.

### D.5 Reverse-break — five mutations, all RED, each restored byte-identical

```text
A  a control group recorded as a physical hop        -> RED (4 tests)
B  the packet order reversed                         -> RED (3 tests)
C  a preview consumes a round-robin slot (fixture)    -> RED
D  a control group recorded as a hop, REAL groups     -> RED (2 tests)
E  a preview consumes a REAL LoadBalance slot         -> RED
```

```text
PHYSICAL_PATH_CORE_STATUS               = READY
PHYSICAL_PATH_STARTUP_VALIDATION_STATUS = READY
```

### D.6 Not done

Per-hop status / error ownership / the MTU reason block (J-3 below) — needs the `adapter.Lifecycle` /
resource walk and was explicitly out of scope. No public `type: chain`, no per-hop timers or probes, no
second resource manager: none added, as required.

---

## E. K4 OBSERVABILITY / LIFECYCLE — PARTIAL

Not implemented: the per-hop status provider, MTU-reason reporting, hop-localised errors.

Implemented and tested in this session, because the ceiling work depends on it:

- **the MASQUE endpoint's inner capacity is now answerable BEFORE Start.** `PortMTU()` returned
  `c.device.PortMTU()`, and `c.device` is created in `StartStateInitialize` — so between construction and
  Start the call PANICKED on a nil interface. That window is exactly when the answer is needed, because
  an upper protocol sizes itself at construction. It now reads `c.mtu`, the same field
  `StartStatePostStart` hands to `device.Configuration{MTU: c.mtu}`.
  Reverse-break RED: restoring `c.device.PortMTU()` reproduces the nil-pointer dereference.
- `PathCapacity` / `DetourPathCapacity` / `PortMTUProvider` in `common/dialer/path_mtu.go`, with
  `Known` as a separate field rather than "zero means unknown", because zero is not a distinguishable
  answer and a caller one refactor away from reading it as "no capacity" would refuse a working
  configuration.

---

## F. L1–L4 LX

### F.1 LX source audit — `LX_NOT_READ`

`https://github.com/Leadaxe/sing-box-lx` was **not read**: this environment has no general internet
access. No LX commit, tag or release is claimed, quoted, or characterised. Everything below is derived
from THIS fork's source and from the failure descriptions in the task documents, treated as hypotheses
to be verified locally rather than as facts about LX.

```text
LX commit list read        = NONE (LX_NOT_READ)
adoption disposition       = derived independently, see below
```

### F.2 L1 XHTTP configured query — `BUG_PRESENT`, fixed

`baseURL` passed the whole configured path through `sHTTP.URLSetPath`, which is
`net/url.(*URL).setPath` — a function that percent-encodes everything as a PATH. `?` is not a legal path
character, so:

```text
configured   /?proxyip=149.56.109.62
URL.Path     /%3Fproxyip=149.56.109.62
URL.RawQuery ""
request line GET /%3Fproxyip=149.56.109.62 HTTP/1.1
```

The origin sees a path segment named `%3Fproxyip=149.56.109.62` and an EMPTY query. Nothing errors — the
request is well formed and the server answers — so a worker reading `proxyip` to select an upstream
silently relays the wrong way. `transport/v2rayxhttp/configured_query_test.go`: 7 of 7 sub-cases RED
before, all GREEN after, plus path-placement, query-placement merging, `%xx` not double-encoded, a `?`
inside a query value, and X-Padding coexistence. Assertions are on `URL.RequestURI()` — what the write
path puts after the method — not on `RawQuery` alone, which would pass for an implementation that dropped
the query entirely.

### F.3 L2 Path MTU — PARTIAL, with a measured boundary

Implemented (`common/dialer/path_mtu.go` + `protocol/hysteria2/outbound.go`):

```text
PacketOverheadCeiling(1280, IPv6)    = 1232      (40 + 8)
PacketOverheadCeiling(1280, IPv4)    = 1252      (20 + 8)
PacketOverheadCeiling(1280, unknown) = 1232      the IPv6 budget, because if it MIGHT go over
                                                 IPv6 then IPv6 is the only safe number
ClampToCeiling: no ceiling -> unchanged; 0 + ceiling -> ceiling; below -> kept; above -> clamped
```

A ceiling below the QUIC minimum (1200) is REFUSED with the inner MTU, the family and the budget named,
not clamped: clamping up would invent capacity, clamping down would emit a handshake no conforming peer
accepts.

**MEASURED with the package's existing first-datagram harness** (real `WriteTo` lengths, not config
fields):

```text
ChromeParrot off + initial_packet_size 1232 -> 1232 bytes on the wire
ChromeParrot on  + initial_packet_size 1232 -> 1250 bytes on the wire
no detour        + initial_packet_size 1452 -> 1452 bytes on the wire
```

The pinned quic-go replaces `InitialPacketSize` with `chromeInitialPacketSize` (1250) whenever
`ChromeParrot` is set, which hysteria2's default is. So the ceiling is effective only with
`disable_chrome_parrot: true`, or with the pinned library changed. This was verified by reading
`config.go:103-125` of the pinned
`Piggy-Cat-bit-shadow/quic-go@v0.61.1-0.20260929231714-9c94b1e90d94` in the read-only module cache.

`TUIC` was NOT wired. It passes the same `InitialPacketSize`/`DisablePathMTUDiscovery` through
`qtls.QUICOptions`, so the same helper applies, but the change was not made and is not claimed.

`WireGuard` was NOT changed. Its `Endpoint.PortMTU()` delegates to the inner endpoint, which is created
at construction rather than at Start, so no nil window was found there; the WG-over-tunnel MTU arithmetic
was not audited.

```text
LX_SPEC120_MTU_STATUS = PARTIAL
```

### F.4 L3 H3→H2 fallback — `PARTIALLY_FIXED`, gap proven and fixed

The expiry semantics were **already correct and stronger than a latch**: `http3Available()`
(`transport/http/client.go`) compares a stored DEADLINE (`brokenUntil == 0 || now >= brokenUntil`),
bounded 5s → 5m, cleared on H3 success (`tunnel_client.go`) and by `ResetConnections`, with no timer
anywhere — expiry is evaluated per dial, so the memory can never be permanent.

The unclosed part was **concurrency**. `markHTTP3Broken` was a non-atomic read-modify-write over two
separate atomics, run once per FAILING DIAL. Every dial of a burst passes `http3Available()` before the
first of them arms the memory, so N parallel dials met ONE transient failure and multiplied the schedule
by 2^N in that instant. MEASURED with 16 genuinely concurrent dials: the stored window was
`300000000000` ns (5 minutes, the ceiling) instead of `5000000000` ns (5 seconds). One blip therefore
read as "H3 is down for minutes", and each later burst re-pinned the ceiling — the user-visible form of
"HTTP/3 never works here".

Fixed minimally: the escalation step is now CLAIMED by one `CompareAndSwap` on the deadline, so the dial
that finds the memory unarmed escalates and every other dial that failed in the same event is covered by
the window it opened. Both halves are load-bearing — a mutation keeping the CAS but dropping the
open-window guard goes RED again.

Eight new tests pin invariants 2-8, including the two halves of the LX bug that were previously UNTESTED:
that an EXPIRED window retries HTTP/3 (both with a controlled clock and on the real 5-second clock,
writing no state at all), and that a successful H2 does not permanently disqualify HTTP/3. Five
mutations in a disposable copy are RED, including `http3Available` changed to a permanent latch.

Honest limits: `-race` could NOT have caught the original defect — both fields were atomics, so it was a
lost update rather than a data race; the instrument is the value assertion. An adjacent per-authority
memory in `common/httpclient/http3_transport.go` has the same per-attempt escalation shape with a 48h
ceiling (not permanent, and its cap is deliberately pinned) and was NOT changed — flagged for a separate
decision. A pre-existing environmental hang in `TestTunnelTransportIsNotReportedWhenTheTunnelFails` was
proven pre-existing at the baseline commit and is why whole-package runs there use `-skip`.

```text
LX_SPEC121_FALLBACK_STATUS = PARTIALLY_FIXED (expiry already correct; the concurrency gap is FIXED)
```

### F.5 L4 Adjacent bugfixes

- **Six pre-existing gofmt violations**, all byte-identical to their baseline blobs before being touched:
  `dns/{environment_fingerprint_shape,reverse_mapping_atomicity,reverse_mapping_bench}_test.go`,
  `protocol/masque/close_boundary_h3_test.go`,
  `transport/masque/{control_burst,ownership_policy}_test.go`. These FAIL the repository's own gates:
  `android-core-arm64.yml` runs `gofmt -l $(git ls-files '*.go' | grep -v '^clients/')` and
  `client-macos.yml` runs `gofmt -l cmd include option protocol route service transport common dns
  adapter ...`, and both lists cover these paths. Formatting only; the three affected packages pass
  afterwards.
- `windows-core-amd64.yml`: version/provenance ran BEFORE `setup-go`, so `JJ_GO_VERSION` (which
  `version.sh` reads from `go env GOVERSION`) could name the runner image's Go or `unknown` while the
  artifact was compiled with the pinned toolchain. Reordered. No artifact byte changes — the value is not
  in the ldflags. Also added the job's missing `timeout-minutes`.
- `interop-xray.yml`: a header comment claimed the non-live stand runs in Verify on every push; it does
  not, and `test/interop/README.md` says the opposite. Corrected, because a false claim is an invitation
  to delete the step's only caller.

---

## G. Z1–Z3 ZERO-EXTRA-COPY — NOT DONE

No copy/ownership audit was performed and no optimisation was made or claimed. This is deliberate: a
performance change without a measured baseline is exactly the "unverifiable optimisation" the task rules
out, and this environment cannot run the Apple/Darwin paths at all.

```text
ZERO_EXTRA_COPY_STATUS = NOT_RUN
PERF_NOT_MEASURED
```

---

## H. C1–C4 ACTIONS

### H.1 Per-workflow before/after

| Workflow | Change | Reason | Predicted impact (NOT measured) |
|---|---|---|---|
| `verify.yml` | `+concurrency` group `verify-<ref>-<event>`, `cancel-in-progress: event != workflow_dispatch` | the only push-triggered workflow had NO concurrency; a newer push now supersedes an older 40-minute run, while a manual dispatch sits in its own group and can never be cancelled | HIGH on push bursts |
| `verify.yml` | the two release-gate self-tests moved ABOVE `setup-go` | both need no Go, no module download and no network (their own comments say so, and neither script invokes `go`) | LOW (failure path) |
| `verify.yml` | `verify-upstream-assumptions.sh` moved BELOW the three seconds-long structural gates | tripwires link cronet and build the probe; a tag/linkname break is now named by the gate that owns it | MEDIUM (failure feedback) |
| `android-core-arm64.yml` | the four cheap gates moved ABOVE JDK + NDK + gomobile | the file's own comment claimed they ran first; they did not, so a gofmt failure waited for a ~1 GB NDK install | HIGH (failure feedback) |
| `android-core-arm64.yml` | `+concurrency`, same shape | a superseded push no longer pays the NDK + native ARM64 build | HIGH on push bursts |
| `client-apple.yml` | removed `warm the Go module cache` (`go mod download all`) from the `ios` and `macos` jobs | neither compiles this repository's Go; Libbox is the shared artifact both download, and the macOS job's gomobile install fetches its own `@version` module | LOW–MEDIUM (cold cache) |
| `client-desktop-windows.yml` | `setup-go cache: false -> true` + `cache-dependency-path: core/go.sum` | the graph built is the CORE checkout's, whose pin is a fixed commit; the default root-`go.sum` key does not exist in that workspace, which is why caching was off | MEDIUM |
| `windows-core-amd64.yml` | `setup-go` moved above the provenance step; `+timeout-minutes: 60` | see F.5; three cross-builds previously had no ceiling | correctness + MEDIUM (hung run) |
| `interop-xray.yml` | comment only | see F.5 | protects coverage |

### H.2 Preserved artefacts — verified

```text
Android main + legacy AARs   cmd/internal/build_libbox/main.go:418-430 untouched; the workflow still
                             drives it identically and both variants still resolve
                             (android-main carries the mobile geometry and no gVisor; android-legacy too)
windows-core-amd64.yml       official recipe (CGO_ENABLED=0, GOOS/GOARCH, -trimpath), Native Naive
                             POSITIVE control, unstripped symbol inspection via `go tool nm`,
                             upstream-baseline NEGATIVE control — all quoted and present
client-desktop-windows.yml   kept (only the setup-go cache lines changed)
interop-xray.yml             BOTH reference legs kept (matrix default ["v26.9.30","v26.3.27"],
                             fail-fast false, both live legs)
release.yml                  BYTE-IDENTICAL: still no recompile, still selects the CI runs for the
                             commit, still downloads and verifies the artifacts, and
                             release-artifacts.sh still names exactly server-linux-amd64.yml +
                             client-macos.yml, so only already-built, already-verified bytes publish
client-apple.yml /           both present and separate; client-macos.yml untouched
  client-macos.yml
checkout contract            the entire diff adds/removes no fetch-depth, fetch-tags, submodules or
                             ref: line
no new job / no new test / no workflow deleted / no push trigger removed
```

### H.3 Validation actually executed (static only, no remote run)

```text
git diff --check 8e6c0a96..HEAD                    no output, exit 0
YAML parse, all 9 workflows                        built a real parser check in Go (gopkg.in/yaml.v3),
                                                   read the yaml.Node tree so the `on:` key kept its raw
                                                   text and resolved tag !!str — NOT mangled to boolean
                                                   true; events/jobs/steps enumerated from the parse
before/after step inventory                        verify 16 steps REORDERED; android 14 REORDERED;
                                                   windows-core 12 REORDERED; only step-set change is
                                                   client-apple losing exactly ['warm the Go module cache']
                                                   from ios and macos; the other five are step-identical
bash -n over every tracked *.sh                    checked=87 syntax_failures=0
go test ./cmd/internal/...                         exit 0
go test ./cmd/internal/... ./cmd/ci-artifact-probe/...  exit 0
test-gomobile-toolchain.sh                         exit 0 (13/13)
verify-release-acceptance-test.sh                  exit 0
test-release-artifacts.sh                          exit 0 (73 cases)
check-apple-source-selection.sh                    exit 1 — its client-apple.yml section 5/5 PASS;
                                                   the 4 failures are IDENTICAL at the baseline commit
test-apple-signing.sh                              exit 1 — CI section all PASS; 5 failures IDENTICAL
                                                   at baseline
test-apple-beta-publish.sh                         exit 1 — CI workflow section all PASS; 2 failures
                                                   IDENTICAL at baseline (macOS `ditto`)
=> all 11 residual failures are PRE-EXISTING environment failures (uninitialised clients/apple
   submodule, no macOS tooling), proven by re-running the same suites in a detached worktree at
   8e6c0a96 and comparing the failing CASE NAMES.
```

```text
ACTIONS_REFACTOR_STATIC_STATUS = PASS
ACTUAL_ACTIONS_RUNTIME          = NOT_RUN
```

### H.4 Deliberately NOT changed

`interop-xray`'s per-leg duplication (an `if:` on the job index would silently skip the stand in EVERY
leg if wrong — unverifiable locally) · moving `cronet provenance` earlier (its script SKIPS modules absent
from the cache, so before the builds it could pass vacuously) · `setup-go` in the Apple GUI jobs (cannot
prove no Xcode build phase shells out to `go`) · concurrency on dispatch-only workflows (would let a newer
manual dispatch cancel an in-flight audit) · `server-linux-amd64.yml` entirely (dispatch-only; its cache
key and deep-check overlap are deliberate) · the three different gofmt lists, `verify.yml`'s absent path
filter, and `checkout@v4` vs `@v5` (scope changes, not redundant work).

---

## I. TESTS / REVERSE-BREAK

Every command below was run at the commit named, with the real exit code.

```text
go test -count=1 -tags "$TAGS" ./protocol/socks/                      ok
go test -race -count=2 -tags "$TAGS" ./protocol/socks/                ok
go test -count=1 -tags "$TAGS" ./protocol/http/                       ok
go test -race -count=1 -tags "$TAGS" ./protocol/http/                 ok
go test -count=1 -tags "$TAGS" ./transport/v2rayxhttp/                ok
go test -race -count=1 -tags "$TAGS" ./transport/v2rayxhttp/          ok
go test -count=1 -tags "$TAGS" ./common/dialer/                       ok
go test -race -count=1 -tags "$TAGS" ./common/dialer/                 ok
go test -count=1 -tags "$TAGS" ./protocol/masque/                     ok
go test -count=1 -tags "$TAGS" ./transport/masque/                    ok
go test -count=1 -tags "$TAGS" ./dns/                                 ok
go test -count=1 -tags "$TAGS" ./protocol/hysteria2/                  ok
go test -race -count=1 -tags "$TAGS" ./protocol/hysteria2/            ok
```

`./protocol/masque/` requires the `with_quic` tag to build at all (the constructor refuses without it),
so the new lifecycle test carries `//go:build with_quic`; untagged it is excluded rather than failing for
an unrelated reason.

Both halves of the repository's `gofmt` gate now pass for the paths this session touched, and the six
pre-existing violations elsewhere are fixed.

---

## J. PRODUCT RISKS, REMAINING WORK AND VERDICT

### J-1 PhysicalPath / ControlPath — NOT IMPLEMENTED

Root cause: no representation exists. `adapter.InboundContext.OutboundChain` is a list of tags; nothing
walks the resolved `detour`/endpoint/group graph into packet order. Next step and full constraint list:
`docs/fork/v016-overnight-implementation-report.md` section J-1. Missing dependency: none — this is
offline work.

### J-2 Start-time all-reachable-leaf dry-run — NOT IMPLEMENTED

Next step: a read-only `ReachableLeaves` enumerator that consumes no rotation cursor, then a `Start` stage
running the J-1 builder for every reachable leaf. Compatibility risk to check FIRST:
`box_lifecycle*_test.go`, `box_cross_kind_cycle_test.go`, `route/nested_chain_test.go`.

### J-3 Per-hop observability — NOT IMPLEMENTED

Needs J-1/J-2 first. The MTU block must keep `inner_ip` / `inner_udp_ipv6` / `outer_quic_initial`
separate — `common/dialer/path_mtu.go` now provides the inner-IP-to-UDP-budget half.

### J-4 TUIC path ceiling — NOT IMPLEMENTED

`protocol/tuic/outbound.go` passes the same `InitialPacketSize`/`DisablePathMTUDiscovery` through
`qtls.QUICOptions`, so `dialer.DetourPathCapacity` + `dialer.ClampToCeiling` apply directly. Deliverable:
the same wiring plus a regression test.

### J-5 WireGuard-over-tunnel MTU — NOT AUDITED

Needs the WG encapsulation overhead established from the real packet layout before any number is applied.

### J-6 A hard ceiling that ChromeParrot cannot override — NEEDS AUTHORISATION

This is the one product decision this session could not take, and it is stated as a decision rather than
as a gap:

- the ceiling IS computed and IS handed to the library (`InitialPacketSize`);
- the pinned `Piggy-Cat-bit-shadow/quic-go` replaces it with 1250 whenever `ChromeParrot` is set, and
  hysteria2's default is ChromeParrot ON;
- so the default configuration does not yet honour a proven ceiling, and the fix requires changing that
  pinned library — which this session was not authorised to write or push.

Three options, all the user's call: (a) authorise a minimal patch to the pinned quic-go fork that treats a
configured `InitialPacketSize` as a hard ceiling when the caller signals a fixed path, (b) document
`disable_chrome_parrot: true` as the workaround for constrained IPv6 detours and accept the visible
fingerprint change, (c) leave it measured and open. **No fingerprint default was changed and no fork was
touched.**

### J-7 External gates not run

```text
CI at the final SHA      CI_NOT_RUN — no API access; `[skip ci]` deliberately suppresses push runs
Xray reference interop   BLOCKED_DEPENDENCY — no reference binary, no second endpoint
WARP / IPv6 carrier      REAL_NETWORK_NOT_RUN — no credentials, no capture environment
platform build matrix    NOT_RUN
full `go test ./...`     NOT_RUN (packages touched by the changes WERE run, listed in section I)
real-device soak         NOT_RUN
Zero-extra-copy audit    NOT_RUN
```

### J-8 Status

```text
CLASH_AND_DNS_CONCURRENCY_STATUS        = READY (previous session, unchanged and re-run green)
DIRECT_FAST_PATH_BOUNDARY_STATUS        = READY (previous session, comments/tests only)
DESTINATION_DNS_OWNERSHIP_STATUS        = READY (SOCKS TCP / SOCKS UDP / UoT / HTTP CONNECT)
PHYSICAL_PATH_CORE_STATUS               = READY
PHYSICAL_PATH_STARTUP_VALIDATION_STATUS = READY
PHYSICAL_PATH_OBSERVABILITY_LIFECYCLE_STATUS = NOT_READY (per-hop status is not implemented; the
                                          MASQUE PortMTU lifecycle fix and the path-capacity
                                          helper it needed ARE done)
LX_SPEC119_QUERY_STATUS                 = READY
LX_SPEC120_MTU_STATUS                   = PARTIAL (HY2 wired and measured; TUIC not wired;
                                          ChromeParrot override needs authorisation)
LX_SPEC121_FALLBACK_STATUS              = PARTIALLY_FIXED, gap FIXED (expiry already correct;
                                          the per-dial escalation burst is fixed)
ZERO_EXTRA_COPY_STATUS                  = NOT_RUN
ACTIONS_REFACTOR_STATIC_STATUS          = PASS
ACTIONS_RUN_STATUS                      = NOT_RUN (hard requirement)
GIT_PUSH_STATUS                         = see the SHA recorded at the end of this file
RELEASE_STATUS                          = NOT_READY
```

`RELEASE_STATUS = NOT_READY` because PhysicalPath, the Start-time dry-run and per-hop observability are
v0.1.6 scope and are not implemented, and because no external gate (CI, interop, carriers, build matrix)
was run. `docs/fork/v016-final-release-verdict.md` was NOT modified and stays `NOT-READY`.
