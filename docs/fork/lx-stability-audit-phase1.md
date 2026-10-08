# LX stability audit — phase 1

Selective absorption of [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx)
bug-fix experience into this fork, without taking its feature work. The phase-1 goal
is the stability base: crashes, stalls, zombies, lifecycle races and the failure
modes those fixes exist to prevent.

## 1. Baseline

| | |
| --- | --- |
| `testing` HEAD at start | `aac61e522` (`fix(ci): sort both sides of the zip content comparison`) |
| `testing` HEAD after | `58d53cc61` (5 commits, see §7) |
| LX reference | `Leadaxe/sing-box-lx` branch `lx` @ `a97658c1` (`changelog: v1.14.2-lx.12`); registry last touched by LX sync 109 (`741d5ffa1`, upstream v1.14.2 + 15) |
| LX task registry | 115 task dirs (`SPECS/TASKS/001…117`, minus 034/036 merged into 033/035), `SPECS/FEATURES/004-HOTFIXES/FEATURE.md` |
| Upstream base | upstream `v1.14.2` line; 4100 commits on `testing` since the upstream base |
| Toolchain | go 1.25.5 (per `go.mod` `go 1.25.5`; `GOTOOLCHAIN=go1.25.5` needed locally because Homebrew's go is 1.25.4 and `GOSUMDB=off` blocks the toolchain fetch) |

Structural difference that decides many rows: **LX carries forked submodules
(`sing-tun`, `wireguard-go`, `gvisor`, `utls`); this fork has no submodules.** It pins
modules in `go.mod` and replaces only `sing`, `cronet-go` and `quic-go`. A bug whose
fix lives in a pinned module cannot be fixed here without taking on a fork, which this
fork's architecture deliberately avoids — those rows are DEFER with the exact module
and pin named.

## 2. Audit summary

Status meanings: **FIX** = present here and fixed in this phase · **TEST-ONLY** =
already protected, a guard was added · **DEFER** = needs a module fork or a feature
this fork does not have · **N/A** = the architecture does not involve it ·
**ALREADY-COVERED** = equivalent or stronger protection already exists.

### 2.1 Fixed in this phase

| LX | Root cause | Status here | Class | Result | Test |
| --- | --- | --- | --- | --- | --- |
| 046 | DNS hijack is enqueued synchronously from the TUN packet loop; the enqueue waits for the resolver's detour dial, so one silent-drop DNS server parks the whole loop for the DNS timeout | Present | FIX | `HijackDNSPacket` parses in the caller and hands the exchange to a goroutine under a 256 in-flight cap; overflow is dropped and logged (a dropped UDP query is retried) | `route/dns_hijack_isolation_test.go` — red: did not return for the whole exchange |
| 045 | `tls.enabled=false` gives `(nil, nil)` by contract, but trojan/vless wrapped the nil config in a live dialer → nil-config `ClientHandshake` → process SIGSEGV on the first dial | Present | FIX | Dialer is only built when a config exists (what vmess already did) | `protocol/{trojan,vless}/outbound_tls_disabled_test.go` — red: `tlsDialer` non-nil |
| 090 | `hex.Decode` writes `len(src)/2` bytes without checking `dst` capacity, so a `short_id` >16 hex chars runs off the `[8]byte` **inside** the decoder; the following `decodedLen > 8` test is unreachable | Present (client **and** server) | FIX | Length checked before the decode; 17 hex (previously an odd-length decode error) is now the same invalid-length error | `common/tls/reality_short_id_test.go` — red: the test process panics |
| 047 | `NetworkManager.router` is assigned on the initialize stage, but the daemon publishes the instance before `Start` finishes, so an interface-change RPC in that window dereferenced nil | Present (both layers) | FIX (kernel half) | `resetNetworkLocked` returns early when there is no router. The libbox `Ready()` gate is **not** taken: this fork has no `daemon`/libbox command surface (see FORK-DIFF: the launcher/LXD surface is removed) | `route/reset_before_start_test.go` — red: nil dereference |
| 071/072a | The WireGuard bind dials the detour under `connAccess` with only the endpoint-lifetime context; a silent-drop path parks it forever and queues sends, Close and every rebind behind it | Present | FIX | `C.TCPTimeout` budget on the dial (a var, so tests shrink it) | `transport/wireguard/client_bind_lifecycle_test.go` — red: hangs |
| 072b | A closed bind made `receive` return a nil error; wireguard-go's loop only exits on an error, so it hot-spun at 100% of a core and `device.Close()` waited forever on the loop's `Done()` | Present | FIX | A closed bind reports `net.ErrClosed`; the sleep-retry path re-checks `done` | same file — red: nil error / hang |
| 072c | `ClientBind.conn` was read unlocked on the connect fast path and written under the lock | Present | FIX | `atomic.Pointer[wireConn]` | same file, `-race` |
| 082 (H3 half) | The HTTP/3 server tested generic closed-ness before the typed classifier; quic-go's `TransportError.Unwrap()` returns `net.ErrClosed`, so the classifier never ran and `PROTOCOL_VIOLATION` / `FRAME_ENCODING_ERROR` were never logged | Present | FIX | `serveErrorIsAFault`: typed classification first, generic sentinels only as a fallback — the rule already stated on `IsExpectedH3Closure` | `transport/http/serve_error_fault_test.go` — red: a protocol violation classified as an orderly close |
| 085 | A SOCKS5 relay address of `0.0.0.0`/`::` is legal and means "any address of mine", but Go reads an unspecified literal as the local system, so every datagram went to loopback with **no error** while TCP through the same proxy worked | Present | FIX | A packet dial to an unspecified/empty relay address is redirected to the configured server with the server's port; a concrete address is honoured as sent; port 0 is an explicit error | `protocol/socks/udp_associate_relay_test.go`, including a tripwire that fails if sing starts normalising the bind itself |
| 091 (§1) | `tuic.udp_relay_mode` had no `default` in its switch, so any typo silently meant `native`; the `enum:` tag is read only by the schema generator | Present | FIX | Unrecognised value is a configuration error; `""` still means native | `protocol/tuic/udp_relay_mode_test.go` |
| 070 | `Box.Close` was unguarded; a stop is legal at any point of `Start`, so a repeat/concurrent Close unregistered the same callback twice and walked a torn-down scope | Present | FIX | `closeOnce` + the first result returned to every caller | `box_close_test.go`, `-race` |
| 070 (WG leaf) | The endpoint built and published its device without serialising against Close; and the stack device sent on a channel Close closes | Present | FIX | Publish step re-checks a `closing` flag under the lock (the build itself must stay outside it: `IpcSet` runs the pause callbacks, which take the same lock); the event send is serialised with the close (a plain `select` was tried and **failed under test**, because `select` picks uniformly among ready cases) | `transport/wireguard/device_stack_lifecycle_test.go` — red: `send on closed channel` |
| 069 | The standard bind opens udp4+udp6 on one port and only tolerates `EAFNOSUPPORT` per family; a udp6 wildcard control failure (Windows `IPV6_UNICAST_IF` → WSAEINVAL) closes the healthy v4 socket and leaves the device socketless | Present | FIX (local mitigation) | A failure on the udp6 **wildcard** control is reported as `EAFNOSUPPORT`, so the module keeps the v4 socket and never creates the unusable v6 one. Failure on any other socket stays fatal | `transport/wireguard/bind_family_test.go` — red: the v4 socket dies with the v6 wildcard |
| 111 | Tailscale's coordinator channel starts on port 80 and only migrates to 443 after it observes the connection dead; DPI that freezes port 80 produces no observation, so the node reads offline for ~15 min after every start | Not covered here | FIX | Upstream's own `TS_FORCE_NOISE_443` is defaulted on by a package `init`; an explicit environment value (including `false`) wins | `protocol/tailscale/control_https_test.go` |
| 092 | All six `box.New` Create loops named the element by index only, though type and tag were computed for the logger a few lines above | Present | FIX | Upstream prefix preserved, type and tag appended | `test/contract/config/init_error_names_test.go` |

### 2.2 Already protected — no patch taken

| LX | Why no patch | Existing protection here |
| --- | --- | --- |
| 084 (interrupt ABBA deadlock) | **Removed upstream** (`0ed951aa0`, LX sync 109) | `common/interrupt/group.go` `Interrupt` and `conn.go` `Close` collect under the lock and close **outside** it — byte-equal upstream. The fix is in the tree; nothing to port |
| 010 (WG GRO split-brain) | **Removed upstream** (`24ea133`) | The wireguard-go pin is past that fix. Residual CONSTRAINT only: do not roll `MaxSegmentSize` 65535 → 2200 |
| 013 (`package_name_regex`) | **Dissolved into the 1.14 base** (`941ce58b`) | Native upstream rule item |
| 029 (detour start order) | **Root cause fixed upstream** (`f39ab0e9`) | `protocol/wireguard` resolves the detour in the Start stage, behind the toposort barrier; `adapter/outbound/manager.go` fails Start with `dependency[X] not found`. LX's fail-fast guard would be a no-op here |
| 050 (URLTest zombie survives restart) | Fixed, and stronger than LX | `URLTestGroup` owns `groupCtx` and cancels it in `Close`; rounds `cancelRound()` + `b.Wait()` on every exit path; `LoadBalance` closes its inner health group. Guards: `urltest_lifecycle_test.go`, `urltest_context_test.go`, `urltest_round_abort_test.go`, `urltest_close_debt_test.go`. The LX transport half (XHTTP conn deadlines, un-cancelable encryption handshake) is DEFER — this fork has no XHTTP and no `vless.encryption` |
| 052 (netstack connect deadline) | Different mechanism | This fork has no `DialTCPWithBind`; netstack dials go through sing-tun's Go stack, which honours `ctx` and self-bounds at ~63 s (`goSynAttempts=6`). Residual: no `C.TCPTimeout` leaf budget (15 s vs 63 s) — deliberately not changed (behavioural, not a failure mode) |
| 064 (selector interrupt dead on inbound) | The defect cannot be written the same way | This fork is on the upstream 1.15 mechanism: `Selector.AttachConnection` + `route/route.go` `registerInterrupt` walks the resolved chain and attaches the **inbound** connection to every group. TEST-ONLY guard added: `protocol/group/selector_interrupt_test.go` |
| 082 (H2 stream-error leak) | Already guarded, one layer down | `baderror.WrapH2` at every transport read path (`transport/v2rayhttp`, `transport/http/stream_conn.go`, `transport/v2raygrpclite`) wraps the raw `http2.StreamError`, which defeats x/net's **direct** type assertion. Classic CANCEL collapses to `net.ErrClosed`; INTERNAL_ERROR / PROTOCOL_ERROR stay visible. TEST-ONLY guard: `transport/v2rayhttp/h2_stream_error_guard_test.go` (measured ~7M spin iterations/300 ms on a raw StreamError, 1 when wrapped) |
| 099 (nil `RemoteAddr` panic) | Feature absent | No `GetURLViaOutbound` RPC in this tree. Naive itself is present, so the caution applies to any future consumer of an outbound conn's `RemoteAddr()` |
| 016 (connections map mutex), 024 (runtime loop guard), 012 (TCP downlink stall) | Not applicable / not reproducible | 016 is in the removed command surface; 024 is deferred in LX too (static `lintOutbound` cycle detection is present here); 012 was closed in LX as not reproducible |
| 091 (§2, masque `uri`) | Architecturally absent | This fork's `protocol/masque` is the upstream-style endpoint implementation; no `profile`/`uri`/`vhttp` keys exist, so LX's ordering bug cannot be written |

### 2.3 Deferred — needs a feature this fork lacks, or a module fix not worth a fork

| LX | Why deferred | Exact requirement |
| --- | --- | --- |
| 040 | The system stack's TCP `acceptLoop` returned on **any** `Accept` error. The listener is bound to the stack's own address and its port is what the forward path rewrites every new SYN onto; nothing cleared that port, so the stack kept rewriting new connections onto a port nobody was listening on, the OS answered RST, and every new TCP connection failed instantly until the tunnel was rebuilt — while existing connections, UDP and QUIC kept working. The listener can be closed from outside the stack (shared fd space; a fast restart is the observed trigger), so the error says nothing about whether the stack is finished | **FIX — dependency fork** | **Published.** Fork `Piggy-Cat-bit-shadow/sing-tun` (a real GitHub fork of `SagerNet/sing-tun`), base `d769a7080ca203f63735ba93e95014e363e25d62` (= `v0.9.7-0.20261006124248-d769a7080ca2`), branch `fix/acceptloop-selfheal`, tip `1cd9bc2216df5edd8e2d5b684d05f32c1dc72835` (patch `665fbe204ce76c691ff40f58e9e33020af5e44f1` + docs). Upstream `dev` @ `7539c9855f` was re-checked on 2026-10-08 and **still returns bare**, so no upgrade path existed. `go.mod`: `replace github.com/sagernet/sing-tun => github.com/Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008082323-1cd9bc2216df`. Patch is `stack_system.go` + a new test file: classify the error (orderly close → quiet exit; anything else → recover), close the unusable listener, re-bind the same address, publish the new port under a lock, bounded backoff 10 ms → 1 s, `Close` interrupts the wait and stops further attempts, recovery counter. Published via the GitHub Git Database API because `github.com`'s git transport was unreachable while `api.github.com` was not | `stack_system_accept_test.go` (in the fork): transient error recovers and dispatches, repeated failure is spaced not spun, `Close` interrupts the backoff, orderly close stays quiet. Red/green proven by reverting only the loop body (three of four red on base), `-race` clean, and re-run from the downloaded archive |
| 041 (WG give-up rebind) — **DEFER → PHASE 1.5** | No equivalent recovery here. It is not a bug fix but a lifecycle mechanism: a lazily-started worker, a shared debounce, a stale-endpoint predicate, a wake trigger, a rebind via `listen_port`, and its interaction with network transitions and shutdown cancellation. Those pieces belong with this fork's existing `NetworkResetGeneration`, `NetworkTransitionSnapshot`, `OnDemandEndpoint`, `Wake()` and `Scope` cancellation, so bolting them on in phase 1 would design them twice | **Priority P0/P1 · implementation feasibility: in-tree, no fork required.** Hooks the pin already exports: `device.SetSessionStateFunc`, UAPI `listen_port=0` for a fresh ephemeral port. This fork already routes `Wake()`/`WakeNow()` → `PauseManager().DeviceWake()` → the endpoint callback, so no new API is needed. **Do not write the implementation before Phase 1.5.** See the handoff section |
| 048 (gvisor handshake nil deref) | Real panic class, **unreachable in every profile this fork ships**: no tag file names `with_gvisor`, and without it `tun.NewStack("gvisor"/"mixed")` returns `ErrGVisorNotIncluded` as a clean configuration error. The pinned gvisor still has the window (`accept.go` nils `ep.h` then unlocks; `dispatcher.go` `handleConnecting` gates on state but not `h`) | A third module fork. Instead, a CI tripwire now fails if any profile names `with_gvisor` (`scripts/ci/verify-upstream-assumptions.sh`) |
| 069 root cause | The module still clobbers the surviving v4 port to 0 after a per-family failure, and still closes the sibling socket | `wireguard-go` fork/bump, or the already-owned `Piggy-Cat-bit-shadow/sing` fork (`common/control/bind_windows.go` is byte-identical to upstream and carries the `""` vs `"[::]"` asymmetry) |
| 101 (GSO retry log noise) | Cosmetic, module-only | `wireguard-go/device/send.go` — fold into the next pin bump |
| 113 (tailscale DERP rebind leak) | Not planned in LX either; needs a `sagernet/tailscale` fork | Do not set `TS_DEBUG_ALWAYS_USE_DERP=true` on standard Stop/Apply paths |
| 053, 083, 086–089 (REALITY compat) | Not panic class (silent fallback to the camouflage site) and needing field validation against Xray ≥ v26.7.11 | Port in the REALITY phase. 083 is feasible without an extra utls fork on this pin (`metacubex/utls v1.8.7` has `MlkemEcdhe`); note LX's own caveat that only chrome-family fingerprints carry the hybrid |
| 038 (gomobile string frame) | Unverifiable here (needs `gomobile bind`) | Whole-surface reflection guard if the command surface is ever restored |
| XHTTP-specific: 002, 011, 042, 043, 059, 061, 076, 077, 094, 104 | This fork has no XHTTP at all (`grep -rln xhttp` → 0 files) | **Carry these fixes with the feature when XHTTP is ported.** The ones that matter beyond XHTTP: 077 (dial-context contract — a dial context must not outlive the dial), 094 (a local close is not a transport failure), 061 (packet-up dial must not wait on the download answer) |
| 032 / 105 (VLESS Encryption) | Feature absent | Carry the cancelable-handshake fix (`guardHandshake`) and the deadlines with the feature |
| 003/005/008/009/025/026/031/080/081 (AWG) · 073/075 (Chain) · 055–068 (LXD) · 019/054/116 (LX urltest modes) | Features this fork does not have, or deliberately different designs | Do not import. This fork's URLTest/LoadBalance architecture is not LX's and is not replaced |

## 3. What each fix actually changed

The five commits and the reasoning behind each shape are in the commit messages; the
points worth stating in the report:

- **The DNS fix is at the router, not at each inbound.** Seven endpoints call
  `Router.HijackDNSPacket`, so fixing it once there covers the TUN stacks (system and
  gvisor), MASQUE, OpenVPN, OpenConnect, Tailscale and WireGuard endpoints. The payload
  is unpacked in the caller because the packet buffer belongs to the stack and is only
  valid until the call returns.
- **The WG endpoint `Start` lock shape changed twice.** Holding `stateAccess` across the
  whole build looked correct and is a self-deadlock: `wgDevice.IpcSet` brings the device
  up, which runs the pause/network callbacks, which take the same lock. The build now
  runs outside and only the publish re-checks the flag.
- **The `stackDevice` event send was first "fixed" with a `select` over the send and the
  closed channel.** The test failed: `select` chooses uniformly among ready cases, so
  with an empty buffer and a closing device it picks the send and can lose the race.
  Serialising the send with the close is the only correct shape.
- **The socks5 relay wrapper is scoped to `version: 5`** (the only version with UDP
  ASSOCIATE) and to packet dials only, so the CONNECT path and the control connection are
  untouched. The test suite includes a tripwire that fails if sing starts normalising the
  bind itself — the condition for deleting the wrapper.

## 4. Verification

Run on macOS arm64 with `GOTOOLCHAIN=go1.25.5`. Tags unless noted:
`$(cat release/DEFAULT_BUILD_TAGS)`.

| Command | Result |
| --- | --- |
| `gofmt -l cmd include option protocol route service transport common dns adapter box.go` | clean |
| `./scripts/ci/verify-upstream-assumptions.sh` | PASS (all tripwires + the new `with_gvisor` tripwire); pins printed |
| `go build -tags "$tags" -o /tmp/sing-box-final ./cmd/sing-box` | OK; `version` prints `go1.25.5 darwin/arm64` (the release path with `badlinkname` links as a real binary) |
| `go test` over `common dns route protocol transport adapter option service experimental` + root, without `badlinkname` | 50 packages ok; the only failure is `common/tlsfragment` (3 tests, external network: `dial tcp 1.1.1.1:443: operation timed out`) — this environment has no external connectivity |
| same with `badlinkname` | additionally `experimental/libbox [build failed]: link: invalid reference to runtime.fwdSig` — **pre-existing and unrelated**: it only occurs in a test binary, the release binary links fine, and it disappears without the tag. The `badlinkname` pin predates this phase |
| `go test -race` on `route dns protocol/group protocol/socks protocol/tuic protocol/trojan protocol/vless common/tls transport/http transport/v2rayhttp` + root | all ok |
| `GOOS=linux GOARCH=amd64` build of every changed package | OK |
| `GOOS=windows GOARCH=amd64` build (`DEFAULT_BUILD_TAGS_WINDOWS`) | OK |
| `GOOS=darwin GOARCH=arm64` with `low_memory` | OK |
| `common/trafficsched` `TestContentionHighVersusHigh` | failed once in the full run (timing-sensitive), passes in isolation and on re-run — pre-existing flake, unrelated files |
| `git status` | clean except two pre-existing untracked files (`build-screens-doc.py`, `capture-screens.sh`) that predate this phase and are not touched |

Phase-1 finalization re-check (targeted, not a second full run): every phase-1 test
re-ran green — panic/config guards (trojan, vless, tuic, common/tls), DNS hijack
isolation (`-race`, `-count=2`), reset-before-start, the WireGuard recovery and
lifecycle set, the socks relay set, `Box.Close`, the H3 and H2 guards, the selector
interrupt guard, the tailscale knob, and the init-error naming test in the `test`
module. The `-race` exclusion for
`TestStackDeviceConcurrentStartAndCloseDoNotPanic` is deliberate and documented in that
file: running it under `-race` reliably reports the **pinned sing-tun Go stack's own**
Start/Close race (`stack_go.go`), not this fork's code. The package is otherwise run
under `-race` in full. The three known unrelated failures were re-confirmed as unchanged:
`common/tlsfragment` needs external network, `experimental/libbox` links only without
`badlinkname` (test binary only; the release binary links), and the `trafficsched`
contention test is timing-sensitive and passes in isolation.

## 5. Risk — what unit tests cannot prove here

- **046 (DNS isolation)**: the cap and the isolation are unit-proven; the field symptom
  (a real silent-drop detour on a phone) is not. The 256 cap is LX's, carried over
  unchanged; if a resolver legitimately holds more than 256 queries in flight, the excess
  is dropped and retried by the client.
- **069**: Windows runtime behaviour is unverified (no Windows host). The errno mapping
  is read from LX's specs and the sing comment. The local mitigation is cross-platform
  and unit-tested; the module's port-clobber residual is not fixed.
- **070**: no daemon path here runs `Box.Close` concurrently with `Box.Start` (the
  command surface was removed), so this is an API-level hazard for embedders, proven by
  test rather than by a field reproduction.
- **041** (if/when done) and **040**: need a real device / module fork respectively.
- **111**: the knob is verified; the DPI field behaviour is not (needs the reporter's
  network).
- **072 (pause callbacks under the manager lock)**: not changed. `sing`'s pause manager
  invokes callbacks while holding its own lock, so a slow `Down()` blocks pause delivery
  process-wide. Changing that is a `sing`-fork behavioural change, not a phase-1 fix; it
  is recorded here so the next phase decides.

## 6. Carry-forward list

See **Next-stage handoff** at the end of this file: it is the authoritative list of
what the XHTTP, VLESS Encryption and REALITY stages must carry with them. In short —
XHTTP: 050, 061, 076, 077, 082, 094, 104; VLESS Encryption: handshake cancellation,
Vision integration (105); REALITY: keep 090 and continue 053/083/086–089. Every AWG row
stays deferred with the AWG feature itself (§2.3).

## 7. Commits

| Commit | Message |
| --- | --- |
| `994cc243a` | `stability: isolate DNS/TUN blocking paths` |
| `908653330` | `stability: harden configuration and panic boundaries` |
| `808ab6c83` | `stability: harden network endpoint recovery` |
| `6a8f1c483` | `stability: fix lifecycle and cancellation hazards` |
| `58d53cc61` | `test: add LX-derived regression coverage` |
| `c2e34cf6f` | `docs(fork): phase-1 LX stability audit — findings, fixes, deferred items` |
| `38d539094` | `docs(fork): finalize phase 1 — deferral decisions, 040 tripwire, handoff` |
| `acbe11ada` | `stability: pin the sing-tun accept-loop self-heal fork (LX 040)` |

Phase-1 freeze: `aac61e522` → `c2e34cf6f` plus the finalization commit that rewrote the
040/041 rows, added the sing-tun `acceptLoop` tripwire and appended this handoff. No
squash, no rebase, no history rewrite.

**040 was then reopened** by an explicit owner decision: a defect that reaches users as a
permanent failure state is this project's bug even when its cause sits in a pinned
dependency, and "it is in a dependency" is not a reason to leave it deferred. `acbe11ada`
pins the published fork; §2.3 and the dependency policy record it. 041 stays deferred to
Phase 1.5 — 040 was a correctness bug, 041 is a recovery-policy decision.

## Dependency policy

Forking a dependency is permitted only when **all five** hold:

1. the failure is product-critical — it reaches users as a permanent failure state, not
   as a rough edge;
2. no correct in-tree workaround exists — a wrapper, a retry goroutine or a lifecycle
   hack around the boundary would be a fake fix;
3. the patch is small and isolated — one concern, one file where possible, no
   opportunistic changes;
4. upstream has not provided a usable fix — verified against upstream head at fork time,
   not assumed;
5. regression coverage and an upstream-exit path are maintained — the fork carries a test
   that fails without the patch, and the removal condition is recorded and checked.

This exists to stop the pattern of forking a dependency for every small defect. The 040
fork is the worked example: product-critical (all new TCP dies permanently), no in-tree
workaround (`acceptLoop`/`tcpPort` are unexported and `ResetNetwork` does not re-listen),
one file changed, upstream verified still broken on 2026-10-08, four regression tests plus
a tripwire in `verify-upstream-assumptions.sh` that verifies the pin really is the fork,
checks the fix is present, and probes upstream on every run to say when the fork can be
retired.

Publishing it went through the GitHub Git Database API rather than `git push`, because
`github.com`'s git transport was unreachable (curl to `github.com` timed out, `git
ls-remote` failed after 75 s) while `api.github.com` and `codeload.github.com` answered.
The fork is a genuine GitHub fork, so upstream's objects are in the network and the base
commit needed no re-upload: the patch is two trees built with `base_tree` over upstream's
base tree, each with one parent, and one ref. That is also why the remote history has two
commits rather than the local two — the local base commit was only a content snapshot and
the remote history descends from upstream's real commit.

## Next-stage handoff

Constraints the next stages inherit. This is a handoff, not a design document.

### Runtime Lifecycle / Network Recovery (Phase 1.5)

- **041 WG give-up rebind** — the first item of the stage, not a standalone patch: lazy worker, shared debounce, stale-endpoint predicate, wake trigger, rebind, `listen_port` policy, network transition, shutdown cancellation. Priority P0/P1; in-tree, **no fork**. 040 and 041 are kept separate on purpose: 040 was a correctness bug (a listener death becomes a permanent failure state), while 041 is a recovery policy decision that belongs with the runtime primitives.
- **040 removal condition** — when upstream sing-tun makes the accept loop recover on its own, retire the fork, drop the `replace` and let `verify-upstream-assumptions.sh` say so. The tripwire already probes upstream `dev` on every run when `gh` is authenticated.
- The mechanism must be designed against the generation/transition primitives that already exist here (`NetworkResetGeneration`, `NetworkTransitionSnapshot`), not beside them: a rebind is a state mutation and must obey the same ownership checks a DNS answer does.
- **Wake ≠ rebind.** A wake with a healthy session must cost nothing; only a stale predicate (no keypair, or handshake older than the reject window) justifies a rebind.
- **An idle/suspended endpoint must not be woken by background recovery.** No timers or goroutines while the endpoint is idle, asleep or closed; recovery is demand-driven or event-driven.
- **Close must cancel the worker**, and a worker must never outlive the endpoint's generation (the phase-1 `closing` flag pattern is the minimum).
- **Debounce and bounded retry.** One rebind per logical failure series, exponential or fixed backoff, never an unbounded reconnect loop; a pinned `listen_port` must not silently move.
- **Stale socket recovery must be lazy.** Do not add a background prober. The same semantics should later be reused by MASQUE session recovery and the DNS transport pool rather than re-implemented per transport.

### Protocol phase — XHTTP

Porting XHTTP must not move the feature body alone. Re-audit and carry these with it:

- **050** — URLTest zombie half is already fixed at the group layer here; the transport half (conn deadlines, a cancelable handshake, a `Close` that can interrupt an in-flight round) is what arrives with XHTTP.
- **061** — a packet-up dial must not wait on the download answer.
- **076** — xmux reconnect storm: per-connection breaker plus backoff.
- **077** — dial-context contract: after `DialContext` returns, an expired dial deadline must not kill the live connection; and the dial must wait until the HTTP layer has accepted the request body.
- **082** — this fork already guards the H2 leak with `baderror.WrapH2`; XHTTP's own `HideStreamError` half must be re-derived for the new code, and the guard test extended rather than assumed to cover it.
- **094** — a local close is not a transport failure (do not count it toward a breaker).
- **104** — HTTP-version parity between the client's expectations and the transport it actually negotiates.

### Protocol phase — VLESS Encryption

- **Handshake cancellation** — the handshake must be cancelable and bounded; LX's `guardHandshake` is the shape to re-audit, not to copy blindly.
- **Vision integration** — Vision's flow over the encryption layer was its own defect (**105**); re-verify the conn-type expectations end to end rather than only that it compiles.
- Note that 050's root cause lived in exactly this handshake; treat the two as one audit.

### Protocol phase — REALITY

- **Keep the phase-1 guard**: `090`'s pre-decode `short_id` length check in both `common/tls/reality_client.go` and `reality_server.go`. It is panic-class and independent of any REALITY feature work; do not let a REALITY rewrite drop it.
- Continue the deferred research: **ML-KEM / hybrid key share** (LX 083 — feasible here without an extra utls fork on `metacubex/utls v1.8.7`; note LX's own caveat that only chrome-family fingerprints carry the hybrid), **Xray version compatibility** (LX 053 — the stale `1.8.1` client version, silent fallback to the camouflage site), and **fingerprint differences** (LX 086–089).
- None of the REALITY items are panic-class; all need field validation against a real Xray server, so they cannot be closed by unit tests alone.
