# Phase 3.5 report — consolidation, red-team and integration

The model is `phase3.5-consolidation-debug.md`. This file is the record: what was claimed, what was
actually run, and what is still owed.

---

# BLOCKERS / UNRESOLVED RISKS

Nothing blocks the work. These are the risks a reader must know before trusting anything below.

1. **No live verification of anything, anywhere in this project.** There is no Xray binary and no
   external network in this environment. The reference interop stand is complete and has **never run
   a scenario**: it was driven to a real socket against a stand-in that listens and speaks nothing,
   which exercises the gate, the generated configs, the box construction and the artifact capture and
   proves nothing about any wire format. Every protocol claim in this repo remains
   in-process-verified only.
2. **No device validation.** Apple/NetworkExtension and Android are statically and in-process
   verified. Nothing has run on a device. `DEVICE VALIDATION OWED` applies to the whole Apple surface,
   including the foreground/background wake path and the memory-pressure trim ordering.
3. **A blackholing member is never demoted by live traffic.** The dial stack carries no
   machine-checkable stage information, so a first-hop timeout and a destination-side timeout are the
   same error, and a timeout therefore never earns a global penalty. A member that silently drops is
   retried but only the probe retires it. This is the deliberate conservative choice, and it is a
   real functional limitation rather than a note.
4. **The XHTTP transport was unreachable from every config file** until this phase found and fixed it.
   Any build released before that commit cannot use XHTTP at all. Recorded here because it is the
   single most consequential defect this phase found, and because its shape — every unit test, the
   schema, the registry and the build-tag invariants all passed while the feature was dead — is a
   warning about the rest of the suite.
5. **`TestHTTP1PacketUp` is flaky under `-count=60`** on the unchanged baseline (a connection not
   reused). Proven pre-existing, not fixed. It dials with `context.Background()`, so it is unrelated
   to the packet-up context fix.
6. **The Vision tripwire cannot assert at build or link time.** On go1.25.5, a `//go:linkname` pull
   whose target no longer exists does **not** fail the link — the linker materialises a zeroed slice
   and Vision silently reverts to rejecting `CommonConn`. The Phase-2 comment claiming otherwise was
   wrong and has been corrected. The detector is a runtime check.
7. **Two route paths still bypass failover by design**: a flow with more than one candidate address,
   and a member implementing `ConnectionHandler`. A loadbalance nested under a non-capability group
   still gets no route-level failover.
8. **`preMatchFlow`'s committing resolution dials the leaf directly**, so failover is bypassed for a
   `PreMatchFlow` verdict.
9. **The forced-retest valve's real health round is not asserted** — only its throttle.
10. **`metadata.OutboundChain` still names the primary attempt after a successful fallback.**
11. **The DNS group has no parsed-config end-to-end test** and no live-upstream verification.
12. **The MASQUE tunnel's own generation-level assertion is still missing.** The verdict reset is
    covered at the `transport/http` and `ManagedTransport` levels, not through the tunnel endpoint.

---

## A. Known P1 fix table

| Issue | Old failing test | Root cause | Fix | New regression | Race/stress | Status |
| --- | --- | --- | --- | --- | --- | --- |
| **P1-1** WG early trigger never fires | `TestP11EarlyTriggerFiresWithoutAGiveUpEvent` (written first, red on the old code) | `needWorker := session.stale && …`; `Handshake` never sets `stale`, and the settle-window decision lives *inside* the worker, so with no worker nobody decided | start the worker for a handshake in progress too; the loop already exits when nothing is stale and nothing is handshaking | 6 tests: fires with no give-up event; Established before the window costs nothing; 5 retries are one series; Close and Suspend cancel it; a generation earns its own recovery and a second failure coalesces | `-race` clean | **FIXED** |
| **P1-2** coordinator `pending` generation ABA; the "cancellation" was not real | `TestLeaseSupersededCompletionCannotReleaseTheNewGeneration` | a bare bool with no identity, and `observeEpoch` reset bookkeeping without cancelling anything | generation-owned `RebindLease` with id + generation + context; a generation change or close expires and cancels it; `Complete` releases only if still the owner | 8 tests incl. the exact step-by-step interleaving, cancellation by generation change/close/removal, double and post-invalidation completion, 20 successive generations, concurrent Schedule/Advance/Complete | `-race`; goroutine check proves no resident worker | **FIXED** |
| **P1-3** DNS treated local cancellation as server failure | `TestCloseDoesNotRecordMemberFailure`, `TestSingleTargetSubDeadlineDoesNotGetExempted` (both red-checked) | the fan knew a cancelled loser is not a failure; the single and survival paths did not | a `requestLifetime{caller, run}` decides on *which* context is done, never on the error value; the group's own sub-deadline is deliberately excluded so the blackhole detector survives | 6 tests incl. caller cancel, Close, sub-deadline (must be dirty), SERVFAIL vs NXDOMAIN vs empty NOERROR, a cancelled fan loser, and Reset dropping an old result | `-race`, `-count=20` | **FIXED** |
| **P1-4** `disable_version_fallback` bypassed on window expiry | `TestP14StrictNoFallbackOnAttemptWindowExpiry` (red-checked) | the strict check sat inside `if !probeExpired`, and the expiry path also armed the H3-broken memory, which forced HTTP/2 on the *next* dial too | strict is checked before classification and covers every H3 failure mode; nothing is armed on that path | 7 tests incl. the full matrix (immediate refusal, ordinary error, window expiry, caller cancel in both modes, fallback still reachable when not strict, H3 success in both modes, generation reset clearing the verdict) | `-race`; full `transport/http` suite clean | **FIXED** |
| **P1-5** nested failover multiplied the retry budget | `TestLoadBalanceFailoverSpendsOneAlternateAcrossThreeLevels` | each capability group had its own alternate | a `failoverAttemptState` in the context, created by the outermost capability dial and consumed by nested ones: 1 primary + ≤1 alternate for the whole chain | flat / two-level / three-level / alternate-chain / exhausted-deadline / cancellation / hash+sticky assertions, plus a concurrent nested-flow race test | `-race`, `-count=20` | **FIXED** |
| **P1-6** one classifier answered two questions | `TestLoadBalanceGlobalPenaltyClassification` (20 rows, each asserting both decisions) | a single errno table was used for "retry this flow" and "demote this member" | split into `RetryThisFlow` (permissive) and `PenalizeMemberGlobally` (conservative); **investigation found no stage information exists in the dial stack**, so a timeout never penalises globally | 20-row matrix + end-to-end dial-count and ledger tests | `-race` | **FIXED** (with the honest limitation in blocker 3) |
| **P1-7** failover was always on | `TestLoadBalanceFailoverIsOptInAndAnOldConfigIsUnchanged` (decodes the same text with and without the field) | the capability was unconditional | `failover` bool, default false; gating is behavioural — an unopted group is routed through the pre-capability path, not merely retried once | migration test (1 dial / 0 penalties vs 2 dials / 1 penalty) + route-level test that the capability is not advertised + an invalid-value decode test | `-race` | **FIXED** |
| **P1-8** DNS election was a bare bool across generations | `TestResetLetsNewGenerationElectWhileOldFanUnwinds` (red-checked) | `Reset` left `election` set, so a new network could not elect until the old fan unwound | a token carrying its generation and an id; `Reset` invalidates by construction; a slow collector releases only its own token | 6 tests incl. repeated Reset, cancel and Close during an election, and 8/32/128 concurrent queries | `-race`, `-count=20` | **FIXED** |
| **P1-9** Vision private ABI had no tripwire | — (new guard) | the bridge depends on an unexported dependency variable and on our field names/offsets, with no CI signal | a multi-check tripwire: module pin, registry shape, our entry's behaviour through the linked slice, the dependency's own reflecting source, `CommonConn`'s exact field list and offsets, and an end-to-end aliasing assertion | all six checks, each red-checked by perturbing its input; every failure names what moved and what to re-audit | `!race` for the end-to-end call (pinned `sing-msg` `checkptr` reason) | **FIXED** |
| **P1-10** packet-up ignored the caller's context | `TestPacketUpDialPreCancelledContextFailsDial` (red-checked) | `dialPacketUp` discarded `ctx`, and on a warm pool construction is synchronous, so a pre-cancelled dial returned success | check `ctx.Err()` at entry; the error path releases the pool slot exactly once | pre-cancel, cancel-during-construction, cancel-after-return-keeps-conn, and the SPEC 061 deadlock test unchanged | `-count=20` ×3 clean | **FIXED** (one behaviour change, justified in §B) |

---

## B. New bugs found during the red-team work

This is the part that justifies the phase. Five defects were found that were not on the list.

### B.1 — `type: xhttp` could not be loaded from ANY config file (CRITICAL)

`option.V2RayTransportOptions.UnmarshalJSON` had no `xhttp` case, so its `default:` branch rejected
the type:

```
outbounds[0].transport: unknown transport type: xhttp
```

That function is on the production load path (`cmd_run.go`), so the entire XHTTP client transport was
unreachable by any user configuration. Phase 2 added the type constant, the option struct, the
`MarshalJSON` case, the schema entry, the registry hook and the build-tag invariants — and every one
of those passed. **No unit test loaded a config file.**

Found by the interop stand, because generating a real config file is the only thing that exercises the
decoder rather than the struct. Fixed in `8ce22abd7`, with a regression test that asserts **every**
declared transport type survives a round trip through the real decoder, so the next forgotten case is
caught too. Red-checked by removing the case again.

### B.2 — a renamed `//go:linkname` target does not fail the link

The Phase-2 comment in `protocol/vless/encryption/vision.go` claimed a renamed registry "fails the
link at build time". Found false empirically: retargeting the linkname to a nonexistent symbol still
builds on go1.25.5. The linker materialises the declaration as a fresh zeroed slice, our `init`
appends to a slice nobody reads, and Vision silently reverts to rejecting `CommonConn` — so the
failure would have been silent wrong behaviour, not a build error. The comment is corrected and the
runtime length check is the detector.

### B.3 — packet-up returned a connection for an already-cancelled caller

`dialPacketUp` discarded the caller's context. On a warm XMUX pool, construction is entirely
synchronous, so a dial that was cancelled before it returned still produced a connection that looked
successful. Fixed; see P1-10. This is the SPEC-077 contract violated on the one mode that has no
upload body to adopt.

### B.4 — a pre-existing flaky single-flight assertion (fixed)

`TestFastestColdStartElectsOnceUnderConcurrency` asserted the election was released immediately after
the burst joined, but the winning query returns as soon as the winner is delivered while the collector
releases only after draining every participant. Fixed with the codebase's existing `waitFor` barrier;
assertion strength unchanged. The package now survives `-count=20 -race`.

### B.5 — a flaky exact-call-count assertion of my own (fixed during phase 3, confirmed here)

Carried into this phase: the DNS single-flight test's barrier could be satisfied before every query
had entered, and its exact call-count assertion then compared against a burst that had not formed. It
now parks only each member's first call.

### Fault matrices actually exercised (so "found five" is auditable)

| Matrix | What was attacked | Outcome |
| --- | --- | --- |
| Config load | every declared transport type through the real decoder; xhttp option block in full; invalid values | **B.1 found** |
| WireGuard lifecycle | Handshake with no give-up; Established before the window; repeated Handshake; Close during the window; Suspend during the window; generation change during the window | **P1-1 found** |
| Coordinator ownership | the step-by-step ABA interleaving; Advance/Close while a rebind is blocked; double Complete; Complete after invalidation; multiple Advance; concurrent Schedule/Advance/Complete | **P1-2 found** |
| DNS lifetime | caller cancel; group Close; the group's own sub-deadline (must be dirty); SERVFAIL vs NXDOMAIN vs empty NOERROR; a cancelled fan loser; Reset while an exchange is in flight | **P1-3 found** |
| DNS election | old fan blocked then Reset; stale release; repeated Reset; cancel and Close during an election; 8/32/128 concurrent | **P1-8 found** |
| H3 fallback | immediate refusal; ordinary error; window expiry; caller cancel in both modes; blackhole with fallback allowed; H3 success in both modes; generation reset | **P1-4 found** |
| LoadBalance evidence | proxy refused; proxy timeout; proxy-dest refused/timeout/reset/EOF; direct-dest refused/timeout/unreachable; block; caller cancel; `net.ErrClosed`; `ENETUNREACH`; `EHOSTUNREACH`; `EADDRNOTAVAIL`; `ENETDOWN`; `ETIMEDOUT`; nested `E.Cause`; wrapped `net.Error` | **P1-6 found** (and the stage-information gap) |
| Nested retry budget | flat 10-member; two-level; three-level; alternate-is-a-group; exhausted deadline; cancellation; consistent-hashing and sticky bounce; concurrent nested flows | **P1-5 found** |
| Opt-in compatibility | the same config text with and without `failover`; the route-level capability advertisement; an invalid value | **P1-7 found** |
| XHTTP packet-up | warm pool + pre-cancelled ctx; cancel landing inside construction; cancel after return; the SPEC 061 deadlock preserved | **B.3 found** |
| Vision ABI | version bump; a field added to `CommonConn`; a bogus linkname target; a renamed reflected field in the dependency's source | **B.2 found** |

---

## C. Compatibility

| Surface | Behaviour before | Behaviour now | Migration |
| --- | --- | --- | --- |
| `loadbalance` without `failover` | failover silently always-on (**a regression introduced in phase 3**) | exactly the pre-failover behaviour: 1 dial, 0 penalties, no retry | none needed — this *restores* the old semantics; asserted by decoding the same config text both ways |
| `loadbalance.failover` | did not exist | `false` (default) or `true`; a non-boolean fails at decode | add the field to opt in |
| `type: xhttp` in a config | **rejected** at load | loads, with the full option block | none needed — this *restores* reachability |
| `tls.reality.key_share` | phase 2 | unchanged | — |
| `vless.encryption` | phase 2 | unchanged | — |
| `disable_version_fallback: true` | fell back on H3 window expiry | strict for every H3 failure mode | none — this *restores* the documented semantics |
| DNS `group` (modes, TTLs) | phase 3 | unchanged; ownership internals fixed | — |
| Everything else | | **unchanged** | — |

No option was removed, no default changed except to *undo* an unintended regression, and `docs/schema.json`
gained one `"failover": {"type": "boolean"}` entry.

---

## D. Lifecycle ownership table

| Resource | Owner | Construction context | Live context | Cancel source | Network reset | Memory trim | Close |
| --- | --- | --- | --- | --- | --- | --- | --- |
| WireGuard device | `protocol/wireguard.Endpoint` | box ctx | `transport/wireguard.Endpoint` | scope + device | rebind the socket (generation-scoped, TTL'd) | not touched | scope |
| WG recovery worker | the endpoint, lazily | box ctx | poll loop | lease context, box ctx | lease cancelled, worker exits or re-arms | not touched | flag + lease cancel |
| Runtime coordinator | `Box` | box ctx | box ctx | scope (registered first, so closed last) | publishes the epoch; cancels superseded leases | n/a | cancels every lease + its own context |
| XHTTP pool (`xmuxManager`) | the transport client | client ctx | client ctx / `connCtx` per stream | stream close, pool eviction | `Close()` retires all, live streams deferred | `CloseIdleConnections()` — idle only | `Close()` |
| XHTTP stream/split/packet conn | the caller | dial ctx (bounded) | `connCtx`, NOT the dial ctx (SPEC 072/077) | `Close`, deadlines | retired with the pool | not touched | caller |
| H3 QUIC conn / UDP socket | `transport/http.Client` | dial ctx (windowed) | client ctx | `ResetConnection`, `Close` | `ResetConnections` clears the broken verdict | not touched | `Close` |
| MASQUE session | `protocol/masque.Client` | box ctx | one reconnect loop | `Suspend`/`RestartSession`/`Close` | `InterfaceUpdated` → `RestartSession` → `ResetConnections` | `SetKeepIdleConnections(false)` → `Suspend` | scope |
| DNS group fan/election | the group | request ctx | request ctx merged with the run ctx | caller, group Close; a fan loser by us | `Reset()` clears records/current and invalidates the election token | n/a | run context cancelled |
| DNS transport pool | each transport | box ctx | box ctx | `Reset` | retired by the router's loop | `CloseIdleConnections` | scope |
| URLTest round | the group | group ctx | batch ctx | caller, group Close | forced re-probe (deferred while paused) | n/a | cancelled |
| VLESS encryption handshake | the dialer | dial ctx | the returned conn | `guardHandshake` until the handshake returns, then never the dial ctx | n/a | n/a | caller |
| LoadBalance penalty ledger | the group | n/a | atomic snapshot | — (nothing runs) | a foreign epoch is ignored and replaced | n/a | n/a |
| LoadBalance retry budget | the outermost capability dial | dial ctx | the flow's ctx | the dial ctx | n/a | n/a | n/a |
| Apple/Android lifecycle | the platform hooks | platform | `PauseManager` | platform | one generation advance per handover | `TrimMemory` → idle-only release, then `FreeOSMemory` | scope |

---

## E. Integration maturity

Levels: `UNIT` / `COMBINATION` / `IN-PROCESS INTEGRATION` / `REFERENCE INTEROP` / `DEVICE VERIFIED`.

| Capability | Level actually reached | Evidence |
| --- | --- | --- |
| REALITY key_share policy | `UNIT` | handshake-byte assertions per policy and fingerprint |
| REALITY hybrid/classical vs Xray | **not reached** | the rule is encoded in the harness and unit-tested as a rule; no reference server has been contacted |
| REALITY 053 version field | `UNIT` | the session-id bytes are asserted |
| REALITY 088 fragment path | `UNIT` | the wrapper is asserted to be applied on the REALITY path |
| VLESS encryption parser | `UNIT` | grammar, negatives, distinctness |
| VLESS encryption framing / rekey | `UNIT` (in-process) | round trip over a fake duplex |
| VLESS encryption PQ handshake | **not reached** | client half only; no server exists in-tree to complete a round trip |
| Encryption cancellation ownership | `COMBINATION` | guard + deadline tests through `wrapEncryption` |
| Vision over encryption | `COMBINATION` | registry, ABI offsets, end-to-end `NewVisionConn` (`!race`) |
| Vision ABI tripwire | `UNIT` (infrastructure) | six checks, each red-checked |
| XHTTP modes, H1/H2/H3 | `COMBINATION` | 85+ transport tests against `httptest`-based servers, incl. every LX defect |
| XHTTP config reachability | `UNIT` | decoder round trip per transport type |
| XHTTP packet-up dial ownership | `COMBINATION` | warm pool, pre-cancel, post-cancel, SPEC 061 preserved |
| MASQUE H3→H2 window | `COMBINATION` | the full failure matrix, both modes |
| MASQUE tunnel generation reset | `UNIT` (transport level) | not asserted through the tunnel endpoint — blocker 12 |
| LoadBalance failover | `COMBINATION` | dial counts and ledger through `DialWithFailover`, plus the route path |
| LoadBalance nested budget | `COMBINATION` | two and three levels, race-tested |
| DNS group modes / election / anti-storm | `COMBINATION` | 30+ tests with fake transports |
| DNS group in a parsed config | **not reached** | structural only — blocker 11 |
| WireGuard early trigger | `UNIT` | six deterministic tests, no real peer |
| Runtime coordinator leases | `UNIT` | the interleaving matrix |
| Restart / leak / race | `IN-PROCESS INTEGRATION` | cycle tests with counters, `-race`, `-count=20` |
| Anything against a reference implementation | **NOT REACHED** | the harness exists and has never run a scenario |

No row claims more than it earned. In particular nothing is `REFERENCE INTEROP` and nothing is
`DEVICE VERIFIED`.

---

## F. Performance / resource

```
new permanent goroutines     0
new permanent timers         0
idle CPU cost                ~0
per-network-transition cost  one epoch publication + N registration notifications
per-dial added work          two error classifications + one boolean context lookup
new resident state           one lease field, one election token, one context value
```

| Counter | Bound | How established |
| --- | --- | --- |
| dial attempts, 10-member flat pool, all failing | 2 | asserted |
| dial attempts, nested two and three levels | 2 | asserted |
| DNS fans per generation at cold start, 8/32/128 concurrent | 1 | asserted |
| DNS attempts with every member dirty | 1, and 0 fans | asserted |
| DNS records per member on a dead network | capped | asserted |
| DNS fan losers after a winner | cancelled | asserted |
| goroutines after repeated lifecycle cycles | baseline + margin, eventually | cycle tests |
| penalty / TTL / retest state when idle | one atomic read | by construction |
| XHTTP idle trim | idle connections only, never an active stream, never a dial | asserted |

---

## G. Git

| | |
| --- | --- |
| Baseline HEAD | `1a32274e0` (== `origin/testing` at the start) |
| Final HEAD | reported in the session summary — this file is written before the final push |
| Commits | 7 logical commits, listed in the summary |
| `local == origin/testing` | confirmed after the push |
| User-owned files | `clients/apple` (submodule at the user's own commit), `build-screens-doc.py`, `capture-screens.sh` — never staged, never modified |
| Dependency forks | `sing-tun` 040 and `gvisor` 048 — untouched, both tripwires PASS |
| New dependencies / forks / replaces | none |

---

## H. What a maintainer should do next

1. **Run the interop stand against a real Xray.** Everything else here is in-process verification, and
   the WIRE is the one thing this project has never checked. The command is in
   `test/interop/README.md`. Until that run happens, every protocol claim in this repo is provisional.
2. **Add the MASQUE tunnel's generation-level assertion** (blocker 12) — the verdict reset is the one
   adaptive behaviour with no test at its own layer.
3. **Device-validate Apple** (blocker 2), starting with the foreground/background wake path and the
   memory-pressure trim ordering, because those are the two places the code is most confident and
   least observed.
4. **Decide the blackholing question** (blocker 3): either add stage information to the dial path so a
   first-hop timeout can be distinguished from a destination one, or accept that a silent dropper is
   retired only by the probe. Today the code does the latter, deliberately.
