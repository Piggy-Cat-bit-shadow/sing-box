# Upstream sync: SagerNet/sing-box testing → fork

## Transaction boundary

| | |
|---|---|
| `SYNC_PRE_HEAD` | `93255606a` |
| `UPSTREAM_HEAD` | `e85872e9` |
| Merge base | `a781ae65` |
| upstream ahead / fork ahead | 34 / 553 |
| Merge commit | `08f6cb4ed` |
| Ancestry check | `git merge-base --is-ancestor e85872e9 HEAD` → **PASS** |

## Conflicts: 31, and how each was decided

The dangerous part of this merge was not the count. It was that **both sides had
independently created the same subsystems**, so git reported `add/add` on files
that existed at neither parent as a shared ancestor — the merge base contains no
`transport/masque/` and no `transport/http/capsule.go` at all.

| Group | Files | Resolution |
|---|---|---|
| MASQUE + HTTP transport | 19 `AA` | Take ours; verified line-by-line, not assumed |
| na/anytls/http/option | 8 `UU` | Take ours |
| dependency manifests | 4 | Hand-resolved |

### The `add/add` group

Upstream's "Add MASQUE support" (2026-09-28) and the fork's (2026-09-26) are
independent implementations of the same feature, not a shared ancestor. The fork
predates upstream by two days and is the larger superset:

| file | ours | theirs | lines only in ours |
|---|---|---|---|
| `transport/http/capsule.go` | 1003 | 446 | 567 |
| `transport/masque/client.go` | 569 | 479 | 109 |
| `transport/masque/server.go` | 512 | 476 | 48 |
| `transport/masque/session.go` | 301 | 226 | 83 |

**A larger file is not evidence of a superset**, so every "theirs-only" line was
inspected individually. Each one resolved to a pre-refactor form of behaviour the
fork already has — for example `transport/masque/client.go`'s theirs-only lines
are the per-read mutex that the fork replaced with a published atomic snapshot,
and `server.go`'s are an inlined address lookup that the fork extended with
Packet-Too-Big and ICMP error routing.

### Security properties that had to survive

Taking upstream's side of these hunks would have silently reverted hardening, so
each was verified present after resolution:

- `Allow0RTT = false` (upstream sets `true`) — 0-RTT against a non-idempotent
  CONNECT is a replay vector, not a tuning difference.
- No forced `MaxIncomingStreams = 1 << 60`; no unconditional BBR `ProfileStandard`.
- `DisablePathManager` stays opt-in.
- RFC 9931 §8 close-on-CONNECT-reject (`rejectionKeepAlive`) retained.
- `badhttp.ForwardedSource` is **not** used to derive `metadata.Source`. That
  value drives `source_ip_cidr` rules, the unauthenticated limiter and the audit
  trail, so trusting a client-supplied `X-Forwarded-For` is an access-control
  bypass. `TestForwardedSourceHelperIsNotUsedByDefault` pins the boundary.
- HTTP/3 keeps `MaxHeaderBytes` and `IdleTimeout`; masquerade replaces
  `WWW-Authenticate`; auth happens before the 404 branch.

## Dependencies: both `replace` directives are load-bearing

Upstream's `go.mod` has **no** `replace` block. A naive resolution reverts both
pinned forks. Convergence was evaluated against §13's evidence bar and rejected:

- `sing`: upstream `v0.9.7` *does* now contain
  `ConnectedPacketBatchReadWaiter`/`Writer`, which was the original reason for
  the fork replace. But a full tree diff shows the fork's `sing` has **6 files
  upstream does not have** (including `protocol/socks/preconnect.go`, the SOCKS
  preconnect pool) and 3 modified files. The fork references those symbols in 16+
  places, and `SOCKSOutboundPreconnectOptions` /
  `SOCKSOutboundTuningOptions` are user-facing config. Dropping the replace
  breaks the build (reproduced).
- `cronet-go`: supplies the macOS client engine; no upstream equivalent.

Adopted from upstream: released tags for modules the fork does not patch
(`sing-cloudflared`, `sing-mux`, `sing-openconnect`, `sing-openvpn`,
`sing-quic`).

## Silent conflicts the textual merge could not see

Three defects merged cleanly and only surfaced when compiled or run.

1. **`option.LegacyListable` vs `badoption.Listable`.** Upstream's new
   `apple_transport_darwin_test.go` builds TLS options with `LegacyListable`
   literals, but the fork had moved those fields to `badoption.Listable`, and
   `Listable[T]` is a *defined* type, so the assignment is not implicit. The
   merge succeeded, every file parsed, and only building the test binary exposed
   it. Fixed on the test side, since the fork's `Listable` accepts a single JSON
   value or an array and existing configs depend on that. Mutation-verified:
   reverting it reproduces the two compile errors.

2. **`test/go.mod` pinned a stale `sing` revision** (`188cb871422b`) versus root's
   `2616b72468d0`, with no `go.sum` entries for root's revision. The test module
   did not build at all. The CI suite reported this as
   `passed=0 skipped=0 failed=0 (go test exit 1)` — a total build failure that
   reading only the pass/fail counters would misread as "nothing ran".

3. **`docs/schema.json` had already drifted before the merge.** Regenerating at
   the *pre-merge* commit yields 100 definitions against 97 committed. The three
   missing ones (`SOCKSOutboundPreconnectOptions`, `SOCKSOutboundTuningOptions`,
   `UnauthenticatedLimitsOptions`) are fork features present in the option
   structs. Regenerated via the Makefile's tag profile rather than side-picked, so
   it cannot drift from the code again.

## §7 UoT v2 non-connect: nothing to fix, and upstream did not fix it either

The previously-reported `UoT read request: unknown address family: 8` was a test
harness defect, not a product bug, and the correction holds after the merge:
`TestAuditUoTV2NonConnectMode`, `TestAuditUoTV2NonConnectMultipleTargets` and the
whole `TestJiejieNaiveUoTV2*` family pass on the merged tree with **zero** product
changes (`protocol/naive/inbound.go` is byte-identical to its pre-merge content).
See `JIEJIE-NAIVE-UOT-FALSE-P0.md`.

## §9 loopback tests: classification

Both were previously carried as known product failures and both pass without any
behaviour change:

- `TestAuditLoopbackIsReachableByDefault` — **C. test environment assumption.**
  Its failure was collateral from the framing bug; the production behaviour of
  the default route was always correct.
- `TestAuditRouteRuleBlocksLoopback` — **C.** same cause. The rule blocks
  loopback as intended, verified by the rule firing in the logs.
- `TestAuditDomainResolvingToLoopbackIsStillRuled` — **D. intentional behaviour
  retained.** Its `UoT_via_domain` subtest was re-enabled after the false P0 was
  retracted and now passes, so the resolved-IP ACL keeps its security coverage.

No production code was changed for any of the three.

## §10 Naive connection resources: gap confirmed, no default changed

Established by reading the code paths, not by inference:

- `MaxConcurrentStreams` bounds streams **per connection**; it is not a
  connection count, so it cannot bound the number of parked connections.
- The fork already exposes `idle_timeout`, `stream_receive_window`,
  `connection_receive_window` and `max_concurrent_streams` through
  `HTTP2Options`, and `http2Server()` applies them (each documented in
  `option/naive.go`).
- There is **no** connection-count cap anywhere in the Naive path. Upstream has
  none either, so this is not something the merge could have absorbed.

### What is already bounded, and what is not

Tracing the actual call chain rather than reading the struct fields:

| Phase | Bounded? | By what |
|---|---|---|
| TLS handshake | **yes** | `aTLS.Listener` hands out a `LazyConn` whose `Read` calls `HandshakeContext(context.Background())` → `tls.ServerHandshake`, which applies `C.TCPTimeout` (15s) whenever `HandshakeTimeout() == 0` |
| Post-handshake idle | only if opted in | `http2.Server.IdleTimeout` is assigned only when `options.IdleTimeout > 0` |
| Pre-auth request, mid-request | **no** | `http.Server` sets no `ReadHeaderTimeout`/`ReadTimeout`, and `naiveH2Conn.SetReadDeadline` returns `os.ErrInvalid`, so a peer that completes TLS and then stalls mid-request holds the connection |
| Total connection count | **no** | no such mechanism exists |

An earlier draft of this section claimed there was no pre-authentication deadline
at all. That was wrong: the handshake is bounded, and I corrected it after
following `LazyConn` into the dependency. The genuine residual gaps are the
mid-request stall and the absent connection count.

Not actioned in this round, deliberately: per §10 and §5, adding a limit *and*
choosing a default would change production behaviour on hosts whose real
connection concurrency has not been measured. Reported as an open, evidenced gap
rather than closed with a guessed default. Note also that the fork exposes
`idle_timeout` and the receive windows for operators who need to bound a host
today.

## §11 DNS cold path

`dns/router.go` was untouched by this merge, and `dns/client_singleflight_test.go`
already covers leader-failure behaviour in the shared-lookup path. No measurable
double lookup was located. **NOT WORTH CHANGING.**

## Verification

| Check | Result |
|---|---|
| `gofmt -l` (excl. `test/`) | clean |
| `go vet` (macOS client tags) | clean |
| `go vet ./...` | only 2 pre-existing `unsafe.Pointer` advisories in files the merge never touched |
| package tests + `-race` | pass, no data races |
| `test/jiejie` pre-sync | 211 passed / 30 skipped / 0 failed |
| `test/jiejie` post-sync | **211 passed / 30 skipped / 0 failed** |
| new failures | **none** |
| Server Minimal build + contracts | pass, 46,841,506 B |
| macOS arm64 client build | pass, 77,280,178 B |
| `experimental/boxdd` | `invalid reference to runtime.fwdSig` — **pre-existing** (identical at `93255606a`), not a CI target |
| production topology SHA-256 | `dee7dc1a…298c` before **and** after — byte-identical |

## NOT TESTED

- Real remote-network throughput, latency and CPU/RSS for any of this.
- Real JiejieBox GUI acceptance (no GUI session).
- macOS/Windows/Linux non-arm64 builds.
- §10 connection limits: neither implemented nor measured, see above.
