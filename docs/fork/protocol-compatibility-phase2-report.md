# Phase 2 report — protocol compatibility and transport expansion

REALITY current-Xray compatibility, VLESS post-quantum encryption, and the XHTTP client transport, as
one slice. The model is `protocol-compatibility-phase2.md`; this is the engineering record.

## 1. Baseline and final state

| | |
| --- | --- |
| Branch | `testing` |
| Baseline HEAD | `0d2239106` — end of Phase 1.5 |
| Toolchain | Go 1.25.5 (`GOTOOLCHAIN=go1.25.5`) |
| Dependency forks at baseline | `Piggy-Cat-bit-shadow/sing-tun` (LX 040), `Piggy-Cat-bit-shadow/gvisor` (LX 048) — **untouched** |
| New dependency forks | **none** |
| Dependencies added | **none**. `lukechampine.com/blake3` moved from indirect to direct (it was already in the module graph). |
| Reference source | `Leadaxe/sing-box-lx` at `a97658c1` (`v1.14.2-lx.12`), plus the live Xray-core sources for parity checks |

## 2. Interface and configuration surface added

```go
// constant — REALITY key_share policy
RealityKeyShareDefault   = ""
RealityKeyShareClassical = "classical"
RealityKeyShareHybrid    = "hybrid"

// option
OutboundRealityOptions.KeyShare  string   `json:"key_share,omitempty" enum:"classical,hybrid"`
VLESSOutboundOptions.Encryption  string   `json:"encryption,omitempty"`
V2RayXHTTPOptions, V2RayXHTTPXmuxOptions, XmuxRange   // new
_V2RayTransportOptions.XHTTPOptions + enum "xhttp"

// constant — transport type
V2RayTransportTypeXHTTP = "xhttp"

// transport/v2ray — the client transport switch became a registry
type ClientTransportConstructor func(ctx, dialer, serverAddr, options, tlsConfig) (adapter.V2RayClientTransport, error)
func RegisterClient(transportType string, constructor ClientTransportConstructor)

// common/tls — one shared first-flight wrapper, now used by both uTLS paths
func (c *UTLSClientConfig) wrapClientConn(conn net.Conn) (net.Conn, error)

// common/badh2
type RemoteStreamError struct{ … }          // same text, no Unwrap
func HideStreamError(err error) error

// transport/v2rayxhttp
type Client struct{ … }                      // adapter.V2RayClientTransport + adapter.IdleConnectionKeeper
func NewClient(ctx, dialer, serverAddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error)
func (c *Client) CloseIdleConnections()      // idle-only release, for the memory-trim path
func (c *Client) SetKeepIdleConnections(bool)
```

No existing exported signature was changed. The one behavioural default that changed is REALITY's
ClientHello (see §3) — which is the fix, not a side effect.

## 3. REALITY result

**`key_share` implemented.** `""` leaves the fingerprint's own greeting alone; `classical` removes
`X25519MLKEM768` from both `supported_groups` and `key_share` and re-marshals; `hybrid` requires the
share as a **wire fact** (is it in the extension the server will receive — not a table of fingerprint
names that a uTLS update would invalidate) and fails with an error naming the fingerprint. An unknown
value is rejected at outbound construction, so a typo cannot silently become the default.

**Two silent compatibility breaks fixed beyond the option itself:**

1. **The hybrid filter is gone from the default path.** Upstream sing-box deleted
   `X25519MLKEM768` unconditionally. Xray ≥ v26.9.8 requires that share, so the default path could not
   talk to a current server, and the failure is indistinguishable from a wrong public key. The
   `classical` value is now the only path that filters, which is what makes the escape hatch an
   escape hatch rather than the norm.
2. **The auth key now falls back to the hybrid share's X25519 half** (`Ecdhe`, else `MlkemEcdhe`).
   This is bit-for-bit what Xray's own client does, and it is what makes an unfiltered hybrid greeting
   work at all: uTLS records a hybrid first share only in `MlkemEcdhe`, so a build that reads only
   `Ecdhe` has to delete the share to function.

**053 — minimum client version.** `SessionId[0..2]` now declares 26.3.27 instead of upstream's
`1.8.1` (its own release epoch). Needed for Xray v26.7.11–v26.7.28; harmless on ≥ v26.9.8, which does
not check the field at all.

**088 — the fragment bypass.** REALITY built its uTLS connection on the bare conn, so `fragment`,
`record_fragment` and the automatic record-fragment default for a detoured dial were accepted by the
config parser and then silently ignored on the REALITY path — on exactly the path where the
post-quantum hybrid greeting (≈1.7 KB, two TCP segments) makes fragmentation matter most. Both paths
now share one `wrapClientConn`.

**090 — the short_id guard** was already in place from Phase 1 and is unchanged; a new test asserts
the key_share work did not weaken it.

**Xray compatibility, as verified against current Xray-core sources:**

| ClientHello | Xray < v26.9.8 | Xray ≥ v26.9.8 |
| --- | --- | --- |
| default on `chrome`/`chrome_pq` (hybrid present) | accepted | accepted |
| `classical` | accepted | **rejected** (`reality verification failed`, silent) |
| `hybrid` on `edge`/`ios`/`android`/`360`/`qq` | n/a | **explicit configuration error** — the core refuses rather than downgrading |

Two LX premises were checked and one is stale: `minClientVer` is **no longer defaulted** on the
releases that require hybrid (both changed in Xray commit `47cfe999`, 2026-09-08), so the version gate
and the hybrid gate never coexist. The version fix is still carried, and the report says why.

**Not fabricated.** No fingerprint is substituted, and no browser profile is hand-assembled. Where the
fingerprint genuinely cannot carry a hybrid share, the core says so.

## 4. VLESS encryption result

Implemented as `protocol/vless/encryption` plus glue in `protocol/vless/encryption.go`, wired into
`option/vless.go` and both `DialContext` paths and `ListenPacket` in `protocol/vless/outbound.go`. The
layer sits **below** the VLESS client and **above** the transport, so `sing-vmess` is untouched.

- **Parser:** the full grammar, fail-closed, table-driven. Every rejection has a distinct error naming
  the offending segment; malformed input cannot panic.
- **Crypto:** ML-KEM-768 + X25519, BLAKE3 `DeriveKey`, AES-256-GCM or ChaCha20-Poly1305 by hardware
  capability, AES-CTR for the `xorpub`/`random` appearances. No new dependency; no invented scheme.
- **Cancellation (the P0):** the write side is bounded by `SetWriteDeadline` from the dial context —
  **write only**, because an XHTTP read deadline is one-shot and would break a live download body to
  fix a write that was not blocked. The read side is bounded by `guardHandshake`, which owns the
  connection until the handshake returns and is **stopped before `wrapEncryption` returns**, so a
  caller that cancels its dial context immediately after a successful dial cannot tear down a live
  connection. That is the 077 boundary, and it is pinned.
- **Vision (105):** the layer registers a `*CommonConn` caster into `sing-vmess`'s private
  `tlsRegistry` via `//go:linkname`, returning the layer's inner connection for direct copy and the
  type/pointer Vision needs for the `input`/`rawInput` fields. Those fields are therefore a **binary
  ABI**, frozen with a comment and pinned by a test — a `sing-vmess` update that reshapes either the
  registry or the fields breaks Vision silently rather than at build time.

**One deliberate deviation from the reference:** padding together with `0rtt` is **rejected**. The
reference accepts it and then silently ignores the padding, because the 0-RTT branch never uses it;
the feature document nevertheless lists "padding applies only to 1rtt, and must be rejected" as a
guarantee, and fail-closed is a hard rule here. `ParsePadding` also now requires exactly three fields
per block (the reference silently used the first three of more).

**One finding recorded rather than fixed:** `sing-vmess`'s `NewVisionConn` does
`unsafe.Pointer(uintptr + offset)` across a function boundary, so the race detector's `checkptr`
aborts for **every** registered connection type, including the built-in `crypto/tls` entry. That is a
property of the pinned library, so the end-to-end call lives in a `!race` test and the registry lookup
and field offsets are asserted race-clean.

## 5. XHTTP result

The whole client transport, ported from the reference's **final** state rather than its first
release, and adapted to this repository: the file names drop the reference's `lx_` prefix, the
provenance is in every file header, and the client-transport selection became a registry so the
transport can register itself from its own build-tagged package.

| Capability | State |
| --- | --- |
| `packet-up`, `stream-up`, `stream-one`, `auto` | implemented; `auto` = REALITY → `stream-one`, otherwise `packet-up` |
| HTTP/1.1, HTTP/2, HTTP/3 | implemented; version selection follows Xray's rule table |
| Session placement (path/query/header/cookie), sequencing, payload placement, padding | implemented, with the mode legality matrix enforced at config time |
| XMUX pool with reuse/request/age limits | implemented |
| Breaker + manager backoff | implemented |
| H2 `StreamError` type boundary | implemented |
| Local-close / deadline / remote-reset classification | implemented |
| Idle-only trim for the memory-pressure path | added by this phase |

**Build tags.** `with_xhttp` gates the whole transport and its registration; `with_quic` additionally
gates the HTTP/3 connection. Verified that the tag is a **compile-time** gate, not a runtime switch:
zero XHTTP symbols in the binary without the tag, and the tag is in all three `release/DEFAULT_BUILD_TAGS*`
profiles and the Apple tag set, asserted against the same `ResolveBuildTags` function the builders and
the provenance record use.

## 6. LX bug lineage

Every item the brief named, with the status and the reason. `APPLIES` means the defect was present
here as well.

| Item | Status here | Why |
| --- | --- | --- |
| **050** URLTEST_ZOMBIE_RUN_SURVIVES_RESTART | **FIXED** (levels 1–2) / **ALREADY COVERED** (level 3) | Level 3 — `URLTestGroup.Close()` cancelling the running round — was already present. Levels 1–2 (a blocked write being physically uncancellable, and the context never reaching the handshake) are fixed by the encryption layer's write deadline plus `guardHandshake`, and by real deadlines on the XHTTP conn types. |
| **053** REALITY_MIN_CLIENT_VER | **APPLIES → FIXED** | `SessionId[0..2]` declared `1.8.1`; now 26.3.27. |
| **060** TLS_FRAGMENT_AUTO_ON_DETOUR | **ALREADY COVERED, then BROKEN on one path → FIXED** | The detour default existed, but 088's bypass meant it never reached REALITY. Fixed by the shared `wrapClientConn`. |
| **061** XHTTP_DIAL_DOWNLOAD_DEADLOCK | **APPLIES → FIXED** | Present in the original XHTTP shape; the ported implementation returns the connection as soon as the upload stream is raised and binds the download response late. `TestDialDoesNotBlockOnDownloadResponse` runs. |
| **076** XHTTP_XMUX_BREAKER | **APPLIES → FIXED** | Per-connection consecutive-failure counting, threshold, manager backoff, success reset, `GetBody` replay. Six breaker tests run. |
| **077** XHTTP_DIAL_CTX_CONTRACT | **APPLIES → FIXED** | The old form watched the dial context past the dial's return and killed live streams; the DNS transport pool is the case that triggers it. The before/after contract is implemented and pinned, reconciled with 061. |
| **082** H2_STREAM_ERROR_TYPE_LEAK | **APPLIES → FIXED** | `common/badh2.HideStreamError` hides the concrete type at the transport boundary while preserving the text; all six read/setup points funnel through one helper. `TestStreamErrorDoesNotSpinConsumerReadLoop` runs. |
| **083** REALITY_MLKEM_KEYSHARE | **APPLIES → FIXED** | The unconditional hybrid filter is removed from the default path, and the auth key falls back to `MlkemEcdhe`. |
| **086** UTLS_FORK_FIREFOX148 | **DEFERRED** | The preset and the key-share reuse logic live inside uTLS; neither can be supplied from this layer, and hand-assembling a Firefox profile would make the fingerprint itself wrong. Needs a fourth fork, which this phase did not take. |
| **087** UTLS_SAFARI_26_3 | **DEFERRED** | Same reason as 086. |
| **088** REALITY_FRAGMENT_BYPASS | **APPLIES → FIXED** | One shared `wrapClientConn`; a test asserts the REALITY path really gets the wrapper. |
| **089** REALITY_KEY_SHARE_OPTION | **FIXED** | The three-valued option with the semantics above. |
| **090** REALITY_SHORT_ID_OVERFLOW_PANIC | **ALREADY COVERED** (Phase 1) | The length check before `hex.Decode`; a test asserts the key_share work did not weaken it. |
| **094** XHTTP_LOCAL_CLOSE_NOT_FAILURE | **APPLIES → FIXED** | Local close, our own deadline and a clean EOF are neutral; remote resets, real resets and a context deadline on a half-dead peer still count. Two tests run. |
| **104** XHTTP_HTTP_VERSION_PARITY | **APPLIES → FIXED** | Xray's rule table, verified character-identical against Xray at two revisions. Table-driven test per row. |
| **105** VISION_OVER_VLESS_ENCRYPTION | **APPLIES → FIXED** | The registry bridge; without it a node with both a flow and the encryption layer failed at connect with `not a valid supported TLS connection`. |

Items the brief did not name but which the reports surfaced, recorded for completeness:
**042** (the `no_grpc_header` option; the reference's own live run did not close the reporter's
complaint — the real fix was the trailing slash in **043**) and **043** (trailing-slash preservation,
which both the path test and `TestTrailingSlashPreservedOffPath` cover) are `ALREADY COVERED` by the
ported implementation. **059** is `ALREADY COVERED` including its split-connection release bug.

## 7. Maturity matrix

Legend: **impl** = implemented; **unit** = covered by a test in this repository that actually runs;
**combo** = exercised together with another layer in one test; **live** = verified against a real
Xray or reference server. Nothing below upgrades unit coverage to interoperability.

| Feature | impl | unit | combo | live | build profiles | Known limitations |
| --- | --- | --- | --- | --- | --- | --- |
| REALITY `key_share` default / `classical` / `hybrid` | ✅ | ✅ 6 tests + 4 subtests | ✅ with the uTLS path | ❌ | all shipped | `hybrid` impossible for edge/ios/android/360/qq (086/087 deferred) |
| REALITY 053 version field | ✅ | ✅ | — | ❌ | all shipped | only needed for Xray v26.7.11–v26.7.28 |
| REALITY 088 fragment on the REALITY path | ✅ | ✅ 4 subtests | — | ❌ | all shipped | not a promise of DPI evasion |
| REALITY 090 short_id guard | ✅ | ✅ | — | — | all shipped | — |
| VLESS encryption parser | ✅ | ✅ 8 valid + 13 invalid + distinctness | ✅ via outbound wiring | ❌ | always compiled | — |
| VLESS encryption `native` framing / rekey | ✅ | ✅ in-process | ✅ with a fake duplex | ❌ | always compiled | PQ handshake wire format not live-verified; no server half exists here |
| VLESS encryption `xorpub` / `random` | ✅ | ✅ XOR both directions, chunk boundaries | — | ❌ | always compiled | reference itself never live-verified these |
| VLESS encryption padding / delay | ✅ | ✅ parse, CreatePadding defaults, caps | — | ❌ | always compiled | rejected with `0rtt`, deliberately |
| VLESS encryption cancellation (050) | ✅ | ✅ 5 guard/deadline tests | ✅ through `wrapEncryption` | ❌ | always compiled | — |
| Vision over encryption (105) | ✅ | ✅ registry + ABI offsets + sentinel | ✅ end-to-end in a `!race` test | ❌ | always compiled | `input`/`rawInput` are an ABI to the pinned `sing-vmess` |
| XHTTP H1 / H2 | ✅ | ✅ | ✅ | ❌ | `with_xhttp` in all shipped | — |
| XHTTP H3 | ✅ | ✅ | ✅ | ❌ | `with_xhttp` + `with_quic` | — |
| XHTTP 061 dial/download | ✅ | ✅ | ✅ | ❌ | `with_xhttp` | — |
| XHTTP 076 breaker / backoff | ✅ | ✅ 6 tests | ✅ | ❌ | `with_xhttp` | mitigation, not the root cause of 082 |
| XHTTP 077 dial-context contract | ✅ | ✅ 5 tests | ✅ | ❌ | `with_xhttp` | — |
| XHTTP 082 error-type boundary | ✅ | ✅ | ✅ | ❌ | `with_xhttp` | — |
| XHTTP 094 close classification | ✅ | ✅ 2 tests | ✅ | ❌ | `with_xhttp` | — |
| XHTTP 104 version parity | ✅ | ✅ table-driven | ✅ | ❌ | `with_xhttp` | HTTP/1.1 and cleartext unit-tested only |
| XHTTP idle-only trim | ✅ | ✅ 5 tests | — | — | `with_xhttp` | — |
| Combination: VLESS + REALITY + XHTTP + encryption + Vision, end to end | ❌ | ❌ | ❌ | ❌ | — | see §8 |

**Live interoperability status: NOT LIVE-VERIFIED IN THIS ENVIRONMENT.** No Xray server, container
runtime or reference node was available, and no external network is reachable from the build
environment. Every claim above is from tests that run here.

## 8. Regression and stress results

| Check | Result |
| --- | --- |
| `transport/v2rayxhttp` | **85 tests, `-race` clean**, including every item in §6 |
| `protocol/vless/encryption` + `protocol/vless` | `-race` clean |
| `common/tls` (REALITY) | `-race` clean |
| `common/badh2` | `-race` clean |
| Full suite, shipped tags | **60 packages ok** |
| `common/tlsfragment` (3 tests) | pre-existing, environment: no external network |
| `experimental/libbox` | pre-existing: test-binary-only `runtime.fwdSig` link error under `badlinkname` |

**Restart stress:** the reference's end-to-end zombie reproduction (`Start → URLTest → blocked
handshake → Stop → Start`, repeated, asserting the goroutine and outbound counts do not grow) is **not
reproduced here**, because it needs the XHTTP reference server to block against. What is covered
instead is the mechanism at the layer that owns it: the handshake guard's abort-on-cancel and
stop-before-return tests, the XHTTP write-deadline test, and `URLTestGroup.Close()` cancelling the
round. That is weaker than the reference's stand and is recorded as a gap, not as covered.

**Network generation:** covered by construction plus Phase 1.5's own tests — a generation change calls
`InterfaceUpdated`, which calls `Client.Close()` and retires the pool while deferring live streams.
No new generation-plumbing test was added for XHTTP specifically.

## 9. Performance

No new per-second polling, no new goroutine that outlives a connection, no new timer:

- REALITY: the key_share policy is evaluated once per handshake; the fragment wrapper only acts on the
  first write.
- VLESS encryption: the write deadline is set and cleared per dial; the guard starts a goroutine only
  when the dial context is cancellable, and it is joined before `wrapEncryption` returns.
- XHTTP: the pool is event-driven. Its only background work is the breaker's backoff wait, which
  respects the dial context. The trim walks the pool once per memory-pressure pass, and the pool is
  bounded by the xmux configuration.
- `with_xhttp` adds no cost to a build without it: the transport is not compiled in.

## 10. Licence and attribution

- The reference (`Leadaxe/sing-box-lx`) is GPL-3.0-or-later, the same licence as this fork. Every
  ported source file carries a header naming the original upstream (`starifly/sing-box`,
  `protocol/vless/encryption`), the reference fork and path, and stating that the file is adapted.
  No header was removed, and nothing is presented as original work.
- The XHTTP transport is the reference's own **independent lean-native implementation** of the Xray
  wire contract — not vendored Xray code — so no Xray-core licence obligation attaches to it. The one
  component declared as a direct port in the reference is `xmux.go`, from `sing-box-extended`
  (itself a sing-box fork, same licence family); that provenance comment is preserved.
- The reference's own XHTTP files carried **no** licence or copyright header, so the adaptation adds
  an explicit one rather than inheriting a notice.
- The repository `LICENSE` additionally forbids derivative works from using the application's name or
  implying association without prior consent. Nothing added here does either; no branding was touched.
- No `README` was turned into a fork advertisement. All documentation is under `docs/fork/`.

## 11. Known limitations

1. **086/087 deferred.** Firefox and Safari cannot carry a hybrid REALITY key share on the pinned
   uTLS, so `key_share: hybrid` on those fingerprints is an explicit error. Full parity needs a uTLS
   fork carrying three upstream cherry-picks; that is a fourth dependency fork and was not taken.
2. **No live verification of anything.** No Xray server and no external network in this environment.
   The REALITY compatibility table in §3 is derived from the Xray sources, not from a run.
3. **The VLESS encryption handshake has no round-trip test.** Only the client half exists here, so a
   round trip cannot be constructed in-tree without reimplementing the server. The reference's own
   record is narrower still: only `native` + `0rtt` with an ML-KEM-768 key ever met a live server.
4. **The combination matrix is not covered end to end.** The layers are tested at their own
   boundaries and the XHTTP tests exercise the transport against `httptest`-based servers, but there
   is no single test that builds a core with VLESS + REALITY + encryption + XHTTP + Vision and drives
   traffic through it. This is the largest gap in the phase, and it is deliberate: the honest
   alternative would have been a test that asserted the plumbing rather than the behaviour.
5. **`classical` is a footgun on current Xray.** It is documented as "Xray < v26.9.8 only" and
   produces a silent server-side rejection otherwise, because that is what REALITY does to a
   handshake it does not like.
6. **The Vision ABI is fragile by construction.** `CommonConn`'s `input`/`rawInput` fields and the
   `sing-vmess` `tlsRegistry` shape are pinned by a sentinel test, but a `sing-vmess` update that
   changes either will break Vision, and the break will be silent in the field even though the test
   catches it here.
7. **`checkptr` vs the pinned `sing-vmess`.** The end-to-end Vision call cannot run under `-race`
   because of a property of the pinned library, so it is covered by a non-race test.
8. **The XHTTP breaker is a mitigation, not a cure,** and local-close classification has a known
   bypass: any close path that does not go through `Client.Close` sidesteps the `localClosed` flag.

## 12. Commits

Seven logical commits on `testing`; the exact list and the final HEAD are reported in the session
summary, because this document is written before the final push.

| # | Commit |
| --- | --- |
| 1 | `reality: support the current hybrid key share and declare the minimum client version` |
| 2 | `reality: apply the first-flight transforms on the REALITY path` |
| 3 | `vless: add the post-quantum encryption layer` |
| 4 | `vless: bound the encrypted handshake by the dial context` |
| 5 | `xhttp: add the client transport` |
| 6 | `xhttp: integrate with the runtime lifecycle and enable it in the shipped builds` |
| 7 | `docs(fork): protocol compatibility phase 2 model and report` |

## 13. Recommended next step

The highest-value follow-up is item 4 in §11: a single end-to-end test that stands up the reference
XHTTP server (or a minimal one) and drives VLESS + REALITY + encryption + XHTTP + Vision through it,
including the `Start → probe → Stop → Start` zombie reproduction. That would convert the largest
"unit-tested" column entry into "combination tested", and it is the only way any of this becomes
"live interoperable".
