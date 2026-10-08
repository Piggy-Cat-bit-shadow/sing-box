# Protocol compatibility (Phase 2)

REALITY key_share, VLESS post-quantum encryption, and the XHTTP client transport, as one slice on
top of the Phase 1.5 runtime lifecycle.

The engineering record — baseline, per-item LX bug lineage, the maturity matrix, validation results
and known limitations — is `protocol-compatibility-phase2-report.md`. This document is the model.

## 1. Scope and what was deliberately not done

Three capabilities, plus their combinations and their integration with the runtime lifecycle:

| Part | What |
| --- | --- |
| A | REALITY current-Xray compatibility: the `X25519MLKEM768` hybrid key share, the declared minimum client version, the fragment path, and a per-node `key_share` escape hatch |
| B | VLESS application-layer post-quantum encryption (`encryption`), client half, with cancellation-safe handshake establishment |
| C | XHTTP client transport (packet-up, stream-up, stream-one, auto) over HTTP/1.1, HTTP/2 and HTTP/3, absorbing the six historical defects LX had to fix after shipping it |

Not done, and why:

- **A fourth dependency fork** (a uTLS carrying Firefox 148 / Safari 26.3) — see §3. This is the one
  place where this phase cannot reach full parity, and it is recorded as `DEFERRED` rather than
  approximated.
- **The VLESS encryption server half** (`decryption`). This fork's VLESS is client-focused.
- **The XHTTP server half.** The transport registers a client constructor only; an inbound configured
  with `type: xhttp` is rejected as an unknown transport type.
- **AWG, Chain, LXD, DNS Group, the observability command plane, new UI** — out of scope as briefed.

## 2. REALITY

### 2.1 The two silent cut-offs

A REALITY handshake that the server rejects is answered with the camouflage site. The client sees
`reality verification failed`, which is the same message a wrong `public_key`, a wrong `short_id` or a
clock skew produces. There is no diagnostic path from the symptom back to the cause, which is
deliberate anti-probing behaviour and also why every item below is a test rather than a log line.

Xray tightened what it accepts twice, without release notes that a client author would see:

| Change | Effect on a sing-box client |
| --- | --- |
| Xray v26.7.11 defaults `minClientVer` to 26.3.27 | upstream sing-box declared `1.8.1` — its own release epoch — in `SessionId[0..2]`, so every dial was rejected |
| Xray v26.9.8 requires an `X25519MLKEM768` key share before X25519 | upstream sing-box *deleted* that share from the ClientHello, so every dial was rejected |

The two never overlap: Xray ≥ v26.9.8 does not check the version field at all (the default was
commented out in the same change that made hybrid mandatory), and v26.7.11–v26.7.28 checks the version
but does not require hybrid. Both fixes are therefore carried, and the report says which release needs
which.

### 2.2 key_share

`tls.reality.key_share`, three values, default empty:

| Value | Behaviour |
| --- | --- |
| `""` | **Whatever the fingerprint carries.** Chrome (131/133) sends `GREASE, X25519MLKEM768, X25519`; Firefox, Safari, Edge, iOS, Android, 360 and QQ send X25519 only. |
| `classical` | `X25519MLKEM768` is removed from both `supported_groups` and `key_share`, then the greeting is re-marshalled. ~594-byte single-segment ClientHello. **Only Xray < v26.9.8 accepts this.** |
| `hybrid` | The hybrid share is required. A fingerprint that cannot produce one is a configuration error naming the fingerprint, never a silent downgrade. |

Why a three-valued string and not a boolean: an absent field must keep meaning "as the fingerprint
carries it". Applications that rebuild a config from a model collapse a missing field to its zero
value, so a boolean would silently convert the *fingerprint's* policy into a *core* policy. And
`hybrid` has to be expressible as an assertion, because the core can refuse but it cannot add a share
to a preset without lying about which browser it is.

Why neither behaviour can be the unconditional default: stripping breaks Xray ≥ v26.9.8; keeping the
hybrid breaks networks that silently drop a two-segment ~1.7 KB greeting (Xray issue #6256, closed
`not planned`). The core cannot choose for the user, so the default is the only value that is not a
claim about the network.

### 2.3 The auth key

The server derives the REALITY auth key from the X25519 private key of the **first** key share in the
greeting. uTLS records a classical first share in `KeyShareKeys.Ecdhe` and a hybrid first share in
`KeyShareKeys.MlkemEcdhe` (the X25519 half of the hybrid, whose public half travels inside the hybrid
share). Only the first non-GREASE share is recorded at all, so:

```go
ecdheKey := keyShareKeys.Ecdhe
if ecdheKey == nil {
    ecdheKey = keyShareKeys.MlkemEcdhe
}
```

is exactly "the share the server will read", with no second guess available. A build that reads only
`Ecdhe` has to delete the hybrid share to function at all — which is the state this fork was in and
why §2.1's second row existed.

The ordering requirement is about the key-share *list*, not the extensions: the server breaks out of
its loop at the first `X25519`, so a hybrid share placed *after* a classical one is fatal even though
both are present. Chrome's order is correct; a hand-built greeting must preserve it.

### 2.4 Fragmentation

There are two independent mechanisms, and the distinction matters:

- `tls.fragment` splits the ClientHello around the SNI labels and writes each piece as a separate
  socket write, waiting for the ACK between pieces on a real TCP connection. Packet-level.
- `tls.record_fragment` rewrites the first TLS record into several records, each with its own 5-byte
  record header, in one write. Record-level.

The defect this phase fixed: REALITY built its uTLS connection on the **bare** conn, so both options
were accepted by the config parser on a REALITY node and then did nothing, and the automatic
record-fragment default for a detoured dial never reached the handshake — in the one case where an
unsplit greeting is the whole problem. Both paths now go through one shared `wrapClientConn`, and a
test asserts the REALITY path really gets the wrapper rather than asserting the flag is set.

Fragmentation is not a promise of DPI evasion. It is reported as implemented and unit-tested, not as
field-proven.

### 2.5 What is infeasible here

`metacubex/utls` v1.8.7 (and v1.8.8) map `firefox` to `HelloFirefox_120` and `safari` to
`HelloSafari_16_0`; neither carries an `X25519MLKEM768` share, and neither has the hybrid/classical
key-share *reuse* generator that a modern Firefox 148 or Safari 26.3 greeting needs. Both live inside
the library's preset table and inside `ApplyPreset`, so they cannot be supplied from this layer — and
hand-assembling a browser profile would make the TLS fingerprint itself wrong, which is the one thing
the mimicry exists for.

The presets for `edge`, `ios`, `android`, `360` and `qq` are in the same position, and so are
Xray-core's own: its REALITY test set is exactly `chrome, firefox, safari`.

So: on stock metacubex uTLS, `hybrid` genuinely works for the Chrome family and genuinely cannot for
the rest. The core says so in words instead of pretending. Full parity needs a uTLS fork carrying the
three upstream cherry-picks, which this phase did not take (§ report, `DEFERRED`).

## 3. VLESS encryption

### 3.1 What it is

An application-layer, post-quantum, forward-secret AEAD layer **inside** VLESS, aimed at
harvest-now-decrypt-later. It is not REALITY's key exchange and shares nothing with it; the two
combine, but independently.

```
raw transport (tcp | xhttp | ws | grpc | …)
  └─ TLS / REALITY
       └─ VLESS encryption        <- this layer
            └─ VLESS + Vision
```

It sits **below** the VLESS client and **above** the transport, which is why it could be added
without touching `sing-vmess` at all: the layer is a `net.Conn` wrapper, and the VLESS codec above it
is unchanged.

### 3.2 The configuration string

```
mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.<padding-block>…].<key>[.<key>…]
```

- **appearance** — `native` is TLS-1.3-shaped record framing; `xorpub` additionally XORs the relay key
  material with a stream keyed on the client's own configured public key (the legitimate server holds
  the matching private key, a passive observer cannot tell the key from random); `random` XORs the
  whole stream, headers included.
- **RTT** — `0rtt` caches a session ticket and skips the full agreement on a later connection; `1rtt`
  always performs it. Padding and delay apply only to `1rtt`.
- **padding / delay** — `probability-from-to` blocks, alternating length and gap, dot-separated.
- **keys** — base64url of exactly 32 bytes (X25519) or 1184 bytes (ML-KEM-768 encapsulation key),
  dot-separated and order-preserving; several keys form a relay chain whose last hop is the one that
  makes the secret post-quantum.

Fail-closed throughout: an unknown method, appearance or RTT mode, too few segments, an empty
segment, a non-base64url key, a wrong key length and an empty key list each return a distinct error
naming the offending segment. Malformed input cannot panic.

### 3.3 Cancellation ownership — the part that is easy to get wrong

The failure this pins: the handshake is a `net.Conn`-shaped API doing a fragmented-padding write loop,
so a blocked write is physically uncancellable by a context. A URL test stuck in it does not merely
hang — it survives a full stop of the core, holding the run's goroutines and the whole outbound array,
and each restart adds another generation. The field evidence was two runs aged 100 and 43 minutes
holding the same parked stack, and only rebuilding the config cleared it.

The contract, which is the same ownership rule Phase 1.5 established for every resource:

| Phase | Who owns the connection | What can end it |
| --- | --- | --- |
| From `DialContext` until it returns — and for VLESS that includes the encryption handshake | the dialer, and the dial context bounds everything | dial-context cancel or deadline, transport deadlines, `Close` |
| After `DialContext` returns | the caller | **`Close` and read/write deadlines only — never the dial context** |

Two mechanisms implement it, and both are deliberately narrow:

- **Write side:** `wrapEncryption` arms `SetWriteDeadline` from the context deadline and clears it
  afterwards. It must not arm a read or a full deadline: the write is what hangs, and on an XHTTP
  connection the read deadline is one-shot — an expired one closes the late-bound download body and
  cannot be undone by clearing the timer, so arming it would break a live connection to fix a write
  that was not blocked.
- **Read side:** `guardHandshake` owns the connection until the handshake returns, because closing the
  connection is the only lever that reaches a parked read. It is **stopped before** `wrapEncryption`
  returns, so a caller that cancels its dial context immediately after the dial succeeds — which is
  legal `net.Dialer` usage and exactly what this fork's DNS transport pool does — cannot tear down a
  live connection. A handshake that won the race keeps its connection; a guard that fired first does
  not hand up a connection that merely looks healthy.

This is not the transport-level dial watchdog that was tried and removed: that one outlived the dial,
which is why it broke the DNS pool. The guard is stopped at the dial's boundary.

### 3.4 Vision over the layer

`xtls-rprx-vision` finds the TLS connection beneath the VLESS client through a registry private to
`sing-vmess`, which knows only `crypto/tls` and uTLS. Our `CommonConn` is neither, so the connection
failed immediately with `vision: not a valid supported TLS connection: *encryption.CommonConn` on any
node that had **both** a flow and the encryption layer.

One registry entry fixes it, reached by `//go:linkname` because the registry is unexported:

- the returned "raw" connection is the layer's inner connection, so direct copy goes below the
  encryption (matching Xray, which unwraps to the same place), and
- the returned type and pointer let Vision reach the `input` and `rawInput` fields it drains when it
  switches to direct mode.

That makes `CommonConn`'s `input`/`rawInput` field names, types and order a **binary ABI**. They are
frozen with a comment saying so, and pinned by a test — because a `sing-vmess` update that reshapes
the registry or the fields breaks Vision silently rather than at build time.

One real finding from the port, recorded so it is not mistaken for a defect here: `NewVisionConn`
performs `unsafe.Pointer(uintptr + offset)` across a function boundary, so the race detector's
`checkptr` aborts for **every** registered connection type, including the built-in `crypto/tls` entry.
That is a property of the pinned `sing-vmess`, not of this port, so the end-to-end call lives in a
`!race` test and the registry lookup and field offsets are asserted race-clean.

## 4. XHTTP

### 4.1 Shape

A client-only transport: one logical session is one session id plus one pooled HTTP connection shared
by both halves. `Client` owns an `xmuxManager` pool; each pooled connection wraps an HTTP/1.1,
HTTP/2 or HTTP/3 round tripper; each dial takes one release handle; the connection handed to the
caller is one of three implementations:

| Mode | Upload | Download |
| --- | --- | --- |
| `packet-up` | one bounded POST per write, sequenced | a separate long GET |
| `stream-up` | one streamed POST | a separate long GET |
| `stream-one` | the request body | the response body |
| `auto` | REALITY → `stream-one`, otherwise `packet-up` | |

Session metadata placement (`path`, `query`, `header`, `cookie`), sequence numbers, payload placement
and padding are all implemented; header/cookie payload placement and `GET` are rejected or corrected
where the mode cannot support them, at config time rather than at dial time.

### 4.2 The six defects it absorbs

XHTTP was not ported in its first form. The failure knowledge is the deliverable, and each item has
its regression test running:

- **061 — dial/download deadlock.** `DialContext` awaited the download response, the server withheld
  the download until the first uplink packet, and the caller could not send the first uplink until
  `DialContext` returned. Silent on a direct connection; a `504` in front of a reverse proxy. The dial
  now returns as soon as the upload stream is live and the download response is bound later, with its
  error delivered to the same `Read`. `TestDialDoesNotBlockOnDownloadResponse` is the reproduction.
- **077 — the dial-context contract.** The old implementation kept watching the dial context after
  `DialContext` returned, so a caller that cancelled immediately afterwards (legal `net.Dialer`
  usage, and what the DNS transport pool does) killed a live stream with its own `ctx.Err()`. The
  contract in §3.3 is exactly this, and it must be reconciled with 061: "the upload stream is raised"
  means the HTTP layer *adopted the body*, not that the download answered.
- **076 — the XMUX breaker.** A CDN resetting every upload stream ran an unthrottled dial→reset→dial
  loop at channel speed and pinned both cores of a router. Per-pooled-connection consecutive-failure
  counting, a threshold, and a manager backoff now damp it; a success resets both.
- **082 — the H2 `StreamError` type leak.** A raw foreign `http2.StreamError` escaping the transport
  made an outer `x/net/http2` treat it as its own internal stream error, and its read loop spun
  forever with zero syscalls. The type is now hidden at the transport boundary — text and semantics
  preserved, concrete type gone.
- **094 — local close is not a failure.** A local `Close` cancelled an in-flight round trip, the
  breaker counted `context.Canceled` as a remote failure, and three in a row evicted a *healthy*
  pooled connection. Local close, our own deadline and a clean EOF are now neutral; a remote reset, a
  real `ECONNRESET` and a context deadline on a half-dead peer still count.
- **104 — HTTP version parity.** Version selection follows Xray's rule table exactly (no TLS → H1;
  REALITY → H2 whatever `alpn` says, with the list replaced by `["h2"]` and a warning if it lacks it;
  TLS with empty `alpn` → H2; `["http/1.1"]` → H1; `["h3"]` → H3; anything else → H2), verified
  character-identical against Xray at two revisions.

### 4.3 Runtime lifecycle integration

XHTTP is a consumer of the Phase 1.5 model, not a second one. It needed no new machinery, because the
two paths already existed and only one of them had to be added:

| Trigger | Path | Effect on the pool |
| --- | --- | --- |
| network generation change | `InterfaceUpdated` → `Client.Close()` | retire **every** pooled connection: all of them belong to the network being left. Live streams keep theirs to completion (the teardown is deferred), so no active flow is killed. |
| memory pressure | `TrimMemory` → outbound `CloseIdleConnections` → `Client.CloseIdleConnections()` | retire **only** connections with no live stream |
| `Close` | scope cleanup → `Client.Close()` | retire everything, deferred for live streams |

The distinction in the second row is the point. Retiring a connection that carries a stream would not
break that stream, but it would make the next request dial — which is the "trim that caused a
reconnect" the lifecycle model forbids. So the trim only ever touches a connection whose live-stream
count is zero, and that is pinned by a test that asserts both halves.

No new per-second polling, no new goroutine, no new timer: the pool is event-driven and its only
background work is the breaker's backoff wait, which respects the dial context.

## 5. Build tags

| Tag | Contents |
| --- | --- |
| `with_xhttp` | the whole XHTTP client transport, plus its registration into the v2ray client-transport registry |
| `with_xhttp` + `with_quic` | additionally the HTTP/3 connection and the uTLS→`crypto/tls` conversion QUIC needs |

Without `with_xhttp`, nothing registers and `type: xhttp` fails with the ordinary "unknown transport
type" — the code is not compiled in at all (verified: zero XHTTP symbols in the binary without the
tag, and the tag is not merely a runtime switch).

The tag **is** in the shipped compositions: the three `release/DEFAULT_BUILD_TAGS*` profile files and
the Apple tag set. That was a deliberate choice following this fork's build philosophy (the shipped
profiles carry every mainstream protocol), and it is asserted against the same
`ResolveBuildTags` function the builders and the provenance record use — not against the text of a
profile, which is the mistake the Phase-1 gVisor invariant exists to prevent.

## 6. Known unsupported or unverified combinations

Recorded here and in the report so nothing is implied by omission:

- `key_share: hybrid` with `firefox`/`safari`/`edge`/`ios`/`android`/`360`/`qq` — a clear error, by
  design. Full parity needs a uTLS fork; `DEFERRED`.
- `key_share: classical` against Xray ≥ v26.9.8 — the server rejects it. Documented as
  "Xray < v26.9.8 only"; it is an escape hatch for networks that drop the hybrid greeting, not a
  supported default.
- The XHTTP **server** and the VLESS encryption **server** — not implemented in this fork.
- No end-to-end client↔server interoperability test exists for the encryption handshake: only the
  client half is present, so a round trip cannot be constructed in-tree without reimplementing the
  server. The reference project's own record is the same, and narrower: only `native` + `0rtt` with an
  ML-KEM-768 key was ever exercised against a live Xray server there.
- No live-node verification of any of this in this environment. See the report's maturity matrix.
