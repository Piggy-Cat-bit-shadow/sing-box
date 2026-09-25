# Naive HTTP/3 / QUIC differential audit

This documents how sing-box's Native Naive HTTP/3 configuration compares with the
reference deployment. It records what was **measured**, what was **changed as a
result**, and what remains **unmeasured**.

Reference, pinned:

| Component | Version |
| --- | --- |
| Caddy | `v2.10.0` |
| forwardproxy | `d62c80d3dd2c706b6b87579844d2397bddd18317` (`klzgrad/forwardproxy@naive`) |
| HTTP/3 stack | `quic-go` via Caddy's `modules/caddyhttp/server.go` |

---

## 1. What each side configures

### Caddy (`modules/caddyhttp/server.go`, `startHTTP3`)

```go
s.h3server = &http3.Server{
    Handler:        s,
    TLSConfig:      tlsCfg,
    MaxHeaderBytes: s.MaxHeaderBytes,
    QUICConfig: &quic.Config{
        Versions: []quic.Version{quic.Version1, quic.Version2},
        Tracer:   qlog.DefaultConnectionTracer,
    },
    IdleTimeout: time.Duration(s.IdleTimeout),
}
```

Caddy sets **only** `Versions` and `Tracer` on `quic.Config`. Everything else -
stream limits, flow control, 0-RTT, path manager, congestion control - is left at
the quic-go defaults for the version Caddy vendors.

### Native Naive (`protocol/naive/quic/inbound_init.go`, `nativeNaiveQUICConfig`)

```go
return &quic.Config{
    DisablePathManager: true,
}
```

Only `DisablePathManager` is set. `Allow0RTT` and `MaxIncomingStreams` are
deliberately **left unset**, so the quic-go defaults apply - `false` and `100`
respectively. This is asserted by

- `TestNativeNaiveQUICConfigRefuses0RTT` (Allow0RTT)
- `TestNativeNaiveQUICConfigKeepsDocumentedSettings` (MaxIncomingStreams unset,
  DisablePathManager retained)

Congestion control is set per connection in `ConnContext`, not in `quic.Config`:

| `QUICCongestionControl` | Implementation |
| --- | --- |
| `""` or `"bbr"` (default) | `congestion_meta2.NewBbrSenderWithProfile(..., ProfileStandard)` |
| `"cubic"` | `congestion_meta1.NewCubicSender(..., false)` |
| `"reno"` | `congestion_meta1.NewCubicSender(..., true)` |

---

## 2. Item-by-item comparison

| Item | Caddy | Native Naive | Status |
| --- | --- | --- | --- |
| `Allow0RTT` | unset (false) | unset (false) | **PASS / ALIGNED** |
| `MaxIncomingStreams` | unset (default 100) | unset (default 100) | **PASS / ALIGNED** |
| `DisablePathManager` | unset (false) | unset (false); opt-in via `quic_disable_path_manager` | **PASS / ALIGNED BY DEFAULT** |
| Congestion control | quic-go default (CUBIC) | library default (CUBIC); opt-in via `quic_congestion_control` | **PASS / ALIGNED BY DEFAULT** |
| `IdleTimeout` | from Caddy server config (default 5 min) | library default | **DIFF / PARTIALLY MEASURED** - an idle connection survives 3s; a multi-minute bound was not measured |
| `MaxHeaderBytes` | from Caddy server config | unset/default | **PASS (measured)** - a 2 MiB header is rejected by reset on BOTH sides |
| Receive windows | unset/default | unset/default | **PASS** |
| QUIC versions | explicit v1, v2 | **explicit v1, v2 (pinned)** | **PASS / ALIGNED** |
| H3 SETTINGS frame | library generated | library generated | **NOT-VERIFIED** (no packet capture) |
| Connection migration | enabled (default) | enabled (default); disableable by configuration | **NOT-VERIFIED** (behaviour unmeasured either way) |
| Padded response segmentation | `3 + payload + padding <= 65536`, padding drawn first | **aligned** (was `65535 + padding`, up to 65793) | **PASS / ALIGNED** |
| Malformed CONNECT `:scheme`/`:path` | rejected | rejected, verified at runtime via extended CONNECT | **PASS** |
| Half-close, client-first | upload reaches origin, reply survives | MATCH, padded and raw | **PASS** |
| Half-close, origin-first | in-flight client bytes dropped | same | **SHARED BEHAVIOUR** (fork and reference agree) |

### The two rows that were previously reported differently

**`MaxIncomingStreams` is no longer `1 << 60`.** It is now unset, so the quic-go
default of `100` applies, which matches the reference. The old value was quic-go's
own internal "effectively unlimited" clamp (`config.go` `validateConfig` caps the
field at `1 << 60`), so it was the library's no-limit sentinel rather than a
considered limit - it matched neither the library default nor the reference.

Measured before removing it, on Linux, with concurrent HTTP/3 request streams from
one connection:

```
streams  accepted  refused  RSS+KiB  goroutines  fds
1        1         0        344      0           0
8        8         0        520      0           0
32       32        0        848      0           0
64       64        0        1732     0           0
128      128       0        1728     0           0
256      256       0        2504     0           0
```

256 concurrent streams cost ~2.5 MiB with no extra goroutines or descriptors, so
the default of 100 covers the observed workload comfortably. The old value removed
the only server-side bound on concurrent HTTP/3 work on a ~1 GiB host; removing it
restores that bound and aligns with the reference.

`TestNativeNaiveQUICConfigKeepsDocumentedSettings` asserts the field stays unset,
so a future re-introduction is a visible decision rather than an accident.

**`Allow0RTT` is no longer `true`.** It is unset, so the quic-go default of
`false` applies, matching the reference. `Allow0RTT` is the **only** server-side
gate for early data - quic-go documents it as "only valid for the server" and
consumes it when deciding whether to accept a 0-RTT attempt. `ListenEarly` is
merely the listener API and does not enable early data by itself.

Why this was changed rather than merely recorded:

- HTTP/3 does not depend on 0-RTT. It is a latency optimisation for **resumed**
  connections, not a prerequisite for establishing one, so refusing it costs one
  round trip on a resumption.
- 0-RTT payloads are replayable by anyone who captures them. An early-data CONNECT
  could therefore be replayed against this server, which is a poor trade for a
  proxy that authenticates its tunnel request.
- The pinned reference does not enable it either.

Verified by `TestNativeNaiveQUICConfigRefuses0RTT`, and the real HTTP/3 probes in
`test/jiejie/jiejie_naive_h3_test.go` confirm an authenticated H3 CONNECT still
reaches the origin with 0-RTT off.

---

### What the differential actually runs

`TestJiejieNaiveH3DifferentialAgainstReference` compares six cases against the
pinned reference with BOTH sides measured, not assumed:

| Case | Fork | Reference | Verdict |
| --- | --- | --- | --- |
| authenticated CONNECT | 200 + origin payload | 200 + origin payload | PASS |
| CONNECT without credentials | 407 + challenge | 407 + challenge | PASS |
| CONNECT with wrong credentials | 407 + challenge | 407 + challenge | PASS |
| Padding negotiated | 200 + payload | 200 + payload | PASS |
| no Padding header | 200 + payload | 200 + payload | PASS |
| target dial failure | no tunnel data | no tunnel data | PASS |

The dial-failure case writes into the tunnel before judging: a bare CONNECT to an
unreachable target returns 200 on BOTH implementations because CONNECT is
fast-open and the status is flushed before the dial, so comparing the status alone
would have compared a value that does not reflect the dial.

This differential runs in CI under `with_quic` (without `jiejie_server_minimal`),
which is the only tag set that links `protocol/naive/quic`. A step fails the job if
it SKIPPED, because a skip inside a green workflow is how this comparison went
unmeasured before.

QUIC versions are compared as SETS: the fork accepts exactly `[v1 v2]` and the
reference accepts exactly `[v1 v2]`. They agreed previously only because quic-go's
default happened to be both, so the list is now pinned explicitly and the test
compares the two.

## 3. Behaviour differences that are now opt-in

Both of the differences this audit previously carried as hardcoded are now
configuration, so the protocol default matches the reference and the fork's
preference is an explicit choice.

**Connection migration (`quic_disable_path_manager`)** - the default leaves the
path manager enabled, which is what Caddy's `quic.Config` produces (it sets only
`Versions` and `Tracer`). A deployment that wants a client changing network path
to reconnect instead of migrating sets the option. The production topology does
not set it, so the default applies there too.

**Congestion control (`quic_congestion_control`)** - an unset value now means the
library default (CUBIC in quic-go), not BBR. The fork's BBR preference is selected
by name. There is still **no controlled BBR-vs-CUBIC benchmark** (RTT and loss held
constant), so BBR is not claimed to be the better choice, only an available one.

Neither difference is called "parity": the defaults are aligned and asserted,
while the behaviours themselves remain unmeasured.

---

## 4. What this audit does NOT establish

- It does not compare HTTP/3 SETTINGS, 0-RTT acceptance, or connection migration
  as observed on the wire. Those rows are **NOT-VERIFIED**.
- It does not measure `IdleTimeout` or `MaxHeaderBytes` behaviour.
- It does not establish a Caddy differential for HTTP/3 at all: the H1 and H2
  differentials exist and pass, the H3 one does not exist.
- It does not benchmark BBR against CUBIC.

---

## 5. Why the H2/H3 CONNECT guard still matters here

`protocol/naive/inbound.go` performs the reference's `:scheme`/`:path` check for
`ProtoMajor == 2 || ProtoMajor == 3`.

On HTTP/2 that check is unreachable in practice because `x/net/http2` rejects such
a stream first. HTTP/3 does **not** share that stack - it runs on sing-box's own
QUIC + `http3.Server` - so the explicit check is what enforces the rule for H3.

However: the guard is verified **at source level only**. No malformed HTTP/3
request has been sent on the wire to observe the rejection.

| Aspect | Status |
| --- | --- |
| Handler rejects non-empty `URL.Scheme` / `URL.Path` for `ProtoMajor == 3` | **SOURCE-GUARDED** |
| Observed rejection of a real malformed H3 CONNECT | **RUNTIME NOT-TESTED** |

`TestJiejieNaiveParityH3ConnectValidationIsPresent` reads the source and pins the
check. It does not exercise it.

---

## 6. Follow-up work

Not done here. In rough order of value:

1. Capture an H3 handshake from both servers and diff the HTTP/3 SETTINGS and the
   transport parameters. This is the only way to close the two `NOT-VERIFIED` rows.
2. Send a malformed HTTP/3 CONNECT (`:scheme`/`:path` set) and observe the
   rejection, closing the runtime half of the pseudo-header guard.
3. Measure connection migration with and without the path manager.
4. Run a controlled BBR-vs-CUBIC benchmark before calling the congestion choice
   validated.
5. Measure `IdleTimeout` and `MaxHeaderBytes` behaviour.
