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
| `DisablePathManager` | unset (false) | `true` | **RETAINED-DIFF / UNVERIFIED** |
| Congestion control | quic-go default (CUBIC) | **BBR** default | **RETAINED-PERFORMANCE-DIFF** |
| `IdleTimeout` | from Caddy server config | library default | **DIFF / NOT-MEASURED** |
| `MaxHeaderBytes` | from Caddy server config | unset/default | **DIFF / NOT-MEASURED** |
| Receive windows | unset/default | unset/default | **PASS** |
| QUIC versions | explicit v1, v2 | library default v1, v2 | **DEPENDENCY-EQUIVALENT** |
| H3 SETTINGS frame | library generated | library generated | **NOT-VERIFIED** |
| Connection migration | enabled (default) | disabled | **NOT-VERIFIED** |

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

## 3. The two retained differences

Neither is called "parity", and neither is called intentional in the strong sense
(source + runtime + product decision). Both rest on source evidence and an
explicit product decision, with **no runtime measurement**.

**`DisablePathManager: true`** - a client that changes its network path (for
example Wi-Fi to cellular) will not have its connection migrated; it must
reconnect. Caddy leaves the path manager on. The current product choice is to
retain this. **Migration behaviour has not been measured**, so this is recorded as
retained and unverified, not as a verified intentional difference.

**BBR congestion control** - kept as an explicit performance choice. There is **no
controlled BBR-vs-CUBIC benchmark** (RTT and loss held constant) in this audit, so
this is a retained performance difference **by policy, not benchmark-validated**.
It is not claimed to be the more correct choice, only the current one.

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
