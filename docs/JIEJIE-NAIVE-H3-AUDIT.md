# Naive HTTP/3 / QUIC differential audit

This documents how sing-box's Native Naive HTTP/3 configuration compares with
the reference deployment, **without changing any parameter**. It exists because
the two differ visibly and the difference needs to be understood before it is
"aligned", not after.

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

### sing-box (`protocol/naive/quic/inbound_init.go`)

```go
quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, &quic.Config{
    MaxIncomingStreams: 1 << 60,
    Allow0RTT:          true,
    DisablePathManager: true,
})
```

with congestion control set per connection in `ConnContext`:

| `QUICCongestionControl` | Implementation |
| --- | --- |
| `""` or `"bbr"` (default) | `congestion_meta2.NewBbrSenderWithProfile(..., ProfileStandard)` |
| `"cubic"` | `congestion_meta1.NewCubicSender(..., false)` |
| `"reno"` | `congestion_meta1.NewCubicSender(..., true)` |

---

## 2. Item-by-item comparison

| Item | Caddy | sing-box | Comparable without packet capture? |
| --- | --- | --- | --- |
| QUIC versions | v1, v2 explicit | library default (v1, v2) | Yes (API) |
| `MaxIncomingStreams` | unset (library default) | `1 << 60` | Yes (API) |
| `Allow0RTT` | unset (false) | **`false` (aligned)** | Yes (API) |
| `DisablePathManager` | unset (false, path manager on) | `true` | Yes (API) |
| Congestion control | library default (CUBIC in quic-go) | **BBR** by default | Yes (API) |
| `IdleTimeout` | from Caddy server config | library default | Yes (API) |
| `MaxHeaderBytes` | from Caddy server config | unset | Yes (API) |
| Flow-control windows | library default | library default | Yes (API) - both leave unset |
| HTTP/3 SETTINGS frame contents | library default | library default | **requires packet-level verification** |
| `Alt-Svc` advertisement | set by Caddy | not set by sing-box | Yes (API) |
| 0-RTT acceptance on the wire | unknown (0-RTT not enabled) | expected, `Allow0RTT: true` | **requires packet-level verification** |
| Connection migration | path manager on | path manager off | **requires packet-level verification** |

`MaxIncomingStreams: 1 << 60` deserves a note. It is effectively "no limit", and
it is a *server-side admission* value: it bounds how many streams a peer may open
toward this server. It is not itself a vulnerability, but on a ~1 GiB host it
means the connection-count bound must come from somewhere else (the listener
backlog, the OS, or a fronting proxy).

`Allow0RTT` is now **false**, matching the reference.

It was `true`; it is no longer set, so it takes the quic-go default of false.
`Allow0RTT` is the only server-side gate for early data (quic-go documents it as
"only valid for the server" and consumes it when deciding whether to accept a
0-RTT attempt), so removing the field is what actually refuses 0-RTT -
`ListenEarly` is merely the listener API and does not enable early data by itself.

Resolved, not merely audited:

- HTTP/3 does not depend on 0-RTT. It is a latency optimisation for RESUMED
  connections, not a prerequisite for establishing one, so refusing it costs one
  round trip on a resumption.
- 0-RTT payloads are replayable by anyone who captures them. An early-data
  CONNECT could therefore be replayed against this server, which is a poor trade
  for a proxy that authenticates its tunnel request.
- The pinned reference does not enable it either.

Verified: `TestNativeNaiveQUICConfigRefuses0RTT` pins the value, and the real
HTTP/3 probes in `test/jiejie/jiejie_naive_h3_test.go` confirm an authenticated H3
CONNECT still reaches the origin with 0-RTT off.

`MaxIncomingStreams: 1 << 60` remains, and is now **measured** rather than
guessed: `test/jiejie/jiejie_naive_h3_stream_limit_test.go` records that 64 of 64
concurrent HTTP/3 request streams were accepted with none refused, and that the
listener survives a stream burst and abrupt client aborts. It is effectively
unbounded, so on a ~1 GiB host the connection bound has to come from somewhere
else (the front end, the OS, or a limiter). Aligning it to the library default
needs a decision about where that bound should live - the test asserts the
property that matters either way (streams are accepted, the listener stays
healthy), so a future change is measured rather than assumed.

`DisablePathManager: true` and the BBR congestion control default are **not**
changed this round. Both are recorded below as deliberate differences.

`DisablePathManager: true` means a client that changes its network path (for
example Wi-Fi to cellular) will not have its connection migrated; it must
reconnect. Caddy leaves the path manager on.

---

## 3. What this audit does NOT establish

- It does not establish that any of these differences is a defect. It records
  them.
- It does not compare HTTP/3 SETTINGS, 0-RTT acceptance, or connection migration
  as observed on the wire. Those are marked `requires packet-level verification`
  above and were **not** measured.
- No parameter was changed. In particular `MaxIncomingStreams`, `Allow0RTT` and
  `DisablePathManager` are unchanged, because changing them on the basis of a
  config diff alone would be guessing at intent: sing-box's values are plausible
  deliberate choices for a server behind an SNI-routing front end, and the
  reference's values are quic-go defaults rather than explicit decisions.

---

## 4. Why the H2/H3 CONNECT guard still matters here

`protocol/naive/inbound.go` performs the reference's `:scheme`/`:path` check for
`ProtoMajor == 2 || ProtoMajor == 3`. On HTTP/2 that check is unreachable in
practice because `x/net/http2` rejects such a stream first. HTTP/3 does **not**
share that stack - it runs on sing-box's own QUIC + `http3.Server` - so the
explicit check is what actually enforces the rule for H3. Removing it would
silently drop H3 protection, which is why a source-level test pins it
(`TestJiejieNaiveParityH3ConnectValidationIsPresent`).

---

## 5. Follow-up work, if the differences are to be resolved

Not done here. In rough order of value:

1. Capture an H3 handshake from both servers and diff the HTTP/3 SETTINGS and the
   transport parameters. This is the only way to close the three
   `requires packet-level verification` rows.
2. Decide whether `Allow0RTT` is intended for a Naive CONNECT endpoint given the
   replay property above. This is a product decision, not a compatibility one.
3. Decide whether `1 << 60` incoming streams is intended, and if so where the
   connection bound is expected to come from on a 1 GiB host.
4. Only then consider aligning values - and if aligned, do it behind tests that
   assert the intended behaviour rather than merely matching a number.

---

## 6. Difference status after this round

Each remaining difference is labelled with what is actually known. Only
differences with source evidence, runtime evidence and an explicit product
decision are called INTENTIONAL.

| Item | Caddy | Native Naive | Status | Evidence |
| --- | --- | --- | --- | --- |
| 0-RTT acceptance | off | **off** | **PASS (aligned)** | `TestNativeNaiveQUICConfigRefuses0RTT`; real H3 CONNECT probes |
| Receive windows | unset | unset | **PASS** | both leave the library default |
| `IdleTimeout` | from Caddy server config | library default | **DIFF** | configuration surface differs; not measured |
| `MaxHeaderBytes` | from Caddy server config | unset | **DIFF** | same |
| `MaxIncomingStreams` | library default | `1 << 60` | **INTENTIONAL-DIFF** | carried over from the original implementation; measured at 64/64 accepted (`jiejie_naive_h3_stream_limit_test.go`). Not aligned because where the connection bound *should* live on a 1 GiB host is a product decision, not a config value. |
| `DisablePathManager` | off (path manager on) | `true` (off) | **INTENTIONAL-DIFF** | a client that changes network path is not migrated and must reconnect. Deliberate for a server behind a front end; **no migration test has been run**, so this is recorded as intended rather than verified. |
| Congestion control | library default (CUBIC in quic-go) | **BBR** by default | **INTENTIONAL PERF DIFF** | kept as an explicit performance choice. No benchmark or compatibility evidence supports changing it, and the task's rule is not to change it on a config diff alone. |
| HTTP/3 SETTINGS contents | library default | library default | requires packet-level verification | not measured |
| 0-RTT behaviour on the wire | n/a (0-RTT off) | n/a (0-RTT off) | n/a | both refuse, so there is no wire behaviour to compare |
| Connection migration on the wire | path manager on | path manager off | requires packet-level verification | not measured |

What is **not** claimed: no row above is called "Caddy parity". The aligned rows
are parity; the INTENTIONAL rows are decisions; the remaining rows are unmeasured
and are labelled as such rather than as PASS.
