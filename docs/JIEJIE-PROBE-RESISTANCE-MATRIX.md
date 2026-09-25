# Jiejie Server Edition — probe resistance matrix

## What this document claims, and what it does not

Two different things are routinely conflated. This project only claims the
first:

**ACTIVE PROBE RESISTANCE (claimed).** An unauthenticated or wrongly
authenticated probe does not reveal a *proxy authentication surface*. It is not
answered with `401`, `407`, `Proxy-Authenticate`, `WWW-Authenticate`, or any
other proxy-shaped challenge, and it does not get a protocol-specific error that
a plain web or TLS server would not produce. A probe is served plausible
behaviour instead.

**PROTOCOL FINGERPRINT ELIMINATION (NOT claimed).** This project does **not**
claim that the endpoint is unidentifiable as a proxy. HTTP/3 and MASQUE expose
protocol-level capabilities that are observable on the wire no matter what the
application does: QUIC itself, its SETTINGS frame, `H3_DATAGRAM`, and Extended
CONNECT (`connect-udp`). Transport parameters and connection behaviour are
visible as well. Anyone who tells you a MASQUE endpoint is indistinguishable
from a static website is wrong, and this document will not say it.

The practical summary: **"looks like a normal service" is prioritised over
"returns a special proxy error"**, but no claim is made that the endpoint is
unrecognisable at the protocol layer.

## Behaviour matrix

| Protocol | Valid auth | No auth | Wrong auth | Browser probe |
| --- | --- | --- | --- | --- |
| AnyTLS | tunnel | HTTP fallback to web backend | HTTP fallback to web backend | Web fallback |
| MASQUE H2 | tunnel | masquerade web decoy | masquerade web decoy | Web decoy * |
| MASQUE H3 | tunnel | masquerade web decoy | masquerade web decoy | Web decoy |
| ShadowTLS v3 | tunnel | relayed to the real TLS handshake target | relayed to the real TLS handshake target | TLS decoy |
| SS2022 | internal only | N/A | N/A | N/A |

\* **H2's `http/1.1` and no-ALPN boundary is NOT solved in sing-box.** The H2
inbound is HTTP/2-only, so a client that negotiates `http/1.1` or no ALPN at all
reaches an H2-only listener, which does not behave like an ordinary website. That
boundary belongs to Nginx Stream, which owns TCP/443, and is addressed by
[JIEJIE-NGINX-ALPN-HARDENING.md](JIEJIE-NGINX-ALPN-HARDENING.md). It is listed
here as a known limitation rather than presented as solved.

### Per-protocol detail

**AnyTLS.** A non-AnyTLS client, a wrong password, and an ordinary HTTPS request
all reach the configured native fallback backend and receive its normal
response. The fallback is a routing decision made after TLS termination, not an
error path. No `Proxy-Authenticate` or `WWW-Authenticate` is ever emitted, and
no proxy-shaped status code is returned. `fallback_for_alpn` routes by the
negotiated ALPN when configured.

*ALPN audit.* Production configures **no** ALPN on the AnyTLS inbound, so Go
negotiates no protocol. This was measured rather than assumed, for every
client-side offer: `["h2"]`, `["http/1.1"]`, `["h2","http/1.1"]` and no ALPN all
complete the handshake with an empty negotiated protocol and are all served a
normal `HTTP/1.1 200 OK` by the fallback backend. The conclusion is that pinning
an ALPN on this inbound would change nothing observable for a fallback client,
while risking legitimate AnyTLS clients, so **no ALPN change is made**. The
measurement is pinned by `TestJiejieAnyTLSALPNMatrix` so a future change has to
confront it instead of asserting an improvement.

**MASQUE H2.** GET and CONNECT with no credentials and with wrong credentials are
served the masquerade web decoy. This includes CONNECT: an unauthenticated
CONNECT does not get a proxy error, it gets the decoy page. One case is recorded
honestly rather than rounded off: an unauthenticated **CONNECT-UDP** (RFC 9298
extended CONNECT) is routed to the masquerade handler, but the decoy *origin* is
a plain HTTP site that refuses a CONNECT request, so the reverse proxy answers a
bare empty `502`. That `502` is the backend's answer, contains no proxy detail
and no challenge header, and is a status any web server could produce -- but it
is a distinguishable response, so it is documented, asserted exactly as it
behaves, and not described as "the decoy page".

**MASQUE H3.** Same as H2 for GET, CONNECT and CONNECT-UDP. The HTTP/3 path is
reached directly on UDP/443 and is not behind Nginx. Protocol-level
observability (QUIC, SETTINGS, `H3_DATAGRAM`, Extended CONNECT) remains.

**ShadowTLS v3.** An unauthenticated or plain-TLS client is **relayed verbatim to
the real handshake target**, so the prober completes a genuine TLS session with
that target and sees its certificate and HTTP response. This is the strongest
disguise in the stack, because from the prober's point of view it is talking to
the target, not to sing-box. The configured target is the public decoy
(`www.intel.com` in production); tests use a local decoy origin so they do not
depend on the internet. `strict_mode` additionally requires the handshake target
to negotiate TLS 1.3.

**SS2022.** Never exposed publicly. It listens on loopback only and is reached
solely through the ShadowTLS detour. There is no public SS2022 surface to probe,
so the matrix cell is N/A rather than "decoy".

## Resource bounds

These bound what an unauthenticated peer can consume. They are the reason probe
resistance does not become a denial-of-service vector.

| Bound | Value (production `jiejie-balanced-1g`) | Mechanism |
| --- | --- | --- |
| Request header size | 64 KiB | `max_header_bytes`; enforced by HTTP/2 and by HTTP/3 at both the frame and decoded-field-section level |
| Unauthenticated request body | 256 KiB | `maxUnauthenticatedBodyBytes`, `http.MaxBytesReader` on the masquerade path |
| Failed-auth requests/second | 10 | per-IP token bucket |
| Failed-auth burst | 20 | token bucket capacity |
| Failed-auth concurrency | 8 in flight per IP | per-IP counter, held for the whole backend request |
| Tracked IPs | 4096 | bounded map; new sources fail closed at the cap |
| H3 application idle timeout | 60s | `http3.Server.IdleTimeout`; armed at connection creation, stopped while a request stream is open, reset when the last stream closes |
| H3 QUIC transport idle timeout | 60s | `quic.Config.MaxIdleTimeout` |
| H2 stream cap | 256 per connection | `max_concurrent_streams`, applied to `http2.Server.MaxConcurrentStreams` |
| H3 stream cap | **NOT BOUNDED** | the QUIC layer's `MaxIncomingStreams` is set to `1 << 60` when unset, which is quic-go's internal "effectively unlimited" clamp. `max_concurrent_streams` does **not** apply to HTTP/3 |
| 0-RTT | disabled | `quic.Config.Allow0RTT = false` on the proxy inbound |
| H3 connection-count cap | **NOT IMPLEMENTED** | see below |

> **The H3 stream cap row was previously wrong.** It claimed "256 per connection"
> via `max_concurrent_streams`, but that option is only ever assigned to
> `http2.Server.MaxConcurrentStreams` (`transport/http/server.go`). The HTTP/3
> listener's stream limit is a QUIC transport parameter set in
> `transport/http/server_h3.go`, which forces `1 << 60` when the option is unset.
> So H2 is bounded at 256 and H3 is effectively unbounded. This is recorded rather
> than changed: aligning the H3 value is a behaviour change that needs its own
> measurement, in the same way the Native Naive listener's value was measured
> before it was removed (see `docs/JIEJIE-NAIVE-H3-AUDIT.md`).

### The H3 connection-count gap

Neither `max_concurrent_streams` (which is HTTP/2-only) nor the unauthenticated
limiter (which counts HTTP requests) bounds the **number of
established connections**, and the H3 stream limit is effectively unbounded, so
there is no per-source cap on how many QUIC connections or streams a peer may
hold open.

The `http3.Server.IdleTimeout` fix closes the most obvious exploit of that gap: a
connection that completes the QUIC handshake and then never opens a request
stream is now reclaimed, and PING traffic does not keep it alive. That is a real
bound and is covered by tests.

What is **not** implemented is an admission cap on concurrent connections per
source. Doing it properly would mean hooking quic-go's connection acceptance
(`http3.Server.ConnContext`), and the honest position is that no measured basis
exists for choosing a number. Inventing a limit of 128, 256 or 1024 without
measurement would risk breaking legitimate NAT'd users or long-lived CONNECT
tunnels in exchange for an unquantified improvement. It is therefore recorded as
NOT IMPLEMENTED rather than guessed at. See `JIEJIE-FIELD-MATRIX.md`.

## Where the front door ends and sing-box begins

- **TCP/443** is owned by Nginx Stream. Everything about SNI routing, and the
  ALPN boundary described above, lives there and is an operator hardening step,
  not a code change in this repository.
- **UDP/443** is owned by sing-box (MASQUE HTTP/3) and is directly exposed.
- **All protocol backends** (AnyTLS `28436`, MASQUE H2 `28440`, ShadowTLS
  `8554`, SS2022 `17414`, masquerade backend `28437`) are loopback-only.

## How to reproduce this matrix

```sh
TAGS=$(cat release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL)

# Probe behaviour, HTTP/2 and HTTP/3 matrices
(cd test && go test -tags "$TAGS" -run 'TestJiejieMASQUE.*ProbeMatrix' ./jiejie/)

# AnyTLS fallback, ALPN behaviour and the one-shot post-TLS read bound
(cd test && go test -tags "$TAGS" -run 'TestJiejieAnyTLS' ./jiejie/)

# ShadowTLS probe fallback against a local decoy
(cd test && go test -tags "$TAGS" -run 'TestJiejieShadowTLS|TestJiejieSS2022' ./jiejie/)

# Resource bounds
go test -tags "$TAGS" -run 'TestUnauthenticatedLimiter|TestLimiterRelease' ./transport/http/
go test -tags "$TAGS" -run 'TestH3HeaderLimit|TestH3.*IdleTimeout' ./transport/http/
```
