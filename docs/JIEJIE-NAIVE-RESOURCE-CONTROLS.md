# Native Naive inbound: connection lifecycle and resource controls

This documents what actually bounds a Native Naive connection, at each stage, and
the opt-in controls added for the stages that were unbounded. Every claim here is
a measurement from `test/jiejie/jiejie_naive_conn_lifecycle_test.go`, which drives
a real inbound over a real socket — not an inference from reading the code.

That distinction earned its keep twice in this work; both corrections are recorded
below rather than quietly fixed.

## The lifecycle, stage by stage

```
accept TCP                    <- counting happens here when limits are configured
  |
TLS handshake                 <- tls.handshake_timeout, if set
  |
ALPN (h1 / h2)                <- negotiated per-transport view
  |
HTTP request parsing          <- server_limits.header_timeout, if set
  |
auth                          <- 407 on failure, immediately
  |
CONNECT target parsing
  |
ACL / SSRF / routing
  |
tunnel established            <- no deadline from this point
  |
active forwarding
  |
half-close / full close       <- releases the connection slot
```

| Stage | Bounded by default? | Mechanism | Measured |
|---|---|---|---|
| TLS handshake, peer stalls mid-handshake | yes, if configured | `tls.handshake_timeout` | closed in <15s at 3s |
| TLS handshake, peer completes then silent | **no** | — | open past 20s |
| HTTP/1 request headers incomplete | **no** | — | held across 4 keepalive rounds |
| HTTP/2 connection, no stream opened | **no** | — | open past 6s |
| Bad authentication | yes | 407 response | immediate |
| Authenticated idle tunnel | **no** (by design) | — | open past 5s |
| Masquerade (ordinary HTTPS) | n/a | decoy handler | served 200 |
| Connection count | **no** | — | 40 conns → 40 goroutines |

## Two corrections

**1. A previous round claimed the TLS handshake was bounded by `C.TCPTimeout`
(15s). It is not.** The mistake is subtle: two different functions are named
`ServerHandshake`.

- `sing-box/common/tls/server.go` falls back to `C.TCPTimeout` when
  `HandshakeTimeout() == 0`.
- `sing/common/tls/config.go` applies a deadline **only** when
  `HandshakeTimeout() > 0`.

The Naive listener is built with `aTLS.NewListener` from the **sing** package,
whose `LazyConn.Read` calls the second one with `context.Background()`. The Naive
TLS config never sets a handshake timeout, so nothing is applied. The earlier
claim cited a fallback living in a function this path never calls.

**2. `handshake_timeout` bounds less than it appears.** It covers a peer that
stalls *during* the handshake. A peer that *completes* the handshake and then goes
silent is not covered, because the deadline is cancelled once the handshake
succeeds. The first version of the test asserted the wider claim, failed, and was
corrected — the test now pins the property the option actually provides.

## What was added

`server_limits` on the Naive inbound, everything defaulting to disabled:

| Field | Bounds |
|---|---|
| `max_connections` | total concurrent connections (host exposure) |
| `max_connections_per_ip` | concurrent connections from one source |
| `header_timeout` | the request phase |
| `max_tracked_ips` | the limiter's own map |

An omitted or zero value preserves the previous behaviour exactly. No default
limit is applied: the production topology serves long-lived tunnels, and a limit
chosen without measuring that deployment's concurrency would be a guess that
silently breaks traffic.

### Why counting happens at accept

The cheapest attack is a peer that completes TLS and never sends a request — the
measured 20s case. Such a peer never reaches `ServeHTTP`, so a limiter on the
request path would never see it. The slot is therefore taken in `Accept` and
released from the connection's `Close`, which fires exactly once however the
connection ends, including on a handshake failure.

Wrapping outside the TLS layer is what makes this cover both "never completes the
handshake" and "never sends a request".

### Why `header_timeout` uses `ReadHeaderTimeout`

Net/http's own knob, not a hand-rolled wrapper. In its own words, "the
connection's read deadline is reset after reading the headers" — precisely the
required shape: a peer that stalls mid-header is disconnected, while an
established tunnel keeps no deadline at all.

The first draft wrapped the conn and cleared the deadline on the first `Read`. A
slow-header peer defeats that by sending a single byte: the `Read` completes, the
deadline is dropped, the attack proceeds. Only the HTTP parser knows when the
header block is complete.

### Why there is no `handshake_timeout` or `idle_timeout` here

Both would duplicate an existing control:

- `tls.handshake_timeout` already exists and is verified to work.
- `HTTP2Options.IdleTimeout` already exists and is wired to
  `http2.Server.IdleTimeout`.

Two overlapping controls that can disagree are worse than one, and a duplicate
that is never read is worse still. `server_limits.idle_timeout` was written in
the first pass, resolved into a struct, and **never applied** — dead
configuration that looks functional. It was removed rather than left in.

### Per-IP keying

The key is the real transport peer (`conn.RemoteAddr`). Forwarded headers are
never consulted: a client that can name its own source address makes a per-IP
limit decorative. IPv4-mapped IPv6 addresses are unmapped, so `::ffff:1.2.3.4`
and `1.2.3.4` share one budget instead of granting a host twice its allowance.

## Not killing legitimate traffic

The property with the most risk. A Naive tunnel carries a browsing session, which
is legitimately silent for minutes between requests, so a request-phase timeout
that leaked into the tunnel phase would disconnect healthy users.

Two tests pin both sides:

- `TestAuditNaiveActiveTransferSurvivesHeaderTimeout` — a tunnel idle for longer
  than `header_timeout` still carries a full request/response afterwards.
- `TestAuditNaiveSlowButActiveTransferIsNotTreatedAsAbuse` — a valid CONNECT sent
  one byte at a time, with pauses but always progressing, is served. A peer that
  stalls is cut off; a peer that progresses is not.

## Resource accounting

Measured, not asserted:

```
40 idle TLS connections      -> goroutines  9 -> 49  (delta 40)
after close                  -> goroutines 49 ->  9  (delta 0)
40 stalled-header connections-> goroutines  9 -> 49  (delta 40)
close                        -> returns to baseline
```

No goroutine leak. Each held connection costs exactly one server-side goroutine,
and closing it returns the process to baseline.

## Mutation evidence

Five mutations were applied to confirm the tests can fail:

| Mutation | Caught by |
|---|---|
| release disabled | release-idempotence, listener tests |
| per-IP check disabled | per-IP and IPv4-mapped tests |
| IPv4-mapped unmap skipped | IPv4-mapped sharing test |
| `ReadHeaderTimeout` disabled | header-timeout behavioural test |
| accept-time wrapper removed | global and per-IP behavioural tests |

The last one **initially was not caught**, and that is worth recording. The
behavioural tests used a bare `require.Error` on `Read`, which passes both when a
connection is *closed* (refused) and when it is *still open but silent* (accepted,
then timed out). They now use the EOF-versus-timeout distinction the file's helper
already provided. A test that cannot tell refusal from acceptance is not testing
the limit.

## Default behaviour

Unchanged. `protocol/naive/inbound.go` gained 41 lines and **lost none** — the
existing code paths are byte-for-byte what they were. An inbound without
`server_limits` builds no limiter, installs no wrapper, and sets no header
timeout.

## NOT TESTED

- Any real remote-network effect: throughput, latency, CPU or RSS under load.
- Behaviour under a genuinely distributed source (the per-IP limit was exercised
  from a single loopback address, including its IPv4-mapped form).
- The production topology was deliberately not given a limit: choosing one needs
  a measurement of that deployment's real concurrency, which this environment
  cannot produce.
