# Native Naive

The current Native Naive implementation in this fork, and the boundaries around it. Design
decisions that must not be changed casually are in [engineering notes](ENGINEERING-NOTES.md).

## Scope

### Server inbound

`protocol/naive` implements a NaiveProxy **server inbound**, registered in the minimal server
registry as a production protocol rather than a compatibility layer. It runs a real HTTP server
behind TLS and serves HTTP/1.1, HTTP/2 and HTTP/3.

### macOS Cronet outbound

The macOS client's `naive` outbound is a separate implementation backed by the fork's `cronet-go`.
The server does not link the Cronet stack, and `with_naive_outbound` selects the client outbound
only. See the [macOS client document](JIEJIE-MACOS-CLIENT.md).

### Reference implementation boundary

The two custom codecs are independent: the server inbound lives in `protocol/naive` and the client
outbound in `cronet-go`. Server codec tests passing does not prove the client is correct, and the two
custom implementations agreeing with each other does not substitute for comparison with the
reference. Machine-readable padding vectors shared across both repositories are in
[`test/jiejie/reference/naive_padding_vectors.json`](../test/jiejie/reference/naive_padding_vectors.json).

## Server topology

The inbound terminates TLS itself and then serves the proxy protocol on the decrypted stream. It
does not depend on Cronet, on the client registry, or on a Naive outbound being present.

Production places it on loopback behind the TCP front door, alongside the MASQUE HTTP/2 inbound,
AnyTLS and ShadowTLS. See the [server document](JIEJIE-SERVER.md).

## Authentication and CONNECT

Users authenticate with the configured credentials. An authenticated CONNECT establishes the tunnel;
authentication failure and unauthenticated traffic are handled by the masquerade path when one is
configured.

## UoT v1/v2

Both UoT versions are supported through the inbound. An authenticated CONNECT to a magic address
selects the UoT decoder — `sp.v2.udp-over-tcp.arpa` for v2 and `sp.udp-over-tcp.arpa` for v1. The
magic address is never a real destination.

The distinction that matters for the security boundary below is how each carries its destination:

- **v2 Connect mode** — the session header carries a fixed destination, checked when the session is
  established.
- **v1 and v2 non-Connect mode** — the address in the session header is only a **session
  identifier**. Every subsequent datagram carries **its own** destination, which is what lets one v1
  session address several targets.

Two address encodings coexist and must not be mixed: the v2 request header uses the SOCKS5
serializer, while per-datagram addresses use the UoT address parser. Confusing them yields
`unknown address family: 0`. The v2 request header travels *inside* the tunnel, so when padding was
negotiated it must itself be wrapped in a padding frame.

Unpacked datagrams are handed to the router as a packet connection with the authenticated username
preserved, so ordinary routing, DNS, outbound selection and access control all apply. A stock
NaiveProxy client interoperates for TCP only; UoT is a separate extension it does not use.

A previous conclusion that v2 non-Connect was a P0 product defect was a test-fixture error, not a
product bug. The transport matrix is pinned by
[`jiejie_naive_uot_transport_matrix_test.go`](../test/jiejie/jiejie_naive_uot_transport_matrix_test.go).

## Padding / framing

Padding is extracted **first**, then the frame's payload budget is computed:

```text
padding first
payload_budget = 65536 - 3 - padding
3 + payload + padding <= 65536
writerMTU = 65278, front headroom = 3, rear headroom = 255
```

- Framing is enabled **solely** by the request `Padding` header: a CONNECT without it is a valid
  plain HTTP proxy request and gets byte-for-byte I/O. The *response* `Padding` header is sent for
  every authenticated CONNECT regardless, which is an independent concern.
- Frame layout is `[2-byte big-endian data size][1-byte padding size][data][zero padding]`. Both
  sizes have fixed widths, so a hostile frame cannot drive a large allocation.
- Padding applies to the first 8 frames in each direction, then is dropped entirely.
- In-place framing is skipped above `maxFrameSize - 3 - 255`. The padding range 0..255 is
  deliberately never clamped to the buffer.
- A short write is a failure: a `Write` returning fewer bytes than requested with a nil error is
  reported as `io.ErrShortWrite`, and it is never silently truncated. The frame counter advances only
  after the whole frame was written, so server and peer framing cannot diverge.
- A frame carrying padding but no data is consumed and the read continues, so a zero-byte read with a
  nil error is never handed to the caller.
- Data-path failures return an error rather than panicking on a normal failure mode.
- HTTP/1 CONNECT payload is raw bytes: it is **not** framed even when a `Padding` request header is
  present. The header is consulted only on HTTP/2 and HTTP/3. On HTTP/2 the tunnel writer flushes
  through a response controller, and a failed flush is propagated as an error and tears the tunnel
  down rather than being silently discarded.

The write contract is pinned by
[`audit_write_contract_test.go`](../protocol/naive/audit_write_contract_test.go).

## Masquerade

`masquerade` serves requests that are **not** authenticated Naive proxy requests — ordinary browser
traffic, probes, and proxy attempts with no or wrong credentials. It uses the same schema and
semantics as the Hysteria2 and HTTP inbound masquerade, so a normal website can share the port.

- This is a **web response only**. It can never establish a proxy tunnel: the tunnel path requires
  successful authentication first, and the masquerade handler has no access to the proxy or UoT data
  paths.
- Unset means the upstream behaviour: a proxy authentication challenge or a bad-request status.
- It does not make the service undetectable.

## Connection lifecycle and resource controls

`server_limits` bounds what a peer may hold **before** it authenticates. Every field is optional, and
**omitting the block means unlimited**, which is the previous behaviour: no limit is applied by
default because the production topology serves long-lived tunnels and a guessed limit would silently
break them.

| Field | Bounds |
| --- | --- |
| `max_connections` | Total concurrent connections on the inbound, authenticated or not. This is the only bound covering the whole listener. |
| `max_connections_per_ip` | Concurrent connections from one source address. The key is the real transport peer, never a forwarded header: a client that can name its own source address would trivially evade a per-IP limit. |
| `header_timeout` | How long a connection may take to deliver a **complete** request once the handshake is done. Applies to the request phase only. |
| `max_tracked_ips` | Ceiling on tracked source addresses. |

The TLS handshake has **no timeout by default**: the listener applies a deadline only when
`tls.handshake_timeout` is set. `tls.handshake_timeout` covers a peer that stalls *during* the
handshake only — once the handshake succeeds the deadline is cancelled, so a peer that completes the
handshake and then goes silent is covered by `header_timeout` instead.

Two deliberate omissions:

- **No handshake timeout here.** The TLS options already provide `tls.handshake_timeout`, and adding
  a second control for the same phase would give an operator two overlapping fields that can
  disagree. Its scope is narrower than it looks: it covers a peer that stalls *during* the
  handshake, not one that completes the handshake and then goes silent — that case is
  `header_timeout`.
- **No idle timeout here.** `HTTP2Options.IdleTimeout` already provides one and is wired to
  `http2.Server.IdleTimeout`.

**An established tunnel is never subject to `header_timeout`.** A tunnel that is legitimately idle
for longer than the header timeout — which long-lived connections routinely are — must not be torn
down. The request-stage limits apply to the request stage.

`HTTP2Options` bounds the HTTP/2 server this inbound runs, with keys `max_concurrent_streams`,
`idle_timeout`, `stream_receive_window` and `connection_receive_window`. Leaving every field unset
keeps the upstream `net/http` and `x/net/http2` defaults. The receive windows are **server-side
admission windows**, not the client's: they bound how much a peer may have in flight toward this
server, which is the opposite of the client's useful direction. Values that would wrap when narrowed
are rejected.

Counting happens at **accept**, wrapping the outermost listener so it covers both a peer that never
completes the handshake and one that never sends a request. The slot is released exactly once,
however the connection ends, including a TLS handshake failure. The limiter's tracked-IP map is
bounded, swept on an amortized cadence, and **fails closed** at its cap rather than evicting a
tracked source.

Fields are documented in [Naive inbound](configuration/inbound/naive.md).

## Target ACL / SSRF boundary

The client chooses the proxy destination, so the destination must be constrained. The rule of
record: resolve the target, then check the resolved address, then dial exactly that address.

**Resolution must happen before the address check.** `actionResolve` writes its results into
`metadata.DestinationAddresses`, and the connection manager then dials each address in that list via
`DialContext` with an **already-resolved IP**, not the original domain. The outbound therefore does
not re-resolve, so the address that was checked is the address that is dialed. Without a `resolve`
action a domain target is reachable despite an IP-based deny rule, which is why `resolve` is
required rather than optional.

A DNS-rebinding test confirms this is not merely theoretical: a domain that first resolves to an
allowed address and then to loopback is rejected on the second resolution, with the query count
proving a genuine second lookup occurred
(`TestJiejieTargetACLRebindingCannotBypass`).

**Per-datagram destination guard for UoT.** For non-Connect UoT sessions each datagram carries its
own destination, so a session that passed the session-level check could otherwise send later
datagrams somewhere else entirely. `route/packet_destination_guard.go` re-applies the same routing
rules to **every** destination decoded from a datagram and drops rejected ones.

- It is enabled only for non-Connect UoT sessions (`metadata.UoTDatagramDestinations`); other
  protocols' UDP data paths are unaffected.
- It intercepts on the **read** side, because the write side has a batch fast path that cannot be
  guaranteed to see every packet. The read side is the only position that cannot be bypassed.
- Decisions are memoized per destination, so an allowed datagram costs a map lookup after the first.
- IPv4-mapped IPv6 is normalized to IPv4 first, so `::ffff:127.0.0.1` cannot smuggle a restricted
  destination past the rule.
- A rejected datagram is dropped without an error, so other datagrams in the same session are
  unaffected.
- When no rule matches, the guard **permits**. This matters because `common/uot/router.go` is shared
  by twelve protocol inbounds; in the production registry the affected protocols are `anytls` and
  `shadowsocks` (SS2022).

Existing tests show the check is discriminating rather than blanket: an allowed destination is
delivered and a loopback destination is not.

**Server-internal connections are out of scope for this ACL.** The target ACL constrains the
**client-chosen proxy target**; it must not break connections the server itself initiates. The Naive
and MASQUE web masquerade backends, the AnyTLS fallback backend, the local DNS resolver and the
ShadowTLS handshake target are established by server components that do not pass through the
sing-box Router, so inbound-scoped rules do not match them. A test pins this: in the same instance
where the rules genuinely reject loopback, the masquerade still reaches its loopback backend while a
client CONNECT to loopback is still refused.

### Why the deny list must include the host's own address

`<VPS_SELF_IP>:443` must stay permanently rejected. Production TCP/443 is held by Nginx, which
forwards by SNI into this inbound, so allowing a client to re-CONNECT the self address on 443
re-enters the same front door and forms a self-proxy recursion:
`Naive -> <VPS_SELF_IP>:443 -> Nginx -> Naive -> <VPS_SELF_IP>:443 -> ...`.

The CONNECT hostname and the TLS SNI inside the tunnel are **not bound** to each other, so "allow
self 443 for this one domain" is not a reliable recursion defence: a client can CONNECT an allowed
domain and then switch SNI inside the tunnel. Only pre-dial rewriting is robust.

### Self-hosted web: rewrite the target, do not open the public port

A self-hosted web zone resolves to the host's own public address and is therefore caught by the
self-address rule; the symptom is a client failing to reach its own site. The fix is **not** to open
`<VPS_SELF_IP>:443` but to rewrite the target to a loopback-only, web-only internal ingress, using
`override_address`/`override_port` on a `domain_suffix` rule scoped to `network: tcp` and
`port: [443]`. No UDP or UoT path is created.

`override_address` clears `metadata.DestinationAddresses`, so the dial target is the loopback
ingress and never the resolved public address. Even a client that CONNECTs a self-hosted domain and
then switches to an unrelated TLS SNI still terminates at the loopback ingress, so the recursion
path is *cut* rather than merely discouraged.

`domain_suffix` is raw suffix matching: write the bare suffix, not a `*.` prefix. Within one rule's
destination group, `domain`/`domain_suffix` and `ip_cidr` are OR rather than AND, so "only when this
domain resolves to the self address" cannot be expressed by combining them — the recommended form
uses no `ip_cidr` and avoids that trap.

The loopback ingress itself is VPS-side deployment state, not repository state. It must listen on
loopback only, serve only the self-hosted site, and must not proxy back to the public 443 or stream
to any proxy ingress.

### The CONNECT status code is not a rejection signal

The inbound returns `200 OK` when it accepts a CONNECT, and a router-level `reject` closes the
connection *afterwards*. A CONNECT to `127.0.0.1:443`, to the host's own address, or to a proxy entry
name all return `200 OK` and then transfer no data. **The status code must not be used to judge
whether a target was rejected**; a test must write into the tunnel and observe whether the origin
answers.

### Known limits

- **The host's own public address is not yet in the deny set.** A client CONNECT to it could still
  reach an administrative entry point that should only be reachable from specific sources. The
  repository has no trustworthy record of that address, so it was deliberately not guessed and no
  development-machine egress address was substituted. This item must not be marked complete until
  confirmed on the host.
- Suggested CIDR deny lists are not validated against a production environment; documentation-range
  entries and ranges such as CGNAT space must be confirmed against real traffic.
- The per-datagram guard does **not** re-route to a different outbound. Its verdict is permit/deny
  only; a rule that would select a different outbound based on the per-datagram destination does not
  take effect, and the datagram still uses the outbound chosen when the session was established. The
  current production configuration does not rely on that usage, and
  `TestPacketDestinationGuardOutboundSelectionPrecondition` fails if anyone adds such a rule.
- The per-datagram guard is a shared routing-layer change rather than a `protocol/naive` change, so
  it deserves attention at the next upstream merge.
- Per-IP limiting has been exercised only from a single loopback address, including its IPv4-mapped
  form; behaviour under a genuinely distributed source is untested.
- The production topology deliberately configures **no** `server_limits`. Choosing one requires
  measuring that deployment's real concurrency, which the available environment cannot produce.
- The limiter's fail-closed path when the tracked-IP map is full, and its amortized sweep, are proven
  at unit-test level rather than under production load.
- The runtime tests for the self-hosted web rewrite require binding a second loopback address, which
  macOS cannot do, so those tests are **skipped** on macOS and execute only on Linux.

## Cronet async buffer ownership

Cronet reads and writes complete through asynchronous native callbacks. A Go buffer must stay
pinned, valid, and clearly owned until the callback finishes, and must be released correctly on
success, error, timeout, cancel and close.

A cached first payload can be handed over directly when the geometry permits, removing one
plaintext copy; when it does not permit it, the path must fall back safely. Saving one allocation is
never worth a callback-after-free. The client's own boundary is documented in the
[macOS client document](JIEJIE-MACOS-CLIENT.md).

Historical local benchmark of the cached-first-payload handoff: 64 B `470 → 214 ns`,
1400 B `482 → 216 ns`, 16 KiB `796 → 215 ns`, `1 → 0 alloc`. These describe those sizes and that
fixture only; they are not a 64 KiB result and not a remote throughput claim.

## HTTP/2 / HTTP/3 behavior

- The H3 server does not enable 0-RTT.
- `quic_disable_path_manager` turns off QUIC connection migration. Unset leaves quic-go's default,
  which has the path manager **enabled** and matches the reference. Disabling migration is a
  legitimate production choice but it is a behaviour difference from the reference, so it is opted
  into rather than compiled into the protocol default.
- Uncovered stream-limit and path-manager behaviour follows the underlying library unless explicitly
  configured.
- The client offers default, BBR, BBR2, CUBIC and Reno congestion control choices; offering an
  option is not a claim that any one is universally best.

## Verification

| Area | Evidence |
| --- | --- |
| Write contract, short writes, frame counter | `audit_write_contract_test.go` |
| UoT v1/v2 transport matrix | `jiejie_naive_uot_transport_matrix_test.go` |
| Target ACL and DNS rebinding | `TestJiejieTargetACLRebindingCannotBypass` |
| Per-datagram UoT guard | `TestJiejieTargetACLUoTV1MultiTargetChecksEachDatagram`, `TestJiejieTargetACLUoTV2NonConnectMultiTarget` |
| Guard does not break server-internal backends | `TestJiejieTargetACLDoesNotBreakMasqueradeBackend` |
| Guard permits when no rule matches | `TestPacketDestinationGuardPermitsWhenNoRuleMatches` |
| Guard exposes no bypass read path | `TestPacketDestinationGuardExposesNoBypassReadPath` |
| Guard outbound-selection precondition | `TestPacketDestinationGuardOutboundSelectionPrecondition` |
| Padding vectors shared with the client repo | `test/jiejie/reference/naive_padding_vectors.json` |

## Known limits

- The VPS self-address gap described under the target ACL above remains open.
- No end-to-end STUN test, no complete round trip against an independent IPv6 UDP origin, and no
  performance comparison against Caddy.
- Cronet single-versus-multi engine, receive-window sweeps, and congestion-control comparison under
  controlled RTT, random loss and burst loss all require real-network A/B testing before any default
  is changed. Existing experiment scripts are
  [`bench-naive-cronet-engine.sh`](../scripts/ci/bench-naive-cronet-engine.sh) and
  [`bench-naive-receive-window.sh`](../scripts/ci/bench-naive-receive-window.sh).
