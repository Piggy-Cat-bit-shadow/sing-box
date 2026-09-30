# MASQUE

Current MASQUE implementation in this fork: what it does, where the boundaries are, and what is
verified. Design decisions that must not be changed casually are in
[engineering notes](ENGINEERING-NOTES.md).

## Current scope

- **HTTP CONNECT / CONNECT-UDP over H2 and H3** — the production server's L4 proxy path. HTTP/3 is
  primary; HTTP/2 is the fallback transport.
- **CONNECT-IP endpoint** — a MASQUE client endpoint with address assignment, route advertisement,
  DNS_ASSIGN and PREF64 state.

## Two different MASQUE surfaces

These are separate capabilities with separate lifecycles. They must not be conflated.

### L4 HTTP CONNECT / CONNECT-UDP

The production server path. An HTTP inbound authenticates the request, then carries either a TCP
CONNECT or a CONNECT-UDP session over HTTP/2 or HTTP/3. Unauthenticated and wrong-password requests
can be routed to a masquerade instead; see the [server document](JIEJIE-SERVER.md) for the
deployment semantics.

### CONNECT-IP endpoint path

`protocol/masque` and `transport/masque` implement the CONNECT-IP endpoint: an IP tunnel with
address assignment, route advertisement and optional DNS configuration delivered as capsules. This
is endpoint capability, not the L4 proxy path the server serves.

## Architecture boundaries

| Directory | Responsibility |
| --- | --- |
| [`protocol/masque`](../protocol/masque) | Endpoint integration, options, target resolution, DNS_ASSIGN policy and state, PREF64 state, bootstrap policy, routing and capability compilation. |
| [`transport/masque`](../transport/masque) | CONNECT-IP sessions, control capsules, ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, IP packet send/receive, H3 DATAGRAM with capsule fallback, buffer ownership, MTU/PTB and session lifecycle. |
| [`transport/http`](../transport/http) | HTTP/1.1, HTTP/2, HTTP/3, CONNECT, QUIC/TLS establishment, congestion control, H3 ClientConn and request-stream lifecycle. |

The MASQUE layer does not reimplement QUIC, TLS, congestion control or generic H3 lifecycle.
DNS_ASSIGN uses the existing DNS transports rather than introducing a second DNS engine, and PREF64
maintains state only. Do not break these boundaries for a local micro-optimization.

## H3 lifecycle and error semantics

CONNECT and ordinary requests share one HTTP/3 connection but **do not share a lifecycle**:

| | Ordinary request | CONNECT |
| --- | --- | --- |
| Stream owner | quic-go `ClientConn.RoundTrip` | the tunnel, opened by `openConnectStream` |
| Write side at 200 | finished | **stays open** |
| Response | is the response | becomes the tunnel |
| Setup context | applies to the request | bounds setup only, then detached |

A CONNECT's `200` is where the tunnel *begins*. Closing the write side there leaves a stream that
can be read but never written, and the first proxy write fails with `write on closed stream`. The
setup context is detached once the tunnel is handed over, because the caller's `DialContext`
typically cancels its own setup context on return and leaving it wired would tear down a healthy
tunnel.

**Error classification invariant.** Typed QUIC / HTTP/3 semantic classification always precedes any
generic closed/canceled test. Every quic-go error type implements `Unwrap() -> net.ErrClosed`
regardless of severity, so a generic test run first cannot distinguish an orderly shutdown from a
protocol violation. Current behaviour:

| Condition | Classification |
| --- | --- |
| `H3_REQUEST_CANCELLED` (268 / `0x10c`), remote or local | expected closure — stream-local, TRACE |
| `http3.ErrCodeNoError`, code `0` | expected closure |
| `IdleTimeoutError`, `HandshakeTimeoutError` | expected closure |
| `TransportError` with code 0, `ApplicationError` with code 0 | expected closure |
| `TransportError` fault (e.g. `PROTOCOL_VIOLATION`) | **visible fault** |
| `ApplicationError` with a fault code | **visible fault** |
| `http3.Error` with a fault code | **visible fault** |
| `StatelessResetError`, `VersionNegotiationError` | **visible fault** |
| Unclassifiable error | **visible fault** |

A cancelled stream is stream-local: it must not close the shared connection, and other multiplexed
streams continue. A connection-level failure ends every stream on that connection and evicts it.

## Datagram ownership and performance

The outbound owned-DATAGRAM path writes the HTTP/3 Quarter Stream ID in place using buffer headroom,
then transfers buffer ownership to the QUIC queue. Two full payload copies before
packetization/AEAD become zero. The copying `SendDatagram` keeps its original semantics.

Ownership contract for the owned API: on success the receiver releases exactly once; on failure or
an oversized payload the caller still holds the buffer; shutdown drains the queue. See
[`owned_datagram.go`](../transport/http/owned_datagram.go).

A historical local benchmark at 1280 B measured the owned path at roughly **2.7×** the copying path.
That is a dataplane microbenchmark on one machine and fixture; it is not a WAN throughput, VPS
memory or loss-tolerance result.

Inbound still relies on quic-go's receive buffers, asynchronous TUN handoff and buffer lifetime.
*REJECT:* removing the last receive-side copy by introducing cross-layer reference counting or a
shared mutable staging area increases release and race risk, and no profile supports it.

## CONNECT-IP lifecycle

- Address assignment, route advertisement and IP packet send/receive must be handled correctly. When
  H3 DATAGRAM is available it is used; when the peer does not support it the session must fall back
  to capsules.
- Packet Too Big must be attributed to the session that owns it and never broadcast to other
  sessions.
- Non-zero DATAGRAM context IDs are covered: unsupported IDs are dropped and later context-0 traffic
  still round-trips on the same tunnel.

## DNS_ASSIGN / PREF64

`DNS_ASSIGN` is **immutable configuration, not a mutable DNS subsystem.** It is consumed for one
purpose: choosing the resolver this endpoint uses when it resolves a domain destination it is about
to carry through the tunnel. It does not program the sing-box DNS router, configure the OS resolver,
install search domains or NAT64 prefixes, or intercept DNS packets applications send into the TUN
device.

### Four planes

| Plane | Responsibility |
| --- | --- |
| Bootstrap | Resolves the MASQUE *server* hostname before any tunnel exists. Never consults the tunnel or the assignment. |
| Session configuration | Receives capsules, validates them, publishes immutable snapshots. Pure state: no sockets, no goroutines, no lifecycle. |
| DNS policy | Decides *which* configuration owns a name. A pure function; no dialing, no HTTP, no packet handling. |
| DNS execution | Runs the query against an already-chosen configuration, via plain DNS over the native UDP transport or same-connection DoH. |

Bootstrap keeps two pieces of state: the most recent successful resolution, and the address that
most recently completed a QUIC handshake. Every attempt resolves fresh, and a fresh success
*replaces* the remembered set rather than merging it. The winner is the first candidate whose QUIC
handshake **completes** — not the first to create a socket. Losers are closed before the race
returns.

### same-connection DoH

DoH is coalesced onto the connection the tunnel itself uses. Three distinct facts matter:

- **A** — the client *can* speak HTTP/3 (configuration).
- **B** — it currently holds a live HTTP/3 connection.
- **C** — *this tunnel session was established over* HTTP/3.

Same-connection DoH requires **C and B** plus a matching origin and an advertising resolver. Neither
A nor B implies C, because the tunnel path falls back: an HTTP/3 attempt can fail, the session be
established over HTTP/2, and a live HTTP/3 connection remain from an earlier success. Inferring C
from B would send a DNS query on a connection the tunnel traffic does not share.

C is recorded where it is decided — `transport/http` reports the protocol each successful branch of
`openTunnel` used, through an additive `OpenTunnelWithInfo` — and is checked in two places: the
compile-time capability decision and the request-time executor. Checking only B reintroduces the
conflation, and because every individual query would still succeed the mistake is invisible until
someone notices the second connection. DoH uses an **existing-connection-only** call: a DNS query
must never be the reason a second QUIC connection appears.

### Resolver origin

A DoH request is addressed to a host **and a port**; the same host on two ports is two origins. The
authority is built once including the effective port, and both the capability decision and the
runtime same-origin check use that one value. Normalization covers exactly ASCII case and a single
trailing root dot. An advertised SVCB `port` is honoured rather than replaced by a default.

### Capability recomputation

Whether a resolver can use DoH is a *joint* property of the advertisement and the current tunnel. A
snapshot compiled while the tunnel was HTTP/2 would mark an addressless DoH resolver unusable
forever; one compiled on HTTP/3 would keep offering DoH after a fallback. The endpoint therefore
recomputes when the session transport or the routes change and publishes a new immutable snapshot.
The server does not resend `DNS_ASSIGN`, and should not have to: the assignment did not change, our
ability to use it did.

Each resolver carries **both** of its capabilities, so a DoH failure at query time can still fall
back to the transport the server advertised. Executor order is same-connection DoH when currently
applicable, then plain DNS when the server left the default transport available. Selection table:

| Advertised | Selected |
| --- | --- |
| `dohpath` + authentication domain + ALPN containing `h3`, matching the live tunnel connection | same-connection DoH |
| nothing | plain DNS over UDP, with the native transport's TCP retry |
| ALPN list without `no-default-alpn` | DoH when available and matching, else plain DNS |
| `no-default-alpn` and DoH usable | DoH |
| `no-default-alpn` with only DoT or nothing usable | failure for that resolver; try the next in the same configuration |

**ALPN must name `h3` explicitly.** A `dohpath` says *where* to POST, not which protocol carries it;
`alpn=h2` with a `dohpath` is never given an HTTP/3 request. Absent ALPN is not a wildcard.
`no-default-alpn` is binding rather than advisory: omitting it is what indicates support for
unencrypted DNS, so falling back to UDP/53 would send cleartext to a server that said not to. An
ALPN list *without* it is not a restriction.

### SVCB

Wire-boundary validation, because a parameter accepted but misread produces a resolver that looks
usable and is not:

| Parameter | Rule |
| --- | --- |
| `alpn` | Length-prefixed pairs that must exactly fill the value. |
| `no-default-alpn` | Value must be empty. |
| `port` | Exactly 2 octets, network byte order; honoured when present. |
| `mandatory` | Keys present, no repetition, must not list itself, all recognised. |
| `ipv4hint`, `ipv6hint` | **Rejected**, per the CONNECT-IP DNS draft. |
| Unknown, non-mandatory | Ignored. |

A malformed value makes that resolver incompatible and the next resolver in the same configuration
is tried; if none can be used the query fails closed.

Recognised ≠ implemented for `mandatory`: `alpn`, `no-default-alpn`, `port` and `dohpath` are
honoured as mandatory; `ipv4hint`/`ipv6hint` are rejected outright; `ech` is recognised so a
mandatory reference can be refused by name, but no ECH handshake is performed; anything else cannot
be honoured by definition.

An HTTP ALPN without a `dohpath` is not *usable* as DoH but is not *malformed*. It simply cannot
build a DoH capability, so the resolver keeps whatever else it advertised and is unusable only if
the server also withdrew plain DNS.

### dohpath

`dohpath` is a **relative** URI Template that must contain the `dns` variable. For a POST the
template is processed with no variables defined, so an expression expands to the empty string
including its own `?` or `&`: `/dns-query{?dns}` → `/dns-query`, and `/q{?dns}suffix` → `/qsuffix`.
Expansion is implemented rather than approximated — truncating at the first `{` is right for the
first case and wrong for the second.

Supported: `{dns}`, `{?dns}`, `{&dns}`, `{/dns}`, `{.dns}`, `{;dns}`, and comma-separated name
lists. Refused: the `+` and `#` operators, an empty expression, nested braces, unterminated or stray
braces, the `*` and `:` modifiers, invalid variable names including invalid percent escapes, and any
template that is not valid UTF-8. A variable name must match the RFC 6570 grammar where the dot is a
*separator* between non-empty components.

The **expansion** is validated too, because it becomes the request's `:path` verbatim: a raw control
character, a space, a non-ASCII byte, or a `%` beginning no valid escape is refused. A template
whose expansion is empty, lacks a leading slash, or contains no `dns` variable is never sent —
guessing a path the server did not send is worse than reporting the advertisement unusable.
Expansion *deletes* an expression, so a permissive parser would produce a plausible path from a
template it did not understand: a request to the right origin and the wrong resource.

### Cache identity

A configuration-bound transport reports an environment derived from **effective resolver
behaviour**: the claims, the resolvers, their metadata, and the transport each will actually use. It
contains no monotonic generation counter, so:

| Change | Invalidates cached answers? |
| --- | --- |
| The same `DNS_ASSIGN` again | No |
| A `PREF64`-only update | No |
| Search domains changing | No — parsed and preserved, but endpoint-local resolution does not apply them |
| A route change making a resolver unreachable | Yes |
| Losing the TCP route, even with UDP addresses unchanged | Yes — a truncated answer must retry over TCP |

The key is per **configuration**, not per assignment: a lookup is already bound to one configuration
by the time a query runs, so an unrelated configuration changing must not discard that
configuration's answers. TTL handling, caching, negative caching, singleflight and optimistic
caching remain the sing-box DNS client's responsibility; this layer does not reimplement them, and
the bootstrap recovery state is not a DNS cache.

Immutability is load-bearing: a single lookup issues an A and an AAAA query concurrently, so if the
transport read the assignment per query, a capsule arriving mid-lookup could answer IPv4 from one
assignment and IPv6 from the next.

### Ownership

No layer needs a reference count, retirement queue or delayed cleanup, because nothing that owns a
resource is replaceable state. The assignment snapshot owns no socket, goroutine or `Close`, so
replacing it is a single pointer store and an in-flight lookup keeps using the value it captured.
`pref64Store` is separate from DNS state and cannot affect an answer or a transport. Plain DNS is
delegated to the native UDP transport, pointed at the MASQUE device, used for one exchange and then
closed, so there is one implementation of the protocol rather than two that could drift.

The TCP-retry dialer is constrained to the protocols advertised for **that one address**, taken from
`ROUTE_ADVERTISEMENT` — per address, not per resolver, so an address without an advertised TCP route
cannot inherit permission from a sibling. Without that, a UDP-only route would produce TCP traffic
the server never said it routes, and the caller would see a timeout resembling packet loss.

DoH wire rules: requests carry DNS ID 0 on a **copy** of the wire bytes so the caller's message is
never mutated, and the caller's ID is restored on the reply. Any 2xx is success, not only 200. The
response media type is validated by MIME parsing (an absent header is tolerated); an HTML error page
is reported as a media-type mismatch rather than a corrupt DNS message. Responses are bounded, with
one byte read past the ceiling so an oversized message is reported as oversized.

Policy rules: ownership is decided **without reference to usability**, because handing a claimed
name to a public resolver when the internal one is unreachable would leak an internal name at
exactly the moment the internal path is broken. Selection is longest-match on internal domains,
on a label boundary, case- and root-dot-insensitive. An empty list claims nothing; the root claim is
the single empty-string entry.

### Limitations

- Endpoint-local only: no global OS or VPN DNS integration.
- Search domains are preserved, not applied.
- Claims before the first `DNS_ASSIGN` are unknowable — the protocol has no capsule announcing one
  is coming, so until it arrives every name is unclaimed. A name resolved a moment before a claiming
  assignment is a leak this implementation cannot prevent, and no timer or readiness gate pretends
  otherwise.
- PREF64 is state only; there is no DNS64 synthesis.
- DoT and DoQ are recognised and refused, never silently substituted.
- No same-connection DoH over HTTP/2: a resolver offering only `h2` with `no-default-alpn` is
  incompatible; with the default transport permitted it uses plain DNS.
- No ECH, and no cross-origin HTTP/3 coalescing.
- Only the strict `dohpath` subset above is accepted.

## MTU / PTB

Packet Too Big handling belongs to `transport/masque`. An oversized datagram is rejected in the
session that owns it. A historical experiment that lowered a learned DATAGRAM ceiling permanently
after one oversized packet was *REJECT*ed: the underlying effective limit can rise again, so a
one-way ratchet turns a recoverable path into a permanent refusal.

## Security / masquerade boundary

Masquerade is a deployment feature of the HTTP inbound, documented in
[the server document](JIEJIE-SERVER.md). It changes only the response to requests that fail
authentication; the authenticated data plane is unmodified.

**It does not make the protocol undetectable.** QUIC, HTTP/3 SETTINGS, `H3_DATAGRAM` and Extended
CONNECT remain observable on the wire. A `429` decoy is not claimed to be path-indistinguishable.

## Verification

| Area | Evidence |
| --- | --- |
| CONNECT remains writable and bidirectional after 200 | `client_h3_connect_lifecycle_test.go` against a real quic-go HTTP/3 server |
| Tunnel and DoH share one connection | `client_h3_same_conn_test.go` |
| Stream cancellation is stream-local; faults stay visible | `stream_error_class_test.go` |
| Stale connection eviction, replacement isolation, reconnect coalescing | `client_h3_stale_conn_test.go` |
| H3 DATAGRAM with capsule fallback, IPv6 assignment | `test/jiejie/reference/connect_ip_ipv6_test.go` |
| Non-zero DATAGRAM context IDs | `test/jiejie/reference/context_id_test.go` |
| Packet Too Big attribution | `connect_ip_ptb_live_test.go`, `packet_too_big_test.go` |
| Owned datagram ownership | `owned_datagram_ownership_test.go` |
| QUICHE protocol vectors | `quiche_oracle_test.go` |

## Remaining NOT PROVEN

These are evidence gaps, not confirmed defects. Nothing was changed because of them: no timeout was
raised, no speculative retry was added, and the connection cache was not rewritten.

- **Timeout pattern of ~1.84 s followed by ~30 s.** It could not be reproduced, and the available
  logs could not distinguish a second failure on one connection from a redial. Generation and cache
  decision tracing was added so it becomes answerable; the mechanism itself remains unproven.
- **Live IPv6 H3 Packet Too Big.** Existing ICMPv6 shape tests and the IPv4 live H3 PTB test do not
  substitute for it.
- **Google QUICHE live MASQUE tunnel interop.** Only protocol vectors are checked; the live harness
  was removed. Vector agreement is not live interoperability.
- **Real WAN PMTU, fragment blackholes, mobile handover and CGNAT behaviour.** Local and CI tunnel
  tests do not establish these.
- **Long-running VPS stability and production concurrency limits.**
- **NAT rebinding / QUIC path migration.** The cache is proven to key on connection liveness rather
  than an address tuple, and a live connection is not mistaken for a replacement, but this is
  simulated at the lifecycle level. No wire-level migration was performed.
- **Bootstrap winner subsequently going idle.** The narrow window is covered through concurrent
  acquires; the candidate-racing hook itself is not exercised.
- **Whether a connection-level retry after an OpenStream failure is worthwhile.** Deliberately not
  implemented.
