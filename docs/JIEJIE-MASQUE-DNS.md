# MASQUE DNS: the three resolvers and what bounds each one

This is an engineering contract for how DNS works on the Jiejie MASQUE client. It
exists because MASQUE has **three distinct DNS roles** that are easy to conflate,
and conflating them produces either a bootstrap that depends on the tunnel it is
supposed to establish, or a resolution path that silently bypasses the sing-box
DNS router.

All three roles are implemented. Roles A and B were extended for server-pushed DNS
configuration; role C is unchanged upstream sing-box behaviour and is documented here
because it is the role most easily confused with B.

## The three roles

```
  (A) BOOTSTRAP                 (B) INNER                    (C) INTERCEPTION
  resolves the MASQUE           resolves domains             raw DNS packets
  SERVER hostname               reached THROUGH              arriving from TUN
                                the tunnel
        │                             │                             │
        ▼                             ▼                             ▼
  dialer.New            dnsRouter.Lookup(               router.HijackDNSPacket()
  + domain_resolver      ctx, fqdn,                       (unchanged, upstream
  + DNS router           innerQueryOptions)               sing-box behaviour)
        │                             │
        ▼                             ▼
  must work BEFORE            may depend on the
  any tunnel exists           tunnel, or on server-
                              pushed DNS configuration
```

| | A. Bootstrap | B. Inner | C. Interception |
|---|---|---|---|
| Config field | `domain_resolver` | `inner_domain_resolver` | — |
| Code | `common/dialer` | `protocol/masque/client.go` | `route/` |
| May use the tunnel? | **No, never** | Yes | n/a |

### Why A and B must be separate

Role A runs when there is no tunnel yet. If it could consult server-pushed DNS or
`inner_domain_resolver`, the dependency would be circular: connecting requires
resolving the server, resolving requires connecting.

Role B runs after the tunnel exists and legitimately depends on it. Merging the two
fields would make the bootstrap path depend on the thing it bootstraps, so they are
two settings and the code keeps them apart.

## Status

| Role / feature | Status | Code |
|---|---|---|
| A. Bootstrap resolver (`domain_resolver`) | **existing**, unchanged | `common/dialer` |
| A. Bounded fresh resolve + last-known-good cache | **implemented** | `protocol/masque/bootstrap_cache.go` |
| A. QUIC handshake-level happy eyeballs | **implemented** | `protocol/masque/bootstrap_race.go` |
| B. Inner resolver (`inner_domain_resolver`) | **implemented** | `protocol/masque/client.go` |
| B. Server-assigned resolver (`DNS_ASSIGN`) | **implemented** | `protocol/masque/assigned_dns_transport.go` |
| B. Assigned-resolver DoH on the tunnel connection | **implemented** | `protocol/masque/assigned_dns_transport.go` |
| B. TCP happy eyeballs | **implemented** | `protocol/masque/client.go` |
| B. UDP selection stays serial | **implemented (deliberate)** | `protocol/masque/client.go` |
| C. DNS interception | existing, unchanged | `route/` |
| `DNS_ASSIGN` capsule (send + receive) | **implemented** | `transport/masque/capsule_dns.go` |
| `PREF64` capsule (send + receive) | **implemented** | `transport/masque/capsule_dns.go` |
| Generic HTTP/3 request on the tunnel connection | **implemented** | `transport/http/client_h3_request.go` |

## B. Inner resolver

### Configuration

```json
{
  "type": "masque-client",
  "tag": "masque-out",
  "server": "95.169.1.53",
  "server_port": 443,
  "domain_resolver": "dns-bootstrap",
  "inner_domain_resolver": {
    "server": "dns-us",
    "strategy": "prefer_ipv6",
    "timeout": "3s"
  }
}
```

`inner_domain_resolver` reuses `option.DomainResolveOptions`, so it accepts the same
bare-string shorthand and carries the same `strategy`, `timeout` and cache controls
as everywhere else in sing-box. No parallel schema was invented.

### Precedence

```
explicit inner_domain_resolver   (highest)
        >
server-pushed DNS_ASSIGN         (implemented)
        >
normal DNS router rules          (default)
```

A configured inner resolver always wins. A server cannot override explicit local
configuration — that is a security property, not a convenience: the operator's
choice is the trusted one.

### Unset means unchanged

An omitted `inner_domain_resolver` is **nil**, and nil resolves to the zero
`DNSQueryOptions`, which tells the DNS router to apply the configured rules. That is
precisely the behaviour that existed before the option, so no existing configuration
changes meaning. This is asserted by test rather than assumed, because a non-nil
zero value would silently alter every current config.

### Resolved once, at construction

The option becomes an `adapter.DNSQueryOptions` in `NewClientEndpoint`, not on each
connection. Two consequences:

- an unknown resolver tag fails at **configuration time** rather than on the first
  inner lookup;
- an inner lookup takes the DNS router's transport fast path instead of re-walking
  the rule set for every target domain.

## B. TCP happy eyeballs

Inner TCP targets race the address families with `N.DialParallel` and the standard
fallback delay (300ms). A dual-stack target whose preferred family is blackholed
connects over the other family in about one fallback delay.

Measured, from the tests in this repository:

| Scenario | Serial (before) | Raced (after) |
|---|---|---|
| IPv6 blackholed, IPv4 healthy | 10.001s | **102ms** |
| IPv4 blackholed, IPv6 healthy | 10.0s | **101ms** |
| Single-family answer | no race | no race (no timer started) |

The 10s figure is the serial attempt blocking until its context expired; that is the
"page hangs for ten seconds on a broken IPv6 network" symptom. A single-family
answer short-circuits to serial, so single-stack targets pay nothing.

### Family preference

| `strategy` | Behaviour |
|---|---|
| `prefer_ipv6` | IPv6 first |
| `prefer_ipv4` | IPv4 first |
| unset / `AsIS` (zero value) | the family of the resolver's **first** address |

`AsIS` reads the order the DNS layer already chose rather than hardcoding a family,
which is what "as is" asks for. Within a family the resolver's ordering is preserved.

### UDP does NOT race

A UDP socket is connectionless. A successful `connect()` or `ListenPacket` proves
only that the **local kernel** accepted the address; it says nothing about whether
the peer is reachable. Racing on that signal would anoint a winner that has not been
shown to work, which is worse than no race. TCP has a handshake to win and UDP does
not, so the UDP path stays serial on purpose.

## A. Bounded fresh resolve + last-known-good cache

Implemented in `protocol/masque/bootstrap_cache.go`.

A resolver outage during a reconnect storm used to be unrecoverable: the connect loop
retried with a 1s→1m backoff and re-resolved from scratch every time, with no fallback.
The bootstrap path now keeps state across retries:

- an in-memory, **bounded** (`defaultMaxBootstrapCandidates = 8`, deduplicated)
  per-endpoint candidate set;
- fresh-first ordering, `fresh ++ (cached \ fresh)`, so a winner from the previous
  network never outranks a fresh answer;
- when a fresh lookup fails, times out or returns empty, the cache is used instead,
  bounded by `bootstrapFreshTimeout = 3s` rather than a system resolver's 20–30s;
- a candidate is promoted to the front once it actually completes a connection;
- the cache **survives `RestartSession`** and is released only on endpoint close.

This is **connection-recovery** state, not a DNS cache. It does not duplicate, replace
or shadow the sing-box DNS cache.

## A. QUIC handshake-level happy eyeballs

Implemented in `protocol/masque/bootstrap_race.go`.

The constraint that shapes the whole thing is that **a UDP socket connect is not a
winner**. A reachable UDP path is not a reachable QUIC endpoint, so candidates are raced
at the **QUIC handshake** level and the winner is the first candidate whose handshake
actually completes — `quicConn.HandshakeComplete()`. It is deliberately *not* the first
that creates a socket, not the first that returns a `DialEarly` object, and not the first
that offers 0-RTT data. Staggering uses `N.DefaultFallbackDelay` (300ms). Session
resumption is preserved; it just does not decide the race.

`TestRacerDoesNotTreatUDPConnectAsSuccess` pins that property directly.

## B. Server-assigned resolver (`DNS_ASSIGN` and `PREF64`)

Both capsules are implemented in both directions: `transport/masque/capsule_dns.go`
holds the codecs, `transport/masque/server.go` sends them, and
`protocol/masque/assigned_dns_transport.go` consumes them.

Reviewed against `quic-go/connect-ip-go@v0.4.1-0.20260924175820-fdd945e3d600`, which
implements `draft-ietf-masque-connect-ip-dns-06`:

| Capsule | Type ID | Wire shape |
|---|---|---|
| `DNS_ASSIGN` | `0x1ace79ec` | repeated DNS Configuration: nameserver count, then per-nameserver `{priority u16 BE, v4 count + 4-byte each, v6 count + 16-byte each, auth domain (varint len + bytes), SVC params (varint len + key/value pairs)}`, then internal domains, then search domains |
| `PREF64` | `0x274c0fbc` | N × 13 bytes: 1-byte prefix length ∈ {32,40,48,56,64,96} + exactly 12 address bytes, always 12 regardless of prefix length |

Both are **declarative latest-state**: each capsule supersedes the previous one rather
than appending. An empty `PREF64` capsule is a **withdrawal**, which is why the server
distinguishes a nil prefix list (send nothing) from an empty non-nil one (send an empty
capsule). Values are provisional in the draft and will change before publication, so they
stay named constants.

Updates are **independently atomic**: a `DNS_ASSIGN` and a `PREF64` arriving separately
each take effect on their own, and no cross-capsule atomicity is invented.
`TestDNSAndPREF64UpdatesAreIndividuallyAtomic` pins that.

### Reachability and fail-closed behaviour

An assigned nameserver is installed **only** if every one of its addresses lies inside the
routes the server advertised. A nameserver outside those routes would be reached by the
ordinary routing table rather than through the tunnel, which is the cleartext leak the
whole feature exists to prevent. The check is all-or-nothing: one unreachable address
refuses the entire configuration rather than installing a partial resolver that would
answer some queries through the tunnel and send the rest elsewhere.

An address-less nameserver is **not** treated as reachable, because resolving its name
would itself need a resolver — the cycle this design avoids.

The transport **fails closed**: every query goes through the MASQUE device, and there is
no code path that falls back to a host socket. If the tunnel cannot carry a query, the
query fails.

### DoH on the tunnel's own connection

`draft-ietf-masque-connect-ip-dns-06` §3.5 asks that DoH queries to a proxy-authoritative
origin be coalesced over the same HTTPS connection the CONNECT-IP tunnel uses. When the
server advertises a `dohpath`, the assigned transport issues the query as an RFC 8484 POST
on that connection, addressed to the nameserver's authentication domain — the origin the
connection was actually verified for.

This is verified **end to end against a real HTTP/3 server**: the test opens a CONNECT-IP
tunnel, then issues eight concurrent DoH requests, and requires the server to have accepted
exactly **one** QUIC connection, counted from the server's own `ConnContext` rather than
from anything the client reports about itself. The tunnel stream and every DoH stream share
that one connection, each request on its own HTTP/3 stream.

When no `dohpath` is advertised, or before the endpoint has published its HTTP/3 client,
queries go over plain UDP **through the tunnel**. That is a deliberate limit rather than an
oversight: DoT would need a TLS session through the device with its own certificate story,
and claiming support for a transport that cannot actually be completed would mean silently
ignoring the ALPN parameters the server sent.

### Documented deviations from the reference

Two places where this fork is deliberately not byte-identical to the reference, both
documented at the code and covered by tests:

1. **Address-count requirement.** `draft-ietf-masque-connect-ip-dns-06` §3.2 says that when
   `no-default-alpn` is omitted the address count MUST be nonzero — which rejects the
   draft's *own* §3.6.1 example, whose nameserver carries `alpn=h2,h3`, no
   `no-default-alpn`, and **zero** addresses. This fork applies the requirement only when
   `ALPN` is **absent**. That accepts strictly *more* than the reference on receive (so
   anything the reference sends still validates here) and keeps every draft example valid.
   It does not weaken the send path.
2. **PREF64 host bits.** This fork **masks** host bits below the prefix length; the
   reference does not, and its own test asserts that `2001:db8:0:0:1::/32` survives parsing
   with host bits set. Masking is both safe and stricter: RFC 6052 synthesis only reads bits
   within the prefix length, and masking makes the stored value compare equal across
   differently-padded encodings of the same prefix, which is what latest-state replacement
   and cache keys need.

The reference does **not** implement DNS64 synthesis; it only transports the configuration.
This fork does not synthesise either — `PREF64` state is carried and exposed, not used to
rewrite addresses.

## Cycle and leak rules

- Role A must never reach the MASQUE endpoint.
  `TestAssignedResolverIsNeverUsedForBootstrap` pins this.
- Server-pushed resolvers must be reachable **through the tunnel** and must fail
  closed. A server-pushed address must never cause a cleartext query from the host
  interface. `TestUnreachableAssignmentIsRefusedWholesale` and
  `TestAssignedDNSDoHFailureDoesNotFallBackToHostSocket` pin this.
- Same-connection DoH reuses the existing HTTP/3 connection's request streams; it never
  opens a second QUIC connection and never carries DoH inside the CONNECT-IP capsule
  stream. `TestTunnelAndDoHShareOneConnection` pins this against a real server.
- Generic HTTP/3 requests are **same-origin only**. The connection is authenticated for one
  authority, so a request naming another is refused rather than forwarded: allowing it would
  turn the connection into a cross-origin tunnel riding on credentials never presented for
  that origin.

## Testing

| Area | Where |
|---|---|
| Capsule codecs, bounds, reference vectors | `transport/masque/capsule_dns_test.go` |
| Capsule session state (replace / withdraw / clear) | `transport/masque/session_dns_state_test.go` |
| Server emission and ordering | `transport/masque/server_dns_test.go` |
| Server→client end-to-end agreement | `transport/masque/e2e_dns_assign_test.go` |
| Assigned transport, reachability, fail-closed | `protocol/masque/assigned_dns_transport_test.go` |
| Same-connection DoH | `protocol/masque/assigned_doh_test.go` |
| Resolver precedence | `protocol/masque/resolver_precedence_test.go` |
| Leak prevention and resolver cycles | `protocol/masque/dns_leak_cycle_test.go` |
| Bootstrap cache and handshake race | `protocol/masque/bootstrap_cache_test.go`, `bootstrap_race_test.go` |
| Fuzzing (`DNS_ASSIGN`, `PREF64`, encode/parse round trip) | `transport/masque/fuzz_dns_capsule_test.go` |
| Generic H3 requests, same-origin, reuse | `transport/http/client_h3_request_test.go` |
| One-connection proof against a real server | `transport/http/client_h3_same_conn_test.go` |
| Resource leaks (cancellation, abandoned bodies) | `transport/http/client_h3_leak_test.go` |
