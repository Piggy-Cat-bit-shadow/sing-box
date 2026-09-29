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

### What "implemented" means here

A feature is called **implemented** only when all four hold:

1. the code exists;
2. the **production call path reaches it** — a constructor sets it, and a runtime
   operation uses it;
3. an **integration test** exercises it through that path, not through a component
   built by the test itself;
4. CI covers it.

Unit tests alone are explicitly **not** sufficient. This distinction is not
pedantry: the bootstrap cache and the handshake racer were once fully implemented,
fully unit-tested and completely unreachable — `NewClientEndpoint` passed the raw
outbound dialer to the HTTP client and left `HTTP3ConnDialer` nil, so neither ever
ran in production. Everything was green. The column below therefore records the
*production entry point*, so a reader can check the claim rather than trust it.

| Role / feature | Status | Code | Production entry point | Integration test |
|---|---|---|---|---|
| A. Bootstrap resolver (`domain_resolver`) | **existing**, unchanged | `common/dialer` | — | — |
| A. Bounded fresh resolve + last-known-good cache | **implemented** | `bootstrap_cache.go` | `NewClientEndpoint` → `newBootstrapDialer` | `TestConstructorWiresBootstrapRecoveryIntoTheDialer`, `TestBootstrapRecoveryUsesTheCacheAfterTheResolverFails` |
| A. QUIC handshake-level happy eyeballs | **implemented** | `bootstrap_race.go` | `NewClientEndpoint` → `ClientOptions.HTTP3ConnDialer` → `acquire` | `TestConstructorSetsTheHTTP3ConnDialer`, `TestConstructorHookRacesTheResolvedCandidates` |
| B. Inner resolver (`inner_domain_resolver`) | **implemented** | `client.go` | `lookupInner` | `resolver_precedence_test.go` |
| B. Server-assigned resolver (`DNS_ASSIGN`) | **implemented** | `assigned_dns_transport.go` | `installAssignedDNS` → `lookupInner` | `dns_leak_cycle_test.go`, `assigned_dns_model_test.go` |
| B. Assigned-resolver DoH on the tunnel connection | **implemented** | `assigned_dns_transport.go` | `selectTransport` → `RoundTripHTTP3` | `TestDoHMetadataComesFromTheSelectedResolver`, `TestTunnelAndDoHShareOneConnection` |
| B. TCP happy eyeballs | **implemented** | `client.go` | `dialResolved` | `client.go` tests |
| B. UDP selection stays serial | **implemented (deliberate)** | `client.go` | `dialResolved` | `client.go` tests |
| C. DNS interception | existing, unchanged | `route/` | — | — |
| `DNS_ASSIGN` capsule (send + receive) | **implemented** | `capsule_dns.go` | `server.go`, session dispatch | `server_dns_test.go`, `e2e_dns_assign_test.go` |
| `PREF64` capsule (send + receive) | **implemented** | `capsule_dns.go` | `server.go`, session dispatch | `server_dns_test.go`, `e2e_dns_assign_test.go` |
| Generic HTTP/3 request on the tunnel connection | **implemented** | `transport/http/client_h3_request.go` | `Client.RoundTripHTTP3` | `client_h3_same_conn_test.go` |
| `PREF64` NAT64 synthesis | **not implemented (deliberate)** | — | — | — |

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

The production path, as `NewClientEndpoint` builds it:

```
outboundDialer  (domain_resolver, via common/dialer)
     │
     ├─ bootstrapCache          remembers addresses the server ANSWERED on
     │                          (the DNS layer knows TTLs, not this)
     └─ bootstrapDialer         resolves through the cache, tries candidates in order
            │
            ├─ httpDialer      what the HTTP client dials through
            └─ masqueConnDialer → HTTP3ConnDialer hook
                     │
                     └─ handshakeRacer   winner = completed QUIC handshake
```

Both substitutions are **conditional**. With no bootstrap resolver — a literal-IP
server, or a dialer that cannot resolve — the original dialer is passed through
untouched and the hook stays `nil`, so the endpoint behaves exactly as it did before
the recovery path existed rather than acquiring a degraded one. Only `masque-client`
sets the hook; Naive, `protocol/http` and `common/httpclient` keep `hook == nil` and
the default dial path.

### Winner ownership

Every attempt ends in exactly one of two states: it **is** the winner, or it is
**closed**. There is no third state in which a successful attempt is published
somewhere nobody reads.

That third state existed and leaked. Attempts published with
`results <- result{conn}` on a channel buffered to `len(candidates)`; a buffered
send succeeds whenever there is room, so the cancellation arm was never taken and a
second completed handshake parked its connection in a slot nobody would read. With a
socket-counting dialer, a three-candidate race against one reachable server left
**three** sockets open where one is correct. The fix is structural: a
`sync.Once`-guarded CAS decides the winner exactly once, `results` is **unbuffered**,
and the success send also selects on the attempt's context.

Cleanup is **synchronous** — losers are closed before `dial` returns. An earlier
version returned the winner while starting `go func() { wg.Wait() }()`, so a caller
counting descriptors at the moment of return still saw losers, contradicting the
comment that claimed otherwise.

Candidate order **alternates families** (RFC 8305 §4). Grouping as "preferred family,
then the other" gives `IPv6#1 → delay → IPv6#2 → delay → IPv4`, i.e. two fallback
delays of silence before the working family is tried, which is the case the mechanism
exists to fix. The interleave **reorders and never filters**: every address still
appears exactly once, because dropping the preferred family's later addresses would
trade a latency bug for a connectivity one.

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

### The runtime model: two selections, in order

An assignment may carry **several** configurations, and they are not
interchangeable: each owns the internal domains it answers for. So a query is
routed in two steps, and the order matters.

```
query name
    │
    ├─ 1. WHICH configuration?   longest matching internal domain wins
    │                            (a configuration with none is the DEFAULT)
    │
    └─ 2. WHICH resolver in it?  lowest ServicePriority wins
```

`ServicePriority` orders resolvers that serve the **same** domains. It is not a
global ranking: a priority-1 resolver for `corp.example.` must not answer a public
name just because its number is lower. Treating it as global was the defect in the
first version, which flattened every configuration into one address list and then
ranked across all of them.

Matching is on a **label boundary**, so `notcorp.example` does not match
`corp.example`, and it is case- and root-dot-insensitive so presentation cannot
change routing. A name no configuration claims is answered by the default
configuration; if there is no default, the query **fails** rather than being sent
to a resolver that never claimed it.

Per-resolver metadata stays with its resolver. The authentication domain, dohpath
and port used for a DoH request all come from the **same** endpoint — never mixed
from a sibling. That is not tidiness: a request addressed to one origin but sent to
another server is a request the connection was never authenticated for.

### Transport capability is binding

| Advertised | Selected |
|---|---|
| dohpath + authentication domain, same-connection HTTP/3 client available | **DoH** on the tunnel's own connection |
| nothing | plain **UDP** through the tunnel |
| ALPN list, no `no-default-alpn` | DoH when available, else plain UDP |
| `no-default-alpn`, DoH usable | **DoH** |
| `no-default-alpn`, only DoT / nothing usable | **failure** — never cleartext |

`no-default-alpn` is treated as **binding**, not advisory. The parameter exists to
say unencrypted DNS is not offered, so falling back to plain UDP/53 does not
"degrade gracefully" — it sends the query in cleartext to a server that explicitly
said not to. An unsupported transport is therefore a failure **for that resolver**,
and the next resolver in the same configuration is tried; if none can be used, the
query fails closed.

An ALPN list **without** `no-default-alpn` is not a restriction: it names transports
the resolver *also* offers, and unencrypted DNS remains permitted.

DoT is recognised and **not implemented**. Reporting that plainly is better than
silently substituting something else, because the resolver's operator chose DoT
deliberately. Implementing DoT is out of scope; refusing is not the same as
ignoring.

### Reachability, decided per resolver

An assigned resolver is installed only if **every** address it advertises lies
inside the routes the server advertised. A resolver outside those routes would be
reached by the ordinary routing table rather than through the tunnel — the
cleartext leak the feature exists to prevent.

The decision is per **resolver**. A reachable sibling in the same configuration
still answers; a configuration whose resolvers are *all* unreachable is dropped
along with its domains, so it cannot capture matching names and then fail them.

One case is accepted without an address: a **name-only** resolver, and only when it
advertises same-connection DoH. It is then reached over the MASQUE HTTP/3
connection — a request stream, not a tunnel-routed packet — so the routes do not
constrain it and the same-origin check does instead.

A `nil` route set means the server has not advertised routes yet. The draft's §5
ordering rule is that DNS_ASSIGN must not precede ROUTE_ADVERTISEMENT, and treating
"no routes" as "nothing is reachable" enforces that from the receiving side rather
than trusting the peer.

### Fail closed

Every query goes through the MASQUE device. There is no code path that falls back
to a host socket: if the tunnel cannot carry a query, the query fails. Accepted
assignments are published as **one immutable snapshot** whose generation is
allocated inside it, so a reader can never observe a new resolver list with an old
generation — which matters because `Environment()` keys the DNS cache on it.

`DNS_ASSIGN` and `PREF64` remain **independently atomic**. No cross-capsule
atomicity is invented.

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
  interface. `TestUnreachableAssignmentNeverInstallsTheUnreachableResolver`,
  `TestNoDefaultALPNRefusesToDowngradeToPlainUDP` and
  `TestAssignedDNSDoHFailureDoesNotFallBackToHostSocket` pin this.
- Same-connection DoH reuses the existing HTTP/3 connection's request streams; it never
  opens a second QUIC connection and never carries DoH inside the CONNECT-IP capsule
  stream. `TestTunnelAndDoHShareOneConnection` pins this against a real server.
- Generic HTTP/3 requests are **same-origin only**. The connection is authenticated for one
  authority, so a request naming another is refused rather than forwarded: allowing it would
  turn the connection into a cross-origin tunnel riding on credentials never presented for
  that origin.

## Testing

Two layers, and the distinction matters:

- **component tests** build the thing under test themselves, so they cannot tell
  whether production can reach it;
- **constructor / integration tests** call the real entry point
  (`NewClientEndpoint`) and inspect what it built, so a component that is not wired
  in cannot pass.

| Area | Where |
|---|---|
| **Production wiring** (constructor-level) | `protocol/masque/constructor_integration_test.go` |
| **Configuration model** (routing, metadata, ALPN) | `protocol/masque/assigned_dns_model_test.go` |
| **QUIC racer ownership** (socket accounting, family interleave) | `protocol/masque/bootstrap_race_ownership_test.go` |
| Capsule codecs, bounds, reference vectors | `transport/masque/capsule_dns_test.go` |
| Capsule session state (replace / withdraw / clear) | `transport/masque/session_dns_state_test.go` |
| Server emission and ordering | `transport/masque/server_dns_test.go` |
| Server→client end-to-end agreement | `transport/masque/e2e_dns_assign_test.go` |
| Assigned transport, reachability, fail-closed | `protocol/masque/assigned_dns_transport_test.go` |
| Same-connection DoH | `protocol/masque/assigned_doh_test.go` |
| Resolver precedence | `protocol/masque/resolver_precedence_test.go` |
| Leak prevention and resolver cycles | `protocol/masque/dns_leak_cycle_test.go` |
| Bootstrap cache and handshake race (component) | `protocol/masque/bootstrap_cache_test.go`, `bootstrap_race_test.go` |
| Fuzzing (`DNS_ASSIGN`, `PREF64`, encode/parse round trip) | `transport/masque/fuzz_dns_capsule_test.go` |
| Generic H3 requests, same-origin, reuse | `transport/http/client_h3_request_test.go` |
| One-connection proof against a real server | `transport/http/client_h3_same_conn_test.go` |
| Resource leaks (cancellation, abandoned bodies) | `transport/http/client_h3_leak_test.go` |
