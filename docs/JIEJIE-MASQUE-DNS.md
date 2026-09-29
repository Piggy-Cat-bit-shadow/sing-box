# MASQUE DNS: four planes, and what each one owns

This document describes how the Jiejie MASQUE client consumes a server's `DNS_ASSIGN`
and `PREF64` capsules. It is written to be read before the code, and it states the
scope limits as plainly as the capabilities, because the limits are what keep the
design small.

The one-sentence version:

> DNS_ASSIGN is immutable configuration, not a mutable DNS subsystem.

## Scope: endpoint-local, and only that

`DNS_ASSIGN` is consumed for exactly one purpose: choosing the resolver this MASQUE
endpoint uses when **it** resolves a domain destination that it is about to carry
through the tunnel. That is the inner-resolution path behind
`ClientEndpoint.DialContext(domain)` and `ClientEndpoint.ListenPacket(domain)`.

It is **not** global DNS configuration. This implementation does **not**:

- program the sing-box DNS router's global rules or transports;
- configure the operating system resolver;
- install search domains anywhere;
- install NAT64 prefixes anywhere;
- intercept or answer DNS packets that applications send into the TUN device;
- implement a full Remote Access VPN DNS policy.

Those are separate features with separate designs. Nothing here should drift into
them, and nothing here should be read as claiming them. A future full-VPN DNS
integration would be its own design, layered on top of the snapshot this code already
preserves.

## The four planes

```
A. BOOTSTRAP PLANE          resolves the MASQUE SERVER hostname
   bootstrap_cache.go       fresh resolution, last-known-good fallback
   bootstrap_race.go        candidate ordering, stagger, winner selection
        |  knows nothing about DNS_ASSIGN, PREF64, assigned resolvers, or DoH
        v
B. SESSION CONFIGURATION    receives capsules, validates, publishes snapshots
   client.go                DNS_ASSIGN  -> dnsAssignmentSnapshot  (immutable)
   pref64.go                PREF64      -> pref64Store            (separate)
        |  pure state, no sockets, no goroutines, no lifecycle
        v
C. DNS POLICY PLANE         decides WHICH configuration owns a name
   dns_assignment.go        decide(name) -> unclaimed | claimed(usable) | claimed(unusable)
        |  no dialing, no HTTP, no packet handling
        v
D. DNS EXECUTION PLANE      runs the query
   dns_resolver.go          plain DNS via the native sing-box UDP transport
                            same-connection DoH via one thin executor
```

Each plane can be described without reference to the others' internals, which is the
point. The previous design had a single mutable transport that owned all four, and every
responsibility it accumulated produced its own bug.

### A. Bootstrap plane

Resolves the MASQUE **server** hostname. It runs before any tunnel exists, so it must
never consult the tunnel, the assignment, or same-connection DoH: connecting needs the
server's address, and the address cannot need the connection.

It keeps two pieces of state and nothing else:

```
lastFresh    the most recent successful resolution
lastWinner   the address that most recently completed a QUIC handshake
```

Every connection attempt resolves **fresh**, because a server can move and a network can
change. Reusing a remembered list without asking DNS again would keep dialling an address
that is no longer published, and it would fail silently: a stale address that still
answers looks exactly like success.

A fresh **success replaces** the remembered set rather than merging with it. Carrying
forward an address the fresh answer did not mention is a stale-DNS hazard: when an
operator removes an address from the record, the recovery state would put it back and we
would keep dialling it, with no TTL to expire it. A successful DNS answer is
authoritative about where the server is; the remembered set exists only to cover the case
where that answer cannot be obtained.

Candidate ordering alternates address families (RFC 8305 §4), and the winner is the
first candidate whose **QUIC handshake completes** -- not the first that creates a
socket, not the first that returns from `DialEarly`, and not the first that offers 0-RTT.
Everything that opens a socket ends in exactly one of two states: it is the winner, or it
is closed. Losers are closed before the race returns.

The candidate itself is built by `transport/http`, through a connector closure it hands
over per call. That is what keeps the UDP dial, the QUIC start and the congestion-control
installation in the transport's own order and in one place; this package owns candidate
ordering, the stagger and the winner decision, and nothing else.

### B. Session configuration plane

Two independent snapshots, because the two capsules describe unrelated things.

`dnsAssignmentSnapshot` is the compiled `DNS_ASSIGN`. It is **pure data**: it owns no
socket, starts no goroutine, and needs no `Close`. Replacing it is a single pointer store,
and an in-flight lookup keeps using the value it captured.

That immutability is load-bearing rather than stylistic. A single DNS lookup issues an
**A and an AAAA query concurrently**. If the transport read the assignment again per
query, a capsule arriving mid-lookup could answer IPv4 from one assignment and IPv6 from
the next. Capturing once makes that impossible rather than unlikely.

`pref64Store` holds the NAT64 prefixes. It is separate because PREF64 changes nothing:
this client performs no DNS64 synthesis, so the prefixes cannot affect an answer or a
transport. When they lived inside the DNS state, a PREF64-only capsule invalidated the
entire DNS cache for no reason.

### C. DNS policy plane

One pure function, answering one question: **which configuration owns this name**.

```
decide(name)
    |
    +- unclaimed             no configuration claims it
    |                        -> the ordinary DNS rules apply
    |
    +- claimed, usable       a configuration claims it and has a usable resolver
    |                        -> that configuration answers
    |
    +- claimed, unusable     a configuration claims it, but nothing can serve it
                             -> FAIL, and never fall back
```

**Ownership is decided without reference to usability.** That separation is the privacy
invariant of split DNS: a claimed name belongs to a resolver the server nominated, and
handing it to a public resolver when that resolver is unreachable would leak an internal
name at exactly the moment the internal path is broken. So an unusable resolver never
removes the claim.

Selection is longest-match on internal domains, so a configuration claiming `corp.example.`
answers `a.corp.example.` while a configuration claiming `example.` answers `b.example.`.
Matching is on a label boundary (`notcorp.example` does not match `corp.example`) and is
case- and root-dot-insensitive.

#### What an empty internal-domain list means

draft-ietf-masque-connect-ip-dns-06 §3.5 defines exactly one way to claim everything:

> Sending an empty string as an internal domain indicates the DNS root; i.e., that the
> corresponding nameserver can resolve all domain names.

So `[""]` is the root claim. The draft assigns **no** meaning to an empty list, and this
code does not invent one: `[]` claims nothing and is never selected. An earlier version
read `len(...) == 0` as "the default configuration", which silently converted unclaimed
names into claimed ones -- the difference between "resolve this publicly" and "fail
closed".

#### Before the first DNS_ASSIGN

The protocol has no capsule announcing that an assignment is coming, so before the first
`DNS_ASSIGN` arrives the client **cannot know** which names will be claimed. Until then
every name is unclaimed and resolves normally.

That is a protocol limitation, not a gap this code can close, and no timer, sleep or
readiness gate is invented to pretend otherwise. A name resolved a moment before an
assignment that would have claimed it is not a leak this implementation can prevent; it
is a property of the protocol.

### D. DNS execution plane

Execution runs one query against an **already-chosen** configuration. It does not choose a
configuration, does not hold assignment state, and does not implement DNS transports.

**Plain DNS is delegated.** `dns/transport.NewUDPRaw` already implements UDP exchange with
query multiplexing and EDNS sizing, the truncated-answer retry over TCP, TCP framing,
deadlines and lifecycle. The assigned path constructs one, pointed at the MASQUE
**device**, uses it for one exchange, and closes it. That keeps a single implementation of
the protocol instead of two that could drift, and because the transport is short-lived
there is no per-assignment socket state to own, retire or leak.

Every advertised address is tried in turn, and a resolver's advertised `port` is honoured
rather than replaced by a default.

**Same-connection DoH is the one special case.** It is not a DNS transport at all: it is
an HTTP request stream on the connection the tunnel already uses, which is why it cannot
be expressed as one.

## Transport selection, and `no-default-alpn`

| Advertised | Selected |
|---|---|
| dohpath + authentication domain, matching live tunnel H3 connection | **same-connection DoH** |
| nothing | plain **UDP**, with the TCP retry the native transport performs |
| ALPN list, no `no-default-alpn` | DoH when available and matching, else plain UDP |
| `no-default-alpn`, DoH usable | **DoH** |
| `no-default-alpn`, DoT only or nothing usable | **failure** for that resolver; try the next in the same configuration |

`no-default-alpn` is **binding**, not advisory. draft-06 §3.2 says omitting it indicates
the nameserver supports unencrypted DNS, so its presence means the opposite: falling back
to UDP port 53 would send the query in cleartext to a server that explicitly said not to.

An ALPN list **without** `no-default-alpn` is not a restriction. It names transports the
resolver also offers, and unencrypted DNS remains permitted.

An **addressless** resolver is usable when it advertises same-connection DoH and the
tunnel is H3, because the query travels as a request stream on a connection that already
exists. That is exactly the draft's §3.6.1 full-tunnel example.

DoT and DoQ are recognised and **not implemented**. Reporting that plainly is better than
silently substituting something else, because the resolver's operator chose them
deliberately. Refusing is not the same as ignoring.

## Same-connection DoH must be the SAME connection

draft-06 §3.5 asks that DoH be "coalesced over the same HTTPS connection" as the CONNECT-IP
tunnel. That is only meaningful if the tunnel really is that connection.

Two facts are therefore required, and neither is assumed from configuration:

1. **The tunnel's transport really is HTTP/3.** The configured protocol version is not the
   same fact: `transport/http` falls back to HTTP/2, so an endpoint configured for version
   3 can end up on an H2 tunnel while the HTTP/3 code path still exists. The capability is
   asked of the client that owns the connection.
2. **The request goes on the connection that exists.** The DoH path uses an
   existing-connection-only call. It never dials: a DNS query must never be the reason a
   second QUIC connection appears.

Same-origin is enforced strictly, with no cross-origin coalescing. A resolver whose
authentication domain does not match the origin the connection was verified for does not
get this path, and falls back to plain DNS if the advertisement permits it.

Origin comparison normalizes exactly what denotes the same host and nothing more: ASCII
case, and a **single** trailing root dot (the wire carries `resolver.example.` while an
HTTP authority is written `resolver.example`). A non-default port is a different origin and
is never discarded.

## SVCB validation

Service parameters are validated at the wire boundary, because a parameter that is
accepted but misread produces a resolver that looks usable and is not.

| Parameter | Rule | Source |
|---|---|---|
| `alpn` | length-prefixed pairs that MUST exactly fill the value | RFC 9460 §7.1.1 |
| `no-default-alpn` | value MUST be empty | RFC 9460 §7.1.1 |
| `port` | exactly 2 octets, network byte order; honoured when present | RFC 9460 §7.2 |
| `mandatory` | keys present, no repetition, must not list itself, all recognised | RFC 9460 §8 |
| `ipv4hint`, `ipv6hint` | **rejected** | draft-06 §3.2 |
| unknown, non-mandatory | ignored | RFC 9460 §2.4.3 |

A malformed value makes the **resolver** incompatible, and the next resolver in the same
configuration is tried. If none can be used, the query fails closed.

Two deliberate deviations from the reference implementation, both tested:

1. **Address count.** draft-06 §3.2 says that when `no-default-alpn` is omitted the address
   count MUST be nonzero -- which rejects the draft's *own* §3.6.1 example, whose nameserver
   carries `alpn=h2,h3`, no `no-default-alpn`, and zero addresses. This fork applies the rule
   only when `alpn` is **absent**. That accepts strictly more than the literal rule on
   receive, so anything the reference sends still validates, and every published example
   stays valid.
2. **PREF64 host bits.** This fork masks host bits below the prefix length; the reference
   does not. Masking is safe and stricter: RFC 6052 synthesis only reads bits within the
   prefix length, and masking makes the stored value compare equal across differently-padded
   encodings of the same prefix.

`ipv4hint` and `ipv6hint` are rejected per draft-06 even though RFC 9461 permits them
generally, because draft-06 is the direct specification for this extension.

## `dohpath`

RFC 9461 §5 defines `dohpath` as a **relative** URI Template that must contain the `dns`
variable, and RFC 8484 §4.1 says the template is processed **with no variables defined**
for a POST. So an expression expands to the empty string, including its own `?` or `&`:

```
/dns-query{?dns}  ->  /dns-query
/q{?dns}suffix    ->  /qsuffix
```

Truncating at the first `{` happens to give the right answer for the first case and the
wrong one for the second, so the expansion is implemented rather than approximated.

Nothing is invented. An empty template, a missing leading slash, or a template with no
`dns` variable makes the resolver incompatible: guessing a path the server did not send is
worse than reporting that its advertisement is unusable.

## DoH wire details

- Requests carry **DNS ID 0** (RFC 8484 §4.1), on a copy of the wire bytes, so the caller's
  message is never mutated. The caller's ID is restored on the reply, because the DNS client
  sent the query with that ID and matches the response against it.
- Any **2xx** status is a success (RFC 8484 §4.2.1), not only 200.
- The response media type is validated with MIME parsing, so an HTML error page from an
  intercepting proxy is reported as a media-type mismatch rather than as a corrupt DNS
  message. An absent header is tolerated: the RFC sets no MUST for it.
- Responses are bounded, with one byte read past the ceiling so an oversized message is
  reported as oversized.

## Cache identity

A configuration-bound transport reports an `Environment()` derived from **effective
resolver behaviour**: the claims, the resolvers, their metadata, and the transport each one
will actually use.

It contains no monotonic generation counter, so:

- receiving the same `DNS_ASSIGN` twice does **not** invalidate a cache;
- a `PREF64`-only update does **not** invalidate the DNS cache;
- a route change that makes a resolver unreachable **does**, because that changes where
  queries go.

TTL handling, caching, negative caching, singleflight and optimistic caching remain entirely
the sing-box DNS client's responsibility. The assignment layer never reimplements them, and
the bootstrap recovery state is not a DNS cache.

## Ownership

```
bootstrap DNS state             owns no socket
DNS assignment snapshot         owns no socket, no goroutine, no Close
configuration transport         owns no long-lived socket
plain DNS per-attempt transport owns only that query's sockets
transport/http                  owns the HTTP/3 ClientConn
transport/masque session        owns the CONNECT-IP stream
DoH executor                    owns only its request stream
```

No layer needs a refcount, a retirement queue or delayed cleanup, because nothing that owns
a resource is replaceable state.

## Testing

Component tests build the thing under test themselves and therefore cannot tell whether
production can reach it. These call real entry points:

| Area | Where |
|---|---|
| **Production wiring** (constructor-level) | `protocol/masque/constructor_integration_test.go` |
| **Policy and compilation** (snapshots, root semantics, transport selection) | `protocol/masque/dns_assignment_test.go` |
| **Endpoint routing** (unclaimed / claimed / claimed-unusable, snapshot consistency) | `protocol/masque/dns_endpoint_test.go` |
| **Bootstrap and racer** | `protocol/masque/bootstrap_cache_test.go`, `bootstrap_race_test.go`, `bootstrap_race_ownership_test.go` |
| Capsule codecs and bounds | `transport/masque/capsule_dns_test.go` |
| Server emission and ordering | `transport/masque/server_dns_test.go` |
| Fuzzing (capsules, SVCB, PREF64, round trip) | `transport/masque/fuzz_dns_capsule_test.go` |
| Generic H3 requests and same-origin | `transport/http/client_h3_request_test.go` |
| One-connection proof against a real server | `transport/http/client_h3_same_conn_test.go` |

## Known limitations

- **Endpoint-local only.** No global OS or VPN DNS integration, as described at the top.
- **Search domains are preserved, not applied.** They are parsed and kept in the snapshot so
  a future integration has them, and so discarding parsed configuration is not silent.
  Nothing installs them.
- **Claims before the first `DNS_ASSIGN` are unknowable.** See the temporal note above.
- **PREF64 is state only.** No DNS64 synthesis of any kind.
- **No DoT, no DoQ.** Recognised and refused, never silently substituted.
- **No same-connection DoH over HTTP/2.** A resolver offering only h2 with
  `no-default-alpn` is incompatible.
- **No cross-origin HTTP/3 coalescing.**
