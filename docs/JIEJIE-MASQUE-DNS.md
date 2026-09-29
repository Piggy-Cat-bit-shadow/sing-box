# MASQUE DNS: the three resolvers and what bounds each one

This is an engineering contract for how DNS works on the Jiejie MASQUE client. It
exists because MASQUE has **three distinct DNS roles** that are easy to conflate,
and conflating them produces either a bootstrap that depends on the tunnel it is
supposed to establish, or a resolution path that silently bypasses the sing-box
DNS router.

Only the first two roles are implemented today. The third is scoped and specified
here so the next round does not have to rediscover the boundaries.

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

| Role / feature | Status |
|---|---|
| A. Bootstrap resolver (`domain_resolver`) | **existing**, unchanged |
| A. Bounded fresh resolve + last-known-good cache | **NOT IMPLEMENTED** |
| A. QUIC handshake-level happy eyeballs | **NOT IMPLEMENTED** |
| B. Inner resolver (`inner_domain_resolver`) | **implemented** |
| B. TCP happy eyeballs | **implemented** |
| B. UDP selection stays serial | **implemented (deliberate)** |
| C. DNS interception | existing, unchanged |
| DNS_ASSIGN capsule | **NOT IMPLEMENTED** |
| PREF64 capsule | **NOT IMPLEMENTED** |

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
server-pushed DNS_ASSIGN         (not implemented yet)
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

## Not implemented, and what they would need

### A. Bounded fresh resolve + last-known-good cache

Today a resolver outage during a reconnect storm is unrecoverable: `loop()` retries
with a 1s→1m backoff and re-resolves from scratch every time, with no fallback.

The intended design, for whoever picks this up:

- an in-memory, **bounded** (≈8–16 addresses, deduplicated) per-endpoint candidate
  set: `{candidates, winner}`;
- fresh-first ordering: `fresh ++ (cached \ fresh)`, so a winner from the previous
  network never outranks a fresh answer;
- when fresh lookup fails, times out, or returns empty, fall back to the cache with
  a **bounded** fresh timeout (~3s) rather than the system resolver's 20–30s;
- promote a candidate to the front of the cache once it actually completes a
  connection;
- **keep the cache across `RestartSession`** (clearing it would defeat the purpose)
  and release it only on endpoint close.

This cache is **connection-recovery** state, not a DNS cache. It must not duplicate,
replace or shadow the sing-box DNS cache.

### A. QUIC handshake-level happy eyeballs

The critical constraint: **a UDP socket connect is not a winner.** A reachable UDP
path is not a reachable QUIC endpoint. Candidates must be raced at the **QUIC
handshake** level, staggering ~250–300ms apart, and the winner is the first candidate
that *completes* the handshake — not the first that creates a socket, not the first
that returns a `DialEarly` object, and not the first that returns 0-RTT data. Session
resumption must be preserved; it just does not decide the race.

### DNS_ASSIGN and PREF64

Reviewed against `quic-go/connect-ip-go@v0.4.1-0.20260924175820-fdd945e3d600`, which
implements `draft-ietf-masque-connect-ip-dns-06`:

| Capsule | Type ID | Wire shape |
|---|---|---|
| `DNS_ASSIGN` | `0x1ace79ec` | repeated DNS Configuration: nameserver count, then per-nameserver `{priority u16 BE, v4 count + 4-byte each, v6 count + 16-byte each, auth domain (varint len + bytes), SVC params (varint len + key/value pairs)}`, then internal domains, then search domains |
| `PREF64` | `0x274c0fbc` | N × 13 bytes: 1-byte prefix length ∈ {32,40,48,56,64,96} + exactly 12 address bytes, always 12 regardless of prefix length |

Both are **declarative latest-state**: each capsule supersedes the previous one
rather than appending. Values are provisional in the draft and will change before
publication, so they must stay named constants.

The reference does **not** implement DNS64 synthesis; it only transports the
configuration. Anything this fork adds there is a local design choice with no
reference behaviour to match.

## Cycle and leak rules

- Role A must never reach the MASQUE endpoint. A cycle test belongs with any future
  bootstrap-cache work.
- Server-pushed resolvers must be reachable **through the tunnel** and must fail
  closed. A server-pushed address must never cause a cleartext query from the host
  interface.
- Same-connection DoH (if ever added) must reuse the existing HTTP/3 connection's
  request streams — never open a second QUIC connection, and never carry DoH inside
  the CONNECT-IP capsule stream.
