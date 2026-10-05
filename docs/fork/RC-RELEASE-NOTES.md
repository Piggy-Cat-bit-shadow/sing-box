# RC release notes (draft)

Written for people who use the client, not for people who read the diff. Every claim here is one
the repository can support today; where something is a research result rather than a shipped
behaviour, it says so.

## Load balance outbound group

A new outbound type that spreads **new connections** across several outbounds.

```json
{
  "type": "loadbalance",
  "tag": "balanced",
  "outbounds": ["hk", "jp", "sg"],
  "strategy": "round_robin"
}
```

- **`round_robin`** (default) gives each new connection the next member. A connection keeps its
  member for its whole life; a UDP session keeps its member for the whole session, not per packet.
- **`consistent_hashing`** keeps the same destination on the same member, so a site that opens many
  connections to one host does not land on a different member each time. The key is the
  registrable domain, falling back to the literal address.
- **`sticky_sessions`** keeps a source+destination pair on one member for ten minutes, bounded to
  1000 pairs.

Adding `url` (and optionally `expected_status`) makes membership health-aware through the same
measurement the existing `urltest` group uses: a member that is known to be failing is skipped for
new connections and returns to the pool when it recovers. A member with no measurement yet is not
treated as dead.

What it is **not**: it does not combine bandwidth. It does not stripe a single connection across
members, and no single connection is ever faster because of it. It chooses which outbound carries
each connection, which is what makes several servers usable together rather than one at a time.

## Traffic class

Flows can be classified as `default`, `interactive`, `bulk` or `realtime` by route rules - either
explicitly per outbound/rule, or automatically from the flow's own behaviour - and the
classification is what later stages act on. Explicit rules win, and an explicit `default` suppresses
automatic classification for that flow.

## Traffic scheduler

An aggregate pacing layer that can hold a flow's upload to a rate, so that several flows share one
uplink instead of each behaving as if it had the link to itself. `FixedRate` is the shipped
algorithm. The adaptive variant is **research only** and is not enabled by the product.

## Direct correctness and performance

The direct outbound gained a semantic profile that decides per flow whether the native path is
equivalent to a userspace copy, and fails closed when it cannot prove it. A flow that qualifies
takes the kernel's own path; everything else behaves exactly as before. This is where the fork's
TCP splice diagnostics come from: a real-device run can now report, per transport, whether flows
were handed to the socket or fell back.

## DNS and FakeIP hardening

- DNS is resolved and hijacked in a fixed order relative to routing, so a query cannot be diverted
  by a later routing decision, including by a load balance group that selects `direct`.
- A destination arriving as a **v4-mapped IPv6 address** (`::ffff:a.b.c.d`) is canonicalised at the
  ingress boundary, so it matches DNS addresses, FakeIP ranges, route sets and CIDR rules written
  in the four-byte form. This fixed a real policy fail-open: those comparisons silently returned
  false for the mapped spelling.
- Only the mapped form is canonicalised. NAT64 (`64:ff9b::/96`) and the deprecated IPv4-compatible
  form keep their IPv6 identity, so a NAT64 destination is still dialed as IPv6.

## Protocols

VLESS, AnyTLS, Naive, MASQUE, Hysteria2, TUIC, ShadowTLS, WireGuard, OpenVPN and the rest of the
inherited protocol set are present in this build. Two carry fork work: Naive (the cronet engine and
its padding codec, with the native library pinned to the fork's archive) and MASQUE (CONNECT-UDP
with the fork's inner-Happy-Eyeballs behaviour).

## Apple client

The iOS and macOS clients are built from this fork's branch of the SwiftUI client. This round
restyled the secondary destinations - profiles, groups, connections, reports, remote control, logs -
and the desktop detail column around the shared design language, and fixed a routing case where a
page selected as a child destination at launch could be selected without ever being shown. The
kernel, tunnel, libbox bridge, profile format and signing layout are untouched.

## Scope of this release

- **Linux** (amd64, server profile) and **Apple** (iOS, macOS).
- The Linux Naive client remains subject to a known static-link limitation; the shipped Linux
  profile does not include it.

## Known limitations

- Ordinary TUN traffic cannot use the OS-level bypass; the fast path applies to direct flows only.
- The adaptive scheduler is research only.
- The splice diagnostics report *that* a handover was declined, not why: the underlying call returns
  a boolean.
- Real-device validation of the instrumentation is prepared but not yet executed - see
  `RC-DEVICE-CHECKLIST.md`.
