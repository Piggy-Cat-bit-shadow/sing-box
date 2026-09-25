# MASQUE reference audit

Maintenance record for the MASQUE server audit run on the experimental branch
`masque-reference-hardening`. It states what was verified, what was changed, and
what remains unverified. It is not a compatibility claim beyond what the tests
show.

## Baseline

| Item | Value |
| --- | --- |
| BASE_SHA | `96eafce9b9f0ad5fee4c15a223c1baa7d769b465` |
| Branch | `masque-reference-hardening` (experimental; not merged) |
| Scope | the MASQUE server in this repository only |

## Standards consulted

| Document | Use |
| --- | --- |
| RFC 9297 | HTTP Datagrams and the Capsule Protocol |
| RFC 9298 | CONNECT-UDP |
| RFC 9484 | CONNECT-IP, including section 4.2.1 / 4.7.3 route rules |
| RFC 9931 | HTTP/1.1 optimistic protocol transitions; section 8 adds a server-side MUST that this audit found unmet |

## Pinned references

Reference sources are pinned by commit so the comparison cannot drift. Both were
cloned at these revisions during this audit:

| Reference | Commit | Module pin actually used |
| --- | --- | --- |
| quic-go/masque-go | `c1cf0e4dd6439aea94d5491b27439a4736f00246` | `v0.6.0` |
| quic-go/connect-ip-go | `fdd945e3d6009b3cee1b1a66493776d315727549` | `v0.4.1-0.20260924175820-fdd945e3d600` |
| Google QUICHE | NOT-TESTED (see below) | - |

The two pins are not the same kind of pin, and the difference was measured rather
than assumed:

- For masque-go the audited commit **is** the `v0.6.0` tag. `go list -m -json
  github.com/quic-go/masque-go@c1cf0e4dd…` reports version `v0.6.0` with
  `Origin.Ref refs/tags/v0.6.0`, so requiring the tag pins that exact revision and
  no pseudo-version is needed.
- For connect-ip-go the audited commit is untagged, so it is pinned through a
  `replace` to its pseudo-version. A plain `require` was tried first and `go mod
  tidy` silently replaced it with `v0.4.0`, which is **not** the audited revision;
  `replace` cannot be dropped that way.

Google QUICHE was **not** built or run. No interop result is claimed for it.

## Changes made in this audit

### ROUTE_ADVERTISEMENT overlap across protocols (RFC 9484)

Non-overlap was derived from the ordering rule, which only compares consecutive
ranges at the SAME protocol. Every cross-protocol overlap was therefore accepted,
including the case RFC 9484 forbids: 192.0.2.0-192.0.2.255 at protocol 0 followed
by the same range at protocol 6. Protocol 0 means ALL protocols in
`RoutesContain`, so that advertisement describes the same traffic twice and the
effective policy depends on lookup order.

Fixed. The overlap check now compares against the ranges the ordering rule cannot
reach, and the first version of the fix was itself corrected: it scanned every
earlier range and was quadratic, so a 1 MiB capsule of single-address ranges took
13.5 seconds to reject against 16 ms before. The linear form uses a per-protocol
high-water mark, and `TestRouteAdvertisementValidationIsLinear` pins the cost so
the quadratic version cannot return.

### Control capsule entry bounds

The capsule size limit alone allowed 149,796 ADDRESS_ASSIGN entries in one 1 MiB
capsule, retaining 17.65 MiB of parsed state. Measured, not assumed:
`AssignedAddress` is 40 bytes, so the size limit permits 5.24 MB of control state
from one capsule. Bounded at 8192 addresses and 8192 routes per capsule, the value
quic-go/connect-ip-go uses; RFC 9484 states no number, so this is HARDENING.

### MASQUE HTTP/3 QUIC defaults

Three properties were pinned away from the library default. None is what either
reference does - masque-go and connect-ip-go both set only `EnableDatagrams` and
`InitialPacketSize`, leaving everything else to quic-go:

| Property | Before | After |
| --- | --- | --- |
| MaxIncomingStreams | `1 << 60` (quic-go's internal unlimited clamp) | unset, so the default of 100 applies; `max_concurrent_streams` still overrides |
| DisablePathManager | forced `true` | default (manager enabled); opt-in via `quic_disable_path_manager` |
| Congestion control | forced BBR standard | library default; opt-in via `bbr_profile` |

Native Naive is unaffected: it has its own `nativeNaiveQUICConfig` and does not
use this path.

### CONNECT-UDP request path

The RFC 9298 default template is supported and its decisions are now pinned by a
22-case corpus. Arbitrary URI templates are deliberately NOT configurable; RFC
9298 permits an endpoint to define one, so this is a supported-scope decision
rather than an incompleteness.

One recorded decision: an encoded slash in the host segment decodes into the host,
which cannot resolve. It is not a traversal, because segments are split before
unescaping.

### HTTP/1.1 CONNECT rejection and connection reuse (RFC 9931)

RFC 9931 section 8 requires a proxy server to close the underlying connection
when it rejects a CONNECT, "without processing any further requests on that
connection", and states the requirement "applies whether or not the request
includes a 'close' connection option". This was added to RFC 9112 and RFC 9298.

sing-box did not do it. The HTTP/1.1 CONNECT and CONNECT-UDP rejection paths
passed `requestKeepAlive(request)` to the reject helper, so a client that asked
for keep-alive kept the connection and the server read the next request off it.

Reproduced before the fix, on the wire, rather than inferred from reading: a
CONNECT with no credentials followed immediately by a second well-formed request
produced **two** `407` responses on one connection. That second response is the
request-smuggling primitive, and it needs no attacker-controlled payload to
trigger -- the attacker's bytes simply become a request the client is deemed to
have made.

Fixed by rejecting without keep-alive on the two paths that involve a protocol
transition. Ordinary rejected requests still honour keep-alive, because no
transition was requested and the shape does not arise.

HTTP/2 and HTTP/3 are deliberately unaffected. RFC 9931 scopes the requirement to
HTTP/1.1 and recommends the newer versions as the way to avoid its cost, since a
rejected request there has an explicit stream and cannot leave a second request
half-read on a shared byte stream. A control test asserts the opposite outcome for
HTTP/2: after a rejected CONNECT the same connection still serves a further
request.

Accepted cost: the RFC notes the mitigation "will frequently cause slower
connection establishment ... especially when returning a 407", because a
compliant client must reconnect and redo the TLS handshake. That is paid only on
the rejection path.

### Contains() disagreed with lookup() about the server's own address

`Contains()` backs `PreferredAddress`, which a `preferred_by` routing rule uses to
decide whether this MASQUE endpoint should carry a destination. `lookup()` already
refused the server's own address inside the tunnel prefix before consulting any
route advertisement - that address belongs to the server, not to a client.
`Contains()` did not apply the same guard, so it reported the server's own address
as tunnel-owned as soon as any session advertised a route covering it, which is
the normal case because a client advertises the tunnel network.

Found by asserting the two answers against each other rather than by reading
either one. The impact is a routing decision, not a misdelivery, and the
distinction matters: `lookup()`'s guard still stopped the packet from reaching a
session, so no client received traffic addressed to the server. What went wrong is
that the destination was advertised as preferred by this endpoint, the packet was
routed into the MASQUE path, and `lookup()` then found no session for it.

Fixed, and reverting just this guard fails the test, so it is load-bearing rather
than defensive decoration.

## Verified without change

- The capsule size limit fires correctly: a declared length above
  `MaxCapsuleLength` is refused with "capsule too large", including `1 << 40`.
- Malformed capsule framing (truncated type varint, truncated length varint,
  zero-length unknown capsule) returns an error rather than panicking, hanging or
  allocating without bound.

## Verified in process, against a real peer

These results do not need a third-party reference: they drive a purpose-built
peer whose relevant capability is configurable, and assert on bytes that crossed
a real socket.

| Case | Result |
| --- | --- |
| H3 DATAGRAM to Capsule fallback: a peer that does NOT advertise `SETTINGS_H3_DATAGRAM` receives the payload as a DATAGRAM capsule (type 0x00) on the request stream | PASS |
| The same payload to a peer that DOES advertise datagram support comes back as a datagram, so the fallback is conditional rather than the only path | PASS |
| The server always advertises `SETTINGS_H3_DATAGRAM` and extended CONNECT, whatever the client offers | PASS |
| RFC 9931 section 8: a rejected HTTP/1.1 CONNECT closes the connection and the following request is NOT processed | PASS (was FAIL) |
| RFC 9931: the same for a rejected HTTP/1.x CONNECT-UDP upgrade | PASS |
| RFC 9931: HTTP/2 is unaffected, so a rejected CONNECT leaves the connection usable | PASS |
| The address pool never assigns the network, server or broadcast address, and reports exhaustion instead of wrapping | PASS |
| 1000 sequential allocate/release cycles over a /24 all succeed (the leak case) | PASS |
| An address ASSIGNED to one session beats a route another session merely ADVERTISED, even when the interloper registered second | PASS |
| A late teardown of a closed session cannot delete the ownership entry of the session holding the recycled address | PASS |
| Route advertisements respect the protocol number | PASS |
| Four fuzz targets (capsule framer, ROUTE_ADVERTISEMENT, ADDRESS_ASSIGN, URI-template matcher) survive a bounded real fuzz run | PASS, ~3.3M inputs, no crash |

The DATAGRAM fallback tests were checked against an injected regression:
disabling the fallback in `transport/http/capsule.go` makes the fallback test fail
immediately and it passes again once restored.

That experiment also showed there are **two** fallback sites serving different
protocols - `transport/http/capsule.go` for CONNECT-UDP and
`transport/masque/session.go` for CONNECT-IP - so a test that exercises one says
nothing about the other. Which one is covered is stated with the result.

## Verified against the pinned references

These are the external-interoperability results. "External" means the client on
the wire is the pinned third-party library, not sing-box's own client: running
sing-box against itself would only prove that sing-box agrees with sing-box.

The tests live in `test/jiejie/reference`, a **separate Go module**. Verified
that neither package appears in the production dependency graph
(`go list -tags $PRODUCTION_TAGS -deps ./cmd/sing-box` names neither
`quic-go/masque-go` nor `quic-go/connect-ip-go`), and that neither the root
`go.mod` nor `test/go.mod` changed.

| Case | Reference client | Result |
| --- | --- | --- |
| CONNECT-UDP over HTTP/3, real datagram to a loopback origin and the origin's reply read back | masque-go | PASS |
| CONNECT-UDP with no credentials is refused | masque-go | PASS |
| HTTP/3 settings carry Extended CONNECT and datagram support | masque-go | PASS |
| CONNECT-IP tunnel established; ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT parsed | connect-ip-go | PASS |
| CONNECT-IP with no credentials is refused | connect-ip-go | PASS |
| CONNECT-IP carries a real IPv4 + ICMP packet and returns the matching answer | connect-ip-go | PASS |

Measured values from the CONNECT-IP run: the client is assigned `198.18.0.2/32`
and the server advertises `198.18.0.0/24` with protocol 0.

### CORRECTED in Phase 3: the gateway ICMP result was a fixture bug

Phase 2 recorded this claim:

> sing-box's internal IP stack answers an echo request sent to the tunnel gateway
> by echoing the request back (ICMP type 8, the request type) rather than emitting
> a type-0 echo reply.

**That claim was wrong, and the ICMP data-path test was wrong with it.** The
fixture derived its destination as

```go
gateway := source.Masked().Addr()
```

where `source` was the assigned prefix. The server assigns a **/32**
(`198.18.0.2/32`), so `Masked()` returns `198.18.0.2` - the **client's own
address**. The echo request was therefore addressed to the client itself and never
reached the gateway. The stack echoed it back as type 8, and that artifact was
recorded as server behaviour.

Measured on the wire in Phase 3, both destinations side by side:

| Destination | Reply |
| --- | --- |
| `198.18.0.2` (client's own /32) | ICMP type **8** echoed back, `src == dst == 198.18.0.2` |
| `198.18.0.1` (the real gateway) | ICMP type **0** echo reply, `src=198.18.0.1`, `dst=198.18.0.2` |

So nothing was wrong with the server. It answers a gateway echo request in the
conventional way; Phase 2 simply never asked it to.

What the Phase 2 test did prove, and what it did not:

- **It proved** HTTP Datagram framing, the context-ID-0 path, the session return
  path and that the client can read what the server writes back.
- **It did not prove** a server-side IP round trip, because no packet ever reached
  the server's IP stack as a destination.

The destination now comes from a single named constant
(`connectIPServerGateway`) shared by the driver and the assertion, and the test
asserts `source.Addr() != gateway` explicitly, because deriving a /24 gateway from
a /32 assignment is the mistake being locked out. A destination-unreachable or
packet-too-big answer still fails, since those carry no echo identifier.

### The interop tests fail when the implementation is broken

A green test that cannot fail is not evidence, so the harness was checked against
an injected regression: a one-line off-by-one added to the CONNECT-UDP target port
in `transport/http/connect_udp.go`. The masque-go interop failed on it and passed
again once the source was restored. Pointing the harness at a binary that is not a
sing-box server also fails rather than passing.

### CONNECT-IP needs the full registry

`masque-server` is registered only by `include/registry.go`; the production minimal
registry registers **no** endpoints. A CONNECT-IP test built against the production
binary therefore fails with a QUIC handshake timeout that reads like a protocol
bug, so the fixture requires a full-registry binary and reports NOT-TESTED with a
reason otherwise. It also declares `masque-server` as an **endpoint**: the
configuration decoder rejects it as an inbound ("unknown inbound type:
masque-server"), which is correct rather than something to work around.

## Remaining NOT-TESTED

Listed so the gaps are not mistaken for coverage. None of these has a passing test,
and none is claimed as PASS:

- **DATAGRAM context IDs other than 0.** The framer and the zero-context-ID path are
  covered by fuzzing and by the fallback tests, and the size accounting is pinned at
  every varint boundary. What is NOT covered is the receiver's handling of a
  nonzero context ID arriving on a live tunnel: the code drops unknown contexts by
  inspection, but no test drives one through and then confirms a subsequent
  context-0 datagram still works.
- **Loss, reordering and duplication.** A UDP impairment relay was not built, so the
  behaviour of a CONNECT-UDP or CONNECT-IP tunnel under packet loss, reordering or
  duplication is unmeasured. The datagram paths are lossy by design and the capsule
  fallback is a reliable stream, but neither claim is tested.
- **ICMP Packet Too Big for oversize IP packets.** The size at which a datagram is
  rejected in favour of an ICMP error is computed and unit-tested; the ICMPv4
  Fragmentation Needed and ICMPv6 Packet Too Big packets the endpoint GENERATES for
  an oversize inner packet were not driven end to end.
- **Proxy-Status beyond the DNS path.** PARTIAL, not absent: the DNS resolution
  failure is implemented and tested, while the other rejection paths (address pool
  exhausted, policy forbidden, internal error) return a bare status code and were
  not audited against RFC 9209.
- **Google QUICHE interop.** Not built or run. No interop result is claimed.
- **RFC 9931's client-side half.** Section 8 tells proxy CLIENTS to wait for a 2xx
  before forwarding TCP payload or to send `Connection: close`, and section 6.3
  forbids optimistic UDP sending over HTTP/1.x. Those requirements bind a client;
  this repository's HTTP client was not audited against them.

Closed in Phase 3, removed from this list: the CONNECT-IP capsule fallback, the IP
packet parser fuzz target, IPv6 extension-header protocol resolution, send-queue and
capsule write backpressure, and active-tunnel shutdown. QUIC migration and source
identity after a path change are CLOSED for CONNECT-UDP and CONNECT-IP as recorded
above.

Two narrowings stated rather than implied, because collapsing them is how a
NOT-TESTED item becomes an implied PASS:

  - the IP packet parser IS fuzzed and IPv6 extension chains ARE regression-tested,
    but the fragment case reports the base header's protocol rather than a derived
    one. That behaviour is recorded, not certified correct.
  - migration is measured against a NAT rebind produced below the QUIC layer. Path
    validation itself is quic-go's and is not reimplemented or independently
    verified here.

## Phase 3

Phase 3 continued on `masque-reference-hardening-phase3`, branched from the Phase 2
head. Its scope was the areas Phase 2 identified as NOT-TESTED, plus a correction to
a Phase 2 claim that turned out to be wrong.

### The Phase 2 gateway ICMP claim was a fixture bug, now corrected

Phase 2 recorded that sing-box's IP stack "echoes the request back" as ICMP type 8
for a gateway echo request. That measurement was an artefact of the test, not
behaviour of the server: the fixture derived its destination as
`source.Masked().Addr()`, and because the server assigns a **/32** that expression
returns the CLIENT's own address. No packet ever reached the gateway.

Measured side by side in Phase 3:

| Destination | Reply |
| --- | --- |
| `198.18.0.2` (client's own /32) | type 8 echoed back, `src == dst` |
| `198.18.0.1` (the real gateway) | type 0 echo reply, `src=198.18.0.1`, `dst=198.18.0.2` |

The server implements gateway ping conventionally. The destination now comes from a
single named constant shared by driver and assertion, and the test asserts
`source != gateway` explicitly. See the CORRECTED section above for what the old
test did and did not prove.

### CONNECT-IP carries traffic without HTTP Datagrams

The CONNECT-IP half of the RFC 9297 capsule fallback had never been exercised,
because every available client negotiated datagrams. A peer built directly on
quic-go's HTTP/3 API with `EnableDatagrams` false now proves: ADDRESS_ASSIGN and
ROUTE_ADVERTISEMENT arrive as capsules and parse, an IPv4 + ICMP packet travels
client to server as a DATAGRAM capsule and reaches the IP stack, the reply returns
as a capsule, and the tunnel survives a SECOND exchange. A counter-case requires a
datagram-capable peer to receive its answer over the datagram path, so the fallback
is proven conditional rather than being the only path.

Three capsule-encoding details were initially guessed wrong and are now documented
from measurement: ADDRESS_ASSIGN entries have no leading count, the address length
byte is a BYTE count (4 or 16) rather than a family marker, and
ROUTE_ADVERTISEMENT writes a length byte before the START address only - the end
address is raw, and reading a length byte before it shifts every following byte.

### A suspected datagram defect did NOT reproduce

Phase 3 began with a hypothesis that a session inferring datagram capability from a
type assertion would run a receive loop that consumed capsule bytes and could cancel
the session. **Measured, it is false.** The CONNECT-IP fallback passes with and
without the change (5/5 runs unfixed), an active fallback tunnel shows an identical
goroutine count either way (base 2, during 9), and the server-side implementation is
quic-go's `StateTrackingStream.ReceiveDatagram`, which reads a dedicated datagram
queue rather than the DATA stream. The method that reads from the stream is
`Stream.ReceiveDatagram`, a different type.

The capability method added to `DatagramStream` is therefore HARDENING - the session
now decides from the peer's SETTINGS rather than from a type - and is committed and
documented as such, not as a bug fix.

### QUIC migration is live and works

Enabling the path manager in Phase 2 made migration production behaviour. A UDP NAT
relay (no rebind API exists in quic-go, and patching it was out of scope) changes the
source address the server observes, below the QUIC layer. Measured: an existing
CONNECT-UDP tunnel survives a rebind on the same connection object, a NEW tunnel
opens afterwards while the old one keeps working, a CONNECT-IP tunnel survives and
still answers real IP packets, and opaque unrelated traffic does not disturb an
established authenticated tunnel.

One measured behaviour drives the test design: the FIRST exchange after a rebind is
lost while path validation runs, and the second succeeds. That is RFC 9000 section 9
behaviour, so the tests retry within a bounded window and log the attempt number.
A single-attempt test reports "migration is broken" for correct code.

### Malformed IP headers panicked the parser (unreachable, fixed anyway)

Two fuzz targets were added for inputs Phase 2 left unfuzzed: the IP packet parser
and capsule stream fragmentation. `FuzzMasqueIPPacketParser` crashed on its first
run, three ways, all in `decrementHopLimit`: a 4-byte IPv4 prefix, a version nibble
that is neither 4 nor 6 (the code treated "not IPv4" as IPv6), and an IHL declaring
fewer bytes than the fixed header.

**Not reachable in production**: both call sites are preceded by `packetAddresses`,
which rejects a short packet and releases the buffer before `decrementHopLimit` runs.
Verified concretely rather than assumed. It is fixed because the failure mode is a
panic in a network-facing parser that currently depends on a guard in a different
function. After the fix, sustained fuzzing is clean: 1.26M executions for the IP
parser, 770K for fragmentation.

### IPv6 extension headers

Seven chain shapes now resolve correctly to the upper-layer protocol (UDP 17 / TCP
6), and six malformed shapes are rejected without panicking. The walk is performed
by sing-tun's `header.IPTransportProtocol`, which is pinned as a dependency; these
tests lock the behaviour rather than reimplementing the parser.

**One measured result, recorded rather than changed**: a NON-FIRST fragment reports
protocol 17, the base header's value, because the chain walk stops at the fragment
header. A non-first fragment genuinely carries no upper-layer header, so no protocol
can be derived from it - but a route rule keyed on protocol does see the base
header's value for fragmented traffic. Changing that would mean reimplementing
sing-tun's parser or diverging from it.

### Proxy-Status is PARTIAL

The audit previously said "Not implemented", which was inaccurate: the DNS
resolution failure already emits `Proxy-Status: sing-box; error=dns_error`. One of
six rejection paths carries it. Searched the repository exhaustively rather than
sampling.

The authentication boundary is now pinned: an authenticated DNS failure carries the
header, while unauthenticated, wrong-credential, masquerade and over-limit requests
carry none and no upstream failure status.

One measured difference: an unauthenticated request to the `masque-server`
**endpoint** is answered with a bare 401 and a `WWW-Authenticate` challenge, NOT with
a masquerade decoy. The `http` **inbound** has a masquerade option; the endpoint
defines no such field. An anti-fingerprinting assertion copied from the inbound tests
does not apply here.

## Out of scope

Not implemented and not planned here: CONNECT-ETHERNET, Concealed Auth,
CONNECT-UDP-BIND, Compression Assign, DNS_ASSIGN, PREF64, and experimental
drafts.
