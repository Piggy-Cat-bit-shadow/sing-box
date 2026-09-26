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

  **RECLASSIFIED as OUT-OF-SCOPE-FOR-SERVER-PRE-VPS**, not left as an open NOT-TESTED
  item. This fork ships exactly one product - a Linux amd64 VPS SERVER - and the
  production minimal registry serves no MASQUE client endpoint (`EndpointRegistry()`
  registers none). A client-side obligation that no shipped component can violate is
  not a gap in this product's coverage; keeping it on the NOT-TESTED list would imply a
  debt that no planned work would repay. It becomes relevant only if a client product is
  ever added, at which point the obligation moves to that product's scope.

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

**CORRECTED in the Pre-VPS closure round.** This section previously stated that a
NON-FIRST fragment "reports protocol 17, the base header's value, because the chain walk
stops at the fragment header". **That was wrong, and the test that produced it was
producing a different packet than its name claimed.**

Two separate defects, both now fixed:

1. The fixture's packet builder used `nextHeader == 0` as an "unset" sentinel, but 0 is
   the real and only legal Hop-by-Hop value. The base header's Next Header was therefore
   ALWAYS written as 0 regardless of the chain, and an explicit Hop-by-Hop entry was
   silently rewritten to point at the next entry. The packet the old test called "a
   non-first fragment" was actually `Hop-by-Hop -> Fragment(non-first)`.
2. The claim itself misdescribes the dependency. The pinned sing-tun does not read the
   base header's field at that point: `skipIPv6ExtensionHeaders` returns at the fragment
   header (`flow_parse.go`, `case header.IPv6FragmentExtHdrIdentifier: return protocol,
   payload, true, false`), and `IPTransportProtocol` then takes **the fragment header's own
   Next Header** (`icmp_error.go`, `protocol = payload[0]`). The old claim looked right only
   because both fields coincidentally held 17 in the mis-built fixture.

Measured with a discriminator packet in which the two fields differ - base Next Header 43
(Routing), fragment Next Header 6 (TCP) - the resolver returns **6**, i.e. the fragment
header's field. A non-first fragment naming an extension header (0, 43, 60, 44) is
REJECTED. See `transport/masque/ipv6_extension_chain_test.go`.

The rest of the section stands: the walk is sing-tun's, it is pinned as a dependency, and
these tests lock its behaviour rather than reimplementing it. What changed is that the
recorded result now describes what the dependency actually does.

The old fixture's other limitation is also recorded, because it hid coverage: EVERY
Hop-by-Hop, Routing, Destination-Options, Fragment and multi-header case in it was
byte-identical in the base header, so the chain walk was never exercised from a non-zero
entry point.

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

## Pre-VPS Final Closure

This section records the last code-closure round before Linux amd64 VPS acceptance. Its
purpose was NOT to add MASQUE features. It was to finish the correctness, security,
resource-bound, lifecycle, protocol-boundary and test-evidence work that can be done
locally, in CI, or against the reference implementations.

### Baseline corrected

The document header used to describe the audit branch as `masque-reference-hardening`
and marked it "experimental; not merged". **That is no longer true and the header has been
corrected**: the MASQUE hardening is merged into `testing`, which is the fork's main
development branch, and the VPS work continues from there. The Phase 1 / Phase 2 / Phase 3
history above is retained rather than rewritten; this section is the current state.

| Item | Value |
| --- | --- |
| Branch | `testing` (main development branch; MASQUE hardening merged) |
| Phase 1 head | `d159ec09d` |
| Phase 2 head | `67e55b387` |
| Phase 3 head | `419a7e2ef` |
| Pre-VPS closure base | `419a7e2ef` |

### Production bugs found in this round

Exactly one. It is a real defect with a failing regression, not a hardening change.

**The MASQUE inner-packet size bound discarded legal IPv6 packets.**
`transport/masque/session.go` bounded one inner IP packet at 65535 bytes. That is the
IPv4 figure - an IPv4 Total Length field is 16 bits and counts the WHOLE packet - and it
is wrong for IPv6, whose Payload Length field counts only what follows the 40-byte base
header (RFC 8200 section 3). The largest ORDINARY IPv6 packet is therefore
`40 + 65535 = 65575` bytes.

A legal IPv6 packet of 65536..65575 bytes was silently DISCARDED on the DATAGRAM capsule
path: not misrouted, not reported, just dropped, because the size gate runs before the
parser. Evidence, measured before the fix: a real DATAGRAM capsule carrying context ID 0
and then a 65535-byte packet was delivered; 65536 and 65575 produced no packet at all.
sing-tun agrees with the arithmetic (`gtcpip/header/ipv6.go` defines
`IPv6MaximumPayloadSize = 65535` for the amount AFTER the base header, and its
`IPv6.IsValid` admits `IPv6MinimumSize + that`).

Fixed by raising the bound to `40 + 65535`, written as an expression so the arithmetic is
visible. Jumbograms remain UNSUPPORTED and the change does not enable them; the bound is
not removed, and `TestIPv4MaximumPacketStillBounded` plus
`TestOversizedPacketIsDiscardedWithoutKillingTheSession` pin that it is still a bound.

### TEST-HARNESS bugs found in this round

These are defects in the TESTS, not in production. Each is recorded because each one made
a test report something other than what it claimed.

| Harness defect | Symptom | Correction |
| --- | --- | --- |
| The reference module's IPv6 control-capsule decoder read the byte before an address as a BYTE LENGTH (4/16) instead of the IP VERSION (4/6). IPv4 worked by coincidence because 4 is both. | Every IPv6 ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT failed to parse. Five new regression cases fail against the old decoder. | Corrected, with RFC-derived vectors in `control_capsule_wire_test.go` that never call the production encoder. See the table below. |
| The fuzz corpus seeds for ROUTE_ADVERTISEMENT and ADDRESS_ASSIGN were written as if the wire carried a leading entry COUNT and a byte length. | Measured against the real parsers, EVERY "valid" seed failed with "invalid IP version: 1". Because the fuzz functions open with `if err != nil { return }`, the targets reached no assertion at all and passed vacuously. | Corpus rebuilt from RFC-derived tables (`routeSeeds` / `addressSeeds`) with IPv4 and IPv6 cases; `TestRouteAdvertisementSeedsAreValid`, `TestAddressSeedsAreValid` and `TestProductionEncoderReproducesTheRFCVectors` now fail the BUILD if a seed stops being valid. |
| `TestReferenceSourceIdentityIsStableAcrossMigration` claimed in its own doc comment to measure "what identity the SERVER layer reports ... taken from the server's own logs". It read neither the log nor the source. | The audit recorded "source identity CLOSED" on evidence that did not exist. The test proved only that the relay's source port changed and both tunnels still worked - a data-path property already covered elsewhere. | Replaced by four cases that observe `metadata.Source` through the ROUTING LAYER (`source_ip_cidr` selecting one of two named outbounds), plus a load-bearing negative control. |
| The bounded-fuzz CI step listed four targets and had already gone stale: `FuzzMasqueIPPacketParser` and `FuzzCapsuleStreamFragmentation` existed, compiled, and never fuzzed. | Two of six targets reported "covered" while never running. | The step is per-package and ends with a coverage check that compares the targets DEFINED in the source against the ones run. Adding a target without registering it now fails the build. |
| The reference CI coverage check matched only `TestReference*` names. | The four new `TestSourceIdentity*` tests would have been invisible to it and could have silently dropped out of the run filter. | The check now matches both naming conventions. |
| A speculative "nothing arrived" read on the reliable capsule stream left a goroutine parked; when its timeout fired, the goroutine went on to consume the NEXT capsule. | The zero-length CONNECT-IP capsule test reported "no DATAGRAM capsule arrived" - a test artefact that reads exactly like a server defect. | Removed; the property is asserted via ordered reply sequence numbers instead. |
| The impairment relay's CONNECT-IP case asserted its drop counter was positive after a burst of 20 requests. | Only nine packets had crossed and none hit the cadence, so the guard failed - correctly, since a run where nothing was dropped proves nothing. | The loop now drives traffic until the relay reports it actually dropped something. |

### A fuzz target was misnamed, and the gap it hid

`FuzzConnectUDPTemplatePath` never drove CONNECT-UDP. It drove `transport/masque`'s
CONNECT-IP URI template (`/.well-known/masque/ip/{target}/{ipproto}/`). The name claimed
coverage of the CONNECT-UDP target parser - the one on the production minimal VPS path -
that did not exist.

It is renamed to `FuzzConnectIPTemplatePath`, and the real parser now has its own target,
`FuzzConnectUDPTargetPath` in `transport/http`, covering domain / IPv4 / IPv6 (raw and
percent-escaped), ports 0, 1, 65535 and 65536, negatives, non-decimal digits, overflow,
empty hosts, encoded and doubled slashes, malformed percent escapes, extra segments, a
missing trailing slash, zones and Unicode. For any accepted destination it asserts that
`connectUDPURL` followed by `parseConnectUDPTarget` recovers an equivalent destination -
the property that keeps a client and server from routing to different places.

### RFC 9931 attribution corrected

The comment on `rejectionKeepAlive` claimed RFC 9931 section 6.3 requires a CONNECT-UDP
**server** to close the connection when it rejects an upgrade. It does not. Section 6.3
imposes a **client**-side discipline: an HTTP/1.x CONNECT-UDP client must not send UDP
payload optimistically. The obligation is on the sender.

The behaviour is unchanged and is now classified **SECURITY-HARDENING** rather than
compliance: it removes the same smuggling shape for a client that ignores section 6.3, at
the cost of one TLS handshake paid only on the rejection path. RFC 9931 section 8's
server-side MUST for plain CONNECT is unchanged and remains a requirement.

CONNECT-IP is deliberately NOT given the same treatment, and
`TestJiejieMASQUERejectedHTTP1CONNECTIPLeavesTheConnectionReusable` is a guard against
extending the rule by symmetry: RFC 9484 already forbids HTTP/1.x optimistic IP packets,
so the shape the rule exists for is not created there.

### CONNECT-IP packet size and PTB

The `maxPacketSize` defect is recorded above. The ICMP Packet Too Big chain is now covered
field by field for both families, including the ICMPv6 pseudo-header checksum (a functional
requirement: without it every conforming receiver discards the message, so a client would
never learn the tunnel MTU). The live end-to-end case is **NOT-TESTED** for a measured
reason: reaching `DatagramTooLarge` needs a reply larger than its request, and a loopback
echo origin produces a reply the server SHRINKS instead (measured: a 1311-byte request is
answered with a 1276-byte reply). No live PTB E2E is claimed.

### Reference results in this round

| Reference | Result | Note |
| --- | --- | --- |
| quic-go/masque-go (`c1cf0e4d`) | PASS | `v0.6.0` tag; unchanged pin; CONNECT-UDP round trip, no-auth rejection, settings exchange |
| quic-go/connect-ip-go (`fdd945e3`) | PASS | pseudo-version pin via `replace`; unchanged; handshake, assignment, ICMP differential, IPv4 and IPv6 control capsules, capsule fallback, migration |
| Google QUICHE | CHECKED (protocol vectors) | Read at `c961965aa3ee8f2b6f05ebcac794f7854101adcd`; its context-ID decision table and unit vectors are pinned in `test/jiejie/reference/quiche_oracle_test.go`. NOT built and NOT run, so this is a protocol-vector CHECK and NOT interop. |
| Volto-derived migration semantics | PASS | Migration survives a NAT rebind for CONNECT-UDP and CONNECT-IP; new tunnels open afterwards |

Reference HEADs were re-checked at the start of this round: masque-go, connect-ip-go AND
Google QUICHE all still stand at the commits recorded at the top of this document, so no
re-pin was needed. QUICHE's source was additionally fetched and read for the vector check
described above; it was not built. Both remain isolated in
`test/jiejie/reference`, a separate Go module that neither the root nor the `test` module
depends on.

### Closed in this round

Removed from the NOT-TESTED list, each with a live or deterministic test:

- DATAGRAM context IDs other than 0: every varint WIDTH boundary (1, 2, 63, 64, 16383,
  16384, 2^30-1, 2^30, 2^62-1) for BOTH CONNECT-UDP and CONNECT-IP, asserting that the
  datagram is dropped, the tunnel survives, and the next context-0 datagram still works.
- Loss, reordering and duplication: a controllable UDP impairment relay below QUIC with
  per-mode counters, and a guard that FAILS the run if the impairment never fired.
- ICMP Packet Too Big generation: type, code, MTU, checksums, quoted packet and both MTU
  clamps, for IPv4 and IPv6.
- Proxy-Status: the mapping audited path by path against RFC 9209, with a compiled guard
  that fails if a new rejection path is added without a decision.
- RFC 9931's client-side half: reclassified OUT-OF-SCOPE-FOR-SERVER-PRE-VPS rather than
  left as an open NOT-TESTED item. This fork's product is a Linux amd64 VPS server, and the
  production minimal registry serves no MASQUE client endpoint.
- IPv6 extension headers: rebuilt on a correct packet builder, with 10 chain cases
  (plain UDP/TCP, Hop-by-Hop -> UDP, Routing -> TCP, Destination Options -> UDP, Fragment
  offset 0 -> UDP, three-header chains, a 16-octet Hop-by-Hop, Destination Options ->
  Fragment), the corrected non-first-fragment result, fragment-chain termination, nine
  malformed shapes rejected without panicking, and a guard that a declared Payload Length
  is not trusted for slicing. Four mutations of the production path were caught and
  reverted. The IP packet parser stays clean under bounded fuzzing (283,922 executions for
  the packet parser, 208,450 for capsule fragmentation, no crash).
- Cross-session ownership, route policy and control-plane resource bounds: see the tests
  in `transport/masque/ownership_policy_test.go` and `transport/masque/control_burst_test.go`.

### One asymmetry recorded rather than fixed

`serverSession.handlePacket` (peer -> server ingress) ENFORCES source ownership: a forged
source is answered with ICMP Source Address Failed Ingress/Egress Policy and never written
to the device. `Server.WritePacketBuffers` (device -> tunnel egress) applies NO
source-ownership check at all; it routes on DESTINATION plus the receiver's advertised
routes, so a packet whose source is another client's assigned address, or an address
nobody holds, is queued into a tunnel exactly like a legitimate one.

This is recorded as INFORMATION, not as a defect, and no production change was made:

  - the ingress path is the one an untrusted peer can reach. The egress path is fed by the
    local TUN device, where the host chose the source and the kernel has already applied
    its own anti-spoofing filters. There is no attacker model in which a MASQUE peer
    controls what the device emits;
  - a check there would be defence in depth at best, and for a packet the host itself
    generated it would drop legitimate traffic whose source is a routed address rather than
    a tunnel address.

The asymmetry is pinned by `TestDeviceIngressSourcePolicyIsNotEnforced` so that a future
reader does not mistake one direction's behaviour for the other's.

### Still NOT-TESTED, and why

| Item | Verdict | Reason |
| --- | --- | --- |
| Google QUICHE interop | NOT-TESTED | Not built and not run: C++ via Bazel, and no Bazel toolchain is available here. Its protocol vectors are checked instead (see the table above), which is a CHECK and not interop. |
| Live H3 Packet Too Big end to end | NOT-TESTED | Needs an asymmetric origin (a reply larger than its request); a loopback echo cannot produce one. Generation is fully covered. |
| Real VPS / WAN behaviour | NOT-TESTED | Only a real VPS can test it. See `docs/JIEJIE-MASQUE-PRE-VPS-ACCEPTANCE.md`. |
| RFC 9931 client-side half | OUT-OF-SCOPE-FOR-SERVER-PRE-VPS | Server-only product; `include/registry_jiejie_server.go`'s `EndpointRegistry()` registers no endpoint, so no shipped component can violate a client-side obligation. |

### A narrowing stated rather than implied

The impairment tests apply impairment BELOW QUIC. What they measure is therefore the
STACK's tolerance - quic-go's duplicate detection and reassembly, plus the MASQUE session
above it - not any sing-box loss-recovery logic. sing-box deliberately has none, because a
QUIC DATAGRAM is unreliable by design and RFC 9297 gives it no retransmission.
