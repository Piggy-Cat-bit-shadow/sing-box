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

### A measured behaviour, recorded rather than assumed

sing-box's internal IP stack answers an echo request sent to the tunnel gateway by
**echoing the request back** (ICMP type 8, the request type) rather than emitting a
type-0 echo reply. The source address, the echo identifier, the sequence number and
the payload are all the ones the test sent, so the tunnel is demonstrably
bidirectional. The test pins the observed type rather than accepting any ICMP: a
destination-unreachable or packet-too-big answer carries no echo identifier and
still fails.

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

- **The CONNECT-IP side of the DATAGRAM to Capsule fallback.** There are two
  fallback sites: `transport/http/capsule.go` (`http3PacketConn.WritePacket`) for
  CONNECT-UDP on the http inbound, which IS tested end to end, and
  `transport/masque/session.go` (`session.writePacket`) for CONNECT-IP on the
  masque-server endpoint, which is not. The reference interop exercises the
  CONNECT-IP data path with datagrams negotiated, so it does not reach that
  fallback.
- **DATAGRAM context IDs other than 0, and datagram size boundaries.** The framer
  and the zero-context-ID path are covered by fuzzing and by the fallback tests;
  non-zero context IDs and the exact size at which a datagram is rejected in favour
  of an ICMP Packet Too Big are not.
- **The IP packet parser and IPv6 extension-header protocol resolution.** The three
  control parsers and the path matcher are fuzzed; the packet parser that decides
  the protocol number of an inner packet is not, so a route rule keyed on protocol
  is untested for IPv6 with extension headers.
- **Proxy-Status reporting.** Not implemented and not tested.
- **Send-queue backpressure, capsule write backpressure, and shutdown with active
  tunnels.** Cross-session isolation and address-pool lifecycle are now tested (see
  the table above); these three are not, and are not the same thing. A tunnel that
  stops reading, a peer that stops reading the capsule stream, and a server
  shutting down while tunnels are open all exercise the write paths rather than the
  ownership maps.
- **QUIC migration behaviour and source identity after a path change.** The path
  manager is now enabled by default, so this matters more than before and is
  unmeasured.
- **Loss, reordering and duplication for DATAGRAM versus capsule ordering.**
- **Google QUICHE interop.**

Gaps that were listed here previously and are now closed, removed from this list:
the CONNECT-UDP differential against masque-go and CONNECT-IP against
connect-ip-go (both recorded in the table above with the reference client that was
actually driven), the H3 DATAGRAM to Capsule fallback, the RFC 9931 HTTP/1.1
CONNECT rejection requirement, cross-session isolation and address-pool
lifecycle, and fuzz targets for the capsule, route, address and path parsers.

One narrowing to be explicit about: the fuzz targets cover the capsule framer,
ROUTE_ADVERTISEMENT, ADDRESS_ASSIGN and the URI-template matcher. The IP packet
parser and IPv6 extension-header protocol resolution are NOT covered, so they stay
on the list above rather than being closed with the others. Cross-session
isolation and address-pool lifecycle are closed as ownership-map coverage, but the
three write-path items that were listed alongside them are not.

One RFC 9931 item remains open and is narrowed rather than dropped: the RFC's
client-side half is not tested here. Section 8 tells proxy CLIENTS to wait for a
2xx before forwarding TCP payload or to send `Connection: close`, and section 6.3
forbids optimistic UDP sending over HTTP/1.x. Those requirements bind a client;
this repository's HTTP client was not audited against them.

## Out of scope

Not implemented and not planned here: CONNECT-ETHERNET, Concealed Auth,
CONNECT-UDP-BIND, Compression Assign, DNS_ASSIGN, PREF64, and experimental
drafts.
