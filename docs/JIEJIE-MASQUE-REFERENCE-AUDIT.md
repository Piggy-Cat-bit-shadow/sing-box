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
| RFC 9931 | HTTP/1.1 upgrade and optimistic protocol data |

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

## Verified without change

- The capsule size limit fires correctly: a declared length above
  `MaxCapsuleLength` is refused with "capsule too large", including `1 << 40`.
- Malformed capsule framing (truncated type varint, truncated length varint,
  zero-length unknown capsule) returns an error rather than panicking, hanging or
  allocating without bound.

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

- **H3 DATAGRAM to Capsule fallback end to end.** The fallback exists in
  `session.writePacket`; no test drives a peer that disables DATAGRAM and observes
  the payload arriving as a capsule.
- **DATAGRAM context IDs other than 0, and datagram size boundaries.**
- **RFC 9931 HTTP/1.1 optimistic data.** No request-smuggling matrix was run.
- **Proxy-Status reporting.** Not implemented and not tested.
- **Cross-session isolation, resource churn, send-queue backpressure, capsule write
  backpressure, shutdown with active tunnels.** Audited by reading, not tested.
- **QUIC migration behaviour and source identity after a path change.** The path
  manager is now enabled by default, so this matters more than before and is
  unmeasured.
- **Loss, reordering and duplication for DATAGRAM versus capsule ordering.**
- **IPv6 extension-header protocol resolution for route policy.**
- **Fuzz targets for the capsule parser, the path parser and the IP packet
  parser.**
- **Google QUICHE interop.**

Two gaps that were listed here previously are now closed and have been removed from
this list: the CONNECT-UDP differential against masque-go, and CONNECT-IP against
connect-ip-go. Both are recorded in the table above with the reference client that
was actually driven.

## Out of scope

Not implemented and not planned here: CONNECT-ETHERNET, Concealed Auth,
CONNECT-UDP-BIND, Compression Assign, DNS_ASSIGN, PREF64, and experimental
drafts.
