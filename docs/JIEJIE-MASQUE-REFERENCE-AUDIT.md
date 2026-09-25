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

| Reference | Commit |
| --- | --- |
| quic-go/masque-go | `c1cf0e4dd6439aea94d5491b27439a4736f00246` |
| quic-go/connect-ip-go | `fdd945e3d6009b3cee1b1a66493776d315727549` |
| Google QUICHE | NOT-TESTED (see below) |

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

## Remaining NOT-TESTED

Listed so the gaps are not mistaken for coverage. None of these has a passing
test, and none is claimed as PASS:

- **CONNECT-UDP differential against masque-go.** The path corpus and the capsule
  tests are in-process; no cross-implementation run was performed.
- **CONNECT-IP against connect-ip-go.** ADDRESS_ASSIGN, ADDRESS_REQUEST,
  ROUTE_ADVERTISEMENT semantics, ICMP, MTU and hop-limit handling were not
  differentially tested.
- **H3 DATAGRAM to Capsule fallback end to end.** The fallback exists in
  `session.writePacket`; no test drives a peer that disables DATAGRAM and
  observes the payload arriving as a capsule.
- **RFC 9931 HTTP/1.1 optimistic data.** No request-smuggling matrix was run.
- **Proxy-Status reporting.** Not implemented and not tested.
- **Cross-session isolation, resource churn, send-queue backpressure, capsule
  write backpressure, shutdown with active tunnels.** Audited by reading, not
  tested.
- **QUIC migration behaviour and source identity after a path change.** The path
  manager is now enabled by default, so this matters more than before and is
  unmeasured.
- **Loss, reordering and duplication for DATAGRAM versus capsule ordering.**
- **IPv6 extension-header protocol resolution for route policy.**
- **Fuzz targets for the capsule parser, the path parser and the IP packet
  parser.**
- **Google QUICHE interop.**

## Out of scope

Not implemented and not planned here: CONNECT-ETHERNET, Concealed Auth,
CONNECT-UDP-BIND, Compression Assign, DNS_ASSIGN, PREF64, and experimental
drafts.
