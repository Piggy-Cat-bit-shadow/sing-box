# MASQUE DNS spec-conformance analysis (seal round)

Sources re-read from origin, not from prior comments:

- draft-ietf-masque-connect-ip-dns-06 (2026-04-12, still latest)
- RFC 9460 (SVCB), RFC 9461 (SVCB-DNS), RFC 8484 (DoH), RFC 6570 (URI Templates)
- quic-go/connect-ip-go reference implementation

This file records CONFLICTS and the chosen policy. It is deleted before the final
commit; the findings are folded into code comments and docs/JIEJIE-MASQUE-DNS.md.

## 1. draft-06 vs its own example (address count)

draft §3.2:

    If the "no-default-alpn" service parameter is omitted, that indicates that
    the nameserver supports unencrypted DNS ... In that case, the sum of IPv4
    Address Count and IPv6 Address Count MUST be nonzero.

draft §3.6.1 full-tunnel example:

    IPv4 Address = [], IPv6 Address = [],
    Authentication Domain Name = "masque.example.org",
    Service Parameters = { alpn=h2,h3, dohpath=/dns-query{?dns} }

`no-default-alpn` IS omitted and the address sum IS zero. The draft rejects its
own example.

POLICY (unchanged from before, now re-confirmed against the fetched text): apply
the nonzero-address rule only when `alpn` is ABSENT. When `alpn` is present the
resolver has named its encrypted transports explicitly, so "supports unencrypted
DNS" is not inferred. This accepts strictly more than the literal rule on
receive, keeps every draft example valid, and does not weaken the send path.

STATUS: implemented. Keep. Re-document as a deviation.

## 2. InternalDomains: [] vs [""]  -- CODE WAS WRONG

draft §3.5:

    Sending an empty string as an internal domain indicates the DNS root; i.e.,
    that the corresponding nameserver can resolve all domain names.

So `[""]` = root. The draft gives NO meaning to an EMPTY LIST. Our model treated
`len(InternalDomains) == 0` as "default configuration", i.e. as root. That is a
guess the spec does not support, and it silently converts an unclaimed name into
a claimed one.

POLICY: `[]` means the configuration claims NOTHING (it cannot be selected for
any name). `[""]` means root. A configuration is selected only by matching a
listed internal domain.

Consequence for split DNS: draft §3.6.2 is a split-tunnel configuration with
`Internal Domains = ["internal.corp.example"]` and no root configuration.
Public names MUST go to the normal resolver. Our old behaviour sent everything to
the assigned resolver and then errored, breaking public resolution.

## 3. Claimed-but-unusable must fail closed  -- NEW REQUIREMENT

Privacy invariant, derived from §3.5 + §5 and from the product's purpose:

- qname NOT claimed by any configuration  -> normal DNS router is allowed
- qname claimed by a configuration whose resolvers cannot be used -> FAIL

The old install logic dropped configurations (and therefore their claims) when
resolvers were unreachable, which would convert case 2 into case 1 and leak an
internal name to host DNS. Claims are now retained independently of resolver
usability.

## 4. ALPN wire format  -- CODE WAS WRONG

RFC 9460 §7.1.1:

    The wire-format value for "alpn" consists of at least one alpn-id prefixed by
    its length as a single octet ... These pairs MUST exactly fill the
    SvcParamValue; otherwise, the SvcParamValue is malformed.

Also: "no-default-alpn" presentation AND wire value MUST be empty.

Our decoder accepted a comma-separated presentation string as a fallback, and
`decodeLengthPrefixedALPN` returning !ok fell through to it. So a malformed wire
value could be reinterpreted as a protocol name. That is wrong: on the wire there
is no presentation form.

POLICY: wire is length-prefixed only, must consume exactly, at least one entry,
each id 1-255 octets. Malformed -> resolver incompatible (not silently accepted).
The comma form is retained ONLY for constructing test inputs/zone-style values,
never from wire bytes.

## 5. port SvcParam  -- CODE PARTIALLY WRONG

RFC 9460 §7.2: wire is "2-octet numeric value in network byte order"; an empty
value is a syntax error. RFC 9461 makes `port` (and `no-default-alpn`)
AUTOMATICALLY MANDATORY for the DNS binding.

Our code: `len(port) == 2` required, else silently default. A malformed port was
therefore ignored rather than making the resolver incompatible. Under
automatically-mandatory semantics, ignoring it is a downgrade.

POLICY: port present with length != 2 -> resolver incompatible. Port present with
length 2 -> honoured for both plain DNS and DoH.

## 6. mandatory SvcParam  -- NOT IMPLEMENTED

RFC 9460 §8: a key is mandatory if the RR will not work for a client that ignores
it. `mandatory` lists extra mandatory keys.

    - listed keys MUST also appear in the SvcParams (self-consistency)
    - keys MAY appear in any order but MUST NOT appear more than once
    - wire: 2-octet keys in STRICTLY INCREASING numeric order
    - "This SvcParamKey is always automatically mandatory and MUST NOT appear in
      its own value-list."
    - RR is "compatible" only if the client recognizes all mandatory keys and
      their values permit connection
    - incompatible RRs are ignored

AUTOMATICALLY MANDATORY for this binding (RFC 9461 §Table 3 style, applied to
SVCB-DNS): `port`, `no-default-alpn`. draft-06 itself treats dohpath as
meaningful and alpn as transport-defining; a client that ignores `alpn` would
mis-select a transport, so `alpn` is treated as mandatory-when-present for this
binding. Recorded as an explicit choice.

POLICY: implement mandatory validation; unknown mandatory key -> resolver
incompatible; continue to the next resolver in the same configuration.

## 7. Unknown non-mandatory keys

RFC 9460 §2.4.3: "Unless specified otherwise by the protocol mapping, clients
MUST ignore any SvcParam that they do not recognize." So unknown non-mandatory
keys are ignored, NOT invalid. Keep accepting them.

## 8. ipv4hint / ipv6hint

draft §3.2: "The service parameters MUST NOT include ipv4hint or ipv6hint
SvcParams, as they are superseded by the included IP addresses."

draft-06 wins over RFC 9460/9461 which allow them generally. Keep rejecting.
This is already implemented and tested.

## 9. dohpath: RFC 6570, not "truncate at {"

RFC 9461 §5: dohpath is a relative URI Template; it MUST contain the variable
`dns`; the expansion result must be a valid HTTP :path.

RFC 8484 §4.1: "The URI Template defined in this document is processed without
any variables when the HTTP method is POST."

So for POST, `{?dns}` (an undefined variable in a query expansion) expands to
nothing, INCLUDING its leading `?`. And a literal suffix after the expression is
KEPT:

    /dns-query{?dns}   -> /dns-query
    /q{?dns}suffix     -> /qsuffix
    /path/{dns}        -> "" for the {dns} expression (no variables defined)
                          -> /path/    ... which is a legal but odd path

Our `dohPathTemplate` truncated the string at the first `{`, which produces
`/q` for `/q{?dns}suffix` instead of `/qsuffix`.

POLICY: implement RFC 6570 Level-2-ish expansion for the ONE case we need --
expanding with no variables defined -- sufficient to handle `{?dns}`, `{&dns}`,
`{dns}` and literal text around them. Validate: relative (no scheme/authority),
contains variable `dns`, non-empty result, valid path. Invalid -> resolver
incompatible. Do NOT invent a default path.

## 10. DoH HTTP status: 2xx, not ==200  -- CODE WAS WRONG

RFC 8484 §4.2.1: "A successful HTTP response with a 2xx status code is used for
any valid DNS response, regardless of the DNS response code."

Our code required status 200 exactly. A 201/204-with-body from a conforming
server would have been treated as a failure.

POLICY: 200-299 -> parse the body as DNS. Anything else -> bounded error.

## 11. DoH DNS message ID = 0  -- CODE WAS WRONG

RFC 8484 §4.1: "DoH clients using media formats that include the ID field from
the DNS message header, such as application/dns-message, SHOULD use a DNS ID of 0
in every DNS request."

Our code packed the caller's message as-is.

POLICY: for the DoH wire path, copy the message, set ID 0, pack. Do NOT mutate
the caller's Msg. On the response, restore the caller's original ID before
returning, because the sing-box DNSTransport contract and the router's
singleflight/match logic expect the ID they sent.

## 12. DoH media type

RFC 8484 §4.2: the only response type defined is application/dns-message. It does
not require the client to reject other types, but a response that is not DNS wire
would be a parse error anyway. The clear hazard is a 200 text/html body being fed
to the DNS decoder and producing a confusing error.

POLICY: validate response Content-Type with proper MIME parsing; accept
application/dns-message; absent Content-Type is tolerated (the spec sets no MUST);
a different declared type is reported as a media-type error rather than a decode
error.

## 13. Same-H3 must be the EXISTING connection  -- CODE WAS WRONG

draft §3.5: "...those requests SHOULD be coalesced over the same HTTPS
connection." (a SHOULD for coalescing)

Our `dohClient != nil` check does not mean the CONNECT-IP tunnel is H3: the HTTP
client can fall back to H2 while the H3 code path still exists. Calling
`RoundTripHTTP3` in that state could DIAL A NEW H3 CONNECTION purely for DNS,
which defeats the point and creates a second, observable connection.

POLICY: the DoH path must use the EXISTING memoized H3 ClientConn and must never
dial. If there is no live H3 connection, report H3-unavailable. Requires a
narrow "existing connection only" capability that does not expose the ClientConn
to protocol/masque.

## 14. Bootstrap: fresh resolve on EVERY reconnect  -- CODE WAS WRONG

Our `masqueConnDialer` reused `bootstrapCandidates()` whenever non-empty, so
after the first success every later reconnect raced the SAME stale list and never
consulted DNS again. That breaks DNS rotation, failover, and network changes.

POLICY: every new H3 connection attempt performs a bounded fresh lookup first;
fresh non-empty result replaces the cached snapshot and leads; fresh
failure/timeout/empty falls back to the cache.

## 15. Fresh success must NOT merge stale cached addresses  -- CODE WAS WRONG

Our `recordAndMerge` returned `fresh ++ (cached \ fresh)`. If DNS had WITHDRAWN an
address, the recovery cache reintroduced it with no TTL. That is a stale-DNS
hazard: we would keep dialling an address the resolver no longer publishes.

POLICY: fresh SUCCESS with a non-empty answer -> candidate list == fresh answer
ONLY. The cache is updated to that snapshot. Cached addresses are used ONLY when
the fresh lookup fails/times out/returns empty.

## 16. Winner promotion must reach the cache

The racer knows which address won the handshake, but that address was never
recorded, so the recovery ordering could not prefer the last-known-good address.

POLICY: the racer reports the winning address internally; masqueConnDialer
promotes it. The exported transport/http hook signature is unchanged.

## 17. Congestion control ordering for raced candidates  -- CODE WAS WRONG

Default path in transport/http:

    DialEarly -> ApplyClientCongestionControl -> NewClientConn -> memoize

Racer path: the racer calls DialEarly itself and returns only after
HandshakeComplete; transport/http then applies congestion control AFTER the
handshake has already exchanged data under the DEFAULT congestion controller.

POLICY: the racer must install the configured congestion control immediately after
DialEarly and before waiting for handshake completion, matching the default path's
ordering. This requires transport/http to expose a narrow single-candidate
primitive so protocol/masque does not duplicate TLS/QUIC/CC construction.

## 18. Plain assigned DNS completeness  -- CODE WAS INCOMPLETE

- Only `addresses[0]` was ever dialled; the rest were ignored permanently.
- A truncated (TC=1) UDP answer was returned as-is; traditional DNS requires a
  TCP retry.
- Route reachability ignored `AddressRange.Protocol`.

POLICY: try all addresses in order; honour the route protocol per transport
(UDP needs protocol 0/17, TCP needs 0/6); on TC=1 retry over TCP through the
tunnel. All of it through the MASQUE device, never a host socket.

## 19. Cache generation must track EFFECTIVE DNS behaviour  -- CODE WAS WRONG

`apply()` bumped the generation on every call, and Environment() included PREF64.
PREF64 does not participate in DNS resolution, so a PREF64-only update
invalidated the DNS cache for no reason. Conversely a ROUTE_ADVERTISEMENT change
that makes a resolver unreachable DOES change effective behaviour and must bump.

POLICY: build the new effective DNS state, compare a deterministic
resolver-relevant identity against the previous one, and publish a new generation
only when it differs. PREF64 is excluded from the DNS cache identity.

## Summary of code defects found by this re-read

| # | Defect | Severity |
|---|---|---|
| 2 | `[]` treated as root | P0 correctness + privacy |
| 3 | claimed-but-unusable not fail-closed | P0 privacy |
| 13 | same-H3 could dial a new connection | P0 privacy/correctness |
| 14 | no fresh DNS on reconnect | P0 correctness |
| 15 | stale cache merged into fresh success | P0 correctness |
| 17 | CC installed after handshake | P1 correctness |
| 10 | DoH required exactly 200 | P1 interop |
| 11 | DoH did not use ID 0 | P1 spec |
| 4 | ALPN malformed accepted | P1 spec |
| 5 | malformed port ignored | P1 spec |
| 6 | mandatory not implemented | P1 spec |
| 9 | dohpath truncated at `{` | P1 spec |
| 18 | single address, no TCP fallback, protocol-blind routes | P1 completeness |
| 19 | generation churn on PREF64-only | P2 |
| 16 | winner not promoted | P2 |
| 24 | family interleave, timer, ownership | already correct, keep |
