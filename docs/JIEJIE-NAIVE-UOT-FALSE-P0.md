# Retraction: "UoT v2 non-connect is a P0 product bug"

## OLD CONCLUSION

> UoT v2 non-connect mode is a **P0 product defect**. The server rejects the
> request with `UoT read request: unknown address family: 8` and closes the
> tunnel before any datagram is delivered. Reproduced on the untouched baseline
> commit with the pre-existing `TestAuditUoTV2NonConnectMode`, so it is a defect
> in the product and not in the harness.

## REVISED CONCLUSION

**FALSE POSITIVE.** The product path is correct. The test harness framed an
HTTP/1 payload as Naive padded data, even though **HTTP/1 CONNECT is a raw
tunnel**. The error came from the test's own bytes.

## The mechanism

`openUoTNonConnect()` established the tunnel with an HTTP/1 `CONNECT`, then:

1. set `padding: true` on the session, and
2. wrote the UoT request header through `naivePaddingFrame`.

HTTP/1 never frames payloads. `protocol/naive/inbound.go` says so explicitly — the
hijack branch builds `naiveConn{paddingConn: paddingConn{enabled: false}}` with a
literal `false`, mirroring the reference's `serveHijack -> dualStream(..., false)`.
The `Padding` request header is legal on HTTP/1 and the response header is
unconditional, but neither turns on framing.

So the test put a Naive frame around a header that HTTP/1 sends raw:

```text
UoT v2 non-connect request payload (isConnect || SOCKS5 addrport)
    00 01 00 00 00 00 00 00          (8 bytes: isConnect=0, ATYP=1 (IPv4), 0.0.0.0:0)

what the server expects on HTTP/1 (raw) -- the test should have sent this
    00 01 00 00 00 00 00 00

what the test actually wrote (naivePaddingFrame: len_hi len_lo pad)
    00 08 00 00 01 00 00 00 00 00 00
    ^^ ^^ ^^
    |  |  +-- pad size
    |  +----- frame length LOW byte, at the offset the server reads as ATYP
    +-------- frame length high byte, at the offset the server reads as isConnect
```

These exact bytes are asserted by `TestNaiveFrameLengthByteLooksLikeAnAddressFamily`,
so the mechanism is pinned by a test rather than described only in prose.

The server's `uot.ReadRequest` reads byte 0 as `isConnect` (correctly `false`) and
**byte 1 as the SOCKS address type**. Byte 1 of the framed stream is the frame's
length low byte, `0x08`, where the raw stream had `0x01` (IPv4):

```text
unknown address family: 8
```

`0x08` is not a SOCKS5 address type, so the server rejected a request that was
perfectly well-formed in the only form the test ever had to send. The "product
defect" was a length prefix being read as an address family.

This byte sequence is asserted directly, not inferred, by
`TestUoTPaddingFramingIsDerivedNotDeclared` and by the mutation below.

## Why it took a wrong turn

The harness modelled "padding" as **one boolean**. Naive actually has two
independent properties:

| | Padding request header | padding payload framing |
| --- | --- | --- |
| May appear on HTTP/1 | yes | **no** |
| HTTP/2 or HTTP/3 | yes | only if the header is present |

A single flag cannot express that, so `padding: true` meant "framed" to the
harness while it meant "header present" to the product. The same file already
contained the correct rule in a sibling helper (`dialUoT`, which forced
`padding: false` on HTTP/1 with a comment explaining exactly this) — the two
helpers disagreed, and the disagreement was read as a product bug.

## The fix

No production code changed. **`protocol/naive/inbound.go` is byte-identical to
what it was before this investigation.**

The harness now derives framing from the transport instead of accepting it:

```go
func (transport naiveTransport) framesPayload(requestPaddingHeader bool) bool {
	return transport != transportHTTP1 && requestPaddingHeader
}
```

`newUoTSession` computes the framing from `(transport, requestPaddingHeader)`, so
a caller can no longer declare an HTTP/1 tunnel that frames. The four
combinations are pinned by `TestAuditUoTPaddingContractIsTransportDependent`:

| Transport | Padding header | Framing | Result |
| --- | --- | --- | --- |
| HTTP/1 | present | raw | PASS |
| HTTP/1 | absent | raw | PASS |
| HTTP/2 | present | framed | PASS |
| HTTP/2 | absent | raw | PASS |

The padded HTTP/2 case is kept, so fixing HTTP/1 did not cost padded coverage.

## Mutation proofs

Each claim was checked by breaking it:

| Mutation | Expected | Observed |
| --- | --- | --- |
| **A.** force `padding = true` on the HTTP/1 non-connect helper (the original bug) | `unknown address family: 8` | reproduces, 3/3 runs |
| **B.** make the server frame HTTP/1 payloads (`usePadding` in the hijack branch) | H1 reference/differential tests fail | 4 fail, incl. `TestJiejieNaiveH1TunnelIsRawByByteComparison` |
| **C.** have the HTTP/2 helper declare HTTP/1, dropping the frame | the HTTP/2 padded case fails | fails 3/3, "HTTP/2 with a Padding header must frame payloads" |
| **D.** narrow the `ip_cidr` rule so it no longer covers loopback | the re-enabled security subtest fails | fails |

Mutation B is the one that shows the product-side rule is itself pinned: if
anyone later "fixes" HTTP/1 to honour padding, the raw-tunnel parity tests catch
it rather than the change shipping quietly.

## Re-enabled security coverage

`TestAuditDomainResolvingToLoopbackIsStillRuled/UoT_via_domain` had been SKIPPED
with the justification that "UoT v2 non-connect is broken", i.e. it was disabled
by the same false diagnosis. It is now **enabled and passing**, and it asserts the
real property:

- the destination is a **domain** (`localhost`), so a rule that inspected only the
  request string would not match;
- the router logs `drop datagram to localhost:<port>: rejected by route rule`,
  proving resolution happened and the rule applied to the **resolved** address;
- the UDP origin's packet counter stays at zero.

The counter is what makes the check non-vacuous, and mutation D confirms it: with
the rule narrowed, the subtest fails.

One subtlety worth recording: a "positive control" datagram **cannot** be used to
prove the tunnel works here, because the rule rejects all of `127.0.0.0/8` and
every UDP origin in the harness is on loopback — a delivered control would
contradict the property under test. The functional evidence is the established
session itself (the server answered `200` and accepted the UoT request header),
the same standard the TCP subtest uses.

## What this changes elsewhere

- `scripts/ci/run-jiejie-suite.sh`: both tests **removed** from `KNOWN_FAILURES`.
  They are deleted rather than kept as expected failures, because leaving a fixed
  test on a known-failure list is how a real regression later hides behind the
  label.
- No documentation is left claiming a UoT v2 non-connect product defect.

## Lesson

`unknown address family: 8` was a real, well-formed error message produced by the
product for a genuinely malformed input. It was read as evidence about the product
without first decoding the bytes the test sent. The general rule this fork now
applies: when a protocol error appears, decode the test's own wire bytes before
concluding where the defect lives — especially when the test manipulates framing,
where an off-by-one-field error produces a plausible-looking protocol error.
