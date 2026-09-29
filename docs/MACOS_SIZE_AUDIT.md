# macOS client: binary size audit

This records where the macOS arm64 core's bytes actually go, so the size decisions
in this round come from measurement rather than from intuition. It is the evidence
behind `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` and the stripped production build.

## Headline

| Stage | Bytes | MiB | Delta |
|---|---|---|---|
| Start of this round (unstripped) | 73,432,802 | 70.03 | — |
| After `-s -w` | 47,876,386 | 45.65 | **−25,556,416 (−34.8%)** |
| After CLI reduction | 47,164,946 | 44.98 | −711,440 |
| After removing gVisor | **43,075,954** | **41.08** | **−4,088,992 (−3.89 MiB)** |

Total removed this round: **30,356,848 bytes (28.94 MiB), 41.3% of the original.**

## Where the original bytes were

Measured with `otool -l` and `go tool nm -size` on an unstripped build:

| Section | Size | Removable? |
|---|---|---|
| `__DWARF` debug segments | 12.38 MiB | yes — `-w` |
| Mach-O symbol + string tables | ~12 MiB | yes — `-s` |
| `__TEXT.__text` (real code) | 22.28 MiB | only by dropping code |

So more than a third of the image was information the process never executes. That
is what `-s -w` removes, and it is now a property of this product only: the flags
live in `release/LDFLAGS_JIEJIE_CLIENT_MACOS`, so the Linux server, the deep audits
and local debug builds keep their symbols.

## Top remaining components

From `go tool nm -size` on an unstripped build of the final tag set, aggregated by
package (Go symbols only; see the C++ note below):

| MiB | Component | Necessary? |
|---|---|---|
| 12.23 | `runtime` (pclntab, types, rodata) | yes — Go runtime, unavoidable |
| 3.74 | `typerel.*` + `_type:*` | yes — reflection metadata |
| 1.63 | `go:func.*` | yes |
| 1.19 | `github.com/sagernet/*` (sing, sing-tun, quic-go) | yes — transport core |
| 1.00 | `go:string.*` | yes |
| 0.74 | `net` | yes |
| 0.72 | `github.com/sagernet/sing-box` (this repo) | yes |
| 0.54 | `crypto` | yes — TLS |
| 0.50 | `protobuf/internal` | yes — the Native API is gRPC |
| 0.49 | `common` | yes |
| 0.46 | `metacubex/utls` | yes — `with_utls`, Reality/Vision fingerprints |
| 0.38 | `miekg/dns` | yes — DoT/DoH |
| 0.36 | `golang.org/x/net` | yes — HTTP/2 |
| 0.20 | `grpc/internal` | yes — Native API |
| 0.19 | `spf13/cobra` | yes — CLI |
| 0.17 | `quic-go/internal` | yes — MASQUE HTTP/3 |
| 0.16 | `route` | yes |

Each of these is load-bearing for a capability the deployment uses. There is no
remaining item of this size that is dead code.

### Cronet is the dominant non-Go cost

About **10 MiB** of the binary is C/C++ from the Cronet static library, which
`with_naive_outbound` links for NaiveProxy. It does not appear in the Go package
table above because its symbols are mangled C++.

Cronet internal trimming is explicitly out of scope: it is a separate, high-risk
project, and NaiveProxy is a headline capability of this product.

## What was removed, and what it cost

| Removed | Cost | Evidence |
|---|---|---|
| `with_gvisor` | 4,088,992 B (3.89 MiB) | the tun inbound sets no `stack`, and sing-tun resolves unset to `NewGo`; verified against `tun.NewStack` with the tag absent |
| `api` CLI subtree (58 files) | 711,440 B | `github.com/mattn/go-runewidth` left the dependency graph |

### go-runewidth

`go-runewidth` is now **absent from the macOS dependency graph**. It was pulled in
solely by `cmd_api_output.go` for the `sing-box api` command's table output, and it
carried a single `strictWidthLUT` table of **2,228,224 bytes (2.13 MiB)** — measured
with `go tool nm -size`. Its removal is asserted on the dependency graph
(`go list -deps`), not on the binary, because a stripped binary cannot be grepped.

## Unstripped analysis builds

The shipped artifact is stripped, so `go tool nm` on it yields no Go symbols —
verified: zero matches for `sing-box/`. Where symbol-level analysis is needed:

- `scripts/ci/audit-macos-client-registry.sh` builds its own unstripped copy into a
  temporary directory, deletes it on exit, and never uploads it.
- Size attribution (this document) uses the same kind of throwaway build.

There is exactly ONE shipped macOS artifact, and it is stripped.

## Verification layers

Because symbol names are no longer readable in the shipped binary, capability is
established in order of strength:

1. **registry unit tests** — required types resolve, excluded types do not
2. **source / build graph** — `go list -deps`, no build required
3. **config check** — the shipped stripped binary validating the real fixture
4. **runtime smoke** — the shipped stripped binary actually serving the Native API
   and the Dashboard

Layers 3 and 4 run against the artifact users get, and they are what gate the
product. The static symbol audit is now a fifth layer that explains *why* something
is missing, rather than the primary evidence.


## Third round: linking-level trimming

The second round reduced the registry and stripped the binary. This round asked a
different question: which code is still LINKED that the product cannot reach, and for
each candidate, what does it actually cost?

The method matters more than the numbers here. `go list -deps` says a package is in
the graph; it does not say the linker kept its code. Every candidate below was measured
with `go tool nm -size` on an unstripped build, and each change was A/B'd against the
shipped artifact rather than estimated.

| Change | Bytes | Decision |
|---|---|---|
| Unused QUIC protocol imports (Hysteria2, TUIC, v2rayquic) | −264,816 | **KEPT** |
| CLI toolchains compiled out (34 files) | −363,872 | **KEPT** |
| **Total** | **−628,688 (−0.60 MiB)** | |

Shipped macOS artifact: 43,075,954 → **42,447,266 B**.

### The mistake this round fixed

An earlier round stopped REGISTERING Hysteria2 and TUIC and described them as out of
the picture. They were not: a Go import links a package and runs its `init()` whether
or not the registration call is ever reached. The same error appeared one layer up in
the CLI, where skipping `AddCommand` hid ten command families from `--help` while
leaving their packages, and their dependencies, in the binary.

Both are now fixed by build constraint or by removing the import, and both are
asserted on the LINKED IMAGE rather than on the registry, because "not registered" and
"not linked" are different claims.

### Candidates measured and deliberately KEPT

Each of these was a plausible removal that the measurement did not support:

| Candidate | Linked cost | Why kept |
|---|---|---|
| HTTP/3 server code | 37.4 KiB | below the threshold, and splitting shared client/server files is a large risky refactor of upstream-owned code |
| QUIC congestion variants (meta1/meta2) | 47.0 KiB | reachable through `common/httpclient`, which this client legitimately uses |
| DoQ / generic DoH3 DNS transports | 13.6 KiB | removing them would cut real capability for negligible gain |
| `schema` package | 13.8 KiB | a RUNTIME dependency: option structs implement `DescribeSchema`. Only the `schema` COMMAND was CLI-only. |
| Cobra | 0.19 MiB | replacing the CLI parser is more risk than the bytes are worth |

### Explicitly protected, verified present

| Capability | Evidence |
|---|---|
| runtime rule-sets | `common/srs` linked (57 symbols); all four remote SRS fetched and parsed at runtime |
| MASQUE HTTP/3 client | `transport/http/client_h3.go`, `with_quic` |
| Native API | `service/api` |
| Cronet / NaiveProxy | `with_naive_outbound`, CGO |
| uTLS | 15 packages |

The rule-set distinction is the one most at risk from a careless trim, so it is
asserted in both directions: the CLI tooling must be ABSENT and `common/srs` must be
PRESENT. Asserting only the removal would have let a future edit delete runtime SRS
and still pass.

## NOT TESTED

- Any real remote-network throughput or latency comparison; the size work makes no
  performance claim.
- A live TUN device: creating one needs root, which the CI runner and this auditing
  session do not have. TUN stack SELECTION is verified against sing-tun directly;
  TUN device creation is not.
