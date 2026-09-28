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

## NOT TESTED

- Any real remote-network throughput or latency comparison; the size work makes no
  performance claim.
- A live TUN device: creating one needs root, which the CI runner and this auditing
  session do not have. TUN stack SELECTION is verified against sing-tun directly;
  TUN device creation is not.
