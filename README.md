# sing-box

A fork of [SagerNet/sing-box](https://github.com/SagerNet/sing-box) maintained for one private
deployment, built from a single `testing` source tree.

## Products

Two product binaries are built from this tree, with distinct build tags and registries:

| Product | Target | Purpose |
| --- | --- | --- |
| Linux Server Minimal | `linux/amd64`, CGO disabled | The production server: MASQUE H2/H3 front door, AnyTLS, Native Naive, ShadowTLS v3 + SS2022, residential SOCKS exit. |
| macOS Client | `darwin/arm64`, CGO enabled | A headless-first CLI core for Apple Silicon: TUN and mixed inbounds, the Cronet-backed Naive outbound, MASQUE client, and the native API with its Web Dashboard. |

Both come from the same protocol implementations; the profiles select capabilities, not separate
copies. See [build profiles](docs/BUILD-PROFILES.md).

## Current fork capabilities

- **MASQUE** — authenticated HTTP CONNECT and CONNECT-UDP over H2/H3, with a masquerade path for
  unauthenticated probes, plus the CONNECT-IP endpoint with DNS_ASSIGN and PREF64.
- **Native Naive** — a NaiveProxy server inbound in the minimal server registry, with UoT, padding,
  masquerade and pre-authentication resource controls.
- **AnyTLS fallback** — default and ALPN-specific fallback destinations after TLS termination.
- **ShadowTLS v3 + SS2022** — the production TLS-camouflage chain.
- **Residential SOCKS chain** — IPv4-only resolution on the server followed by a pooled SOCKS5 exit.
- **Server pruning and registry control** — explicit per-product registries; the minimal server
  carries no endpoints, services or client-only protocols.
- **Native API and macOS client pruning** — the macOS registry is an audited allowlist, and the
  Clash compatibility API is absent from both products.

## Documentation

| Document | Covers |
| --- | --- |
| [Fork diff](docs/FORK-DIFF.md) | What this fork changes relative to upstream. |
| [Build profiles](docs/BUILD-PROFILES.md) | How one tree produces the two product binaries. |
| [Linux server](docs/JIEJIE-SERVER.md) | The server product and its production deployment contract. |
| [macOS client](docs/JIEJIE-MACOS-CLIENT.md) | The macOS product, usage and verification. |
| [MASQUE](docs/masque.md) | The current MASQUE implementation and its boundaries. |
| [Native Naive](docs/naive.md) | The current Naive implementation and its boundaries. |
| [Engineering notes](docs/ENGINEERING-NOTES.md) | Design decisions that must not be changed casually, and open evidence gaps. |

Configuration fields are documented under [`docs/configuration/`](docs/configuration/index.md).
The machine-readable production topology contract is
[`release/jiejie-production-topology.json`](release/jiejie-production-topology.json).
