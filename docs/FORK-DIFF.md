# Fork diff

What this fork changes relative to [SagerNet/sing-box](https://github.com/SagerNet/sing-box), as of
the current `testing` tree. Only differences that still exist are listed; rationale and history are
in Git, and implementation detail is in the documents linked from each row.

`testing` is the sole long-term source branch. Both products come from it with distinct build tags
and registries — see [build profiles](BUILD-PROFILES.md).

| Area | Current difference | Detail | Source |
| --- | --- | --- | --- |
| MASQUE | The HTTP inbound serves authenticated CONNECT and CONNECT-UDP over H2/H3, and routes unauthenticated probes to a configurable masquerade. | [server](JIEJIE-SERVER.md), [MASQUE](masque.md) | `protocol/http`, `transport/http` |
| CONNECT-IP endpoint | A MASQUE client endpoint with address assignment, route advertisement, DNS_ASSIGN and PREF64 state. | [MASQUE](masque.md) | `protocol/masque`, `transport/masque` |
| AnyTLS fallback | Inbound supports a default fallback destination and ALPN-specific fallbacks, after TLS termination. | [server](JIEJIE-SERVER.md) | `option/anytls.go`, `protocol/anytls` |
| Native Naive | A NaiveProxy server inbound, with UoT, padding, masquerade and pre-authentication resource controls. | [Native Naive](naive.md) | `protocol/naive`, `option/naive.go` |
| HTTP resource controls | Per-inbound header, H2/H3 window, congestion-control and pre-authentication limits, configurable rather than compiled in. | [server](JIEJIE-SERVER.md) | `option/simple.go`, `option/http.go`, `transport/http` |
| SOCKS outbound pooling | An opt-in authenticated SOCKS5 TCP pool and copy-path tuning for a chained hop. | [SOCKS outbound](configuration/outbound/socks.md) | `option/simple.go`, `protocol/socks` |
| Clash API | Removed as a control-plane decision, not a size cut: the Native API plus dashboard is the only management surface. A configuration using `experimental.clash_api` is invalid in both products. `with_clash_api` is therefore dropped from the tag files. | [Build profiles](BUILD-PROFILES.md) | `include/`, `option/experimental.go`, `box.go` |
| Launcher / LXD surface | Removed, including the daemon launcher RPC and LXD integration. | [macOS client](JIEJIE-MACOS-CLIENT.md) | `cmd`, `daemon` |
| Production topology | A checked-in topology contract covering MASQUE H2/H3, AnyTLS, Native Naive, ShadowTLS v3 and SS2022, with residential TCP resolved to IPv4 before a SOCKS5 exit. | [server](JIEJIE-SERVER.md) | `release/jiejie-production-topology.json` |
| Forked dependencies | `sing`, `cronet-go` and `quic-go` are replaced with fork pins in both the root and `test` modules. | [engineering notes](ENGINEERING-NOTES.md) | `go.mod`, `test/go.mod` |

Both products build from upstream's own registries and tag files; there is no fork-specific
registry or capability allowlist. If this manifest drifts, the current source,
registries and [production topology](../release/jiejie-production-topology.json) take precedence.
