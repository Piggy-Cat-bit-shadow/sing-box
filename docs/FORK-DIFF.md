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
| Upload traffic scheduler | An opt-in shaper for managed upload flows, configured by `route.traffic_scheduler.upload_rate`. Absent by default, in which case it observes every managed byte and admits all of them. `traffic_class` on an outbound expresses what its traffic is for and is preferred within the shaped budget. A configuration using either key is not loadable by official sing-box. | [traffic scheduler](fork/traffic-scheduler.md) | `common/trafficsched`, `common/trafficclass`, `option/traffic_scheduler.go`, `option/route.go`, `route/conn.go`, `box.go` |
| Direct Offload | A direct flow that is provably equivalent to a plain OS connect is marked eligible for the platform's own routing. Eligibility is decided per FLOW from a precomputed profile of the dialer options, so an option the flow never reaches is not a reason to refuse: the topology's `direct` outbound carries only `domain_resolver`, and literal-IP flows through it are now eligible. Fails closed on any unclassified option, on any tracker, and on a FakeIP destination at every layer. **The verdict is a data-plane bypass only in Linux `auto_redirect` mode**: no TUN stack honours it, so in TUN mode an eligible flow is still proxied in userspace. See the trace. | [Direct Offload](fork/direct-offload.md), [native bypass trace](fork/native-bypass-trace.md) | `common/dialer/profile.go`, `protocol/direct/outbound.go`, `route/bypass_verdict.go`, `route/route.go`, `protocol/tun/inbound.go` |
| SOCKS outbound pooling | An opt-in authenticated SOCKS5 TCP pool and copy-path tuning for a chained hop. | [SOCKS outbound](configuration/outbound/socks.md) | `option/simple.go`, `protocol/socks` |
| Clash API | Upstream's, enabled in both profiles. It coexists with the Native API over one shared traffic and routing-mode manager rather than being a separate plane. | [Build profiles](BUILD-PROFILES.md) | `experimental/clashapi`, `include/clashapi.go`, `option/experimental.go`, `box.go` |
| Launcher / LXD surface | Removed, including the daemon launcher RPC and LXD integration. | [macOS client](JIEJIE-MACOS-CLIENT.md) | `cmd`, `daemon` |
| Production topology | A checked-in topology contract covering MASQUE H2/H3, AnyTLS, Native Naive, ShadowTLS v3 and SS2022, with residential TCP resolved to IPv4 before a SOCKS5 exit. | [server](JIEJIE-SERVER.md) | `release/jiejie-production-topology.json` |
| Push-triggered verification | `.github/workflows/verify.yml` gates every push to `testing` on the pinned-upstream tripwires, the fork's build matrix (linux, windows, freebsd, darwin+low_memory) and its race suite. The artifact workflows stay manual dispatch. The assumption inventory and the audit procedure are in [upstream sync](UPSTREAM-SYNC.md); current evidence and blockers are in the [release certificate](RELEASE-CERTIFICATE.md). | [upstream sync](UPSTREAM-SYNC.md) | `.github/workflows/verify.yml`, `scripts/ci/verify-upstream-assumptions.sh` |
| Forked dependencies | `sing`, `cronet-go` and `quic-go` are replaced with fork pins in both the root and `test` modules. | [engineering notes](ENGINEERING-NOTES.md) | `go.mod`, `test/go.mod` |

Both products build from upstream's own registries and tag files; there is no fork-specific
registry or capability allowlist. If this manifest drifts, the current source,
registries and [production topology](../release/jiejie-production-topology.json) take precedence.
