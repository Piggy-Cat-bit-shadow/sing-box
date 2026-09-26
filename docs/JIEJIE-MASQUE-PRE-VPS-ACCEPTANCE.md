# Jiejie MASQUE pre-VPS acceptance checklist

This document is the handover for the Linux amd64 VPS acceptance run. It does not repeat
the audit: `docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md` holds the reasoning and the evidence
for what has already been proven. This file is what to DO on the machine.

It is split in two, and the split is the point:

- **Part 1** is what local and CI evidence already establishes. On the VPS these are
  REGRESSION checks: run them to confirm the deployed binary behaves like the tested one,
  not to discover new information.
- **Part 2** is what only a real VPS can establish. Nothing in Part 1 substitutes for it,
  and no Part 1 result may be reported as a Part 2 result.

Every line has a verdict column. Use only: `PASS`, `FAIL`, `SKIP`, `NOT-TESTED`,
`REFERENCE-DIFF`, `OUT-OF-SCOPE`. A SKIP needs a reason on the same line. A SKIP is never
a PASS.

---

## Part 1 — Established by local / CI evidence

Run these on the VPS against the deployed binary. Each one has a command, and each one has
already passed in CI, so a failure here means the deployed artefact differs from the
tested one.

### 1.1 Artefact identity

| Check | Command | Expect |
| --- | --- | --- |
| Binary is the production minimal build | `./sing-box-linux-amd64 version` | `with_quic` and `jiejie_server_minimal` present; `with_tailscale` and `with_openvpn` absent |
| Size guard | `stat -c '%s' sing-box-linux-amd64` | `<= 38000000` |
| Fixture still valid | `./sing-box-linux-amd64 check -c release/jiejie-production-topology.json` | exit 0 |
| Excluded protocol really pruned | a `vmess` inbound config | `check` FAILS |

### 1.2 CONNECT-UDP — the production path

| Check | Evidence already held | Verdict |
| --- | --- | --- |
| HTTP/3 CONNECT-UDP round trip to a real UDP origin | masque-go interop, CI; live H3 test | |
| HTTP/2 CONNECT-UDP behind Nginx | live H2 test in `test/jiejie` | |
| IPv6 destination, H3 and H2 | `TestJiejieMinimalMASQUEH3ConnectUDPIPv6`, `...H2ConnectUDPIPv6` | |
| RFC 9298 request-path parsing | 22-case corpus + `FuzzConnectUDPTargetPath` | |
| Zero-length UDP datagram, both directions, both transports | `TestReferenceConnectUDPZeroLengthDatagram*` | |
| DATAGRAM to Capsule fallback | fallback tests, both protocols | |
| Context IDs other than 0 are dropped, tunnel survives | `TestReferenceConnectUDPUnsupportedContextIDsAreDropped` | |
| Protocol 0 target-port semantics are correct | `TestConnectUDPPortBoundaries`; masque-go interop | |
| Loss / duplication / reordering tolerance | impairment relay with counters | |
| NAT rebind: tunnel survives, new tunnel opens | migration tests | |
| Unauthenticated limiter keyed on source IP, not port | unit + live port-churn test | |
| Authentication boundary (no tunnel without credentials) | masque-go negative case | |
| Graceful shutdown reclaims tunnels | `shutdown_test.go` | |

### 1.3 CONNECT-IP

| Check | Evidence already held | Verdict |
| --- | --- | --- |
| Tunnel handshake, ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT | connect-ip-go interop | |
| IPv4 and IPv6 control capsules decode correctly | `control_capsule_wire_test.go` + live IPv6 endpoint tests | |
| IPv6 ICMPv6 echo round trip | `TestReferenceConnectIPv6DatagramCapsuleFallback` | |
| Capsule fallback with datagrams disabled | `TestReferenceConnectIPDatagramFallback*` | |
| Context IDs other than 0 dropped, session survives | `TestReferenceConnectIPUnsupportedContextIDsAreDropped` | |
| Empty payload dropped, session survives | `TestReferenceConnectIPEmptyPayload*` | |
| Largest ordinary IPv6 packet (65575) accepted | `TestIPv6MaximumOrdinaryPacketIsNotSilentlyDropped` | |
| ICMP Packet Too Big generation, IPv4 and IPv6, both checksums | `TestPacketTooBig*` | |
| ICMP Packet Too Big delivered over a live HTTP/3 tunnel from a real `DatagramTooLarge` | `TestReferenceConnectIPPacketTooBigOverHTTP3Live` | |
| PTB addressed to the peer, checksums valid after the destination rewrite | `TestPacketTooBigCanBeAddressedToAnExplicitPeer` | |
| Cross-session ownership (source forgery rejected) | route/session isolation tests | |
| Route advertisement cannot override the gateway or another client | route validation tests | |
| Protocol 0 means all protocols, and overlap cannot bypass ownership | route validation tests | |
| Control-plane bursts stay bounded | capsule bound and pool lifecycle tests | |

### 1.4 Protocol and abuse boundaries

| Check | Evidence already held | Verdict |
| --- | --- | --- |
| Malformed DATAGRAM capsule terminates the request, not the connection | `TestReferenceConnectUDPDatagramCapsuleFramingIsFatal`, `TestReferenceStreamFailureDoesNotKillTheHTTP3Connection` | |
| Malformed QUIC DATAGRAM does NOT terminate the tunnel | `TestReferenceConnectUDPMalformedDatagramKeepsTheTunnelAlive` | |
| ALPN isolation: TCP cannot negotiate `h3`, QUIC cannot negotiate `h2` | Jiejie ALPN isolation tests | |
| Rejected HTTP/1.1 CONNECT closes the connection (RFC 9931 section 8) | `TestJiejieMASQUERejectedCONNECTClosesTheConnection` | |
| Rejected HTTP/1.1 CONNECT-UDP closes it too (SECURITY-HARDENING) | `TestJiejieMASQUERejectedCONNECTUDPUpgradeClosesTheConnection` | |
| Proxy-Status is present only on the authenticated DNS path | `TestProxyStatus*` | |
| Unauthenticated probes reach the masquerade, never a proxy challenge | probe matrix | |
| Native Naive is not broken by the shared transport changes | Native Naive regression group | |

### 1.5 Fuzzing

| Check | Evidence already held | Verdict |
| --- | --- | --- |
| Seven fuzz targets run bounded in CI | `Fuzz the MASQUE parsers (bounded)` step | |
| Every target defined in the source is registered in CI | coverage check inside that step | |
| Seed corpora are genuinely valid | `TestRouteAdvertisementSeedsAreValid`, `TestAddressSeedsAreValid`, `TestProductionEncoderReproducesTheRFCVectors` | |
| QUICHE protocol vectors agree (context-ID decision table, both protocols) | `TestQuicheOracle*` | |
| Google QUICHE binary builds at the pin and completes an HTTP/3 exchange with sing-box | `TestReferenceQuicheH3TransportLiveInterop` | |
| RFC 9931 client-side optimism (no payload before 2xx/101) | `TestRFC9931*` | |

---

## Part 2 — Only a real VPS can establish this

Nothing below has been measured. Report each as `PASS`, `FAIL`, `SKIP` or `NOT-TESTED`,
with the measurement attached. Do not infer any of these from Part 1.

### 2.1 Real network reachability

| Check | How | What to record |
| --- | --- | --- |
| UDP/443 reachable from a real client network | external client to the TLS name | handshake completes, ALPN is `h3` |
| TCP/443 reaches Nginx Stream, then the H2 listener | `openssl s_client`, then a real client | ALPN `h2`, tunnel works |
| Real Nginx Stream -> `127.0.0.1:28440` path | production Nginx config | request reaches the MASQUE H2 inbound |
| Firewall allows UDP/443 inbound and the reply path | `nft list ruleset` / provider panel | no stateful drop |
| IPv4 WAN and IPv6 WAN both work end to end | client over each family | both carry a tunnel |
| Certificate is the real one, not the fixture | `openssl s_client -showcerts` | correct CN/SAN, valid dates |

### 2.2 Real clients

| Check | How | What to record |
| --- | --- | --- |
| A real MASQUE client completes a session | the client the users actually run | version, protocol, duration |
| CONNECT-UDP to a real UDP service | DNS, QUIC, or a game service | round trip works |
| Behaviour on a mobile network change (real NAT rebinding) | move between Wi-Fi and cellular mid-session | tunnel survives or reconnects; record which |
| Client behind CGNAT | a mobile carrier | tunnel establishes and holds |

### 2.3 Real PMTU and fragmentation

| Check | How | What to record |
| --- | --- | --- |
| Real path MTU to a real client | large-payload probe through the tunnel | the MTU actually observed |
| ICMP Packet Too Big reaches a real client and it reacts | force an oversized packet | client shrinks and recovers |
| No fragmentation black hole | DF-set probe | packets either fit or elicit PTB |
| Behaviour when an intermediate drops ICMP | a path that filters ICMP | record the failure mode |

### 2.4 Resource behaviour over time

| Check | How | What to record |
| --- | --- | --- |
| Long-lived tunnel, hours | one tunnel held open | RSS, FD count, goroutines over time |
| Multi-hour soak with mixed load | realistic client mix | RSS/FD/goroutine trend, CPU |
| High concurrency | many simultaneous tunnels | peak RSS, refused connections, error rate |
| FD exhaustion behaviour | raise concurrency past `ulimit -n` | clean refusal, not a crash |
| Goroutine growth under churn | connect/disconnect loop | goroutines return to baseline |
| CPU under sustained throughput | `pidstat` / `top` | per-core usage at target load |
| Memory under memory pressure | constrained cgroup | behaviour under OOM pressure |
| Network jitter and loss on the WAN | real mobile/congested path | tunnels recover |

### 2.5 Deployment lifecycle

| Check | How | What to record |
| --- | --- | --- |
| `systemctl stop` is graceful | stop with tunnels open | tunnels closed, no error log, clean exit |
| `systemctl restart` | restart under load | reconnects, no port collision |
| Crash recovery | kill -9 | systemd restarts, service returns |
| Real logs at production level | the configured log level | no ERROR for normal operation |
| Log rotation | after rotation | no lost or duplicated output |
| Production config loads | the real server config | `check` passes, service starts |
| Production minimal binary | the shipped artefact | correct tags, size within guard |

### 2.6 Upstream dependencies of the real deployment

| Check | How | What to record |
| --- | --- | --- |
| Upstream DNS (AdGuard Home) resolves correctly | a tunnel to a named target | resolution succeeds |
| Routing rules behave against the real route table | production routing | the intended outbound is chosen |
| `source_ip_cidr` rules see the real client source | a rule that logs or diverts | the source is the real peer |
| Residential SOCKS upstream is reachable | a tunnel through the chain | exit IP is the residential one |

### 2.7 What would make this FAIL rather than NOT-TESTED

A Part 2 row is `FAIL` only when a measurement contradicts an expectation. "Could not test"
is `NOT-TESTED` or `SKIP` with a reason. In particular:

- a tunnel that does not establish from a real client is `FAIL`;
- a path that does not exist on this machine is `SKIP` with the reason;
- behaviour under a load level that was never generated is `NOT-TESTED`.

---

## Reporting

Fill in the verdict column, attach the raw measurements for anything that is not `PASS`,
and record the binary SHA256 and `BUILD-INFO-VPS.txt` alongside the result. If any Part 2
row is `FAIL`, the deployment does not ship until it is understood.

---

## Part 3 — The repeatable runner

`scripts/acceptance/jiejie-masque-vps.sh` automates the parts of this checklist that can be
collected mechanically, and writes a verdict table in the format above.

It is a RUNNER, not a substitute for a deployment. Without reachable infrastructure it
writes `NOT-TESTED` for every row and exits 0 with a report that contains **zero** `PASS`
lines. That is the intended behaviour: the script can only report what it observed, and it
observed nothing.

### Modes

| Mode | What it does | Safety |
| --- | --- | --- |
| `--safe` (default) | Collects facts, inspects the certificate, checks ALPN, runs the external client | Read-only. Changes nothing on the server |
| `--stress` | Adds soak and churn at 10/50/100/250/500 concurrency, with RSS/VmPeak/FD/thread sampling | Loads the server; still modifies nothing |
| `--destructive` | Adds kill -9 recovery | Requires `--destructive` **and** `JIEJIE_ACCEPT_DESTRUCTIVE=1`; anything it changes it restores |

`--destructive` without `JIEJIE_ACCEPT_DESTRUCTIVE=1` refuses to start. A single flag is
too easy to leave in a shell history and re-run against production by accident.

FD exhaustion and cgroup memory pressure are deliberately `SKIP` even in destructive
mode: they need a reviewed plan for the specific host, and an unattended script that
lowers a production limit and fails to restore it is worse than no test.

### Environment

| Variable | Meaning |
| --- | --- |
| `JIEJIE_VPS_HOST` | The deployment. Unset means every row is `NOT-TESTED` |
| `JIEJIE_VPS_USER` | SSH user (default `root`) |
| `JIEJIE_TLS_NAME` | The SNI name, for the certificate and ALPN checks |
| `JIEJIE_MASQUE_USER` / `JIEJIE_MASQUE_PASSWORD` | Test credentials |
| `JIEJIE_VPS_CLIENT` | The EXTERNAL client harness. It must not run on the VPS |
| `JIEJIE_ACCEPTANCE_OUT` | Where the report and `BUILD-INFO-VPS.txt` are written |

Credentials are read from the environment only and never appear on a command line, so they
cannot leak through `ps`, shell history or a CI log. The runner never echoes a password.

### The external client is not optional

The runner refuses to claim any WAN result from the server itself. A `curl` on the VPS
proves the loopback path and nothing about the deployment, so every WAN row depends on
`JIEJIE_VPS_CLIENT` running somewhere else. Its exit codes are interpreted as: `0` PASS,
`77` SKIP with a reason, anything else FAIL.

### Real WAN PMTU is a separate measurement

The runner probes inner payload sizes from 1000 to 1400 over the real path. That result is
recorded **separately** from the loopback Packet Too Big test in
`test/jiejie/reference/connect_ip_ptb_live_test.go`, and the two must never be conflated:
the loopback test proves the ICMP error is generated and delivered by the real
`DatagramTooLarge` path, while this proves what the real network does. Neither substitutes
for the other.

### What automation still cannot produce

Mobile handover, NAT rebinding under a real carrier, and CGNAT remain `NOT-TESTED` until a
person performs the recorded procedure in the report's manual section. Both "survived" and
"reconnected" are acceptable outcomes; what matters is that the recorded observation
matches the expectation.
