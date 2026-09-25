# Production protocol capability matrix

This documents what the **production server binary** actually provides, and how
each item is verified. It exists because a comment saying "registered" and a test
saying "the port listens" are both weaker than they look: neither proves the
protocol chain works end to end, and neither says what was deliberately left out.

**This binary is NOT a general-purpose sing-box build.** It is composed for one
topology (`release/jiejie-production-topology.json`) and deliberately excludes
everything that topology does not need. See "Intentional pruning" below.

Labels are calibrated to evidence strength, not to how good the result sounds. A
row is `PASS` only when a runtime test actually measured the property. Where only
part of a property was measured the row says `PARTIAL`, and where nothing was
measured it says `NOT-TESTED` even if the code is believed correct.

---

## 1. Components

| Component | Implementation | Wire E2E | Security evidence | Resource evidence | Minimal pruning |
| --- | --- | --- | --- | --- | --- |
| AnyTLS | UPSTREAM CORE + FORK HARDENING | **PARTIAL** | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| MASQUE HTTP/2 | UPSTREAM CORE + FORK-MODIFIED SERVER/HARDENING | PASS | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| MASQUE HTTP/3 | UPSTREAM CORE + FORK-MODIFIED SERVER/HARDENING | PASS | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| ShadowTLS v3 | UPSTREAM CORE + FORK HARDENING | **NOT-TESTED** (chain) | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| Shadowsocks 2022 | UPSTREAM CORE | **PARTIAL** | **NOT-TESTED** | **NOT-TESTED** | OK |
| DNS (AGH over UDP) | UPSTREAM | PASS | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| direct outbound | UPSTREAM | PASS | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| residential SOCKS5 outbound | UPSTREAM | PASS | TARGETED CHECKS PASS | **NOT-TESTED** | OK |
| minimal registry | FORK-MODIFIED (`include/`) | **N/A** | INDIRECTLY VERIFIED | **NOT-TESTED** | OK |

### Implementation labels

| Label | Meaning |
| --- | --- |
| `UPSTREAM CORE` | the protocol implementation is not modified by this fork |
| `UPSTREAM CORE + FORK HARDENING` | upstream core, plus fork-added error classification / timeout / logging files |
| `UPSTREAM CORE + FORK-MODIFIED SERVER/HARDENING` | upstream core, plus fork changes to the server and hardening layers |
| `FORK-MODIFIED` | the file is fork-specific |

Why the labels are split this way:

- **AnyTLS** carries fork files `first_read_timeout.go` and `preauth_log.go`, plus
  inbound integration and fallback hardening. Its core wire protocol is upstream,
  so it is `UPSTREAM CORE + FORK HARDENING` rather than plain `UPSTREAM`.
- **ShadowTLS** carries `probe_log.go` and handshake-target failure
  classification, so it is labelled the same way.
- **MASQUE / generic HTTP** carries fork changes across `transport/http/*`,
  `common/badhttp/*`, `option/simple.go` (resource bounds) and the
  forwarded-source policy, so it is
  `UPSTREAM CORE + FORK-MODIFIED SERVER/HARDENING`.
- **SS2022** core is unmodified, so it stays `UPSTREAM CORE` - but that label says
  nothing about testing, and its rows below remain NOT-TESTED.
- **minimal registry** is not a wire protocol at all. `Wire E2E` is `N/A` for it;
  calling it PASS would be a category error.

### Verification strength, stated per row

- **Wire E2E** means a real protocol client exchanged real bytes with the server
  through the actual chain and the payload was checked. "The server starts" and
  "the port listens" are NOT E2E and are not counted as such.
- **Security evidence**, where it says `TARGETED CHECKS PASS`, means the *specific*
  properties listed for that component were tested. It does **not** mean the
  protocol's security has been validated as a whole.
- **Resource evidence** means goroutine, file-descriptor and connection counts
  were observed to return to baseline under churn. **No component currently has
  this**, because no churn-baseline measurement exists outside Native Naive. A
  `-race` pass is not a resource measurement.

---

## 2. Shapes of test, and what each does not prove

| Test shape | Proves | Does NOT prove |
| --- | --- | --- |
| Registry audit | every type the topology names is constructible; nothing extra is registered | that the protocol works |
| Config validation (`sing-box check`) | the fixture parses and references resolve | that anything runs |
| Port listening | a listener was created | that a handshake or a tunnel succeeds |
| In-process integration | the chain works with the built-in registries | that the shipped binary does |
| Real-binary integration | the shipped binary serves the chain as a separate process | behaviour under production load |
| Source read | a guard or dependency is present in the code | that the guard fires at runtime |

Each claim in this document names which shape supports it.

---

## 3. Per-component evidence

### AnyTLS

| Aspect | Status | Evidence |
| --- | --- | --- |
| TLS handshake | PASS | `jiejie_anytls_alpn_*_test.go`, `jiejie_server_test.go` |
| Fallback (non-client) | PASS | `TestJiejieAnyTLSNonClientFallsBackToWeb` |
| Wrong-password fallback | PASS | `TestJiejieAnyTLSWrongPasswordFallsBack` |
| ALPN routing | PASS | `TestJiejieAnyTLSALPNMatrix`, `...FallbackForALPN*` |
| Pre-auth silent-peer timeout | PASS | `TestJiejieAnyTLSSilentPeerIsClosedAfterHandshake` |
| Pre-auth error classification | PASS | `preauth_log_test.go` |
| **Authenticated tunnel E2E** | **NOT-TESTED** | no test drives a real authenticated AnyTLS session through router to origin with byte-for-byte payload |
| **Fragmented authentication prologue** | **NOT-TESTED** | `sing-anytls` `ReadOnceFrom` behaviour with a split prologue is unassessed |
| **Resource churn / baseline** | **NOT-TESTED** | no goroutine/FD/connection baseline measurement |

`Wire E2E` is therefore **PARTIAL**: several real paths were exercised, but the
central authenticated tunnel was not.

### MASQUE HTTP/2 and HTTP/3

| Aspect | Status | Evidence |
| --- | --- | --- |
| Authenticated CONNECT to origin, payload checked | PASS | `authenticated CONNECT works` in `jiejie_server_test.go` (H2 and H3) |
| Unauthorised matrix (GET / CONNECT / CONNECT-UDP, no-auth and wrong-auth) | PASS | `TestJiejieMASQUEH2ProbeMatrix`, `TestJiejieMASQUEH3ProbeMatrix` |
| Unauthenticated limiter, no auth-surface leak | PASS | `TestJiejieMASQUEH3UnauthenticatedLimits`, `...LimiterDoesNotRevealProxyAuthWhenExhausted` |
| Authenticated traffic not limited | PASS | `TestJiejieMASQUEH3AuthenticatedTrafficNotLimited` |
| **Resource churn / baseline** | **NOT-TESTED** | the probe matrix makes no resource measurement (`NumGoroutine` appears zero times). The stream-churn and abort tests in `jiejie_naive_h3_stream_limit_test.go` exercise the **Native Naive** H3 listener, not this one, so they are not counted here |
| **H3 stream limit** | **NOT BOUNDED** | `transport/http/server_h3.go` forces `MaxIncomingStreams = 1 << 60` when unset; `max_concurrent_streams` is HTTP/2-only |
| **IPv6 differential** | **NOT-TESTED** | not measured |
| **Half-close matrix** | **NOT-TESTED** | not measured |

### ShadowTLS v3

| Aspect | Status | Evidence |
| --- | --- | --- |
| Server-side fault classification (ECONNREFUSED, ENETUNREACH, EHOSTUNREACH stay visible; peer reset classified correctly) | PASS | `probe_log_test.go`, `handshake_target_failure_test.go` |
| Inbound registration in the minimal build | PASS | `TestJiejieMinimalShadowTLSInboundRegisters` (listening only) |
| **ShadowTLS -> SS2022 wire E2E** | **NOT-TESTED** | no ShadowTLS client is linked into the production build |
| **UID/auth propagation through the chain** | **NOT-TESTED** | not measured |
| **Resource churn / baseline** | **NOT-TESTED** | not measured |

`Security evidence` is `TARGETED CHECKS PASS`: error classification and
auth-related checks only. The full wire/security E2E remains NOT-TESTED.

### SS2022

| Aspect | Status | Evidence |
| --- | --- | --- |
| Implementation | UPSTREAM CORE, unmodified | - |
| SS2022 session carrying TCP to an origin | **PASS** | `TestJiejieMinimalResidentialSOCKSOutbound` drives a real `shadowaead_2022` client into a production-style SS2022 inbound and reads a real HTTP response back |
| SS2022 -> ShadowTLS chain | **NOT-TESTED** | no test links the two |
| SS2022 standalone against the shipped binary | **NOT-TESTED** | the existing test constructs the inbound in-process, not from the shipped binary |
| Security | **NOT-TESTED** | authentication properties were not probed |
| Resource | **NOT-TESTED** | no churn measurement |

`Wire E2E` is **PARTIAL**: a real SS2022 client does carry real TCP payload
through a real SS2022 inbound to an origin, which is genuine wire coverage - but
it is in-process, not the shipped binary, and it does not cover the ShadowTLS
chain or any UDP path.

Note that the earlier claim "no Shadowsocks client is linked into the production
build" was true of the *server binary* but misleading as a statement about test
coverage: the test module links `sing-shadowsocks` directly and drives the
protocol with a real client.

---

## 4. Minimal registry is not a wire protocol

| Aspect | Status |
| --- | --- |
| Implementation | FORK-MODIFIED (`include/`) |
| Registry coverage | PASS |
| Construction / config audit | PASS |
| Wire E2E | **N/A** - it is a registry, not a protocol |
| Security | INDIRECTLY VERIFIED (it determines what is *not* reachable) |
| Resource | **NOT-TESTED** |

### Intentional pruning

Excluded on purpose, because the production topology does not use them. Their
absence is **not** a defect and is asserted by the CI dependency audit.

| Family | Reason |
| --- | --- |
| Hysteria, Hysteria2, TUIC | other transports; this server is TCP CONNECT over TCP/443 plus MASQUE |
| VMess, VLESS, Trojan, Snell, ShadowTLS client | not part of this topology |
| TrustTunnel | removed when the fork narrowed to VPS-only |
| Reality, XHTTP and other Xray-side protocols | not used by this topology |
| Cronet / Chromium client stack | server build; the Naive OUTBOUND is tag-gated out |
| Caddy, forwardproxy | replaced by Native Naive |
| DNS over TLS/HTTPS/QUIC, hosts, systemd-resolved | the server resolves through AdGuard Home over UDP |

`github.com/sagernet/cronet-go` is asserted absent from the built binary by CI, and
`protocol/naive/outbound.go` carries `//go:build with_naive_outbound` so a server
build cannot compile it in.

---

## 5. DNS transports: why `local` is registered

The topology configures one DNS server (`local-agh`, `type: udp`, AdGuard Home at
`127.0.0.1:53`), but the registry also provides `local`, which looks like dead
weight. It is not.

`box.go` unconditionally initialises the DNS transport manager with a fallback:

```go
dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
    return dnsTransportRegistry.CreateDNSTransport(ctx, ..., "local",
        C.DNSTypeLocal, &option.LocalDNSServerOptions{})
})
```

Omitting the transport makes **every start** fail with
`default DNS server fallback: transport type not found: local`. It is a boot
dependency, not a feature choice.

`TestJiejieRegistryAuditFindsTheExpectedSet` does not carve the name out. It reads
`box.go` and requires `C.DNSTypeLocal` to still be present, so if that fallback is
ever removed the test fails and reports that `local` has become prunable.

---

## 6. Minimal tag scope

The `jiejie_server_minimal` build tag selects between whole registration files.
It does **not** compile out protocol internals:

| File | Build tag | Role |
| --- | --- | --- |
| `include/registry_jiejie_server.go` | `jiejie_server_minimal` | the production registry |
| `include/registry.go` | `!jiejie_server_minimal` | the full registry |
| `include/quic_minimal.go` | `with_quic && jiejie_server_minimal` | registers no inbounds; Naive H3 is absent here |
| `include/quic.go` | `with_quic && !jiejie_server_minimal` | registers `protocol/naive/quic` |

No codec, fallback, UoT path, TLS helper, DNS helper or route helper is behind
this tag. The one behavioural consequence is that the production tag set does not
link `protocol/naive/quic`, so a Naive inbound configured with UDP reports
`C.ErrQUICNotIncluded` instead of starting HTTP/3 - which is why the HTTP/3
integration tests run under a separate tag set in CI rather than silently skipping.

---

## 7. Dependency risks

`CONFIRMED DEPENDENCY BUGS: none.`

`UNASSESSED DEPENDENCY RISKS:`

- `sing-anytls` `ReadOnceFrom` behaviour with a fragmented authentication prologue
  is **NOT-TESTED**.
- `quic-go` HTTP/3 SETTINGS and transport-parameter contents are **NOT-VERIFIED**
  (no packet-level capture).

No confirmed dependency defect was found. Several dependency behaviours remain
unassessed; this is not a statement that the dependencies are risk-free.

---

## 8. Upstream tests are not production-minimal E2E

The repository contains upstream protocol tests (for example `test/shadowtls_test.go`)
that pass under the **full** registry. Those are not counted here as
production-minimal E2E, because:

```
full test topology  !=  shipped minimal server binary
```

Upstream/full-build protocol tests exist and are useful; the production matrix
rows stay `NOT-TESTED` until the minimal binary itself is driven end to end.

---

## 9. Known gaps: REMAINING / NOT-VERIFIED

### Native Naive

- H3 Caddy differential
- H1 / H2 / H3 half-close matrix
- IPv6 differential
- H3 dial-failure comparison against the reference
- `DisablePathManager` connection-migration behaviour
- BBR vs CUBIC controlled benchmark
- H3 `IdleTimeout` / `MaxHeaderBytes`
- Packet-level HTTP/3 SETTINGS and transport parameters
- Malformed H3 CONNECT pseudo-header rejection observed at runtime
  (currently SOURCE-GUARDED only)

### AnyTLS

- Authenticated tunnel production-minimal E2E
- Fragmented authentication prologue
- Full resource churn
- IPv6 / half-close

### ShadowTLS / SS2022

- Production-minimal ShadowTLS -> SS2022 wire E2E
- SS2022 standalone wire E2E against the **shipped binary** (in-process SS2022 TCP
  is covered; the binary and the chain are not)
- SS2022 authentication probing
- UDP / UoT chain
- Resource churn

### MASQUE

- IPv6 differential
- Half-close matrix
- Resource churn / baseline
- **H3 stream limit is effectively unbounded.** `transport/http/server_h3.go`
  forces `MaxIncomingStreams = 1 << 60` when the option is unset (quic-go's
  internal "unlimited" clamp). `max_concurrent_streams` is HTTP/2-only and does
  **not** apply here. This is the same pattern that was measured and removed from
  the Native Naive listener; the MASQUE path retains it and has not been measured.

### Cross-cutting

- No component other than Native Naive has a resource baseline measurement.
- `local` boot dependency is verified by source, not by removing it.
