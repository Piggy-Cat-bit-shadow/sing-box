# Production protocol capability matrix

This documents what the **production server binary** actually provides, and how
each item is verified. It exists because a comment saying "registered" and a test
saying "the port listens" are both weaker than they look: neither proves the
protocol chain works end to end, and neither says what was deliberately left out.

**This binary is NOT a general-purpose sing-box build.** It is composed for one
topology (`release/jiejie-production-topology.json`) and deliberately excludes
everything that topology does not need. See "Intentional pruning" below.

---

## 1. Components

| Component | Implementation | Wire E2E | Security | Resource | Minimal pruning |
| --- | --- | --- | --- | --- | --- |
| AnyTLS | UPSTREAM (pinned `sing-anytls`) | PASS | PASS | PASS | OK |
| MASQUE HTTP/2 | UPSTREAM (`transport/http`) | PASS | PASS | PASS | OK |
| MASQUE HTTP/3 | UPSTREAM (`transport/http` + `server_h3.go`) | PASS | PASS | PASS | OK |
| ShadowTLS v3 | UPSTREAM (`protocol/shadowtls`) | **NOT-TESTED** (chain) | PASS | NOT-TESTED | OK |
| Shadowsocks 2022 | UPSTREAM (`protocol/shadowsocks`) | **NOT-TESTED** (chain) | NOT-TESTED | NOT-TESTED | OK |
| DNS (AGH over UDP) | UPSTREAM (`dns/transport/udp`) | PASS | PASS | NOT-TESTED | OK |
| direct outbound | UPSTREAM | PASS | PASS | NOT-TESTED | OK |
| residential SOCKS5 outbound | UPSTREAM | PASS | PASS | NOT-TESTED | OK |
| minimal registry | FORK-MODIFIED (`include/`) | PASS | PASS | NOT-TESTED | OK |

"UPSTREAM" means this fork carries no modification to the protocol implementation.
"FORK-MODIFIED" means the file is fork-specific and is listed with what it does.

### Verification strength, stated per row

The table above distinguishes what was measured from what was assumed:

- **Wire E2E** means a real protocol client exchanged real bytes with the server
  through the actual chain and the payload was checked. "The server starts" and
  "the port listens" are NOT E2E and are not counted as such.
- **Security** means the specific properties were tested: authentication is
  required, a failed authentication cannot reach a backend, and the source address
  cannot be chosen by the client.
- **Resource** means goroutine, file-descriptor and connection counts were
  observed to return to baseline under churn.

---

## 2. Shapes of test, and what each does not prove

| Test shape | Proves | Does NOT prove |
| --- | --- | --- |
| Registry audit | every type the topology names is constructible; nothing extra is registered | that the protocol works |
| Config validation (`sing-box check`) | the fixture parses and references resolve | that anything runs |
| Port listening | a listener was created | that a handshake or a tunnel succeeds |
| In-process integration | the chain works with the built-in registries | that the shipped binary does |
| Real-binary integration | the shipped binary serves the chain as a separate process | behaviour under production load |

Each claim in this document names which shape supports it.

---

## 3. Intentional pruning

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

## 4. DNS transports: why `local` is registered

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

## 5. Minimal tag scope

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

## 6. Known gaps

Listed so this document is not read as stronger than it is:

- **DNS, direct and SOCKS outbound have no resource tests.** They are exercised
  functionally by the integration suite, but goroutine/fd behaviour under churn was
  not measured.
- **No IPv6 differential** for the MASQUE or AnyTLS paths.
- **No half-close matrix** for MASQUE or AnyTLS.
- **The ShadowTLS to SS2022 chain has no wire E2E.** The existing minimal test
  (`TestJiejieMinimalShadowTLSInboundRegisters`) asserts that both ports LISTEN,
  which proves the registry constructed the inbounds and the detour resolved - it
  does not prove a ShadowTLS client can hand off to SS2022 and reach an origin.
  Reaching that chain needs a full ShadowTLS client, and the server build
  deliberately does not link one. Claiming E2E from a listening port is exactly
  the conflation this document exists to prevent, so the row says NOT-TESTED.
- **SS2022 has no wire E2E at all.** No Shadowsocks client is linked into the
  production build, and no test drives a real SS2022 session against the minimal
  binary.
- **ShadowTLS to SS2022 UDP capability is untested.** The production `ss2022-in` is
  `network: tcp`, so no native Shadowsocks UDP listener exists; UDP would have to
  travel as UoT inside the TCP tunnel. That path is not covered by a test, so it is
  not claimed.
- **UID/auth propagation through the chain is untested** for ShadowTLS.
- **`local` boot dependency verified by source, not by removing it.** The claim
  that omission breaks startup is read from `box.go` rather than reproduced by
  building without it.
