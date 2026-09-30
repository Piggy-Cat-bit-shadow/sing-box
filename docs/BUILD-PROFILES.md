# Build profiles

One `testing` source tree produces two product binaries. The profiles choose build tags, registries, platform glue and packaging; they share protocol implementations.

| | Linux Server Minimal | macOS Client |
| --- | --- | --- |
| Target | `linux/amd64` | `darwin/arm64` |
| CGO | disabled | enabled for Cronet |
| Tag file | `release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL` | `release/BUILD_TAGS_JIEJIE_CLIENT_MACOS` |
| Tags | `with_quic,jiejie_server_minimal,badlinkname,tfogo_checklinkname0` | `with_quic,with_utls,with_naive_outbound,jiejie_client_macos,badlinkname,tfogo_checklinkname0` |
| Registry | `include/registry_jiejie_server.go` | `include/registry_jiejie_client_macos.go` |
| Workflow | `.github/workflows/server-linux-amd64.yml` | `.github/workflows/client-macos.yml` |

## Capability boundary

| | Linux Server Minimal | macOS Client |
| --- | --- | --- |
| Inbounds | `http`, `anytls`, `naive`, `shadowtls`, `shadowsocks` | `tun`, `mixed` |
| Outbounds | `direct`, `socks` | `direct`, `block`, `selector`, `urltest`, `http` (MASQUE), `shadowsocks`, `shadowtls`, `vless`, `anytls`, `naive` (Cronet) |
| Endpoints | none | `masque-client` |
| DNS transports | `udp`, `local` | `udp`, `tcp`, `tls`, `https`, `local`, `hosts`, `fakeip`, `quic`, `h3` |
| Services | none | native `api` |

Both profiles need `with_quic` for MASQUE H3. The client does not use `with_gvisor`: its TUN configuration leaves the stack unset and uses the default Go stack. The server's Native Naive inbound does not imply a Cronet client dependency; only the macOS Naive outbound uses `with_naive_outbound` and CGO. The default-tag upstream full registry remains available.

See [server](JIEJIE-SERVER.md) and [macOS client](JIEJIE-MACOS-CLIENT.md) for product details.

## Build and verification

```sh
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64

./scripts/ci/audit-macos-client-registry.sh dist/sing-box-darwin-arm64
./scripts/ci/check-macos-client-config.sh dist/sing-box-darwin-arm64 /tmp/cfg
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64 /tmp/runtime
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64 /tmp/headless
```

Each build script reads its tag file, and each workflow checks the binary it builds. The scripts inject the version, use `-trimpath` and disable VCS metadata. Reproducibility means equal hashes for repeated builds with the same source, toolchain and build environment; it does not promise bit-identical output across unrelated machines or toolchains.

## CI

Push workflows run formatting, focused tests, one product build and artifact/config/registry checks. `workflow_dispatch` with `deep_checks=true` adds the expensive checks, including vet, reproducibility, race/fuzz work and relevant reference or Cronet checks. Consult the two workflows for the exact current steps and gates. Documentation-only changes are excluded from product builds by their path filters.
