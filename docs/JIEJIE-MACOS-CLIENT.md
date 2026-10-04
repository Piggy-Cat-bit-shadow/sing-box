# Jiejie macOS Client Edition

The macOS client is a headless-first sing-box CLI core for Apple Silicon (`darwin/arm64`). It shares the `testing` source tree with the Linux server and is built from upstream's own Darwin feature profile. launchd can supervise the process; the Native API serves its Web Dashboard. No companion GUI is bundled.

## Build profile and registry

The canonical tag file is `release/DEFAULT_BUILD_TAGS`, which is upstream's Darwin profile:

```text
with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,with_naive_outbound,with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0
```

Both products use `include/registry.go`, which is upstream's complete registry. There is no
fork-specific registry and no capability allowlist: capabilities upstream adds are inherited
automatically. The tag file is upstream's, unmodified: the default capability set matches
upstream's exactly, including `with_clash_api`.

`with_quic` enables MASQUE H3. `with_naive_outbound` links the Cronet-backed Naive client and requires CGO. TUN uses the default Go stack; `with_gvisor` is absent. The client is one product, with no Intel or reduced-capability variant.

| Registry surface | Registered capabilities |
| --- | --- |
| Inbounds | `tun`, `mixed` |
| Outbounds | `direct`, `block`, `selector`, `urltest`, `http` (MASQUE), `shadowsocks`, `shadowtls`, `vless`, `anytls`, `naive` (Cronet) |
| Endpoint | `masque-client` only |
| DNS transports | `udp`, `tcp`, `tls`, `https`, `local`, `hosts`, `fakeip`, `quic`, `h3` |
| Service | native `api` |

The registry is `include/registry.go` (upstream's), with its QUIC surface in `include/quic.go`. `local` DNS remains available for startup fallback. Routing and rule-set support remain available. Capability presence is verified by `scripts/ci/verify-full-capabilities.sh`, which resolves a minimal valid configuration for every major protocol, DNS transport, endpoint and service through the shipped binary.

## Control plane and dashboard

The native `api` service is the management interface. It supports status, logs, connections, groups, outbound selection and tests over its gRPC-based API, and serves the sing-box Web Dashboard. A typical loopback service is:

```json
{
  "services": [{
    "type": "api",
    "tag": "api",
    "listen": "127.0.0.1",
    "listen_port": 9090,
    "dashboard": { "enabled": true, "path": "dashboard" }
  }]
}
```

The dashboard is downloaded or served from the configured directory; it is not embedded in the binary. An unavailable dashboard does not stop TUN, DNS, routing or proxy traffic. Keep the API on loopback unless authentication and exposure are deliberately configured. The Native API remains; the launcher RPC surface and LXD integration have been removed. The Clash compatibility API is also available and can run alongside the Native API, sharing the same traffic and routing-mode state.

## TUN, Naive and MASQUE

The `tun` inbound uses the default Go userspace stack when `stack` is omitted. `mixed` supplies a local HTTP/SOCKS proxy on one port. TUN setup needs the appropriate system privileges; a per-user LaunchAgent cannot create the required interface and routes. CI validates configuration and non-privileged process paths, but does not claim to route real host traffic through TUN.

The shipped `naive` outbound is the Cronet implementation, not a type-only stub. The client uses the `masque-client` endpoint for CONNECT-IP / CONNECT-UDP and an `http` outbound for its MASQUE proxy configuration. Both can use HTTP/3 through the shared transport. Client protocol logic remains in the common source tree; the macOS registry selects the outbound role only. Real remote Naive and MASQUE connectivity is separate from local fixture checks.

## Headless usage

```sh
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64
./dist/sing-box-darwin-arm64 check -c config.json
./scripts/macos/run-headless.sh config.json
open http://127.0.0.1:9090/
```

For supervision, `scripts/macos/install-launchd.sh` installs and starts the service; `scripts/macos/launchd.sh` provides `start`, `stop`, `restart`, `status` and `logs`; `scripts/macos/uninstall-launchd.sh` removes it. A third-party GUI may use the same binary as an external core, but GUI integration is not the supported or verified primary path. Keep files for a LaunchAgent outside macOS TCC-protected Desktop, Documents and Downloads directories. For TUN mode, arrange a privileged run or root-managed service; the helper does not install one automatically.

Example configurations live in `test/jiejie/macos-client/`, including `example-headless.json` and `example-config.json`.

## Verification and limits

```sh
BIN=dist/sing-box-darwin-arm64
./scripts/ci/check-macos-client-config.sh "$BIN" /tmp/fixture
./scripts/ci/check-macos-client-runtime.sh "$BIN" /tmp/runtime
./scripts/ci/check-macos-client-headless.sh "$BIN" /tmp/headless
./scripts/ci/audit-macos-client-registry.sh "$BIN"
```

The scripts check the configuration, process lifecycle, Native API, registry and linked symbols. The audit distinguishes the Cronet implementation from the Naive outbound stub and checks excluded roles. The [macOS workflow](../.github/workflows/client-macos.yml) runs the routine build and offers manual deep checks. Current verification does not establish privileged TUN traffic, third-party GUI integration, remote proxy connectivity or dashboard download from a public network during CI. See [build profiles](BUILD-PROFILES.md) and [engineering notes](ENGINEERING-NOTES.md) for the wider evidence boundary.
