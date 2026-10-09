# Build profiles

One `testing` source tree produces two product binaries. Both are built from
**upstream's own feature profiles**: there is no fork-specific protocol registry and
no allowlist of permitted capabilities.

| | Linux Server | macOS Client |
| --- | --- | --- |
| Target | `linux/amd64` | `darwin/arm64` |
| CGO | disabled | enabled for Cronet |
| Tag file | `release/DEFAULT_BUILD_TAGS_OTHERS` | `release/DEFAULT_BUILD_TAGS` |
| Registry | `include/registry.go` | `include/registry.go` |
| Workflow | `.github/workflows/server-linux-amd64.yml` | `.github/workflows/client-macos.yml` |

Both tag files carry upstream's capability set exactly. The platform split is upstream's
own - its CI uses `DEFAULT_BUILD_TAGS` for CGO/naive builds and
`DEFAULT_BUILD_TAGS_OTHERS` otherwise.

One entry is deliberately missing from both, and it is not a capability:
`tfogo_checklinkname0`, which records that the build passes `-checklinkname=0`. The products do
pass that flag, but these files are also read by `go build ./...` and `go test ./...` under those
tags, where cmd/go cannot apply `-ldflags` to one package - and with the tag set,
`experimental/libbox`'s `//go:linkname` pulls of runtime internals stop linking. The tag lives
where the flag does: `cmd/internal/mobilebuildtags` for the libbox artifacts and
`cmd/internal/build_boxdd` for the daemon. See
[build from source](installation/build-from-source.md#build-tags).

## Capability boundary

Both binaries carry the **complete upstream registry**: the protocols, endpoints,
DNS transports, services and certificate providers upstream ships, not a subset
chosen for this product. That includes `hysteria`, `hysteria2`, `tuic`, `vmess`,
`trojan`, `vless`, `snell`, `ssh`, `tor`, `tproxy`, `redirect`, the `wireguard` and
`tailscale` endpoints, the full DNS transport set and the `resolved` / `ssmapi` /
`origin_ca` services, alongside the capabilities this fork actually serves.

The practical difference between the two profiles is therefore upstream's tag
difference, not a capability boundary this fork maintains:

- The **server** profile omits `with_naive_outbound`, because the Cronet outbound
  is a client capability. The Naive **inbound** is present in both — the live
  production configuration declares one.
- The **client** profile adds `with_naive_outbound` and `with_utls`, because
  upstream's `DEFAULT_BUILD_TAGS` carries them. It does NOT add `with_gvisor`:
  upstream retired that tag when it removed the gVisor dependency in favour of the
  in-process Go TUN stack, and both profiles follow. `scripts/ci/build-macos-client.sh`
  asserts this in both directions - the required tags must be present, and retired
  tags must not reappear.

Because the registry is upstream's, a protocol, endpoint, DNS transport, service or
certificate provider that upstream adds is inherited automatically. There is no
fork-side list to update, and no CI step that has to be told about it.

## Clash API

`with_clash_api` is enabled in both profiles, as upstream ships it. The Clash API and
the Native `api` service are two management surfaces over **one** instance: they share
the traffic manager and the routing-mode manager, so a mode set through the Native
API's `SetClashMode` is the mode the Clash API reports, and both observe the same
connection and log streams.

The two may be configured together. `external_controller` is what makes the Clash API
listen; the Native API listens through its own `api` service entry.

See [server](JIEJIE-SERVER.md) and [macOS client](JIEJIE-MACOS-CLIENT.md) for
product details, and [FORK-DIFF.md](FORK-DIFF.md) for the full list of
fork-specific changes.

## Build and verification

```sh
./scripts/ci/build-server.sh linux amd64 dist/sing-box-linux-amd64
./scripts/ci/build-macos-client.sh arm64 dist/sing-box-darwin-arm64

./scripts/ci/verify-full-capabilities.sh dist/sing-box-darwin-arm64
./scripts/ci/check-macos-client-config.sh dist/sing-box-darwin-arm64 /tmp/cfg
./scripts/ci/check-macos-client-runtime.sh dist/sing-box-darwin-arm64 /tmp/runtime
./scripts/ci/check-macos-client-headless.sh dist/sing-box-darwin-arm64 /tmp/headless
```

`verify-full-capabilities.sh` resolves a minimal valid configuration for every
major protocol, DNS transport, endpoint and service through the shipped binary's
own registry. It replaces the previous capability audit, whose contract was the
opposite one: proving that capabilities were *absent*.

Each build script reads its tag file, and each workflow checks the binary it
builds. The scripts inject the version, use `-trimpath` and disable VCS metadata.
Reproducibility means equal hashes for repeated builds with the same source,
toolchain and build environment; it does not promise bit-identical output across
unrelated machines or toolchains.

## CI

Push workflows run formatting, focused tests, one product build and
capability/config/runtime checks. `workflow_dispatch` with `deep_checks=true` adds
the expensive checks, including vet, reproducibility, race/fuzz work and relevant
reference or Cronet checks. Consult the two workflows for the exact current steps
and gates. Documentation-only changes are excluded from product builds by their
path filters.
