First stable release of this sing-box fork.

- MASQUE / CONNECT-IP implementation and optimizations
- Native Naive server and Cronet Naive client
- HTTP/3 / QUIC lifecycle and error-handling fixes
- DNS and SOCKS5 improvements
- Shadowsocks data-path optimizations
- Native API and Clash API support
- Linux amd64 and macOS arm64 builds

## Downloads

| Platform | File |
|---|---|
| Linux amd64 | `jiejie-sing-box-linux-amd64-v0.1.tar.gz` |
| macOS arm64 | `jiejie-sing-box-macos-arm64-v0.1.tar.gz` |

Each archive contains the binary, a `BUILD-INFO` with the exact commit, tag set and
dependency versions, the licence, and a `.sha256` for the binary. `SHA256SUMS`
covers the archives.

Verify a download with:

```sh
sha256sum -c SHA256SUMS
```

Both binaries are built from upstream's own feature profile, so they carry the
complete upstream protocol and service registry alongside this fork's changes.
