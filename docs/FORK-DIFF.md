# Fork diff manifest

Base: `SagerNet/sing-box` `testing`  
Fork: `Piggy-Cat-bit-shadow/sing-box` `testing`

This fork intentionally changes only the following areas.

## Patch 1: HTTP inbound masquerade

The HTTP inbound can use the existing Hysteria2-style `masquerade` schema for
failed authentication in the shared HTTP/2 and HTTP/3 handler. Authenticated
HTTP CONNECT, CONNECT-UDP, HTTP Datagram, QUIC, and routing paths are not
changed. See [FORK-MASQUERADE.md](FORK-MASQUERADE.md).

## Patch 2: AnyTLS fallback

The AnyTLS inbound exposes `sing-anytls`' existing `FallbackHandler` using
`fallback` and `fallback_for_alpn` options. It does not change the AnyTLS wire
protocol, authentication algorithm, padding, outbound, or `sing-anytls`.
Fallback occurs after TLS termination and routes only to the configured backend.
See [FORK-ANYTLS-FALLBACK.md](FORK-ANYTLS-FALLBACK.md).

## Maintenance

The sole GitHub Actions workflow builds and validates a Linux amd64 server
artifact with the portable upstream build tags, including `with_quic`. It uses
the upstream golangci-lint version for the Linux build, plus focused vet and
feature tests; it intentionally does not run the upstream multi-platform matrix.

There are no other intentional sing-box runtime behavior changes.

## Upstream sync policy

```sh
git fetch upstream
git switch testing
git log --oneline testing..upstream/testing
git diff testing...upstream/testing
```

Merge or rebase upstream changes only after resolving the two patches above and
running the server workflow. Never reset `testing` to `upstream/testing` and
never force-push `testing`.

After every sync, verify HTTP masquerade, AnyTLS fallback, authenticated CONNECT
and CONNECT-UDP, H2/H3 capability, and the Linux amd64 artifact.
