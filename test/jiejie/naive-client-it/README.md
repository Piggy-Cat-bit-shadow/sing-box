# Real-client compatibility test (official NaiveProxy)

`run.sh` runs the **official** [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)
client against this fork's Native Naive inbound.

It exists because the Go test suite cannot prove this: those tests use sing-box's
own outbound or a hand-written client, and neither is the original implementation.
Passing them says nothing about whether the original client can connect.

## Why it is not part of `go test`

It requires a third-party binary that is not vendored, and a TLS certificate the
client will trust. Neither belongs in CI by default, so it is a manual script.

## Client source

Official release asset, verified to be the upstream project's own build:

```
https://github.com/klzgrad/naiveproxy/releases/download/v154.0.8037.49-1/naiveproxy-v154.0.8037.49-1-mac-arm64-arm64.tar.xz
```

Observed identity: `naive 154.0.8037.49`.

## The certificate problem, and why it matters

The official client uses the **platform trust store** (CFNetwork/Security on
macOS) and deliberately offers **no** option to skip certificate verification.
That is correct behaviour for a privacy tool, but it means a self-signed test
certificate is rejected with `ERR_PROXY_CERTIFICATE_INVALID` unless its CA is
trusted first.

A rejection for this reason is **not** a protocol incompatibility, and it must not
be reported as one. The distinction is easy to get wrong:

| Symptom | Meaning |
| --- | --- |
| `ERR_PROXY_CERTIFICATE_INVALID` | TLS trust problem. The protocol was never exercised. |
| TLS succeeds, then the request fails | A real protocol problem. |

To trust a test CA on macOS, add it to the login keychain as a trusted root
(`security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ca.pem`),
then restart the client. The client reads trust state at startup.

## Usage

```sh
./run.sh <naive-binary> <sing-box-binary> <cert-chain.pem> <key.pem>
```

`sing-box-binary` must be built with the Naive inbound registered, for example:

```sh
go build -tags "with_quic,badlinkname,tfogo_checklinkname0,with_naive_outbound" \
  -o /tmp/sing-box-naive ./cmd/sing-box
```

The script builds a temporary server config, a temporary origin, starts the real
client in SOCKS mode, and checks TCP CONNECT, padding negotiation and concurrent
connections. It prints `RESULT: PASS` or `RESULT: FAIL`.

## Results

Run against `naive 154.0.8037.49` and this fork's inbound:

```
PASS  TCP CONNECT through the official client
PASS  Naive Padding negotiated        (client log: "negotiated padding type: Variant1")
PASS  8 concurrent connections
RESULT: PASS
```
