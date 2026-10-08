# Reference interop stand (REALITY · VLESS encryption · XHTTP · Vision)

> **REFERENCE INTEROP: HARNESS ONLY — NOT RUN.**
>
> Nothing in this directory has been executed against a reference Xray-core
> server. This environment has no external network and no container runtime, so
> the live half of the stand **skips by default** and the reference side was
> never started here. What *has* been verified is the generator and the gate:
> the configurations this stand hands to a reference are asserted, field by
> field, both as raw JSON and through this repository's own config parser.
>
> A maintainer on a machine with Xray installed can run the live half with the
> command in [Running it](#running-it).

## Why this exists

This fork implements four things upstream sing-box does not have in this form —
the REALITY hybrid/classical `key_share` policy, the VLESS application-layer
post-quantum encryption layer, the XHTTP client transport, and Vision running on
top of the encryption layer. All of them are unit-tested. None of them had ever
been verified against a reference implementation.

That is the single largest gap in the project, and it is a specific kind of gap:
a suite of mocks can agree with itself about a wire format and still be wrong.
The only artefact that can falsify a wire format is a real peer, so this stand
generates a real Xray configuration, starts a real Xray process, and moves real
bytes through it. **Nothing here stubs the reference.** If there is no Xray
binary, the live tests skip; they do not pass.

## Layout

| File | What it is |
| --- | --- |
| `scenarios.go` | The scenario matrix: one `Scenario` per combination, with a `Note` recording what a maintainer must know before trusting a failure. |
| `config.go` | The generator. Two independent schemas — this fork's (`snake_case`, `transport`) and Xray's (`camelCase`, `streamSettings`) — written as local structs so a wrong wire key cannot hide behind the option package. |
| `keymaterial.go` | REALITY key pairs, and the two encryption-key providers (reference-owned, and synthetic-for-validation-only). |
| `certificate.go` | The per-run self-signed certificate used by the camouflage server and by the plain-TLS (H3) scenario. |
| `target.go` | The local echo/HTTP destination (`/hello`, `/echo`, `/sink`, `/source`, `/slow`) and the REALITY camouflage TLS server. |
| `reference.go` | Reference process orchestration: locate, start, wait for readiness, capture stdout/stderr, stop, version, and the classical/hybrid version gate. |
| `client.go` | This fork's `box`: parse the generated config, start, stop, restart, and the readiness probe that makes a real proxied request. |
| `registry.go` | The shared compiled-in registry context. |
| `gate.go`, `tag_live_*.go`, `capabilities_*.go` | The gate, its compile-time halves, and the build-capability constants. |
| `optionlayer.go` | The probe for the option-layer gap this stand found (and that is now fixed) — see [The gap this stand found](#the-gap-this-stand-found). |
| `live_test.go` | One top-level test per scenario. Compiled and registered always; the body is gated. |
| `validate_test.go` | The tests that run everywhere. |
| `orchestration_test.go` | Tests for the harness itself (target, camouflage, process exit handling). |
| `harness_test.go` | `*testing.T` wiring: artifact directory, t.Cleanup, failure messages carrying the reference log, and the five per-scenario behaviours. |
| `gen/main.go` | A command that writes every configuration pair to a directory for manual inspection and replay. |

## Running it

The tests live in the repository's `test` module (`test/go.mod`), so **run them
from `test/`**. `go test ./test/interop/` from the repository root does not
resolve, because `test/` is its own module — the same reason the existing
`./contract/server/` and `./jiejie/` suites are invoked as `cd test && …`.

```sh
export GOTOOLCHAIN=go1.25.5
TAGS="$(cat release/DEFAULT_BUILD_TAGS)"
```

### The default run (works anywhere, no Xray)

```sh
cd test
go test -count=1 -tags "$TAGS" -v ./interop/
```

Every live test **skips** with the command that would enable it, and the
generator/validation tests run and must pass. This is the half that is verified
in the environment this stand was written in.

### The live run (needs a reference Xray binary)

```sh
cd test
RUN_LIVE_XRAY_INTEROP=1 XRAY_BINARY=/path/to/xray \
  go test -count=1 -timeout 20m -v \
  -tags "$TAGS,liveinterop" \
  -run TestLiveInterop ./interop/
```

Keep the artifacts (generated configs and both sides' logs) after the run:

```sh
cd test
RUN_LIVE_XRAY_INTEROP=1 INTEROP_KEEP_ARTIFACTS=1 XRAY_BINARY=/path/to/xray \
  go test -count=1 -timeout 20m -v \
  -tags "$TAGS,liveinterop" \
  -run TestLiveInterop ./interop/
```

The random `sing-box-interop-*` directory under `$TMPDIR` is printed; it holds
`client-<scenario>.json`, `server-<scenario>.json`, `box-client.log` and
`xray-server.log`. Without `INTEROP_KEEP_ARTIFACTS=1` the artifacts still land
in the test's temporary directory and their paths **and the tail of every log**
are written into the test output whenever the test fails.

### Inspect a generated pair without running anything

```sh
cd test
go run ./interop/gen -out /tmp/sing-box-interop
```

### Environment variables

| Variable | Meaning |
| --- | --- |
| `RUN_LIVE_XRAY_INTEROP` | Must be `1` for the live half. The environment-side half of the gate. |
| `XRAY_BINARY` | Path to the reference binary. Default: `xray` on `PATH`. |
| `INTEROP_KEEP_ARTIFACTS` | `1` keeps the generated configs and logs in a directory that survives the run. |
| `INTEROP_ENABLE_H3` | `1` enables the XHTTP-over-HTTP/3 scenario, which is opt-in for the reason in the table below. |
| `XRAY_VLESS_ENCRYPTION` | The client `encryption` string of a matched pair. Required for the encryption scenarios to run live. |
| `XRAY_VLESS_DECRYPTION` | The reference `decryption` string of the same pair. |

### Smoke-testing the harness without a reference

A maintainer who wants to confirm the harness itself reaches a protocol
handshake — on a machine with no Xray — can point `XRAY_BINARY` at a stand-in
that is alive and listening but speaks no protocol. The run then **fails** at the
client readiness probe (a present-but-broken reference is a real failure, not a
skip), and the failure message proves what it got to: the client log shows the
`outbound/vless[interop-out]` dial, and a `start the box client:` message would
instead mean the generated config did not even load.

```sh
cat > /tmp/fake-ref-xray <<'PY'
#!/usr/bin/env python3
import json, socket, sys
if len(sys.argv) > 1 and sys.argv[1] == 'version':
    print('Xray 26.10.1 (fake)'); sys.exit(0)
port = json.load(open(sys.argv[sys.argv.index('-c') + 1]))['inbounds'][0]['port']
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port)); s.listen(32)
print('fake xray started', flush=True)
while True:
    s.accept()[0].close()
PY
chmod +x /tmp/fake-ref-xray

cd test
RUN_LIVE_XRAY_INTEROP=1 XRAY_BINARY=/tmp/fake-ref-xray \
  go test -count=1 -timeout 5m -v \
  -tags "$TAGS,liveinterop" \
  -run TestLiveInteropRealityXHTTPStreamOne ./interop/
```

This is **not** reference verification and must never be reported as such: the
stand-in speaks nothing, so no wire format is exercised. It only proves the
orchestration reaches the handshake.

## The gate

The live half needs **both** of:

1. the build tag `liveinterop`, and
2. `RUN_LIVE_XRAY_INTEROP=1` in the environment.

Two halves because they fail differently. The build tag is what a maintainer
controls when *building* — without it the test binary cannot be asked to run
live, so a stray environment variable in a CI image cannot start reference
processes. The environment variable is what a maintainer controls when *running*
— without it, a binary that happens to be built with `-tags liveinterop` for some
other purpose still spawns nothing.

When either half is missing, each live test skips with the exact command that
turns it on. Nothing fails: a machine without a reference has not found a bug.

Further conditions also skip, each naming what is missing:

- **build capability** — a scenario needing `with_utls`, `with_xhttp` or
  `with_quic` in a build that lacks it would otherwise fail inside `box.New` with
  a build-configuration message that reads like a protocol bug;
- **reference version** — see the classical/hybrid split below;
- **encryption key material** — see below;
- **an option-layer regression** — only if the probe in `optionlayer.go` reports
  that this build can no longer load an `xhttp` transport from JSON. That probe
  currently reports success and nothing skips on it; see
  [The gap this stand found](#the-gap-this-stand-found).

The live tests are **compiled and registered in every build**; only their bodies
are gated. `go test -list .` always reports the full inventory.

## Scenarios

| Scenario | Covers | Status |
| --- | --- | --- |
| `reality-classical` | VLESS + REALITY, `key_share: classical` | Implemented. Skips unless the reference is **below v26.9.8**; on v26.9.8+ the server answers with the camouflage site, the client reports a REALITY verification failure, and the failure is indistinguishable from a wrong key — which is why it skips rather than fails, with the version in the message. |
| `reality-hybrid` | VLESS + REALITY, `key_share: hybrid` | Implemented. Skips unless the reference is **at or above v26.9.8**, the release that made the X25519MLKEM768 share mandatory. |
| `reality-encryption` | + VLESS encryption (`native.0rtt`) | Implemented. Also asserts the `key_share` field stays **absent** when no policy is configured. Needs reference-owned key material to run live. |
| `reality-encryption-vision` | + `flow: xtls-rprx-vision` | Implemented. Vision finds the TLS-shaped connection beneath it through the encryption layer's registry entry; without that layer there is no registered connection type to hand Vision and the client fails before the reference sees anything. |
| `reality-xhttp-stream-one` | XHTTP in `stream-one` | Implemented and verified here: raw JSON shape, the option parser round trip, and `box.New`. |
| `reality-encryption-vision-xhttp-stream-one` | **the priority scenario**: every layer at once | Implemented and verified here, same as above. |
| `reality-xhttp-packet-up` | XHTTP `packet-up` | Implemented and verified here, same as above. |
| `reality-xhttp-stream-up` | XHTTP `stream-up` | Implemented and verified here, same as above. |
| `reality-xhttp-auto` | XHTTP `auto` (must resolve to `stream-one` in front of REALITY) | Implemented and verified here, same as above. |
| `tls-xhttp-h3-stream-one` | XHTTP over HTTP/3 | Implemented and verified here; additionally opt-in via `INTEROP_ENABLE_H3=1`. REALITY cannot carry H3 — it is a TCP construction and the client rewrites a REALITY ALPN of `["h3"]` to `["h2"]` — so this scenario uses ordinary TLS with the per-run self-signed certificate. |

Each live scenario, once running, asserts five behaviours, and every one of them
compares bytes:

1. **sequential** — five separate connections, each a fresh TCP connection
   (keep-alives are off, so "separate" means separate), each body compared
   byte-for-byte with what was sent;
2. **concurrent** — eight connections at once, each with its own payload;
3. **cancel** — a request to the never-answering endpoint, cancelled from the
   caller, must end with the caller's `context.Canceled` and must not end before
   the cancellation could have applied;
4. **deadline** — the same endpoint with a 700 ms deadline, which must end with
   `context.DeadlineExceeded` and must have waited for it;
5. **restart** — the client box is stopped and started again over the same live
   reference, must become usable again, and must then carry a real payload. This
   is the fork's own "zombie" reproduction: a stopped core that leaves a session
   or a pooled HTTP connection alive at the reference would show up here.

### Not covered, with reasons

- **UDP.** `xtls-rprx-vision` does not support UDP, and every scenario here uses
  Vision or is a TLS-shaped TCP stream. XHTTP's UDP behaviour (`xudp`,
  `packet_encoding`) is out of scope for this stand.
- **Multiplexing.** The scenarios use one connection per dial; `mux` is a
  separate subsystem with its own tests.
- **XHTTP server.** This fork has no XHTTP server, so the reference must be the
  server for every XHTTP scenario. That is deliberate, not a limitation of the
  stand.
- **The XHTTP `packet-up` + H3 combination.** Refused at generation time: it
  combines the least-verified mode with the least-verifiable listener, and a
  failure would be unattributable.
- **Anything downstream of the reference's `freedom` outbound.** The target is a
  local HTTP server; no external destination is ever contacted.

## The gap this stand found

The first run of the validation tests failed on every xhttp scenario, for a
reason that had nothing to do with the reference. It is recorded here because
finding it is the clearest evidence of what this stand is for.

`option.V2RayTransportOptions.UnmarshalJSON` switches on the transport type to
choose a sub-options struct, and its switch had cases for `http`, `ws`, `quic`,
`grpc` and `httpupgrade` — but **not `xhttp`**. `MarshalJSON` and
`DescribeSchema` knew xhttp, which is how the omission survived: a test that built
options in Go and marshalled them, or that read the JSON schema, never saw it.

`cmd/sing-box/cmd_run.go` loads configuration with
`json.UnmarshalExtendedContext[option.Options]`, so this is the production load
path. A config file containing

```json
"transport": { "type": "xhttp", "path": "/interop", "mode": "stream-one" }
```

was rejected with

```
outbounds[0].transport: unknown transport type: xhttp
```

before `box.New` was ever reached. The transport was compiled in, registered, and
worked — it was simply unreachable from any config file, which also meant no
harness could exercise it.

It was reported to the `option/**` owner and fixed in commit
`8ce22abd7 xhttp: make the transport reachable from a config file`. The xhttp
scenarios now round-trip through the parser and through `box.New` and are
verified here like every other scenario.

The machinery is kept, because the class of defect it guards against is not
fixed by fixing one case:

- `optionlayer.go` **probes** the option layer once per process with a minimal
  xhttp config, and a positive control (`type: ws` must parse) so the probe
  cannot pass vacuously.
- `TestOptionLayerHandlesTheXHTTPTransport` passes both before and after the
  fix: before it pinned the exact rejection so a *different* one could not hide
  behind it, and now it reports that the gap is closed. If the parser ever stops
  understanding xhttp again, the probe fails and this is the first test that
  says so.
- The tests that must load a config through the parser — the option round trip,
  `box.New`, and the live xhttp scenarios — **skip** with a message naming
  `option/v2ray_transport.go` if the probe ever reports a gap again, instead of
  failing for a reason that has nothing to do with the reference.

The **raw-JSON assertions are never gated**: the generator's output is correct
whether or not this build can parse it back, and those tests run either way.

## Encryption key material

The VLESS encryption layer is asymmetric and this fork implements **only the
client half**; the server half (`decryption`) lives in the reference. A Go
program therefore cannot mint a pair the reference would accept, and the stand
does not pretend otherwise:

- `NewSyntheticEncryptionKeyMaterial` mints an X25519 pair in Go. It is used by
  the default validation tests, so the generator and its assertions run in an
  environment with no reference at all. `LiveUsable()` is false and the live
  harness refuses it.
- `ReferenceEncryptionKeyMaterial` obtains a **live-usable** pair from
  `XRAY_VLESS_ENCRYPTION` + `XRAY_VLESS_DECRYPTION`, or by running
  `$XRAY_BINARY vlessenc` and parsing the pair it prints. Both halves are taken
  **verbatim**; the reference is the authority on what it will accept.

If neither source is available and a scenario needs encryption, that scenario
skips with the exact `xray vlessenc` / `export …` sequence to run. It does not
fall back to synthetic material, and it does not fail.

## Reference versions

REALITY's two key_share policies are accepted by **disjoint** ranges of Xray
releases, and one binary cannot satisfy both. The stand reads the reference's own
`xray version` and skips only the impossible one:

| Policy | Accepted by |
| --- | --- |
| `classical` (hybrid share stripped) | Xray **below** v26.9.8 |
| `hybrid` (X25519MLKEM768 required) | Xray **at or above** v26.9.8 |
| unset (fingerprint decides) | any, since the Chrome fingerprint carries the hybrid share |

An unparseable version is treated as *compatible*: failing to parse a version is
the harness's problem, and silently skipping a scenario because of it would hide
a real regression. To cover the classical scenario, point `XRAY_BINARY` at a
pre-v26.9.8 build and run `-run TestLiveInteropRealityClassical`; the workflow
takes the same choice through its `xray_version` input.

## CI

`.github/workflows/interop-xray.yml` is `workflow_dispatch` only. It runs the
default (non-live) half unconditionally, resolves an Xray-core release tag
(`latest` by default, overridable), downloads the linux/amd64 binary, runs the
live matrix with both halves of the gate set, and uploads the generated configs
and both logs as an artifact on every outcome. It fails if the `-run` filter
matches nothing, because a vacuous green tick is the failure mode this stand
exists to prevent.

The default (non-live) half is **not** wired into the push-time `Verify`
workflow: that workflow's test steps are scoped to the packages this fork
changed in the root module, and this package lives in the separate `test` module.
Until someone adds a `cd test && go test -tags "$TAGS" ./interop/` step there, the
default half runs only when this workflow is dispatched or when a maintainer runs
it by hand. That is stated here rather than implied, because "some CI runs it" is
exactly the assumption that lets a suite rot.

## Maturity

Honest summary:

| Part | State |
| --- | --- |
| Configuration generator | **Implemented and verified here.** Every scenario generates a pair; the client config is asserted as raw JSON and through `badjson.UnmarshalExtendedContext[option.Options]`, and accepted by `box.New`; the server config is asserted key-by-key against Xray's schema; the REALITY and encryption key pairs are proven matched by deriving the public half from the private half. |
| Gate | **Implemented and verified here.** The default run reports one skip per scenario with the enable command; `-tags liveinterop` without the environment variable still skips cleanly; the message wording is asserted by a test. |
| Harness (target, camouflage, process orchestration) | **Implemented and verified here** for everything that does not need a reference: echo semantics, TLS with ALPN h2, exit detection (clean and failing), log capture, and the artifact-on-failure path. |
| Live wiring (config → `box.New` → `Start` → outbound dial) | **Driven to a real socket here** against a stand-in reference that listens but speaks no protocol (see [Smoke-testing the harness without a reference](#smoke-testing-the-harness-without-a-reference)). The client started from the generated config, the proxied request reached the outbound, and the failure message carried both logs. The stand-in speaks nothing, so **no wire format was exercised**. |
| Live interop against a real Xray | **NOT RUN.** Never executed, in this environment or any other, for any scenario. |
| The classical/hybrid version split | **Encoded and unit-tested as a rule; not observed.** |
| The option-layer gap this stand found | **Found, reported, and fixed** in `8ce22abd7`; the xhttp scenarios now validate end to end through this build's parser and `box.New`. |

The generator is a harness component. The wire format it targets is still
unverified against a reference server until someone runs the live command on a
machine with Xray. This document will say so until then.
