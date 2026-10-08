# REALITY interoperability fix — acceptance report

Audit baseline `01a56cc2a` → **FINAL `1292a85a5`** (plus the flaky-test fix that follows it in the
tree). Branch `testing`, ordinary pushes only, no tag, no Release, no force.

## Verdict

**The REALITY release blocker was a PRODUCT bug, not a harness bug, and it is fixed and verified
against real Xray in CI.**

```
interop (v26.3.27)  success      interop (v26.9.30)  success        run 37823950876
--- PASS: TestLiveInteropRealityClassical                              (v26.3.27 leg)
--- PASS: TestLiveInteropRealityEncryption                             (v26.3.27 leg)
--- PASS: TestLiveInteropRealityHybrid                                 (v26.9.30 leg)
--- PASS: TestLiveInteropRealityEncryptionVision                       (v26.9.30 leg)
--- PASS: TestLiveInteropRealityXHTTPStreamOne                         (v26.9.30 leg)
--- PASS: TestLiveInteropRealityXHTTPPacketUp                          (v26.9.30 leg)
--- PASS: TestLiveInteropRealityXHTTPStreamUp                          (v26.9.30 leg)
--- PASS: TestLiveInteropRealityXHTTPAuto                              (v26.9.30 leg)
--- PASS: TestLiveInteropRealityEncryptionVisionXHTTPStreamOne         (v26.9.30 leg)  ← priority
```
Every scenario runs sequential / concurrent / cancel / deadline / restart subtests; all pass.

## Root causes

Both were introduced by **`f12f44618`** (the REALITY key_share / minimum-client-version commit), and
both were invisible to the unit suite because it tested this client against this fork's own
expectations.

### P0-A — the AEAD additional data carried the PLAINTEXT session id

`prepareFirstFlight` wrote the filled session id into `hello.Raw[39:]` and *then* sealed, so the
additional data — the whole greeting — contained those 16 plaintext bytes. The server rebuilds the
same greeting by **zeroing** the session-id region of the ClientHello it received before it opens the
seal; Xray and the uTLS server both do `copy(hs.clientHello.sessionId, plainText)`, where the parsed
session_id aliases `raw[39:]`. The two additional-data values therefore differed by exactly 16 bytes,
the GCM tag failed inside the server's REALITY handler, the connection fell through to the camouflage
site, and the client reported **`reality verification failed`** — the same message a wrong public key
produces, with no path from that symptom back to the offending line.

Decisive measurement, replaying Xray's own acceptance path over the captured greeting:

```
server authKey from WIRE share[1] match = true      ← key, nonce and shares were all correct
AEAD open with AAD "handshake-raw"         FAILED: cipher: message authentication failed
AEAD open with AAD raw-with-plaintext-sid  MATCH   ← the client's AAD
```

Fixed to the reference order: the raw region stays zeroed through the seal, and the ciphertext is
written into it afterwards.

### P0-A step 7 — a second clock read

`buildSessionID` built the version/time field from the `now` it was given and the timestamp four bytes
later from a fresh `time.Now()`. A caller injecting a clock through uTLS's `Config.Time` — how a test
makes the greeting reproducible — controlled one field and not the other.

### P0-B — the server verifier was dropped

`ClientHandshake` built a uTLS config carrying `realityVerifier.VerifyPeerCertificate`, and
`newClientUConn` then cloned the **stored** config a second time and handed *that* to `utls.UClient`.
The callback was set on one config and the handshake ran on another, so the connection ran with
`InsecureSkipVerify` and no verification callback at all: a connection the server had **accepted**
still ended in `reality verification failed`. Unified into one `realityUConfig(verify)` constructor.

## Harness fixes (the blocker could not have been *seen* without them)

- **`xray vlessenc` is not JSON.** It prints two blocks of `"decryption"/"encryption"` lines under
  `Authentication:` headers (one X25519, one ML-KEM-768). The old parser failed with
  `invalid character 'C'`. It now parses that shape and pairs the halves of **one** block — mixing
  them would produce a key pair no server has. `reality-encryption` runs instead of skipping.
- **The version pin made five scenarios skip, and a skip is not a pass.** `latest` resolves to the
  newest *non-prerelease*, below the hybrid threshold. The workflow now runs two pinned legs with
  `fail-fast: false`, per-leg artifacts, and **a leg that passes no scenario fails**. The gate was
  verified, not assumed: a hybrid-stripped greeting is rejected by v26.9.30 and accepted by v26.3.27.
- **A third gap, found while making the matrix run:** current Xray gives its freedom outbound a
  default rule that blackholes **private** destinations, and the stand's target is loopback by design
  — every scenario would have failed for a reason unrelated to this fork
  (`proxy/freedom: blocked target: tcp:127.0.0.1:...`). The generated server config now allows
  `127.0.0.0/8` and `::1/128` as a final rule, which older references ignore. Same class as the
  version pin: a harness assumption that silently makes the test unable to fail.

## Protocol compatibility — gRPC `service_name`

`v2raygrpclite` **was wrong** and `v2raygrpc` matched the reference. The reference builds
`"/"+name+"/"+tun` and grpc-go writes it into `:path` **verbatim**; the server splits the raw path at
its last slash and matches the literal name, so nothing is escaped anywhere. The lite transport
escaped the whole name, sending `a%2Fb` for a literal `a/b` and `%252F` for a pre-escaped one, so the
same config reached a different service depending on the transport.

Now: no escaping in either; a `Path`/`RawPath` pair whose `EscapedPath()` is the reference string; and
the lite **server** compares `EscapedPath`, not the decoded `Path`, or a name that *is* an escape could
never match its own literal. Tests cover plain, multi-segment, `/`-bearing and pre-escaped names, plus
a cross-transport end-to-end test against a **real grpc-go server** — the implementation Xray uses.

## Commits

| SHA | Purpose |
| --- | --- |
| `245b1321b` | **A** — authenticate the zeroed session id, and read the clock once |
| `1112e7c9b` | **B** — carry the server verifier onto the connection that handshakes |
| `317ce06e9` | sing-tun: serialize Go stack startup and close (release blocker, see below) |
| `eef6bafff` | libbox: retention bound, 7 ABI entries retired, test-link tag fix |
| `933857930` | QUIC idle trim, H2 close residual proven, trafficcontrol race |
| `d8b190f76` | route/dns: cancel stale in-flight dials, refuse cross-kind cycles |
| `060b743bb` | **D + E** — reference matrix, vlessenc parser, gRPC service_name |
| `1292a85a5` | test: deterministic suite + TUN real data-path coverage |
| (tree) | masque: the linearity gate now measures the algorithm |

## Actual test execution

| | Result |
| --- | --- |
| `go test ./common/tls/ -race` | **ok** (17 REALITY tests pass, incl. the server-parse replay, the real-server handshake and the callback test) |
| REALITY regressions reintroduced | both bugs proven to **FAIL** the new tests when re-applied |
| `go test ./... -tags TAGS` | **72 ok, 1 fail** — `experimental/libbox [build failed]`, which is the *inherent* `-checklinkname=0` contract (cmd/go cannot pass per-package ldflags), not fixable from here |
| `common/tlsfragment` | now **green offline** (was 3 permanent reds) and now actually proves fragmentation; it also exposed a latent production bug — with both switches off, `Write` returned `len(b)` **without writing the first flight** |
| `common/trafficsched` | now **deterministic**; 20 iterations under the load that used to break it pass |
| `go build ./...` | only the same libbox linkname |
| `gofmt`, `go mod tidy -diff` | clean, both modules |

## Still not verifiable here

- **H3 (`TestLiveInteropTLSXHTTPH3StreamOne`) never runs** — opt-in by design.
- **IPv6 PacketTooBig / IPv6 fragment reassembly** — addable, needs IPv6 addressing.
- **Device-only**: Android OEM trim delivery, battery, iOS jetsam, radio handover.
- **`test/` module integration suites need Docker** (45 pre-existing environment failures, none in
  touched code).
- **The gated internet tlsfragment test** cannot be exercised on a host with no outbound network; it
  compiles, vets and skips by design.

## Protected files

`clients/apple` (uncommitted user work), `build-screens-doc.py`, `capture-screens.sh` — untouched
throughout; never staged, stashed, reset or cleaned. The Apple `*StringBox` call-site migration
required by the ABI work was made on a **clean worktree at the recorded gitlink**
(`sing-box-apple-worktree`, branch `libbox-stringbox-result-frame`), deliberately out-of-tree.

One stray **127 MB `boxdd` binary** was found in the repo root (an agent build artifact) and deleted
before it could be committed.
