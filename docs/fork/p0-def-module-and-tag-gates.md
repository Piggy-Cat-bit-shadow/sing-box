# P0-D / P0-E / P0-F — module parity, the libbox link, and build-tag gates

Scope: the nested-module dependency parity (P0-D), the `experimental/libbox` link failure (P0-E),
and the untagged build plus the XHTTP capability gate (P0-F). Every claim below was produced by
running the command shown; the outputs are verbatim apart from paths and ANSI colour.

Environment: `GOTOOLCHAIN=go1.25.5`, Go 1.25.5, `darwin/arm64`,
`TAGS=$(cat release/DEFAULT_BUILD_TAGS)`, base commit `fb51b5075`.

---

## 1. P0-D — the two modules did not build the same code

### 1.1 What was wrong

`test/go.mod` is a separate module and inherits neither the root's `replace` directives nor its
`go.sum`. At the base commit:

```text
$ go list -m github.com/sagernet/sing github.com/sagernet/sing-tun github.com/sagernet/quic-go   # root
github.com/sagernet/sing     v0.9.7-0.20260929150544-6f21f2425a95 => .../sing     v0.9.6-0.20261008194531-3af46fe99d3b
github.com/sagernet/sing-tun v0.9.7-0.20261007151655-7539c9855f19 => .../sing-tun v0.0.0-20261008172655-8dde9c8cbe27
github.com/sagernet/quic-go  v0.61.0-sing-box-mod.9              => .../quic-go  v0.61.1-0.20260929231714-9c94b1e90d94

$ cd test && go list -m github.com/sagernet/sing github.com/sagernet/sing-tun github.com/sagernet/quic-go
github.com/sagernet/sing     ... => .../sing    v0.9.6-0.20261004070536-dc9f4ea02e02   <- one commit behind
github.com/sagernet/sing-tun v0.9.7-0.20261007151655-7539c9855f19                      <- NO replace: upstream
github.com/sagernet/quic-go  ... => .../quic-go v0.61.1-0.20260929231714-9c94b1e90d94
```

The two `sing` revisions differ only in `protocol/socks/lazy.go`
(`diff -rq` over both extracted module trees), which is the `WriteOwnedBuffer` first-payload
ownership handoff the root pin adds. The `sing-tun` difference is not a one-file difference: the
nested module linked **upstream** `sing-tun`, so the Go TUN stack's `Start`/`Close` handshake and
the 040 accept-loop recovery — the code whose regressions the integration tests exist to catch —
were not in the binary under test at all.

The guard could not see it. `PARITY_REPLACES=(sing, quic-go)` did not name `sing-tun`, and the
comparison skipped any module the root did not replace, so an omission on both sides was also
invisible. It had already gone green on a tree in exactly that state:

```text
$ GOTOOLCHAIN=auto bash <(git show HEAD:scripts/ci/check-go-module-integrity.sh)   # OLD guard
  ok: github.com/sagernet/sing
  ok: github.com/sagernet/quic-go
PASSED: 3 module(s) verified.
```

…while the tree it passed on had `test` resolving upstream `sing-tun`.

### 1.2 The fix

* `test/go.mod` now replaces `sing` with `v0.9.6-0.20261008194531-3af46fe99d3b` (the root pin) and
  adds the missing `replace github.com/sagernet/sing-tun => ... v0.0.0-20261008172655-8dde9c8cbe27`.
  `test/go.sum` was updated by `go mod tidy`; the only lines that moved are the two fork pins.
* `scripts/ci/check-go-module-integrity.sh` no longer keeps a hand-written parity list. It reads
  the **effective** replacements from the toolchain (`go list -m` with a `.Replace` template),
  which covers every directive form (single-line, `replace (...)` block, filesystem replace) and
  reports nothing for a module the graph does not resolve. The rule is now: *every module the root
  replaces that the nested module also resolves must be replaced identically by the nested module*.
  On this tree that is 34 modules instead of 3 hand-listed ones.
* The hole a derived rule cannot close — a load-bearing replace dropped from **both** sides — is
  closed by an independent expectation, `REQUIRED_FORK_REPLACES` / `REQUIRED_FORK_REPLACE_PREFIXES`.
  It is deliberately not derived from any `go.mod`: it fails when the root stops replacing one of
  the forks, when a parity module stops replacing one, and when the expectation itself rots because
  a module left the graph.
* The guard also evaluates each module with the toolchain that module declares. The reference
  isolation module needs Go 1.26.0; under a pinned `GOTOOLCHAIN=go1.25.5` that used to surface as a
  red gate for something that is not drift. It is now evaluated with `GOTOOLCHAIN=auto`, the
  substitution is printed, and `local`/path settings (explicit "do not download" constraints) are
  honoured as failures rather than overridden. No module is skipped.

### 1.3 Verification

```text
$ bash scripts/ci/check-go-module-integrity.sh --require-checked test
…
--- ./test/jiejie/reference ---
  note: ./test/jiejie/reference declares go 1.26.0 and this toolchain is go 1.25.5;
        evaluating it with GOTOOLCHAIN=auto (the toolchain the module declares).
  ok: go mod tidy -diff is clean
  ok: go list -mod=readonly -m all
Fork replace parity
…
  ok: github.com/sagernet/sing-tun
        root:   github.com/Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27
        test: github.com/Piggy-Cat-bit-shadow/sing-tun v0.0.0-20261008172655-8dde9c8cbe27
  (test: 34 of 34 root replace(s) present in its graph verified)
  ok: test: 31/31 path(s) under github.com/sagernet/cronet-go pinned identically
PASSED: 3 module(s) verified.
```

**Red check.** The `sing-tun` replace was removed from `test/go.mod` and `go mod tidy` re-run, so
the tree was *self-consistent* — tidy clean, graph resolving — and only the resolution was wrong.
That is the historical state exactly. The new guard fails on it:

```text
  FAIL: test/go.mod does not replace github.com/sagernet/sing-tun, but the root module does (… 8dde9c8cbe27).
        A nested module does NOT inherit root replaces; add the same replace.
        Without it test builds UPSTREAM github.com/sagernet/sing-tun, so anything it verifies about
        the fork is a statement about code that is not in the product.
  FAIL: test does not replace the required fork github.com/sagernet/sing-tun (root: … 8dde9c8cbe27)
FAILED: 2 module integrity problem(s).
```

**Red check, both sides.** The case a derived rule cannot see by construction: the `sing-tun`
replace was removed from the **root** module as well. Nothing is left to compare, so the derived
rule has nothing to say — and the independent expectation is what fails:

```text
-- required fork replaces (independent of any go.mod)
  FAIL: cannot verify required fork replace 'github.com/sagernet/sing-tun': the root module graph did not resolve
…
FAILED: 9 module integrity problem(s).
```

### 1.4 Do the `test` suites run against the production sources?

Yes, and the two halves are now both checked:

```text
$ cd test && go list -m -f '{{.Path}} {{.Dir}} => {{.Replace.Path}} {{.Replace.Dir}}' github.com/sagernet/sing-box
github.com/sagernet/sing-box /tmp/fc-deps => ../ /tmp/fc-deps

$ cd test && go list -m -f '{{.Path}} => {{.Replace.Dir}}' github.com/sagernet/sing github.com/sagernet/sing-tun
github.com/sagernet/sing => …/sing@v0.9.6-0.20261008194531-3af46fe99d3b
github.com/sagernet/sing-tun => …/sing-tun@v0.0.0-20261008172655-8dde9c8cbe27
```

The race fix is in the revision both modules now resolve: the module source contains
`stack_go.go`'s published `started` / `closed` / `s.access` handshake and `stack_system.go`'s
re-bind-on-unexpected-accept-error loop.

`test/*.go` being `package main` with no `func main` is verified, not assumed:

```text
$ grep -h '^package' test/*.go | sort | uniq -c
  48 package main
$ grep -rn '^func main' --include='*.go' test/ | grep -v _test.go
test/interop/gen/main.go:28:func main() {          # the config generator, a separate package
```

So `go build ./...` inside `test` legitimately fails and is NOT the build check for that module:

```text
$ cd test && go build ./...
# test
runtime.main_main·f: function main is undeclared in the main package
```

`go vet -tags "$(cat ../release/DEFAULT_BUILD_TAGS_OTHERS)" ./...` is the equivalent whole-module
compile check (it type-checks the test files too and links nothing), and it passes. `verify.yml`
now runs it on every push, next to the module-integrity guard.

---

## 2. P0-E — the `experimental/libbox` link

### 2.1 The three propositions, separated

**(a) The general `-checklinkname=0` contract is real.** `experimental/libbox` pulls
`runtime.getsig`, `runtime.setsig`, `runtime.cgoSigtramp`, `runtime.fwdSig` and
`runtime.handlingSig` (darwin crash handler) and `runtime.allgs`
(`internal/runtimeinfo`). None of those has a push-form `//go:linkname` in the runtime, so the
linker rejects a reference unless the build passes `-checklinkname=0`. That is not a repository
opinion; it is checked against the pinned toolchain's own runtime sources in
`cmd/internal/build_libbox/tag_checklinkname_test.go`, which reads
`$(go env GOROOT)/src/runtime` for push directives and then requires every first-party pull of an
unpushed `runtime.X` to sit behind the `tfogo_checklinkname0` tag.

**(b) The failing link is NOT inherently unfixable, and it is not really about per-package linker
flags.** The concrete failure at the base commit was:

```text
$ go build -tags "$TAGS" ./...            # base commit
# github.com/sagernet/sing-box/experimental/boxdd
link: github.com/sagernet/sing-box/experimental/libbox: invalid reference to runtime.fwdSig
```

`go build ./...` links every `main` package, and `experimental/boxdd` is one that imports libbox.
The build was not missing a cmd/go feature: it was compiling code that requires a linker flag the
tag set claimed and the command did not pass. `release/DEFAULT_BUILD_TAGS` named
`tfogo_checklinkname0`, whose documented meaning (upstream's own
`docs/installation/build-from-source.md`) is "the build uses the `-checklinkname=0` linker flag" —
but the same file is also read by `go build`/`go test ... ./...`, which cannot pass that flag per
package.

**The flag does work when it is passed**, so the test binary is linkable:

```text
$ go build -tags "$TAGS" ./experimental/libbox/                     # library, no link: EXIT 0
$ go build -tags "$TAGS" ./experimental/boxdd/                      # EXIT 1, fwdSig
$ go build -tags "$TAGS" -ldflags=-checklinkname=0 ./experimental/boxdd/     # EXIT 0
$ go test  -tags "$TAGS" -run XXX ./experimental/libbox/            # EXIT 1, fwdSig
$ go test  -tags "$TAGS" -ldflags=-checklinkname=0 -run XXX ./experimental/libbox/
ok  github.com/sagernet/sing-box/experimental/libbox  2.617s [no tests to run]   # EXIT 0
```

**(c) The product build was never affected.** Both release recipes pass the flag —
`release/LDFLAGS` (`-checklinkname=0`) is used by `scripts/ci/build-server.sh`,
`build-macos-client.sh` and `release/local/common.sh`, and `cmd/internal/build_shared.LinkerFlags`
carries it for the libbox/daemon builders.

### 2.2 The fix: the tag now travels with the flag

`tfogo_checklinkname0` was removed from the three `release/DEFAULT_BUILD_TAGS*` profile files. It
is not a capability tag; it is a statement about the link command, and it must live only where the
link command is the one it describes:

| Consumer | Tag source | Passes `-checklinkname=0`? | Result |
|---|---|---|---|
| Android libbox (AAR) | `cmd/internal/mobilebuildtags` | yes | real crash handler and goroutine report |
| Apple libbox (XCFramework) | `cmd/internal/mobilebuildtags` via `applebuildtags` | yes | same |
| `experimental/boxdd` daemon | profile file **+ appended by `build_boxdd`** | yes | same |
| Linux server, macOS CLI | profile file | yes, but neither links libbox | no change at all |
| `go build ./...`, `go test ./...` | profile file | no | stubs; the link completes |

`cmd/internal/build_boxdd/main.go` appends the tag itself, with the reason at the call site:
it is the one profile-file consumer that links libbox into a product, and dropping the tag there
would silently reduce the daemon to the stub crash handler.

The invariant is enforced rather than described, by four tests in
`cmd/internal/build_libbox/tag_checklinkname_test.go`:

* `TestRuntimeLinknamePullsAreGatedOnChecklinkname0` — computed from the pinned runtime.
* `TestProfileTagFilesDoNotClaimChecklinkname0` — the profile files must not name the tag.
* `TestShippedMobileVariantsKeepChecklinkname0` — every shipped mobile variant must, so the fix
  cannot be "remove the tag everywhere and ship stubs".
* `TestBuildBoxddKeepsChecklinkname0` — the daemon still appends it, and `-checklinkname=0` is
  still in `build_shared.LinkerFlags`, so the tag is honest there.

Both halves were red-checked: re-adding the tag to `DEFAULT_BUILD_TAGS_OTHERS` fails the second
test, and removing the constraint from `internal/runtimeinfo/goroutine_badlinkname.go` fails the
first with the `runtime.allgs` mechanism.

### 2.3 Result

```text
$ go build -tags "$TAGS" ./...        # after
# (ld warnings only)
TAGGED_EXIT=0

$ go build -tags "$TAGS" ./experimental/boxdd/     # after, no -ldflags
EXIT=0   (127,416,498 bytes)
```

### 2.4 What remains, precisely

A test binary built with the **mobile** tag set still needs the flag, because that tag set
deliberately includes `tfogo_checklinkname0`: `cmd/internal/mobilebuildtags` describes what the
libbox artifacts ship, and the libbox artifacts do pass `-checklinkname=0`. cmd/go accepts
`-ldflags` only for a whole invocation, never for one package, so a single `go test ./...` that
includes the mobile tag set cannot link libbox interchangeably with packages that must not carry
the flag.

This is `NOT-TESTABLE-AS-ORDINARY-GO-TEST` for exactly one combination — libbox under the mobile
tag set — and it is already handled without skipping anything:
`scripts/ci/test-low-memory.sh` runs `./experimental/libbox` separately with the canonical Apple
tag set and `-ldflags=-checklinkname=0`, and it is a hard gate. Every other configuration lands on
the stub through the tag constraint, so `go test -tags "$TAGS" ./...` (the release profile) and
`go test ./...` (untagged) both link and run libbox normally. Nothing is deleted and nothing is
hidden behind `|| true`.

---

## 3. P0-F — the untagged build and the XHTTP capability

### 3.1 The untagged build did not compile

`go build ./...` with no tags reported three `undefined` errors in `transport/http`. Fixing those
exposed the rest of the same defect class; the complete set at the base commit was:

```text
transport/http/client.go:239:33:        undefined: http3LifecycleTracer
transport/http/stream_error.go:170:5:    undefined: classifyH3ErrorCode
transport/http/stream_error.go:170:34:   undefined: h3ErrorExpected
transport/masque/session.go:88:31:       undefined: transportHTTP.OwnedDatagramSender
transport/masque/session.go:96:36:       undefined: transportHTTP.BatchOwnedDatagramSender
transport/masque/session.go:110:35:      undefined: transportHTTP.OwnedDatagramSender
transport/masque/session.go:111:40:      undefined: transportHTTP.BatchOwnedDatagramSender
transport/masque/session.go:116:34:      undefined: transportHTTP.AsOwnedDatagramSender
transport/masque/session.go:117:39:      undefined: transportHTTP.AsBatchOwnedDatagramSender
transport/masque/server.go:617:19:       undefined: transportHTTP.CarriesQuicSemantics
transport/masque/server.go:618:24:       undefined: transportHTTP.IsExpectedH3Closure
protocol/naive/quic/inbound_init.go:203:12: undefined: newNaiveH3ServerLogger
protocol/naive/quic/inbound_init.go:221:23: undefined: classifyNaiveH3Error
protocol/naive/quic/inbound_init.go:231:20: undefined: normalizeNaiveStreamError
```

Each one is a build constraint that did not match the code it guarded:

| Symbol / file | Was | Is | Why |
|---|---|---|---|
| `http3LifecycleTracer` (`client_h3.go`) | `with_quic` | untagged (`client_h3_tracer.go`) | `client.go`'s constructor type-asserts it; a logging contract with no QUIC dependency |
| `h3ErrorClass`, `classifyH3ErrorCode` (`h3_error_class.go`) | `with_quic` | untagged | `stream_error.go` (untagged by design: it also normalizes HTTP/2 stream errors) needs the shared table |
| `IsExpectedH3Closure`, `CarriesQuicSemantics`, `classifyH3Error` | `with_quic` | untagged | `transport/masque` is untagged and its untagged tests call them |
| `owned_datagram.go` | `with_quic` | untagged | the two capability interfaces and their adapters are `*buf.Buffer` types; `masque` asserts them untagged |
| `protocol/naive/quic/inbound_init.go` | untagged | `with_quic` | the package's only importer is `include/quic.go` (`with_quic`), which exists for this file's side effect; every sibling file and test already had the tag |
| `transport/http/client_h3_strict_fallback_test.go` | untagged | `with_quic` | uses `stubConn` from a `with_quic` test file |
| `protocol/tailscale/endpoint_detour_dependency_test.go` | untagged | `with_tailscale` | constructs `NewEndpoint`, which is `with_tailscale` |
| `common/tls/reality_session_id_test.go` | untagged | `with_utls` | constructs `RealityClientConfig`, which is `with_utls`; its four sibling reality test files already had the tag |

Where the symbol is genuinely usable without QUIC the constraint was removed; where the *package*
is QUIC-only by construction the constraint was added (that is the `protocol/naive/quic` row —
the untagged product already turns a nil `naive.ConfigureHTTP3ListenerFunc` into
`C.ErrQUICNotIncluded` with the "rebuild with `-tags with_quic`" hint, so there is no unsupported
implementation to write).

**No capability was enabled by any of this**, which is checked two ways:

```text
$ go list -deps ./cmd/sing-box            | grep -c <pkg>   # untagged: 0 for every QUIC package
$ go list -deps -tags "$TAGS" ./cmd/sing-box | grep -c <pkg>   # tagged:   1
  protocol/hysteria, protocol/hysteria2, protocol/tuic, dns/transport/quic,
  protocol/naive/quic, transport/v2rayquic

$ /tmp/sb-untagged check -c hysteria2.json
FATAL initialize outbound[1] hysteria2[o]: QUIC is not included in this build, rebuild with -tags with_quic   # exit 1
$ /tmp/sb-untagged check -c dns-quic.json
FATAL initialize DNS server[0] quic[d]: QUIC is not included in this build, rebuild with -tags with_quic     # exit 1
$ /tmp/sb-tagged check -c …                # both accepted, exit 0
```

### 3.2 Results

```text
$ go build ./...                        # untagged, after:  EXIT 0
$ go build -tags "$TAGS" ./...          # after:            EXIT 0
$ go vet ./...                          # untagged, after: only daemon/ and experimental/libbox,
                                        # both "possible misuse of unsafe.Pointer" — pre-existing
                                        # upstream warnings the repo already documents and excludes
```

### 3.3 XHTTP, end to end

`with_xhttp` is in all three profile files and has a registration path
(`include/v2rayxhttp.go` blank-imports `transport/v2rayxhttp`, whose `init` registers the
constructor with the v2ray client transport registry). "Present" was previously asserted by one
`TestProfileTagFilesCarryXHTTP` string check; that proves the file names the tag and nothing about
the binary. Both halves are now covered.

**Compile-time (`go list -deps`, the Linux workflow's audit).** `transport/v2rayxhttp` was added to
the `required` list:

```text
$ go list -deps -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" ./cmd/sing-box | grep -x …/transport/v2rayxhttp
github.com/sagernet/sing-box/transport/v2rayxhttp          # present
$ # same command with with_xhttp removed from the tag list
(no output)                                                 # absent -> the audit fails
```

**Runtime (`scripts/ci/verify-full-capabilities.sh`), which is the half that proves the registry
accepts a config.** Two vless+xhttp cases were added (`stream-one` and `packet-up`), plus an
untagged websocket **control** so a failure can be attributed:

```text
$ verify-full-capabilities.sh <binary built with with_xhttp>
  PASS: outbound-vless-xhttp-stream-one
  PASS: outbound-vless-xhttp-packet-up
  PASS: outbound-vless-ws-control
== capability smoke: 54 passed, 0 failed ==

$ verify-full-capabilities.sh <binary built WITHOUT with_xhttp>       # red check
  PASS: outbound-vless
  FAIL: outbound-vless-xhttp-stream-one
        FATAL initialize outbound[1] vless[o]: create client transport: xhttp: unknown transport type: xhttp
  FAIL: outbound-vless-xhttp-packet-up
        FATAL initialize outbound[1] vless[o]: create client transport: xhttp: unknown transport type: xhttp
  PASS: outbound-vless-ws-control
== capability smoke: 52 passed, 2 failed ==
missing capabilities: outbound-vless-xhttp-stream-one outbound-vless-xhttp-packet-up
```

Removing `with_xhttp` therefore fails the gate in two independent places, at two different levels,
and the control case shows the section is otherwise healthy.

### 3.4 The stale `build-server.sh` claim

The header said the script's "single deviation from upstream's tag file is the removal of
`with_clash_api`, which no longer names any file: the Clash API was deleted from this fork as a
control-plane decision". All three parts were false:

* the script reads `release/DEFAULT_BUILD_TAGS_OTHERS` verbatim and removes nothing;
* `with_clash_api` is in that file, and it names `include/clashapi.go` (`//go:build with_clash_api`),
  which blank-imports `experimental/clashapi`; `include/clashapi_stub.go` is its negation;
* `docs/FORK-DIFF.md` records the Clash API as "Upstream's, enabled in both profiles", and
  `experimental/clashapi` is in the workflow's `required` deps list, so the binary is asserted to
  contain it.

The comment now states that there is no deviation and records what the old one claimed, so a later
reader cannot mistake it for a live decision.

---

## 4. Gates added to CI (`verify.yml`, every push)

| Step | What it fails on |
|---|---|
| `nested Go module integrity` (`--require-checked test`) | a nested module building different fork revisions than the root, or one silently dropped from the checked set |
| `nested test module type-checks against this checkout` | the `test` module not compiling against this tree |
| `build-tag policy and linkname gates` (`go test ./cmd/internal/...`) | the linkname/tag invariants above, plus the existing tag-composition and gVisor tripwires |
| `untagged build of every package` (`go build ./...`) | the untagged configuration regressing to `undefined` |
| `tagged build of every package` (`go build -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" ./...`) | a package whose link depends on a flag the tag set does not carry |

`DEFAULT_BUILD_TAGS_OTHERS` is used for the tagged step because the runner is Linux and the Darwin
profile carries `with_naive_outbound`, which no Linux product links. The same linker contract is
still exercised: `internal/runtimeinfo`'s `runtime.allgs` pull is not GOOS-gated. The Darwin-only
`runtime.fwdSig` half cannot be linked from a Linux runner (a Darwin cgo binary cannot be
cross-linked), so it is guarded structurally by the linkname test instead, which is stated in the
step's comment.

All four workflows touched were checked with `actionlint` (clean), and every changed script with
`bash -n`.

---

## 5. Verification summary

| Command | Before | After |
|---|---|---|
| `go build -tags "$TAGS" ./...` | FAIL (`link: …libbox: invalid reference to runtime.fwdSig`) | **PASS** |
| `go build ./...` (untagged) | FAIL (14 `undefined` errors in 3 packages) | **PASS** |
| `go vet ./...` (untagged) | FAIL (5 packages: 3 missing test constraints + 2 pre-existing) | only the 2 pre-existing `unsafe.Pointer` warnings |
| `go test -count=1 -tags "$TAGS" ./...` | not runnable (build failure) | **PASS**, 74 packages ok, 0 FAIL |
| `cd test && go vet -tags "$(cat ../release/DEFAULT_BUILD_TAGS_OTHERS)" ./...` | PASS | PASS |
| `cd test && go test -tags "$(cat ../release/DEFAULT_BUILD_TAGS_OTHERS)" -count=1 ./...` | not clean (see below) | not clean (see below) |
| `go mod tidy -diff` (root, `test`, reference) | clean | clean |
| `scripts/ci/check-go-module-integrity.sh` | FAILED (and blind to the real defect) | **PASSED**, 34/34 replaces compared |
| `scripts/ci/verify-full-capabilities.sh` | no XHTTP coverage | 54/54, and 52/54 without `with_xhttp` |
| `gofmt -l cmd include option protocol route service transport common dns adapter test` | clean | clean |

### 5.1 The `test` module suite, classified

```text
$ cd test && go test -tags "$(cat ../release/DEFAULT_BUILD_TAGS_OTHERS)" -count=1 -timeout 30m ./...
FAIL	test	619.902s      (39 test failures)
ok  	test/contract/config	1.042s
ok  	test/contract/server	1.835s
ok  	test/interop	2.364s
FAIL	test/jiejie	897.754s  (1 test failure)
```

Every failure is classified, and **none is introduced by this change**:

| Class | Count | Evidence |
|---|---|---|
| ENVIRONMENT — no Docker daemon | 23 | `Cannot connect to the Docker daemon at unix:///var/run/docker.sock` |
| ENVIRONMENT — macOS, Linux-only feature | 7 | `kTLS is only supported on Linux` (3), `TCP Brutal is only supported on Linux` (4) |
| ENVIRONMENT — no working local peer | 6 | `timeout` / `i/o timeout` / `read endpoint: address family not supported` |
| PRE-EXISTING — reproduced with the base pins | 4 | `TestReality`, `TestShadowTLS` (×6 subtests), `TestMASQUESelfToSelf/HTTP2`: `socks5: request rejected, code=1`; `TestJiejieNaiveSharedTLSLifecycleIsSingleOwner`: `close inbound/naive: use of closed network connection` |

The "PRE-EXISTING" column is not an assertion, it is an A/B: the same tree was run with
`test/go.mod`/`go.sum` taken from the base commit `fb51b5075` (upstream `sing-tun`, `sing`
`dc9f4ea02e02`) and those tests failed identically —

```text
BASE pins:
  github.com/sagernet/sing     => …/sing     v0.9.6-0.20261004070536-dc9f4ea02e02
  github.com/sagernet/sing-tun    v0.9.7-0.20261007151655-7539c9855f19        (no replace)

--- FAIL: TestReality (5.02s)      socks5: request rejected, code=1
--- FAIL: TestShadowTLS/v1..v3-utls   socks5: request rejected, code=1
--- FAIL: TestChainedInbound (10.01s)  timeout
--- FAIL: TestMASQUEPacketTooBig (180.37s)  read tcp …: i/o timeout
--- FAIL: TestJiejieNaiveSharedTLSLifecycleIsSingleOwner (0.61s)  close inbound/naive[naive-in]: use of closed network connection
--- FAIL: TestOpenVPNStaticKeySelfToSelf/tcp,udp   missing openvpn outbound queue
--- FAIL: TestBrutalShadowsocks   TCP Brutal is only supported on Linux
```

The pin change made no failure appear and no failure disappear. Nothing is skipped, nothing is
behind `continue-on-error`, and the `test` module's compile check (`go vet ./...`, which is the
build check for that module) is green — the suites themselves need an environment with Docker and
Linux, which this one is not.
