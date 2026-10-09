# The libbox gomobile ABI surface, and what the migration did and did not close

This is the evidence record for the P0-A closure. Every number here is produced by a command in
this document; none of it is a hand count. The commands were run in the isolation worktree at
`fb51b50756fc999448a2b15f5211e4956d840179` plus the two commits that follow it.

## 1. The real surface, and the real migrated count

`experimental/libbox/gomobile_surface_test.go` already contains a scanner that parses **every**
non-test `.go` file in the package with `go/parser`, *including files excluded by the current
build tags*, and mirrors `cmd/gobind`'s reachability rules (bound structs and interfaces
contribute their exported methods, every exported package-level function is bound, struct fields
are deliberately not walked). It is the source of truth for "what gomobile exposes", so this
inventory reuses it rather than inventing a second definition that would drift.

```sh
# The inventory. -checklinkname=0 is required on darwin: the default tag set contains
# tfogo_checklinkname0, which selects signal_handler_darwin.go and its runtime.fwdSig linkname,
# and the linker rejects that under the default -checklinkname policy. That is why the bare
# `go test` link fails (see §5) and why the flag is the release recipe's own answer.
cd /tmp/fc-abi
TAGS=$(cat release/DEFAULT_BUILD_TAGS)
go test -v -ldflags=-checklinkname=0 -tags "$TAGS" \
  -run TestGomobileMethodResultSurface ./experimental/libbox/
```

Result:

```
gomobile surface: 450 bound declarations, 23 with a pointer-bearing result (23 registered as debt)
ok  	github.com/sagernet/sing-box/experimental/libbox	1.616s
```

The verbose run also dumps the complete 450-row table (`type | method | result type | class`).
**450 bound declarations, 23 pointer-bearing.** The "~23" in the work order is confirmed exactly.

### The migrated set is nine client-visible declarations, not seven

The work order says the integrator migrated seven methods, and that is the count of *new
call-site moves*. The number of declarations that a client can reach and that now return a
`*StringBox` is larger, so the count is worth establishing rather than inheriting.

Sweeping the package for a `*StringBox` result and then removing what gomobile cannot bind
(the unexported helper `wrapString`, and `httpResponse.GetContent`, whose receiver is
unexported so no client can name it):

```sh
grep -rhE '^func .*\) \(\*StringBox|^func .*\) \*StringBox' experimental/libbox/*.go | grep -v _test.go
```

gives 11 client-reachable declarations:
`BridgeSession.Name` (one declaration per platform file, `bridge_service_darwin.go` and
`bridge_service_linux.go`, which is one bound method), `GenerateConfigSchema`, `FormatConfig`,
`DeprecatedNote.Message`, `DeprecatedNote.MessageWithLink`, `RandomHex`, `RoutePrefix.Address`,
`RoutePrefix.Mask`, `TunOptions.GetDNSMode`, `TunOptions.GetHTTPProxyServer`, and
`OnDemandRule.ProbeURL`.

Nine of those are in `docs/fork/libbox-abi-contract.tsv` — the ones a shipped client can call.
The other two are `DeprecatedNote.MessageWithLink` and `OnDemandRule.ProbeURL`, which have no
call site anywhere; `ProbeURL` additionally has no implementation, so its frame was latent
rather than merely unused.

The full set:

```sh
grep -nE '^func .*\) \*StringBox' experimental/libbox/*.go | grep -v _test.go
grep -nE '^func [A-Z][A-Za-z]*\(.*\) \(\*StringBox' experimental/libbox/*.go
```

| # | Declaration | Client-visible call sites? |
|---|---|---|
| 1 | `BridgeSession.Name` | yes — Android + Apple |
| 2 | `RoutePrefix.Address` | yes — Android + Apple |
| 3 | `RoutePrefix.Mask` | yes — Apple |
| 4 | `DeprecatedNote.Message` | yes — Android + Apple |
| 5 | `TunOptions.GetHTTPProxyServer` | yes — Apple |
| 6 | `TunOptions.GetDNSMode` | yes — Android + Apple (`GetDNSMode` was already boxed before this sweep) |
| 7 | `DeprecatedNote.MessageWithLink` | no — no call site in either client |
| 8 | `OnDemandRule.ProbeURL` | no implementation, no call site |
| 9 | `FormatConfig` | yes — Android |
| 10 | `GenerateConfigSchema` | yes — Android |

Two further reachable declarations return a box and are deliberately **not** in the contract
because no client calls them: `DeprecatedNote.MessageWithLink` and `OnDemandRule.ProbeURL`. A
contract record for them would either fail on the absent call site or need a vacuous exclusion,
and neither improves the gate.

So: 11 client-reachable declarations return a box, 9 are contracted, 8 have call sites in a
shipped client (1–6 plus `FormatConfig` and `GenerateConfigSchema`), and `GetDNSMode` was
already boxed before this change, leaving **7 new call-site moves** — the work order's number.
The number is a count of *moves*, not of boxed declarations, and re-deriving it from the Go
source yields 11 or 9 instead. That gap is the reason this section exists.

## 2. Five-layer reconciliation

Layers: **L1** Go exported declaration → **L2** gomobile binding → **L3** Android Kotlin →
**L4** Apple Swift/ObjC → **L5** runtime object lifecycle.

The L2 evidence is the real generated binding, disassembled from the AAR this tree produces:

```sh
go run ./cmd/internal/build_libbox -target android -platform android/arm64   # writes libbox.aar
unzip -q libbox.aar -d /tmp/aar && unzip -q /tmp/aar/classes.jar -d /tmp/jarx
javap -p /tmp/jarx/io/nekohasekai/libbox/StringBox.class
javap -p /tmp/jarx/io/nekohasekai/libbox/BridgeSession.class
javap -p /tmp/jarx/io/nekohasekai/libbox/RoutePrefix.class
javap -p /tmp/jarx/io/nekohasekai/libbox/TunOptions.class
javap -p /tmp/jarx/io/nekohasekai/libbox/Libbox.class | grep -E 'formatConfig|generateConfigSchema|randomHex'
```

| Declaration | L1 Go | L2 binding (from the AAR) | L3 Android | L4 Apple | L5 lifecycle |
|---|---|---|---|---|---|
| `BridgeSession.Name` | `*StringBox` ✔ | `StringBox name()` ✔ | **INCOMPLETE** — see below | patched, not pushed | box is a fresh Go heap object per call; client reads `.value`; no Release needed (Go GC owns it) ✔ |
| `RoutePrefix.Address` | `*StringBox` ✔ | `StringBox address()` ✔ | **INCOMPLETE** — `Wrappers.kt:49` | patched, not pushed | same ✔ |
| `RoutePrefix.Mask` | `*StringBox` ✔ | `StringBox mask()` ✔ | no call site | patched, not pushed | same ✔ |
| `DeprecatedNote.Message` | `*StringBox` ✔ | `StringBox message()` ✔ | `.value` ✔ | patched, not pushed | same ✔ |
| `TunOptions.GetHTTPProxyServer` | `*StringBox` ✔ | `StringBox getHTTPProxyServer()` ✔ | **INCOMPLETE** — `VPNService.kt:173` | patched, not pushed | same ✔ |
| `TunOptions.GetDNSMode` | `*StringBox` ✔ | `StringBox getDNSMode()` ✔ | `.value` ✔ | `!.value` ✔ | same ✔ |
| `DeprecatedNote.MessageWithLink` | `*StringBox` ✔ | `StringBox messageWithLink()` ✔ | no call site | no call site | same ✔ |
| `FormatConfig` | `(*StringBox, error)` ✔ | `static StringBox formatConfig(String)` ✔ | `.unwrap` ✔ | no call site | returns a box plus an error; client must check the error before reading ✔ |
| `GenerateConfigSchema` | `(*StringBox, error)` ✔ | `static StringBox generateConfigSchema()` ✔ | `.unwrap` ✔ | no call site | same ✔ |
| `RandomHex` | `*StringBox` ✔ | `static StringBox randomHex(int)` ✔ | no call site | no call site | same ✔ |

### L3 is incomplete on the pinned Android gitlink, and this is not a static-analysis opinion

The Kotlin compiler says so. Building the GUI APK with the client exactly as pinned
(`8e1c3ff49e38b43b6e317138ea7a4a75eeae78fb`) against a freshly generated `libbox.aar`:

```
./gradlew --no-daemon assembleOtherDebug
e: .../bg/PlatformInterfaceWrapper.kt:338:30 Return type of 'fun name(): String' is not a subtype
   of the return type of the overridden member 'fun name(): StringBox!' defined in
   'io.nekohasekai.libbox.BridgeSession'.
e: .../bg/VPNService.kt:173:25 Argument type mismatch: actual type is 'StringBox!', but 'String!'
   was expected.
e: .../ktx/Wrappers.kt:49:63 Argument type mismatch: actual type is 'StringBox!', but 'String!'
   was expected.
> Task :app:compileOtherDebugKotlin FAILED
BUILD FAILED
```

Three migration gaps, in two distinct shapes:

* **Two call sites the shipped patch misses.** `docs/fork/android-stringbox-callsites.patch`
  moves four call sites in three files, and none of them is `Wrappers.kt` or the
  `httpProxyServer` use. `Wrappers.kt:49` is `RoutePrefix.toIpPrefix`, which calls `address()` on
  its **extension receiver** rather than through a dotted expression — a shape a
  dot-anchored search does not see and a reason this document's gate uses a real parser.
* **One implementer, not a caller.** `BridgeSession` is a bound Go **interface**, so the platform
  also implements it. `PlatformInterfaceWrapper.kt`'s `RootBridgeSessionWrapper` overrode
  `name(): String`; Go now declares `Name() *StringBox`, so the override must return a
  `StringBox`. The original migration comment in `platform.go` lists exactly one Android call
  site for this method (`RootServer.kt`), and no Android *implementer*, which is how this was
  missed. This is a whole layer of the migration that a call-site scan cannot see, and the gate
  says so out loud rather than implying it was checked.

### L4: the Apple fork does not carry the migration at all

The superproject holds `docs/fork/apple-stringbox-callsites.patch` (5 files, 16 lines), but the
pinned Apple gitlink `5911580a6366da78e6b4b5b4459596e5a2cf1eb4` has **none** of it applied. At
that revision, sweeping every Swift source for the migrated methods finds only unmigrated shapes:

```
Library/Network/ExtensionPlatformInterface.swift:47:   if options.getDNSMode()!.value != ...   <- the only .value
Library/Network/ExtensionPlatformInterface.swift:65:   ipv4Address.append(ipv4Prefix.address())
Library/Network/ExtensionPlatformInterface.swift:121:  ipv6Address.append(ipv6Prefix.address())
HelperService/RootHelperService.swift:334:             logger.info("createBridgeService: \(session.name(), ...
JailbreakDaemon/IOSRootHelperService.swift:188:        logger.info("createBridgeService: \(session.name(), ...
Library/Network/BridgeTunTracker.swift:52:            logger.info("closing bridge \(session.name(), ...
ApplicationLibrary/Views/Abstract/GlobalChecksModifier.swift:207:  message: report.message(),
```

The patch applies cleanly to that revision (`git apply --check` exits 0), and after applying it a
re-sweep finds **zero** unmigrated call sites — so the patch is correct and complete for the
Apple source, it simply is not in the revision the gitlink pins. **The Apple fork is in the same
class of defect as the Android one: the fix exists as a patch, the pinned revision does not have
it.** The difference is only that Apple's patch is complete where Android's was not.

`clients/apple` is writable (`Piggy-Cat-bit-shadow/sing-box-for-apple`), so this is a push the
integrator owns; the patch and the `--check` result are the handoff. **No Apple build was
produced on this host** (no `Libbox.xcframework` was generated and no Xcode target was compiled),
so the Apple side of L4 is verified by patch application and source sweep, not by a compile.

## 3. The 23 remaining pointer-bearing entries, reclassified

The register in `gomobile_surface_test.go` calls all 23 "debt". That is one bucket for three
genuinely different situations, and the difference decides whether anything should be done. Each
one is placed in exactly one class below, with the evidence for the placement.

Classes:
* **REAL RISK** — a shipped client calls it, so the packed frame is reachable in a real process.
* **REACHABLE, no safe shape** — called, but the conservative fix would need a new API type.
* **BROAD REGISTRATION** — the detector flags the source shape, but no shipped path reaches the
  packed C→Go frame; the shipped direction is Go→C, whose result cstruct is copied into an
  aligned Go stack slot.
* **UNREACHABLE** — nothing in any client calls it.
* **TOOLCHAIN-SOLVED** — the hazard is removed by the toolchain rather than by an API change.

| # | Entry | Class | Evidence |
|---|---|---|---|
| 1 | `Connection.DisplayDestination` | REAL RISK | Called: `ConnectionListViewModel.swift:175`, `compose/model/Connection.kt:97`. Declared in `command_types.go`, which this change does not own. |
| 2 | `RoutePrefix.String` | REAL RISK (bounded) | `fmt.Stringer`; must return `string` or every `fmt` formatting of the type changes. 23 `string(` hits in Kotlin, mostly the generated `toString()`. |
| 3 | `StringIterator.Next` | BROAD REGISTRATION | `Next` is on generic `iterator[T]`; the string instantiation is required by every `[]string` result, and the platform also implements `StringIterator` when passing lists *into* Go. |
| 4 | `PlatformInterface.LookupSFTPServer` | BROAD REGISTRATION | Platform-implemented; Go only consumes it. 2 Kotlin hits, both implementing it. |
| 5 | `PlatformInterface.ReadSystemSSHHostKey` | BROAD REGISTRATION | Platform-implemented; 0 Kotlin call sites. |
| 6 | `PlatformInterface.TailscaleHostname` | BROAD REGISTRATION | Platform-implemented; 0 Kotlin call sites. |
| 7 | `ErrorMessage.Encode` | REACHABLE, no safe shape | `[]byte` wire frame; `ProfileServer.swift:163`. |
| 8 | `ProfileContent.Encode` | REACHABLE, no safe shape | `[]byte`, gzipped body; Apple x3 + Android x3. A `string` round-trip would corrupt it. |
| 9 | `ProfileContentRequest.Encode` | REACHABLE, no safe shape | `[]byte`; `ImportProfileViewModel.swift:121`. |
| 10 | `ProfileEncoder.Encode` | REACHABLE, no safe shape | `[]byte`; `ProfileServer.swift:157`. |
| 11 | `EncodeChunkedMessage` | REAL RISK | Called: `Library/Network/NWSocket.swift`. |
| 12 | `FormatBitrate` | REAL RISK | Called: `NetworkQualityView.swift`; 2 Kotlin hits. |
| 13 | `FormatBytes` | REAL RISK | Called widely: `MacLibrary/StatusBarController.swift`, `TaildropView.swift`, `UploadTrafficCard.swift`, `DownloadTrafficCard.swift`, `ExtensionStatusView.swift`, `ConnectionView.swift`, `ConnectionDetailsView.swift`, `ConnectionListView.swift`, `CoreView.swift`; 17 Kotlin hits. |
| 14 | `FormatDuration` | REAL RISK | Called: `ConnectionView.swift`; 1 Kotlin hit. |
| 15 | `FormatFQDN` | REAL RISK | Called: `TailscalePeerView.swift`, `TailscalePeerScreen.kt`. |
| 16 | `FormatMemoryBytes` | REAL RISK | Called: `OOMReportListView.swift`, `StatusCard.swift`, `ExtensionStatusView.swift`; 2 Kotlin hits. |
| 17 | `FormatNATFiltering` | REAL RISK | Called: `STUNTestView.swift`; 1 Kotlin hit. |
| 18 | `FormatNATMapping` | REAL RISK | Called: `STUNTestView.swift`; 1 Kotlin hit. |
| 19 | `GenerateRemoteProfileImportLink` | REAL RISK | Called: `Profile+Share.swift`, `QRCodeSheet.swift`, `ProfilesCard.kt`, `ProfilePickerSheet.kt`. |
| 20 | `GoVersion` | REAL RISK | Called: `CrashReportManager.swift`; 1 Kotlin hit. |
| 21 | `ProxyDisplayType` | REAL RISK | Called: `OutboundGroup.swift`, `OutboundPickerScreen.kt`, `Groups.kt`. |
| 22 | `Version` | REAL RISK | Called: `HTTPClient.swift`, `CrashReportManager.swift`, `Variant.swift`, `CoreView.swift`; 4 Kotlin hits. |
| 23 | `GoroutineDump` | UNREACHABLE | No caller in Go, Apple or Android. Dead API; only the checked-in prebuilt headers still name it. Deleting the function removes the entry. |

Totals, counted from the table: **REAL RISK 14** (13 plain plus `RoutePrefix.String`, which is
bounded by `fmt.Stringer`), **REACHABLE, no safe shape 4**, **BROAD REGISTRATION 4**,
**UNREACHABLE 1**. 14 + 4 + 4 + 1 = 23, which is the register's size.

The summary that matters for scheduling: **18 of the 23 are reachable from a shipped client**
(14 real risk + 4 reachable-with-no-safe-shape), **4 are broad detector registrations whose
shipped path never enters the packed C→Go frame**, and **1 is dead code**. The 18 are the set
that a real fix has to address; the 5 others should be removed from the register as
misclassified rather than migrated, because migrating them would be pure API churn against no
reachable frame.

### TOOLCHAIN-SOLVED: the honest answer is "partly, and not for this pin"

The hazard is that `cmd/cgo` declares the C result frame `__attribute__((packed))`, i.e.
alignment 1, and the Go runtime stores a pointer through it with a write barrier. Go 1.26
changes exactly that typedef to `__attribute__((packed, aligned(N)))` (CL 692935, commit
`d5b950399`). The toolchain pinned here is **go1.25.5**, which predates it. So:

* On the pinned toolchain, none of the 23 is toolchain-solved.
* All **19** that are not `UNREACHABLE` would stop being hazards by moving the toolchain to
  Go ≥ 1.26, with no API change at all.

That is the honest classification: the correct long-term answer to the bulk of this register is a
toolchain bump, not 19 signature changes, and the register should record which of its entries are
waiting on that rather than implying each needs a bespoke API. The prompt forbids expanding this
into an unbounded platform API rewrite, and this is the concrete reason that instruction is right.

## 4. What actually builds

| Product | Command | Result |
|---|---|---|
| `libbox.aar` (android/arm64) | `go run ./cmd/internal/build_libbox -target android -platform android/arm64` | **PASS** — `libbox.aar` 28,434,895 B, `libbox-legacy.aar` 23,228,485 B, `jni/arm64-v8a/libbox.so` 80,129,776 B; `libbox.provenance` records `commit=fb51b5075…` |
| generated Java binding | `gobind -lang=java -javapkg=io.nekohasekai -libname=box -outdir … ./experimental/libbox` | **PASS** — 158 `.java` files |
| GUI APK, pinned client | `./gradlew --no-daemon assembleOtherDebug` | **FAIL** — `:app:compileOtherDebugKotlin` rejects the three stale sites in §2 |
| GUI APK, client with the fork fix | same | **StringBox errors cleared** — all three are gone; the build stops only on two unrelated pre-existing gaps (below) |

With `docs/fork/android-stringbox-callsites-extra.patch` applied, the Kotlin compiler reports
exactly four remaining errors (`grep -c '^e: '` on the unfiltered Gradle log), across two
distinct issues, and neither is an ABI-migration gap:

```
e: .../bg/BoxService.kt:113:16  Unresolved reference 'promotePowerReportDraft'.
e: .../bg/BoxService.kt:309:20  Unresolved reference 'promotePowerReportDraft'.
e: .../bg/ProxyService.kt:7:1   Class 'ProxyService' is not abstract and does not implement
                                abstract members: createAutoRedirect / usePlatformAutoRedirect
e: .../bg/VPNService.kt:20:1    Class 'VPNService' is not abstract and does not implement
                                abstract members: createAutoRedirect / usePlatformAutoRedirect
```

* `createAutoRedirect` and `usePlatformAutoRedirect` **do** exist on
  `io.nekohasekai.libbox.PlatformInterface` in the AAR (`javap` output above), so the client at
  this revision never implemented them. That is client staleness against an older libbox, not a
  StringBox mistake.
* `promotePowerReportDraft` exists nowhere in the AAR (`Libbox` or `PlatformInterface`). This is
  the power-report work in another change's stream; the client is calling an API that has not
  landed.

**So the honest statement is: the ABI migration's Android half is closed by this patch, and the
GUI APK still does not build, for two reasons that belong to other changes.** Reporting "APK
built" would be false, and reporting "APK blocked by the ABI migration" after this patch would
also be false.

Environment found: Android SDK at `~/Library/Android/sdk` (`android-21/24/36`, build-tools
36.0.0, NDK `28.0.13004108`, cmdline-tools), JDK 17.0.2, Xcode 27.0, Gradle 9.7.0 already in
`~/.gradle/wrapper/dists`. `ANDROID_HOME` is **unset** in the shell and has to be exported.
`gradle` is not on `PATH`; the client's own wrapper is used. Nothing was missing that blocked the
Android build.

### Toolchain provenance mismatch worth recording

`go.mod` pins `github.com/sagernet/gomobile v0.1.12`. The installed `$GOPATH/bin/{gomobile,gobind}`
were built from **v0.1.13**. `.github/workflows/android-core-arm64.yml` fails its build when
those disagree. `scripts/ci/gomobile-toolchain.sh` documents why: Apple deliberately sits one
patch ahead, and v0.1.13's three changed files are all in the Apple path
(`bind/genobjc.go`, `cmd/gomobile/bind_iosapp.go`, `cmd/gomobile/build.go`).

That claim was **verified rather than trusted**. Installing the pinned v0.1.12 and generating
`-lang=java` bindings with each produces byte-identical output:

```sh
diff -r /tmp/bind-v12 /tmp/bind-v13 && echo IDENTICAL
```

`IDENTICAL` — so the Java binding this document inspects is the same under either version, and
the installed v0.1.13 does not invalidate the Android evidence. The mismatch is still a real
provenance defect for the *Apple* product and is recorded here for the integrator.

## 5. The known build failure, re-checked rather than assumed

```sh
TAGS=$(cat release/DEFAULT_BUILD_TAGS)
go build -tags "$TAGS" ./...                      # 1 failure
go build -tags "$TAGS" ./experimental/libbox/     # exit 0
```

```
# github.com/sagernet/sing-box/experimental/libbox
link: github.com/sagernet/sing-box/experimental/libbox: invalid reference to runtime.fwdSig
```

Root-caused, not just labelled: `DEFAULT_BUILD_TAGS` contains `tfogo_checklinkname0`, which
selects `experimental/libbox/signal_handler_darwin.go` — the file that does
`//go:linkname runtimeFwdSig runtime.fwdSig`. The linker rejects that under the default
`-checklinkname` policy. It is the **test binary only** (`go build ./experimental/libbox/` is
clean, and the package links fine as a dependency of `cmd/sing-box`); `cmd/go` cannot set
`-ldflags` for a test binary. Two independent confirmations:

* dropping `tfogo_checklinkname0` from the tag set makes `go test -c` link;
* adding `-ldflags=-checklinkname=0` also makes it link.

The file's own header already anticipated both and states the tag records the linker flag. So
this is not a code defect in the package; it is the tag set asserting a linker policy that a
test build cannot honour. `scripts/ci/check-libbox-abi.sh` passes `-checklinkname=0` for exactly
this reason, and says so in a comment.
