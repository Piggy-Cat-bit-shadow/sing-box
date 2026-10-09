# Apple build artifacts: what was produced, what was verified, and what is blocked

Verification run performed on `fix/apple-artifacts`, from core commit
`0fbca85462689c1ea72f7f1af511540ff873aeba` (the inherited head of the Apple artifact work),
with `GOTOOLCHAIN=go1.25.5` and `TAGS=$(cat release/DEFAULT_BUILD_TAGS)`.

The Apple gitlink under test is `2b23330d489b9f6b45e98f903f458842e8961594`
(`git ls-tree HEAD clients/apple`).

**Read this first:** the Apple client tree at that revision was NOT reachable from the host this
run was performed on, so every claim below is separated into one of three classes, and the class is
named in each case:

| class | meaning |
|---|---|
| **ARTIFACT** | proven against a built binary, header or artifact on this host |
| **PATCH** | proven against the patch text in this repository, not against the client revision |
| **DEVICE-ONLY** | cannot be established without a running extension on hardware |

Nothing below is promoted from PATCH to ARTIFACT, and nothing is reported as a product build that
was not produced.

---

## 1. Environment, measured rather than assumed

Present:

```
Xcode 27.0 (27A266a), xcode-select /Applications/Xcode.app/Contents/Developer
iOS SDK 27.0, iOS Simulator SDK 27.0, macOS SDK 27.0, tvOS SDK 27.0
Apple Swift 6.4 (swiftlang-6.4.0.34.1 clang-2100.3.34.1)
Apple clang 21.0.0 (clang-2100.3.34.2), host macOS 27.0 arm64
go1.25.5 darwin/arm64, GOTOOLCHAIN=go1.25.5
gomobile and gobind: github.com/sagernet/gomobile v0.1.13, built with go1.25.5
  (read out of the binaries with `go version -m`; this is the Apple pin that
   scripts/ci/gomobile-toolchain.sh declares, not the root go.mod pin)
OpenJDK 17.0.2 (arm64)
```

Absent, and it decides two of the items in §6:

```
network to github.com: unreachable. `git ls-remote` and `curl` to
  raw.githubusercontent.com both time out (75 s / 20 s); web fetch fails identically.
clients/apple: an UNPOPULATED submodule in this worktree, and this worktree is forbidden
  from reading the superproject it borrows its object store from.
```

One environment defect cost a build and is worth recording: `~/go/bin` is not on `PATH`, and
`gomobile bind` resolves `gobind` with `exec.LookPath` (`cmd/gomobile/bind.go:102`), so the first
build died with `gobind was not found. Please run gomobile init before trying again` while both
binaries existed. The build needs `PATH="$HOME/go/bin:$PATH"`; that is a harness fact, not a code
defect, and the CI workflow puts the same directory on `GITHUB_PATH` for exactly this reason.

## 2. `Libbox.xcframework` — produced (ARTIFACT)

Built with the project's own entry point, which is the script the release pipeline uses:

```
$ APPLE_CLIENT_DIR=/tmp/v16-apple-install PATH="$HOME/go/bin:$PATH" \
    bash scripts/ci/build-apple-libbox.sh both
building Libbox.xcframework for: ios,macos
source commit: 0fbca85462689c1ea72f7f1af511540ff873aeba
  module proxy: local cache first (file:///Users/jie/go/pkg/mod/cache/download)
...
xcframework successfully written out to: /private/tmp/v16-applebuild/Libbox.xcframework
INFO[1018] wrote libbox.provenance (commit=0fbca85462689c1ea72f7f1af511540ff873aeba version=0.0.0-v0.1-0fbca8546)
installed: /tmp/v16-apple-install/Libbox.xcframework  (from Libbox.xcframework)
  ios-arm64                        ['arm64']
  macos-arm64_x86_64               ['arm64', 'x86_64']
build-apple-libbox: PASS
real 17m1.681s
```

`APPLE_CLIENT_DIR` was pointed at a scratch directory because `install_into` writes into the client
checkout and `clients/apple` is read-only for this work; the framework is byte-identical wherever
it is copied.

Paths, sizes and architectures:

```
/tmp/v16-applebuild/Libbox.xcframework                        349M
  ios-arm64                                                  116M   arm64
    Libbox.framework/Versions/A/Libbox  121,441,584 bytes   Mach-O universal, [arm64: current ar archive]
  macos-arm64_x86_64                                         233M   x86_64 arm64
    Libbox.framework/Versions/A/Libbox  244,075,160 bytes   Mach-O universal, [x86_64][arm64: current ar archive]
/tmp/v16-apple-install/Libbox.xcframework                     349M   (installed copy)
```

`Info.plist` reports exactly two slices, `ios-arm64` (ios) and `macos-arm64_x86_64` (macos); the
script asserts the `ios-arm64` slice and a macOS slice rather than assuming them. There is no
simulator and no tvOS slice by design (tvOS is not a product this fork builds; the x86_64
simulator cannot link against the pinned cronet-go, which ships no `ios_amd64_simulator`
library).

Provenance, from the `libbox.provenance` the build wrote at the repository root:

```
commit=0fbca85462689c1ea72f7f1af511540ff873aeba
version=0.0.0-v0.1-0fbca8546
tags.apple=with_quic,with_wireguard,with_utls,with_naive_outbound,with_xhttp,with_clash_api,
  with_usbip,with_openvpn,with_openconnect,badlinkname,tfogo_checklinkname0,with_tailscale,
  ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor,
  ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_dhcp,grpcnotrace
```

The provenance is corroborated from inside the binary rather than only from the file: the macOS
probe in §3.3 prints `LibboxVersion() = 0.0.0-v0.1-0fbca8546`, which is the same commit.

The same `Libbox.objc.h` is shipped in both slices
(`sha256 030b845c0f640163a02436dbe1b1f0755dd630d1c21ca12510c23b5a308b1d02`), so the two platforms
cannot be reading different declarations.

## 3. The ABI, checked at the artifact and not in the source (ARTIFACT)

### 3.1 What the shipped header declares

`Libbox.xcframework/ios-arm64/Libbox.framework/Headers/Libbox.objc.h` (143,681 bytes, 272
declarations). Every method the migration moved returns the box:

```
  255  [LibboxBridgeSession]  - (LibboxStringBox* _Nullable)name;
  574  [LibboxTunOptions]     - (LibboxStringBox* _Nullable)getDNSMode;
  579  [LibboxTunOptions]     - (LibboxStringBox* _Nullable)getHTTPProxyServer;
 1086  [LibboxDeprecatedNote] - (LibboxStringBox* _Nullable)message;
 1756  [LibboxRoutePrefix]    - (LibboxStringBox* _Nullable)address;
 1757  [LibboxRoutePrefix]    - (LibboxStringBox* _Nullable)mask;
 2374  FOUNDATION_EXPORT LibboxStringBox* _Nullable LibboxFormatConfig(...);
 2386  FOUNDATION_EXPORT LibboxStringBox* _Nullable LibboxGenerateConfigSchema(...);
 2482  FOUNDATION_EXPORT LibboxStringBox* _Nullable LibboxRandomHex(int32_t length);
```

`libbox-abi-contract.tsv` names nine migrated declarations. One of them, `BridgeSession.Name`, is
an **interface**, so the platform implements it as well as calling it, and its Swift spelling is
the protocol, not the class:

```objc
@protocol LibboxBridgeSession <NSObject>
- (BOOL)close:(NSError* _Nullable* _Nullable)error;
- (int32_t)fileDescriptor;
- (BOOL)inet6Active;
- (LibboxStringBox* _Nullable)name;
- (BOOL)setEgress:(NSString* _Nullable)interfaceName error:(NSError* _Nullable* _Nullable)error;
@end
```

and the box itself is constructible and writable from Swift, which the implementer needs:

```objc
@interface LibboxStringBox : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;
- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic, setter=setValue:) NSString* _Nonnull value;
@end
```

The observer's calls are present with the types the patch uses:
`- (void)recordScreenState:(BOOL)on;` (line 806), `- (void)recordLockState:(BOOL)locked;`
(line 784), `- (void)wakeNow;` (line 907), `- (void)pause;`, `- (void)wake;`.

The generated header also carries the Go doc comment that names the shipped call sites, so the
contract is visible in the artifact itself, not only in the TSV.

### 3.2 The compiler, on the real header (GREEN and RED)

The harness is committed and re-runnable: `scripts/ci/apple-abi-probe.sh <path-to-Libbox.xcframework>`
sources `scripts/ci/apple-abi-probe/`. It is not a re-typing of the API: the call-site
lvalues are copied from the right-hand sides of `docs/fork/apple-stringbox-callsites.patch`, the
implementer body is copied from `docs/fork/apple-bridge-session-implementer.patch`, and the
observer file is the verbatim text of `docs/fork/apple-screen-state-observer.patch`. On the
framework built in §2 it prints:

```
-- green: migrated call sites + implementer + observer, arm64-apple-ios15.0
   GREEN OK (0 errors)
-- green: the same three files, arm64-apple-macos13.0 (the observer compiles away)
   GREEN OK (0 errors)
-- red: the pre-migration shapes must NOT compile
   RED OK (15 errors, all naming LibboxStringBox)
-- runtime: link and run against the macOS slice
LibboxStringBox round-trip OK: jiejiebox-abi-probe
LibboxVersion(): 0.0.0-v0.1-0fbca8546
two independent LibboxStringBox instances OK
apple-abi-probe: PASS
```

GREEN, iOS device, against the built framework:

```
$ swiftc -typecheck -target arm64-apple-ios15.0 -sdk "$(xcrun --sdk iphoneos --show-sdk-path)" \
      -F Libbox.xcframework/ios-arm64 callsites.swift implementer.swift observer.swift
IOS_GREEN_EXIT=0        (0 errors)
```

GREEN, macOS, same three files:

```
$ swiftc -typecheck -target arm64-apple-macos13.0 -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
      -F Libbox.xcframework/macos-arm64_x86_64 callsites.swift implementer.swift observer.swift
MACOS_TYPECHECK_EXIT=0  (0 errors; the `#if os(iOS)` observer compiles away)
```

RED — the pre-migration shapes must not compile, or the check above proves nothing:

```
$ swiftc -typecheck -target arm64-apple-ios15.0 ... redcheck.swift
IOS_RED_EXIT=1   (15 errors)
redcheck.swift:18:34: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (message)
redcheck.swift:19:39: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (session.name)
redcheck.swift:20:34: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (address)
redcheck.swift:21:31: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (mask)
redcheck.swift:22:39: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (getHTTPProxyServer)
redcheck.swift:23:35: error: cannot convert value of type 'LibboxStringBox?' to specified type 'String'   (getDNSMode)
redcheck.swift:29:13: error: type 'OldBridgeServiceSession' does not conform to protocol 'LibboxBridgeSessionProtocol'
```

This is the half a call-site grep cannot reach: the old `func name() -> String` witness is rejected
by conformance, so the implementer really did have to move with the interface.

### 3.3 The artifact runs (ARTIFACT)

Type-checking proves declarations; it does not prove the framework links or works. A macOS arm64
binary was linked against the shipped macOS slice and executed:

```
$ swiftc -target arm64-apple-macos13.0 -F Libbox.xcframework/macos-arm64_x86_64 runtime.swift \
      -framework Foundation -framework AppKit -framework CoreFoundation -framework CoreText \
      -framework CoreServices -framework CFNetwork -framework Network -framework SystemConfiguration \
      -framework Security -framework IOKit -framework IOUSBHost -framework UniformTypeIdentifiers \
      -framework DiskArbitration -lresolv -lbsm -o runtime_probe
$ ./runtime_probe
LibboxStringBox round-trip OK: jiejiebox-abi-probe
LibboxVersion(): 0.0.0-v0.1-0fbca8546
two independent LibboxStringBox instances OK
RUNTIME_EXIT=0
```

`runtime_probe` is `Mach-O 64-bit executable arm64`, 78,341,728 bytes, `Signature=adhoc`
(linker-signed, no identity applied).

The system-framework list is not arbitrary and is worth keeping: the static framework needs
`Network`, `SystemConfiguration`, `Security`, `CoreServices`/`CFNetwork`, `CoreText`, `IOKit`,
`IOUSBHost`, `UniformTypeIdentifiers`, `AppKit`, `libresolv` and `libbsm` on macOS; without
`libbsm` the link fails on `_audit_token_to_pid`, and without `IOUSBHost` on the USB/IP symbols.

## 4. The iOS link, and a real defect it exposed (ARTIFACT)

The iOS slice does **not** link with a plain link, and this is not a configuration mistake on the
harness side:

```
$ swiftc -target arm64-apple-ios15.0 ... -F Libbox.xcframework/ios-arm64 runtime.swift ...
Undefined symbols for architecture arm64:
  "base::MessagePumpKqueue::InitializeFeatures()", referenced from:
      base::features::Init() in Libbox[arm64][119](features.o)
ld: symbol(s) not found for architecture arm64
IOS_LINK_EXIT=1
```

Attribution, measured in both slices and in the pinned dependency:

| archive | `MessagePumpKqueue::InitializeFeatures` | defined `MessagePumpKqueue` symbols |
|---|---|---|
| `Libbox.xcframework/ios-arm64/.../Libbox` | **undefined** | **0** |
| `Libbox.xcframework/macos-arm64_x86_64/.../Libbox` | defined (`T`) | 54 |
| cronet-go prebuilt `lib/ios_arm64@.../libcronet.a` | **undefined** | **0** |
| cronet-go prebuilt `lib/darwin_arm64@.../libcronet.a` | defined (`T`) | 54 |

So the defect is upstream of this repository: the pinned
`github.com/Piggy-Cat-bit-shadow/cronet-go` prebuilt iOS archive contains an object that calls
`base::MessagePumpKqueue::InitializeFeatures()` while the archive does not contain the object that
defines it. The macOS archive is internally consistent. This is the first time it has been visible
in this repository, because this is the first Libbox.xcframework built for iOS here - the same
limitation `docs/fork/apple-screen-state-acceptance.md` §7.1 records.

With `-dead_strip` (Xcode's Release default, `DEAD_CODE_STRIPPING = YES`) the reference is dropped
with the dead code and the link succeeds:

```
$ swiftc -target arm64-apple-ios15.0 -sdk "$IOS_SDK" -F Libbox.xcframework/ios-arm64 runtime.swift \
      ... -Xlinker -dead_strip -Xlinker -syslibroot -Xlinker "$IOS_SDK" \
      -Xlinker -platform_version -Xlinker ios -Xlinker 15.0 -Xlinker 15.0 -o ios_runtime
IOS_LINK_EXIT=0
$ file ios_runtime
ios_runtime: Mach-O 64-bit executable arm64          (70,126,536 bytes)
$ vtool -show-build ios_runtime
 platform IOS, minos 15.0, sdk 15.0
$ codesign -dvv ios_runtime
ios_runtime: code object is not signed at all
```

**This is an unsigned iOS device binary produced from this core, and it is the strongest iOS
evidence this host can produce.** It is not a product: it is a link-level consumer of the shipped
framework. The consequence for the release is stated rather than smoothed over - an iOS app built
from this core links only because the dead-strip drops the reference; whether that holds for every
configuration, and whether the cronet path that would have called `InitializeFeatures` is
reachable at runtime, is not established here. The dependency-level fix (rebuild the cronet-go
`ios_arm64` archive with the `base::MessagePumpKqueue` translation unit included) is outside this
workstream and is reported as an upstream item.

## 5. The observer against §7-§12 of the brief (PATCH)

Target of review: `docs/fork/apple-screen-state-observer.patch`
(`sha256 51504470cc178360d7bff509fa52ab6d009940ee74069d9f7558d2a6d49e166a`) and its design doc
`docs/fork/apple-screen-state-observer.md`, compared case by case with the brief. **The shipped
form at `2b23330d` could not be read** (see §6.3), so this is a review of the prepared patch, which
is what the brief names as the design under review.

### §7 screen-state observer file

| brief | prepared patch | verdict |
|---|---|---|
| `Library/Network/ScreenStateObserver.swift`, new file | same path, new file | match |
| listen to `com.apple.iokit.hid.displayStatus` and `com.apple.springboard.lockstate` | both registered with `notify_register_dispatch` | match |
| on notification: read state, forward to commandServer | `notify_get_state` then `recordScreenState`/`recordLockState` | match |
| `queue`, `displayToken`, `lockToken`, `commandServer` | `queue` + both tokens; `commandServer` is captured by the handlers rather than stored in a property | equivalent, no behavioural difference |
| `cancel()` cancels both tokens | `notify_cancel` on both | match |
| `#if os(iOS)` | on the file and on both call sites | match |
| iOS SDK support | `import notify` resolves from `iPhoneOS27.0.sdk/usr/include/notify.modulemap` (`OSX_AVAILABLE_STARTING(__MAC_10_6,__IPHONE_3_2)`), and the verbatim file type-checks for `arm64-apple-ios15.0` | **ARTIFACT** |

### §8 displayStatus semantics

| brief | prepared patch | verdict |
|---|---|---|
| `displayStatus == on → recordScreenState(true)` | `recordScreenState(state == 1)` | match |
| `displayStatus == off → recordScreenState(false)` | `recordScreenState(state == 1)` | match |
| no extra power policy copied into the observer | none present | match |
| **forbidden:** `display on → wakeNow()` unless the core has been re-checked and a design doc says so | `wakeNow()` appears nowhere in the file | match |

The patch deliberately differs from this repository's own `dev`-branch observer, which does call
`wakeNow()` on display-on. The brief's §8 forbids that call for exactly the reason the design doc
gives, so the divergence is *toward* the brief: on iOS a push notification lights the lock screen,
and releasing health checks, URLTests and provider refreshes for that is the wake storm.

Convention evidence for `state == 1` meaning "on": the `dev`-branch implementation of the same
repository, fetched and preserved by an earlier round
(`/tmp/apple-src/ss-macos.swift`, `sha256 5dfab55bb08845eddf1079d52d3223ed681487846ad5b6090880bd2892340b04`),
reads the same two names with the same `state == 1` test. That makes the mapping consistent with
the project's own shipped iOS-gated code; it is **DEVICE-ONLY** evidence for what iOS actually
posts.

### §9 lockstate semantics

| brief | prepared patch | verdict |
|---|---|---|
| `locked → recordLockState(true)` | `recordLockState(state == 1)` | match |
| `unlocked → recordLockState(false)` | `recordLockState(state == 1)` | match |
| `RecordLockState(false)` is the fact that releases the device pause | verified in the core: `command_server.go:387` → `box.go:1037` → `box_lifecycle.go:164` `lockState(false)` → `woke()` → `Resumed()` then `DeviceWake()` | **ARTIFACT** (core) + match |

Convention evidence is the same `dev`-branch file. The risk is stated rather than assumed away: if
iOS posted `1` for *unlocked* on some version, this mapping would call `DeviceWake()` on every lock
- a wake storm, not a missed optimisation, and the opposite failure from the one this work fixes.
Nothing on this host can settle it; it is the first item in the device runbook.

### §10 no state machine in Swift

The brief forbids `if displayOn && !locked { ... }` and forbids storing `wasSleeping`,
`alreadyWoke`, `deepIdle`, `currentGovernorState`. The patch publishes two independent facts and
stores nothing but the two registration tokens that §7's own skeleton declares. **Match.**

### §11 observer lifecycle

| brief | prepared patch | verdict |
|---|---|---|
| create after `commandServer.start()` and `startService()` succeed | in `startTunnel`, after `writeMessage("(packet-tunnel): Here I stand")` and after the `startService` success path, guarded by `if let commandServer` | PATCH-level match |
| `stopTunnel`: `cancel()` then `= nil`, before the service stop and the command-server close | `screenStateObserver?.cancel(); screenStateObserver = nil` at the head of the `#if os(iOS)` teardown block | PATCH-level match on the calls; the **relative order** against `stopService`/command-server close cannot be confirmed without the client revision |
| `reloadService()` must not create a second observer | lifecycle is bound to start/stopTunnel, the property is assigned rather than appended, and a restart cancels before installing | match by construction |
| no token or observer leak | `notify_cancel` on both tokens; the queue is released by the notify subsystem at cancel | PATCH-level |

### §12 initial state - **DIVERGENCE: not implemented**

The brief is explicit: "不要只等以后某个通知 … 推荐：register → read current display state → read current
lock state → publish initial facts", with the precondition "必须对 Core 的 dedup 语义先做测试".

The prepared patch registers and returns. Its only `notify_get_state` calls are inside the two
handlers, so **no fact is published until the next transition**, and the design doc does not
mention §12 at all.

Measured on this host (`scripts/ci/apple-abi-probe/notify-initial-state-probe.c`, compiled with
`clang -fblocks -o notifyprobe notify-initial-state-probe.c -framework CoreFoundation` and run as
`./notifyprobe <fresh|state|preexisting|system>`; Darwin notify, the same subsystem iOS uses):

```
[fresh]       registered a name nobody has posted; after 2 s:
              handler_fired_without_post=0
[preexisting] state set to 1 and posted BEFORE registration, setter kept alive:
              dispatch registration status=0 token=4; notify_get_state(dispatch token) status=0 reports 1
              notify_check on a fresh registration: status=0 changed=1
              after 3 s: handler_fired_from_preexisting_state=0
[state]       registration first, then set_state+post:
              state-handler fired with state=7
```

So registration does **not** deliver a state that already exists, while `notify_get_state` does have
it at registration time. The gap is real and it is not covered implicitly.

Consequence, with the core's actual semantics: a tunnel that starts while the device is already
locked and the display already off never enters the device pause until the next lock, unlock or
display transition. Speculative work - health checks, URLTests, provider refreshes - is then
permitted on a phone in a pocket for the whole of that period, which is the power regression the
device axis exists to prevent. It is **not** a wake storm and it does **not** manufacture a sleep
boundary; the direction of the error is "the device is assumed active".

The precondition the brief demands is satisfied, so this does not need core-side initial-state
handling:

```
$ go test -count=1 -tags "$TAGS" -v -run 'TestAFactWithoutASleepPublishesNothing|...' .
--- PASS: TestAFactWithoutASleepPublishesNothing (0.00s)      # a fact with no sleep publishes no boundary;
                                                              # an unlock lifts a pause that was never entered
--- PASS: TestTheDeviceAxisIsReleasedByAnUnlockAndNotByADisplayTurningOn (0.00s)
--- PASS: TestOneSleepProducesOneLevelTransitionHoweverManyFactsReportIt (0.00s)
--- PASS: TestASleepAndResumePairIsOneBoundaryAndTheLevelIsHeld (0.00s)
--- PASS: TestTheBridgeUsesThePolicyBandsAndNothingElse (0.00s)
```

Prepared fix: **`docs/fork/apple-screen-state-initial-facts.patch`**,
`sha256 95a221006c2816fc68818b5adc31973dc32dcec77bbe3d8d8f1b8a1e3d4131aa`.

It adds one `queue.async` block after the two registrations that reads `notify_get_state` for each
token and publishes the fact, guarding each publish on `NOTIFY_STATUS_OK` so a read that arrives
after `cancel()` (token `-1`) publishes nothing. The lock fact is published before the display
fact, which decides the one state where they disagree: a display that is off on a device that is
not locked (no passcode, or the passcode-grace window) ends up PAUSED, matching the design's own
residual rather than releasing speculation for a screen nobody is looking at. The read is
submitted to the observer's own serial queue so it cannot interleave with a handler, and it
re-reads the current state rather than the state at registration, so a transition that arrives
first is published first and this publish merely repeats it, which the governor coalesces.

Verification of the fix, on this host:

```
base file (as docs/fork/apple-screen-state-observer.patch writes it)
  sha256 33d388e9073ae1d92e4f86420a2918330d08c36741b7db0dcfc7f151e7f3ae0f
  (identical to the hash the design doc records for that file)

$ git apply --check -v docs/fork/apple-screen-state-initial-facts.patch
Checking patch Library/Network/ScreenStateObserver.swift...
APPLY-CHECK: OK

$ swiftc -typecheck -target arm64-apple-ios15.0 -sdk "$(xcrun --sdk iphoneos --show-sdk-path)" \
      -F Libbox.xcframework/ios-arm64 Library/Network/ScreenStateObserver.swift
POST_PATCH_TYPECHECK_EXIT=0
resulting file sha256 25cc61a4d9fe9d52ca2b305946955d525ba83047c5ac12186c9087e27351011c
```

Two honest limits. First, the apply-check is against the file the *prepared* observer patch
produces, because that is the only base obtainable here; if `2b23330d` carries a differently edited
`ScreenStateObserver.swift`, the patch must be re-based on it. Second, whether the initial publish
is *sufficient* on a real device - whether iOS posts the two names at all, and with what latency -
remains device-only, exactly as the design doc's own limitation 1 states.

### §13 the power governor

Not redone and not touched: no commit in this work modifies `common/power`, and the mapping in
`box_lifecycle.go` was read and exercised, not rewritten. The five lifecycle tests above are the
verification.

## 6. Product builds: status per platform, and the exact blocker

### 6.1 macOS app / DMG - **BLOCKED**

`BLOCKED: missing Apple client source tree (macOS branch) at the pinned revision.`

`scripts/ci/build-macos-dmg.sh <out>` is the entry point and it needs `APPLE_CLIENT_DIR` to
contain the macOS client checkout, including `sing-box.xcodeproj` and the `SFM.System` scheme. The
signing side is **not** the blocker: `scripts/ci/apple-signing-config.sh` defaults
`APPLE_SIGNING_MODE` to `unsigned`, and the script exists precisely to produce an unsigned arm64
DMG without `archive`/`exportArchive`, a Developer ID certificate, a provisioning profile or any
contact with App Store Connect.

What was produced instead, as far as this host allows, is §3.3: the shipped macOS slice links and
runs, and the boxed ABI round-trips at runtime.

### 6.2 iOS IPA - **BLOCKED**

`BLOCKED: missing Apple client source tree (iOS branch) at the pinned revision.`

`scripts/ci/build-ios-ipa.sh <out> [--app-name SFI]` needs `APPLE_CLIENT_DIR` with the iOS client
checkout and its `SFI` scheme; it builds `Release, iphoneos, arm64` directly and packages
`Payload/SFI.app/PlugIns/Extension.appex`, asserting the appex is present and of the right
architecture. It requires no certificate, no provisioning profile, no Team ID and no App Store
Connect. `$client/Libbox.xcframework` is already satisfied - the framework in §2 can be installed
into a client checkout as-is.

What was produced instead is §4: an unsigned `arm64` iPhoneOS binary linked against the shipped
iOS slice, plus the cronet defect that a real IPA build would meet.

### 6.3 Why the client source could not be obtained

Three independent routes are closed on this host, and each was tried:

1. **Clone the fork** - `https://github.com/Piggy-Cat-bit-shadow/sing-box-for-apple.git` is
   unreachable: `git ls-remote` times out after 75 s, `curl` to `raw.githubusercontent.com` after
   20 s, and the harness's own web fetch fails identically. No proxy is configured.
2. **Initialise the submodule in this worktree** - `clients/apple` is unpopulated (`git submodule
   status` shows `-2b23330d...`), and initialising it would fetch into the shared object store of
   the superproject this run is forbidden to write to.
3. **Read the shared object store read-only** - refused by this run's constraints, and the refusal
   was not worked around. This is the one route that would unblock §3's Swift half, §5's review of
   the *shipped* observer and both product builds.

Nothing in §3, §4, §5 or §6 is reported as a product result. `docs/fork/apple-screen-state-acceptance.md`
§7.1 already records the same limitation for the previous round; this run removes it for the Go
side, the framework, the header and the link, and leaves it in place for the client tree.

## 7. Core verification (ARTIFACT)

```
$ go build -tags "$TAGS" ./...                       TAGGED_EXIT=0
$ go build ./...                                     UNTAGGED_EXIT=0
$ gofmt -l $(git ls-files '*.go' | grep -v '^clients/')     (empty; 1971 tracked files)
$ go mod tidy -diff                                  TIDY_EXIT=0   (empty output)
$ go test -count=1 -tags "$TAGS" ./...               RUN2_EXIT=0   ok count: 76, FAIL: none
```

Two full-suite runs were needed and both are reported:

* **run 1**, concurrent with the 17-minute gomobile build at load average **99.31**:
  `FULL_TEST_EXIT=1`, **75 ok**, one failure -
  `TestReportedDelayIsNotTheSumOfBothRequests` (`common/urltest`): `"170" is not less than "160"`.
* **run 2**, alone: `RUN2_EXIT=0`, **76 ok**, no failure.

Classification of the one failure, with evidence rather than an assumption: the test measures the
wall-clock time of an HTTP response the test server delays by 100 ms and requires the reported
value to be under 160 ms; 170 ms is 70 % scheduling overhead on a host at load 99. Re-run in
isolation it passed **5/5** (`common/urltest`, `-run TestReportedDelay`), and it is untouched by
this work (no file it exercises is in the Apple change set). 12 external CPU hogs did not
reproduce it, which points at the suite's own package-level parallelism rather than external load.
It is reported as an environment-induced failure of a timing assertion, not as a regression, and
not as a pass.

### Cross-compiles

```
$ CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -tags "$TAGS" ./...
DARWIN_FULL_EXIT=0

$ CGO_ENABLED=1 GOOS=ios GOARCH=arm64 go build -tags "$TAGS" ./experimental/libbox/...
IOS_CGO_LIBBOX_EXIT=0

$ CGO_ENABLED=1 GOOS=ios GOARCH=arm64 go build -tags "$TAGS" ./...
IOS_FULL_EXIT=1   -> ld: framework 'UIKit' not found   (final link of main packages only)

$ GOOS=ios GOARCH=arm64 go build -tags "$TAGS" ./...            # Go's cross-compile default
IOS_CHANGED_EXIT=1 -> build constraints exclude all Go files in
                      cronet-go/lib/ios_arm64@v0.0.0-20260929202119-8c68ce89873c
```

The last two lines correct a claim in this repository's own documentation.
`docs/fork/apple-screen-state-acceptance.md` §7.6 records the iOS cross-compile as failing because
of the listed package, and §7.1 generalises it to "cross-compiling the whole tagged tree to iOS,
Linux and Windows fails on the baseline". It is not a missing iOS library: the prebuilt
`libcronet.a` for `ios_arm64` is present (46,280,672 bytes) and is the archive the successful
gomobile build uses. The excluded file is `libcronet_cgo.go`, whose constraint is
`ios && arm64 && !tvos && !iossimulator && !with_purego` - it is a **cgo** file, and `go build`
defaults to `CGO_ENABLED=0` when `GOOS` differs from the host, which is also why the
`GOOS=darwin` cross-compile on a darwin host always worked. With `CGO_ENABLED=1` the same package
compiles:

```
$ CGO_ENABLED=1 GOOS=ios GOARCH=arm64 go list -f 'CgoFiles={{.CgoFiles}}' github.com/sagernet/cronet-go/lib/ios_arm64
CgoFiles=[libcronet_cgo.go]
```

After that, `./...` for iOS fails only at the final link of `main` packages, on the iOS sysroot
that a bare `go build` does not pass to clang - a build-configuration matter, not a platform
limitation.

## 8. Two documentation defects found, and fixed in this branch

1. `scripts/ci/check-libbox-abi.sh` - the constant `VERIFIED_APPLE_SHA` was moved to
   `2b23330d489b9f6b45e98f903f458842e8961594` (it matches `git ls-tree HEAD clients/apple`), but
   the ten-line comment above it still said "THE APPLE VALUE BELOW IS STALE … 5911580a is the
   revision the superproject gitlink pins and it carries NONE of the migration", and still told the
   reader to move the value. A reader following the comment would have concluded that layer 4 fails
   on this pin, or re-pointed the constant back. The comment now states what the value is, and
   states plainly that naming a revision is not verifying it - layer 4 needs a client checkout,
   which this host did not have.
2. `docs/fork/libbox-abi-contract.tsv` - the header row named six columns while every data row and
   the format section above it have seven, with `check` in position 4. A reader following the
   header row would have mapped `kotlin-res` onto the `check` column. The name is added; the row is
   a `#` comment and the parser filters those (line 117), so nothing reads it.

## 9. What this run does not establish

1. **The Swift call sites in the gitlink revision.** They are verified as *shapes* against the real
   header (GREEN) and shown to be load-bearing (RED), and they are taken from the patches the
   revision is documented to carry. Whether `2b23330d` actually contains them is **not** verified
   here, and this is the exact question a previous round answered wrongly by sweeping source. The
   gate that would answer it - `scripts/ci/check-libbox-abi.sh` layer 4, or
   `scripts/ci/probe-accessors.py` against a client root - needs a client checkout.
2. **The shipped observer's text.** §5 reviews the prepared patch. If the fork head edited it while
   porting, §5 and the §12 patch both need to be re-based.
3. **The `BridgeServiceSession` implementer in the macOS/jailbreak layout at `2b23330d`.** The
   protocol requirement is proven from the generated header, and a correct witness is proven to
   type-check; the client's own file was not read.
4. **Any device behaviour.** The two notification names are not public API, and whether iOS posts
   them - and with what state convention - is device-only. The runbook is
   `docs/fork/apple-screen-state-acceptance.md` §6.
5. **The iPhone Hako custom UI and the macOS/iPad layouts as source layouts.** The two layouts are
   not merged or compared here, and nothing in this run touches them. What is checked is that the
   ABI the two layouts must compile against is one artifact with one header, that the observer is
   `#if os(iOS)` and compiles away on macOS, and that the migration shapes type-check for both
   targets. Which files each layout compiles is not checkable without the client tree.
