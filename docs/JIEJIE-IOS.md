# Jiejie iOS: Libbox pipeline and the pinned-Apple blocker

## What this stage does

`Jiejie iOS` (`.github/workflows/jiejie-ios.yml`) builds the Jiejie Go core into
`Libbox.xcframework`, installs it into the Apple client commit this repository
pins, and builds SFI against it without signing.

The stage exists to prove four things and nothing more:

1. the Jiejie core produces an iOS + iOS-Simulator `Libbox.xcframework`;
2. the Libbox config path accepts `http3_connection_pool` and `http3_fallback`;
3. SFI links that framework and builds;
4. no Swift source, no Apple submodule update and no TrustTunnel is involved.

It deliberately does **not** sign, notarize, export an installable IPA, or
change any Swift code.

## The two Apple sources involved

| Piece | Source | Pin |
| --- | --- | --- |
| Go core | this repository | `testing` |
| Apple client | `SagerNet/sing-box-for-apple` | gitlink `clients/apple` |

The Apple client is consumed as the submodule gitlink, never as a moving branch.
The workflow checks out with `submodules: recursive` and fails if the submodule
ends up with any tracked modification.

## Blocker: pinned Apple commit and this core disagree on the Libbox Swift API

The SFI application build does not compile against a Libbox generated from this
core. Two errors, both in the same direction:

| Error | Direction | Detail |
| --- | --- | --- |
| `cannot find 'LibboxPromotePowerReportDraft' in scope` | Swift expects · core lacks | Called from `Library/Network/ExtensionProvider.swift:182`. Introduced by Apple commit `88fbbc0 "Add power report"`. **No core ref exports it**, including `upstream/testing`. The core's own `experimental/libbox/power_report.go` exports `DiscardPowerReportDraft`, not a `Promote…` counterpart. |
| `type 'ExtensionPlatformInterface' does not conform to protocol 'LibboxPlatformInterfaceProtocol'` | Core expects · Swift lacks | Core `experimental/libbox/platform.go` requires `UsePlatformAutoRedirect() bool` and `createAutoRedirect(_:handler:)`. The pinned Apple client implements neither. |

### This is not a Jiejie regression

The evidence is direct rather than inferred:

```sh
# Jiejie commits that touched the Libbox package: none.
git log --oneline origin/testing --not upstream/testing -- experimental/libbox/
# -> (empty)

# The Libbox package is identical to upstream.
git diff --stat upstream/testing origin/testing -- experimental/libbox/
# -> (empty)

# The missing export is missing upstream too.
git grep 'PromotePowerReportDraft' upstream/testing -- 'experimental/libbox/*.go'
# -> (empty)
```

So a pristine upstream core at this commit is mismatched with the pinned Apple
commit in exactly the same way. The skew is between two upstream repositories,
at two different points in time, not between Jiejie and upstream.

The two mechanisms that keep a core and an Apple client in step are the
submodule pin and Apple's own release CI; upstream builds `Libbox.xcframework`
as a standalone artifact and the Apple app is built in its own repository, so a
pin that has drifted shows up exactly like this.

### Why the submodule was not upgraded

Updating `clients/apple` to Apple `dev`/`main` would make the Swift compile, but
it would also mean this stage silently changes the client application, which is
precisely what the stage is specified not to do. A working SFI build produced
from a different, newer UI would not demonstrate "official SFI + Jiejie Libbox".

The pin was therefore left untouched and the failure recorded instead.

## Resolution options (not applied here)

Pick one deliberately; each changes what the stage is proving.

1. **Move the pin to the Apple commit that matches this core.** Smallest change
   to the Apple side, but it is an Apple-client update and must be an explicit,
   reviewed decision, not a side effect of an iOS build job.
2. **Add the missing Libbox exports in the core.** A `PromotePowerReportDraft`
   counterpart and the auto-redirect platform hooks would have to be
   implemented in `experimental/libbox`, which is upstream-owned code and
   beyond a build-pipeline stage.
3. **Build SFI for the simulator only, without the power-report path.** Not
   available: the call site is unconditional in `ExtensionProvider.swift`.

Option 1 is the likely path, as a dedicated change whose diff is visibly about
the Apple client.

## What the workflow still produces

Because the Libbox artifact is the Jiejie deliverable, it is collected and
uploaded as soon as the framework is built, before the SFI application build
runs. A failing SFI build therefore does not cost the `Libbox.xcframework`
artifact.

The SFI build step is **not** wrapped in `continue-on-error` and does not skip
its assertions: it runs for real and fails red when it cannot compile. A
separate classification step then states the cause from the build log and prints
the Libbox/Jiejie evidence, so the failure reads as a diagnosis rather than an
unexplained red job.

## Signing

Artifacts are named `UNSIGNED` and their `BUILD-INFO.txt` records
`signed: false` and `installable_on_stock_ios: false`. No IPA is fabricated from
an unsigned `.app`, and no signing identity, certificate or provisioning profile
is requested anywhere in this stage.
