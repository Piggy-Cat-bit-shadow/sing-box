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

## The Libbox Swift API skew, and how it was resolved

The Apple gitlink originally pinned `2b1763a` (2026-09-14) did not compile
against a Libbox generated from this core. Two errors, both in the same
direction:

| Error | Direction | Detail |
| --- | --- | --- |
| `cannot find 'LibboxPromotePowerReportDraft' in scope` | Swift expects · core lacks | Called from `Library/Network/ExtensionProvider.swift:182`. The core **renamed** this export: commit `3aff5d0f1` (2026-09-23) changed `PromotePowerReportDraft()` into `DiscardPowerReportDraft()`. |
| `type 'ExtensionPlatformInterface' does not conform to protocol 'LibboxPlatformInterfaceProtocol'` | Core expects · Swift lacks | Core commit `061889303` (2026-09-23) added `UsePlatformAutoRedirect()` and `createAutoRedirect(_:handler:)` to `experimental/libbox/platform.go`. The pinned Apple client implements neither. |

### The pin is one Apple release behind the core

Both core changes landed on **2026-09-23**. The Apple gitlink pins **2026-09-14**
(`2b1763a`, "Update App Store marketing versions", Apple 1.14.1). The pinned
client predates the core's Libbox interface change by nine days, so it calls an
export that no longer exists and lacks the two methods that now exist.

Neither change is Jiejie's:

```sh
git log --format='%h %ci %s' -1 3aff5d0f1
# 3aff5d0f1 2026-09-23 Close idle connections of unreferenced outbounds and DNS servers
git log --format='%h %ci %s' -1 061889303
# 061889303 2026-09-23 Implement fully functional auto redirect for Android

# Both are in upstream as well, so upstream's own pin has the same skew.
git merge-base --is-ancestor 3aff5d0f1 upstream/testing   # -> yes
```

### This is not a Jiejie regression

The evidence is direct rather than inferred:

```sh
# Jiejie commits that touched the Libbox package: none.
git log --oneline origin/testing --not upstream/testing -- experimental/libbox/
# -> (empty)

# The Libbox package is identical to upstream.
git diff --stat upstream/testing origin/testing -- experimental/libbox/
# -> (empty)
```

So a pristine upstream core at this commit is mismatched with the pinned Apple
commit in exactly the same way. The skew is between two upstream repositories
pinned at two different dates, not between Jiejie and upstream.

This is inherent to how the two repositories are kept in step: the core pins the
Apple client by gitlink, and upstream builds `Libbox.xcframework` as a
standalone artifact while the Apple app is built in its own repository. A pin
that has drifted behind a Libbox interface change surfaces exactly like this.

### Why the submodule was not upgraded

Updating `clients/apple` to Apple `dev`/`main` would make the Swift compile, but
it would also mean this stage silently changes the client application, which is
precisely what the stage is specified not to do. A working SFI build produced
from a different, newer UI would not demonstrate "official SFI + Jiejie Libbox".

The pin was therefore left untouched and the failure recorded instead.

### Resolution: the Apple pin was moved to the earliest compatible commit

The pin was updated from `2b1763a` (2026-09-14) to
`65fae11640bf67c0966aae8e12ece6596d2a3469` (2026-09-24), which is the **earliest
commit across all official Apple refs** that satisfies every condition:

| Condition | Verified |
| --- | --- |
| no longer calls `LibboxPromotePowerReportDraft` | yes — calls `LibboxDiscardPowerReportDraft` |
| implements `usePlatformAutoRedirect` | yes |
| implements `createAutoRedirect` | yes |

`65fae11` is the earliest: its parent `4731a25` adds the auto-redirect stub but
still calls `PromotePowerReportDraft`, so it does not compile. Neither `stable`
nor `main` ever implements `usePlatformAutoRedirect`, so `dev` is the only ref
that can pair with this core.

The pin moved 14 commits. Only two are interface fixes:

```
4731a25 Add stub for platform auto redirect
65fae11 Discard unfinished power report draft instead of promoting it
```

The other twelve are ordinary client fixes that came along because the two
interface fixes sit on top of them (iOS/macOS UI, terminal, font and
taildrop work). Only the submodule gitlink changed; no Swift, `.pbxproj`,
`.entitlements` or `Package.resolved` was hand-edited, and CI fails if the
checked-out client is not exactly the pinned commit.

No deprecated Libbox API was re-added to the core to accommodate the old pin.

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
