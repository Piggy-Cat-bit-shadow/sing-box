# Apple development signing

How to build and run this fork's Apple clients with your own Apple Developer
Program account, for personal testing on your own Mac and iPhone.

This is not an App Store or TestFlight guide. There is no notarization, no
Developer ID and no distribution here; the goal is a client you can install and run
yourself so the tunnel actually starts.

Everything below assumes the signing infrastructure in `scripts/ci/`. Nothing in
this repository contains a team ID, certificate, profile or password — those are
supplied by you at build time.

## What the two signing modes mean

| | `unsigned` (default) | `development` |
|---|---|---|
| Apple account needed | no | yes |
| Entitlements applied | no | yes |
| App Group works | **no** | yes |
| Network Extension works | **no** | yes |
| Purpose | CI, packaging checks | actually running the client |

An unsigned artifact is a compile and packaging check. It builds and mounts, and
its App Group and Network Extension do **not** function at runtime. The CI summary
says this explicitly rather than implying the client is usable.

Select the mode with `APPLE_SIGNING_MODE`:

```sh
APPLE_SIGNING_MODE=development ./scripts/ci/build-ios-ipa.sh dist/SFI.ipa
```

## Step 1 — the Apple Developer Program account

Enrol, then in [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources):

1. Note your **Team ID** (10 characters, e.g. `ABCDE12345`). It appears at the top
   right of the account page.
2. Create a **development certificate** (Apple Development) if you do not have one,
   and install it in your login keychain. Downloading the WWDR intermediate is also
   required — see the note below.

If Xcode is signed in under **Settings → Accounts**, Xcode can create the
certificate and the profiles for you, which is why `automatic` is the default
signing style.

> A development certificate alone is not enough. It is issued by an intermediate
> (currently `AppleWWDRCAG3`), and without that intermediate installed,
> `security find-identity -v -p codesigning` reports **0 valid identities** even
> though the import succeeded. Download it from
> [Apple's certificate authority page](https://www.apple.com/certificateauthority/)
> if Xcode has not already installed it.

## Step 2 — identifiers

Every bundle identifier is derived from **one** base value,
`APPLE_BASE_BUNDLE_ID`. You register the derived identifiers; you do not register
the base by itself.

With `APPLE_BASE_BUNDLE_ID=com.example.jiejiebox` you need these App IDs:

| Purpose | Identifier | Notes |
|---|---|---|
| iOS app | `com.example.jiejiebox` | |
| iOS Packet Tunnel extension | `com.example.jiejiebox.extension` | needs **Network Extensions** |
| macOS app | `com.example.jiejiebox.standalone` | needs **System Extension** (for its own extension) and **Network Extensions** |
| macOS System Extension | `com.example.jiejiebox.system` | needs **Network Extensions** |
| macOS share extension | `com.example.jiejiebox.share` | only App Groups |
| macOS root helper | `com.example.jiejiebox.helper` | only App Groups |

Do **not** create identifiers for the tvOS targets, the UI-test bundles or the
FileProvider/Intents/Widget extensions unless you actually intend to run those.
`scripts/ci/prepare-apple-client.sh` checks only the six targets the two shipped
products embed, which is what the list above covers.

### Capabilities

Enable these on the App IDs that need them:

| Capability | Where |
|---|---|
| **Network Extensions** | iOS app, iOS extension, macOS app, macOS System Extension |
| **App Groups** | all six |
| **System Extension** | macOS app (it installs the System Extension) |
| iCloud / Ubiquity | iOS app and macOS app, if you want profile sync |

The exact set is not guesswork: read it from the entitlements the project actually
declares.

```sh
for f in clients/apple/SFI/SFI.entitlements \
         clients/apple/Extension/Extension.entitlements \
         clients/apple/SFM.System/SFM.entitlements \
         clients/apple/SystemExtension/SystemExtension.entitlements; do
  echo "== $f"; grep -oE '<key>[a-zA-Z0-9.-]+</key>' "$f" | sed 's/<[^>]*>//g'
done
```

### App Group

Create **one** App Group, for example `group.com.example.jiejiebox`. All six App
IDs above must be assigned to it.

The host app and every extension must resolve to the same group or the client
cannot open its database — this was the first fatal runtime error observed while
debugging this client. The build now enforces it in two places:

- `prepare-apple-client.sh` asserts every participating target resolves to one
  group and fails if they disagree;
- `verify-apple-signed-artifact.sh` reads the group back out of the *signed*
  entitlements and compares the app against each of its extensions.

> Historical note, in case you see it elsewhere: the upstream project defines
> `APP_GROUP_IDENTIFIER` inconsistently, and ten of its macOS configuration blocks
> use `$(TeamIdentifierPrefix)$(BASE_PACKAGE_IDENTIFIER)`. `TeamIdentifierPrefix`
> is empty outside a signed build, which collapses the value to a bare bundle
> identifier — not a valid App Group at all. The build scripts now pass
> `APP_GROUP_IDENTIFIER` explicitly so the project's own blocks cannot produce that
> value.

### Multicast is off by default

`Multicast Networking` (`com.apple.developer.networking.multicast`) must be
requested from Apple and approved separately. Until then it stays removed from the
iOS extension and the macOS System Extension so they can be signed at all.

If you have been granted it:

```sh
APPLE_ENABLE_MULTICAST=true APPLE_SIGNING_MODE=development \
  ./scripts/ci/build-ios-ipa.sh dist/SFI.ipa
```

No patch edit is needed; the switch adds it back.

## Step 3 — configure and verify

Export the values (or source a local, git-ignored file):

```sh
export APPLE_SIGNING_MODE=development
export APPLE_TEAM_ID=ABCDE12345
export APPLE_BASE_BUNDLE_ID=com.example.jiejiebox
export APPLE_APP_GROUP_ID=group.com.example.jiejiebox
```

Then check everything that can be checked before Xcode runs:

```sh
./scripts/ci/check-apple-signing-environment.sh
```

It verifies that a signing identity for your team exists, that the App Group is
well formed, that the bundle/group namespaces differ, and it reports what
multicast is set to. In `unsigned` mode it prints SKIP and does nothing.

To see the fully resolved configuration without building:

```sh
./scripts/ci/apple-signing-config.sh --print
```

## Step 4 — build

```sh
# iOS
./scripts/ci/build-apple-libbox.sh both
./scripts/ci/prepare-apple-client.sh
./scripts/ci/build-ios-ipa.sh dist/SFI.ipa
./scripts/ci/verify-apple-signed-artifact.sh ios-ipa dist/SFI.ipa

# macOS
./scripts/ci/build-macos-dmg.sh dist/SFM.dmg
./scripts/ci/verify-apple-signed-artifact.sh macos-dmg dist/SFM.dmg
```

`build-apple-libbox.sh` compiles Libbox from this repository's own
`experimental/libbox`, so the app links this fork rather than an upstream build.

### Manual signing

Automatic signing is the default because it is what a single developer on their
own machine wants: Xcode creates and renews the profiles. For CI, or if you prefer
explicit control, use manual signing and name the profiles:

```sh
export APPLE_SIGNING_STYLE=manual
export IOS_APP_PROFILE="My iOS App Profile"
export IOS_EXTENSION_PROFILE="My iOS Tunnel Profile"
export IOS_UI_EXTENSION_PROFILE="My iOS UI Extensions Profile"
export MACOS_APP_PROFILE="My macOS App Profile"
export MACOS_SYSTEM_EXTENSION_PROFILE="My macOS System Extension Profile"
export MACOS_HELPER_PROFILE="My macOS Helper Profile"
```

The preflight requires all six, so a missing one fails before the build rather
than partway through it.

## Step 5 — install and run

### iPhone

The IPA is unsigned-with-respect-to-distribution but signed for development, so it
installs onto a registered device:

```sh
xcrun devicectl device install app --device <udid> dist/SFI.ipa
# or: ios-deploy --bundle dist/SFI.ipa
# or: Apple Configurator, or Xcode's Devices window
```

Your device must be registered. With automatic signing Xcode does this when you run
the scheme from Xcode once; otherwise add the device UDID in the developer portal.
The profile also has to list the device for an Ad Hoc profile.

### Mac

Open the DMG and drag `SFM.app` to Applications, then launch it. Gatekeeper will
warn because the app is not notarized — right-click → Open, or allow it in
**System Settings → Privacy & Security**. That warning is expected for a
development-signed build.

## Step 6 — verify the App Group actually works

This is the check that matters, because the failure it catches is invisible at
build time.

```sh
# The signed entitlements of the app and its system extension must name the same group.
codesign -d --entitlements :- /Applications/SFM.app 2>&1 | grep -A2 application-groups
codesign -d --entitlements :- \
  /Applications/SFM.app/Contents/Library/SystemExtensions/*.systemextension 2>&1 \
  | grep -A2 application-groups
```

Both must print your group. Then, from the app, confirm the container is readable
and writable:

```sh
# The group container is created on first use; if the entitlement is wrong this
# path does not exist and the app logs a permission error instead.
ls -la ~/Library/Group\ Containers/group.com.example.jiejiebox/
```

If the client logs a permission error opening its database, the group in the
signed entitlements does not match the one assigned to the App IDs — re-check
Step 2 rather than the build.

## Step 7 — the System Extension

The macOS client uses a System Extension, which the system must approve:

1. Launch the app; it requests installation.
2. Approve it in **System Settings → General → Login Items & Extensions → System
   Extensions** (older macOS: **Privacy & Security**).
3. Confirm it is active:

```sh
systemextensionsctl list
```

You should see `<your base>.system` listed and enabled. Enabling developer mode may be required for a
development-signed System Extension:

```sh
systemextensionsctl developer on
```

A GitHub-hosted runner cannot meaningfully test this: activating a System
Extension requires an interactive approval that CI has no way to give. The scripts
therefore report System Extension activation as NOT TESTED in CI rather than
asserting success.

## Troubleshooting

**`0 valid identities found`** — the certificate's intermediate is missing. See
Step 1. A successful `security import` does not imply a usable identity.

**`No signing certificate "iOS Development" found`** — no identity for
`APPLE_TEAM_ID`. Run `security find-identity -v -p codesigning` and compare the
team in parentheses.

**`Provisioning profile ... doesn't match`** — the profile's App ID or team does
not match the bundle identifier being signed. With automatic signing, delete the
derived data and let Xcode recreate the profile; with manual signing, regenerate
the profile in the portal.

**The app installs but the tunnel will not start** — almost always the App Group.
Run the Step 6 checks.

**`APPLE_SIGNING_MODE=development` fails immediately** — intentional. The
configuration layer refuses to continue rather than silently producing an unsigned
artifact; the message names the missing values.

## What is deliberately not supported yet

- notarization and Developer ID distribution;
- App Store / TestFlight submission;
- App Group values, team IDs or profiles committed to the repository.

When you want to distribute a DMG to other Macs, that is a separate change: a
`developer-id` signing mode plus notarization and stapling.
