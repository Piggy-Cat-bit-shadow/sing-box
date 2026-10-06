# Apple beta release

How to publish a TestFlight build for iOS and macOS.

## Daily flow

```bash
git push
# wait for the Apple client workflow to go green
./scripts/publish-apple-beta.sh
```

That is the whole procedure. The script finds the CI run for the commit you have checked out,
downloads the Libbox it built, proves the artifact belongs to that commit, and hands off to the
existing signing and upload pipeline.

## Two Apple UI sources, one core

The iOS and macOS clients do **not** share an Apple UI source. They are built from two branches of
the same Apple client repository, and the two branches are never merged:

| Product | Target | Apple source | UI |
| --- | --- | --- | --- |
| iOS | `SFI` | `clients/apple` gitlink (`hako-ui`) | custom Hako |
| macOS | `SFM` / `SFM.System` | `MACOS_APPLE_SHA` (`dev`) | original sing-box |

The iOS revision is the parent repository's `clients/apple` gitlink, which stays the single
authority for it. The macOS revision is an exact commit pinned in
`release/apple-client-refs.env` together with the branch it must be an ancestor of — a release
never follows the `dev` branch tip, because that would not be reproducible.

Only one Apple gitlink exists in this repository, and it is the iOS one. The macOS source is
materialised at build time into `build/apple-client-macos/` by
`scripts/ci/apple-client-source.sh`, which is not a submodule and is not tracked.

`Libbox.xcframework` comes from this repository at the release commit, is built **once**, and the
identical framework is installed into both checkouts. The core never depends on which UI branch
links it.

## What runs where

The split follows the line of what needs Apple secrets.

**GitHub** — no secrets, and the expensive work:

- compiles `Libbox.xcframework` **once** per commit and publishes it as an artifact
- builds the iOS client from the `hako-ui` source and the macOS client from the pinned `dev`
  commit, both against that same artifact
- runs the signing, publish and source-selection regression suites

**This Mac** — everything that needs the certificate, the profile and an Apple ID session:

- archives, signs, exports and uploads
- unpacks the verified CI artifact into both Apple checkouts instead of compiling Libbox

Apple private keys, certificates, provisioning profiles and App Store Connect credentials never
leave this machine. There is nothing to configure in the repository for them.

## Why it refuses to run

The script fails rather than publishing something unattributable:

| Condition | Why it stops |
| --- | --- |
| Uncommitted changes | A published build must correspond to a commit that exists. There is no `--allow-dirty`. |
| No successful CI for this exact SHA | Publishing the previous commit's framework is the failure this check exists to prevent. |
| CI did not build all three jobs | A run-level success hides a skipped `ios` or `macos` job, which would upload a client whose framework was verified for one platform only. |
| Artifact parent SHA mismatch | The framework was built from a different commit than the one being released. |
| iOS source ≠ the parent gitlink | The iOS build must come from the revision the release commit records. |
| macOS source ≠ `MACOS_APPLE_SHA` | The macOS pin is the only authority for the original-UI source; a branch tip is not accepted. |
| macOS pin unreachable or off-branch | A pin that names a commit the declared branch never contained is refused. |
| The two sources are identical | One SHA cannot be both the custom iOS UI and the original macOS UI. |
| The two checkouts do not link the same Libbox | One release must ship one core. |
| Checksum mismatch | The artifact was altered in transit or storage. |
| No Libbox installed in prebuilt mode | Falling back to a local compile would publish a binary that does not match the verified artifact. |

The artifact itself binds only the parent commit. It deliberately records no Apple client
revision: the two platforms use different ones, and an artifact tied to either could not be valid
for both. Each platform's Apple revision is recorded in that platform's `BUILD-INFO`.

## Manual steps this does not replace

Two things are configured once in the App Store Connect website and are not scripted:

- the **Internal Testing** group
- **Automatic Distribution** to that group

Those are account-level settings, not build settings. The script uploads; App Store Connect then
processes the build on Apple's side, and "uploaded" is not the same as "available for testing".
Check TestFlight for processing status.

## Related

- `scripts/publish-apple-beta.sh` — the entry point described above
- `scripts/release-apple.sh` — archiving, signing and uploading; also supports
  `development`, `development-ios`, `development-macos` and `unsigned`
- `scripts/ci/apple-libbox-artifact.sh` — packs and validates the shared Libbox artifact
- `docs/APPLE-DEVELOPMENT-SIGNING.md` — local development signing for running the client directly
