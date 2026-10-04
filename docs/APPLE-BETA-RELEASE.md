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

## What runs where

The split follows the line of what needs Apple secrets.

**GitHub** — no secrets, and the expensive work:

- compiles `Libbox.xcframework` **once** per commit and publishes it as an artifact
- builds the iOS and macOS clients against that same artifact
- runs the signing and publish regression suites

**This Mac** — everything that needs the certificate, the profile and an Apple ID session:

- archives, signs, exports and uploads
- reads `clients/apple/Libbox.xcframework` from the verified CI artifact instead of compiling it

Apple private keys, certificates, provisioning profiles and App Store Connect credentials never
leave this machine. There is nothing to configure in the repository for them.

## Why it refuses to run

The script fails rather than publishing something unattributable:

| Condition | Why it stops |
| --- | --- |
| Uncommitted changes | A published build must correspond to a commit that exists. There is no `--allow-dirty`. |
| No successful CI for this exact SHA | Publishing the previous commit's framework is the failure this check exists to prevent. |
| Artifact parent SHA mismatch | The framework was built from a different commit than the one being released. |
| Artifact submodule SHA mismatch | The Xcode project and the framework would disagree about the Apple client revision. |
| Checksum mismatch | The artifact was altered in transit or storage. |
| No Libbox installed in prebuilt mode | Falling back to a local compile would publish a binary that does not match the verified artifact. |

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
