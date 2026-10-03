#!/usr/bin/env python3
"""Stop the Apple client from following the upstream update channel.

Usage: apply-apple-updater-overlay.py <client-dir>

# What the pinned client actually does

Settings > Update is not an informational panel. The chain is:

    MacApplication.initialize / runAutomaticUpdateCheck
      -> UpdateManager.refreshUpdateInfo
        -> GitHubUpdateChecker.checkAsync
          -> GET https://api.github.com/repos/SagerNet/sing-box/releases
      -> UpdateSheet presents the found version
        -> UpdateManager.downloadAndInstall
          -> PKGDownloader.download(updateInfo.downloadURL)
            -> PKGInstaller.install(pkgPath:)

So a fork build can, with no user action beyond the update prompt, download SagerNet's macOS
package and install it over itself. The installed app is no longer this fork.

# Why not just repoint the API at the fork

That trades a working channel for a broken one. This fork has no signed, notarised release
with a .pkg asset that the updater could consume - the Apple workflows produce unsigned
IPA/DMG artifacts. Pointing the checker at
api.github.com/repos/Piggy-Cat-bit-shadow/sing-box/releases would find either nothing or an
asset it cannot verify, so the failure mode becomes "update silently unavailable" while
still carrying the code path that installs a package.

The path is therefore disabled, and restored when the fork has a release channel worth
following.

# Why checkAsync, and not the URL

checkAsync is the single production entry point: UpdateManager calls it and nothing else
does. Returning nil there stops the check, and with no UpdateInfo there is no sheet, no
download and no install. Editing the URL would leave every one of those steps in place.

# Disabled rather than deleted

The surrounding code is upstream's and is repinned whenever the submodule moves. Replacing
the body wholesale would make every future repin conflict, and the deletion would be
invisible to a reader trying to understand why the feature is missing. Returning nil keeps
the shape intact and makes the reason readable at the call site.

# Fail-closed

The body being replaced is asserted to match the upstream text exactly. A repin that
restructures GitHubUpdateChecker makes this fail and ask for review rather than silently
leaving a build that installs packages from a different project.
"""

import sys

CHECKER_FILE = "Library/Update/GitHubUpdateChecker.swift"

UPSTREAM_URL = 'private static let releasesURL = "https://api.github.com/repos/SagerNet/sing-box/releases"'

# The exact upstream body of checkAsync. Matched literally so a repin is noticed.
UPSTREAM_CHECK_ASYNC = '''    public static func checkAsync(track: UpdateTrack, githubToken: String = "", force: Bool = false) async throws -> UpdateInfo? {
        try await BlockingIO.run {
            try check(track: track, githubToken: githubToken, force: force)
        }
    }'''

DISABLED_CHECK_ASYNC = '''    public static func checkAsync(track: UpdateTrack, githubToken: String = "", force: Bool = false) async throws -> UpdateInfo? {
        // Disabled for JiejieBox builds. See scripts/ci/apply-apple-updater-overlay.py.
        //
        // The upstream channel is SagerNet/sing-box. Following it would download that
        // project's macOS package and install it over this app, replacing the fork with a
        // different build - and this fork has no signed, notarised .pkg release of its own,
        // so repointing the URL would only produce a broken channel.
        //
        // Returning nil here stops the entire path: no version is reported, so
        // UpdateManager has no UpdateInfo, the sheet is not presented, and
        // downloadAndInstall is never reached.
        _ = track
        _ = githubToken
        _ = force
        return nil
    }'''


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"apply-apple-updater-overlay: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: apply-apple-updater-overlay.py <client-dir>")

    path = f"{sys.argv[1]}/{CHECKER_FILE}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    if DISABLED_CHECK_ASYNC in src:
        print("apply-apple-updater-overlay: already applied")
        return 0

    if UPSTREAM_CHECK_ASYNC not in src:
        fail(
            "GitHubUpdateChecker.checkAsync does not match the expected upstream text",
            [
                "refusing to guess at how the update path is shaped now",
                "if the client was repinned, review whether the upstream update channel is still "
                "followed and update this overlay deliberately",
            ],
        )

    # The upstream URL is asserted to still be present, so that removing it later is a decision
    # rather than a silent drift.
    if UPSTREAM_URL not in src:
        fail(
            "the upstream releases URL this overlay documents is no longer present",
            [f"looked for {UPSTREAM_URL!r}"],
        )

    src = src.replace(UPSTREAM_CHECK_ASYNC, DISABLED_CHECK_ASYNC, 1)
    open(path, "w", encoding="utf-8").write(src)

    # Re-read and assert, rather than trusting the in-memory string.
    verified = open(path, encoding="utf-8").read()
    if DISABLED_CHECK_ASYNC not in verified:
        fail("the edit did not produce the disabled checkAsync")
    if UPSTREAM_CHECK_ASYNC in verified:
        fail("the upstream checkAsync body survived the edit")

    print("apply-apple-updater-overlay: upstream update channel disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
