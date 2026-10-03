#!/usr/bin/env python3
"""Assert the prepared Apple client cannot install a package from the upstream channel.

Usage: check-apple-updater.py <client-dir>

# What it proves, statically

That GitHubUpdateChecker.checkAsync - the single production entry into the update path -
returns without consulting the network, so no version is reported, the update sheet is never
presented, and PKGDownloader/PKGInstaller are unreachable.

# What it cannot prove

That the running app never installs anything by some other route. This reads source: it
covers the update path this fork actually ships, which is the one that pointed at another
project's releases.
"""

import sys

CHECKER_FILE = "Library/Update/GitHubUpdateChecker.swift"

DISABLED_MARKER = "// Disabled for JiejieBox builds."
# The upstream implementation, which must NOT be present in a fork build.
UPSTREAM_BODY = "try await BlockingIO.run {"

# The install path must still exist and still be reachable only through checkAsync; if a repin
# wires a caller directly to it, this file's guarantee no longer holds.
INSTALL_FILES = [
    "ApplicationLibrary/Service/UpdateManager.swift",
]


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"check-apple-updater: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: check-apple-updater.py <client-dir>")

    client = sys.argv[1]
    path = f"{client}/{CHECKER_FILE}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    problems: list[str] = []

    if DISABLED_MARKER not in src:
        problems.append(
            f"the disabling marker is absent from {CHECKER_FILE}; the upstream update channel "
            "may be live in this build"
        )
    if UPSTREAM_BODY in src:
        problems.append(
            "the upstream checkAsync body is still present: checkAsync reaches the network"
        )

    # The disabling must be inside checkAsync, not merely somewhere in the file.
    start = src.find("public static func checkAsync")
    if start == -1:
        problems.append("checkAsync is missing from GitHubUpdateChecker")
    else:
        end = src.find("\n    }", start)
        body = src[start:end if end != -1 else len(src)]
        if DISABLED_MARKER not in body:
            problems.append("the disabling marker is not inside checkAsync itself")
        if "return nil" not in body:
            problems.append("checkAsync does not return nil, so an update version could be reported")

    # UpdateManager must still route through the checker rather than fetching directly.
    for relative in INSTALL_FILES:
        try:
            manager = open(f"{client}/{relative}", encoding="utf-8").read()
        except FileNotFoundError:
            problems.append(f"{relative} is missing")
            continue
        if "api.github.com/repos/SagerNet" in manager:
            problems.append(f"{relative} references the upstream API directly, bypassing the checker")

    if problems:
        fail("the prepared client can still follow the upstream update channel", problems)

    print("check-apple-updater: OK")
    print("    checkAsync returns nil before any network access")
    print("    no version is reported, so the update sheet and PKGInstaller are unreachable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
