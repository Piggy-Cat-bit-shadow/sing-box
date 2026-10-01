#!/usr/bin/env python3
"""Removes the SwiftLint build-tool plug-in from a resolved package manifest.

Invoked by scripts/ci/build-macos-dmg.sh on the SwiftPM checkouts under
DerivedData, NOT on the pinned Apple client submodule. See that script for why:
the plug-in aborts the macOS build inside Xcode's plug-in sandbox because it
cannot load sourcekitdInProc, Xcode has no flag to skip executing a dependency's
build-tool plug-in, and the failure reproduces with a pristine Apple client.

The plug-in only lints; dropping it changes no build product. It is re-added
automatically whenever SwiftPM re-resolves the package.
"""
import os
import re
import stat
import sys


def main() -> int:
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()

    if "SwiftLintPlugin" not in src:
        return 0

    # The plug-in package's OWN manifest declares it; that is not an attachment and
    # must be left alone, or SwiftPM loses the package it is resolving.
    if os.path.basename(os.path.dirname(path)) == "SwiftLintPlugin":
        return 0

    # Drop every `plugins: [ ... ]` block that attaches it. The non-greedy match is
    # safe because SwiftPM manifests do not nest array literals inside `plugins:`.
    out = re.sub(r",\s*plugins:\s*\[[^\]]*?\]", "", src, flags=re.S)

    # Then the package dependency itself, if nothing references it any more.
    if "SwiftLintPlugin" in out:
        out = re.sub(
            r'\s*\.package\(\s*url:\s*"https://github\.com/lukepistrol/SwiftLintPlugin"[^)]*\),?',
            "",
            out,
            flags=re.S,
        )

    if "SwiftLintPlugin" in out:
        print(f"strip-swiftlint-plugin: could not fully remove it from {path}", file=sys.stderr)
        return 1

    # SwiftPM checks out packages read-only.
    os.chmod(path, os.stat(path).st_mode | stat.S_IWUSR)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
