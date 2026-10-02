#!/usr/bin/env python3
"""Fails if a comment appears inside a backslash-continued argument list.

A '#' line following a line that ends in '\\' is part of the command, not a comment
to the shell: the continuation joins them, so the '#' begins a comment only after the
command has already been assembled - and every argument after it is dropped.

This is not hypothetical. build-ios-testflight.sh carried its distribution-signing
explanation inside the xcodebuild argument list, so CODE_SIGN_STYLE and
CODE_SIGN_IDENTITY never reached xcodebuild. The archive silently fell back to the
project's Apple Development identity and asked Apple for a device-scoped development
profile, which reads exactly like a device-registration problem. `sh -n` does not
catch it, and the echoed command line is the only place it shows up.
"""
import sys

SCRIPTS = [
    "scripts/ci/build-ios-testflight.sh",
    "scripts/ci/build-macos-testflight.sh",
    "scripts/ci/build-ios-ipa.sh",
    "scripts/ci/build-macos-dmg.sh",
    "scripts/release-apple.sh",
]


def main() -> int:
    bad = []
    for path in SCRIPTS:
        try:
            lines = open(path, encoding="utf-8").read().split("\n")
        except FileNotFoundError:
            continue
        for index, line in enumerate(lines):
            if line.rstrip().endswith("\\") and index + 1 < len(lines):
                nxt = lines[index + 1].strip()
                if nxt.startswith("#"):
                    bad.append(f"{path}:{index + 2}")
    if bad:
        print("comments inside an argument list (settings after them are dropped):", file=sys.stderr)
        for item in bad:
            print(f"  {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
