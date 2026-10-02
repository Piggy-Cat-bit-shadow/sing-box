#!/usr/bin/env python3
"""Fails if an Apple build script actively sets a specific signing identity.

Usage: test-no-active-identity.py <script>

The TestFlight archives must not pin CODE_SIGN_IDENTITY. With Automatic style Xcode
derives the provisioning profile TYPE from that setting, so pinning "Apple
Development" makes it ask for a device-scoped development profile, and pinning
"Apple Distribution" contradicts Automatic on every target. The archives therefore
package unsigned and let -exportArchive, which knows the App Store destination, do
the distribution signing.

Comment lines are ignored on purpose: these scripts document the approaches that
were tried and rejected, so the strings being ruled out appear in their
explanations. Only executable lines matter.
"""
import re
import sys

# Any assignment of a concrete identity, e.g. CODE_SIGN_IDENTITY="Apple Distribution"
# or CODE_SIGN_IDENTITY=Apple\ Development. An EMPTY assignment is allowed: the
# archives use CODE_SIGN_IDENTITY="" alongside CODE_SIGNING_ALLOWED=NO.
ACTIVE_IDENTITY = re.compile(r'CODE_SIGN_IDENTITY(\[[^\]]*\])?=\s*"?[A-Za-z]')


def main() -> int:
    path = sys.argv[1]
    offenders = []
    for number, line in enumerate(open(path, encoding="utf-8").read().split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if ACTIVE_IDENTITY.search(line):
            offenders.append(f"{path}:{number}: {stripped}")
    if offenders:
        print("these lines pin a signing identity:", file=sys.stderr)
        for item in offenders:
            print(f"  {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
