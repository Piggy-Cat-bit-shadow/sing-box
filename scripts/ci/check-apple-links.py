#!/usr/bin/env python3
"""Assert the Apple client's external links are the ones this fork intends to ship.

Usage: check-apple-links.py <client-dir>

Run after apply-apple-link-overlay.py, and separately by any build that wants to verify
the prepared source without applying anything.

# What it checks, and why the documentation links are checked too

It is not enough to confirm the fork links are present. A build that had silently lost
the documentation links - or had them rewritten to something else - would still pass a
check that only looked for the fork URLs. Every assertion below is therefore two-sided:
the fork links must be present exactly once, and the upstream documentation links must
still be present exactly once.

# What it cannot check

This reads source. It cannot prove that tapping a row opens Safari on a device. That
distinction is stated rather than blurred: a static check passes for a build whose links
are correct in source, which is the strongest claim this file can make.
"""

import sys

SOURCE_FILE = "ApplicationLibrary/Views/Setting/SettingView.swift"

EXPECTED = {
    "source code": 'URL(string: String("https://github.com/Piggy-Cat-bit-shadow/sing-box"))!',
    "releases": 'URL(string: String("https://github.com/Piggy-Cat-bit-shadow/sing-box/releases"))!',
    "documentation": 'URL(string: String(localized: "https://sing-box.sagernet.org/"))!',
    "changelog": 'URL(string: String(localized: "https://sing-box.sagernet.org/changelog/"))!',
    "configuration": 'URL(string: String(localized: "https://sing-box.sagernet.org/configuration/"))!',
}

# Attribution that must NOT appear in the About section's product links.
FORBIDDEN = {
    "upstream source code": 'URL(string: String("https://github.com/SagerNet/sing-box"))!',
    "upstream releases": 'URL(string: String("https://github.com/SagerNet/sing-box/releases"))!',
}


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"check-apple-links: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: check-apple-links.py <client-dir>")

    path = f"{sys.argv[1]}/{SOURCE_FILE}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    problems: list[str] = []

    for label, needle in EXPECTED.items():
        found = src.count(needle)
        if found != 1:
            problems.append(f"{label}: expected exactly 1, found {found} -> {needle}")

    for label, needle in FORBIDDEN.items():
        found = src.count(needle)
        if found != 0:
            problems.append(f"{label}: still present x{found} -> {needle}")

    if problems:
        fail("the prepared client does not carry the links this fork ships", problems)

    print("check-apple-links: OK")
    print("    source        = https://github.com/Piggy-Cat-bit-shadow/sing-box")
    print("    releases      = https://github.com/Piggy-Cat-bit-shadow/sing-box/releases")
    print("    documentation = https://sing-box.sagernet.org/ (upstream technical docs, unchanged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
