#!/usr/bin/env python3
"""Counts how many build configurations the branding overlay renamed.

Usage: test-branding-scope.py <client-dir>

Prints the number of configuration blocks that now declare the branded product
name. The branding overlay is only allowed to touch the SFI target's Debug and
Release blocks, so the expected answer is 2. Three targets share
PRODUCT_NAME = "sing-box" (SFI, SFT, SFM), so a global string replacement would
rename the tvOS and macOS apps as well.
"""
import re
import sys

TARGET = "SFI"
BRAND = "JiejieBox"


def main() -> int:
    client = sys.argv[1]
    src = open(f"{client}/sing-box.xcodeproj/project.pbxproj", encoding="utf-8").read()

    m = re.search(
        r'Build configuration list for PBXNativeTarget "' + TARGET + r'" \*/ = \{(.*?)\n\t\t\};',
        src,
        re.S,
    )
    if not m:
        print("0")
        return 0

    ids, seen = [], set()
    for cid in re.findall(r"(\w{24})", m.group(1)):
        if cid not in seen:
            seen.add(cid)
            ids.append(cid)

    renamed = 0
    for cid in ids:
        b = re.search(
            rf'{cid} /\* (\w+) \*/ = \{{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\}};',
            src,
            re.S,
        )
        if b and f'PRODUCT_NAME = "{BRAND}"' in b.group(2):
            renamed += 1
    print(renamed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
