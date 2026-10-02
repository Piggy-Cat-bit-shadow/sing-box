#!/usr/bin/env python3
"""Checks that release-apple.sh dispatches each TestFlight target correctly.

Usage: test-dispatch.py <testflight|testflight-ios|testflight-macos>

A regression here is quiet and expensive: if the combined `testflight` target
silently stopped calling one platform, or if `testflight-ios` started calling the
macOS builder, the run would still succeed while publishing only half the product.
Parsing the case arms is a blunt instrument, but it is enough to catch a target
being dropped or wired to the wrong builder.
"""
import re
import sys

TARGETS = ("testflight", "testflight-ios", "testflight-macos")
IOS = "build-ios-testflight.sh"
MACOS = "build-macos-testflight.sh"


def arm_body(src: str, target: str) -> str | None:
    # Match "  target)" ... ";;" - the combined target has no suffix, so anchor the
    # name to avoid `testflight` also matching inside `testflight-ios`.
    m = re.search(rf"\n  {re.escape(target)}\)(.*?);;", src, re.S)
    return m.group(1) if m else None


def main() -> int:
    target = sys.argv[1]
    if target not in TARGETS:
        print(f"test-dispatch: unknown target {target}", file=sys.stderr)
        return 2

    src = open("scripts/release-apple.sh", encoding="utf-8").read()
    body = arm_body(src, target)
    if body is None:
        print(f"test-dispatch: {target} has no case arm", file=sys.stderr)
        return 1

    has_ios = IOS in body
    has_macos = MACOS in body

    if target == "testflight-ios":
        ok = has_ios and not has_macos
        detail = "must call only the iOS builder"
    elif target == "testflight-macos":
        ok = has_macos and not has_ios
        detail = "must call only the macOS builder"
    else:
        # The combined target must do BOTH, iOS first: the order is part of the
        # contract because the report reads top to bottom.
        ok = has_ios and has_macos and body.find(IOS) < body.find(MACOS)
        detail = "must call both builders, iOS before macOS"

    if not ok:
        print(
            f"test-dispatch: {target} {detail} "
            f"(iOS={has_ios}, macOS={has_macos})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
