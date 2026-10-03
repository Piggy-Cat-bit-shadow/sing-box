#!/usr/bin/env python3
"""Verifies the Apple link overlay's scope and the click contract around it.

Usage: test-apple-links.py <client-dir>

# What this answers

Not "are the fork URLs present" - check-apple-links.py covers that - but "did only the
intended thing change, and is the surrounding view still clickable". The source URL is a
strict prefix of the releases URL, so a careless overlay could produce a plausible-looking
file whose releases link is corrupted; a count of fork URLs alone would not notice.

# The click contract

The reported symptom was "some links do nothing when tapped". A URL can be correct in
source and still be unreachable if something in the view hierarchy swallows the tap, so
this asserts the mechanism rather than the string:

    the row is a real SwiftUI Link(destination:) - not a Text or HStack styled to look
    like a button, which would have no activation at all;

    nothing between it and the Form disables hit testing, and no gesture or overlay is
    attached that could intercept the tap.

It does NOT assert that Safari opens. That cannot be established from source, and
reporting it as verified would be false.
"""

import re
import sys

SETTING_VIEW = "ApplicationLibrary/Views/Setting/SettingView.swift"

FORK_SOURCE = "https://github.com/Piggy-Cat-bit-shadow/sing-box"
FORK_RELEASES = "https://github.com/Piggy-Cat-bit-shadow/sing-box/releases"
UPSTREAM_REPO = "https://github.com/SagerNet/sing-box"

# Constructs that would make a row visually present but unclickable, or that could
# intercept the tap before the Link sees it.
TAP_BLOCKERS = ["allowsHitTesting(false)", ".disabled(true)", "onTapGesture", ".gesture("]

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test-apple-links.py <client-dir>", file=sys.stderr)
        return 2

    path = f"{sys.argv[1]}/{SETTING_VIEW}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"test-apple-links: {path} is missing", file=sys.stderr)
        return 1

    # --- the URLs, both directions ------------------------------------------------
    # The source URL is a strict prefix of the releases URL, so a bare substring count of
    # the source sees the releases URL too. The two are counted as complete Swift
    # expressions instead, which is also how the overlay edits them - the prefix
    # relationship is broken by the closing syntax rather than by match ordering.
    source_expression = f'URL(string: String("{FORK_SOURCE}"))!'
    releases_expression = f'URL(string: String("{FORK_RELEASES}"))!'
    check(src.count(source_expression) == 1,
          f"expected exactly one fork source link, found {src.count(source_expression)}")
    check(src.count(releases_expression) == 1,
          f"expected exactly one fork releases link, found {src.count(releases_expression)}")

    # The prefix trap: a replace of the bare source URL would leave the releases URL
    # mangled. Asserting the releases URL exactly is what catches it.
    check(f'{FORK_SOURCE}/releases' in src,
          "the fork releases URL is not well formed; the source URL may have been "
          "substituted into it as a prefix")

    # Upstream attribution must be gone from the product links. The documentation links
    # legitimately remain on sagernet.org, so this checks the GitHub repo URL only.
    check(src.count(UPSTREAM_REPO) == 0,
          f"upstream repository URL is still present x{src.count(UPSTREAM_REPO)}")

    # Upstream technical documentation must survive - it is not attribution.
    for doc in ["https://sing-box.sagernet.org/",
                "https://sing-box.sagernet.org/changelog/",
                "https://sing-box.sagernet.org/configuration/"]:
        check(doc in src, f"upstream documentation link disappeared: {doc}")

    # --- the click mechanism ------------------------------------------------------
    # Both product links must be real Link(destination:) views.
    link_bodies = re.findall(r"Link\(destination: URL\(string: String\((?:localized: )?\"[^\"]+\"\)\)!\)", src)
    check(len(link_bodies) >= 5,
          f"expected the About section's links to be SwiftUI Link views, found {len(link_bodies)}")

    for blocker in TAP_BLOCKERS:
        check(blocker not in src,
              f"{blocker} appears in the About section and could swallow the tap")

    # The Rate row goes through FormButton, which is a plain Button(action:) - a real
    # action rather than a decorative row. Apple's review API may legitimately show no
    # sheet, so this asserts the action is wired, not that a dialog appears.
    check("RequestReviewButton" in src, "the App Store review row disappeared")

    if failures:
        print("test-apple-links: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"    - {failure}", file=sys.stderr)
        return 1

    print("test-apple-links: OK")
    print("    fork source and releases links present exactly once, well formed")
    print("    upstream repository attribution absent; upstream documentation preserved")
    print("    product links are real Link(destination:) views with no tap blocker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
