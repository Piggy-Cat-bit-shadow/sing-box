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
    #
    # Each link is matched together with the row it activates and the URL it opens, in one
    # expression. Counting Link views anywhere in the file - which an earlier version did - would
    # pass on a file whose Documentation link is a Link and whose Source Code row is a plain Text,
    # because the total would still clear the threshold. The URL being present somewhere and a Link
    # being present somewhere is not the claim; the claim is that THIS row is a Link to THIS URL.
    def link_expression(url: str, label: str) -> str:
        """A Link to `url` whose view body carries `label`.

        The label may be a Label(_:systemImage:) row in a Form or a Text in a context menu, so both
        are accepted - but only when they sit inside THIS Link's closure, immediately after the URL.
        """
        return (
            r'Link\(destination: URL\(string: String\("' + re.escape(url) + r'"\)\)!\)\s*\{\s*'
            r'(?:Label|Text)\("' + re.escape(label) + r'"'
        )

    for label, url in (("Source Code", FORK_SOURCE), ("Releases", FORK_RELEASES)):
        match = re.search(link_expression(url, label), src)
        check(match is not None,
              f"the {label} row is not a Link(destination:) opening {url}. A Link elsewhere in the "
              f"file, or the bare URL string, does not make this row clickable to that destination")

    # Releases lives in the Source Code row's contextMenu. Asserted structurally, because the
    # product expectation is a long-press / right-click item: if the URL appeared in the About
    # section without that relationship, the row would look present but have no context menu.
    source_row = re.search(
        r'Link\(destination: URL\(string: String\("' + re.escape(FORK_SOURCE) + r'"\)\)!\)'
        r'(.*?)(?:RequestReviewButton|^\s*#if)',
        src,
        re.S | re.M,
    )
    check(source_row is not None, "the Source Code row's body could not be read")
    if source_row is not None:
        body = source_row.group(1)
        check("contextMenu" in body,
              "the Source Code row has no contextMenu, so Releases is not reachable from it")
        check(FORK_RELEASES in body,
              "the Source Code contextMenu does not contain the fork releases URL")

    # --- tap blockers -------------------------------------------------------------
    #
    # Scoped to the two rows under test, not the whole file. A blanket scan would fail on an
    # unrelated control elsewhere in Settings, and SwiftUI's .overlay is not itself a tap blocker -
    # so the check is about what is attached to THESE links.
    for label, pattern in (("Source Code", link_expression(FORK_SOURCE, "Source Code")),
                           ("Releases", link_expression(FORK_RELEASES, "Releases"))):
        match = re.search(pattern, src)
        if match is None:
            continue
        # The modifiers between the Link and the end of its label closure.
        start = match.start()
        window = src[start:start + 400]
        for blocker in TAP_BLOCKERS:
            check(blocker not in window,
                  f"{blocker} appears in the {label} row and could swallow the tap")

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
