#!/usr/bin/env python3
"""Point the Apple client's Source Code and Releases links at this fork.

Usage: apply-apple-link-overlay.py <client-dir>

# What this changes, and what it deliberately does not

Two links in the Settings > About section are product attribution: the row that opens
the source repository, and the Releases item in its context menu. Both are shipped
pointing at upstream SagerNet/sing-box, which is the wrong product for this fork.

The Documentation, Changelog and Configuration links are NOT touched. They point at
sing-box.sagernet.org, which is the upstream project's technical documentation and
stays correct for a downstream client: the fork changes who publishes the app, not
where the protocol is documented. Rewriting them to a GitHub README would replace
maintained documentation with a file that is not a substitute for it.

The Sponsors links are not touched either. They credit the upstream author, and this
fork has no sponsor configuration of its own to substitute.

# Why an overlay rather than editing the submodule

clients/apple is a pinned upstream checkout. Committing changes inside it would either
be lost on the next submodule checkout or become an unmaintainable private fork. The
edit is applied to the WORKING TREE at build time, and the parent repository never
records a modified gitlink.

# Fail-closed

The source is asserted to be in one of exactly two states: pristine upstream, or fully
patched. Anything else - a partial application, a missing anchor, an unexpected count -
exits non-zero rather than producing a build whose links nobody verified. If a
repinning changes the URLs or the surrounding code, this fails and asks for review
instead of silently shipping upstream attribution.
"""

import sys

SOURCE_FILE = "ApplicationLibrary/Views/Setting/SettingView.swift"

# The two links this overlay owns. Both are matched as complete Swift expressions
# rather than as bare URLs - see replace_longest_first.
UPSTREAM_SOURCE = 'URL(string: String("https://github.com/SagerNet/sing-box"))!'
FORK_SOURCE = 'URL(string: String("https://github.com/Piggy-Cat-bit-shadow/sing-box"))!'

UPSTREAM_RELEASES = 'URL(string: String("https://github.com/SagerNet/sing-box/releases"))!'
FORK_RELEASES = 'URL(string: String("https://github.com/Piggy-Cat-bit-shadow/sing-box/releases"))!'

# Anchors that must survive untouched, asserted so that a repinning which rewrites the
# About section is noticed rather than silently accepted.
DOCUMENTATION_ANCHORS = [
    'URL(string: String(localized: "https://sing-box.sagernet.org/"))!',
    'URL(string: String(localized: "https://sing-box.sagernet.org/changelog/"))!',
    'URL(string: String(localized: "https://sing-box.sagernet.org/configuration/"))!',
]


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"apply-apple-link-overlay: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def replace_all(src: str, old: str, new: str, expected: int) -> tuple[str, int]:
    """Replace `old` exactly `expected` times, or fail.

    The count is asserted rather than assumed: a repinning that adds, removes or moves a
    link changes the number of sites, and applying the wrong number of edits is how a
    half-patched build ships.
    """
    found = src.count(old)
    if found != expected:
        fail(
            f"expected {expected} occurrence(s) of {old!r}, found {found}",
            ["refusing to apply a partial edit; the pinned client may have been repinned"],
        )
    return src.replace(old, new), found


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: apply-apple-link-overlay.py <client-dir>")

    path = f"{sys.argv[1]}/{SOURCE_FILE}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    upstream_source_count = src.count(UPSTREAM_SOURCE)
    fork_source_count = src.count(FORK_SOURCE)
    upstream_releases_count = src.count(UPSTREAM_RELEASES)
    fork_releases_count = src.count(FORK_RELEASES)

    # Classify the state before editing. A file holding BOTH the upstream and the fork URL
    # is a partially applied state that cannot be resolved safely.
    if fork_source_count > 0 or fork_releases_count > 0:
        if upstream_source_count > 0 or upstream_releases_count > 0:
            fail(
                "the About section references BOTH the upstream and fork links",
                [
                    f"upstream source x{upstream_source_count}, fork source x{fork_source_count}",
                    f"upstream releases x{upstream_releases_count}, fork releases x{fork_releases_count}",
                    "this is a partially applied state that cannot be resolved safely",
                ],
            )
        if fork_source_count != 1 or fork_releases_count != 1:
            fail(
                "the About section is already patched, but not to the expected shape",
                [
                    f"fork source x{fork_source_count}, fork releases x{fork_releases_count}",
                    "expected exactly one of each",
                ],
            )
        state = "patched"
    else:
        if upstream_source_count == 0:
            fail(
                "the source-code link matches neither the upstream nor the fork URL",
                [f"looked for {UPSTREAM_SOURCE!r}", f"and {FORK_SOURCE!r}"],
            )
        state = "upstream"

    # The documentation links are upstream's own technical docs and must be left alone.
    # Asserting them here means a repinning that rewrites the About section is caught by
    # this overlay rather than discovered later.
    for anchor in DOCUMENTATION_ANCHORS:
        if anchor not in src:
            fail(
                "a documentation link this overlay expects to preserve is missing",
                [f"looked for {anchor!r}", "the About section may have been restructured"],
            )

    if state == "patched":
        print("apply-apple-link-overlay: already applied")
        return 0

    # Releases FIRST.
    #
    # The source URL is a strict PREFIX of the releases URL, so a naive replace of the
    # source URL would rewrite the start of the releases URL and leave
    # ".../sing-box/releases" attached to the fork path in an uncontrolled way. Ordering
    # alone is not enough to rely on, which is why both patterns are complete Swift
    # expressions ending in `))!` - the prefix relationship is broken by the closing
    # syntax, not by the order of these calls.
    src, releases_changed = replace_all(src, UPSTREAM_RELEASES, FORK_RELEASES, 1)
    src, source_changed = replace_all(src, UPSTREAM_SOURCE, FORK_SOURCE, 1)

    open(path, "w", encoding="utf-8").write(src)

    # Re-read and assert the result rather than trusting the in-memory string.
    verified = open(path, encoding="utf-8").read()
    if verified.count(FORK_SOURCE) != 1 or verified.count(FORK_RELEASES) != 1:
        fail("the edit did not produce exactly one fork source and one fork releases link")
    if verified.count(UPSTREAM_SOURCE) or verified.count(UPSTREAM_RELEASES):
        fail("an upstream link survived the edit")
    for anchor in DOCUMENTATION_ANCHORS:
        if anchor not in verified:
            fail("the edit disturbed a documentation link", [anchor])

    print(f"apply-apple-link-overlay: source x{source_changed}, releases x{releases_changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
