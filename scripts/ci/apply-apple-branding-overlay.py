#!/usr/bin/env python3
"""Brands the iOS app product as JiejieBox.

Invoked by scripts/ci/prepare-apple-client.sh. See that file for why this is an
overlay on the working tree rather than a change to the pinned submodule.

# Scope

Only the SFI target's Debug and Release configurations are touched, and only two
settings within them:

    INFOPLIST_KEY_CFBundleDisplayName  "sing-box" -> "JiejieBox"
    PRODUCT_NAME                       "sing-box" -> "JiejieBox"

which together produce JiejieBox.app with CFBundleDisplayName=JiejieBox.

Deliberately NOT changed, because they are compatibility or technical identifiers
rather than branding:

    scheme name            SFI
    target name            SFI
    bundle identifier      $(BASE_PACKAGE_IDENTIFIER)
    App Group              $(APP_GROUP_IDENTIFIER)
    entitlements           untouched
    the sing-box:// URL scheme, profile types, config format, core name
    SFT, SFM, SFM.System and every extension target

Three targets share PRODUCT_NAME = "sing-box" (SFI, SFT, SFM). A global string
replacement would rename the tvOS and macOS apps too, so the edit is addressed by
build-configuration id, resolved from the project's own configuration lists.

# Fail closed

The anchors are the upstream values themselves. If the pinned client is updated and
these settings change or move, this script fails rather than silently skipping -
a branding overlay that quietly stops working would ship an app still called
sing-box, which is the bug it exists to fix.
"""
import re
import sys

# Target -> the upstream values this overlay expects to find, and their replacements.
EXPECTED = {
    "INFOPLIST_KEY_CFBundleDisplayName": ("sing-box", "JiejieBox"),
    "PRODUCT_NAME": ("sing-box", "JiejieBox"),
}

TARGET = "SFI"

# The scheme refers to the built product by its bundle name, so it has to follow the
# rename. Only the application buildable entry changes: SFIUITests.xctest is a
# different buildable in the same scheme and must be left alone.
SCHEME = "sing-box.xcodeproj/xcshareddata/xcschemes/SFI.xcscheme"
SCHEME_OLD = 'BuildableName = "sing-box.app"'
SCHEME_NEW = 'BuildableName = "JiejieBox.app"'


def patch_scheme(client: str) -> int:
    """Rewrite the SFI scheme's application BuildableName. Returns change count."""
    path = f"{client}/{SCHEME}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"apply-apple-branding-overlay: {path} is missing", file=sys.stderr)
        raise SystemExit(1)

    if SCHEME_NEW in src and SCHEME_OLD not in src:
        return 0  # already applied
    if SCHEME_OLD not in src:
        print(
            "apply-apple-branding-overlay: the SFI scheme does not reference "
            f'{SCHEME_OLD!r}; refusing to guess.',
            file=sys.stderr,
        )
        raise SystemExit(1)

    count = src.count(SCHEME_OLD)
    open(path, "w", encoding="utf-8").write(src.replace(SCHEME_OLD, SCHEME_NEW))
    return count


def config_ids_for_target(src: str, target: str) -> list[str]:
    """Build-configuration ids belonging to `target`, in file order."""
    m = re.search(
        r'Build configuration list for PBXNativeTarget "' + re.escape(target) + r'" \*/ = \{(.*?)\n\t\t\};',
        src,
        re.S,
    )
    if not m:
        print(f"apply-apple-branding-overlay: no configuration list for target {TARGET}", file=sys.stderr)
        raise SystemExit(1)
    ids, seen = [], set()
    for cid in re.findall(r"(\w{24})", m.group(1)):
        if cid not in seen:
            seen.add(cid)
            ids.append(cid)
    return ids


def settable(block: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)} = "([^"]*)";', block, re.M)
    return m.group(1) if m else None


def main() -> int:
    client = sys.argv[1]
    path = f"{client}/sing-box.xcodeproj/project.pbxproj"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        print(f"apply-apple-branding-overlay: {path} is missing", file=sys.stderr)
        return 1

    ids = config_ids_for_target(src, TARGET)

    blocks = {}
    for cid in ids:
        m = re.search(
            rf'{cid} /\* (\w+) \*/ = \{{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\}};',
            src,
            re.S,
        )
        if m:
            blocks[cid] = (m.group(1), m.group(2))

    if not blocks:
        print("apply-apple-branding-overlay: no build configurations resolved for SFI", file=sys.stderr)
        return 1

    # --- already applied? -----------------------------------------------------
    already = all(
        settable(body, key) == new
        for _, body in blocks.values()
        for key, (_, new) in EXPECTED.items()
    )
    if already:
        print("  [branding] already applied")
        return 0

    # --- verify every anchor BEFORE editing anything --------------------------
    problems = []
    for cid, (name, body) in blocks.items():
        for key, (old, _new) in EXPECTED.items():
            current = settable(body, key)
            if current != old:
                problems.append(
                    f"SFI {name}: {key} is {current!r}, expected {old!r}"
                )
    if problems:
        print("apply-apple-branding-overlay: the pinned client does not match the expected structure.", file=sys.stderr)
        print("  Refusing to edit: a fuzzy replacement could rename other targets.", file=sys.stderr)
        for p in problems:
            print(f"    - {p}", file=sys.stderr)
        return 1

    # --- apply, by exact block substitution -----------------------------------
    changed = 0
    for cid, (_name, body) in blocks.items():
        new_body = body
        for key, (old, new) in EXPECTED.items():
            new_body = re.sub(
                rf'^(\s*{re.escape(key)} = )"{re.escape(old)}";',
                rf'\g<1>"{new}";',
                new_body,
                flags=re.M,
            )
        if new_body != body:
            src = src.replace(body, new_body, 1)
            changed += 1

    if changed != len(blocks):
        print(
            f"apply-apple-branding-overlay: edited {changed} of {len(blocks)} SFI configurations",
            file=sys.stderr,
        )
        return 1

    open(path, "w", encoding="utf-8").write(src)
    print(f"  [branding] SFI product renamed to JiejieBox in {changed} configurations")

    scheme_changed = patch_scheme(client)
    if scheme_changed:
        print(f"  [branding] SFI scheme BuildableName updated ({scheme_changed} references)")
    else:
        print("  [branding] SFI scheme already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
