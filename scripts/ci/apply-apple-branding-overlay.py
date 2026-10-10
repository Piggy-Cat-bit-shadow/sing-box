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

# Why the display name also accepts "Jiejiebox"

The Apple source started branding the SFI display name itself at the revision this
repository now pins, spelling it "Jiejiebox" - the spelling this fork uses for
user-visible strings. `PRODUCT_NAME` was left upstream, so those configurations arrive
HALF branded: the display name is ours and the product name is not.

That is a state this script has to handle rather than refuse. Refusing was the previous
behaviour and it failed the build, because "branded" was defined as "byte-identical to
what this script writes" - so a configuration the Apple source had already branded read
as neither upstream nor branded. The two spellings are now both recognised as branded,
and the script NORMALISES the display name to the canonical "JiejieBox" so that the
single spelling test-branding-scope.py asserts is the one that ships.

The product name has no such variant: only "sing-box" appears, so it is still an exact
match. An unrecognised third value still fails closed.

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
replacement would rename the tvOS and macOS apps too, so every edit is addressed by
build-configuration id.

# Why edits are addressed by id and not by block text

The previous version located each configuration block by regex, then wrote the result
with `src.replace(old_body, new_body, 1)`. That is a text replacement with an assumption
attached: it only lands on the intended configuration if no other configuration's body
text is identical or a superset. Two build configurations with the same settings -
which is exactly what Debug and Release often are - would make the choice of victim
depend on file order rather than on identity.

This version computes the byte span of each `XCBuildConfiguration` block and splices by
offset, so the id decides what is edited and position in the file is irrelevant.

# Fail closed

The anchors are the upstream values themselves. If the pinned client is updated and
these settings change or move, this script fails rather than silently skipping - a
branding overlay that quietly stops working would ship an app still called sing-box,
which is the bug it exists to fix.
"""
import re
import sys

EXPECTED = {
    "INFOPLIST_KEY_CFBundleDisplayName": ("sing-box", "JiejieBox"),
    "PRODUCT_NAME": ("sing-box", "JiejieBox"),
}

# Spellings of the branded value that count as branded but are not what this script writes.
# A key listed here is canonicalised to the EXPECTED value, so the shipped project always
# carries one spelling whatever the Apple source happened to use.
ALIASES = {
    # The Apple source spells the display name with a lower-case b.
    "INFOPLIST_KEY_CFBundleDisplayName": ("Jiejiebox",),
}

TARGET = "SFI"

# The configurations this overlay is scoped to. Named explicitly so that a new
# configuration appearing upstream is a failure rather than something that silently gets
# branded: "Profile" or "Staging" could legitimately need a different product name, and
# guessing would ship a build nobody reviewed.
EXPECTED_CONFIG_NAMES = {"Debug", "Release"}

SCHEME = "sing-box.xcodeproj/xcshareddata/xcschemes/SFI.xcscheme"
SCHEME_OLD = 'BuildableName = "sing-box.app"'
SCHEME_NEW = 'BuildableName = "JiejieBox.app"'


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"apply-apple-branding-overlay: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def config_ids_for_target(src: str, target: str) -> list[str]:
    """Build-configuration ids belonging to `target`, in file order.

    Only the buildConfigurations array is read. The surrounding XCConfigurationList also
    contains defaultConfigurationIsVisible and defaultConfigurationName, and a naive scan
    for 24-character words picks up fragments of those names as if they were ids - which
    the earlier version did, and which then resolved to no block at all.
    """
    m = re.search(
        r'Build configuration list for PBXNativeTarget "' + re.escape(target) + r'" \*/ = \{(.*?)\n\t\t\};',
        src,
        re.S,
    )
    if not m:
        fail(f"no configuration list for target {target}")

    array = re.search(r"buildConfigurations = \((.*?)\);", m.group(1), re.S)
    if not array:
        fail(f"the configuration list for {target} has no buildConfigurations array")

    # Each entry is `<id> /* <name> */`. Requiring the comment form keeps this to real
    # entries rather than anything else that happens to look like an id.
    ids, seen = [], set()
    for cid in re.findall(r"([0-9A-Fa-f]{24}) /\*", array.group(1)):
        if cid not in seen:
            seen.add(cid)
            ids.append(cid)
    if not ids:
        fail(f"the configuration list for {target} yielded no configuration ids")
    return ids


def block_span(src: str, cid: str) -> tuple[int, int, str, str] | None:
    """Locate one XCBuildConfiguration block by id.

    Returns (start, end, name, body). The span covers exactly this configuration's
    text, so a splice at these offsets cannot touch another block however similar its
    contents are.
    """
    header = re.compile(
        rf'{re.escape(cid)} /\* (\w+) \*/ = \{{\s*isa = XCBuildConfiguration;',
    )
    m = header.search(src)
    if not m:
        return None
    # The block ends at the first line that is exactly two tabs and a closing brace,
    # which is the indentation every XCBuildConfiguration in this file uses.
    end_marker = src.find("\n\t\t};", m.end())
    if end_marker < 0:
        return None
    end = end_marker + len("\n\t\t};")
    return m.start(), end, m.group(1), src[m.start():end]


def settable(block: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)} = "([^"]*)";', block, re.M)
    return m.group(1) if m else None


def brand_block(block: str) -> str:
    for key, (old, new) in EXPECTED.items():
        # An accepted alias is rewritten to the canonical spelling FIRST, so a project the
        # Apple source already branded with a variant ends up byte-identical to one this
        # script branded itself. Without this the block would be reported as branded and
        # left carrying the variant, and the spelling assertion downstream would fail.
        for alias in ALIASES.get(key, ()):
            block = re.sub(
                rf'^(\s*{re.escape(key)} = )"{re.escape(alias)}";',
                rf'\g<1>"{new}";',
                block,
                flags=re.M,
            )
        block = re.sub(
            rf'^(\s*{re.escape(key)} = )"{re.escape(old)}";',
            rf'\g<1>"{new}";',
            block,
            flags=re.M,
        )
    return block


def is_branded(block: str) -> bool:
    for key, (_, new) in EXPECTED.items():
        current = settable(block, key)
        if current != new and current not in ALIASES.get(key, ()):
            return False
    return True


def is_upstream(block: str) -> bool:
    return all(settable(block, key) == old for key, (old, _) in EXPECTED.items())


def patch_scheme(client: str) -> int:
    """Rewrite the SFI scheme's application BuildableName. Returns change count.

    Only the app buildable is touched. An earlier version replaced every occurrence of
    the app name in the file, which would have renamed SFIUITests.xctest if it had
    matched; this asserts on the exact buildable string instead and reports what it
    found.
    """
    path = f"{client}/{SCHEME}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    old_count = src.count(SCHEME_OLD)
    new_count = src.count(SCHEME_NEW)

    if new_count > 0 and old_count == 0:
        return 0  # already applied
    if old_count == 0:
        fail(
            "the SFI scheme does not reference the expected application buildable",
            [f"looked for {SCHEME_OLD!r}", "refusing to guess at the intended rename"],
        )

    open(path, "w", encoding="utf-8").write(src.replace(SCHEME_OLD, SCHEME_NEW))
    return old_count


def scheme_state(client: str) -> str:
    """"old", "new", or fail on anything ambiguous."""
    path = f"{client}/{SCHEME}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    old_count = src.count(SCHEME_OLD)
    new_count = src.count(SCHEME_NEW)
    if old_count > 0 and new_count > 0:
        fail(
            "the SFI scheme references BOTH the old and new buildable names",
            [
                f"{SCHEME_OLD!r} x{old_count}",
                f"{SCHEME_NEW!r} x{new_count}",
                "this is a partially applied state that cannot be resolved safely",
            ],
        )
    if old_count > 0:
        return "old"
    if new_count > 0:
        return "new"
    fail(
        "the SFI scheme references neither buildable name",
        [f"looked for {SCHEME_OLD!r} and {SCHEME_NEW!r}"],
    )


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: apply-apple-branding-overlay.py <client-dir>")
    client = sys.argv[1]
    path = f"{client}/sing-box.xcodeproj/project.pbxproj"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    # --- resolve the SFI configurations by id ---------------------------------
    ids = config_ids_for_target(src, TARGET)

    # Resolve the listed ids to their names first, so an unrecognised configuration is
    # reported as a scope change rather than as a missing block.
    listed = []
    for cid in ids:
        found = block_span(src, cid)
        if found is None:
            fail(
                "the SFI configuration list references an id with no matching block",
                [cid, "the project structure is not the one this overlay was written for"],
            )
        listed.append((cid,) + found)

    names = {name for _, _, _, name, _ in listed}

    # Check the SCOPE before anything else. A new configuration upstream is the case this
    # overlay must not guess about.
    if names != EXPECTED_CONFIG_NAMES:
        fail(
            "the SFI target's configuration set is not the expected one",
            [
                f"found {sorted(names)}",
                f"expected {sorted(EXPECTED_CONFIG_NAMES)}",
                "a new configuration may need different branding; review required",
            ],
        )

    spans = {cid: (start, end, name, block) for cid, start, end, name, block in listed}
    # New name upstream means new scope. Refuse rather than brand something unreviewed.
    if names != EXPECTED_CONFIG_NAMES:
        fail(
            "the SFI target's configuration set is not the expected one",
            [
                f"found {sorted(names)}",
                f"expected {sorted(EXPECTED_CONFIG_NAMES)}",
                "a new configuration may need different branding; review required",
            ],
        )
    if len(spans) != len(EXPECTED_CONFIG_NAMES):
        fail(
            "the SFI target resolves to more configurations than expected",
            [f"resolved {len(spans)} ids for {sorted(names)}"],
        )

    # --- partial states -------------------------------------------------------
    #
    # Normalisation runs BEFORE classification, so that "is this block branded?" is asked of
    # the text that would actually ship rather than of the text we found.
    #
    # The Apple source brands the SFI display name itself at the revision this repository
    # pins, spelling it "Jiejiebox". Classifying the raw text would call that half-branded and
    # refuse the build, which is what happened; classifying the canonicalised text calls it
    # what it is - branded, needing only the spelling normalised - and the write path below
    # then does exactly that.
    normalised = {cid: brand_block(b) for cid, (_, _, _, b) in spans.items()}
    branded = {cid for cid, block in normalised.items() if is_branded(block)}
    upstream = {cid for cid, block in normalised.items() if is_upstream(block)}
    unknown = set(spans) - branded - upstream

    if unknown:
        details = []
        for cid in sorted(unknown):
            _, _, name, block = spans[cid]
            current = {k: settable(block, k) for k in EXPECTED}
            details.append(f"SFI {name}: {current}")
        fail(
            "some SFI configurations are in neither the upstream nor the branded state",
            details + ["refusing to edit a partially branded project"],
        )
    if branded and upstream:
        fail(
            "SFI configurations disagree: some are branded and some are not",
            [
                f"branded: {sorted(spans[c][2] for c in branded)}",
                f"upstream: {sorted(spans[c][2] for c in upstream)}",
            ],
        )

    scheme = scheme_state(client)
    changed_ids = 0

    # The condition is "every block is already exactly what we would write", not "every block
    # reads as branded": those differ precisely when a spelling needs normalising, and using
    # the weaker test would report success without ever writing the canonical spelling.
    pending = {cid for cid in spans if normalised[cid] != spans[cid][3]}

    if not pending:
        # Project fully branded and canonical. The scheme is validated above, so a project-new
        # / scheme-old state is finished rather than reported as done - the previous version
        # returned success here without ever looking at the scheme.
        print("  [branding] project already applied")
    else:
        # Splice by descending offset so earlier spans stay valid.
        for cid in sorted(spans, key=lambda c: spans[c][0], reverse=True):
            start, end, name, block = spans[cid]
            branded_block = normalised[cid]
            if branded_block == block:
                # Already canonical; nothing to splice for this configuration.
                continue
            src = src[:start] + branded_block + src[end:]
            changed_ids += 1
        if changed_ids != len(pending):
            fail(
                f"edited {changed_ids} of {len(pending)} SFI configurations needing branding",
                ["refusing to write a partial result"],
            )
        open(path, "w", encoding="utf-8").write(src)
        print(f"  [branding] SFI product renamed to JiejieBox in {changed_ids} configurations")

    if scheme == "old":
        scheme_changed = patch_scheme(client)
        print(f"  [branding] SFI scheme BuildableName updated ({scheme_changed} references)")
    else:
        print("  [branding] SFI scheme already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
