#!/usr/bin/env python3
"""Brands the macOS App Store / TestFlight app product as Jiejiebox.

Invoked by scripts/ci/prepare-apple-client.sh, and ONLY for
APPLE_CLIENT_PLATFORM=macos. See that file for why this is an overlay on the working
tree rather than a change to the pinned client.

# Why this exists

The macOS product reached TestFlight still called sing-box. The iOS overlay
(apply-apple-branding-overlay.py) brands the SFI target only, and the macOS product is
a DIFFERENT target - SFM - so nothing renamed it and the installed app kept upstream's
PRODUCT_NAME. That is the bug this script fixes.

# Scope

Exactly one target, exactly two configurations, and within them only the two settings
that exist in the pinned project:

    SFM Debug    PRODUCT_NAME, INFOPLIST_KEY_CFBundleDisplayName  sing-box -> Jiejiebox
    SFM Release  PRODUCT_NAME, INFOPLIST_KEY_CFBundleDisplayName  sing-box -> Jiejiebox

plus the SFM scheme's application buildable, sing-box.app -> Jiejiebox.app. Together
those produce Jiejiebox.app with CFBundleDisplayName=Jiejiebox.

The spelling is Jiejiebox, with a lower-case b. It is NOT Jijiebox, JiejieBox or
JiejieBox. The iOS product spells it JiejieBox; that difference is deliberate and is
NOT to be reconciled here - this task renames the macOS TestFlight app and nothing else.

# Why SFM and not SFM.System

SFM (<base>) is the sandboxed Mac App Store/TestFlight app. SFM.System
(<base>.standalone) is the unsandboxed Developer ID product that installs a System
Extension and a privileged helper. It is not an App Store product and is deliberately
NOT touched - this script refuses to edit it even if asked.

# Deliberately NOT changed, because they are compatibility or technical identifiers

    scheme name            SFM
    target name            SFM
    BlueprintIdentifier    every one of them
    bundle identifier      $(BASE_PACKAGE_IDENTIFIER)
    App Group              $(APP_GROUP_IDENTIFIER)
    entitlements           untouched
    the sing-box:// URL scheme, profile types, config format, core name
    SFI, SFT and every extension target, including SFM.System

Three targets share PRODUCT_NAME = "sing-box" (SFI, SFT, SFM) and two share
INFOPLIST_KEY_CFBundleDisplayName, so a global string replacement would rename the
iOS and tvOS products too. Every edit is addressed by build-configuration id.

# Fail closed

The anchors are the upstream values themselves. If the pinned client is updated and
these settings change or move, this script fails rather than silently skipping: a
branding overlay that quietly stops working ships an app still called sing-box, which
is the bug it exists to fix.
"""
import re
import sys

# The product name macOS users see. Kept here as the single definition and read back by
# scripts/ci/test-apple-macos-name.sh and scripts/ci/build-macos-testflight.sh, so the
# overlay, its regression test and the pre-upload gate cannot disagree.
NEW_NAME = "Jiejiebox"

EXPECTED = {
    "PRODUCT_NAME": ("sing-box", NEW_NAME),
    "INFOPLIST_KEY_CFBundleDisplayName": ("sing-box", NEW_NAME),
}

TARGET = "SFM"

# The configurations this overlay is scoped to. Named explicitly so that a new
# configuration appearing upstream is a failure rather than something that silently gets
# branded: "Profile" or "Staging" could legitimately need a different product name, and
# guessing would ship a build nobody reviewed.
EXPECTED_CONFIG_NAMES = {"Debug", "Release"}

SCHEME = "sing-box.xcodeproj/xcshareddata/xcschemes/SFM.xcscheme"
SCHEME_OLD = 'BuildableName = "sing-box.app"'
SCHEME_NEW = f'BuildableName = "{NEW_NAME}.app"'

# The SFM application's BlueprintIdentifier. Every application buildable the scheme
# renames must carry it, so the rename cannot land on some other product's reference.
SFM_BLUEPRINT = "3AEC21082A459B1900A63465"


def fail(message: str, details: list[str] | None = None) -> None:
    print(f"apply-apple-macos-branding-overlay: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def config_ids_for_target(src: str, target: str) -> list[str]:
    """Build-configuration ids belonging to `target`, in file order.

    Only the buildConfigurations array is read. The surrounding XCConfigurationList also
    contains defaultConfigurationIsVisible and defaultConfigurationName, and a naive scan
    for 24-character words picks up fragments of those names as if they were ids.
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

    Returns (start, end, name, body). The span covers exactly this configuration's text,
    so a splice at these offsets cannot touch another block however similar its contents
    are.
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


# `brand_block`, `is_branded` and `is_upstream` were removed with the per-configuration state
# machine they served. They classified a whole configuration as (old,old) or (new,new), which
# cannot describe the mixed state the pinned source ships, and the field-wise replacement in
# main() is both simpler and stricter: it decides each field by exact equality and rewrites
# only what still holds the upstream value.


def scheme_counts(client: str) -> tuple[int, int]:
    path = f"{client}/{SCHEME}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    # Only the application buildable is counted, and only where it carries SFM's
    # BlueprintIdentifier. The scheme also references SFMUITests.xctest, which must keep
    # its name, and a bare string count could not tell the two apart if a product were
    # ever named alike.
    pattern = re.compile(
        r'BlueprintIdentifier = "' + re.escape(SFM_BLUEPRINT) + r'"\s*\n\s*'
        r'BuildableName = "([^"]*)"'
    )
    names = pattern.findall(src)
    if not names:
        fail(
            "the SFM scheme has no application buildable with the expected blueprint id",
            [
                f"looked for BlueprintIdentifier = {SFM_BLUEPRINT!r}",
                "the scheme was restructured; refusing to guess at the intended rename",
            ],
        )

    old_count = names.count("sing-box.app")
    new_count = names.count(f"{NEW_NAME}.app")
    if old_count + new_count != len(names):
        fail(
            "the SFM scheme references an application buildable this overlay does not know",
            [f"buildables: {names}", f"expected only 'sing-box.app' or '{NEW_NAME}.app'"],
        )
    return old_count, new_count


def patch_scheme(client: str) -> int:
    """Rewrite the SFM scheme's application BuildableName. Returns change count."""
    path = f"{client}/{SCHEME}"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    old_count, new_count = scheme_counts(client)
    if new_count > 0 and old_count == 0:
        return 0  # already applied
    if old_count == 0:
        fail(
            "the SFM scheme does not reference the expected application buildable",
            [f"looked for {SCHEME_OLD!r}", "refusing to guess at the intended rename"],
        )

    # Scoped replacement: SFM's application buildable appears once in each of the Build,
    # Launch and Profile actions and all of them must move together, so every occurrence
    # of the exact buildable string is replaced - and the count is checked against what
    # the blueprint-scoped scan found, so a fourth, unrelated occurrence cannot be swept
    # up silently.
    if src.count(SCHEME_OLD) != old_count:
        fail(
            "the SFM scheme references the app buildable outside the SFM target",
            [
                f"the scheme contains {src.count(SCHEME_OLD)} occurrence(s) of {SCHEME_OLD!r}",
                f"but only {old_count} belong to BlueprintIdentifier {SFM_BLUEPRINT}",
                "refusing a replacement that would rename another product",
            ],
        )

    open(path, "w", encoding="utf-8").write(src.replace(SCHEME_OLD, SCHEME_NEW))
    return old_count


def scheme_state(client: str) -> str:
    """"old", "new", or fail on anything ambiguous."""
    old_count, new_count = scheme_counts(client)
    if old_count > 0 and new_count > 0:
        fail(
            "the SFM scheme references BOTH the old and new buildable names",
            [
                f"{SCHEME_OLD!r} x{old_count}",
                f"{SCHEME_NEW!r} x{new_count}",
                "this is a partially applied state that cannot be resolved safely",
            ],
        )
    if old_count > 0:
        return "old"
    return "new"


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: apply-apple-macos-branding-overlay.py <client-dir>")
    client = sys.argv[1]
    path = f"{client}/sing-box.xcodeproj/project.pbxproj"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    # --- resolve the SFM configurations by id ---------------------------------
    ids = config_ids_for_target(src, TARGET)

    # Resolve the listed ids to their names first, so an unrecognised configuration is
    # reported as a scope change rather than as a missing block.
    listed = []
    for cid in ids:
        found = block_span(src, cid)
        if found is None:
            fail(
                "the SFM configuration list references an id with no matching block",
                [cid, "the project structure is not the one this overlay was written for"],
            )
        listed.append((cid,) + found)

    names = {name for _, _, _, name, _ in listed}

    # Check the SCOPE before anything else. A new configuration upstream is the case this
    # overlay must not guess about.
    if names != EXPECTED_CONFIG_NAMES:
        fail(
            "the SFM target's configuration set is not the expected one",
            [
                f"found {sorted(names)}",
                f"expected {sorted(EXPECTED_CONFIG_NAMES)}",
                "a new configuration may need different branding; review required",
            ],
        )

    spans = {cid: (start, end, name, block) for cid, start, end, name, block in listed}
    if len(spans) != len(EXPECTED_CONFIG_NAMES):
        fail(
            "the SFM target resolves to more configurations than expected",
            [f"resolved {len(spans)} ids for {sorted(names)}"],
        )

    # --- the field-wise state machine -----------------------------------------
    #
    # Each field is decided ON ITS OWN, by exact equality:
    #
    #     value == old  ->  rewrite to new
    #     value == new  ->  already satisfied, leave it
    #     anything else ->  hard fail
    #
    # Per-FIELD, not per-configuration, because the pinned Apple source ships a legitimately
    # MIXED configuration: SFM Debug and Release carry
    #
    #     PRODUCT_NAME = "sing-box"
    #     INFOPLIST_KEY_CFBundleDisplayName = "Jiejiebox"
    #
    # - the source has branded the display name it shows a user and left the upstream product
    # identifier alone, which is the same split this repository makes for the Windows
    # executable name. Classifying a whole configuration as (old,old) or (new,new) called that
    # partial corruption and refused to build; it is a valid starting state, and only the
    # remaining field needs overlaying.
    #
    # Still exact, still fail-closed: there is no fuzzy or case-insensitive matching, a third
    # value is a hard failure, and the counts are asserted per field.
    pending_by_id: dict[str, dict[str, str]] = {}
    for cid, (_, _, name, block) in spans.items():
        pending: dict[str, str] = {}
        for key, (old, new) in EXPECTED.items():
            value = settable(block, key)
            if value == old:
                pending[key] = new
            elif value == new:
                continue
            else:
                fail(
                    f"SFM {name}: {key} is neither the upstream nor the branded value",
                    [
                        f"found {value!r}",
                        f"expected exactly {old!r} or {new!r}",
                        "refusing to edit a project whose branding state this overlay does not "
                        "recognise",
                    ],
                )
        if pending:
            pending_by_id[cid] = pending

    scheme = scheme_state(client)
    changed_ids = 0

    if not pending_by_id:
        # Every field already holds the branded value. The scheme is validated above, so a
        # project-new / scheme-old state is finished rather than reported as done.
        print("  [branding] macOS project already applied")
    else:
        # Splice by descending offset so earlier spans stay valid.
        for cid in sorted(spans, key=lambda c: spans[c][0], reverse=True):
            start, end, name, block = spans[cid]
            pending = pending_by_id.get(cid)
            if not pending:
                continue  # this configuration was already fully branded
            branded_block = block
            for key, new in pending.items():
                branded_block, replacements = re.subn(
                    rf'^(\s*{re.escape(key)} = )"[^"]*";',
                    rf'\g<1>"{new}";',
                    branded_block,
                    flags=re.M,
                )
                # Exactly one line is edited per pending field. A different count means the
                # field moved or was duplicated between the read above and here.
                if replacements != 1:
                    fail(
                        f"SFM {name}: expected to rewrite {key} once, rewrote it {replacements} time(s)",
                        ["refusing to write a result this script cannot account for"],
                    )
            if branded_block == block:
                fail("a configuration needed branding but no substitution matched", [f"SFM {name}"])
            src = src[:start] + branded_block + src[end:]
            changed_ids += 1
        if changed_ids != len(pending_by_id):
            fail(
                f"edited {changed_ids} of {len(pending_by_id)} SFM configurations needing branding",
                ["refusing to write a partial result"],
            )
        open(path, "w", encoding="utf-8").write(src)
        print(
            f"  [branding] macOS SFM product renamed to {NEW_NAME} "
            f"in {changed_ids} configuration(s)"
        )

    if scheme == "old":
        scheme_changed = patch_scheme(client)
        print(f"  [branding] macOS SFM scheme BuildableName updated ({scheme_changed} references)")
    else:
        print("  [branding] macOS SFM scheme already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
