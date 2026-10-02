#!/usr/bin/env python3
"""Verifies the branding overlay's scope, positively and negatively.

Usage: test-branding-scope.py <client-dir>

The question this answers is not "did the rename happen" but "did ONLY the intended
thing change". Three targets share PRODUCT_NAME = "sing-box" (SFI, SFT, SFM), so a
global string replacement would rename the tvOS and macOS apps as well and still leave
the SFI target looking correct. A test that only counted branded SFI configurations
would pass in that case.

So this asserts both directions:

    SFI Debug and Release   PRODUCT_NAME and CFBundleDisplayName are JiejieBox
    SFT, SFM, SFM.System    still sing-box, both settings, unchanged
    every other extension   still sing-box
    the URL scheme          sing-box, read from the plist rather than grepped
    bundle id and App Group target-scoped, and unchanged in SFI Debug and Release

Exit status is non-zero on any failure, so a CI step cannot mistake a report for a pass.
"""
import plistlib
import re
import sys

BRAND = "JiejieBox"
UPSTREAM = "sing-box"

# Targets that must NOT be branded, with the settings they must still hold.
#
# SFM.System declares no PRODUCT_NAME at all, which is legitimate upstream: it derives
# its name another way. Requiring "sing-box" there would fail on an untouched project,
# so its absence is asserted as absence rather than as a specific value.
UNTOUCHED_TARGETS = ["SFT", "SFM", "SFM.System"]
TARGETS_WITHOUT_PRODUCT_NAME = {"SFM.System"}

SETTINGS = ["PRODUCT_NAME", "INFOPLIST_KEY_CFBundleDisplayName"]

# Values that are legitimate upstream and must not be reported as an unexpected rename.
# Some targets build their product name from the target name rather than a literal.
ALLOWED_UPSTREAM_PRODUCT_NAMES = {
    UPSTREAM,
    "$(TARGET_NAME)",
    "$(TARGET_NAME:c99extidentifier)",
}

problems: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        problems.append(message)


def config_list_ids(src: str, target: str) -> list[str]:
    """Real configuration ids for a target, from its buildConfigurations array."""
    m = re.search(
        r'Build configuration list for PBXNativeTarget "' + re.escape(target) + r'" \*/ = \{(.*?)\n\t\t\};',
        src,
        re.S,
    )
    if not m:
        return []
    array = re.search(r"buildConfigurations = \((.*?)\);", m.group(1), re.S)
    if not array:
        return []
    ids, seen = [], set()
    for cid in re.findall(r"([0-9A-Fa-f]{24}) /\*", array.group(1)):
        if cid not in seen:
            seen.add(cid)
            ids.append(cid)
    return ids


def config_blocks(src: str, target: str) -> dict[str, tuple[str, str]]:
    """{configuration name: (id, block body)} for a target."""
    out: dict[str, tuple[str, str]] = {}
    for cid in config_list_ids(src, target):
        m = re.search(
            rf'{re.escape(cid)} /\* (\w+) \*/ = \{{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\}};',
            src,
            re.S,
        )
        if m:
            out[m.group(1)] = (cid, m.group(0))
    return out


def setting(block: str, key: str) -> str | None:
    m = re.search(rf'^\s*{re.escape(key)} = "([^"]*)";', block, re.M)
    return m.group(1) if m else None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test-branding-scope.py <client-dir>", file=sys.stderr)
        return 2
    client = sys.argv[1]
    src = open(f"{client}/sing-box.xcodeproj/project.pbxproj", encoding="utf-8").read()

    # --- SFI: both configurations, BOTH settings, branded ---------------------
    sfi = config_blocks(src, "SFI")
    check(set(sfi) == {"Debug", "Release"},
          f"SFI configurations: expected Debug and Release, found {sorted(sfi)}")
    for name in ("Debug", "Release"):
        if name not in sfi:
            continue
        _, block = sfi[name]
        for key in SETTINGS:
            got = setting(block, key)
            check(got == BRAND, f"SFI {name} {key}: expected {BRAND!r}, got {got!r}")

    # --- every other target: untouched ----------------------------------------
    # Enumerating the targets we care about is not enough on its own, so the global
    # swept check below catches anything new.
    for target in UNTOUCHED_TARGETS:
        blocks = config_blocks(src, target)
        check(bool(blocks), f"{target}: no build configurations found; the scope check cannot run")
        for name, (_, block) in blocks.items():
            for key in SETTINGS:
                got = setting(block, key)
                if key == "PRODUCT_NAME" and target in TARGETS_WITHOUT_PRODUCT_NAME:
                    # Legitimately absent upstream; the only real requirement is that this
                    # overlay did not add the brand here.
                    check(got != BRAND,
                          f"{target} {name} {key}: must not be branded, got {got!r}")
                    continue
                check(got == UPSTREAM,
                      f"{target} {name} {key}: expected {UPSTREAM!r}, got {got!r} (must not be branded)")

    sfi_ids = {cid for cid, _ in sfi.values()}

    # --- global sweep: a blanket replacement must fail this test --------------
    #
    # The assertion that matters is where the BRAND appears, not which upstream values are
    # legitimate. An earlier version also flagged any unrecognised PRODUCT_NAME, which
    # meant enumerating every value the project legitimately uses - $(TARGET_NAME),
    # $(inherited), sfajb-roothelper, and whatever a future update adds. That is a test
    # that breaks for reasons unrelated to branding, so it was replaced with the direct
    # question: is the brand anywhere it should not be?
    branded_ids: set[str] = set()
    for m in re.finditer(
        r'([0-9A-Fa-f]{24}) /\* (\w+) \*/ = \{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\};',
        src, re.S,
    ):
        cid, name, block = m.group(1), m.group(2), m.group(3)
        for key in SETTINGS:
            if setting(block, key) == BRAND:
                branded_ids.add(cid)

    check(branded_ids == sfi_ids,
          "the brand must appear in exactly the SFI configurations and nowhere else; "
          f"branded {sorted(branded_ids)}, SFI is {sorted(sfi_ids)}")
    for cid in sorted(branded_ids - sfi_ids):
        m = re.search(re.escape(cid) + r' /\* (\w+) \*/', src)
        problems.append(
            f"configuration {m.group(1) if m else cid} ({cid}) carries the brand but is not SFI"
        )

    # --- the URL scheme, read from the plist ----------------------------------
    # grep cannot prove CFBundleURLSchemes is intact: the string appears in many
    # contexts in an Info.plist. Reading the structured value can.
    plist_path = f"{client}/SFI/Info.plist"
    try:
        with open(plist_path, "rb") as fh:
            plist = plistlib.load(fh)
    except FileNotFoundError:
        problems.append(f"{plist_path} is missing, so the URL scheme cannot be verified")
    except Exception as exc:  # noqa: BLE001 - report, do not crash the gate
        problems.append(f"{plist_path} could not be parsed: {exc}")
    else:
        schemes: list[str] = []
        for entry in plist.get("CFBundleURLTypes", []):
            schemes.extend(entry.get("CFBundleURLSchemes", []))
        check(UPSTREAM in schemes,
              f"CFBundleURLSchemes must still contain {UPSTREAM!r}, found {schemes}")
        check(BRAND not in schemes,
              f"CFBundleURLSchemes must not contain {BRAND!r}; the URL scheme is a compatibility contract")

    # --- bundle id and App Group, target-scoped -------------------------------
    #
    # Previously this only proved the variable name still appeared SOMEWHERE in the
    # project, which a rename elsewhere would not have disturbed. Each location is now
    # checked where it actually lives.
    #
    # The bundle id is a pbxproj setting on the SFI configurations themselves.
    for name in ("Debug", "Release"):
        if name not in sfi:
            continue
        _, block = sfi[name]
        got = setting(block, "PRODUCT_BUNDLE_IDENTIFIER")
        check(got is not None and got.startswith("$("),
              f"SFI {name} PRODUCT_BUNDLE_IDENTIFIER: expected a build-setting reference, got {got!r}")

    # The App Group is an entitlement, not a build setting, so it is read from the
    # entitlements plist. Asserting on the pbxproj would have been asserting on the
    # wrong file - and would have passed whether or not the entitlement was intact.
    entitlements_path = f"{client}/SFI/SFI.entitlements"
    try:
        with open(entitlements_path, "rb") as fh:
            entitlements = plistlib.load(fh)
    except FileNotFoundError:
        problems.append(f"{entitlements_path} is missing, so the App Group cannot be verified")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"{entitlements_path} could not be parsed: {exc}")
    else:
        groups = entitlements.get("com.apple.security.application-groups", [])
        check(groups == ["$(APP_GROUP_IDENTIFIER)"],
              "the App Group entitlement must remain $(APP_GROUP_IDENTIFIER), "
              f"found {groups}")
        check(all(BRAND not in str(g) for g in groups),
              f"the App Group must not be renamed to include {BRAND!r}")

    # --- report ---------------------------------------------------------------
    if problems:
        print("test-branding-scope: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("test-branding-scope: PASS")
    print("  SFI Debug/Release: PRODUCT_NAME and CFBundleDisplayName are JiejieBox")
    print(f"  {'/'.join(UNTOUCHED_TARGETS)}: still {UPSTREAM}")
    print("  URL scheme, bundle id and App Group: intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
