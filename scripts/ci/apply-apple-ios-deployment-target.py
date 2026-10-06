#!/usr/bin/env python3
"""Raises the iOS minimum deployment target to 16.0.

Usage:
    apply-apple-ios-deployment-target.py apply <client-dir>
    apply-apple-ios-deployment-target.py check <client-dir>

Invoked by scripts/ci/prepare-apple-client.sh. See that file for why this is an overlay on
the working tree rather than a change to the pinned client.

# Why this is needed at all

SFI/MainView.swift installs a toolbar item conditionally:

    content.toolbar {
        if environments.remoteServer != nil {
            ToolbarItem(placement: .topBarLeading) { ... }
        }
    }

A conditional inside `toolbar { }` is built by `ToolbarContentBuilder.buildIf`, and the SDK
annotates that entry point

    @available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *)
    public static func buildIf<Content>(_ content: Content?) -> Content?

so at `IPHONEOS_DEPLOYMENT_TARGET = 15.0` the app does not compile:

    SFI/MainView.swift:128:21: error: 'buildIf' is only available in iOS 16.0 or newer

The client is the fork's own UI and its toolbar logic is frozen, so the correct fix is to
raise the floor rather than wrap the construct in an availability check. This project does
not support iOS 15.

# Scope

Only `IPHONEOS_DEPLOYMENT_TARGET` is touched, and only on the targets that take part in
the iOS product. Every one of them must end up at 16.0 or above:

    PBXProject          the inherited default, which the targets below rely on
    SFI                 the app
    ApplicationLibrary  the iOS UI library
    Extension           the packet tunnel provider
    Library             the shared core library
    IntentsExtension, ShareExtension, ActionExtension,
    FileProviderExtension, WidgetExtension

`WidgetExtension` is already at 18.0 and is left alone: this overlay only ever RAISES a
value, so a target that legitimately requires a newer OS is never dragged down to the
floor. Nothing here lowers a version.

Deliberately NOT touched:

    MACOSX_DEPLOYMENT_TARGET   macOS is a different product with a different floor
    TVOS_DEPLOYMENT_TARGET     SFT is not part of this release
    any Swift source           the UI is frozen; this is a build setting, not a code change

`TARGETED_DEVICE_FAMILY`/`SUPPORTED_PLATFORMS` are untouched, so the multi-platform
targets (Library, ApplicationLibrary) keep building for tvOS and macOS; only their iOS
slice moves.

# Fail closed

A target this overlay expects but cannot find is a failure, not a skip: the project was
restructured and the floor would silently stay at 15.0, which is the compile error this
exists to remove. After editing, the effective value of every expected target is re-read
from the file and asserted, and the macOS/tvOS deployment targets are asserted unchanged.
Running `apply` twice is a no-op.
"""

import re
import sys

MINIMUM = (16, 0)
MINIMUM_TEXT = "16.0"

# The targets that make up the iOS product. Named explicitly so a restructured project
# fails instead of quietly keeping a 15.0 floor.
IOS_TARGETS = (
    "SFI",
    "ApplicationLibrary",
    "Extension",
    "Library",
    "IntentsExtension",
    "ShareExtension",
    "ActionExtension",
    "FileProviderExtension",
    "WidgetExtension",
)

# Settings that belong to the other two platforms and must come out of this byte-identical.
UNTOUCHED_SETTINGS = ("MACOSX_DEPLOYMENT_TARGET", "TVOS_DEPLOYMENT_TARGET")


def fail(message, details=None):
    print(f"apply-apple-ios-deployment-target: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def parse_version(text):
    parts = text.split(".")
    if not parts or not parts[0].isdigit():
        return None
    numbers = []
    for part in parts:
        if not part.isdigit():
            # A value like "16.0$(FOO)" is not something this overlay can reason about.
            return None
        numbers.append(int(part))
    while len(numbers) < 2:
        numbers.append(0)
    return tuple(numbers[:2])


def configuration_ids(src, target):
    """Build-configuration ids for a target, in file order.

    The PBXProject has no target name, so it is addressed by its own list comment.
    """
    if target == "__project__":
        match = re.search(
            r'Build configuration list for PBXProject "[^"]*" \*/ = \{(.*?)\n\t\t\};',
            src,
            re.S,
        )
        label = "PBXProject"
    else:
        match = re.search(
            r'Build configuration list for PBXNativeTarget "'
            + re.escape(target)
            + r'" \*/ = \{(.*?)\n\t\t\};',
            src,
            re.S,
        )
        label = target
    if not match:
        fail(f"no configuration list for {label}")

    array = re.search(r"buildConfigurations = \((.*?)\);", match.group(1), re.S)
    if not array:
        fail(f"the configuration list for {label} has no buildConfigurations array")

    entries = re.findall(r"([0-9A-Fa-f]{24}) /\* (\w+) \*/", array.group(1))
    if not entries:
        fail(f"the configuration list for {label} yielded no configuration ids")
    return entries


def block_span(src, cid):
    """Byte span of one XCBuildConfiguration block, addressed by id.

    Splicing by offset rather than by text means the id decides what is edited and position
    in the file is irrelevant - the same reasoning as the branding overlay.
    """
    header = re.compile(
        re.escape(cid) + r" /\* (\w+) \*/ = \{\s*isa = XCBuildConfiguration;",
    )
    match = header.search(src)
    if not match:
        return None
    end_marker = src.find("\n\t\t};", match.end())
    if end_marker < 0:
        return None
    end = end_marker + len("\n\t\t};")
    return match.start(), end, match.group(1), src[match.start():end]


def explicit_target(block):
    match = re.search(r"IPHONEOS_DEPLOYMENT_TARGET = ([0-9.]+);", block)
    return match.group(1) if match else None


def effective_targets(src):
    """The value each expected target builds with: its own setting, else the project's."""
    project_ids = configuration_ids(src, "__project__")
    project_value = None
    for cid, name in project_ids:
        span = block_span(src, cid)
        if span is None:
            fail(f"configuration {cid} ({name}) of PBXProject has no block")
        block = span[3]
        value = explicit_target(block)
        if project_value is None:
            project_value = value
        elif value != project_value:
            fail("the PBXProject's configurations disagree on IPHONEOS_DEPLOYMENT_TARGET",
                 [f"Debug/Release: {project_value} vs {value}"])

    result = {}
    for target in IOS_TARGETS:
        for cid, name in configuration_ids(src, target):
            span = block_span(src, cid)
            if span is None:
                fail(f"configuration {cid} ({name}) of {target} has no block")
            value = explicit_target(span[3])
            result[(target, name)] = (value if value is not None else project_value,
                                      value is not None)
    return result


def untouchable_snapshot(src):
    snapshot = {}
    for setting in UNTOUCHED_SETTINGS:
        snapshot[setting] = re.findall(rf"{setting} = ([^;]+);", src)
    return snapshot


def report(state, action):
    print(f"apply-apple-ios-deployment-target: {action}")
    for (target, name), (value, explicit) in sorted(state.items()):
        origin = "explicit" if explicit else "inherited"
        mark = "ok " if parse_version(value) and parse_version(value) >= MINIMUM else "LOW"
        print(f"  {mark} {target:<20} {name:<8} {value:<8} ({origin})")


def apply(client):
    path = f"{client}/sing-box.xcodeproj/project.pbxproj"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    original = src
    before = untouchable_snapshot(src)

    edits = []
    raised = 0
    already = 0
    added = 0

    # The project-level default first: it is what the inheriting targets resolve to.
    for target in ("__project__",) + IOS_TARGETS:
        for cid, name in configuration_ids(src, target):
            span = block_span(src, cid)
            if span is None:
                fail(f"configuration {cid} ({name}) of {target} has no block")
            start, end, config_name, block = span
            value = explicit_target(block)

            if value is None:
                # Inheriting is fine only if it resolves to the floor, and the project-level
                # value is edited in this same pass. Pinning it explicitly makes the result
                # independent of inheritance order and keeps `check` simple.
                marker = "\t\t\tbuildSettings = {\n"
                if marker not in block:
                    fail(f"{target} {config_name} has no buildSettings block to edit")
                new_block = block.replace(
                    marker, marker + f"\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = {MINIMUM_TEXT};\n", 1
                )
                edits.append((start, end, new_block))
                added += 1
                continue

            parsed = parse_version(value)
            if parsed is None:
                fail(f"{target} {config_name} has an unreadable IPHONEOS_DEPLOYMENT_TARGET",
                     [repr(value)])
            if parsed >= MINIMUM:
                already += 1
                continue

            new_block = block.replace(
                f"IPHONEOS_DEPLOYMENT_TARGET = {value};",
                f"IPHONEOS_DEPLOYMENT_TARGET = {MINIMUM_TEXT};",
                1,
            )
            if new_block == block:
                fail(f"could not raise {target} {config_name} from {value}")
            edits.append((start, end, new_block))
            raised += 1

    # Splice from the end so earlier offsets stay valid.
    for start, end, new_block in sorted(edits, key=lambda item: item[0], reverse=True):
        src = src[:start] + new_block + src[end:]

    if src != original:
        open(path, "w", encoding="utf-8").write(src)
        src = open(path, encoding="utf-8").read()

    after = untouchable_snapshot(src)
    if after != before:
        fail("the edit changed a macOS or tvOS deployment target",
             [f"{k}: {before[k]} -> {after[k]}" for k in before if before[k] != after[k]])

    state = effective_targets(src)
    for (target, name), (value, _) in state.items():
        parsed = parse_version(value)
        if parsed is None or parsed < MINIMUM:
            fail(f"{target} {name} still resolves to {value}, below {MINIMUM_TEXT}")

    report(state, f"raised {raised}, pinned {added}, already at or above {already}")
    return 0


def check(client):
    path = f"{client}/sing-box.xcodeproj/project.pbxproj"
    try:
        src = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        fail(f"{path} is missing")

    state = effective_targets(src)
    low = []
    for (target, name), (value, _) in state.items():
        parsed = parse_version(value)
        if parsed is None or parsed < MINIMUM:
            low.append(f"{target} {name} = {value}")
    report(state, "check")
    if low:
        fail(f"the iOS floor is below {MINIMUM_TEXT}", low)
    print(f"PASS: every iOS target builds at or above iOS {MINIMUM_TEXT}")
    return 0


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("apply", "check"):
        fail("usage: apply-apple-ios-deployment-target.py <apply|check> <client-dir>")
    action, client = sys.argv[1], sys.argv[2]
    return apply(client) if action == "apply" else check(client)


if __name__ == "__main__":
    raise SystemExit(main())
