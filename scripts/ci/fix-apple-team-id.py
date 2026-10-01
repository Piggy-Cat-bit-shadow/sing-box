#!/usr/bin/env python3
"""Fixes AppConfiguration.teamID, which cannot return a real team identifier.

Invoked by scripts/ci/prepare-apple-client.sh. Read that file for why the edit is
an overlay rather than a change to the pinned submodule.

# The bug

AppConfiguration.teamID derives the team from the App Group's NAME:

    public static var teamID: String {
        guard let dotIndex = appGroupID.firstIndex(of: ".") else { ... }
        return String(appGroupID[..<dotIndex])
    }

That returns everything before the first dot, which is never the team identifier
under either App Group convention in this project:

    group.io.nekohasekai.sfamt        -> "group"
    ABCDE12345io.nekohasekai.sfamt    -> "ABCDE12345io"

Both are wrong. The value is not cosmetic: it is interpolated into XPC and
System Extension code-signing requirements of the form

    certificate leaf[subject.OU] = "<teamID>"

so a wrong value makes those requirements unsatisfiable and the XPC connection is
rejected at runtime. That surfaces as a macOS client whose helper and System
Extension cannot talk to the app, which is easy to mistake for a networking fault.

# The fix

The real team comes from the build. Xcode exposes it as $(DEVELOPMENT_TEAM), which
the build already sets from APPLE_TEAM_ID, so a TeamIdentifier Info.plist key
carries it into the bundle exactly as AppGroupIdentifier already does. teamID then
reads that, and falls back to the old derivation only if the key is absent, so a
build without the overlay behaves as before rather than crashing.
"""
import os
import re
import sys

# Read the real team from the injected Info.plist key.
CONFIG_PATCH_OLD = '''    public static var teamID: String {
        guard let dotIndex = appGroupID.firstIndex(of: ".") else {
            fatalError("Invalid appGroupID format: \\(appGroupID)")
        }
        return String(appGroupID[..<dotIndex])
    }'''

CONFIG_PATCH_NEW = '''    public static var teamID: String {
        // Applied by scripts/ci/prepare-apple-client.sh.
        //
        // The real team identifier is carried in the bundle by the build. The
        // previous implementation split appGroupID on the first ".", which cannot
        // produce a team id under any App Group convention this project uses:
        // "group.io.example.app" gave "group" and "TEAMIDio.example.app" gave
        // "TEAMIDio". The value is used in code-signing requirements
        // (certificate leaf[subject.OU] = "<teamID>"), so a wrong one silently
        // rejects every XPC connection.
        if let value = Bundle.main.object(forInfoDictionaryKey: "TeamIdentifier") as? String,
           !value.isEmpty, !value.contains("$(") {
            return value
        }
        // Fallback for a build that does not inject the key.
        guard let dotIndex = appGroupID.firstIndex(of: ".") else {
            fatalError("Invalid appGroupID format: \\(appGroupID)")
        }
        return String(appGroupID[..<dotIndex])
    }'''

INFO_KEY = "\t<key>TeamIdentifier</key>\n\t<string>$(DEVELOPMENT_TEAM)</string>\n"


def patch_config(path: str) -> bool:
    src = open(path, encoding="utf-8").read()
    if "Applied by scripts/ci/prepare-apple-client.sh" in src:
        return False  # already applied
    if CONFIG_PATCH_OLD not in src:
        print(f"fix-apple-team-id: anchor not found in {path}", file=sys.stderr)
        raise SystemExit(1)
    open(path, "w", encoding="utf-8").write(src.replace(CONFIG_PATCH_OLD, CONFIG_PATCH_NEW, 1))
    return True


def patch_infoplist(path: str) -> bool:
    src = open(path, encoding="utf-8").read()
    if "<key>TeamIdentifier</key>" in src:
        return False
    if "<key>AppGroupIdentifier</key>" not in src:
        # Not a target that uses AppConfiguration; nothing to do.
        return False
    # Insert beside AppGroupIdentifier so the two travel together.
    marker = "\t<key>AppGroupIdentifier</key>\n\t<string>$(APP_GROUP_IDENTIFIER)</string>\n"
    if marker not in src:
        # Some targets hardcode a different group instead of using the build
        # setting - JailbreakDaemon does, and it is not part of the shipped iOS or
        # macOS schemes. They are skipped rather than treated as an error, because
        # the value this fix carries would not be used correctly there anyway.
        print(f"  [team-id] skipped {path} (non-standard AppGroupIdentifier)")
        return False
    os.chmod(path, os.stat(path).st_mode | 0o200)
    open(path, "w", encoding="utf-8").write(src.replace(marker, marker + INFO_KEY, 1))
    return True


def main() -> int:
    client = sys.argv[1]
    config = os.path.join(client, "Library/Shared/AppConfiguration.swift")
    if not os.path.isfile(config):
        print(f"fix-apple-team-id: {config} is missing", file=sys.stderr)
        return 1

    changed_config = patch_config(config)

    changed_plists = []
    for root, _dirs, files in os.walk(client):
        if "Info.plist" not in files:
            continue
        # Skip dependency checkouts inside the submodule.
        if f"{os.sep}Frameworks{os.sep}" in root + os.sep:
            continue
        if patch_infoplist(os.path.join(root, "Info.plist")):
            changed_plists.append(os.path.basename(root))

    if not changed_config and not changed_plists:
        print("  [team-id] already applied")
    else:
        print(f"  [team-id] AppConfiguration.teamID now reads the build's team")
        if changed_plists:
            print(f"  [team-id] TeamIdentifier added to {len(changed_plists)} Info.plist file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
