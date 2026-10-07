#!/usr/bin/env python3
"""Applies the Jiejiebox branding and unsigned-build overlay to a desktop client.

Invoked by scripts/ci/prepare-desktop-client.sh. See that file for why this is an
overlay on the working tree rather than a change to the pinned submodule.

# Scope

Every rule is an EXACT, COUNTED replacement. There is no global substitution anywhere:
`sing-box` appears in this client as a product name, as the name of the core it talks
to, and inside compatibility identifiers, and a blanket rename would corrupt the third
group. So each edit names one line (or one block) and states how many of it must exist.

The rules fall into three groups:

  release identity   the desktop app's version, and the installer's file name
  unsigned build     signing off by default, and the Windows signing configuration
                     made optional instead of mandatory
  visible branding   the strings a user reads that name the product

# Why the unsigned-build group reaches into package.ts and afterPack.cjs

`forceCodeSigning: false` in electron-builder.yml is necessary but NOT sufficient. Two
more places require a certificate before electron-builder is even reached or once it has
packed:

  scripts/package.ts     readWindowsSigningConfiguration() throws when signing.local.json
                         is absent, so the build never started. The fix is to make the
                         absence of that file mean "build unsigned", while keeping a
                         PRESENT but invalid file a hard error, and to supply
                         signtoolOptions only when a certificate was configured.
  scripts/afterPack.cjs  signs sing-box-daemon.exe and windows_share.node - which the
                         app's own signature does not cover - and throws if that did not
                         happen. With no certificate it returns instead.

Both use the same predicate: a certificate is configured exactly when signing.local.json
exists. electron-builder's signing support is left intact in both cases - give it a
certificate and it still signs, and afterPack still enforces that it did.

# Fail closed, and atomically

An early version applied rules one at a time, so a failure part-way through left a
client branded in some places and not others - worse than not running at all, because
the result builds. This version PLANS every rule first, writes only if all of them
resolved, and then re-reads what it wrote. Nothing is written unless everything can be.

A rule that finds neither its original text nor its target text is a failure, not a
skip: it means the pinned client changed shape underneath the overlay, and continuing
would ship a client nobody reviewed.
"""
import os
import re
import sys
import tempfile

# --- rule engine -------------------------------------------------------------


class Rule:
    """One exact, counted replacement.

    kind "line"   `old` is matched against the STRIPPED text of a single physical line
                  and the line's own indentation is carried over to `new`. `anchor`,
                  when set, additionally requires the nearest preceding non-blank line
                  to be exactly that text - which is how two identical `sing-box` lines
                  are told apart from the other three in the same file.
    kind "block"  `old` and `new` are literal multi-line text, matched and replaced
                  verbatim. Used where the edit is a whole object rather than one line.
    """

    def __init__(self, path, old, new, expected, kind="line", anchor=None, note=""):
        self.path = path
        self.old = old
        self.new = new
        self.expected = expected
        self.kind = kind
        self.anchor = anchor
        self.note = note

    @property
    def label(self):
        return self.note or self.old


def preceding_non_blank(lines, index):
    position = index - 1
    while position >= 0:
        if lines[position].strip():
            return lines[position].strip()
        position -= 1
    return None


def line_matches(lines, text, anchor):
    """Indices of lines whose stripped text is `text`, optionally after `anchor`."""
    found = []
    for index, line in enumerate(lines):
        if line.strip() != text:
            continue
        if anchor is not None and preceding_non_blank(lines, index) != anchor:
            continue
        found.append(index)
    return found


def plan(text, rule):
    """Returns ("already", None) | ("pending", payload) | ("fail", reason)."""
    if rule.kind == "block":
        current = text.count(rule.new)
        previous = text.count(rule.old)
        if current == rule.expected:
            return "already", None
        if current != 0 or previous != rule.expected:
            return "fail", (
                f"expected {rule.expected} x {rule.old!r}, "
                f"found {previous}; and {current} already-overlaid"
            )
        return "pending", text.replace(rule.old, rule.new, rule.expected)

    # A line rule names one physical line, compared with surrounding whitespace removed,
    # because the file's indentation is not part of what is being matched - it is carried
    # over from the line being replaced. Comparing the raw text instead would both miss a
    # rule written with its indentation and, when it did match, double that indentation on
    # the way back out.
    old_text = rule.old.strip()
    new_text = rule.new.strip()
    if "\n" in old_text or "\n" in new_text:
        return "fail", f"a line rule must name a single physical line: {rule.old!r}"

    lines = text.splitlines(keepends=True)
    current = len(line_matches(lines, new_text, rule.anchor))
    if current == rule.expected:
        return "already", None
    if current != 0:
        return "fail", f"expected {rule.expected} overlaid lines, found {current}"

    indices = line_matches(lines, old_text, rule.anchor)
    if len(indices) != rule.expected:
        return "fail", (
            f"expected {rule.expected} line(s) {old_text!r}"
            + (f" after {rule.anchor!r}" if rule.anchor is not None else "")
            + f", found {len(indices)}"
        )

    reindented = []
    for index in indices:
        line = lines[index]
        indent = line[: len(line) - len(line.lstrip())]
        reindented.append(f"{indent}{new_text}\n")
    for index, replacement in zip(indices, reindented):
        lines[index] = replacement
    return "pending", "".join(lines)


# --- the rules ---------------------------------------------------------------
#
# Ordered by group. Within scripts/package.ts the block rules are listed before the
# line rules, and the engine runs them in that order, so a line rule can never be
# applied inside a region a block rule is about to rewrite.

RULES = [
    # --- release identity ----------------------------------------------------
    #
    # The desktop GUI for this release is the v0.1.5 client, so its version is the
    # core's version rather than the upstream desktop client's own 1.14.2. That value
    # is what electron-builder stamps into the app and substitutes for ${version} in
    # the installer name below, so setting it here is what makes the artifact called
    # Jiejiebox-v0.1.5-windows-x64.exe rather than naming it after the wrong product.
    Rule(
        "version.json",
        '"version": "1.14.2",',
        '"version": "0.1.5",',
        1,
        note='version.json application version -> 0.1.5',
    ),
    Rule(
        "scripts/package.ts",
        'const artifactName = `SFW-\\${version}-${artifactArchitecture}'
        '${developmentPackage ? "-dev" : ""}.\\${ext}`;',
        'const artifactName = `Jiejiebox-v\\${version}-windows-${artifactArchitecture}'
        '${developmentPackage ? "-dev" : ""}.\\${ext}`;',
        1,
        note="Windows installer name -> Jiejiebox-v<version>-windows-<arch>.exe",
    ),
    # --- unsigned build ------------------------------------------------------
    #
    # Necessary: electron-builder refuses to produce an installer without a
    # certificate while this is true.
    Rule(
        "electron-builder.yml",
        "forceCodeSigning: true",
        "forceCodeSigning: false",
        1,
        note="allow an unsigned build (signing still happens when a cert is given)",
    ),
    # Sufficient, together with the three edits below: package.ts otherwise requires
    # signing.local.json even when electron-builder would not have signed anything.
    Rule(
        "scripts/package.ts",
        "function readWindowsSigningConfiguration(): WindowsSigningConfiguration {",
        "function readWindowsSigningConfiguration(): WindowsSigningConfiguration | undefined {",
        1,
        note="the signing configuration becomes optional",
    ),
    Rule(
        "scripts/package.ts",
        "  let value: unknown;\n  try {\n",
        "  // UNSIGNED BUILD OVERLAY: an absent configuration file means no certificate is\n"
        "  // configured, so the build proceeds unsigned. A file that EXISTS but is invalid\n"
        "  // is still a hard error, so a broken signing setup cannot silently ship an\n"
        "  // unsigned installer.\n"
        "  if (!fs.existsSync(signingConfigurationPath)) {\n"
        "    return undefined;\n"
        "  }\n"
        "\n"
        "  let value: unknown;\n  try {\n",
        1,
        kind="block",
        note="absent signing.local.json means build unsigned",
    ),
    Rule(
        "scripts/package.ts",
        "  signingConfiguration: WindowsSigningConfiguration,",
        "  signingConfiguration: WindowsSigningConfiguration | undefined,",
        1,
        note="runWindowsElectronBuilder accepts an absent certificate",
    ),
    Rule(
        "scripts/package.ts",
        "        win: {\n"
        "          artifactName,\n"
        "          signtoolOptions: {\n"
        "            certificateFile: signingConfiguration.certificateFile,\n"
        "            certificatePassword: signingConfiguration.certificatePassword,\n"
        "          },\n"
        "        },\n",
        "        win: {\n"
        "          artifactName,\n"
        "          // UNSIGNED BUILD OVERLAY: signtoolOptions is supplied only when a\n"
        "          // certificate was configured. electron-builder's signing support is\n"
        "          // left intact - a build given a certificate still signs.\n"
        "          ...(signingConfiguration === undefined\n"
        "            ? {}\n"
        "            : {\n"
        "                signtoolOptions: {\n"
        "                  certificateFile: signingConfiguration.certificateFile,\n"
        "                  certificatePassword: signingConfiguration.certificatePassword,\n"
        "                },\n"
        "              }),\n"
        "        },\n",
        1,
        kind="block",
        note="signtoolOptions supplied only when a certificate is configured",
    ),
    # Upstream signs these two binaries - which electron-builder does NOT cover with the
    # app's own signature - and hard-fails if that did not happen. With no certificate
    # configured there is nothing to sign, so the hook returns instead of throwing. The
    # predicate is the same one package.ts uses: a configured certificate is the presence
    # of signing.local.json, so "signed build" means one thing in both places.
    Rule(
        "scripts/afterPack.cjs",
        '  if (context.electronPlatformName !== "win32") {\n'
        "    return;\n"
        "  }\n"
        "  for (const relativePath of [\n",
        '  if (context.electronPlatformName !== "win32") {\n'
        "    return;\n"
        "  }\n"
        "  // UNSIGNED BUILD OVERLAY: the two binaries below are signed separately because\n"
        "  // electron-builder's app signature does not cover them. With no certificate\n"
        "  // configured there is nothing to sign, so this is a no-op rather than a failure.\n"
        "  // electron-builder's own signing support is untouched.\n"
        '  if (!fs.existsSync(path.join(context.packager.projectDir, "signing.local.json"))) {\n'
        "    return;\n"
        "  }\n"
        "  for (const relativePath of [\n",
        1,
        kind="block",
        note="afterPack no longer requires signing when no certificate is configured",
    ),
    # --- visible branding ----------------------------------------------------
    #
    # The five audit-confirmed user-visible product names, plus productName - which is the
    # name the operating system shows in the window title, the Start Menu entry, the
    # installer's own display name and Add/Remove Programs. Everything else that says
    # `sing-box` was classified as a core/service/API name, a localStorage key, an
    # internal identifier or attribution, and is left exactly as it is.
    Rule(
        "electron-builder.yml",
        "productName: sing-box",
        "productName: Jiejiebox",
        1,
        note="productName -> Jiejiebox (window title, Start Menu, installer)",
    ),
    Rule(
        "dashboard/src/App.tsx",
        "<div className={styles.mobileTopbarBrand}>sing-box</div>",
        "<div className={styles.mobileTopbarBrand}>Jiejiebox</div>",
        1,
        note="dashboard mobile topbar brand",
    ),
    Rule(
        "dashboard/src/App.tsx",
        "sing-box",
        "Jiejiebox",
        2,
        anchor="<div className={styles.sidebarBrand}>",
        note="dashboard desktop + mobile sidebar brand",
    ),
    Rule(
        "dashboard/index.html",
        '<meta name="apple-mobile-web-app-title" content="sing-box" />',
        '<meta name="apple-mobile-web-app-title" content="Jiejiebox" />',
        1,
        note="dashboard apple-mobile-web-app-title",
    ),
    Rule(
        "dashboard/vite.config.ts",
        'name: "sing-box dashboard",',
        'name: "Jiejiebox dashboard",',
        1,
        note="PWA manifest name",
    ),
    Rule(
        "dashboard/vite.config.ts",
        'short_name: "sing-box",',
        'short_name: "Jiejiebox",',
        1,
        note="PWA manifest short_name",
    ),
]

# Strings that must still be present afterwards. These are the other side of the same
# coin: they are the identifiers a global rename would have destroyed.
PRESERVED = [
    ("dashboard/src/App.tsx", 'name: "sing-box"', "the local core server is still sing-box"),
    ("dashboard/index.html", "sing-box-dashboard.theme", "theme localStorage key"),
    ("dashboard/index.html", "sing-box-dashboard.accent", "accent localStorage key"),
    ("dashboard/index.html", "sing-box-dashboard.language", "language localStorage key"),
    ("dashboard/vite.config.ts", "Web dashboard for sing-box.", "PWA core description"),
    ("electron-builder.yml", "application/x-sing-box-profile", "profile MIME type"),
    ("electron-builder.yml", "executableName: sing-box", "NSIS executable name"),
    ("electron-builder.yml", "to: daemon/sing-box-daemon.exe", "daemon file name"),
    ("package.json", '"name": "sing-box"', "package and appId identity"),
    ("package.json", '"name": "SagerNet"', "SagerNet attribution"),
    ("electron-builder.yml", "copyright: nekohasekai", "upstream copyright"),
    (
        "scripts/afterPack.cjs",
        "await context.packager.signIf(executablePath);",
        "the daemon and native module are still signed when a certificate is configured",
    ),
    (
        "scripts/package.ts",
        "signtoolOptions: {",
        "electron-builder signing support is still present",
    ),
]

WRONG_SPELLINGS = ["Jijiebox", "JieJieBox", "JiejieBox"]


def fail(message, details=None):
    print(f"apply-desktop-branding-overlay: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def write_atomically(path, text):
    directory = os.path.dirname(path) or "."
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".overlay-")
    try:
        with os.fdopen(handle, "w") as stream:
            stream.write(text)
        os.chmod(temporary, os.stat(path).st_mode & 0o7777)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def main():
    if len(sys.argv) != 2:
        fail("usage: apply-desktop-branding-overlay.py <desktop-client-dir>")
    root = os.path.realpath(sys.argv[1])

    # --- read everything, then plan -----------------------------------------
    originals = {}
    for rule in RULES:
        path = os.path.join(root, rule.path)
        if rule.path not in originals:
            if not os.path.isfile(path):
                fail(f"{rule.path} is missing; is this a desktop client checkout?")
            with open(path) as stream:
                originals[rule.path] = stream.read()

    planned = dict(originals)
    failures = []
    for rule in RULES:
        status, payload = plan(planned[rule.path], rule)
        if status == "fail":
            failures.append(f"{rule.path}: {rule.label}: {payload}")
        elif status == "pending":
            planned[rule.path] = payload
    if failures:
        fail(
            "the pinned desktop client does not have the shape this overlay was written"
            " against, so nothing was written",
            failures,
        )

    # --- write --------------------------------------------------------------
    changed = []
    for path, text in planned.items():
        if text != originals[path]:
            write_atomically(os.path.join(root, path), text)
            changed.append(path)

    # --- confirm what was written, by re-reading it -------------------------
    confirmed = []
    for rule in RULES:
        with open(os.path.join(root, rule.path)) as stream:
            text = stream.read()
        if rule.kind == "block":
            count = text.count(rule.new)
        else:
            count = len(line_matches(text.splitlines(keepends=True), rule.new.strip(), rule.anchor))
        if count != rule.expected:
            fail(f"{rule.path}: {rule.label}: wrote it but read back {count}, expected {rule.expected}")
        confirmed.append(f"{rule.path}: {rule.label}")

    preserved_failures = []
    for path, needle, why in PRESERVED:
        with open(os.path.join(root, path)) as stream:
            if needle not in stream.read():
                preserved_failures.append(f"{path}: {why} ({needle!r} is gone)")
    if preserved_failures:
        fail("a preserved non-branding string was destroyed by this overlay", preserved_failures)

    spelling_failures = []
    for path in originals:
        with open(os.path.join(root, path)) as stream:
            text = stream.read()
        for wrong in WRONG_SPELLINGS:
            if wrong in text:
                spelling_failures.append(f"{path}: contains {wrong!r}")
    if spelling_failures:
        fail("a misspelled product name is present", spelling_failures)

    print(f"  overlay rules: {len(RULES)} applied/confirmed")
    for line in confirmed:
        print(f"    {line}")
    if changed:
        for path in changed:
            print(f"  wrote: {path}")
    else:
        print("  nothing to write: the client already carries this overlay")


if __name__ == "__main__":
    main()
