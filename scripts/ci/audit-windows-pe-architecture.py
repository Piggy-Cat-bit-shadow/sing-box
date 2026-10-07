#!/usr/bin/env python3
"""Architecture audit for a packaged Windows desktop client.

Usage:
    audit-windows-pe-architecture.py <path>... [options]

    --profile NAME          fill in the expected architecture, the required contents and
                            the justified exceptions for a known package (see PROFILES)
    --root DIR              directory that --require paths are relative to
                            (default: the first path when it is a directory)
    --expect NAME           the architecture every PE image must be (default: amd64)
    --allow GLOB=REASON     permit one PE image to be a different architecture, and say
                            why. Repeatable. Without a REASON this is rejected, because
                            an exception nobody justified is how a wrong-architecture
                            binary ships.
    --require RELATIVE      a file that must exist and must be the expected architecture.
                            Repeatable.
    --record PATH           also write the audit to PATH

# Why this exists

The Windows client is x64 only. Nothing downstream would notice if an x86 or ARM64
binary ended up in the package: the installer builds, the app starts on the build
machine, and the failure appears as a native module that will not load on a user's
machine. scripts/package.ts already checks the binaries it stages, but that is the
INPUT to packaging - it says nothing about what electron-builder actually put in the
package, which is what this audits.

Only PE images are judged. A package legitimately contains .pak, .asar, .js, .json and
image files; those are counted and skipped rather than reported as failures.

# Why the expected contents are a profile

"Everything in the Jiejiebox Windows package is x64, and it contains these files" is one
fact about one product. Stating it twice - once for the tree electron-builder produced and
once for the payload extracted from the built installer - is how the two drift apart, and
the drift is invisible because both would still pass. The profile is that fact, named
once, and both audits use it.

# Exceptions are declared, never inferred

Two i386 images appear in a correct build, for reasons that have nothing to do with the
target architecture:

  Jiejiebox-v*-windows-x64.exe   an NSIS installer is a 32-bit stub whatever it installs.
                                 This is the file the user runs, and it is not the payload.
  resources/elevate.exe          electron-builder's own elevate helper, which it packs
                                 into the application by default (packElevateHelper). The
                                 client does not use it - src/main/repair.ts elevates with
                                 PowerShell's "runas" verb instead - but it is
                                 electron-builder's file and it is not this overlay's
                                 place to remove it. It runs as a 32-bit process on 64-bit
                                 Windows, which is what it is for.

Neither is excused by a wildcard. Each is named, and each states why it is not a defect.
An exception that never matched anything is reported as unused rather than passing
silently, so a stale one is visible.
"""
import argparse
import fnmatch
import pathlib
import sys

MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "amd64",
    0x01C0: "arm",
    0x01C4: "armnt",
    0xAA64: "arm64",
}

EXPECTED_MACHINES = {
    "amd64": 0x8664,
    "i386": 0x014C,
    "arm64": 0xAA64,
    "arm": 0x01C0,
}

PROFILES = {
    "desktop-win-x64": {
        "expect": "amd64",
        "require": [
            "Jiejiebox.exe",
            "resources/daemon/sing-box-daemon.exe",
            "resources/daemon/libcronet.dll",
            "resources/daemon/WinDivert64.sys",
            "resources/daemon/VBoxUSB.sys",
            "resources/daemon/VBoxUSBMon.sys",
            "resources/daemon/usbip2_ude.sys",
            "resources/daemon/usbip2_filter.sys",
            "resources/native/windows_share.node",
        ],
        "allow": {
            "resources/elevate.exe": (
                "i386 electron-builder's elevate helper (packElevateHelper), shipped by "
                "electron-builder, not by this fork; the client elevates with PowerShell "
                "runas and does not use it"
            ),
        },
    },
}


def fail(message, details=None):
    print(f"audit-windows-pe-architecture: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def pe_machine(path):
    """The COFF machine field, or None when the file is not a PE image."""
    try:
        with path.open("rb") as stream:
            data = stream.read(4096)
    except OSError:
        return None
    if len(data) < 64 or data[0:2] != b"MZ":
        return None
    header = int.from_bytes(data[0x3C:0x40], "little")
    if header + 6 > len(data) or data[header:header + 4] != b"PE\x00\x00":
        return None
    return int.from_bytes(data[header + 4:header + 6], "little")


def collect(paths):
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file():
                    yield candidate
        elif path.is_file():
            yield path
        else:
            fail(f"{path} does not exist")


def parse_allows(entries):
    allowed = {}
    for entry in entries:
        pattern, separator, reason = entry.partition("=")
        if not separator or not reason.strip():
            fail(
                f"--allow {entry!r} has no reason",
                ["every architecture exception must say why it is not a defect"],
            )
        allowed[pattern] = reason.strip()
    return allowed


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--profile", choices=sorted(PROFILES))
    parser.add_argument("--root")
    parser.add_argument("--expect")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--require", action="append", default=[])
    parser.add_argument("--record")
    arguments = parser.parse_args()

    profile = PROFILES[arguments.profile] if arguments.profile else {}
    expect = arguments.expect or profile.get("expect") or "amd64"
    if expect not in EXPECTED_MACHINES:
        fail(f"unknown architecture {expect!r}; expected one of {', '.join(EXPECTED_MACHINES)}")
    expected = EXPECTED_MACHINES[expect]

    required = list(profile.get("require", [])) + arguments.require
    allow_entries = [f"{pattern}={reason}" for pattern, reason in profile.get("allow", {}).items()]
    allowed = parse_allows(allow_entries + arguments.allow)

    paths = [pathlib.Path(item) for item in arguments.paths]
    root = pathlib.Path(arguments.root) if arguments.root else (
        paths[0] if paths[0].is_dir() else paths[0].parent
    )
    root = root.resolve()

    rows, skipped, violations, exemptions = [], 0, [], []
    used_patterns = set()
    for path in collect(paths):
        machine = pe_machine(path)
        if machine is None:
            skipped += 1
            continue
        try:
            relative = path.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = path.as_posix()
        name = MACHINE_NAMES.get(machine, f"0x{machine:04x}")
        exempt = None
        for pattern, reason in allowed.items():
            if fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern):
                exempt = reason
                used_patterns.add(pattern)
                break
        rows.append((relative, machine, name, path.stat().st_size, exempt))
        if machine == expected:
            continue
        if exempt is not None:
            exemptions.append((relative, name, exempt))
        else:
            violations.append((relative, name))

    for relative, machine, name, size, exempt in sorted(rows):
        note = f"  [allowed: {exempt}]" if exempt and machine != expected else ""
        print(f"  {name:6} 0x{machine:04x} {size:>12}  {relative}{note}")

    print()
    print(f"  PE images audited:     {len(rows)}")
    print(f"  non-PE files skipped:  {skipped}")
    print(f"  expected architecture: {expect} (0x{expected:04x})")
    print(f"  exemptions applied:    {len(exemptions)}")
    for relative, name, reason in exemptions:
        print(f"    {relative}: {name} - {reason}")
    unused = sorted(set(allowed) - used_patterns)
    if unused:
        print(f"  exceptions not needed: {', '.join(unused)}")
        print("    (declared but nothing needed them; consider removing them)")

    missing = []
    for relative in required:
        candidate = (root / relative).resolve()
        if not candidate.is_file():
            missing.append(f"{relative}: missing")
            continue
        machine = pe_machine(candidate)
        if machine is None:
            missing.append(f"{relative}: not a Windows executable")
        elif machine != expected:
            missing.append(
                f"{relative}: {MACHINE_NAMES.get(machine, hex(machine))}, expected {expect}"
            )
    if missing:
        fail("required package contents are wrong", missing)

    if violations:
        fail(
            f"{len(violations)} PE image(s) are not {expect}",
            [f"{relative}: {name}" for relative, name in violations]
            + ["the Windows client ships x64 only; x86 and ARM64 must not be mixed in"],
        )

    print()
    if exemptions:
        print(
            f"PASS: every audited PE image is {expect}, except "
            f"{len(exemptions)} declared exception(s) listed above"
        )
    else:
        print(f"PASS: every audited PE image in this package is {expect}")

    if arguments.record:
        lines = [
            "windows package architecture audit",
            f"profile                {arguments.profile or '(none)'}",
            f"expected               {expect} (0x{expected:04x})",
            f"pe images audited      {len(rows)}",
            f"non-pe files skipped   {skipped}",
            f"exemptions             {len(exemptions)}",
            "",
        ]
        lines += [
            f"{name:6} 0x{machine:04x} {size:>12}  {relative}"
            + (f"  [allowed: {exempt}]" if exempt and machine != expected else "")
            for relative, machine, name, size, exempt in sorted(rows)
        ]
        record_path = pathlib.Path(arguments.record)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record_path.write_text("\n".join(lines) + "\n")
        print(f"  record written to {arguments.record}")


if __name__ == "__main__":
    main()
