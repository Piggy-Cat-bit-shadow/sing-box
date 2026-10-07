#!/usr/bin/env python3
"""Proves which core the Windows daemon that ships in the installer was built from.

Usage:
    verify-desktop-daemon-provenance.py <daemon.exe> [options]

    --core-dir DIR          the core checkout the daemon was built in (default: .)
    --expect-core-sha SHA   the core commit the daemon must come from
    --expect-version V      the version the daemon must report
    --require-execution     fail instead of skipping when the daemon cannot be run
    --record PATH           also write the provenance record to PATH

# Why this exists

The desktop client does not download an upstream daemon; scripts/package.ts builds one
from the core checkout it finds next to it, so the daemon's provenance is a property of
WHERE the build happened, not of the artifact alone. Nothing in the build asserts that
the checkout was the intended commit, and a daemon built from the wrong commit produces
an installer that looks completely normal.

Three independent things are checked, because each can be right while another is wrong:

  1. the core checkout's git state   cmd/internal/build_boxdd derives the version stamp
                                     from `git describe --tags` in that checkout. A
                                     checkout that is not exactly on v0.1.5 produces
                                     "0.1.5-<commit>" or, if another tag is nearer,
                                     something else entirely - so the git state is the
                                     thing the stamp depends on and is checked first.
  2. the artifact's build metadata   `go version -m` reads the embedded Go build info
                                     without running the binary, and reports GOOS,
                                     GOARCH and the exact build tags.
  3. the daemon's own report          `sing-box-daemon version` prints the stamped
                                     constant.Version. This is the only check that reads
                                     the value the code will actually use at runtime, and
                                     it is the reason this script is run on Windows: the
                                     binary cannot be executed anywhere else.

A static scan for the version bytes was considered and rejected. The daemon contains
eleven occurrences of "0.1.5" as a substring and one of "0.1.15" from a dependency, and
Go's string table offers no delimiter to tell the stamped constant apart from any of
them, so such a scan would be a check that cannot fail.
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys

# The tags the Windows daemon must carry. Required explicitly rather than diffed against
# release/DEFAULT_BUILD_TAGS_WINDOWS, so that a tag being dropped from that file is
# caught instead of silently accepted.
REQUIRED_TAGS = [
    "with_quic",
    "with_naive_outbound",
    "with_utls",
    "with_clash_api",
    "with_external_windivert",
]

MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "amd64",
    0x01C0: "arm",
    0x01C4: "armnt",
    0xAA64: "arm64",
}


def fail(message, details=None):
    print(f"verify-desktop-daemon-provenance: {message}", file=sys.stderr)
    for detail in details or []:
        print(f"    - {detail}", file=sys.stderr)
    raise SystemExit(1)


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        fail(
            f"{' '.join(str(part) for part in command)} exited {result.returncode}",
            [(result.stderr or result.stdout).strip()],
        )
    return result.stdout


def pe_machine(path):
    """The COFF machine field, or None when the file is not a PE image."""
    data = path.read_bytes()[:4096]
    if len(data) < 64 or data[0:2] != b"MZ":
        return None
    header = int.from_bytes(data[0x3C:0x40], "little")
    if header + 6 > len(data) or data[header:header + 4] != b"PE\x00\x00":
        return None
    return int.from_bytes(data[header + 4:header + 6], "little")


def build_settings(binary):
    """`go version -m` as a dict of build setting -> value, plus the main module path.

    The output is tab-separated and every line starts with a tab, so each line is
    stripped before splitting - splitting the raw line would put an empty field first and
    silently match nothing.
    """
    output = run(["go", "version", "-m", str(binary)])
    settings = {}
    main_path = None
    for line in output.splitlines():
        fields = line.strip().split("\t")
        if not fields or not fields[0]:
            continue
        if fields[0] == "path" and len(fields) >= 2:
            main_path = fields[1]
        elif fields[0] == "build" and len(fields) >= 2:
            key, separator, value = fields[1].partition("=")
            settings[key] = value if separator else ""
    return main_path, settings


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("daemon")
    parser.add_argument("--core-dir", default=".")
    parser.add_argument("--expect-core-sha", required=True)
    parser.add_argument("--expect-version", required=True)
    parser.add_argument("--require-execution", action="store_true")
    parser.add_argument("--record")
    arguments = parser.parse_args()

    daemon = pathlib.Path(arguments.daemon).resolve()
    core = pathlib.Path(arguments.core_dir).resolve()
    if not daemon.is_file():
        fail(f"{daemon} does not exist")
    if not (core / ".git").exists():
        fail(f"{core} is not a git checkout, so the daemon's source cannot be attributed")

    record = []

    # --- 1. the core checkout the daemon was built in ------------------------
    head = run(["git", "-C", str(core), "rev-parse", "HEAD"]).strip()
    if head != arguments.expect_core_sha:
        fail(
            f"the daemon was built in a core checkout at {head}, not {arguments.expect_core_sha}",
            ["a daemon built from another commit is not the v0.1.5 daemon"],
        )
    described = run(["git", "-C", str(core), "describe", "--tags"]).strip()
    expected_tag = f"v{arguments.expect_version}"
    if described != expected_tag:
        fail(
            f"`git describe --tags` in {core} reports {described!r}, not {expected_tag!r}",
            [
                "cmd/internal/build_boxdd stamps constant.Version from this value, so the",
                "daemon would not report the release version even though the source is right",
            ],
        )
    record.append(f"core commit            {head}")
    record.append(f"core describe          {described}")

    # --- 2. the artifact ------------------------------------------------------
    machine = pe_machine(daemon)
    if machine is None:
        fail(f"{daemon.name} is not a Windows executable")
    if machine != 0x8664:
        fail(
            f"{daemon.name} has PE machine 0x{machine:04x} "
            f"({MACHINE_NAMES.get(machine, 'unknown')}), expected amd64"
        )
    record.append(f"pe machine             0x{machine:04x} (amd64)")
    record.append(f"size                   {daemon.stat().st_size} bytes")

    main_path, settings = build_settings(daemon)
    if main_path is None or not main_path.endswith("/experimental/boxdd"):
        fail(f"{daemon.name} was not built from experimental/boxdd (path {main_path!r})")
    if settings.get("GOOS") != "windows":
        fail(f"{daemon.name} reports GOOS={settings.get('GOOS')!r}, expected 'windows'")
    if settings.get("GOARCH") != "amd64":
        fail(f"{daemon.name} reports GOARCH={settings.get('GOARCH')!r}, expected 'amd64'")
    tags = set((settings.get("-tags") or "").split(","))
    missing = [tag for tag in REQUIRED_TAGS if tag not in tags]
    if missing:
        fail(
            f"{daemon.name} is missing required build tags: {', '.join(missing)}",
            ["the daemon would not link the code those tags enable"],
        )
    record.append(f"go path                {main_path}")
    record.append(f"GOOS/GOARCH            {settings.get('GOOS')}/{settings.get('GOARCH')}")
    record.append(f"build tags ({len(tags)})       {','.join(sorted(tags))}")
    record.append(f"required tags          all {len(REQUIRED_TAGS)} present")

    # --- 3. what the daemon says about itself --------------------------------
    if os.name == "nt":
        output = run([str(daemon), "version"])
        match = re.search(r"sing-box-daemon version (\S+)", output)
        reported = match.group(1) if match else None
        if reported != arguments.expect_version:
            fail(
                f"{daemon.name} reports version {reported!r}, "
                f"expected {arguments.expect_version!r}",
                [output.strip()],
            )
        for line in output.strip().splitlines():
            record.append(f"daemon reports         {line.strip()}")
    elif arguments.require_execution:
        fail(
            "the daemon's own version cannot be read on this platform "
            f"({sys.platform}), and --require-execution was given"
        )
    else:
        record.append(
            "daemon reports         SKIPPED (not Windows; the CI run performs this check)"
        )

    print(f"PASS: {daemon.name} is the {arguments.expect_version} core daemon")
    for line in record:
        print(f"  {line}")

    if arguments.record:
        pathlib.Path(arguments.record).write_text(
            "desktop daemon provenance\n"
            + "".join(f"{line}\n" for line in record)
            + f"verified by    scripts/ci/verify-desktop-daemon-provenance.py\n"
        )
        print(f"  record written to {arguments.record}")


if __name__ == "__main__":
    main()
