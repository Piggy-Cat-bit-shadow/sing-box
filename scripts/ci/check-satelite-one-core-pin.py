#!/usr/bin/env python3
"""Assert that satelite-one's release pin, its libbox.aar and its APK name one core.

satelite-one is the shipping Android app. Its release workflow resolves
`coreCommit` out of `version.properties`, fetches that exact commit, builds
`libbox.aar` from it, and packages the AAR into the APK. Four separate places
therefore carry the same fact, and each of them can drift on its own:

  1. `version.properties`  — what the release workflow will fetch and build.
  2. `libbox.provenance`   — what the core builder recorded when it produced the AAR.
  3. the packaged `libbox.so` — what is actually inside the binary.
  4. the packaged APK      — what the shipped product tells the user it contains.

The app already has its own gates for (2)/(3) against BuildConfig
(`verifyCoreProvenance` in `app/build.gradle.kts`,
`.github/scripts/check_core_provenance.py`). This script exists for the step
those two cannot cover: proving that the revision the *workflow will fetch* is
the revision the AAR and the APK under review actually contain. That is the
cross-artifact question a release reviewer asks, and until now it was answered
by reading three files by eye.

Why not just trust `version.properties`: the pin is a promise about a future
fetch. A pin that points at a revision which is not on the remote makes the
release job fail at its "Verify pinned core revision is fetchable" step, and a
pin that points at the wrong revision produces a green build of the wrong core.
Both are checked here.

Usage:
    check-satelite-one-core-pin.py --app-dir <satelite-one checkout> \
                                   --expected-core-sha <40 hex chars> \
                                   [--aar <libbox.aar>] [--apk <app.apk>] \
                                   [--remote <git url>]

Exit status is 0 only when every requested check passes. Checks whose inputs
were not supplied are reported as SKIP on stdout and do not affect the status,
so the script is useful at whatever stage of a build the artifacts exist.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
import zipfile

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The architecture satelite-one ships. The release build produces per-ABI APKs
# (arm64-v8a is the shipping target, x86_64 exists for the emulator), so an APK
# that does not carry arm64-v8a is not the shipping product regardless of what
# revision it advertises.
SHIPPING_ABI = "arm64-v8a"


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def check(label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {label}{('  — ' + detail) if detail else ''}")
    return ok


def skip(label, why):
    print(f"SKIP  {label}  — {why}")
    return True


def read_properties(path):
    """Parse a java.util.Properties-style key=value file, ignoring comments."""
    fields = {}
    if not os.path.isfile(path):
        return fields
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
    return fields


def zip_entry_contains(path, needle, suffix=None):
    """True when any (matching) entry of `path` contains the literal bytes `needle`.

    Streamed in 1 MiB chunks because the shared objects are tens of megabytes and
    an APK holds several of them; the tail of each chunk is carried into the next
    so a needle split across a chunk boundary is still found.
    """
    needle = needle.encode("utf-8")
    if not needle:
        return False
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if suffix is None or n.endswith(suffix)]
        for name in names:
            with archive.open(name) as handle:
                overlap = b""
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    hay = overlap + chunk
                    if needle in hay:
                        return True
                    overlap = hay[-(len(needle) - 1):] if len(needle) > 1 else b""
    return False


def pinned_core_commit(app_dir):
    props = read_properties(os.path.join(app_dir, "version.properties"))
    return props.get("coreCommit", "")


def check_pin(app_dir, expected):
    """The pin itself: present, well-formed, and equal to the frozen revision.

    The 40-char lowercase requirement is not this script's invention — the
    release workflow rejects anything else before it will resolve the value, so a
    pin that fails here would have failed the release job too.
    """
    value = pinned_core_commit(app_dir)
    if not value:
        return check("version.properties pins a core revision", False,
                     "no coreCommit= entry; a release must pin its core revision")
    if not SHA_RE.match(value):
        return check("version.properties pins a core revision", False,
                     f"coreCommit must be a full 40-char lowercase SHA, got {value!r}")
    if value != expected:
        return check("version.properties pins the frozen core revision", False,
                     f"pinned {value}, frozen revision is {expected}")
    return check("version.properties pins the frozen core revision", True, value)


def check_provenance(aar_path, provenance_path, expected):
    """The producer's own record of what it compiled, next to the AAR it produced."""
    if not os.path.isfile(aar_path):
        return skip("libbox.provenance names the frozen revision", f"{aar_path} absent")
    if not os.path.isfile(provenance_path):
        return check("libbox.provenance names the frozen revision", False,
                     f"{provenance_path} absent next to {aar_path}")
    fields = read_properties(provenance_path)
    commit = fields.get("commit", "")
    version = fields.get("version", "")
    if commit != expected:
        return check("libbox.provenance names the frozen revision", False,
                     f"commit={commit or 'missing'}, frozen revision is {expected}")
    # The app's Gradle gate accepts a version that merely contains the revision
    # (tag-style versions). CI builds set version == commit, so require it here:
    # this check runs on the release path, where they must agree.
    if version != expected:
        return check("libbox.provenance names the frozen revision", False,
                     f"version={version or 'missing'} differs from commit={commit}; "
                     "the release path builds with SING_BOX_BUILD_VERSION=<sha>")
    return check("libbox.provenance names the frozen revision", True,
                 f"commit={commit} version={version}")


def check_aar_binary(aar_path, expected):
    """The revision is really inside the packaged shared object, not just recorded."""
    if not os.path.isfile(aar_path):
        return skip("packaged libbox.so contains the frozen revision", f"{aar_path} absent")
    if not zip_entry_contains(aar_path, expected, suffix="libbox.so"):
        return check("packaged libbox.so contains the frozen revision", False,
                     f"no libbox.so in {aar_path} contains {expected}")
    with zipfile.ZipFile(aar_path) as archive:
        abis = sorted({n.split("/")[1] for n in archive.namelist()
                       if n.endswith("libbox.so") and n.startswith("jni/")})
    return check("packaged libbox.so contains the frozen revision", True,
                 f"ABIs: {', '.join(abis) or 'none'}")


def check_apk(apk_path, expected):
    """The shipped product's own bytes name the frozen revision.

    This is deliberately a byte search of the whole APK rather than a read of
    BuildConfig: the question a reviewer is asking is what the artifact on disk
    says, and a value read out of a build script would answer a different one.
    """
    if not os.path.isfile(apk_path):
        return skip("APK contains the frozen revision", f"{apk_path} absent")
    with zipfile.ZipFile(apk_path) as archive:
        names = archive.namelist()
    shipping = [n for n in names if SHIPPING_ABI in n]
    if not shipping:
        return check(f"APK carries the {SHIPPING_ABI} shipping ABI", False,
                     f"{apk_path} has no {SHIPPING_ABI} entries")
    if not zip_entry_contains(apk_path, expected):
        return check("APK contains the frozen revision", False,
                     f"no entry of {apk_path} contains {expected}")
    return check("APK contains the frozen revision", True,
                 f"{os.path.getsize(apk_path)} B, {SHIPPING_ABI} present")


def check_fetchable(remote, expected):
    """The pinned revision must be on the remote the release workflow fetches from.

    `git ls-remote` lists ref *tips* only, so it can never confirm an ancestor
    commit — fetching the SHA is the actual existence check. This is the same
    step, and the same reasoning, as the release workflow's own gate.
    """
    if not remote:
        return skip("pinned revision is fetchable from the remote", "no --remote given")
    with tempfile.TemporaryDirectory() as work:
        subprocess.run(["git", "init", "-q", work], check=True)
        add = subprocess.run(["git", "-C", work, "remote", "add", "origin", remote],
                             capture_output=True, text=True)
        if add.returncode != 0:
            return check("pinned revision is fetchable from the remote", False,
                         add.stderr.strip())
        fetch = subprocess.run(["git", "-C", work, "fetch", "--depth", "1", "origin", expected],
                               capture_output=True, text=True)
        if fetch.returncode != 0:
            return check("pinned revision is fetchable from the remote", False,
                         f"{remote} does not serve {expected}: "
                         f"{fetch.stderr.strip().splitlines()[-1] if fetch.stderr.strip() else 'fetch failed'}")
        head = subprocess.run(["git", "-C", work, "rev-parse", "FETCH_HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        if head != expected:
            return check("pinned revision is fetchable from the remote", False,
                         f"fetched {head} but pinned {expected}")
    return check("pinned revision is fetchable from the remote", True, f"{remote} serves {expected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app-dir", required=True,
                        help="satelite-one checkout whose version.properties is the pin")
    parser.add_argument("--expected-core-sha", required=True,
                        help="the frozen core revision, 40 lowercase hex chars")
    parser.add_argument("--aar", help="path to the libbox.aar being shipped")
    parser.add_argument("--provenance",
                        help="path to libbox.provenance (default: alongside --aar)")
    parser.add_argument("--apk", help="path to the APK being shipped")
    parser.add_argument("--remote",
                        help="core repository URL the release workflow fetches from; "
                             "enables the fetchability check (needs git transport)")
    args = parser.parse_args()

    if not SHA_RE.match(args.expected_core_sha):
        fail(f"--expected-core-sha must be a full 40-char lowercase SHA, got "
             f"{args.expected_core_sha!r}")
    if not os.path.isdir(args.app_dir):
        fail(f"not a directory: {args.app_dir}")

    results = [check_pin(args.app_dir, args.expected_core_sha)]

    if args.aar:
        provenance = args.provenance or os.path.join(os.path.dirname(args.aar),
                                                     "libbox.provenance")
        results.append(check_provenance(args.aar, provenance, args.expected_core_sha))
        results.append(check_aar_binary(args.aar, args.expected_core_sha))
    else:
        skip("libbox.provenance names the frozen revision", "no --aar given")
        skip("packaged libbox.so contains the frozen revision", "no --aar given")

    results.append(check_apk(args.apk, args.expected_core_sha) if args.apk
                   else skip("APK contains the frozen revision", "no --apk given"))
    results.append(check_fetchable(args.remote, args.expected_core_sha))

    print()
    if all(results):
        print("core pin, AAR and APK all name the frozen revision "
              f"{args.expected_core_sha}")
        return 0
    print("::error::the pinned core revision is not consistent across the artifacts checked")
    return 1


if __name__ == "__main__":
    sys.exit(main())
