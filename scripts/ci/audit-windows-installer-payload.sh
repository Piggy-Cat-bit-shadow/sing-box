#!/usr/bin/env bash
# Extracts a built Windows installer and audits what it ACTUALLY contains.
#
# Usage: audit-windows-installer-payload.sh <installer.exe> <workdir>
#
# Environment:
#   SEVEN_ZIP   the 7-Zip executable to use (default: 7z, 7za or 7zz, whichever is found)
#   PYTHON      the Python interpreter to use (default: python3, then python)
#
# # Why this is separate from the package audit
#
# The workflow audits release/win-unpacked - the tree electron-builder produced before it
# built the installer. That is the right input to check, but it is not what a user
# receives: the installer packs that tree into an NSIS container, and the brief's
# requirement is that everything inside the PACKAGE is x64. Extracting the installer and
# auditing the extracted application closes the gap between "what was packed" and "what
# the installer carries", which is the thing that will be installed.
#
# electron-builder's NSIS installer holds the application as a nested app-<arch>.7z, so
# this is two extractions. Both are done with the runner's own 7-Zip rather than a
# bundled one, so what is audited is not produced by the tool being tested.
#
# Fail closed: a missing extractor, an installer with no app archive in it, or an app
# archive that extracts to nothing is a failure, not a skip. An audit that quietly
# examines an empty directory would pass and mean nothing.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

installer="${1:?usage: audit-windows-installer-payload.sh <installer.exe> <workdir>}"
workdir="${2:?usage: audit-windows-installer-payload.sh <installer.exe> <workdir>}"

[ -f "$installer" ] || { echo "FAIL: $installer does not exist" >&2; exit 1; }

seven_zip="${SEVEN_ZIP:-}"
if [ -z "$seven_zip" ]; then
  for candidate in 7z 7za 7zz; do
    if command -v "$candidate" >/dev/null 2>&1; then
      seven_zip="$candidate"
      break
    fi
  done
fi
[ -n "$seven_zip" ] || {
  echo "FAIL: 7-Zip is required to extract the installer payload (set SEVEN_ZIP)" >&2
  exit 1
}

python_bin="${PYTHON:-}"
if [ -z "$python_bin" ]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      python_bin="$candidate"
      break
    fi
  done
fi
[ -n "$python_bin" ] || { echo "FAIL: python3 is required" >&2; exit 1; }

nsis_dir="$workdir/nsis"
app_dir="$workdir/app"
rm -rf "$workdir"
mkdir -p "$nsis_dir" "$app_dir"

echo "== extracting the installer container =="
"$seven_zip" x -y "-o$nsis_dir" "$installer" >/dev/null || {
  echo "FAIL: could not extract $installer" >&2; exit 1; }

# electron-builder names it app-<arch>.7z (app-64.7z for x64); matched by pattern rather
# than by an exact name so a naming change is a loud failure rather than a false pass.
archive=""
while IFS= read -r candidate; do
  archive="$candidate"
  break
done < <(find "$nsis_dir" -name 'app-*.7z' -type f | sort)
[ -n "$archive" ] || {
  echo "FAIL: the installer contains no app-*.7z payload" >&2
  echo "      contents: $(find "$nsis_dir" -maxdepth 1 | sort | tr '\n' ' ')" >&2
  exit 1
}
echo "  payload archive: ${archive#"$workdir"/}"

echo "== extracting the application =="
"$seven_zip" x -y "-o$app_dir" "$archive" >/dev/null || {
  echo "FAIL: could not extract $archive" >&2; exit 1; }

file_count="$(find "$app_dir" -type f | wc -l | tr -d ' ')"
echo "  extracted files: $file_count"
[ "$file_count" -gt 0 ] || { echo "FAIL: the payload archive extracted to nothing" >&2; exit 1; }

echo "== auditing the payload the installer carries =="
# The same policy the workflow applies to the tree electron-builder produced: every PE
# image must be amd64, and the only non-amd64 images that may appear are the ones named
# here with a reason. Both are electron-builder's own, and neither is x64 payload:
#
#   resources/elevate.exe   electron-builder's NSIS UAC elevation helper, which
#                           electron-builder packs into the application by default. It is
#                           a legitimate 32-bit helper and it runs as such on 64-bit
#                           Windows. The client does not use it (src/main/repair.ts
#                           elevates with PowerShell's "runas" verb), but it is
#                           electron-builder's file rather than this fork's.
#
# The paths are exact. There is no wildcard for elevate.exe, no resources/*.exe, and no
# rule that would admit any other i386 image: anything not named here still fails.
# The installed application executable is sing-box.exe, not Jiejiebox.exe: that is the
# name experimental/boxdd resolves and Authenticode-verifies when it registers the service
# and on every peer handshake, so it is the name the payload must contain. productName is
# still Jiejiebox and is what the user reads.
"$python_bin" "$root/scripts/ci/audit-windows-pe-architecture.py" "$app_dir" \
  --root "$app_dir" \
  --expect amd64 \
  --allow "resources/elevate.exe=i386 electron-builder NSIS UAC elevation helper" \
  --require "sing-box.exe" \
  --require "resources/daemon/sing-box-daemon.exe" \
  --require "resources/daemon/libcronet.dll" \
  --require "resources/daemon/WinDivert64.sys" \
  --require "resources/daemon/VBoxUSB.sys" \
  --require "resources/daemon/VBoxUSBMon.sys" \
  --require "resources/daemon/usbip2_ude.sys" \
  --require "resources/daemon/usbip2_filter.sys" \
  --require "resources/native/windows_share.node" \
  --record "$workdir/installer-payload-audit.txt"

echo "PASS: the installer's own payload is entirely x64"
