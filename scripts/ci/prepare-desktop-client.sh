#!/usr/bin/env bash
# Prepares the desktop (Electron) client checkout for an UNSIGNED Windows x64 build.
#
# Usage: prepare-desktop-client.sh [--brand]
#
# Environment:
#   DESKTOP_CLIENT_DIR   the desktop checkout to prepare (default: clients/desktop)
#
# # Why this is an overlay rather than a commit in the client
#
# clients/desktop is a submodule pinned to upstream SagerNet/sing-box-for-desktop. Branding
# cannot be committed into a pinned upstream checkout - doing so would either need a fork of
# that repository or an unpinned working tree, and either one breaks the property that the
# client source is exactly the revision the parent records.
#
# So this follows the same shape as prepare-apple-client.sh: the parent records the revision,
# and the parent owns the overlay. Re-running it is safe, and it fails closed rather than
# leaving a half-branded client behind.
#
# # What it deliberately does NOT touch
#
#   sing-box-daemon.exe   the daemon keeps its name; it is an internal component
#   appId                 io.nekohasekai.sfw / .sfl are install identity, not branding
#   IPC / service ids     internal identifiers
#   driver, WinDivert     driver names
#   config schema         user configuration compatibility
#
# The rule is the one the brief states: the user sees Jiejiebox, and the internals keep the
# names they already have. There is no global string replacement here.
set -euo pipefail

brand="${1:-}"
case "$brand" in
  ""|--brand) ;;
  *) echo "usage: prepare-desktop-client.sh [--brand]" >&2; exit 2 ;;
esac

client_dir="${DESKTOP_CLIENT_DIR:-clients/desktop}"
[ -d "$client_dir" ] || { echo "FAIL: $client_dir is missing" >&2; exit 1; }

builder="$client_dir/electron-builder.yml"
pkg="$client_dir/package.json"
for f in "$builder" "$pkg"; do
  [ -f "$f" ] || { echo "FAIL: $f is missing; is $client_dir a desktop checkout?" >&2; exit 1; }
done

# The overlay is expressed as replacements that must APPLY, and that are idempotent: after the
# first run the file already holds the target value, and a second run is a no-op rather than a
# double-application.
apply_once() {
  local file="$1" from="$2" to="$3" label="$4"
  if grep -qF -- "$to" "$file"; then
    echo "  already applied: $label"
    return 0
  fi
  if ! grep -qF -- "$from" "$file"; then
    # Neither the original nor the target is present. The client has changed shape underneath
    # us, and guessing would produce a build that is branded in a way nobody verified.
    echo "FAIL: $label: expected to find '$from' in $file" >&2
    exit 1
  fi
  # A literal, whole-line replacement. Not a global substitution: only the exact line named
  # here changes, so an unrelated occurrence of the same text is not collateral.
  python3 - "$file" "$from" "$to" <<'PY'
import sys, pathlib
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
lines = p.read_text().splitlines(keepends=True)
changed = 0
old = old.strip()
for i, line in enumerate(lines):
    if line.strip() == old:
        indent = line[:len(line) - len(line.lstrip())]
        lines[i] = f"{indent}{new}\n"
        changed += 1
if changed != 1:
    sys.stderr.write(f"FAIL: expected exactly one line '{old}' in {path}, found {changed}\n")
    raise SystemExit(1)
p.write_text("".join(lines))
PY
  echo "  applied: $label"
}

echo "== desktop overlay: $client_dir =="

# --- branding ---------------------------------------------------------------
# productName is the user-visible product name: window title, Start Menu entry, installer
# display name and the default artifact name all derive from it. This is the single highest
# value branding change and the only one that is not UI source.
apply_once "$builder" "productName: sing-box" "productName: Jiejiebox" "productName -> Jiejiebox"

# --- unsigned mode ----------------------------------------------------------
# Upstream requires a certificate. A development and an unsigned release build must be able to
# complete WITHOUT one, and a signed build must still be possible when a certificate is
# configured - so this turns the hard requirement off rather than removing signing support.
# electron-builder still signs automatically when it is given a certificate.
apply_once "$builder" "  forceCodeSigning: true" "  forceCodeSigning: false" "allow unsigned build"

echo "PASS: desktop client prepared"
