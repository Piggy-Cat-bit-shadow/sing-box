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
#   localStorage keys     renaming them would silently discard a user's theme and accent
#   attribution           SagerNet authorship, the licence and the fork lineage
#
# The rule is the one the brief states: the user sees Jiejiebox, and the internals keep the
# names they already have. There is no global string replacement here.
#
# # Why the rules live in a Python file
#
# The edit set is exact, counted, multi-line, and has to be planned before anything is
# written so that a partial overlay is impossible. Expressing that in shell heredocs is
# what broke an earlier attempt at this overlay, so it lives next to the other
# apply-*-overlay.py scripts instead.
set -euo pipefail

brand="${1:-}"
case "$brand" in
  ""|--brand) ;;
  *) echo "usage: prepare-desktop-client.sh [--brand]" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
client_dir="${DESKTOP_CLIENT_DIR:-clients/desktop}"
[ -d "$client_dir" ] || { echo "FAIL: $client_dir is missing" >&2; exit 1; }

builder="$client_dir/electron-builder.yml"
pkg="$client_dir/package.json"
for f in "$builder" "$pkg"; do
  [ -f "$f" ] || { echo "FAIL: $f is missing; is $client_dir a desktop checkout?" >&2; exit 1; }
done

overlay="$root/scripts/ci/apply-desktop-branding-overlay.py"
[ -f "$overlay" ] || { echo "FAIL: $overlay is missing" >&2; exit 1; }

echo "== desktop overlay: $client_dir =="

# Every rule is resolved before the first byte is written, and every rule is re-read
# afterwards. A rule that cannot find its anchor - because the pinned client changed shape -
# aborts the whole overlay instead of leaving a client branded in some places and not others.
python3 "$overlay" "$client_dir"

echo "PASS: desktop client prepared"
