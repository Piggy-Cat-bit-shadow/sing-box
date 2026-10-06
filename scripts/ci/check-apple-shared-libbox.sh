#!/usr/bin/env bash
# Proves that two Apple client checkouts link the SAME Libbox framework.
#
# Usage: check-apple-shared-libbox.sh <client-dir-a> <client-dir-b>
#
# # Why this is a check and not an assumption
#
# The two Apple products take their Swift source from two branches of one Apple
# repository, but they must ship ONE core: Libbox is compiled once from this repository
# at the parent commit and installed into both checkouts. "Installed into both" is the
# step where that can quietly stop being true - a stale slice left in one tree, an
# install that silently did nothing, or a second build that ran when it should not have.
#
# Comparing the two trees makes the invariant observable. A digest rather than a
# version string, because two frameworks can both claim the same commit and still differ.
#
# The digest covers file contents AND symlink targets: an xcframework's versioned bundle
# layout is held together by symlinks, so a tree that agrees on bytes but not on links is
# not the same framework.
set -euo pipefail

a="${1:?usage: check-apple-shared-libbox.sh <client-dir-a> <client-dir-b>}"
b="${2:?usage: check-apple-shared-libbox.sh <client-dir-a> <client-dir-b>}"

fail() { echo "check-apple-shared-libbox: $*" >&2; exit 1; }

for dir in "$a" "$b"; do
  [ -d "$dir/Libbox.xcframework" ] || fail \
    "$dir/Libbox.xcframework is missing.
  Both Apple clients must have the framework installed before they are built."
done

# digest prints one deterministic digest for an xcframework tree.
digest() {
  python3 - "$1/Libbox.xcframework" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
entries = []
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    dirnames.sort()
    for name in sorted(filenames) + sorted(dirnames):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        if os.path.islink(path):
            entries.append(f"L {rel} -> {os.readlink(path)}")
        elif os.path.isfile(path):
            with open(path, "rb") as handle:
                entries.append(f"F {rel} {hashlib.sha256(handle.read()).hexdigest()}")
        elif os.path.isdir(path):
            entries.append(f"D {rel}")

# Sorted so the digest does not depend on the order the filesystem hands entries back.
entries.sort()
blob = "\n".join(entries).encode("utf-8")
print(hashlib.sha256(blob).hexdigest())
PY
}

da="$(digest "$a")"
db="$(digest "$b")"

echo "  $a: $da"
echo "  $b: $db"

if [ "$da" != "$db" ]; then
  fail "the two Apple clients do not link the same Libbox.
  $a and $b hold different frameworks, so the iOS and macOS products would ship
  different cores from one release. Re-install the verified Libbox artifact into both."
fi

echo "PASS: both Apple clients link the identical Libbox ($da)"
