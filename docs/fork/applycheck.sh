#!/usr/bin/env bash
# Read-only presence probe: for every upstream-only commit, test per-file
#   git apply -R --check  -> fork tip already contains the post-image (present)
#   git apply     --check -> fork tip still contains the pre-image (absent)
# Output: TSV  sha<TAB>file<TAB>verdict
# verdict: PRESENT | ABSENT | UNCLEAR(both/neither)
set -u
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
BASE=origin/testing
UP=upstream/testing
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for c in $(git rev-list --reverse "$BASE".."$UP"); do
  files=$(git show --format= --name-only "$c")
  for f in $files; do
    git show --format= "$c" -- "$f" > "$TMP/p.patch" 2>/dev/null
    [ -s "$TMP/p.patch" ] || continue
    rev=no; fwd=no
    git apply -R --check --whitespace=nowarn "$TMP/p.patch" 2>/dev/null && rev=yes
    git apply    --check --whitespace=nowarn "$TMP/p.patch" 2>/dev/null && fwd=yes
    if [ "$rev" = yes ] && [ "$fwd" = no ]; then v=PRESENT
    elif [ "$rev" = no ] && [ "$fwd" = yes ]; then v=ABSENT
    elif [ "$rev" = yes ] && [ "$fwd" = yes ]; then v="UNCLEAR-both"
    else v="UNCLEAR-neither"; fi
    printf '%s\t%s\t%s\n' "$c" "$f" "$v"
  done
done
