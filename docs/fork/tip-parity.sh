#!/usr/bin/env bash
# Read-only tip-parity probe: is the fork tip's copy of a path byte-identical to upstream tip's?
#
# This is the third and strongest of the three probes, and it exists because the other two can
# both report a gap that is not one:
#   * `git apply -R --check` fails as soon as any neighbouring line differs;
#   * the line-level probe compares a commit's OWN added lines against the fork tip, so a line a
#     LATER upstream commit deleted shows up as "missing" even when the fork matches upstream's
#     final state exactly.
# A path that is identical at both tips cannot be missing anything from any commit that touched it.
#
# Usage: tip-parity.sh <path>...    (paths are read from stdin when no argument is given)
# Output TSV: path<TAB>IDENTICAL|DIFFERENT|ONLY_UPSTREAM|ONLY_FORK
set -u
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
FORK=origin/testing
UP=upstream/testing
paths=("$@")
if [ "${#paths[@]}" -eq 0 ]; then
	# bash 3.2 (macOS) has no mapfile; read the paths one per line.
	while IFS= read -r line; do
		paths+=("$line")
	done
fi
for p in "${paths[@]}"; do
	[ -n "$p" ] || continue
	in_fork=no; in_up=no
	git cat-file -e "$FORK:$p" 2>/dev/null && in_fork=yes
	git cat-file -e "$UP:$p" 2>/dev/null && in_up=yes
	if [ "$in_fork" = no ] && [ "$in_up" = no ]; then
		printf '%s\tNEITHER\n' "$p"
	elif [ "$in_fork" = no ]; then
		printf '%s\tONLY_UPSTREAM\n' "$p"
	elif [ "$in_up" = no ]; then
		printf '%s\tONLY_FORK\n' "$p"
	elif git diff --quiet "$FORK" "$UP" -- "$p"; then
		printf '%s\tIDENTICAL\n' "$p"
	else
		printf '%s\tDIFFERENT\n' "$p"
	fi
done
