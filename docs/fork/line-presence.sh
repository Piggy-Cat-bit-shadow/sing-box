#!/usr/bin/env bash
# Read-only line-level presence probe, resolving the "UNCLEAR" rows of applycheck.sh.
#
# For every upstream-only commit and every file it touches:
#   added   = '+' lines of the upstream diff (excluding the +++ header), trimmed, non-empty
#   removed = '-' lines of the upstream diff, trimmed, non-empty
#   *Present = how many of those lines appear verbatim in the fork tip's copy of the file
#
# A post-image whose added lines are all present in the fork tip is substantively applied even
# when `git apply -R --check` fails, which happens as soon as the fork edited a neighbouring line.
#
# Output TSV: sha<TAB>file<TAB>added_total<TAB>added_present<TAB>removed_total<TAB>removed_present
set -u
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
BASE=origin/testing
UP=upstream/testing
CACHE=$(mktemp -d)
trap 'rm -rf "$CACHE"' EXIT

fork_file() { # $1 = path -> cached copy, empty file when the path does not exist at the tip
	local key
	key="$CACHE/$(printf '%s' "$1" | tr '/' '_')"
	if [ ! -f "$key" ]; then
		# The cached copy is whitespace-stripped at both ends so the comparison is
		# indentation-insensitive: gofmt re-indents, the probe must not care.
		git show "$BASE:$1" 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' >"$key" || : >"$key"
	fi
	printf '%s' "$key"
}

for c in $(git rev-list --reverse "$BASE".."$UP"); do
	git show --format= "$c" >"$CACHE/commit.diff"
	awk -v sha="$c" '
		/^diff --git /{ f=$3; sub(/^a\//,"",f); next }
		/^\+\+\+ |^--- /{ next }
		/^\+/{ l=substr($0,2); gsub(/^[[:space:]]+/,"",l); gsub(/[[:space:]]+$/,"",l); if (l!="") print sha"\t"f"\tA\t"l; next }
		/^-/{ l=substr($0,2); gsub(/^[[:space:]]+/,"",l); gsub(/[[:space:]]+$/,"",l); if (l!="") print sha"\t"f"\tR\t"l; next }
	' "$CACHE/commit.diff" >"$CACHE/lines.tsv"
	cut -f2 "$CACHE/lines.tsv" | sort -u | while read -r f; do
		[ -n "$f" ] || continue
		src=$(fork_file "$f")
		at=0; ap=0; rt=0; rp=0
		while IFS=$'\t' read -r _ _ kind line; do
			if grep -Fxq -- "$line" "$src" 2>/dev/null; then
				[ "$kind" = A ] && ap=$((ap + 1)) || rp=$((rp + 1))
			fi
			[ "$kind" = A ] && at=$((at + 1)) || rt=$((rt + 1))
		done < <(awk -F'\t' -v f="$f" '$2==f' "$CACHE/lines.tsv")
		printf '%s\t%s\t%d\t%d\t%d\t%d\n' "$c" "$f" "$at" "$ap" "$rt" "$rp"
	done
done
