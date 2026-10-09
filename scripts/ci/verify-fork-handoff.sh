#!/bin/sh
# verify-fork-handoff.sh - gate the fork handoff on facts that are resolvable from the remote.
#
# This validator exists because a documentation tree can otherwise claim an integration that no
# remote contains. It fails when:
#
#   1. any final_*_sha / integration_final_sha field is null while the handoff claims the
#      integration is complete;
#   2. a recorded coordinate cannot be resolved from the remote - a SHA that exists only as a local
#      object is not evidence, so the check is `git fetch` + `git cat-file -e` + ancestry, never
#      `git rev-parse` alone;
#   3. the Markdown twin and the JSON twin disagree on the phase-A SHA;
#   4. a RELEASE-READY verdict is recorded in docs/fork/v016-final-release-verdict.md while any
#      check above fails, or while the release-candidate manifest is still "not frozen yet".
#
# Exit codes: 0 = every check passed · 1 = at least one check failed · 2 = usage or environment error.
#
# The paths are overridable so the validator itself can be exercised against a deliberately broken
# copy without touching the real documents:
#   HANDOFF_JSON, HANDOFF_MD, VERDICT_MD, RC_MANIFEST, REMOTE, BRANCH
#
# POSIX sh only - no bashisms, no jq, no network tools other than git.

set -eu

FAILURES=0

fail() { printf 'FAIL  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
ok()   { printf 'ok    %s\n' "$1"; }
note() { printf 'note  %s\n' "$1"; }
die()  { printf 'ERROR %s\n' "$1" >&2; exit 2; }

if [ -z "${ROOT:-}" ]; then
	if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
		:
	else
		ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
	fi
fi

HANDOFF_JSON=${HANDOFF_JSON:-$ROOT/docs/fork/upstream-sync-handoff.json}
HANDOFF_MD=${HANDOFF_MD:-$ROOT/docs/fork/upstream-sync-handoff.md}
VERDICT_MD=${VERDICT_MD:-$ROOT/docs/fork/v016-final-release-verdict.md}
RC_MANIFEST=${RC_MANIFEST:-$ROOT/docs/fork/v016-release-candidate-manifest.md}
REMOTE=${REMOTE:-origin}
BRANCH=${BRANCH:-testing}

[ -f "$HANDOFF_JSON" ] || die "handoff JSON not found: $HANDOFF_JSON"
[ -f "$HANDOFF_MD" ] || die "handoff Markdown not found: $HANDOFF_MD"
command -v git >/dev/null 2>&1 || die "git is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required to parse the handoff JSON"

printf 'verify-fork-handoff: %s\n' "$HANDOFF_JSON"
printf 'verify-fork-handoff: remote %s branch %s\n\n' "$REMOTE" "$BRANCH"

# --- JSON flattening -------------------------------------------------------------------------
# Emits "path<TAB>value" for every scalar, so the checks below never depend on JSON formatting.
json_fields() {
	python3 - "$HANDOFF_JSON" <<'PY'
import json, sys
path = sys.argv[1]
try:
    with open(path) as handle:
        document = json.load(handle)
except Exception as error:  # noqa: BLE001 - the caller turns this into a failed check
    sys.stderr.write("json parse error: %s\n" % error)
    sys.exit(3)

def walk(node, prefix):
    if isinstance(node, dict):
        for key, value in node.items():
            walk(value, prefix + "/" + key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            walk(value, prefix + "[" + str(index) + "]")
    elif node is None:
        print("%s\t%s" % (prefix, ""))
    elif isinstance(node, bool):
        print("%s\t%s" % (prefix, "true" if node else "false"))
    elif isinstance(node, (str, int, float)):
        print("%s\t%s" % (prefix, node))

walk(document, "")
PY
}

if ! FIELDS=$(json_fields); then
	die "could not parse $HANDOFF_JSON as JSON"
fi

field() {
	printf '%s\n' "$FIELDS" | awk -F'\t' -v want="$1" '$1 == want { print $2; exit }'
}

is_sha() {
	case "$1" in
		????????????????????????????????????????) ;;
		*) return 1 ;;
	esac
	printf '%s' "$1" | grep -Eq '^[0-9a-f]{40}$'
}

# --- check 1: no null final SHA while integration is claimed complete ------------------------
INTEGRATION_STATUS=$(field /integrated_remote_state/integration_status)
if [ "$INTEGRATION_STATUS" = "complete" ]; then
	NULL_FINALS=$(printf '%s\n' "$FIELDS" | awk -F'\t' '
		{
			n = split($1, parts, "/")
			last = parts[n]
			if (last ~ /^final_.*_sha$/ || last == "integration_final_sha") {
				if ($2 == "") { print $1 }
			}
		}')
	if [ -n "$NULL_FINALS" ]; then
		fail "integration is claimed complete but these fields are null: $(printf '%s' "$NULL_FINALS" | tr '\n' ' ')"
	else
		ok "no final_*_sha / integration_final_sha field is null while integration_status=complete"
	fi
else
	note "integration_status='${INTEGRATION_STATUS:-<absent>}' - the null-final check does not apply, but RELEASE-READY stays forbidden"
fi

# --- check 2: every recorded coordinate must resolve from the remote -------------------------
INTEGRATION_FINAL=$(field /integrated_remote_state/integration_final_sha)
PHASE_A_START=$(field /integrated_remote_state/phase_a_start_sha)
PHASE_B_START=$(field /integrated_remote_state/phase_b_start_sha)
PHASE_B_BRANCH=$(field /integrated_remote_state/phase_b_start_branch)
CANDIDATE=$(field /integrated_remote_state/current_candidate_core_sha)
PHASE_A_START=${PHASE_A_START:-$(field /coordinates/phase_a_base_sha)}

printf '\n-- remote resolvability --\n'
FETCH_ATTEMPTS=0
REMOTE_TIP=""
while [ "$FETCH_ATTEMPTS" -lt 3 ]; do
	FETCH_ATTEMPTS=$((FETCH_ATTEMPTS + 1))
	if git fetch --quiet "$REMOTE" "$BRANCH" 2>/dev/null; then
		REMOTE_TIP=$(git rev-parse FETCH_HEAD)
		break
	fi
	if [ "$FETCH_ATTEMPTS" -lt 3 ]; then
		sleep 2
	fi
done
if [ -n "$REMOTE_TIP" ]; then
	ok "git fetch $REMOTE $BRANCH -> $REMOTE_TIP (attempt $FETCH_ATTEMPTS)"
else
	fail "cannot fetch $REMOTE $BRANCH after $FETCH_ATTEMPTS attempts: the recorded SHAs cannot be verified, so the handoff is BLOCKED, not passed"
fi

verify_remote_sha() {
	# $1 = label, $2 = sha, $3 = ref whose ancestry must contain it
	label=$1
	sha=$2
	ref=$3
	if [ -z "$sha" ]; then
		note "$label is not set yet (allowed only where the handoff says it is pending)"
		return 0
	fi
	if ! is_sha "$sha"; then
		fail "$label is not a full 40-hex SHA: '$sha'"
		return 0
	fi
	if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
		fail "$label $sha is not a commit object present locally"
		return 0
	fi
	if [ -z "$ref" ]; then
		# No remote ref could be resolved. A local object is explicitly NOT evidence.
		fail "$label $sha exists only locally: the remote ref could not be resolved, so remote resolvability is unproven"
		return 0
	fi
	if git merge-base --is-ancestor "$sha" "$ref" 2>/dev/null; then
		ok "$label $sha is reachable from $ref (remote-resolvable, not merely a local object)"
	else
		fail "$label $sha is NOT reachable from $ref: it exists only as a local object, or the branch has moved"
	fi
}

verify_remote_sha "integration_final_sha" "$INTEGRATION_FINAL" "${REMOTE_TIP:-}"
verify_remote_sha "phase_a_start_sha" "$PHASE_A_START" "${REMOTE_TIP:-}"
verify_remote_sha "coordinates.final_phase_a_sha" "$(field /coordinates/final_phase_a_sha)" "${REMOTE_TIP:-}"

if [ -n "$PHASE_B_START" ]; then
	PB_BRANCH=${PHASE_B_BRANCH:-}
	if [ -z "$PB_BRANCH" ]; then
		fail "phase_b_start_sha is set but integrated_remote_state.phase_b_start_branch is missing, so it cannot be resolved remotely"
	elif [ "$PB_BRANCH" = "$BRANCH" ]; then
		verify_remote_sha "phase_b_start_sha" "$PHASE_B_START" "${REMOTE_TIP:-}"
	elif git fetch --quiet "$REMOTE" "$PB_BRANCH" 2>/dev/null; then
		verify_remote_sha "phase_b_start_sha" "$PHASE_B_START" "$(git rev-parse FETCH_HEAD)"
	else
		fail "phase_b_start_sha is set to $PHASE_B_START but branch $PB_BRANCH is not published on $REMOTE, so the coordinate is local-only"
	fi
else
	note "phase_b_start_sha is null - allowed until the reconciliation branch pins it, but it forbids RELEASE-READY"
fi

if [ -n "$CANDIDATE" ]; then
	verify_remote_sha "current_candidate_core_sha" "$CANDIDATE" "${REMOTE_TIP:-}"
else
	note "current_candidate_core_sha is null - no release candidate is frozen"
fi

# --- check 3: the twins must agree -----------------------------------------------------------
printf '\n-- markdown/JSON twin agreement --\n'
md_line() { sed -n "s/^$1=\(.*\)\$/\1/p" "$HANDOFF_MD" | head -1; }

MD_INTEGRATION=$(md_line INTEGRATION_FINAL_SHA)
MD_PHASE_A_START=$(md_line PHASE_A_START)
MD_PHASE_B_START=$(md_line PHASE_B_START)

if [ "$MD_INTEGRATION" = "$INTEGRATION_FINAL" ]; then
	ok "phase-A integrated SHA agrees between the twins ($INTEGRATION_FINAL)"
else
	fail "twin disagreement on the phase-A integrated SHA: JSON='$INTEGRATION_FINAL' Markdown='$MD_INTEGRATION'"
fi

if [ "$MD_PHASE_A_START" = "$PHASE_A_START" ]; then
	ok "PHASE_A_START agrees between the twins ($PHASE_A_START)"
else
	fail "twin disagreement on PHASE_A_START: JSON='$PHASE_A_START' Markdown='$MD_PHASE_A_START'"
fi

if [ -n "$INTEGRATION_FINAL" ] && grep -q -- "$INTEGRATION_FINAL" "$HANDOFF_MD"; then
	ok "the full integrated SHA appears verbatim in the Markdown twin"
else
	fail "the full integrated SHA does not appear verbatim in $HANDOFF_MD"
fi

if [ -n "$PHASE_B_START" ] && is_sha "$PHASE_B_START" && [ "$MD_PHASE_B_START" != "$PHASE_B_START" ]; then
	fail "twin disagreement on PHASE_B_START: JSON='$PHASE_B_START' Markdown='$MD_PHASE_B_START'"
elif [ -n "$PHASE_B_START" ]; then
	ok "PHASE_B_START agrees between the twins ($PHASE_B_START)"
fi

# --- check 4: the RELEASE-READY gate ---------------------------------------------------------
# The verdict is read from a line-anchored machine-readable marker, never from prose: a document
# that merely *explains* the rule must not trip it (the first version of this validator did).
printf '\n-- release-verdict gate --\n'
VERDICT_MARKER=""
if [ ! -f "$VERDICT_MD" ]; then
	fail "verdict document is missing: $VERDICT_MD (the gate has nothing to read)"
else
	VERDICT_MARKER=$(sed -n 's/^<!-- release-verdict: \([A-Za-z-]*\) -->$/\1/p' "$VERDICT_MD" | head -1)
	case "$VERDICT_MARKER" in
		RELEASE-READY)
			if [ "$FAILURES" -ne 0 ]; then
				fail "RELEASE-READY is claimed in $(basename "$VERDICT_MD") while $FAILURES check(s) above fail"
			else
				ok "every check above passed, so a RELEASE-READY claim is permitted"
			fi
			if [ ! -f "$RC_MANIFEST" ]; then
				fail "RELEASE-READY is claimed while the release-candidate manifest is missing"
			elif grep -q 'not frozen yet' "$RC_MANIFEST"; then
				fail "RELEASE-READY is claimed while the release-candidate manifest is still 'not frozen yet'"
			else
				ok "release-candidate manifest is frozen"
			fi
			if [ -z "$CANDIDATE" ]; then
				fail "RELEASE-READY is claimed while current_candidate_core_sha is null"
			else
				ok "current_candidate_core_sha is set ($CANDIDATE)"
			fi
			;;
		NOT-READY)
			ok "verdict marker is NOT-READY, so no release gate is being bypassed"
			;;
		*)
			fail "no machine-readable verdict marker ('<!-- release-verdict: ... -->') in $VERDICT_MD"
			;;
	esac
fi

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
	printf 'PASS  verify-fork-handoff: every recorded coordinate is remotely resolvable and the twins agree\n'
	exit 0
fi
printf 'FAIL  verify-fork-handoff: %s check(s) failed\n' "$FAILURES"
exit 1
