#!/bin/sh
# verify-release-acceptance-test.sh - the self-test for the strict release acceptance gate.
#
# The gate is only worth having if it refuses the cases it exists to refuse. This harness builds
# deliberately broken API snapshots and requires the gate to REJECT every one of them, and requires it
# to ACCEPT one snapshot that is genuinely complete.
#
# It runs entirely offline against snapshots under a temporary directory, so it asserts the gate's
# logic and never touches a real repository, run or release.
#
# Exit codes: 0 = every case behaved as required ? 1 = at least one case did not ? 2 = setup error.
#
# POSIX sh only, plus python3 for the fixture JSON.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GATE="$SCRIPT_DIR/verify-release-acceptance.sh"
[ -f "$GATE" ] || { printf 'ERROR the gate is missing: %s\n' "$GATE" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf 'ERROR python3 is required\n' >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-release-acceptance-test.XXXXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

CANDIDATE=96fd0263c1be4b683bb99d6a14a369974cc13220
OTHER_SHA=ef83b86819c97cbe58b0397dc74af6aca5f1859d
ARTIFACT_NAME=sing-box-linux-amd64
ARTIFACT_DIGEST=1111111111111111111111111111111111111111111111111111111111111111

PASSED=0
FAILED=0

# write_fixtures <directory> <variant>
#
# The variant names the single defect to inject. "good" injects none.
write_fixtures() {
	python3 - "$1" "$2" "$CANDIDATE" "$OTHER_SHA" "$ARTIFACT_NAME" "$ARTIFACT_DIGEST" <<'PY'
import json
import os
import sys

root, variant, candidate, other_sha, artifact_name, artifact_digest = sys.argv[1:7]

WORKFLOWS = [
    ("verify.yml", "Verify", "Verify"),
    ("interop-xray.yml", "Interop", "Interop Xray reference"),
    ("server-linux-amd64.yml", "Server Linux amd64", "Server Linux amd64"),
]

os.makedirs(root, exist_ok=True)


def dump(path, document):
    with open(os.path.join(root, path), "w") as handle:
        json.dump(document, handle, indent=2)


for index, (file, display, job_name) in enumerate(WORKFLOWS):
    run_id = 1000 + index
    head = candidate
    status = "completed"
    conclusion = "success"
    name = display

    if variant == "wrong-sha" and file == "verify.yml":
        head = other_sha
    if variant == "queued" and file == "verify.yml":
        status = "in_progress"
        conclusion = None
    if variant == "failure" and file == "verify.yml":
        conclusion = "failure"
    if variant == "cancelled" and file == "verify.yml":
        conclusion = "cancelled"
    if variant == "similar-name" and file == "verify.yml":
        name = "Verify (fork)"

    jobs = [{
        "id": run_id * 10 + 1,
        "run_id": run_id,
        "name": job_name,
        "status": "completed",
        "conclusion": "success",
    }]
    if variant == "skipped-job" and file == "verify.yml":
        jobs[0]["conclusion"] = "skipped"
    if variant == "missing-job" and file == "verify.yml":
        jobs = []

    artifacts = [{
        "id": run_id * 100 + 1,
        "name": artifact_name,
        "digest": "sha256:" + artifact_digest,
    }]
    if variant == "wrong-digest" and file == "verify.yml":
        artifacts[0]["digest"] = "sha256:" + ("0" * 64)
    if variant == "no-digest" and file == "verify.yml":
        artifacts[0].pop("digest")
    if variant == "no-artifact" and file == "verify.yml":
        artifacts = []

    dump("%s.runs.json" % file, {"total_count": 1, "workflow_runs": [{
        "id": run_id,
        "name": name,
        "head_sha": head,
        "status": status,
        "conclusion": conclusion,
        "html_url": "https://example.invalid/%s/%s" % (file, run_id),
    }]})
    dump("%s.jobs.json" % file, {"total_count": len(jobs), "jobs": jobs})
    dump("%s.artifacts.json" % file, {"total_count": len(artifacts), "artifacts": artifacts})

    # A variant that removes a whole snapshot must remove it for EVERY workflow, or the other two
    # would still prove the point and the case would not test what it claims.
    if variant == "missing-jobs-snapshot":
        os.remove(os.path.join(root, "%s.jobs.json" % file))
    if variant == "missing-runs-snapshot":
        os.remove(os.path.join(root, "%s.runs.json" % file))
PY
}

# run_case <name> <expected-exit> <variant> [extra gate arguments...]
run_case() {
	name=$1
	expected=$2
	variant=$3
	shift 3
	directory="$WORK/$name"
	mkdir -p "$directory"
	if [ "$variant" != "no-snapshot-at-all" ]; then
		write_fixtures "$directory" "$variant"
	fi
	output="$WORK/$name.out"
	set +e
	sh "$GATE" --candidate-sha "$CANDIDATE" --snapshot "$directory" \
		--artifact "$ARTIFACT_NAME=$ARTIFACT_DIGEST" "$@" > "$output" 2>&1
	status=$?
	set -e
	if [ "$status" -eq "$expected" ]; then
		printf 'ok    %-28s exit %s (expected %s)\n' "$name" "$status" "$expected"
		PASSED=$((PASSED + 1))
	else
		printf 'FAIL  %-28s exit %s (expected %s)\n' "$name" "$status" "$expected"
		sed 's/^/        /' "$output"
		FAILED=$((FAILED + 1))
	fi
}

printf 'verify-release-acceptance self-test\n'
printf 'gate: %s\n\n' "$GATE"

# --- the case that must be accepted ------------------------------------------------------------
run_case complete-evidence 0 good

# --- every way of being wrong must be refused --------------------------------------------------
run_case wrong-sha 1 wrong-sha
run_case queued-run 1 queued
run_case failed-run 1 failure
run_case cancelled-run 1 cancelled
run_case similar-workflow-name 1 similar-name
run_case skipped-required-job 1 skipped-job
run_case missing-required-job 1 missing-job
run_case wrong-artifact-digest 1 wrong-digest
run_case artifact-without-digest 1 no-digest
run_case required-artifact-absent 1 no-artifact
run_case jobs-snapshot-absent 1 missing-jobs-snapshot
run_case runs-snapshot-absent 1 missing-runs-snapshot
run_case snapshot-directory-absent 1 no-snapshot-at-all

# --- and the escape hatches must not be a way through ------------------------------------------
run_case skipped-job-declared-optional 0 skipped-job --optional-job Verify
run_case all-jobs-optional 0 skipped-job \
	--optional-job Verify --optional-job "Interop Xray reference" --optional-job "Server Linux amd64"
# run_case always declares the artifact, so every variant below runs with that declaration in force.
# "The artifact is absent while --allow-no-artifacts was given" is therefore a REQUIREMENT failure,
# not a permitted absence: the flag relaxes the absence of artifacts, never the absence of a declared
# one. That is the case below, and it is the reason the flag is not an escape hatch.
run_case declared-artifact-outranks-allow-no-artifacts 1 no-artifact --allow-no-artifacts
run_case optional-job-does-not-excuse-others 1 skipped-job --optional-job SomethingElse

printf '\n'
if [ "$FAILED" -eq 0 ]; then
	printf 'PASS  verify-release-acceptance self-test: %s case(s) behaved as required\n' "$PASSED"
	printf '      This says the GATE refuses bad evidence. It says nothing about whether a real\n'
	printf '      release is ready: only a real run at a frozen SHA can do that.\n'
	exit 0
fi
printf 'FAIL  verify-release-acceptance self-test: %s of %s case(s) did not behave as required\n' \
	"$FAILED" "$((PASSED + FAILED))"
exit 1
