#!/bin/sh
# verify-release-acceptance.sh - the STRICT release acceptance gate.
#
# verify-fork-handoff.sh answers "is the handoff internally consistent and are its coordinates
# resolvable from the remote". That is a handoff-integrity gate, and it deliberately does NOT answer
# the release question: it never reads a GitHub Actions run, so EVERY release precondition it enforces
# can be satisfied by writing strings into documents. A candidate SHA, a run id and the word
# "success" are all just text as far as it is concerned.
#
# This script is the missing layer. It refuses a release claim unless a real, completed, successful
# Actions run exists AT THE FROZEN CANDIDATE SHA, with every required job successful and every
# declared artifact present with the digest that was recorded for it.
#
# # Fail closed
#
# Every way of not being able to answer is a FAILURE, never a pass:
#
#   - no snapshot directory, no run list, no jobs list for a required workflow, no artifacts list;
#   - no snapshot at the candidate SHA at all (a green run at some OTHER commit is not evidence);
#   - a run that is queued / in_progress / requested / waiting / pending;
#   - a run whose conclusion is anything but success, in any casing;
#   - a required job that is missing entirely, or skipped / cancelled / timed_out / neutral when the
#     job is not declared optional;
#   - a declared artifact with no snapshot, or with a digest that does not match the recorded one.
#
# Exit codes: 0 = every acceptance requirement is satisfied ? 1 = at least one failed ? 2 = usage or
# environment error (including "cannot answer", which is a failure and is reported as one).
#
# # Inputs
#
# The gate reads API SNAPSHOTS rather than the network, so it is deterministic and can be tested
# against deliberately broken evidence. `--fetch` fills the snapshots from the GitHub REST API using
# curl and a token, and refuses to run without both.
#
#   SNAPSHOT/<workflow>.runs.json    GET /repos/{repo}/actions/workflows/{file}/runs?head_sha={sha}
#   SNAPSHOT/<workflow>.jobs.json    GET /repos/{repo}/actions/runs/{run_id}/jobs
#   SNAPSHOT/<workflow>.artifacts.json
#                                    GET /repos/{repo}/actions/runs/{run_id}/artifacts
#
# POSIX sh only - no bashisms, no jq. Python 3 is required to read JSON, which the fork's other CI
# scripts also require.

set -eu

FAILURES=0
BLOCKERS=0

fail()    { printf 'FAIL     %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
blocked() { printf 'BLOCKED  %s\n' "$1"; BLOCKERS=$((BLOCKERS + 1)); }
ok()      { printf 'ok       %s\n' "$1"; }
note()    { printf 'note     %s\n' "$1"; }
die()     { printf 'ERROR    %s\n' "$1" >&2; exit 2; }

# --- option parsing helpers ------------------------------------------------------------------
# "file.yml_Display_Name" -> file.yml / "Display Name".
#
# The separator is an underscore, and that is forced by the shell rather than chosen: the list is a
# space-separated string, so any display name containing a space must encode them. A pipe or a colon
# would have to survive that split, and neither does. Underscores are mapped back to spaces here, in
# one place, so the comparison below sees the workflow's real name.
#
# These are defined before the argument loop because the required-workflow list is validated against
# the workflow files as soon as it is final, and that validation needs both of them.
workflow_file() { printf '%s' "${1%%_*}"; }
workflow_name() {
	case "$1" in
		*_*) printf '%s' "$(printf '%s' "${1#*_}" | tr '_' ' ')" ;;
		*) printf '' ;;
	esac
}

usage() {
	cat <<'USAGE'
usage: sh scripts/ci/verify-release-acceptance.sh --candidate-sha SHA --snapshot DIR [options]

  --candidate-sha SHA     the frozen candidate code SHA (40 hex). REQUIRED.
  --snapshot DIR          directory holding the API snapshots described above. REQUIRED.
  --workflow FILE_NAME    a required workflow. May repeat. The separator is an UNDERSCORE, not a
                          colon and not a space: the list is split on spaces, so a display name that
                          contains spaces must use underscores, which are mapped back to spaces
                          before the name is compared. If NAME is omitted, "FILE" is the label and the
                          run's own workflow name is not compared.
  --job NAME              a job that must exist and be successful in EVERY required workflow.
                          May repeat. If none is given, every job in the snapshot must be
                          successful unless it is named in --optional-job.
  --optional-job NAME     a job that may be skipped or neutral (a matrix leg that does not apply).
                          May repeat. This is a per-JOB property, not per-workflow: a job named here is
                          optional everywhere, so name it exactly.
  --artifact NAME=SHA256  an artifact that must exist on the accepted run, with this SHA256.
                          May repeat. A declaration is a REQUIREMENT: it is not relaxed by
                          --allow-no-artifacts.
  --allow-no-artifacts    accept a run that produced no artifacts when none are declared. It permits
                          the absence of artifacts, not the absence of one that was declared.
  --fetch                 fill the snapshots from the API before checking. Requires
                          GITHUB_TOKEN (or GH_TOKEN) and curl.
  --repo OWNER/NAME       repository. Default: Piggy-Cat-bit-shadow/sing-box
  --json PATH             also write the machine-readable result to PATH.

The default required workflow list is:
  verify.yml_Verify  interop-xray.yml_Reference_interop_(Xray)  server-linux-amd64.yml_Linux_amd64

The display names are the workflows' own `name:` values, and the gate refuses to run if
any of them has drifted: a rename that is not reflected here makes the gate reject a
correct release with "run N belongs to workflow X, not Y".

Every one of these is overridable so the gate can be exercised against a deliberately broken
snapshot without touching the real evidence. Nothing in this script writes to a repository, signs,
tags or releases anything.
USAGE
}

CANDIDATE_SHA=""
SNAPSHOT=""
REPO="Piggy-Cat-bit-shadow/sing-box"
JSON_OUT=""
DO_FETCH=0
ALLOW_NO_ARTIFACTS=0
WORKFLOWS=""
JOBS=""
OPTIONAL_JOBS=""
ARTIFACTS=""

while [ $# -gt 0 ]; do
	case "$1" in
		--candidate-sha) CANDIDATE_SHA=$2; shift 2 ;;
		--snapshot) SNAPSHOT=$2; shift 2 ;;
		--repo) REPO=$2; shift 2 ;;
		--workflow) WORKFLOWS="$WORKFLOWS $2"; shift 2 ;;
		--job) JOBS="$JOBS $2"; shift 2 ;;
		--optional-job) OPTIONAL_JOBS="$OPTIONAL_JOBS $2"; shift 2 ;;
		--artifact) ARTIFACTS="$ARTIFACTS $2"; shift 2 ;;
		--allow-no-artifacts) ALLOW_NO_ARTIFACTS=1; shift ;;
		--fetch) DO_FETCH=1; shift ;;
		--json) JSON_OUT=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) usage >&2; die "unknown argument: $1" ;;
	esac
done

[ -n "$CANDIDATE_SHA" ] || { usage >&2; die "--candidate-sha is required: an acceptance without a frozen SHA is not an acceptance"; }
[ -n "$SNAPSHOT" ] || { usage >&2; die "--snapshot is required: this gate reads evidence, and it will not invent it"; }
command -v python3 >/dev/null 2>&1 || die "python3 is required to read the API snapshots"

# A SHA is evidence only in its full form. An abbreviation can be extended by anyone, so accepting one
# would let a run at a different commit satisfy the gate.
if ! printf '%s' "$CANDIDATE_SHA" | grep -Eq '^[0-9a-f]{40}$'; then
	die "--candidate-sha must be a full 40-hex SHA, not '$CANDIDATE_SHA'"
fi

if [ -z "$WORKFLOWS" ]; then
	WORKFLOWS="verify.yml_Verify interop-xray.yml_Reference_interop_(Xray) server-linux-amd64.yml_Linux_amd64"
fi

# A display name is evidence only if it is the name the workflow actually declares. The names below
# are literals, and a literal that drifts from the YAML does not fail loudly at the right moment: it
# fails at RELEASE time, rejecting a correct run with "belongs to workflow X, not Y". That already
# happened - server-linux-amd64.yml was renamed from "Linux amd64 server" to "Linux amd64", and this
# list kept a third spelling ("Server Linux amd64") that was never any workflow's name, while
# interop-xray.yml's "Reference interop (Xray)" was recorded as "Interop".
#
# So the literals are checked against the workflow files here, before any snapshot is read, and a
# mismatch is a usage error: it is the gate's own inputs that are wrong, never the evidence.
for entry in $WORKFLOWS; do
	file=$(workflow_file "$entry")
	declared=$(workflow_name "$entry")
	[ -n "$declared" ] || continue
	workflow_path=".github/workflows/$file"
	if [ ! -f "$workflow_path" ]; then
		die "$workflow_path does not exist, so '$file' in the required workflow list names no workflow. Fix the list (or --workflow) before trusting this gate's answer."
	fi
	actual=$(sed -n 's/^name:[[:space:]]*//p' "$workflow_path" | head -n 1)
	if [ "$actual" != "$declared" ]; then
		die "$workflow_path declares name '$actual', but the required workflow list expects '$declared'. The list is stale: run 'grep -m1 ^name: $workflow_path' and correct it (or pass --workflow FILE_NAME), because comparing against the wrong name rejects a correct release."
	fi
done

printf 'verify-release-acceptance: repo %s\n' "$REPO"
printf 'verify-release-acceptance: candidate %s\n' "$CANDIDATE_SHA"
printf 'verify-release-acceptance: snapshots %s\n\n' "$SNAPSHOT"

# --- fetching --------------------------------------------------------------------------------
if [ "$DO_FETCH" -eq 1 ]; then
	TOKEN=${GITHUB_TOKEN:-${GH_TOKEN:-}}
	[ -n "$TOKEN" ] || blocked "--fetch was requested but GITHUB_TOKEN / GH_TOKEN is not set, so no run can be read. This is BLOCKED, not PASS"
	command -v curl >/dev/null 2>&1 || blocked "--fetch was requested but curl is not available, so no run can be read. This is BLOCKED, not PASS"
	if [ -n "$TOKEN" ] && command -v curl >/dev/null 2>&1; then
		mkdir -p "$SNAPSHOT"
		api() {
			# $1 = path (no leading slash), $2 = output file
			curl -fsSL \
				-H "Authorization: Bearer $TOKEN" \
				-H 'Accept: application/vnd.github+json' \
				-H 'X-GitHub-Api-Version: 2022-11-28' \
				"https://api.github.com/$1" -o "$2" 2>/dev/null || return 1
		}
		for entry in $WORKFLOWS; do
			file=$(workflow_file "$entry")
			if api "repos/$REPO/actions/workflows/$file/runs?head_sha=$CANDIDATE_SHA&per_page=100" "$SNAPSHOT/$file.runs.json"; then
				ok "fetched the run list for $file"
			else
				blocked "could not fetch the run list for $file (network, permissions or a missing workflow). This is BLOCKED, not PASS"
			fi
		done
	fi
fi

# --- the check --------------------------------------------------------------------------------
# One python3 pass over every snapshot, so the rules are in one place and the shell does not have to
# parse JSON.
#
# The division of the two streams is deliberate and load-bearing: the human-readable findings go to
# stderr and the machine-readable SUMMARY goes to stdout, so the shell captures one without having to
# filter the other. An earlier version printed both to stdout and split them with grep, which silently
# dropped findings whose message happened to be blank or to start with "{"; the self-test's
# complete-evidence case is what caught it, which is the point of having one.
RESULT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-release-acceptance.XXXXXXXX")
trap 'rm -f "$RESULT_FILE"' EXIT INT TERM

if ! python3 - "$CANDIDATE_SHA" "$SNAPSHOT" "$WORKFLOWS" "$JOBS" "$OPTIONAL_JOBS" "$ARTIFACTS" "$ALLOW_NO_ARTIFACTS" > "$RESULT_FILE" <<'PY'
import json
import os
import sys

candidate = sys.argv[1]
snapshot = sys.argv[2]
workflows = sys.argv[3].split()
required_jobs = sys.argv[4].split()
optional_jobs = sys.argv[5].split()
required_artifacts = sys.argv[6].split()
allow_no_artifacts = sys.argv[7] == "1"

failures = 0
blockers = 0
records = []


def emit(level, message):
    # Findings go to stderr: stdout is reserved for the summary the shell reads back.
    sys.stderr.write("%s\t%s\n" % (level, message))


def fail(message):
    global failures
    failures += 1
    emit("FAIL", message)


def blocked(message):
    global blockers
    blockers += 1
    emit("BLOCKED", message)


def ok(message):
    emit("ok", message)


def load(path):
    """Return (document, None) or (None, reason). Never raises past this function."""
    if not os.path.isfile(path):
        return None, "snapshot missing: %s" % path
    try:
        with open(path) as handle:
            return json.load(handle), None
    except Exception as error:  # noqa: BLE001 - the caller reports it as a failure
        return None, "snapshot is not readable JSON (%s): %s" % (path, error)


# Every failure mode below is a FAILURE rather than a skip: the gate's whole purpose is to refuse a
# release claim it cannot substantiate.
if not os.path.isdir(snapshot):
    blocked("the snapshot directory does not exist: %s. Nothing can be verified, so this is BLOCKED" % snapshot)
else:
    for entry in workflows:
        file, _, encoded_display = entry.partition("_")
        display = encoded_display.replace("_", " ")
        label = display or file

        runs, reason = load(os.path.join(snapshot, file + ".runs.json"))
        if runs is None:
            # Deliberately NOT "no runs found": an absent file means the question was never asked.
            blocked("%s: %s. A workflow whose run list cannot be read is unverified, not green" % (label, reason))
            continue

        run_list = runs.get("workflow_runs") if isinstance(runs, dict) else None
        if run_list is None:
            fail("%s: the run list has no workflow_runs array, so it is not a run list" % label)
            continue
        if not run_list:
            fail("%s: no run exists at the candidate SHA %s. A green run at another commit is not "
                 "evidence for this one" % (label, candidate))
            continue

        # A run is admissible only when its head SHA is the candidate, full length, exactly. The
        # query filters by head_sha, but a snapshot is an input like any other and must be checked
        # rather than trusted.
        admissible = []
        for run in run_list:
            head = str(run.get("head_sha", ""))
            if head != candidate:
                fail("%s: run %s reports head_sha %s, which is not the candidate SHA %s" % (
                    label, run.get("id"), head or "<absent>", candidate))
                continue
            admissible.append(run)

        if not admissible:
            continue

        # More than one completed successful run at one SHA is fine; prefer a successful one, and
        # record every candidate for the report.
        chosen = None
        for run in admissible:
            if str(run.get("conclusion", "")).lower() == "success" and str(run.get("status", "")).lower() == "completed":
                chosen = run
                break
        if chosen is None:
            chosen = admissible[0]

        run_id = chosen.get("id")
        status = str(chosen.get("status", "")).lower()
        conclusion = str(chosen.get("conclusion") or "").lower()

        if status != "completed":
            fail("%s: run %s at the candidate SHA is '%s', not completed. A queued or in-progress run "
                 "is not a finished acceptance" % (label, run_id, status or "<absent>"))
            continue
        if conclusion != "success":
            fail("%s: run %s at the candidate SHA concluded '%s', not success" % (
                label, run_id, conclusion or "<absent>"))
            continue

        run_name = str(chosen.get("name") or "")
        if display and run_name and run_name != display:
            # A similar-looking workflow is not the workflow. The name is checked because a run id
            # alone does not say which file produced it.
            fail("%s: run %s belongs to workflow '%s', not '%s'" % (label, run_id, run_name, display))

        ok("%s: run %s completed successfully at %s" % (label, run_id, candidate))
        records.append({"workflow": file, "workflow_name": run_name or display, "run_id": run_id,
                        "head_sha": candidate, "url": chosen.get("html_url"), "conclusion": conclusion})

        # --- jobs ---
        jobs_document, reason = load(os.path.join(snapshot, file + ".jobs.json"))
        if jobs_document is None:
            blocked("%s: %s. The run's jobs cannot be read, so 'every required job succeeded' is "
                    "unverified" % (label, reason))
        else:
            job_list = jobs_document.get("jobs") if isinstance(jobs_document, dict) else None
            if job_list is None:
                fail("%s: the jobs snapshot has no jobs array" % label)
            else:
                by_name = {}
                for job in job_list:
                    by_name.setdefault(str(job.get("name", "")), []).append(job)
                # The snapshot must describe THIS run, not another one.
                for job in job_list:
                    job_run = job.get("run_id")
                    if job_run is not None and str(job_run) != str(run_id):
                        fail("%s: the jobs snapshot belongs to run %s, not to run %s" % (
                            label, job_run, run_id))
                        break
                if required_jobs:
                    wanted = required_jobs
                else:
                    wanted = sorted(by_name)
                    if not wanted:
                        fail("%s: the run has no jobs at all, so there is nothing to have succeeded" % label)
                for name in wanted:
                    entries = by_name.get(name)
                    if not entries:
                        fail("%s: required job '%s' is absent from run %s" % (label, name, run_id))
                        continue
                    for job in entries:
                        job_conclusion = str(job.get("conclusion") or "").lower()
                        job_status = str(job.get("status", "")).lower()
                        if job_status != "completed":
                            fail("%s: job '%s' is '%s', not completed" % (label, name, job_status or "<absent>"))
                            continue
                        if job_conclusion == "success":
                            ok("%s: job '%s' succeeded" % (label, name))
                        elif job_conclusion in ("skipped", "neutral") and name in optional_jobs:
                            ok("%s: job '%s' is %s and is declared optional" % (label, name, job_conclusion))
                        else:
                            fail("%s: job '%s' concluded '%s'. A skipped, cancelled, timed-out or "
                                 "neutral required job is not a passed acceptance" % (
                                     label, name, job_conclusion or "<absent>"))

        # --- artifacts ---
        artifacts_document, reason = load(os.path.join(snapshot, file + ".artifacts.json"))
        if artifacts_document is None:
            if required_artifacts:
                blocked("%s: %s. Declared artifacts cannot be verified" % (label, reason))
            elif allow_no_artifacts:
                ok("%s: no artifact snapshot and none required" % label)
            else:
                blocked("%s: %s. The artifact list cannot be read, so 'no artifact was expected' "
                        "cannot be established either" % (label, reason))
        else:
            artifact_list = artifacts_document.get("artifacts") if isinstance(artifacts_document, dict) else None
            if artifact_list is None:
                fail("%s: the artifacts snapshot has no artifacts array" % label)
            else:
                by_artifact = {}
                for artifact in artifact_list:
                    by_artifact[str(artifact.get("name", ""))] = artifact
                if not required_artifacts:
                    if not artifact_list and not allow_no_artifacts:
                        fail("%s: the accepted run produced no artifacts at all, and --allow-no-artifacts "
                             "was not given" % label)
                    else:
                        ok("%s: %d artifact(s) present" % (label, len(artifact_list)))
                for declaration in required_artifacts:
                    if "=" not in declaration:
                        fail("%s: artifact declaration '%s' is not NAME=SHA256" % (label, declaration))
                        continue
                    name, expected = declaration.split("=", 1)
                    artifact = by_artifact.get(name)
                    if artifact is None:
                        fail("%s: declared artifact '%s' is absent from run %s" % (label, name, run_id))
                        continue
                    digest = str(artifact.get("digest") or "")
                    if not digest:
                        fail("%s: artifact '%s' has no recorded digest, so the expected digest %s "
                             "cannot be matched to it" % (label, name, expected))
                        continue
                    normalized = digest.split(":", 1)[1].lower() if ":" in digest else digest.lower()
                    if normalized != expected.lower():
                        fail("%s: artifact '%s' digest is %s, not the recorded %s" % (
                            label, name, digest, expected))
                        continue
                    ok("%s: artifact '%s' present with the recorded digest" % (label, name))

sys.stdout.write(json.dumps({"failures": failures, "blockers": blockers, "records": records}) + "\n")
PY
then
	die "the acceptance checker could not run"
fi

# The checker already wrote its findings (FAIL / BLOCKED / ok, one per line) to this process's
# stderr as it went, so they are on the console in the order they were decided. What is read back here
# is only the summary.
SUMMARY=$(cat "$RESULT_FILE")
FAILED=$(printf '%s' "$SUMMARY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["failures"])')
BLOCKED_N=$(printf '%s' "$SUMMARY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["blockers"])')

if [ -n "$JSON_OUT" ]; then
	printf '%s\n' "$SUMMARY" > "$JSON_OUT"
fi

printf '\n'
if [ "$FAILED" -eq 0 ] && [ "$BLOCKED_N" -eq 0 ]; then
	printf 'PASS  verify-release-acceptance: %s has a completed successful run for every required workflow\n' "$CANDIDATE_SHA"
	exit 0
fi
printf 'FAIL  verify-release-acceptance: %s failure(s), %s blocked check(s) for %s\n' "$FAILED" "$BLOCKED_N" "$CANDIDATE_SHA"
printf '      A blocked check is a failure: this gate never passes on "could not determine".\n'
exit 1
