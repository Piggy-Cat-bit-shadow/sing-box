#!/usr/bin/env bash
# Publishes an Apple beta to TestFlight from a CI-verified Libbox artifact.
#
# # Why this exists
#
# The Apple pipeline splits cleanly along the line of what needs secrets. Compiling Libbox and
# proving the client builds needs none, and CI already does both. Archiving, signing and uploading
# need the certificate, the provisioning profile and an Apple ID session, and those must never leave
# this Mac.
#
# Before this script, a release meant running the heavy non-secret work locally as well, and
# compiling Libbox a third time for a commit CI had already compiled. This script instead requires
# that CI has passed for the exact commit being released, takes the Libbox it produced, proves the
# artifact belongs to that commit, and then hands off to the existing release pipeline. Signing,
# export and upload are not reimplemented here.
#
# Usage:
#   ./scripts/publish-apple-beta.sh [--run-id <id>] [--no-dispatch]
#
#   --run-id       publish from a specific run instead of looking one up for this commit
#   --no-dispatch  fail when no run exists for this commit instead of dispatching one
#
# Environment:
#   APPLE_BUILD_NUMBER   respected if set; otherwise derived once for the whole run
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

workflow="client-apple.yml"
input_dir="build/apple-publish/input"
run_id=""
no_dispatch=0

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) run_id="${2:?--run-id needs a value}"; shift 2 ;;
    --no-dispatch) no_dispatch=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "publish-apple-beta: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

fail() { echo; echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "== $* =="; }

# ---------------------------------------------------------------------------
# 1. repository preflight
# ---------------------------------------------------------------------------
step "repository"
local_sha="$(git rev-parse HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD)"

# A TestFlight build has to correspond to a commit that exists. Publishing a dirty tree produces a
# binary nobody can rebuild or attribute, and App Store Connect would accept it without complaint,
# so the check has to be here rather than left to the operator's judgement.
if [ -n "$(git status --porcelain)" ]; then
  echo "The working tree has uncommitted changes:" >&2
  git status --short | sed 's/^/  /' >&2
  fail "TestFlight release must correspond to a reproducible Git commit.
  Commit or discard these changes, then re-run.
  There is deliberately no --allow-dirty: an unreproducible build is not attributable to CI."
fi

# ---------------------------------------------------------------------------
# 1b. select the two Apple sources
# ---------------------------------------------------------------------------
#
# One Apple repository, ONE source, two products. Both iOS and macOS are built from the
# commit the parent gitlink records, so both are gated against that single authority. Which
# UI a device shows is the Apple source's runtime decision, not a parent-side branch choice.
step "Apple source"
eval "$(./scripts/ci/apple-client-source.sh resolve)"

ios_client_dir="$IOS_APPLE_DIR"
macos_client_dir="$MACOS_APPLE_DIR"
export APPLE_CLIENT_REPOSITORY IOS_APPLE_SHA IOS_APPLE_BRANCH MACOS_APPLE_SHA MACOS_APPLE_BRANCH

gitlink_sha="$(git ls-tree HEAD "$ios_client_dir" | awk '{print $3}')"
[ -n "$gitlink_sha" ] || fail "the parent records no gitlink at $ios_client_dir."
[ "$gitlink_sha" = "$IOS_APPLE_SHA" ] || fail \
  "the parent records $ios_client_dir at $gitlink_sha but the iOS source selection resolved
  to $IOS_APPLE_SHA. The iOS build must come from the gitlink the release commit records."

./scripts/ci/apple-client-source.sh assert-shared-source
echo "  source: $APPLE_CLIENT_SHA on $APPLE_CLIENT_BRANCH (shared by both products)"
echo "  iOS:    $IOS_APPLE_BRANCH @ $IOS_APPLE_SHA"
echo "  macOS:  $MACOS_APPLE_BRANCH @ $MACOS_APPLE_SHA"

# ---------------------------------------------------------------------------
# Restore what this run changes
# ---------------------------------------------------------------------------
#
# prepare-apple-client.sh applies overlays that MODIFY each Apple checkout in place. That is
# by design, but it left the iOS submodule dirty, so the next run of this script failed its
# own clean-tree gate and the operator had to clean up by hand after every release.
#
# The gate above has already established that the tree was clean, so anything dirty under
# either checkout when this script exits was produced by this script. Restoring cannot
# discard user work - and restoring only the Apple checkouts, rather than running
# `git reset --hard` on the parent, keeps the blast radius to the directories the overlays
# touch.
#
# `checkout -- .` rather than `reset --hard`: every overlay write targets a file it read
# first, so the changes are tracked modifications and there is nothing untracked to sweep.
# Both were verified against a real overlay run.
#
# The macOS checkout is deliberately NOT removed: it is a pinned checkout under build/,
# reused across runs, and leaving it in place means a re-run does not re-clone it. It is
# restored to its own revision, not deleted.
#
# Installed with `trap ... EXIT` so success, failure and Ctrl-C all take the same path.
restore_clients() {
  local status
  status=$?
  local dir
  for dir in "$ios_client_dir" "$macos_client_dir"; do
    [ -e "$dir/.git" ] || continue
    if [ -n "$(git -C "$dir" status --porcelain 2>/dev/null)" ]; then
      git -C "$dir" checkout -- . 2>/dev/null || true
      echo
      echo "restored $dir to its pinned revision (overlay changes from this run discarded)"
    fi
  done
  return $status
}
trap restore_clients EXIT
# shellcheck disable=SC1091
eval "$(./scripts/ci/version.sh)"
echo "  commit:    $local_sha"
echo "  branch:    $branch"
echo "  version:   $JJ_VERSION"

# ---------------------------------------------------------------------------
# 2. GitHub CLI preflight
# ---------------------------------------------------------------------------
step "GitHub"
command -v gh >/dev/null 2>&1 || fail "the GitHub CLI (gh) is required but was not found."
gh auth status >/dev/null 2>&1 || fail "gh is not authenticated. Run: gh auth login"

# Resolved rather than hardcoded, so a fork or a rename does not silently query the wrong repository.
repo="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)" \
  || fail "could not determine the repository. Run this from inside a checkout with a GitHub remote."
echo "  repository: $repo"

# ---------------------------------------------------------------------------
# 3. find the Apple CI run for THIS commit
# ---------------------------------------------------------------------------
step "Apple CI for $local_sha"

if [ -z "$run_id" ]; then
  # The SHA is matched exactly. Taking the most recent successful run would happily publish the
  # previous commit's Libbox, which is the failure this whole check exists to prevent.
  run_id="$(gh run list --repo "$repo" --workflow "$workflow" --branch "$branch" \
    --limit 100 --json databaseId,headSha,conclusion \
    -q "[.[] | select(.headSha == \"$local_sha\" and .conclusion == \"success\")][0].databaseId" \
    2>/dev/null || true)"
fi

if [ -z "$run_id" ] || [ "$run_id" = "null" ]; then
  if [ "$no_dispatch" = "1" ]; then
    fail "no $workflow run found for $local_sha, and --no-dispatch was given.
  Dispatch it and wait, then re-run:
      gh workflow run $workflow --ref $branch
      gh run watch"
  fi

  # Dispatching is safe only because the run it produces is verified against the local commit before
  # anything is published from it. A dispatch runs the BRANCH, so if the branch has moved it builds
  # someone else's commit - and the headSha check below refuses exactly that, which is why the check
  # is what makes this convenience permissible rather than a hole in it.
  #
  # The branch tip is compared first anyway, so the common mistake - publishing a commit that was
  # never pushed - is reported as itself instead of as a 40-minute wait for a run that cannot match.
  remote_sha="$(gh api "repos/$repo/commits/$branch" --jq .sha 2>/dev/null || true)"
  if [ -z "$remote_sha" ]; then
    fail "could not read $branch from $repo to check that $local_sha is pushed."
  fi
  [ "$remote_sha" = "$local_sha" ] || fail \
    "$branch is at $remote_sha on $repo, but $local_sha is checked out.
  A dispatched run would build the branch tip, not this commit. Push first, then re-run."

  step "dispatching $workflow for $local_sha"
  gh workflow run "$workflow" --ref "$branch" --repo "$repo" \
    || fail "could not dispatch $workflow."

  # Wait for the run that belongs to THIS commit. A run created for another commit never satisfies
  # this, so the wait ends in a refusal rather than in publishing the wrong one.
  deadline=$((SECONDS + 5400))
  while [ "$SECONDS" -lt "$deadline" ]; do
    read -r candidate_id candidate_status candidate_conclusion <<<"$(
      gh run list --repo "$repo" --workflow "$workflow" --branch "$branch" --limit 20 \
        --json databaseId,headSha,status,conclusion \
        -q "[.[] | select(.headSha == \"$local_sha\")][0] | \"\(.databaseId) \(.status) \(.conclusion)\"" \
        2>/dev/null || true
    )"
    if [ -n "${candidate_id:-}" ] && [ "$candidate_id" != "null" ] && [ "$candidate_status" = "completed" ]; then
      run_id="$candidate_id"
      echo "  run:        $run_id ($candidate_status)"
      break
    fi
    echo "  waiting for a run of $local_sha... (${candidate_status:-not created yet})"
    sleep 30
  done
  [ -n "$run_id" ] || fail \
    "no completed $workflow run for $local_sha appeared within 90 minutes.
  Check: gh run list --workflow $workflow --branch $branch"
fi

# Re-verify the run even when the id was supplied: --run-id is an escape hatch for re-publishing a
# known run, not a way to publish an arbitrary one.
run_sha="$(gh run view "$run_id" --repo "$repo" --json headSha -q .headSha)"
run_conclusion="$(gh run view "$run_id" --repo "$repo" --json conclusion -q .conclusion)"
[ "$run_sha" = "$local_sha" ] || fail \
  "run $run_id is for $run_sha, not the checked-out $local_sha."
[ "$run_conclusion" = "success" ] || fail "run $run_id concluded '$run_conclusion', not success."

echo "  run:        $run_id"
echo "  conclusion: $run_conclusion"
echo "  head SHA:   $run_sha  (matches)"

# A run-level success does not prove both clients were built: the workflow's build_ios and
# build_macos inputs skip their job without failing the run, and a skipped job contributes nothing to
# the conclusion. The pipeline below signs and uploads BOTH clients, so the run has to have proved
# both. This applies to --run-id as well - it is a way to re-publish a known run, not to accept one.
jobs_json="$(gh run view "$run_id" --repo "$repo" --json jobs)" \
  || fail "could not read the jobs of run $run_id."
if ! job_results="$(printf '%s' "$jobs_json" | python3 scripts/ci/apple-ci-job-gate.py)"; then
  fail "run $run_id may not be published from (see above).
  Re-dispatch with both platforms enabled:
      gh workflow run $workflow --ref $branch -f build_ios=true -f build_macos=true
      gh run watch"
fi
job_libbox="$(printf '%s\n' "$job_results" | sed -n 's/^libbox=//p')"
job_ios="$(printf '%s\n' "$job_results" | sed -n 's/^ios=//p')"
job_macos="$(printf '%s\n' "$job_results" | sed -n 's/^macos=//p')"
echo "  jobs:       libbox=$job_libbox ios=$job_ios macos=$job_macos"

# ---------------------------------------------------------------------------
# 4. download the Libbox artifact from that exact run
# ---------------------------------------------------------------------------
step "download the verified Libbox"
rm -rf "$input_dir"
mkdir -p "$input_dir"

# Named after the commit by the workflow, and downloaded by that name rather than by pattern, so a
# stale artifact from an earlier run cannot be picked up.
gh run download "$run_id" --repo "$repo" --name "jiejiebox-libbox-$local_sha" --dir "$input_dir" \
  || fail "run $run_id has no Libbox artifact for $local_sha.
  The run may predate the shared-libbox pipeline; re-dispatch the workflow."

# ---------------------------------------------------------------------------
# 5. validate and install
# ---------------------------------------------------------------------------
step "validate the Libbox artifact"
# Everything that makes the artifact attributable lives in the manifest, so the manifest is what is
# checked - not the artifact name. The parent commit is the only binding: the core does not depend on
# which Apple UI branch links it, and the two platforms deliberately use two different ones.
./scripts/ci/apple-libbox-artifact.sh validate "$input_dir" \
  --parent-sha "$local_sha"

artifact_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifact_sha256"])' \
  "$input_dir/manifest.json")"

# Materialise both Apple sources at their own pinned revisions, then install the ONE verified
# framework into each. A failure here is fatal: publishing with only one client's source present
# would either build the wrong UI for a platform or ship a half-configured release.
step "check out both Apple sources"
./scripts/ci/apple-client-source.sh checkout ios >/dev/null
./scripts/ci/apple-client-source.sh verify ios
./scripts/ci/apple-client-source.sh checkout macos >/dev/null
./scripts/ci/apple-client-source.sh verify macos

step "install the verified Libbox into both clients"
./scripts/ci/apple-libbox-artifact.sh install "$input_dir" "$ios_client_dir"
./scripts/ci/apple-libbox-artifact.sh install "$input_dir" "$macos_client_dir"
./scripts/ci/check-apple-shared-libbox.sh "$ios_client_dir" "$macos_client_dir"

# ---------------------------------------------------------------------------
# 6. hand off to the existing release pipeline
# ---------------------------------------------------------------------------
step "sign and upload"
echo "  Libbox is installed and verified; the pipeline below will not rebuild it."
echo

# The build number is derived HERE, once, for two reasons.
#
# It is what keeps iOS and macOS on the same number: release-apple.sh only derives one when the
# caller left it unset, and both builders then read the same exported value.
#
# It is also what lets the summary below report the real number. When release-apple.sh generated it
# in its own process, the value never reached this shell, so the summary printed a placeholder for
# every default run. An explicit APPLE_BUILD_NUMBER from the caller still wins.
if [ -z "${APPLE_BUILD_NUMBER:-}" ]; then
  export APPLE_BUILD_NUMBER="$(date -u +%Y%m%d%H%M)"
fi

# APPLE_USE_PREBUILT_LIBBOX is what keeps the local run from compiling a fourth copy. release-apple.sh
# owns signing, the overlays, archiving, export and upload; nothing about that path is duplicated here.
APPLE_USE_PREBUILT_LIBBOX=1 ./scripts/release-apple.sh testflight

step "APPLE BETA RELEASE"
cat <<EOF
Source:
  commit:              $local_sha
  branch:              $branch
  version:             $JJ_VERSION

Apple source (one repository, ONE commit, two products):
  repository:          $APPLE_CLIENT_REPOSITORY
  branch:              $APPLE_CLIENT_BRANCH

  iOS / SFI:
    commit:            $IOS_APPLE_SHA
    source of truth:   parent clients/apple gitlink
    gitlink match:     PASS

  macOS / SFM:
    commit:            $MACOS_APPLE_SHA
    source of truth:   the same parent clients/apple gitlink
    gitlink match:     PASS

  shared source:       PASS (iOS and macOS build the same Apple commit)
  UI ownership:        the Apple source routes presentation at runtime
                       (iPhone Hako / iPad upstream / macOS upstream)

GitHub Apple CI:
  run:                 $run_id
  libbox:              ${job_libbox:-PASS}
  ios GUI:             ${job_ios:-PASS}
  macOS GUI:           ${job_macos:-PASS}
  run head SHA:        $local_sha (exact match)
  Libbox artifact:     PASS
  Libbox SHA256:       $artifact_sha
  parent SHA match:    PASS
  shared by both:      PASS (identical framework in both Apple checkouts)

Local:
  Libbox build:        SKIPPED (reused the verified artifact)
  signing style:       ${APPLE_SIGNING_STYLE:-automatic}
  build number:        ${APPLE_BUILD_NUMBER}

RESULT:
  TESTFLIGHT UPLOAD:   PASS (iOS + macOS, one App Store Connect record)

The archive, export and upload all completed successfully. App Store Connect
processes the build afterwards, on Apple's side; "uploaded" is not the same as
"available for testing". Check TestFlight for processing status.
EOF
