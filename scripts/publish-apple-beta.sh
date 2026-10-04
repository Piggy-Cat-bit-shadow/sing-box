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
#   ./scripts/publish-apple-beta.sh [--run-id <id>]
#
# Environment:
#   APPLE_BUILD_NUMBER   respected if set; otherwise derived once for the whole run
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

workflow="client-apple.yml"
input_dir="build/apple-publish/input"
run_id=""

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) run_id="${2:?--run-id needs a value}"; shift 2 ;;
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

submodule_sha="$(git -C clients/apple rev-parse HEAD)"
# shellcheck disable=SC1091
eval "$(./scripts/ci/version.sh)"
echo "  commit:    $local_sha"
echo "  branch:    $branch"
echo "  version:   $JJ_VERSION"
echo "  submodule: clients/apple @ $submodule_sha"

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
  fail "no successful $workflow run found for $local_sha.
  Dispatch it and wait, then re-run this script:
      gh workflow run $workflow --ref $branch
      gh run watch"
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
# checked - not the artifact name.
./scripts/ci/apple-libbox-artifact.sh validate "$input_dir" \
  --parent-sha "$local_sha" \
  --submodule-sha "$submodule_sha"

artifact_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifact_sha256"])' \
  "$input_dir/manifest.json")"

./scripts/ci/apple-libbox-artifact.sh install "$input_dir" "$PWD"

# ---------------------------------------------------------------------------
# 6. hand off to the existing release pipeline
# ---------------------------------------------------------------------------
step "sign and upload"
echo "  Libbox is installed and verified; the pipeline below will not rebuild it."
echo

# APPLE_USE_PREBUILT_LIBBOX is what keeps the local run from compiling a fourth copy. release-apple.sh
# owns signing, the overlays, archiving, export and upload; nothing about that path is duplicated here.
APPLE_USE_PREBUILT_LIBBOX=1 ./scripts/release-apple.sh testflight

step "APPLE BETA RELEASE"
cat <<EOF
Source:
  commit:              $local_sha
  branch:              $branch
  version:             $JJ_VERSION

GitHub:
  Apple CI:            PASS
  run:                 $run_id
  Libbox artifact:     PASS
  Libbox SHA256:       $artifact_sha
  parent SHA match:    PASS
  submodule SHA match: PASS

Local:
  Libbox build:        SKIPPED (reused the verified artifact)
  signing style:       ${APPLE_SIGNING_STYLE:-automatic}
  build number:        ${APPLE_BUILD_NUMBER:-<per-run>}

RESULT:
  TESTFLIGHT UPLOAD:   PASS (iOS + macOS)

The archive, export and upload all completed successfully. App Store Connect
processes the build afterwards, on Apple's side; "uploaded" is not the same as
"available for testing". Check TestFlight for processing status.
EOF
