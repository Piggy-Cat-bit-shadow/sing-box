#!/usr/bin/env bash
# Single source of truth for version strings used by every Jiejie workflow.
#
# Outputs shell-assignable KEY=VALUE lines so a workflow can append them to
# $GITHUB_ENV. Keeping the logic here rather than in YAML means the same values
# can be produced locally, and no two workflows can drift.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

commit="$(git rev-parse HEAD)"
short_sha="$(git rev-parse --short=7 HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

# The upstream version, from the same file the Makefile uses, so the fork does
# not invent its own version. release/JIEJIE_VERSION may append a suffix.
version="$(cat release/JIEJIE_VERSION 2>/dev/null | tr -d '[:space:]')"
if [ -z "$version" ]; then
  version="unknown"
fi

# Artifact version carries the revision so a downloaded file identifies its
# source commit without opening BUILD-INFO.
artifact_version="${version}+jiejie.${short_sha}"

go_version="$(go env GOVERSION 2>/dev/null || echo unknown)"

echo "JJ_COMMIT=$commit"
echo "JJ_SHORT_SHA=$short_sha"
echo "JJ_BRANCH=$branch"
echo "JJ_VERSION=$version"
echo "JJ_ARTIFACT_VERSION=$artifact_version"
echo "JJ_GO_VERSION=$go_version"
