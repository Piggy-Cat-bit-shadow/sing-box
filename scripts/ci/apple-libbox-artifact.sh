#!/usr/bin/env bash
# Packs and validates the Libbox.xcframework artifact that CI hands to the Apple GUI builds and to
# the local TestFlight publish.
#
# # Why this exists
#
# Compiling Libbox is the most expensive step in the Apple pipeline, and it is determined entirely by
# the source commit - it needs no Apple secrets. Both GUI jobs previously compiled it themselves, so
# the same commit was compiled twice per CI run and a third time on the publishing Mac.
#
# The artifact is the unit that lets all three share one build, which only works if the artifact can
# be proven to belong to the commit being built. A bare directory cannot carry that proof, and
# artifact NAMES are chosen by whoever uploads them, so the name is a label and not evidence. This
# script therefore writes a manifest and treats it as authoritative, and it validates against the
# manifest rather than against any string a caller supplies.
#
# Usage:
#   apple-libbox-artifact.sh pack    <xcframework-dir> <output-dir>
#   apple-libbox-artifact.sh validate <input-dir> --parent-sha <sha>
#   apple-libbox-artifact.sh install  <input-dir> <client-dir>
#
# # What the artifact is bound to, and what it is not
#
# The artifact is bound to ONE thing: the parent commit it was compiled from. Libbox is
# the sing-box core, and the core does not depend on which Apple UI branch a client was
# built from - so the artifact deliberately records no Apple client revision and none is
# validated against it.
#
# This matters because the two Apple products are built from two different Apple
# branches (iOS from hako-ui, macOS from the pinned dev commit), with two different
# SHAs. An earlier version of this script required the artifact's recorded Apple
# submodule to equal the building checkout's, which could only ever hold for one of the
# two platforms. Each platform's Apple revision is recorded in that platform's
# BUILD-INFO instead, where it is meaningful.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

action="${1:-}"
case "$action" in
  pack)     ;;
  validate) ;;
  install)  ;;
  ""|-h|--help)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "apple-libbox-artifact.sh: unknown action '$action'" >&2
    exit 2
    ;;
esac

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- pack --------------------------------------------------------------------
#
# The directory is archived with `ditto` on macOS and `tar` elsewhere: ditto is what preserves the
# symlinks and resource forks an xcframework relies on, and a plain tar round trip has silently
# dropped them before.
pack() {
  local xcframework="$1" output="$2"
  [ -d "$xcframework" ] || fail "no xcframework at $xcframework"
  mkdir -p "$output"

  local tarball="$output/Libbox.xcframework.tar.gz"
  rm -f "$tarball"
  if command -v ditto >/dev/null 2>&1; then
    # --sequesterRsrc keeps the bundle's resource forks inside the archive; --keepParent keeps the
    # top-level directory so extraction restores the name the Xcode project references.
    ditto -c -k --sequesterRsrc --keepParent "$xcframework" "$tarball"
  else
    tar -czf "$tarball" -C "$(dirname "$xcframework")" "$(basename "$xcframework")"
  fi

  local parent_sha version go_version xcode_version
  parent_sha="$(git rev-parse HEAD)"
  # shellcheck disable=SC1091
  eval "$(./scripts/ci/version.sh)"
  version="$JJ_ARTIFACT_VERSION"
  go_version="$JJ_GO_VERSION"
  # Collapse to a single printable line. `xcodebuild -version` on a runner can emit a control
  # character that is legal in a shell variable and illegal in JSON; sanitising here keeps the
  # value readable in BUILD-INFO-LIBBOX.txt as well.
  xcode_version="$(xcodebuild -version 2>/dev/null | head -1 | tr -d '\000-\037\177' || true)"
  [ -n "$xcode_version" ] || xcode_version="unknown"

  local artifact_sha
  artifact_sha="$(sha256_of "$tarball")"

  cat > "$output/BUILD-INFO-LIBBOX.txt" <<EOF
Jiejie Libbox build information
===============================
parent_sha:            $parent_sha
version:               $version
build_time_utc:        $(date -u +%Y-%m-%dT%H:%M:%SZ)
xcode_version:         $xcode_version
go_version:            $go_version
artifact:              $(basename "$tarball")
artifact_sha256:       $artifact_sha
EOF

  printf '%s  %s\n' "$artifact_sha" "$(basename "$tarball")" > "$output/SHA256SUMS-LIBBOX.txt"

  # manifest.json is the authoritative record. The workflow job that uploads this also names the
  # artifact after the commit, but nothing downstream trusts the name.
  #
  # Written with a real JSON encoder rather than by interpolating into a heredoc. Hand-built JSON
  # cannot escape what it interpolates, and a single control character in the Xcode version string
  # was enough to make the manifest unparseable on a runner while it parsed fine on a workstation.
  #
  # parent_sha is the ONLY commit this records. Libbox comes from the core repository and is
  # independent of which Apple UI branch links it - see the header.
  python3 - "$output/manifest.json" "$parent_sha" "$version" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$xcode_version" "$go_version" \
    "$(basename "$tarball")" "$artifact_sha" <<'PY'
import json
import sys

path, parent, version, built, xcode, goversion, artifact, digest = sys.argv[1:9]
with open(path, "w", encoding="utf-8") as handle:
    json.dump(
        {
            "parent_sha": parent,
            "version": version,
            "build_time_utc": built,
            "xcode_version": xcode,
            "go_version": goversion,
            "artifact": artifact,
            "artifact_sha256": digest,
        },
        handle,
        indent=2,
    )
    handle.write("\n")
PY

  echo "packed:   $tarball"
  echo "sha256:   $artifact_sha"
  echo "manifest: $output/manifest.json"
}

# --- manifest field ----------------------------------------------------------
#
# Reads one string field without requiring jq, which is not present on every runner image. The
# manifest is written by pack() in a fixed shape, so this is a lookup rather than a parser.
manifest_field() {
  local file="$1" key="$2"
  python3 - "$file" "$key" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle).get(sys.argv[2])
if value is None:
    sys.exit(1)
print(value)
PY
}

# --- validate ----------------------------------------------------------------
#
# Every gate is fail-closed. A wrong commit, a missing file or a checksum mismatch all stop the
# publish: the whole point of downloading a prebuilt xcframework is that the build it came from is
# known to be the build being shipped.
#
# The parent commit is the only binding. The Apple UI branch is deliberately not checked: the two
# platforms build from two different Apple SHAs and both link this one framework.
validate() {
  local input="$1" expect_parent="$2"

  [ -d "$input" ] || fail "no artifact directory at $input"
  local manifest="$input/manifest.json"
  [ -f "$manifest" ] || fail "the artifact has no manifest.json; it cannot be attributed to a commit"

  local parent_sha artifact_sha
  parent_sha="$(manifest_field "$manifest" parent_sha)" || fail "manifest.json has no parent_sha"
  artifact_sha="$(manifest_field "$manifest" artifact_sha256)" || fail "manifest.json has no artifact_sha256"

  [ "$parent_sha" = "$expect_parent" ] || fail \
    "the Libbox artifact was built from $parent_sha but this checkout is $expect_parent.
  Publishing it would ship a binary that does not match the commit you are releasing."

  local tarball="$input/$(manifest_field "$manifest" artifact)"
  [ -f "$tarball" ] || fail "manifest names $(manifest_field "$manifest" artifact) but the artifact is missing"

  local actual_sha
  actual_sha="$(sha256_of "$tarball")"
  [ "$actual_sha" = "$artifact_sha" ] || fail \
    "checksum mismatch for $(basename "$tarball"):
  manifest: $artifact_sha
  actual:   $actual_sha"

  echo "PASS: manifest parent_sha    $parent_sha"
  echo "PASS: artifact sha256        $artifact_sha"
}

# --- install -----------------------------------------------------------------
#
# Extracts into an Apple client checkout named by the caller, so the SAME artifact can be
# installed into the iOS checkout and the macOS checkout. The existing directory is replaced rather
# than merged: a stale slice left behind by a previous build would make the two platforms link
# different frameworks while both believed they installed the same artifact.
install() {
  local input="$1" client="$2"
  local manifest="$input/manifest.json"
  [ -f "$manifest" ] || fail "no manifest.json in $input; run validate first"

  [ -d "$client" ] || fail \
    "no Apple client checkout at $client. Check the platform's source out before installing."
  [ -f "$client/sing-box.xcodeproj/project.pbxproj" ] || fail \
    "$client does not look like an Apple client checkout (no sing-box.xcodeproj)."

  local tarball="$input/$(manifest_field "$manifest" artifact)"
  [ -f "$tarball" ] || fail "artifact $(manifest_field "$manifest" artifact) is missing"

  local destination="$client/Libbox.xcframework"
  local staging
  staging="$(mktemp -d)"
  trap 'rm -rf "$staging"' RETURN

  if tar -tzf "$tarball" >/dev/null 2>&1; then
    tar -xzf "$tarball" -C "$staging"
  else
    fail "could not read $tarball"
  fi

  [ -d "$staging/Libbox.xcframework" ] || fail \
    "the artifact did not contain Libbox.xcframework at its root"

  rm -rf "$destination"
  mkdir -p "$(dirname "$destination")"
  if command -v ditto >/dev/null 2>&1; then
    ditto "$staging/Libbox.xcframework" "$destination"
  else
    cp -R "$staging/Libbox.xcframework" "$destination"
  fi

  local slices
  slices="$(ls "$destination" | grep -v Info.plist | tr '\n' ' ')"
  [ -n "$slices" ] || fail "the installed xcframework has no slices"
  echo "installed: $destination"
  echo "slices:    $slices"
}

case "$action" in
  pack)
    pack "${2:?usage: pack <xcframework-dir> <output-dir>}" "${3:?usage: pack <xcframework-dir> <output-dir>}"
    ;;
  validate)
    shift
    input="${1:?usage: validate <input-dir> --parent-sha <sha>}"
    shift
    expect_parent=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --parent-sha) expect_parent="${2:?}"; shift 2 ;;
        # Accepted and ignored so an older caller that still passes it is not silently
        # mis-parsed into a different gate. It binds nothing: see the header.
        --submodule-sha) shift 2 ;;
        *) fail "unknown argument '$1'" ;;
      esac
    done
    [ -n "$expect_parent" ] || fail "validate requires --parent-sha"
    validate "$input" "$expect_parent"
    ;;
  install)
    install "${2:?usage: install <input-dir> <client-dir>}" "${3:?usage: install <input-dir> <client-dir>}"
    ;;
esac
