#!/usr/bin/env bash
# Regression tests for the Apple beta publish pipeline.
#
# Usage: test-apple-beta-publish.sh
#
# These cover the gates that decide whether a CI-built Libbox may be signed and uploaded, and they
# all run offline against fixtures: no Apple account, no upload, no network. Each one guards a
# failure that would otherwise be silent - the wrong commit's framework being shipped, a tampered
# artifact being trusted, or a local run quietly recompiling what CI already verified.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

artifact_tool="./scripts/ci/apple-libbox-artifact.sh"
publish="./scripts/publish-apple-beta.sh"

pass=0
fail=0

# Output is captured rather than discarded, so a failure in CI reports WHY. A suite that prints
# only "FAIL" forces the next reader to reproduce the whole run to learn anything.
check() {
  local name="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    echo "  PASS: $name"
    pass=$((pass + 1))
  else
    echo "  FAIL: $name" >&2
    [ -n "$output" ] && echo "$output" | sed 's/^/        /' >&2
    fail=$((fail + 1))
  fi
}

expects_fail() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL: $name (expected failure, but it succeeded)" >&2
    fail=$((fail + 1))
  else
    echo "  PASS: $name"
    pass=$((pass + 1))
  fi
}

# --- fixtures ----------------------------------------------------------------
#
# A fake xcframework is enough: these tests exercise attribution and integrity, which do not depend
# on what is inside the slices.

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

parent_sha="$(git rev-parse HEAD)"
submodule_sha="$(git -C clients/apple rev-parse HEAD)"

make_xcframework() {
  local dir="$1"
  mkdir -p "$dir/ios-arm64" "$dir/macos-arm64_x86_64"
  echo "ios-slice" > "$dir/ios-arm64/Libbox"
  echo "macos-slice" > "$dir/macos-arm64_x86_64/Libbox"
}

build_artifact() {
  local xcframework="$1" out="$2"
  make_xcframework "$xcframework"
  "$artifact_tool" pack "$xcframework" "$out" >/dev/null
}

echo "== artifact attribution =="

build_artifact "$tmp/x1/Libbox.xcframework" "$tmp/a1"
check "an artifact built from this commit validates" \
  "$artifact_tool" validate "$tmp/a1" --parent-sha "$parent_sha" --submodule-sha "$submodule_sha"

expects_fail "a different parent SHA is rejected" \
  "$artifact_tool" validate "$tmp/a1" --parent-sha "0000000000000000000000000000000000000000" \
    --submodule-sha "$submodule_sha"

expects_fail "a different Apple submodule SHA is rejected" \
  "$artifact_tool" validate "$tmp/a1" --parent-sha "$parent_sha" \
    --submodule-sha "0000000000000000000000000000000000000000"

echo "== artifact integrity =="

cp -R "$tmp/a1" "$tmp/a_tampered"
printf 'tampered' >> "$tmp/a_tampered/Libbox.xcframework.tar.gz"
expects_fail "a tampered archive is rejected" \
  "$artifact_tool" validate "$tmp/a_tampered" --parent-sha "$parent_sha" --submodule-sha "$submodule_sha"

cp -R "$tmp/a1" "$tmp/a_missing"
rm -f "$tmp/a_missing/Libbox.xcframework.tar.gz"
expects_fail "a missing archive is rejected" \
  "$artifact_tool" validate "$tmp/a_missing" --parent-sha "$parent_sha" --submodule-sha "$submodule_sha"

mkdir -p "$tmp/a_nomanifest"
expects_fail "an artifact with no manifest is rejected" \
  "$artifact_tool" validate "$tmp/a_nomanifest" --parent-sha "$parent_sha" --submodule-sha "$submodule_sha"

echo "== manifest is authoritative, not the artifact name =="

# A renamed artifact whose manifest still names the right commit must validate; the name carries no
# authority, so a rename is neither evidence for nor against attribution.
cp -R "$tmp/a1" "$tmp/a_renamed"
mv "$tmp/a_renamed" "$tmp/anything-at-all"
check "validation does not depend on the directory name" \
  "$artifact_tool" validate "$tmp/anything-at-all" --parent-sha "$parent_sha" --submodule-sha "$submodule_sha"

echo "== manifest content =="

check "the manifest records the parent commit" \
  grep -q "\"parent_sha\": \"$parent_sha\"" "$tmp/a1/manifest.json"
check "the manifest records the submodule revision" \
  grep -q "\"apple_submodule_sha\": \"$submodule_sha\"" "$tmp/a1/manifest.json"
check "the manifest records the artifact checksum" \
  grep -q '"artifact_sha256":' "$tmp/a1/manifest.json"

echo "== install =="

mkdir -p "$tmp/installroot/clients/apple"
check "install places the xcframework" \
  "$artifact_tool" install "$tmp/a1" "$tmp/installroot"
check "the installed framework has its iOS slice" \
  test -d "$tmp/installroot/clients/apple/Libbox.xcframework/ios-arm64"
check "the installed framework has its macOS slice" \
  test -d "$tmp/installroot/clients/apple/Libbox.xcframework/macos-arm64_x86_64"

expects_fail "install without an archive is rejected" \
  "$artifact_tool" install "$tmp/a_missing" "$tmp/installroot"

echo "== release-apple prebuilt mode =="

# The prebuilt flag must not fall back to compiling. A fallback would publish a framework that is
# not the artifact the operator verified, which is the whole reason the flag exists.
expects_fail "prebuilt mode refuses when no Libbox is installed" \
  env APPLE_USE_PREBUILT_LIBBOX=1 \
      ./scripts/release-apple.sh nonexistent-target

check "release-apple still builds Libbox when the flag is unset" \
  grep -q 'build-apple-libbox.sh both' scripts/release-apple.sh

# The build call must sit in the else arm. An awk range from the flag to the closing `fi` also spans
# the else branch, so it matched either way and proved nothing.
if python3 scripts/ci/check-prebuilt-branch.py < scripts/release-apple.sh; then
  echo "  PASS: the prebuilt branch does not build Libbox"
  pass=$((pass + 1))
else
  echo "  FAIL: the prebuilt branch still builds Libbox" >&2
  fail=$((fail + 1))
fi

echo "== publish entry point =="

check "publish-apple-beta.sh exists and is executable" test -x "$publish"

# The dirty-tree gate is what makes a published build attributable to a commit. Driven from a real
# dirty repository, with the script invoked by absolute path so it inspects THAT tree. Passing --help
# would exit before the gate and prove nothing.
dirty_repo="$(mktemp -d)"
git -C "$dirty_repo" init -q .
touch "$dirty_repo/tracked"
git -C "$dirty_repo" add tracked
git -C "$dirty_repo" -c user.email=t@t -c user.name=t commit -qm initial
echo "uncommitted" >> "$dirty_repo/tracked"
expects_fail "publish refuses a dirty working tree" \
  bash -c 'cd "$1" && "$2"' _ "$dirty_repo" "$root/$publish"
rm -rf "$dirty_repo"

# The script mentions --allow-dirty in the message explaining why it does not exist, so a plain grep
# would find that prose. What must be absent is a code path that accepts the flag.
check "publish has no --allow-dirty escape hatch" \
  bash -c '! grep -qE "^\s*--allow-dirty\)|case .*allow-dirty" "$0"' "$publish"

check "publish matches the commit SHA exactly, not the latest run" \
  grep -q 'headSha == \\"\$local_sha\\"' "$publish"

check "publish re-verifies a supplied --run-id" \
  grep -q 'run_sha="\$(gh run view' "$publish"

check "publish validates the manifest before installing" \
  grep -q 'apple-libbox-artifact.sh validate' "$publish"

check "publish delegates signing to release-apple.sh" \
  grep -q 'release-apple.sh testflight' "$publish"

# The publish script must not grow its own archive or upload logic; that is release-apple's job.
check "publish does not call xcodebuild directly" \
  bash -c '! grep -q "xcodebuild" "$0"' "$publish"

check "publish does not exportArchive directly" \
  bash -c '! grep -q "exportArchive" "$0"' "$publish"

echo "== build number is shared by both platforms =="

# One testflight run must not publish two build numbers into one App Store Connect record.
check "release-apple derives APPLE_BUILD_NUMBER once" \
  grep -q 'export APPLE_BUILD_NUMBER=' scripts/release-apple.sh

if grep -q 'build_number="\${APPLE_BUILD_NUMBER:-' scripts/ci/build-ios-testflight.sh; then
  echo "  PASS: the iOS builder still accepts an inherited build number"
  pass=$((pass + 1))
else
  echo "  FAIL: the iOS builder ignores APPLE_BUILD_NUMBER" >&2
  fail=$((fail + 1))
fi

if grep -q 'build_number="\${APPLE_BUILD_NUMBER:-' scripts/ci/build-macos-testflight.sh; then
  echo "  PASS: the macOS builder still accepts an inherited build number"
  pass=$((pass + 1))
else
  echo "  FAIL: the macOS builder ignores APPLE_BUILD_NUMBER" >&2
  fail=$((fail + 1))
fi

echo "== upload gate does not require a local IPA or PKG =="

# destination=upload leaves the export directory empty by design. Requiring a local file there was a
# real regression once, so it is asserted rather than assumed.
for script in scripts/ci/build-ios-testflight.sh scripts/ci/build-macos-testflight.sh; do
  if grep -qE 'local (ipa|pkg)|test -f .*\.(ipa|pkg)"' "$script"; then
    echo "  FAIL: $script gates upload on a local file existing" >&2
    fail=$((fail + 1))
  else
    echo "  PASS: $(basename "$script") does not gate upload on a local file"
    pass=$((pass + 1))
  fi
done

echo "== CI workflow =="

check "the workflow defines a libbox job" \
  grep -q '^  libbox:' .github/workflows/client-apple.yml
for job in ios macos; do
  if python3 scripts/ci/check-job-needs.py "$job" < .github/workflows/client-apple.yml; then
    echo "  PASS: the $job job needs libbox"
    pass=$((pass + 1))
  else
    echo "  FAIL: the $job job does not depend on libbox" >&2
    fail=$((fail + 1))
  fi
done

libbox_builds="$(grep -c 'build-apple-libbox.sh both' .github/workflows/client-apple.yml)"
if [ "$libbox_builds" = "1" ]; then
  echo "  PASS: Libbox is compiled exactly once per CI run"
  pass=$((pass + 1))
else
  echo "  FAIL: Libbox is compiled $libbox_builds times per CI run (expected 1)" >&2
  fail=$((fail + 1))
fi

check "the workflow uploads the Libbox artifact" \
  grep -q 'name: jiejiebox-libbox-\${{ github.sha }}' .github/workflows/client-apple.yml

downloads="$(grep -c 'actions/download-artifact@v4' .github/workflows/client-apple.yml)"
if [ "$downloads" = "2" ]; then
  echo "  PASS: both GUI jobs download the shared artifact"
  pass=$((pass + 1))
else
  echo "  FAIL: expected 2 download-artifact steps, found $downloads" >&2
  fail=$((fail + 1))
fi

check "the workflow packs the artifact through the shared helper" \
  grep -q 'apple-libbox-artifact.sh pack' .github/workflows/client-apple.yml
check "this suite runs in CI" \
  grep -q 'test-apple-beta-publish.sh' .github/workflows/client-apple.yml
check "the signing suite runs in CI too" \
  grep -q 'test-apple-signing.sh' .github/workflows/client-apple.yml
check "the workflow validates before installing" \
  grep -q 'apple-libbox-artifact.sh validate' .github/workflows/client-apple.yml

echo
echo "test-apple-beta-publish: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
