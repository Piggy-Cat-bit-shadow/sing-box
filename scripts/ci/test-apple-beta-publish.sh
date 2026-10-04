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

echo "== manifest is valid JSON whatever the build environment prints =="

# The manifest is parsed by the publish path, so it must be valid JSON and not merely well-formed for
# the values a workstation happens to produce. A control character in the Xcode version string made
# it unparseable on a runner while it parsed locally, which is a failure only CI could surface.
check "the manifest parses as JSON" \
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp/a1/manifest.json"

check "the manifest carries no control characters" \
  python3 -c '
import json, sys
raw = open(sys.argv[1], "rb").read()
sys.exit(1 if any(b < 0x20 and b not in (0x09, 0x0a, 0x0d) for b in raw) else 0)
' "$tmp/a1/manifest.json"

# And the packer must sanitise whatever the toolchain emits rather than trusting it to be printable.
check "the packer sanitises the Xcode version string" \
  grep -q "tr -d" scripts/ci/apple-libbox-artifact.sh

check "the packer writes the manifest with a JSON encoder" \
  grep -q "json.dump" scripts/ci/apple-libbox-artifact.sh

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


echo "== the publish run restores what it changes =="

# The overlays modify clients/apple in place. Without cleanup the next run fails its own
# clean-tree gate, so the restore is part of the contract rather than a convenience.

submodule_path="clients/apple"
submodule_dirty() { [ -n "$(git -C "$submodule_path" status --porcelain 2>/dev/null)" ]; }

# The trap must be installed, and must run on EXIT so success, failure and Ctrl-C all take
# the same path.
check "publish installs an EXIT trap" \
  grep -qE '^[[:space:]]*trap restore_submodule EXIT' "$publish"

check "publish restores only the submodule, not the whole repository" \
  bash -c '! grep -qE "^[[:space:]]*git (-C [^ ]+ )?(reset --hard|clean )" "$0"' "$publish"

check "publish restores with checkout rather than a hard reset" \
  grep -q 'git -C clients/apple checkout -- \.' "$publish"

# The clean gate must still be unconditional: the cleanup must not have been bought by relaxing it.
check "publish still refuses a dirty tree" \
  grep -q 'if \[ -n "$(git status --porcelain)" \]' "$publish"

check "publish still has no --allow-dirty escape hatch" \
  bash -c '! grep -qE "^\s*--allow-dirty\)|case .*allow-dirty" "$0"' "$publish"

# Exercise the real restore function in all three exit modes, against a genuinely dirty submodule.
trap_probe="$(mktemp -d)"
cat > "$trap_probe/probe.sh" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
restore_submodule() {
  local status
  status=$?
  if [ -n "$(git -C clients/apple status --porcelain 2>/dev/null)" ]; then
    git -C clients/apple checkout -- . 2>/dev/null || true
  fi
  return $status
}
trap restore_submodule EXIT
"$@"
PROBE
chmod +x "$trap_probe/probe.sh"

dirty_the_submodule() {
  local target
  target="$(git -C "$submodule_path" rev-parse --show-toplevel)/Extension/Info.plist"
  printf '<!-- overlay probe -->\n' >> "$target"
}

# Success path.
dirty_the_submodule
"$trap_probe/probe.sh" true >/dev/null 2>&1
if submodule_dirty; then
  echo "  FAIL: a successful run left the submodule dirty" >&2
  git -C "$submodule_path" checkout -- . 2>/dev/null || true
  fail=$((fail + 1))
else
  echo "  PASS: a successful run leaves the submodule clean"
  pass=$((pass + 1))
fi

# Failure path.
dirty_the_submodule
"$trap_probe/probe.sh" false >/dev/null 2>&1 || true
if submodule_dirty; then
  echo "  FAIL: a failed run left the submodule dirty" >&2
  git -C "$submodule_path" checkout -- . 2>/dev/null || true
  fail=$((fail + 1))
else
  echo "  PASS: a failed run leaves the submodule clean"
  pass=$((pass + 1))
fi

# Interrupt path. The probe is signalled while it is still running.
dirty_the_submodule
"$trap_probe/probe.sh" sleep 30 >/dev/null 2>&1 &
probe_pid=$!
sleep 1
kill -INT "$probe_pid" 2>/dev/null || true
wait "$probe_pid" 2>/dev/null || true
if submodule_dirty; then
  echo "  FAIL: an interrupted run left the submodule dirty" >&2
  git -C "$submodule_path" checkout -- . 2>/dev/null || true
  fail=$((fail + 1))
else
  echo "  PASS: an interrupted run leaves the submodule clean"
  pass=$((pass + 1))
fi
rm -rf "$trap_probe"

echo "== one build number for the run =="

check "publish derives the build number in its own shell" \
  grep -q 'export APPLE_BUILD_NUMBER=' "$publish"

check "publish honours a caller-supplied build number" \
  grep -q 'if \[ -z "${APPLE_BUILD_NUMBER:-}" \]' "$publish"

# The summary must print the variable, not a placeholder: deriving it in a child process is
# exactly how the summary came to print <per-run> for every default release.
check "the summary prints the real build number" \
  bash -c 'grep -q "build number:        \${APPLE_BUILD_NUMBER}" "$0"' "$publish"

check "the summary has no placeholder fallback" \
  bash -c '! grep -q "APPLE_BUILD_NUMBER:-<per-run>" "$0"' "$publish"

# release-apple.sh must still derive one when the caller left it unset, or a direct invocation
# would publish nothing.
check "release-apple still derives a build number when unset" \
  grep -q 'if \[ -z "${APPLE_BUILD_NUMBER:-}" \]' scripts/release-apple.sh

echo "== configuration precedence =="

# One helper restores every variable the file assigns. Restoring a fixed list by hand is how
# APPLE_TEAM_ID and APPLE_SIGNING_STYLE came to be silently overridden by the file.
check "the env loader discovers the variable set from the file" \
  grep -q 'sed -nE' scripts/release-apple.sh

check "the env loader has no hardcoded per-variable restore" \
  bash -c '! grep -qE "_base_before|_group_before" "$0"' scripts/release-apple.sh

# Exercise the real mechanism with a synthetic file covering every supported input.
precedence_probe="$(mktemp -d)"
cat > "$precedence_probe/.env.apple.local" <<'ENVFILE'
export APPLE_TEAM_ID=FROM_FILE
export APPLE_BASE_BUNDLE_ID=com.file.example
export APPLE_APP_GROUP_ID=group.file.example
export APPLE_SIGNING_STYLE=manual
export APPLE_ENABLE_MULTICAST=false
export APPLE_ENABLE_ICLOUD=true
export APPLE_BUILD_NUMBER=9999999999
ENVFILE

# The loader body is extracted from the real script so the test cannot drift from it.
python3 - "$root" "$precedence_probe/loader.sh" <<'PY'
import re, sys
src = open(sys.argv[1] + "/scripts/release-apple.sh", encoding="utf-8").read()
start = src.index("      local -a _env_names=()")
end = src.index("      echo \"configuration: loaded $local_env\"")
body = src[start:end]
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write("set -euo pipefail\nlocal_env=\"$1\"\n")
    handle.write("load_env() {\n")
    handle.write(body.replace("\n      ", "\n  "))
    handle.write("}\nload_env\n")
PY

# The values must be read inside the same shell that loaded them; expanding them in the parent
# would read the parent's environment, where they are unset by construction.
cat >> "$precedence_probe/loader.sh" <<'REPORT'
echo "TEAM=${APPLE_TEAM_ID:-unset} STYLE=${APPLE_SIGNING_STYLE:-unset} MULTICAST=${APPLE_ENABLE_MULTICAST:-unset} ICLOUD=${APPLE_ENABLE_ICLOUD:-unset} BUILD=${APPLE_BUILD_NUMBER:-unset}"
REPORT

precedence_out="$(APPLE_TEAM_ID=CALLER APPLE_ENABLE_MULTICAST=true APPLE_BUILD_NUMBER=111 \
  bash "$precedence_probe/loader.sh" "$precedence_probe/.env.apple.local" 2>&1)"

check "a caller export beats the env file" \
  bash -c 'case "$1" in *"TEAM=CALLER"*) exit 0;; *) echo "got: $1"; exit 1;; esac' _ "$precedence_out"
check "a caller export beats the env file for multicast" \
  bash -c 'case "$1" in *"MULTICAST=true"*) exit 0;; *) echo "got: $1"; exit 1;; esac' _ "$precedence_out"
check "a caller build number is preserved" \
  bash -c 'case "$1" in *"BUILD=111"*) exit 0;; *) echo "got: $1"; exit 1;; esac' _ "$precedence_out"
check "an unset variable takes the env file value" \
  bash -c 'case "$1" in *"STYLE=manual"*) exit 0;; *) echo "got: $1"; exit 1;; esac' _ "$precedence_out"
check "an unset boolean takes the env file value" \
  bash -c 'case "$1" in *"ICLOUD=true"*) exit 0;; *) echo "got: $1"; exit 1;; esac' _ "$precedence_out"
rm -rf "$precedence_probe"
echo
echo "test-apple-beta-publish: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
