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
  "$artifact_tool" validate "$tmp/a1" --parent-sha "$parent_sha"

expects_fail "a different parent SHA is rejected" \
  "$artifact_tool" validate "$tmp/a1" --parent-sha "0000000000000000000000000000000000000000"

# The artifact binds the parent commit ONLY. Libbox is the core and does not depend on
# which Apple UI branch links it, and the two Apple products are built from two different
# Apple revisions - so an artifact that recorded one Apple revision could never be valid
# for both platforms.
echo "== the artifact does not bind an Apple revision =="

check "the manifest records no Apple client revision" \
  bash -c "! grep -q '\"apple_submodule_sha\"' '$tmp/a1/manifest.json'"
check "validate takes no submodule argument" \
  bash -c "! grep -qE '^\\s+\\[ -n \"\\\$expect_submodule\" \\]' scripts/ci/apple-libbox-artifact.sh"
check "a caller that still passes --submodule-sha is accepted" \
  "$artifact_tool" validate "$tmp/a1" --parent-sha "$parent_sha" \
    --submodule-sha "0000000000000000000000000000000000000000"

echo "== artifact integrity =="

cp -R "$tmp/a1" "$tmp/a_tampered"
printf 'tampered' >> "$tmp/a_tampered/Libbox.xcframework.tar.gz"
expects_fail "a tampered archive is rejected" \
  "$artifact_tool" validate "$tmp/a_tampered" --parent-sha "$parent_sha"

cp -R "$tmp/a1" "$tmp/a_missing"
rm -f "$tmp/a_missing/Libbox.xcframework.tar.gz"
expects_fail "a missing archive is rejected" \
  "$artifact_tool" validate "$tmp/a_missing" --parent-sha "$parent_sha"

mkdir -p "$tmp/a_nomanifest"
expects_fail "an artifact with no manifest is rejected" \
  "$artifact_tool" validate "$tmp/a_nomanifest" --parent-sha "$parent_sha"

echo "== manifest is authoritative, not the artifact name =="

# A renamed artifact whose manifest still names the right commit must validate; the name carries no
# authority, so a rename is neither evidence for nor against attribution.
cp -R "$tmp/a1" "$tmp/a_renamed"
mv "$tmp/a_renamed" "$tmp/anything-at-all"
check "validation does not depend on the directory name" \
  "$artifact_tool" validate "$tmp/anything-at-all" --parent-sha "$parent_sha"

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
check "the manifest records the artifact checksum" \
  grep -q '"artifact_sha256":' "$tmp/a1/manifest.json"

echo "== install =="

# Install now takes the Apple client checkout itself, because the two products are built from
# two different checkouts of two different branches. The same artifact goes into each.
make_client_tree() {
  local dir="$1"
  mkdir -p "$dir/sing-box.xcodeproj"
  : > "$dir/sing-box.xcodeproj/project.pbxproj"
}
make_client_tree "$tmp/ios-client"
make_client_tree "$tmp/macos-client"

check "install places the xcframework in the iOS client" \
  "$artifact_tool" install "$tmp/a1" "$tmp/ios-client"
check "the iOS client framework has its iOS slice" \
  test -d "$tmp/ios-client/Libbox.xcframework/ios-arm64"
check "the iOS client framework has its macOS slice" \
  test -d "$tmp/ios-client/Libbox.xcframework/macos-arm64_x86_64"

check "install places the same xcframework in the macOS client" \
  "$artifact_tool" install "$tmp/a1" "$tmp/macos-client"
check "both clients link the identical Libbox" \
  ./scripts/ci/check-apple-shared-libbox.sh "$tmp/ios-client" "$tmp/macos-client"

# A second install must replace the framework, not merge into it: a stale slice left behind
# would make one platform link a framework the other does not have.
printf 'stale' > "$tmp/ios-client/Libbox.xcframework/ios-arm64/STALE"
"$artifact_tool" install "$tmp/a1" "$tmp/ios-client" >/dev/null
check "a re-install replaces the framework rather than merging" \
  bash -c "test ! -e '$tmp/ios-client/Libbox.xcframework/ios-arm64/STALE'"

expects_fail "install into a directory that is not an Apple client is rejected" \
  "$artifact_tool" install "$tmp/a1" "$tmp/not-a-client"

expects_fail "install without an archive is rejected" \
  "$artifact_tool" install "$tmp/a_missing" "$tmp/ios-client"

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

echo "== the Apple CI run must have proved all three platform jobs =="

# The workflow's build_ios / build_macos inputs skip their job without failing the run, so a run that
# concludes success can still have built one client. The pipeline publishes both, so the run has to
# have proved both - and every way of failing to prove it has to be refused, not just the obvious one.
job_gate=scripts/ci/apple-ci-job-gate.py

job_payload() {
  python3 - "$@" <<'PAYLOAD'
import json, sys
jobs = []
for spec in sys.argv[1:]:
    name, status, conclusion = spec.split(":")
    jobs.append({"name": name, "status": status, "conclusion": conclusion})
print(json.dumps({"jobs": jobs}))
PAYLOAD
}

runs_job_gate() {
  printf '%s' "$1" | python3 "$job_gate" >/dev/null 2>&1
}

check "a run with libbox, ios and macos successful is accepted" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:success macos:completed:success)"

expects_fail "an iOS-only run is refused (macos job absent)" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:success)"

expects_fail "a macOS-only run is refused (ios job absent)" \
  runs_job_gate "$(job_payload libbox:completed:success macos:completed:success)"

expects_fail "a run whose macOS job was skipped is refused" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:success macos:completed:skipped)"

expects_fail "a run whose iOS job was skipped is refused" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:skipped macos:completed:success)"

expects_fail "a run with a cancelled platform job is refused" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:cancelled macos:completed:success)"

expects_fail "a run with a failed platform job is refused" \
  runs_job_gate "$(job_payload libbox:completed:success ios:completed:success macos:completed:failure)"

expects_fail "a run whose libbox job failed is refused" \
  runs_job_gate "$(job_payload libbox:completed:failure ios:completed:success macos:completed:success)"

expects_fail "a run whose platform job never completed is refused" \
  runs_job_gate "$(job_payload libbox:completed:success ios:in_progress:success macos:completed:success)"

expects_fail "a run with no jobs at all is refused" \
  runs_job_gate '{"jobs":[]}'

expects_fail "unparseable run data is refused" \
  runs_job_gate 'not json'

# A job display name may carry a suffix - a matrix or a label - and the required name is still the
# name. This is asserted so the match cannot quietly become exact-only and start refusing real runs.
check "a suffixed job name still counts as its job" \
  runs_job_gate "$(job_payload 'libbox (ios,macos):completed:success' ios:completed:success macos:completed:success)"

# The gate is worthless if the publish script does not reach it, or reaches it only in one of its two
# paths. It is applied after the run's SHA has been verified, so --run-id passes through it too.
check "publish applies the job gate" \
  grep -q 'apple-ci-job-gate.py' "$publish"

check "publish applies the job gate after verifying the run SHA" \
  bash -c 'test "$(grep -n "run_sha=\"\$(gh run view" "$0" | head -1 | cut -d: -f1)" -lt "$(grep -n "apple-ci-job-gate.py" "$0" | head -1 | cut -d: -f1)"' "$publish"

check "publish reports each platform job in its summary" \
  bash -c 'grep -q "ios GUI:" "$0" && grep -q "macOS GUI:" "$0"' "$publish"

echo "== one-command publish stays bound to this commit =="

# Dispatching is what makes one command possible; binding the dispatched run to the local commit is
# what makes it safe. Both halves are asserted, because either one alone is a different bug.
check "publish can dispatch the workflow when no run exists" \
  grep -q 'gh workflow run "\$workflow" --ref "\$branch"' "$publish"

check "publish refuses to dispatch when the branch is not at this commit" \
  grep -q '\[ "\$remote_sha" = "\$local_sha" \]' "$publish"

check "publish waits only for a run of this commit" \
  grep -qF 'select(.headSha == \"$local_sha\")' "$publish"

check "the dispatch wait reads the run's own status" \
  grep -q 'databaseId,headSha,status,conclusion' "$publish"

check "publish offers a way to refuse dispatching" \
  grep -q -- '--no-dispatch' "$publish"

check "the parent gitlink must match the checked-out submodule" \
  grep -q 'gitlink_sha' "$publish"

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

# The overlays modify each Apple checkout in place. Without cleanup the next run fails its own
# clean-tree gate, so the restore is part of the contract rather than a convenience. There are
# now TWO checkouts to restore, because the two products are built from two Apple branches.

submodule_path="clients/apple"
client_dirty() { [ -n "$(git -C "$1" status --porcelain 2>/dev/null)" ]; }

# The trap must be installed, and must run on EXIT so success, failure and Ctrl-C all take
# the same path.
check "publish installs an EXIT trap" \
  grep -qE '^[[:space:]]*trap restore_clients EXIT' "$publish"

check "publish restores only the Apple checkouts, not the whole repository" \
  bash -c '! grep -qE "^[[:space:]]*git (-C [^ ]+ )?(reset --hard|clean )" "$0"' "$publish"

check "publish restores with checkout rather than a hard reset" \
  grep -q 'git -C "$dir" checkout -- \.' "$publish"

# The restore must cover BOTH sources. Restoring only the iOS submodule would leave the macOS
# checkout dirty and fail the next run's clean-tree gate - the exact failure the restore exists
# to prevent, reintroduced for the new platform.
check "publish restores the iOS source" \
  grep -q 'ios_client_dir="\$IOS_APPLE_DIR"' "$publish"
check "publish restores the macOS source" \
  grep -q 'macos_client_dir="\$MACOS_APPLE_DIR"' "$publish"
check "publish's restore loops over both client directories" \
  bash -c "grep -q 'for dir in \"\$ios_client_dir\" \"\$macos_client_dir\"' \"\$0\"" "$publish"

# The clean gate must still be unconditional: the cleanup must not have been bought by relaxing it.
check "publish still refuses a dirty tree" \
  grep -q 'if \[ -n "$(git status --porcelain)" \]' "$publish"

check "publish still has no --allow-dirty escape hatch" \
  bash -c '! grep -qE "^\s*--allow-dirty\)|case .*allow-dirty" "$0"' "$publish"

# Exercise the real restore shape in all three exit modes, against genuinely dirty checkouts.
# The probe mirrors restore_clients with the same loop, so a regression in the two-directory
# restore is caught here rather than after a real release.
trap_probe="$(mktemp -d)"
probe_second="$(mktemp -d)"
(
  cd "$probe_second"
  git init -q .
  git config user.email probe@example.invalid
  git config user.name probe
  : > tracked.txt
  git add tracked.txt
  git commit -qm init
)
cat > "$trap_probe/probe.sh" <<PROBE
#!/usr/bin/env bash
set -euo pipefail
restore_clients() {
  local status
  status=\$?
  local dir
  for dir in $submodule_path $probe_second; do
    [ -e "\$dir/.git" ] || continue
    if [ -n "\$(git -C "\$dir" status --porcelain 2>/dev/null)" ]; then
      git -C "\$dir" checkout -- . 2>/dev/null || true
    fi
  done
  return \$status
}
trap restore_clients EXIT
"\$@"
PROBE
chmod +x "$trap_probe/probe.sh"

dirty_the_clients() {
  local target
  target="$(git -C "$submodule_path" rev-parse --show-toplevel)/Extension/Info.plist"
  printf '<!-- overlay probe -->\n' >> "$target"
  printf 'overlay probe\n' >> "$probe_second/tracked.txt"
}

any_client_dirty() {
  client_dirty "$submodule_path" || client_dirty "$probe_second"
}

clean_the_clients() {
  git -C "$submodule_path" checkout -- . 2>/dev/null || true
  git -C "$probe_second" checkout -- . 2>/dev/null || true
}

for mode in success failure interrupt; do
  dirty_the_clients
  case "$mode" in
    success)   "$trap_probe/probe.sh" true >/dev/null 2>&1 ;;
    failure)   "$trap_probe/probe.sh" false >/dev/null 2>&1 || true ;;
    interrupt)
      "$trap_probe/probe.sh" sleep 30 >/dev/null 2>&1 &
      probe_pid=$!
      sleep 1
      kill -INT "$probe_pid" 2>/dev/null || true
      wait "$probe_pid" 2>/dev/null || true
      ;;
  esac
  if any_client_dirty; then
    echo "  FAIL: an interrupted/successful/failed ($mode) run left an Apple checkout dirty" >&2
    clean_the_clients
    fail=$((fail + 1))
  else
    echo "  PASS: a $mode run leaves BOTH Apple checkouts clean"
    pass=$((pass + 1))
  fi
done
rm -rf "$trap_probe" "$probe_second"

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
