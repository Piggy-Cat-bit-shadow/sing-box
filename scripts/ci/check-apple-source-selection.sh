#!/usr/bin/env bash
# Regression tests for the Apple source selection.
#
# Usage: check-apple-source-selection.sh
#
# # What this protects
#
# The two Apple products are built from two branches of ONE Apple client repository, and
# they must never be built from each other's:
#
#     iOS / SFI     Repo B @ the parent's clients/apple gitlink   branch hako-ui
#     macOS / SFM   Repo B @ MACOS_APPLE_SHA                      branch dev
#
# Both then link ONE Libbox built once from this repository. Almost every way this can be
# wrong is silent: the build succeeds, the app runs, and one platform is quietly shipping
# the other platform's UI, or a release is built from whatever `dev` happened to point at.
#
# So the checks below are of two kinds:
#
#   structural  the workflow is wired so each job can only see its own source
#   behavioural the resolver is exercised in a scratch repository, including the cases
#               that must FAIL - a missing pin, an unreachable commit, a commit that is
#               not on the branch it claims, and a checkout that is not the gitlink
#
# The scratch fixtures are local git repositories, so this suite needs no network.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

pass=0
fail=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS: $name"
    pass=$((pass + 1))
  else
    echo "  FAIL: $name" >&2
    fail=$((fail + 1))
  fi
}

expects_fail() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL: $name (expected failure, but it succeeded)" >&2
    fail=$((fail + 1))
  else
    echo "  PASS: $name"
    pass=$((pass + 1))
  fi
}

# ---------------------------------------------------------------------------
# 1. One source for both platforms, and no per-platform revision anywhere
# ---------------------------------------------------------------------------
echo "== the Apple source is one commit, pinned by the gitlink =="

refs_file="release/apple-client-refs.env"
check "the Apple refs file exists" test -f "$refs_file"

# shellcheck disable=SC1090
eval "$(. "$refs_file" && printf 'PIN_REPO=%q PIN_BRANCH=%q' \
  "$APPLE_CLIENT_REPOSITORY" "$APPLE_CLIENT_BRANCH")"

check "the refs file names the Apple client repository" \
  bash -c "case '$PIN_REPO' in *sing-box-for-apple) exit 0 ;; *) exit 1 ;; esac"
check "the refs file names the reviewed branch" test -n "$PIN_BRANCH"

# The single-source invariant, stated against the file rather than against a value: a
# per-platform Apple revision is the two-source model this topology removed, so its return
# is a failure even if the two values happened to agree.
check "no macOS-specific Apple SHA is declared" \
  bash -c "! grep -qE '^[[:space:]]*MACOS_APPLE_SHA=' '$refs_file'"
check "no macOS-specific Apple branch is declared" \
  bash -c "! grep -qE '^[[:space:]]*MACOS_APPLE_BRANCH=' '$refs_file'"
check "the gitlink is the only authority for the Apple SHA (not duplicated into the file)" \
  bash -c "! grep -qE '^[[:space:]]*(IOS_APPLE_SHA|APPLE_CLIENT_SHA)=' '$refs_file'"

# ---------------------------------------------------------------------------
# 2. Structural: the workflow can only build each platform from its own source
# ---------------------------------------------------------------------------
echo "== the workflow separates the two sources =="

workflow=".github/workflows/client-apple.yml"

python3 - "$workflow" <<'PY'
import re
import sys

# Deliberately stdlib-only. PyYAML is present on a macOS workstation but NOT on the GitHub
# runner image - scripts/ci/check-job-needs.py records the same discovery - so importing it
# here would make this suite fail in CI for a reason unrelated to the workflow it inspects.
#
# Job blocks are found by indentation, which is what YAML uses: a top-level job key sits at
# exactly two spaces under `jobs:`, and the block runs until the next such key.
path = sys.argv[1]
text = open(path, encoding="utf-8").read()

problems = []


def job_text(name):
    match = re.search(
        r"^  " + re.escape(name) + r":\n(.*?)(?=^  \S|\Z)",
        text,
        re.M | re.S,
    )
    if not match:
        problems.append(f"the workflow has no {name} job")
        return ""
    # Comments are not configuration. The macOS job *explains* that it must not use
    # `submodules: recursive`, and reading that explanation back as the setting itself would
    # report the job as doing the thing it is documented not to do.
    return "\n".join(
        line for line in match.group(1).splitlines() if not line.lstrip().startswith("#")
    )


ios = job_text("ios")
macos = job_text("macos")
libbox = job_text("libbox")

# Each platform job must declare which platform it is and which directory that resolves to.
for name, body, platform in (("ios", ios, "ios"), ("macos", macos, "macos")):
    if f"APPLE_CLIENT_PLATFORM={platform}" not in body:
        problems.append(f"the {name} job does not declare APPLE_CLIENT_PLATFORM={platform}")

if "APPLE_CLIENT_DIR=$IOS_APPLE_DIR" not in ios:
    problems.append("the ios job does not point APPLE_CLIENT_DIR at the iOS source")
if "APPLE_CLIENT_DIR=$MACOS_APPLE_DIR" not in macos:
    problems.append("the macos job does not point APPLE_CLIENT_DIR at the macOS source")

# The macOS job must never materialise the iOS source. `submodules: recursive` would check
# out clients/apple - the custom Hako UI - inside a job that must build the original UI.
if "submodules: recursive" in macos:
    problems.append(
        "the macos job checks out submodules recursively, which materialises the iOS "
        "clients/apple source in the macOS job"
    )
if "submodules: false" not in macos:
    problems.append("the macos job does not explicitly decline submodules")

# Each job must materialise its own platform's source and not the other's. The iOS source IS
# the parent's submodule, so checking it out means `submodules: recursive`; the macOS source
# is an explicit pinned checkout.
if "apple-client-source.sh checkout ios" not in ios and "submodules: recursive" not in ios:
    problems.append("the ios job does not materialise the iOS Apple source")
if "apple-client-source.sh checkout macos" in ios:
    problems.append("the ios job checks out the macOS Apple source")
if "apple-client-source.sh checkout macos" not in macos:
    problems.append("the macos job does not check out the macOS Apple source")
if "apple-client-source.sh checkout ios" in macos:
    problems.append("the macos job checks out the iOS Apple source")

# Both jobs must install the shared artifact into their own client directory, and validate
# it against the parent commit only.
for name, body in (("ios", ios), ("macos", macos)):
    if 'apple-libbox-artifact.sh install build/apple-libbox "$APPLE_CLIENT_DIR"' not in body:
        problems.append(f"the {name} job does not install Libbox into its own client dir")
    if "apple-libbox-artifact.sh validate build/apple-libbox" not in body:
        problems.append(f"the {name} job does not validate the Libbox artifact")
    if "--submodule-sha" in body:
        problems.append(
            f"the {name} job still binds the Libbox artifact to an Apple revision; the two "
            "platforms use different ones"
        )

if "check-apple-source-selection.sh" not in libbox and "check-apple-source-selection.sh" not in ios:
    problems.append("the source selection suite does not run in CI")

# Neither SHA may be hardcoded in the workflow: the pin file and the gitlink own them.
for name, body in (("ios", ios), ("macos", macos)):
    for token in ("d1224bb5", "14f015e1"):
        if token in body:
            problems.append(f"the {name} job hardcodes an Apple revision ({token})")

# Every variable the job's later steps read out of the environment must be exported into it.
# The BUILD-INFO and summary steps run under `set -u`, so a name referenced there but never
# written to $GITHUB_ENV aborts the job rather than printing an empty value.
EXPORTED = (
    "APPLE_CLIENT_REPOSITORY",
    "APPLE_CLIENT_PLATFORM",
    "APPLE_CLIENT_DIR",
    "APPLE_CLIENT_SHA",
    "APPLE_CLIENT_BRANCH",
    "APPLE_CLIENT_UI",
)
for name, body in (("ios", ios), ("macos", macos)):
    for variable in EXPORTED:
        if f'echo "{variable}=' not in body:
            problems.append(f"the {name} job never exports {variable} into its environment")

# Libbox must still be compiled exactly once, in the shared job.
if "build-apple-libbox.sh both" not in libbox:
    problems.append("the libbox job does not build the framework")
if "build-apple-libbox.sh both" in ios or "build-apple-libbox.sh both" in macos:
    problems.append("a platform job compiles Libbox instead of consuming the shared artifact")

if problems:
    print("apple source selection: the workflow is not wired correctly.", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    raise SystemExit(1)

print("  PASS: the ios job builds only from the iOS source")
print("  PASS: the macos job builds only from the macOS source")
print("  PASS: the macos job never materialises the iOS source")
print("  PASS: neither job hardcodes an Apple revision")
print("  PASS: both jobs consume the one shared Libbox artifact")
PY
if [ $? -eq 0 ]; then
  pass=$((pass + 5))
else
  fail=$((fail + 1))
fi

# ---------------------------------------------------------------------------
# 3. Behavioural: the resolver, in a scratch repository
# ---------------------------------------------------------------------------
echo "== the resolver, against local fixtures =="

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/scripts/ci" "$scratch/release"
cp scripts/ci/apple-client-source.sh "$scratch/scripts/ci/"

# --- a fake Apple repository with ONE reviewed branch ------------------------
#
# Both platforms build the same commit now, so the fixture has a single reviewed branch
# plus a second commit it can move a branch tip to. `other` is a commit the reviewed
# branch does NOT contain, which is what the on-branch check has to refuse.
apple_origin="$scratch/fixtures/apple.git"
apple_work="$scratch/fixtures/apple-work"
shared_branch="jiejiebox/integrated"
git init -q --bare "$apple_origin"
git init -q "$apple_work"
git -C "$apple_work" config user.email probe@example.invalid
git -C "$apple_work" config user.name probe
git -C "$apple_work" config commit.gpgsign false

printf 'one\n' > "$apple_work/file.txt"
git -C "$apple_work" add file.txt
git -C "$apple_work" commit -qm "first"
apple_sha_fixture="$(git -C "$apple_work" rev-parse HEAD)"

git -C "$apple_work" branch -M "$shared_branch"

# A commit that exists and is on its OWN branch, for the "not on the declared branch"
# case, and for proving that a branch tip moving does not move the resolved source.
git -C "$apple_work" checkout -q "$apple_sha_fixture"
printf 'two\n' >> "$apple_work/file.txt"
git -C "$apple_work" commit -qam "on other only"
other_sha="$(git -C "$apple_work" rev-parse HEAD)"
git -C "$apple_work" branch other "$other_sha"
git -C "$apple_work" checkout -q "$shared_branch"

git -C "$apple_work" remote add origin "$apple_origin"
git -C "$apple_work" push -q origin "$shared_branch" other

# --- a fake parent repository, with the iOS source as a gitlink --------------
git init -q "$scratch"
git -C "$scratch" config user.email probe@example.invalid
git -C "$scratch" config user.name probe
git -C "$scratch" config commit.gpgsign false
git clone -q "$apple_origin" "$scratch/clients/apple"
git -C "$scratch/clients/apple" checkout -q "$apple_sha_fixture"
git -C "$scratch" add clients/apple

write_refs() {
  cat > "$scratch/release/apple-client-refs.env" <<EOF
APPLE_CLIENT_REPOSITORY=$apple_origin
APPLE_CLIENT_BRANCH=$shared_branch
IOS_APPLE_BRANCH=hako-ui
EOF
}

write_refs
git -C "$scratch" commit -qm "parent with the Apple gitlink"

resolver="$scratch/scripts/ci/apple-client-source.sh"
gitlink_of() { git -C "$scratch" ls-tree HEAD clients/apple | awk '{print $3}'; }

echo "== the selection resolves to ONE source =="

check "the iOS source is the parent gitlink" \
  bash -c "test \"\$($resolver sha ios)\" = \"$(gitlink_of)\""
check "the macOS source is the SAME commit" \
  bash -c "test \"\$($resolver sha macos)\" = \"\$($resolver sha ios)\""
check "both platforms resolve to the fixture commit" \
  bash -c "test \"\$($resolver sha ios)\" = '$apple_sha_fixture'"
check "the shared-source invariant holds" "$resolver" assert-shared-source

# Requirement: a change to the parent gitlink must change BOTH platforms' source.
git -C "$scratch/clients/apple" checkout -q "$other_sha"
git -C "$scratch" add clients/apple
git -C "$scratch" commit -qm "move the Apple gitlink"
check "changing the parent gitlink changes the iOS source" \
  bash -c "test \"\$($resolver sha ios)\" = '$other_sha'"
check "and changes the macOS source with it" \
  bash -c "test \"\$($resolver sha macos)\" = '$other_sha'"
check "both sources still equal the gitlink after the move" \
  bash -c "test \"\$($resolver sha ios)\" = \"$(gitlink_of)\" && test \"\$($resolver sha macos)\" = \"$(gitlink_of)\""
# Put it back so the remaining cases use the original commit.
git -C "$scratch/clients/apple" checkout -q "$apple_sha_fixture"
git -C "$scratch" add clients/apple
git -C "$scratch" commit -qm "restore the Apple gitlink"
check "the shared-source invariant holds again" "$resolver" assert-shared-source

# Requirement (fail closed): a checkout that is not the gitlink must be refused.
git -C "$scratch/clients/apple" checkout -q "$other_sha"
expects_fail "an iOS checkout that is not the gitlink is refused" "$resolver" verify ios
git -C "$scratch/clients/apple" checkout -q "$apple_sha_fixture"
check "the iOS checkout verifies once it matches" "$resolver" verify ios

echo "== the macOS tree is a copy of the SAME commit, not a second source =="

check "the macOS source checks out at the gitlink" \
  bash -c "test \"\$($resolver checkout macos)\" = '$apple_sha_fixture'"
check "the macOS checkout is at that same commit" \
  bash -c "test \"\$(git -C '$scratch/build/apple-client-macos' rev-parse HEAD)\" = '$apple_sha_fixture'"
check "the macOS tree is at the same commit as the iOS tree" \
  bash -c "test \"\$(git -C '$scratch/build/apple-client-macos' rev-parse HEAD)\" = \"\$(git -C '$scratch/clients/apple' rev-parse HEAD)\""

# Requirement: moving the gitlink must move the macOS tree too - there is no independent
# macOS source that could stay behind.
#
# The fixture advances the reviewed branch first and THEN pins the new commit, which is what
# a real re-pin looks like: a commit that is on no branch is refused by the on-branch check,
# so pinning one would be testing the refusal rather than the follow.
git -C "$apple_work" checkout -q "$shared_branch"
printf 'four\n' >> "$apple_work/file.txt"
git -C "$apple_work" commit -qam "advance the reviewed branch"
advanced_sha="$(git -C "$apple_work" rev-parse HEAD)"
git -C "$apple_work" push -q origin "$shared_branch"

git -C "$scratch/clients/apple" fetch -q origin "$shared_branch"
git -C "$scratch/clients/apple" checkout -q "$advanced_sha"
git -C "$scratch" add clients/apple
git -C "$scratch" commit -qm "re-pin to the advanced commit"
check "moving the gitlink moves the macOS source" \
  bash -c "test \"\$($resolver sha macos)\" = '$advanced_sha'"
check "the macOS copy follows it on checkout" \
  bash -c "test \"\$($resolver checkout macos)\" = '$advanced_sha'"
check "the macOS copy is on the new commit, not the old one" \
  bash -c "test \"\$(git -C '$scratch/build/apple-client-macos' rev-parse HEAD)\" = '$advanced_sha'"
check "the shared-source invariant still holds after the move" "$resolver" assert-shared-source
git -C "$scratch/clients/apple" checkout -q "$apple_sha_fixture"
git -C "$scratch" add clients/apple
git -C "$scratch" commit -qm "restore the gitlink"

# Requirement: a branch tip that moves must NOT move the resolved source. The reviewed
# branch is advanced again on the remote, and the resolver must still answer with the gitlink.
echo "== a moving branch tip does not move the release source =="
git -C "$apple_work" checkout -q "$shared_branch"
printf 'five\n' >> "$apple_work/file.txt"
git -C "$apple_work" commit -qam "advance the reviewed branch again"
tip_sha="$(git -C "$apple_work" rev-parse HEAD)"
git -C "$apple_work" push -q origin "$shared_branch"
check "a branch tip that moved past the pin does not change the iOS source" \
  bash -c "test \"\$($resolver sha ios)\" = '$apple_sha_fixture'"
check "nor the macOS source" \
  bash -c "test \"\$($resolver sha macos)\" = '$apple_sha_fixture'"
check "the checkout did not follow the branch tip" \
  bash -c "test \"\$($resolver checkout macos)\" != '$tip_sha'"

echo "== the selection fails closed =="

expects_fail "a missing refs file is refused" \
  bash -c "mv '$scratch/release/apple-client-refs.env' '$scratch/release/refs.bak' && \
           $resolver sha macos; rc=\$?; \
           mv '$scratch/release/refs.bak' '$scratch/release/apple-client-refs.env'; exit \$rc"

# The two-source model is the thing this migration removed, so its reappearance must be a
# hard failure rather than a value that happens to be ignored.
expects_fail "a macOS-specific Apple SHA in the refs file is refused" \
  bash -c "printf 'APPLE_CLIENT_REPOSITORY=%s\nAPPLE_CLIENT_BRANCH=%s\nMACOS_APPLE_SHA=0000000000000000000000000000000000000000\n' \
             '$apple_origin' '$shared_branch' > '$scratch/release/apple-client-refs.env'; \
           $resolver sha macos; rc=\$?; \
           write_refs; exit \$rc"

expects_fail "a macOS-specific Apple branch in the refs file is refused" \
  bash -c "printf 'APPLE_CLIENT_REPOSITORY=%s\nAPPLE_CLIENT_BRANCH=%s\nMACOS_APPLE_BRANCH=dev\n' \
             '$apple_origin' '$shared_branch' > '$scratch/release/apple-client-refs.env'; \
           $resolver sha macos; rc=\$?; \
           write_refs; exit \$rc"

expects_fail "an unreachable commit is refused" \
  bash -c "git -C '$scratch/clients/apple' checkout -q '$other_sha' && \
           git -C '$scratch' add clients/apple && \
           git -C '$scratch' commit -qm 'unreachable gitlink' && \
           git -C '$scratch/clients/apple' checkout -q '$other_sha'; \
           $resolver checkout macos; rc=\$?; \
           git -C '$scratch/clients/apple' checkout -q '$apple_sha_fixture'; \
           git -C '$scratch' add clients/apple; git -C '$scratch' commit -qm 'restore'; exit \$rc"

# The gitlink is read from the COMMIT, so the removal has to be committed for this to be the
# case it claims to test - `git rm --cached` alone would leave HEAD unchanged.
expects_fail "a parent commit with no iOS gitlink is refused" \
  bash -c "before=\$(git -C '$scratch' rev-parse HEAD); \
           git -C '$scratch' rm -q --cached clients/apple; \
           git -C '$scratch' commit -qm 'drop the iOS gitlink'; \
           $resolver sha ios; rc=\$?; \
           git -C '$scratch' reset -q --hard \"\$before\"; \
           exit \$rc"

# ---------------------------------------------------------------------------
# 4. The two clients are proven to share one Libbox
# ---------------------------------------------------------------------------
echo "== the shared Libbox check is wired in =="

check "the shared-Libbox checker exists" test -x scripts/ci/check-apple-shared-libbox.sh
check "release-apple verifies both clients link one Libbox" \
  grep -q 'check-apple-shared-libbox.sh' scripts/release-apple.sh

# Every invocation of a platform builder in release-apple.sh must carry an explicit
# APPLE_CLIENT_DIR. The scripts default to `clients/apple`, which is the iOS source, so an
# unqualified call would silently build the macOS product from the custom iOS UI.
python3 - <<'PY'
import re
import sys

src = open("scripts/release-apple.sh", encoding="utf-8").read()
lines = src.splitlines()

problems = []
# A builder invocation is any line whose command mentions one of these scripts.
pattern = re.compile(r"scripts/ci/build-(ios|macos)-(ipa|dmg|testflight)\.sh")
for index, line in enumerate(lines):
    if not pattern.search(line):
        continue
    window = "\n".join(lines[max(0, index - 3): index + 1])
    if "APPLE_CLIENT_DIR=" not in window:
        problems.append(f"line {index + 1}: {line.strip()}")

if problems:
    print("release-apple: a platform builder is invoked without APPLE_CLIENT_DIR:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    raise SystemExit(1)
print("  PASS: every release-apple platform build names its Apple source")
PY
if [ $? -eq 0 ]; then
  pass=$((pass + 1))
else
  fail=$((fail + 1))
fi

# And the iOS and macOS builders must be pointed at DIFFERENT directories.
check "release-apple points the iOS builder at the iOS source" \
  bash -c "grep -q 'APPLE_CLIENT_DIR=\"\$ios_client_dir\"' scripts/release-apple.sh"
check "release-apple points the macOS builder at the macOS source" \
  bash -c "grep -q 'APPLE_CLIENT_DIR=\"\$macos_client_dir\"' scripts/release-apple.sh"
check "publish verifies both clients link one Libbox" \
  grep -q 'check-apple-shared-libbox.sh' scripts/publish-apple-beta.sh

echo
echo "check-apple-source-selection: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
