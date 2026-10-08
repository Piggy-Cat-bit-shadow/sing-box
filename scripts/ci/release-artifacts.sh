#!/usr/bin/env bash
# Selects the CI runs that built one commit, downloads their artifacts, and proves
# every platform in the release contract is present, unique, hashed and genuine.
#
# Usage:
#   release-artifacts.sh check-tag  --tag TAG
#   release-artifacts.sh plan       --repo R --sha SHA --out FILE [--interval N] [--timeout N]
#   release-artifacts.sh download   --repo R --plan FILE --dir DIR
#   release-artifacts.sh verify     --dir DIR --sha SHA
#   release-artifacts.sh flatten    --plan FILE --dir DIR --out DIR --tag TAG
#   release-artifacts.sh publish-flag --dry-run VALUE
#
# # Why this file exists
#
# The previous release workflow asked `gh run list --limit 60` for the runs on a
# commit and required the answer to be EXACTLY two rows, both `completed`, joined
# into the string "completed,completed". Every part of that is fragile:
#
#   * `--limit 60` is a window over the whole repository, so unrelated activity
#     pushes the target runs out of it and they read as "not built yet";
#   * selecting by workflow NAME breaks silently when a workflow is renamed;
#   * `count == 2` is unsatisfiable as soon as a workflow is re-run for the same
#     commit - which is routine here: 13 of the last 100 commits on each product
#     workflow carry two or three runs - and the loop then spins until its
#     90-minute deadline while both runs are green;
#   * a commit with NO runs at all took the same path, so the job burned the full
#     90 minutes before saying so.
#
# That is not hypothetical. Run 37811184607 (tag v1.15.0-alpha.7) printed
# "runs: 0" every 30 seconds from 16:44:51Z to 18:14:55Z and then failed with
# "did not complete within 90 minutes".
#
# This script replaces the whole thing:
#
#   * runs are queried BY WORKFLOW ID AND COMMIT SHA through the API, so an
#     unrelated run cannot displace them and a renamed file is caught by the
#     path assertion in resolve_workflow_id;
#   * the newest run per workflow decides. A completed non-success fails at once
#     - a failed or cancelled run is never papered over by an older green one;
#   * zero runs fails immediately with the exact dispatch command to run;
#   * only a run that is genuinely still executing is waited for, with an
#     explicit interval and deadline;
#   * downloads are not wrapped in `|| true`;
#   * each platform must independently have its binary, its .sha256, its
#     BUILD-INFO and a passing `sha256sum -c`, plus a byte-level check that the
#     binary is the architecture the name claims.
#
# Every branch below is exercised by scripts/ci/test-release-artifacts.sh against
# a mock `gh`, so the matrix can be verified without waiting for a real 90-minute
# release.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/lib.sh"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# The release contract
# ---------------------------------------------------------------------------
#
# Exactly the products this fork ships from an automated build: the Linux amd64
# Server Edition and the macOS arm64 core. Windows, Android and the Apple IPA/DMG
# are deliberately NOT here - pulling them into the release is a product decision,
# not a bug fix, and a third artifact that nobody verified would be worse than a
# missing one.

TARGET_WORKFLOWS=(
  ".github/workflows/server-linux-amd64.yml"
  ".github/workflows/client-macos.yml"
)

# target_field <workflow file> <field>
#
# One row per product, so a field cannot be added for one platform and forgotten
# for the other. An unknown workflow is an error rather than a default: a default
# here would let a third workflow slip into the release unnoticed.
target_field() {
  local wf="$1" field="$2"
  case "$wf:$field" in
    .github/workflows/server-linux-amd64.yml:binary)    echo "sing-box-linux-amd64" ;;
    .github/workflows/server-linux-amd64.yml:buildinfo) echo "BUILD-INFO-LINUX.txt" ;;
    .github/workflows/server-linux-amd64.yml:magic)     echo "elf-x86-64" ;;
    .github/workflows/server-linux-amd64.yml:platform)  echo "linux" ;;
    .github/workflows/server-linux-amd64.yml:arch)      echo "amd64" ;;
    .github/workflows/server-linux-amd64.yml:tarball)   echo "jiejie-sing-box-linux-amd64" ;;

    .github/workflows/client-macos.yml:binary)          echo "sing-box-darwin-arm64" ;;
    .github/workflows/client-macos.yml:buildinfo)       echo "BUILD-INFO-MACOS.txt" ;;
    .github/workflows/client-macos.yml:magic)           echo "macho-arm64" ;;
    .github/workflows/client-macos.yml:platform)        echo "darwin" ;;
    .github/workflows/client-macos.yml:arch)            echo "arm64" ;;
    .github/workflows/client-macos.yml:tarball)         echo "jiejie-sing-box-macos-arm64" ;;

    *) die "the release contract has no '$field' for workflow '$wf'" ;;
  esac
}

# Statuses GitHub may report. Anything that is not a completed run is waited for;
# anything completed that is not `success` fails the release.
is_in_flight() {
  case "$1" in
    queued | in_progress | pending | requested | waiting) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# GitHub access
# ---------------------------------------------------------------------------

# resolve_workflow_id <repo> <workflow file>
#
# Prints the numeric workflow id. The path returned by the API is asserted to be
# the file we named, so a workflow that was renamed or replaced by one with a
# different path fails here instead of silently resolving to a different product.
#
# The API accepts a workflow's file NAME or its numeric id but not a repository
# path, so only the basename is sent; the full path we expect is then asserted
# against what came back.
resolve_workflow_id() {
  local repo="$1" file="$2" row id path state
  if ! row="$(gh api "repos/$repo/actions/workflows/$(basename "$file")" --jq '[.id, .path, .state] | @tsv')"; then
    die "cannot resolve workflow '$file' in '$repo'. Check the repository name and that the workflow still exists."
  fi
  IFS=$'\t' read -r id path state <<<"$row"
  [ -n "${id:-}" ] || die "workflow '$file' resolved to an empty id"
  [ "$path" = "$file" ] || die \
    "workflow '$file' resolved to id $id at path '$path'. The release contract names workflows by file, so a moved or renamed workflow must be updated there deliberately."
  [ "$state" = "active" ] || die "workflow '$file' is '$state', not active"
  printf '%s\n' "$id"
}

# newest_run <repo> <workflow id> <sha>
#
# Prints one TSV row for the NEWEST run of that workflow on that exact commit,
# or nothing when the commit has no run of it. The query is filtered by
# head_sha server-side, so it does not matter how many other runs exist or how
# the API orders them.
newest_run() {
  local repo="$1" wfid="$2" sha="$3" rows
  # `.conclusion` is null while a run is in progress, and the API is documented to
  # use null rather than "" - but both are normalised to "-" here, because `//`
  # alone does NOT substitute for an empty string, and a tab-separated EMPTY field
  # is consumed by `read`: tab is IFS whitespace, so `read` collapses runs of it and
  # every later field shifts left by one, silently turning the workflow id into the
  # head SHA.
  local conclusion_field='(if (.conclusion // "") == "" then "-" else .conclusion end)'
  if ! rows="$(gh api --paginate \
      "repos/$repo/actions/workflows/$wfid/runs?head_sha=$sha&per_page=100" \
      --jq ".workflow_runs[] | [.id, .run_number, .status, $conclusion_field, .created_at, .html_url, .head_sha, .workflow_id] | @tsv")"; then
    die "the GitHub API query for workflow $wfid on $sha failed. Refusing to continue: an unreadable answer is not a green one."
  fi
  [ -n "$rows" ] || return 0

  local row
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    # awk counts an empty field where bash `read` would silently consume it, so
    # this is the guard that notices a shift instead of trusting it.
    [ "$(printf '%s' "$row" | awk -F'\t' '{print NF}')" -eq 8 ] || die \
      "the API returned a run row with the wrong number of fields:
      $row"
    printf '%s\n' "$row"
  done <<<"$rows" | sort -t$'\t' -k2,2n -k1,1n | tail -n 1
}

# ---------------------------------------------------------------------------
# check-tag
# ---------------------------------------------------------------------------
#
# Validates the tag's shape, resolves it, and proves the commit it points at is
# the commit that was checked out - so the artifacts verified later cannot belong
# to a different commit than the tag being released.
#
# The shape check is also the injection guard: the tag reaches this script through
# an environment variable, and anything outside this alphabet is refused before it
# can be used in a path, a URL or an argument.
cmd_check_tag() {
  local tag=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --tag) tag="${2:-}"; shift 2 ;;
      *) die "check-tag: unknown argument '$1'" ;;
    esac
  done
  [ -n "$tag" ] || die "check-tag: --tag is required"

  case "$tag" in
    v[0-9]*) ;;
    *) die "tag '$tag' is not a release tag: it must start with 'v' followed by a digit" ;;
  esac
  # Only characters that are safe in a URL, a path and a git ref. This rejects
  # whitespace, ';', '$(', backticks, '/', '..' and a leading '-'.
  #
  # Matched with bash's own pattern matching rather than `printf | grep -q`: grep
  # exits as soon as it matches, which can kill the writer with SIGPIPE, and
  # `set -o pipefail` then reports the pipeline as FAILED - so the unsafe tag
  # would be the one that slipped through.
  if [[ "$tag" = *[!0-9A-Za-z._+-]* ]]; then
    die "tag '$tag' contains characters outside [0-9A-Za-z._+-]"
  fi
  case "$tag" in
    *..*) die "tag '$tag' contains '..'" ;;
  esac

  local tag_sha head_sha
  if ! tag_sha="$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}")"; then
    die "tag '$tag' does not exist in this checkout, or does not point at a commit. Push the tag, or check out with fetch-depth 0 and fetch-tags."
  fi
  if ! head_sha="$(git rev-parse --verify --quiet HEAD)"; then
    die "cannot resolve HEAD in this checkout"
  fi
  [ "$tag_sha" = "$head_sha" ] || die \
    "tag '$tag' points at $tag_sha but the checked-out commit is $head_sha. Releasing would attach artifacts built from one commit to a tag naming another."

  printf '%s\n' "$tag_sha"
  note "tag $tag -> $tag_sha (matches the checked-out commit)"
}

# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------
#
# Waits for both product workflows on the commit and writes the selected runs to
# a plan file. The plan is the ONLY thing the download step reads, so the run that
# was judged is the run that is unpacked - the two steps cannot disagree.
#
# Plan columns: workflow_file, workflow_id, run_id, run_number, status,
#               conclusion, head_sha, html_url

cmd_plan() {
  local repo="" sha="" out="" interval=30 timeout=5400
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --repo) repo="${2:-}"; shift 2 ;;
      --sha) sha="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      --interval) interval="${2:-}"; shift 2 ;;
      --timeout) timeout="${2:-}"; shift 2 ;;
      *) die "plan: unknown argument '$1'" ;;
    esac
  done
  [ -n "$repo" ] || die "plan: --repo is required"
  [ -n "$sha" ] || die "plan: --sha is required"
  [ -n "$out" ] || die "plan: --out is required"
  case "$interval" in ''|*[!0-9]*) die "plan: --interval must be a whole number of seconds" ;; esac
  case "$timeout" in ''|*[!0-9]*) die "plan: --timeout must be a whole number of seconds" ;; esac

  mkdir -p "$(dirname "$out")"
  : > "$out"

  local deadline=$(( $(date +%s) + timeout ))
  local wf wfid newest pending
  while :; do
    : > "$out"
    pending=0
    for wf in "${TARGET_WORKFLOWS[@]}"; do
      wfid="$(resolve_workflow_id "$repo" "$wf")"
      newest="$(newest_run "$repo" "$wfid" "$sha")"

      if [ -z "$newest" ]; then
        # Fail fast with something to DO. The old workflow waited 90 minutes for
        # runs that were never going to appear: run 37811184607 sat on "runs: 0"
        # from 16:44:51Z until its deadline at 18:14:55Z.
        die "no run of $wf exists for commit $sha, so there is nothing to release.
      The release attaches artifacts that CI built; it does not build them.
      Request those builds for this commit, then dispatch the release again:
$(for f in "${TARGET_WORKFLOWS[@]}"; do printf '        gh workflow run %s --repo %s --ref %s\n' "$(basename "$f")" "$repo" "$sha"; done)"
      fi

      local rid rnum status conclusion created url rsha rwfid
      IFS=$'\t' read -r rid rnum status conclusion created url rsha rwfid <<<"$newest"

      # Defence in depth: the query filtered by SHA server-side, and every row is
      # checked again here, so a wrong artifact source cannot reach the release.
      # The shape checks catch a shifted parse (see newest_run) before the values
      # are compared, so the failure names the real problem.
      [[ "$rwfid" =~ ^[0-9]+$ ]] || die "could not read the workflow id of the newest run of $wf (got '$rwfid'); the API row was not in the expected shape:
      $newest"
      [[ "$rsha" =~ ^[0-9a-f]{40}$ ]] || die "could not read the commit of the newest run of $wf (got '$rsha'); the API row was not in the expected shape:
      $newest"
      [ "$rsha" = "$sha" ] || die "the newest run of $wf reports head_sha $rsha, not $sha"
      [ "$rwfid" = "$wfid" ] || die "the newest run of $wf reports workflow_id $rwfid, not $wfid"

      if is_in_flight "$status"; then
        note "  $wf: run $rid is $status - waiting up to ${timeout}s (every ${interval}s)"
        note "        $url"
        pending=$((pending + 1))
        continue
      fi
      if [ "$status" != "completed" ]; then
        die "the newest run of $wf for $sha is in unexpected status '$status' (run $rid). $url"
      fi
      case "$conclusion" in
        success) ;;
        skipped)
          die "the newest run of $wf for $sha was SKIPPED (run $rid). A skipped workflow did not verify anything, so it cannot gate a release. $url" ;;
        *)
          die "the newest run of $wf for $sha did not succeed: conclusion=$conclusion (run $rid). Re-run it and dispatch the release again. $url" ;;
      esac

      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$wf" "$wfid" "$rid" "$rnum" "$status" "$conclusion" "$sha" "$url" >> "$out"
      note "  $wf: selected run $rid (#$rnum) $conclusion  $url"
    done

    [ "$pending" -eq 0 ] && break

    if [ "$(date +%s)" -ge "$deadline" ]; then
      die "timed out after ${timeout}s waiting for ${pending} of ${#TARGET_WORKFLOWS[@]} product workflow(s) on $sha to finish. The runs above are still going; check them and dispatch the release again."
    fi
    sleep "$interval"
  done

  local lines
  lines="$(grep -c . "$out" || true)"
  [ "$lines" -eq "${#TARGET_WORKFLOWS[@]}" ] || die \
    "the release plan has $lines row(s), expected ${#TARGET_WORKFLOWS[@]}. Refusing to release a partial product."

  note "PASS: every product workflow succeeded for $sha"
}

# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------

cmd_download() {
  local repo="" plan="" dir=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --repo) repo="${2:-}"; shift 2 ;;
      --plan) plan="${2:-}"; shift 2 ;;
      --dir) dir="${2:-}"; shift 2 ;;
      *) die "download: unknown argument '$1'" ;;
    esac
  done
  [ -n "$repo" ] || die "download: --repo is required"
  [ -n "$plan" ] || die "download: --plan is required"
  [ -n "$dir" ] || die "download: --dir is required"
  [ -s "$plan" ] || die "download: the release plan '$plan' is empty; nothing was verified for this commit"

  rm -rf "$dir"
  mkdir -p "$dir"

  local rows=0
  local wf wfid rid rnum status conclusion sha url binary dest subdirs files row
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    # See newest_run: an empty field would shift the rest of the row, and here that
    # would mean downloading a run that was never verified. awk counts an empty
    # field where `read` would silently consume it.
    [ "$(printf '%s' "$row" | awk -F'\t' '{print NF}')" -eq 8 ] || die \
      "the release plan has a malformed row:
      $row"
    IFS=$'\t' read -r wf wfid rid rnum status conclusion sha url <<<"$row"
    binary="$(target_field "$wf" binary)"
    # One directory per product, named for the binary it must contain, so a
    # second run of the other workflow can never overwrite this one.
    dest="$dir/$binary"
    mkdir -p "$dest"
    note "downloading run $rid ($wf) -> $dest"
    # NOT wrapped in `|| true`: a download that failed leaves the artifact
    # unverified, and an unverified artifact must not be publishable.
    if ! gh run download "$rid" --repo "$repo" --dir "$dest"; then
      die "gh run download failed for run $rid ($wf). $binary is NOT verified; refusing to continue."
    fi
    subdirs="$(find "$dest" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    [ "$subdirs" -eq 1 ] || die \
      "run $rid produced $subdirs artifact directories in $dest, expected exactly 1. The shipped file set must be deterministic."
    files="$(find "$dest" -type f | wc -l | tr -d ' ')"
    [ "$files" -gt 0 ] || die "run $rid downloaded no files into $dest"
    rows=$((rows + 1))
  done < "$plan"

  [ "$rows" -eq "${#TARGET_WORKFLOWS[@]}" ] || die \
    "downloaded $rows run(s), expected ${#TARGET_WORKFLOWS[@]}"
  note "PASS: downloaded artifacts from $rows verified run(s)"
}

# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

# check_sha256_file <dir> <sumfile basename>
#
# Actually verifies, in the directory the sumfile describes. `sha256sum -c` on the
# Linux runner, `shasum -a 256 -c` here, so the same check can be run locally.
check_sha256_file() {
  local dir="$1" sum="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$dir" && sha256sum -c "$sum" )
  elif command -v shasum >/dev/null 2>&1; then
    ( cd "$dir" && shasum -a 256 -c "$sum" )
  else
    echo "FAIL: neither sha256sum nor shasum is available to verify $sum" >&2
    return 1
  fi
}

# check_magic <file> <kind>
#
# Reads the architecture out of the FILE, so a binary that is present, hashed and
# documented but built for the wrong platform cannot pass on the strength of its
# name. `od -N` is used rather than `head -c`: an early-exiting reader on the other
# end of a pipe raises SIGPIPE, which `set -o pipefail` reports as a failure.
check_magic() {
  local file="$1" kind="$2" hex
  hex="$(od -An -tx1 -N 20 "$file" | tr -d ' \n')"
  case "$kind" in
    elf-x86-64)
      [ "${hex:0:8}" = "7f454c46" ] || { echo "FAIL: $(basename "$file") is not an ELF file (magic '${hex:0:8}')" >&2; return 1; }
      [ "${hex:36:4}" = "3e00" ] || { echo "FAIL: $(basename "$file") is ELF but not x86-64 (e_machine '${hex:36:4}', want '3e00')" >&2; return 1; }
      ;;
    macho-arm64)
      [ "${hex:0:8}" = "cffaedfe" ] || { echo "FAIL: $(basename "$file") is not a 64-bit little-endian Mach-O (magic '${hex:0:8}')" >&2; return 1; }
      [ "${hex:8:8}" = "0c000001" ] || { echo "FAIL: $(basename "$file") is Mach-O but not arm64 (cputype '${hex:8:8}', want '0c000001')" >&2; return 1; }
      ;;
    *) echo "FAIL: unknown platform magic '$kind'" >&2; return 1 ;;
  esac
  return 0
}

# count_files <find args...> - prints the number of matches, 0 when there are none.
count_files() {
  local n
  n="$(find "$@" | wc -l | tr -d ' ')"
  printf '%s\n' "$n"
}

# verify_platform <dir> <sha> <workflow file>
#
# Every requirement is enforced PER PLATFORM. A hash for Linux does not stand in
# for a hash for macOS, which is what the old single loop allowed.
verify_platform() {
  local dir="$1" sha="$2" wf="$3"
  local binary buildinfo magic platform arch
  binary="$(target_field "$wf" binary)"
  buildinfo="$(target_field "$wf" buildinfo)"
  magic="$(target_field "$wf" magic)"
  platform="$(target_field "$wf" platform)"
  arch="$(target_field "$wf" arch)"

  note "--- $platform/$arch ($wf)"

  local n bin sum info
  n="$(count_files "$dir" -type f -name "$binary")"
  [ "$n" -eq 1 ] || die "$binary: found $n copies under $dir, expected exactly 1"
  bin="$(find "$dir" -type f -name "$binary")"

  n="$(count_files "$dir" -type f -name "$binary.sha256")"
  [ "$n" -eq 1 ] || die "$binary.sha256: found $n copies under $dir, expected exactly 1. Every platform must carry its own checksum."
  sum="$(find "$dir" -type f -name "$binary.sha256")"

  n="$(count_files "$dir" -type f -name "$buildinfo")"
  [ "$n" -eq 1 ] || die "$buildinfo: found $n copies under $dir, expected exactly 1"
  info="$(find "$dir" -type f -name "$buildinfo")"

  local bin_dir sum_dir info_dir
  bin_dir="$(dirname "$bin")"
  sum_dir="$(dirname "$sum")"
  info_dir="$(dirname "$info")"
  [ "$bin_dir" = "$sum_dir" ] && [ "$bin_dir" = "$info_dir" ] || die \
    "$binary, $binary.sha256 and $buildinfo are not in the same artifact directory. They must travel together."

  # Empty files are a real failure mode of an interrupted upload.
  local size
  size="$(wc -c < "$bin" | tr -d ' ')"
  [ "$size" -gt 0 ] || die "$binary is empty (0 bytes)"

  check_magic "$bin" "$magic" || die "$binary is not a $platform/$arch executable"

  check_sha256_file "$bin_dir" "$(basename "$sum")" || die \
    "$binary.sha256 does not match $binary. The published checksum would not verify the published binary."

  # The sidecar must name THIS commit. A binary from a different commit can share
  # the artifact name, so the recorded commit is what ties the bytes to the tag.
  local recorded
  recorded="$(sed -n 's/^git_commit:[[:space:]]*//p' "$info")"
  [ -n "$recorded" ] || die "$buildinfo has no git_commit line"
  [ "$recorded" = "$sha" ] || die \
    "$buildinfo records git_commit $recorded, but the release is verifying $sha. These bytes were built from a different commit."

  local recorded_platform recorded_arch
  recorded_platform="$(sed -n 's/^platform:[[:space:]]*//p' "$info")"
  recorded_arch="$(sed -n 's/^arch:[[:space:]]*//p' "$info")"
  [ "$recorded_platform" = "$platform" ] || die "$buildinfo records platform '$recorded_platform', expected '$platform'"
  [ "$recorded_arch" = "$arch" ] || die "$buildinfo records arch '$recorded_arch', expected '$arch'"

  # The artifact's own hash, as recorded at build time, must agree with the bytes
  # that were downloaded. This catches a truncated or substituted transfer.
  local recorded_sha actual_sha
  recorded_sha="$(sed -n 's/^artifact_sha256:[[:space:]]*//p' "$info")"
  [ -n "$recorded_sha" ] || die "$buildinfo has no artifact_sha256 line"
  actual_sha="$(sha256_of "$bin")"
  [ "$recorded_sha" = "$actual_sha" ] || die \
    "$buildinfo records artifact_sha256 $recorded_sha, but the downloaded $binary hashes to $actual_sha"

  note "    $binary  $size bytes  sha256=$actual_sha"
  note "    verified: binary, checksum, build info, platform magic, commit $sha"
}

cmd_verify() {
  local dir="" sha=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --sha) sha="${2:-}"; shift 2 ;;
      *) die "verify: unknown argument '$1'" ;;
    esac
  done
  [ -n "$dir" ] || die "verify: --dir is required"
  [ -n "$sha" ] || die "verify: --sha is required"
  [ -d "$dir" ] || die "verify: '$dir' does not exist"

  local wf
  for wf in "${TARGET_WORKFLOWS[@]}"; do
    verify_platform "$dir" "$sha" "$wf"
  done

  # Nothing outside the contract may reach the release. The allowlist is derived
  # from the same table that produced the checks above, so a third product cannot
  # appear in the tarballs without being added to the contract deliberately.
  local allowed=() wf f unexpected=""
  allowed+=( LICENSE )
  for wf in "${TARGET_WORKFLOWS[@]}"; do
    allowed+=( "$(target_field "$wf" binary)" "$(target_field "$wf" binary).sha256" "$(target_field "$wf" buildinfo)" )
  done
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    local ok=0 a
    for a in "${allowed[@]}"; do
      [ "$f" = "$a" ] && ok=1
    done
    [ "$ok" -eq 1 ] || unexpected="${unexpected}${f}"$'\n'
  done < <(find "$dir" -type f -exec basename {} \;)
  if [ -n "$unexpected" ]; then
    die "unexpected file(s) in the release tree:
$(printf '      %s\n' $unexpected)
      The shipped file set must be exactly the verified one."
  fi

  note "PASS: both platforms verified against commit $sha"
}

# ---------------------------------------------------------------------------
# flatten
# ---------------------------------------------------------------------------

cmd_flatten() {
  local plan="" dir="" out="" tag=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --plan) plan="${2:-}"; shift 2 ;;
      --dir) dir="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      --tag) tag="${2:-}"; shift 2 ;;
      *) die "flatten: unknown argument '$1'" ;;
    esac
  done
  [ -n "$plan" ] || die "flatten: --plan is required"
  [ -n "$dir" ] || die "flatten: --dir is required"
  [ -n "$out" ] || die "flatten: --out is required"
  [ -n "$tag" ] || die "flatten: --tag is required"
  case "$tag" in
    v[0-9]*) ;;
    *) die "flatten: '$tag' is not a release tag" ;;
  esac
  # Re-checked here because the tag is interpolated into an output FILENAME; see
  # the note in cmd_check_tag for why this is a bash glob and not `grep -q`.
  if [[ "$tag" = *[!0-9A-Za-z._+-]* ]]; then
    die "flatten: tag '$tag' contains unsafe characters"
  fi

  rm -rf "$out"
  mkdir -p "$out"

  local wf binary buildinfo prefix src expected actual
  for wf in "${TARGET_WORKFLOWS[@]}"; do
    binary="$(target_field "$wf" binary)"
    buildinfo="$(target_field "$wf" buildinfo)"
    prefix="$(target_field "$wf" tarball)"
    src="$(dirname "$(find "$dir" -type f -name "$binary")")"

    # The archive contents are pinned to an allowlist, so what a downloader gets
    # is a known, small set that has been verified - not "whatever was in the
    # artifact directory".
    expected="$(printf '%s\n%s\n%s\n%s\n' "$binary" "$binary.sha256" "$buildinfo" LICENSE | sort)"
    actual="$(find "$src" -maxdepth 1 -type f -exec basename {} \; | sort)"
    [ "$actual" = "$expected" ] || die \
      "artifact directory for $binary holds an unexpected file set.
    expected:
$(printf '      %s\n' $expected)
    actual:
$(printf '      %s\n' $actual)"

    tar -C "$src" -czf "$out/${prefix}-${tag}.tar.gz" .
    note "packaged $out/${prefix}-${tag}.tar.gz"
  done

  # One manifest over the tarballs. `./`-prefixed names, matching the format the
  # previous releases published, so existing verification instructions still work.
  (
    cd "$out"
    : > SHA256SUMS
    for archive in ./*.tar.gz; do
      printf '%s  %s\n' "$(sha256_of "$archive")" "$archive" >> SHA256SUMS
    done
  )

  local archives
  archives="$(count_files "$out" -maxdepth 1 -type f -name '*.tar.gz')"
  [ "$archives" -eq "${#TARGET_WORKFLOWS[@]}" ] || die \
    "flatten produced $archives tarball(s), expected ${#TARGET_WORKFLOWS[@]}"

  note "release assets:"
  ( cd "$out" && ls -la . && cat SHA256SUMS )
}

# ---------------------------------------------------------------------------
# publish-flag
# ---------------------------------------------------------------------------
#
# Turns the dry_run input into an explicit publish decision. Anything that is not
# exactly `true` or `false` is refused, so a malformed or missing input fails
# closed instead of publishing a release by accident.

cmd_publish_flag() {
  local dry=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run) dry="${2:-}"; shift 2 ;;
      *) die "publish-flag: unknown argument '$1'" ;;
    esac
  done
  case "$dry" in
    true) echo "false" ;;
    false) echo "true" ;;
    *) die "the dry_run input must be exactly 'true' or 'false', got '${dry:-<empty>}'. Refusing to guess whether this run may publish." ;;
  esac
}

# ---------------------------------------------------------------------------

main() {
  [ "$#" -gt 0 ] || die "usage: release-artifacts.sh <check-tag|plan|download|verify|flatten|publish-flag> [args]"
  local sub="$1"
  shift
  case "$sub" in
    check-tag) cmd_check_tag "$@" ;;
    plan) cmd_plan "$@" ;;
    download) cmd_download "$@" ;;
    verify) cmd_verify "$@" ;;
    flatten) cmd_flatten "$@" ;;
    publish-flag) cmd_publish_flag "$@" ;;
    *) die "unknown subcommand '$sub'" ;;
  esac
}

main "$@"
