#!/usr/bin/env bash
# Tie the Apple ABI probe's witnesses back to the REAL client source.
#
# `apple-abi-probe.sh` compiles three extracted witness files against a freshly
# built Libbox.xcframework. A green probe therefore proves exactly one thing:
# *those three files* type-check. It does not prove that the witnesses still
# correspond to the client, that the client they came from is the revision the
# Core pins, or that every caller of a migrated accessor was migrated. This
# script is that missing half.
#
# It checks, in order:
#
#   1. GITLINK      the Core's `clients/apple` gitlink resolves to a real commit
#                   in the Apple clone, and which refs carry it.
#   2. PATCH TIE    every `index <old>..<new>` line of the three patches named
#                   by the witnesses matches the pinned tree, so the patch text
#                   is the pinned text and not a stale draft. A patch whose
#                   post-image is not the pinned blob is reported as a
#                   PREIMAGE_DRAFT and must still trace to a commit that made
#                   the same change.
#   3. ANCHORS      every declaration/expression a witness depends on appears in
#                   the pinned file text (tier 1), or in the patch's added
#                   lines when the patch is tied to the pin by blob hash
#                   (tier 2). It must also appear in the live checkout (tiers 3
#                   and 4), otherwise the probe is validating text the product
#                   no longer contains.
#   4. COVERAGE     every call site of a migrated bound accessor in the live
#                   client is in the migrated shape. This is the check a witness
#                   structurally cannot make: a witness only contains the call
#                   sites someone remembered to extract.
#   5. CHECKOUT     the live checkout IS the pinned revision. If it is not, a
#                   green probe says nothing about the tree that gets built.
#
# Exit status:
#   0  every check passed
#   1  at least one FAIL finding
#   2  usage / environment error (no Apple clone, unreadable framework, ...)
#
# Findings that are known-open gaps can be downgraded to warnings with
# APPLE_ABI_PROVENANCE_ALLOW_GAPS=1, which turns exit 1 into exit 0 while still
# printing them. That switch exists so this script can be wired into a job
# before the gaps are closed; it is not a way to make a red run green silently.
#
# Usage:
#   apple-abi-provenance.sh [--apple-clone DIR] [--core-rev REV] [--framework DIR] [--audit]
#
# Environment:
#   APPLE_CLIENT_DIR              the Apple fork clone (default: <core>/clients/apple
#                                 when it is a populated checkout, else <core>/../repos/apple)
#   APPLE_ABI_CORE_REV            the Core revision whose gitlink is checked (default HEAD)
#   APPLE_LIBBOX_XCFRAMEWORK      when set, the migrated accessor declarations are also
#                                 read out of the shipped Libbox.objc.h
#   APPLE_ABI_PROVENANCE_ALLOW_GAPS=1   downgrade FAIL to WARN
#   APPLE_ABI_CHECK_REMOTE=1      also confirm the gitlink resolves on the fork's remote
#                                 (needs github.com; skipped by default because it is slow
#                                 and this environment's link to github.com is unreliable)
set -euo pipefail

here_core="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
apple=""
core_rev="HEAD"
framework="${APPLE_LIBBOX_XCFRAMEWORK:-}"
allow_gaps="${APPLE_ABI_PROVENANCE_ALLOW_GAPS:-0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --apple-clone) apple="${2:?--apple-clone needs a directory}"; shift 2 ;;
    --core-rev) core_rev="${2:?--core-rev needs a revision}"; shift 2 ;;
    --framework) framework="${2:?--framework needs a directory}"; shift 2 ;;
    --audit) allow_gaps=1; shift ;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

core_rev="${APPLE_ABI_CORE_REV:-$core_rev}"

# --- locating the Apple clone -------------------------------------------------
if [ -z "$apple" ]; then
  for candidate in "$here_core/clients/apple" "$here_core/../repos/apple"; do
    if [ -d "$candidate/.git" ] || [ -f "$candidate/.git" ]; then apple="$candidate"; break; fi
  done
fi
if [ -z "$apple" ] || [ ! -e "$apple/.git" ]; then
  echo "FAIL: no Apple client clone. Pass --apple-clone DIR or set APPLE_CLIENT_DIR." >&2
  echo "      The Core's clients/apple is a gitlink; a bare worktree has an empty directory there." >&2
  exit 2
fi
apple="$(cd "$apple" && pwd)"

# Never let a partial clone try to fetch while we are only reading history unless
# the caller says the network is up: a blob:none clone with an unreachable remote
# hangs on a lazy fetch instead of failing, and a hang is worse than a skip.
# With APPLE_ABI_ALLOW_LAZY_FETCH=1 the pinned blobs can be read out of the
# promisor remote, which is what promotes the anchors from tier 2 to tier 1.
if [ "${APPLE_ABI_ALLOW_LAZY_FETCH:-0}" = "1" ]; then
  g() { git -C "$apple" "$@"; }
else
  g() { GIT_NO_LAZY_FETCH=1 git -C "$apple" "$@"; }
fi

fails=0
warns=0
report() { printf '%-4s %-12s %s\n' "$1" "$2" "$3"; }
pass() { report PASS "$1" "$2"; }
warn() { warns=$((warns + 1)); report WARN "$1" "$2"; }
fail() {
  fails=$((fails + 1))
  if [ "$allow_gaps" = "1" ]; then report WARN "$1" "$2"; else report FAIL "$1" "$2"; fi
}
skip() { report SKIP "$1" "$2"; }

need() { # need <tool>
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: $1 is required" >&2; exit 2; }
}
need git
need awk

patches_dir="$here_core/docs/fork"
witness_dir="$here_core/scripts/ci/apple-abi-probe"

echo "core:         $here_core"
echo "core rev:     $core_rev ($(git -C "$here_core" rev-parse --short "$core_rev" 2>/dev/null || echo '?'))"
echo "apple clone:  $apple"
echo "witnesses:    $witness_dir"
[ -n "$framework" ] && echo "framework:    $framework"
echo

# =============================================================================
# 1. GITLINK
# =============================================================================
echo "== 1. the clients/apple gitlink"
gitlink="$(git -C "$here_core" ls-tree "$core_rev" clients/apple | awk '{print $3}')"
if [ -z "$gitlink" ]; then
  fail GITLINK "no clients/apple gitlink at $core_rev"
  gitlink=""
else
  report INFO GITLINK "core $core_rev pins clients/apple = $gitlink"
  if g cat-file -e "$gitlink^{commit}" 2>/dev/null; then
    pass GITLINK "the pin resolves to a commit object in $apple"
    g log -1 --format='     subject:  %s%n     date:     %ci' "$gitlink" | sed 's/^/     /'
    echo "     refs carrying it:"
    while read -r ref; do
      [ -n "$ref" ] && echo "       $ref"
    done < <(g for-each-ref --contains "$gitlink" --format='%(refname)' 2>/dev/null)
    # Is it the tip of a branch or a tag? A gitlink to a commit that only exists
    # on an unmerged feature branch is a different product statement than a
    # gitlink to a release tag, so say which one it is.
    tagged="$(g tag --points-at "$gitlink" 2>/dev/null | tr '\n' ' ')"
    [ -n "$tagged" ] && report INFO GITLINK "pointed at by tag(s): $tagged"
  else
    fail GITLINK "the pin $gitlink does NOT resolve in $apple (fetch the fork, or the pin is wrong)"
  fi
fi

if [ "${APPLE_ABI_CHECK_REMOTE:-0}" = "1" ]; then
  echo "     remote check (APPLE_ABI_CHECK_REMOTE=1):"
  if out="$(g ls-remote origin 2>&1)"; then
    if printf '%s' "$out" | grep -q "^$gitlink"; then
      pass GITLINK "origin advertises $gitlink: $(printf '%s' "$out" | grep "^$gitlink" | head -1 | awk '{print $1}')"
      printf '%s\n' "$out" | grep "^$gitlink" | sed 's/^/       /'
    else
      fail GITLINK "origin does not advertise $gitlink"
    fi
  else
    warn GITLINK "git ls-remote origin failed; the remote could not confirm the pin: $(printf '%s' "$out" | head -1)"
  fi
else
  skip GITLINK "remote not queried (set APPLE_ABI_CHECK_REMOTE=1 to query origin; recorded command: git -C $apple ls-remote origin)"
fi

# =============================================================================
# 2. PATCH TIE
#
# For each patch named by a witness, every `index <old>..<new> <path>` line must
# line up with the pinned tree:
#   TREE_MATCH      <new> is the blob the pin's tree carries for <path>
#   PREIMAGE_DRAFT  <new> is not, but <old> is the blob some commit in the pin's
#                   history started from for <path>. That is what an independent
#                   draft against the same base looks like; the patch's hunk text
#                   is then NOT hash-verified and the anchors fall back to tier 2.
#   anything else   FAIL - the patch describes a file the pin does not have.
# =============================================================================
echo
echo "== 2. patch text vs the pinned tree"
patch_files="apple-stringbox-callsites.patch apple-bridge-session-implementer.patch apple-screen-state-observer.patch"

# patch_index_lines <patch> -> "<old> <new> <path>"
patch_index_lines() {
  awk '
    /^diff --git / { p = $4; sub(/^b\//, "", p) }
    /^index / && p != "" { split($2, h, "\\.\\."); print h[1], h[2], p }
  ' "$1"
}

# patch_added_lines <patch> <path> -> the "+" lines of that file's hunks
patch_added_lines() {
  awk -v want="$2" '
    /^diff --git / { p = $4; sub(/^b\//, "", p); inwant = (p == want) }
    inwant && /^\+\+\+/ { next }
    inwant && /^\+/ { print substr($0, 2) }
  ' "$1"
}

# patch_deleted_lines <patch> <path> -> the "-" lines, for the pre-image checks
patch_deleted_lines() {
  awk -v want="$2" '
    /^diff --git / { p = $4; sub(/^b\//, "", p); inwant = (p == want) }
    inwant && /^---/ { next }
    inwant && /^-/ { print substr($0, 2) }
  ' "$1"
}

tied_patches=""   # patches whose every index line is TREE_MATCH
for pname in $patch_files; do
  ppath="$patches_dir/$pname"
  if [ ! -f "$ppath" ]; then
    fail PATCH_TIE "missing patch $ppath (a witness cites it)"
    continue
  fi
  all_tree_match=1
  while read -r old new path; do
    [ -n "$path" ] || continue
    pinblob="$(g rev-parse "$gitlink:$path" 2>/dev/null || true)"
    if [ -z "$pinblob" ]; then
      fail PATCH_TIE "$pname: $path is not in the pinned tree $gitlink"
      all_tree_match=0
      continue
    fi
    case "$pinblob" in
      "$new"*)
        pass PATCH_TIE "$pname: $path post-image $new == pinned blob ${pinblob:0:12}"
        ;;
      *)
        # Independent draft against the same base? Look for a commit in the
        # pin's recent history whose PARENT carries <old> for this path.
        found=""
        while read -r c; do
          pblob="$(g rev-parse "$c^:$path" 2>/dev/null || true)"
          case "$pblob" in
            "$old"*) found="$c"; break ;;
          esac
        done < <(g rev-list -n 60 "$gitlink" 2>/dev/null)
        if [ -n "$found" ]; then
          warn PATCH_TIE "$pname: $path post-image $new != pinned ${pinblob:0:12}; PREIMAGE_DRAFT against $(g rev-parse --short "$found") (pre-image $old matches). Hunk text is NOT hash-verified."
          all_tree_match=0
        else
          fail PATCH_TIE "$pname: $path post-image $new matches neither the pinned blob ${pinblob:0:12} nor any commit's pre-image; the patch does not describe this tree"
          all_tree_match=0
        fi
        ;;
    esac
  done < <(patch_index_lines "$ppath")
  [ "$all_tree_match" = "1" ] && tied_patches="$tied_patches $pname"
done
echo "     hash-tied patches (tier 2 usable):${tied_patches:- (none)}"

# 2b. A patch that CREATES a file can be replayed offline: rebuild the file from
# its "+" lines, hash it as a git blob and compare both to the pinned tree blob
# and to the witness body. That is a byte-exact tie between the witness, the
# patch and the pin, and it is the strongest check available without the pin's
# blobs, which a blob:none clone does not have.
while read -r old new path; do
  [ -n "$path" ] || continue
  [ "$old" = "0000000" ] || continue
  for pname in $patch_files; do
    ppath="$patches_dir/$pname"
    [ -f "$ppath" ] || continue
    replay="$(mktemp)"
    patch_added_lines "$ppath" "$path" >"$replay"
    [ -s "$replay" ] || { rm -f "$replay"; continue; }
    # patch_added_lines already terminates every line, so the replay is byte-exact
    replayed="$(git hash-object --stdin <"$replay")"
    pinned="$(g rev-parse "$gitlink:$path" 2>/dev/null || true)"
    if [ -z "$pinned" ] || [ "$replayed" != "$pinned" ]; then
      rm -f "$replay"
      continue
    fi
    pass WITNESS_BLOB "$pname recreates $path byte-exactly (blob ${replayed:0:12} == pinned)"
    case "$path" in
      *ScreenStateObserver.swift) wfile="$witness_dir/observer.swift" ;;
      *) wfile="" ;;
    esac
    if [ -n "$wfile" ] && [ -f "$wfile" ]; then
      body="$(mktemp)"
      awk 'p { print } /^#if os\(iOS\)$/ { p = 1; print }' "$wfile" >"$body"
      if cmp -s "$replay" "$body"; then
        pass WITNESS_BLOB "the compiled witness $(basename "$wfile") body is byte-identical to that pinned file"
      else
        fail WITNESS_BLOB "the compiled witness $(basename "$wfile") body differs from the pinned $path"
      fi
      rm -f "$body"
    fi
    rm -f "$replay"
  done
done < <(for pname in $patch_files; do patch_index_lines "$patches_dir/$pname"; done)

# =============================================================================
# 3. ANCHORS
#
# Each witness mirrors text that must exist in a real client file. The table is
# the machine-checkable form of the witness header comments.
#
#   witness | real file | literal that must appear | cited patch
# =============================================================================
echo
echo "== 3. witness anchors vs the real client declarations"

anchors="$(mktemp)"
trap 'rm -f "$anchors"' EXIT
cat >"$anchors" <<'EOF'
callsites.swift	ApplicationLibrary/Views/Abstract/GlobalChecksModifier.swift	message: report.message()!.value	apple-stringbox-callsites.patch
callsites.swift	HelperService/RootHelperService.swift	session.name()!.value as NSString	apple-stringbox-callsites.patch
callsites.swift	JailbreakDaemon/IOSRootHelperService.swift	session.name()!.value	apple-stringbox-callsites.patch
callsites.swift	Library/Network/BridgeTunTracker.swift	closing bridge \(session.name()!.value	apple-stringbox-callsites.patch
callsites.swift	Library/Network/ExtensionPlatformInterface.swift	ipv4Prefix.address()!.value	apple-stringbox-callsites.patch
callsites.swift	Library/Network/ExtensionPlatformInterface.swift	ipv4Prefix.mask()!.value	apple-stringbox-callsites.patch
callsites.swift	Library/Network/ExtensionPlatformInterface.swift	options.getHTTPProxyServer()!.value	apple-stringbox-callsites.patch
callsites.swift	Library/Network/ExtensionPlatformInterface.swift	options.getDNSMode()!.value	apple-stringbox-callsites.patch
implementer.swift	Library/Network/ExtensionPlatformInterface.swift	func name() -> LibboxStringBox?	apple-bridge-session-implementer.patch
implementer.swift	Library/Network/ExtensionPlatformInterface.swift	LibboxStringBox()	apple-bridge-session-implementer.patch
observer.swift	Library/Network/ScreenStateObserver.swift	notify_register_dispatch("com.apple.iokit.hid.displayStatus"	apple-screen-state-observer.patch
observer.swift	Library/Network/ScreenStateObserver.swift	commandServer.recordScreenState(state == 1)	apple-screen-state-observer.patch
observer.swift	Library/Network/ScreenStateObserver.swift	commandServer.recordLockState(state == 1)	apple-screen-state-observer.patch
EOF

tier1_hits=0
tier2_hits=0
tier3_hits=0
tier4_hits=0
unattributed=0

while IFS=$'\t' read -r witness path anchor patch; do
  [ -n "$anchor" ] || continue
  where=""

  # tier 1: the pinned file text itself, when this clone actually has the blob
  if g cat-file -e "$gitlink:$path" 2>/dev/null; then
    if g show "$gitlink:$path" 2>/dev/null | grep -Fq -- "$anchor"; then
      where="tier1:pin"; tier1_hits=$((tier1_hits + 1))
    fi
  fi

  # tier 2: the cited patch's added lines, only when that patch is hash-tied
  case " $tied_patches " in
    *" $patch "*) ;;
    *)
      if [ -z "$where" ]; then
        # Fall back to the patch anyway, but say so: the text is attributed, not verified.
        if patch_added_lines "$patches_dir/$patch" "$path" | grep -Fq -- "$anchor"; then
          where="tier2:patch-unverified"; tier2_hits=$((tier2_hits + 1))
        fi
      fi
      ;;
  esac
  if [ -z "$where" ]; then
    if patch_added_lines "$patches_dir/$patch" "$path" | grep -Fq -- "$anchor"; then
      where="tier2:patch"; tier2_hits=$((tier2_hits + 1))
    fi
  fi

  # tier 3: the live working tree - what a build would actually compile
  if [ -f "$apple/$path" ] && grep -Fq -- "$anchor" "$apple/$path"; then
    [ -z "$where" ] && { where="tier3:worktree"; tier3_hits=$((tier3_hits + 1)); }
  fi

  # tier 4: the live checkout's committed HEAD
  if g cat-file -e "HEAD:$path" 2>/dev/null && g show "HEAD:$path" 2>/dev/null | grep -Fq -- "$anchor"; then
    [ -z "$where" ] && { where="tier4:checkout-head"; tier4_hits=$((tier4_hits + 1)); }
  fi

  if [ -z "$where" ]; then
    fail ANCHOR "$witness: '$anchor' is in NEITHER the pinned text, the cited patch, nor the live checkout ($path)"
    continue
  fi

  # Attribution: the witness header says the text came from the cited patch.
  # An anchor that exists in the real source but not in the patch it names is a
  # provenance claim that is simply wrong, even when the code is fine.
  if ! patch_added_lines "$patches_dir/$patch" "$path" | grep -Fq -- "$anchor"; then
    unattributed=$((unattributed + 1))
    fail ANCHOR "$witness: '$anchor' is NOT in the cited $patch (found only in $where); the witness header names the wrong source"
  else
    pass ANCHOR "$witness: '$anchor' [$where, cited by $patch]"
  fi
done <"$anchors"

# The witnesses are only meaningful if the framework really declares the boxed
# results they depend on. When a framework is supplied, read that out of the
# shipped header rather than trusting the probe's green run.
if [ -n "$framework" ]; then
  header="$(ls "$framework"/*/Libbox.framework/Headers/Libbox.objc.h 2>/dev/null | head -1 || true)"
  if [ -z "$header" ]; then
    warn ABI_HEADER "no Libbox.objc.h under $framework; the declaration check was skipped"
  else
    for acc in name message address mask getHTTPProxyServer getDNSMode; do
      if grep -qE "^\- \(LibboxStringBox\* _Nullable\)$acc;" "$header"; then
        pass ABI_HEADER "shipped header declares - (LibboxStringBox* _Nullable)$acc"
      else
        fail ABI_HEADER "shipped header does NOT declare $acc as returning LibboxStringBox* ($header)"
      fi
    done
  fi
fi

# =============================================================================
# 4. COVERAGE
#
# The witness contains the call sites someone extracted. This sweeps the live
# client for EVERY call site of the migrated accessors and reports the ones that
# are still in the pre-migration shape. Against a framework whose accessors
# return LibboxStringBox*, each of those is a compile error in the real target -
# which is exactly what a green witness run hides.
# =============================================================================
echo
echo "== 4. caller coverage in the live client"
accessors="message name address mask getHTTPProxyServer getDNSMode"
sweep="$(mktemp)"
unmigrated=0
# shellcheck disable=SC2016
find "$apple" -name '*.swift' -not -path '*/Frameworks/*' -not -path '*/.git/*' -print0 2>/dev/null |
  xargs -0 awk -v accs="$accessors" '
    BEGIN { n = split(accs, A, " ") }
    {
      for (i = 1; i <= n; i++) {
        a = A[i]; pat = "\\." a "\\(\\)"; s = $0
        while (match(s, pat)) {
          after = substr(s, RSTART + RLENGTH, 1)
          if (after == "!") { migrated++ } else { unmigrated++; printf "%s:%d: %s\n", FILENAME, FNR, a }
          s = substr(s, RSTART + RLENGTH)
        }
      }
    }
    END { printf "SUMMARY migrated=%d unmigrated=%d\n", migrated + 0, unmigrated + 0 }
  ' >"$sweep" 2>/dev/null || true

grep -v '^SUMMARY' "$sweep" | sed 's/^/     /' || true
summary="$(grep '^SUMMARY' "$sweep" || echo 'SUMMARY migrated=0 unmigrated=0')"
unmigrated="$(printf '%s' "$summary" | sed -n 's/.*unmigrated=\([0-9]*\).*/\1/p')"
migrated_n="$(printf '%s' "$summary" | sed -n 's/.*migrated=\([0-9]*\).*/\1/p')"
if [ "${unmigrated:-0}" = "0" ]; then
  pass COVERAGE "all $migrated_n call site(s) of the migrated accessors are in the migrated shape"
else
  # one finding per file: a finding per site would bury the summary in repetition
  while IFS= read -r file; do
    sites="$(grep -F "$file:" "$sweep" | awk -F: '{printf "%s:%s ", $2, $3}')"
    fail COVERAGE "${file#"$apple"/} has unmigrated accessor call(s) at line:accessor $sites - these do not compile against a Libbox whose accessor returns LibboxStringBox*"
  done < <(grep -v '^SUMMARY' "$sweep" | awk -F: '{print $1}' | sort -u)
fi

# =============================================================================
# 5. CHECKOUT
# =============================================================================
echo
echo "== 5. is the live checkout the pinned revision?"
head_sha="$(g rev-parse HEAD 2>/dev/null || echo '?')"
if [ -n "$gitlink" ] && [ "$head_sha" = "$gitlink" ]; then
  pass CHECKOUT "the checkout is the pinned revision"
else
  fail CHECKOUT "the checkout HEAD is ${head_sha:0:12}, the Core pins ${gitlink:0:12}; a green probe validates the pin, not the tree that would be built"
fi
if [ -n "$(g status --porcelain 2>/dev/null)" ]; then
  warn CHECKOUT "the checkout has uncommitted changes; the anchors above were read from the working tree"
fi
# Which lineage is pinned, and does it carry the migration commits at all?
if [ -n "$gitlink" ] && g cat-file -e "$gitlink^{commit}" 2>/dev/null; then
  for c in $(g log -n 6 --format='%h' "$gitlink" 2>/dev/null); do
    printf '     %s\n' "$(g log -1 --format='%h %ci %s' "$c")"
  done
fi

# The counter-check to section 4: sweep the PINNED revision the same way. A gap of
# "pinned=0 unmigrated, checkout=N unmigrated" is the whole finding in one line, and
# it is the difference between "the migration is missing" and "the migration is not
# checked out". Only possible when the pin's blobs can be read.
if [ "${APPLE_ABI_ALLOW_LAZY_FETCH:-0}" = "1" ] && [ -n "$gitlink" ]; then
  pinned_sweep="$(mktemp -d)"
  pinned_paths="$(for pname in $patch_files; do
    awk '/^diff --git /{p=$4; sub(/^b\//,"",p); print p}' "$patches_dir/$pname"
  done | sort -u)"
  got_any=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    mkdir -p "$pinned_sweep/$(dirname "$path")"
    if g show "$gitlink:$path" >"$pinned_sweep/$path" 2>/dev/null; then got_any=1; fi
  done <<<"$pinned_paths"
  if [ "$got_any" = "1" ]; then
    psum="$(find "$pinned_sweep" -name '*.swift' -print0 2>/dev/null | xargs -0 awk -v accs="$accessors" '
      BEGIN { n = split(accs, A, " ") }
      { for (i = 1; i <= n; i++) { a = A[i]; pat = "\\." a "\\(\\)"; s = $0
          while (match(s, pat)) { after = substr(s, RSTART + RLENGTH, 1)
            if (after == "!") { m++ } else { u++ }
            s = substr(s, RSTART + RLENGTH) } } }
      END { printf "migrated=%d unmigrated=%d", m + 0, u + 0 }')"
    p_unmig="$(printf '%s' "$psum" | sed -n 's/.*unmigrated=\([0-9]*\).*/\1/p')"
    if [ "${p_unmig:-1}" = "0" ]; then
      pass COVERAGE "the pinned revision itself has 0 unmigrated accessor call sites ($psum), so the gap above is the checkout, not the migration"
    else
      fail COVERAGE "the pinned revision itself has $p_unmig unmigrated accessor call site(s) ($psum); the migration is incomplete at the pin"
    fi
  else
    skip COVERAGE "the pinned file text could not be read; the pinned-revision sweep was skipped"
  fi
  rm -rf "$pinned_sweep"
fi

# =============================================================================
echo
echo "---- provenance summary ----"
echo "tier1 (pinned blob text) anchors: $tier1_hits"
echo "tier2 (patch added lines) anchors: $tier2_hits"
echo "tier3 (live worktree) anchors:    $tier3_hits"
echo "tier4 (checkout HEAD) anchors:    $tier4_hits"
echo "misattributed anchors:            $unattributed"
echo "unmigrated call sites:            ${unmigrated:-0}"
echo "FAIL: $fails   WARN: $warns"

if [ "$tier1_hits" = "0" ]; then
  echo
  echo "SCOPE LIMIT: no anchor could be read from the pinned blob text. This clone is a"
  echo "partial clone (blob:none) and the pinned blobs are not local, so the strongest"
  echo "tier was unavailable and the anchors rest on the patch text. Re-run with"
  echo "  APPLE_ABI_ALLOW_LAZY_FETCH=1 (and a working route to the fork) to fetch"
  echo "  ${gitlink:0:12} and raise the verification tier."
fi

if [ "$fails" != "0" ]; then
  echo
  echo "apple-abi-provenance: SOURCE GAP ($fails finding(s))"
  exit 1
fi
echo
echo "apple-abi-provenance: PASS"
