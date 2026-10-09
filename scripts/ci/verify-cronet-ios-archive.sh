#!/usr/bin/env bash
# Gate: the pinned cronet-go iOS archive must not contain an undefined base:: symbol
# that nothing in the archive defines.
#
# # Why this exists
#
# `github.com/Piggy-Cat-bit-shadow/cronet-go/lib/ios_arm64` ships `libcronet.a` in which
# `features.o` references `base::MessagePumpKqueue::InitializeFeatures()` while
# `message_pump_kqueue.o` - the only member that defines it - is a macOS-only object and
# is not in the iOS archive at all. The reference therefore survives into the shipped
# Libbox.framework for iOS as an unresolved `U`. A link WITHOUT dead stripping fails on it:
#
#   "base::MessagePumpKqueue::InitializeFeatures()", referenced from:
#       base::features::Init() in Libbox[arm64][119](features.o)
#
# # Why it is still tracked even though the product currently builds
#
# The real Apple client does link today: `project.pbxproj` sets `DEAD_CODE_STRIPPING = YES`
# and the real link lines carry `-dead_strip`, so `features.o` is never extracted and the
# linked `sing-box.debug.dylib` contains zero `MessagePumpKqueue` symbols. The product is
# green BY ACCIDENT, and the accident is load-bearing: it stops the moment anything makes
# `base::features::Init()` live - one of the 769 symbols `features.o` defines, an
# `-all_load`/`-force_load`, an ObjC `+load`, a target that does not dead-strip, or a
# third-party consumer of the framework.
#
# So the correct verdict is DEAD_CODE_ONLY, not "the archive is unusable": a proven
# incomplete artifact that is currently masked by the linker. That is exactly the kind of
# thing this gate exists to keep visible.
#
# It is the ONLY such hole in the iOS archive: every other intra-`base::` symbol is
# either defined in the archive or absent from it entirely. The macOS archive has zero.
# That is what makes a narrow, mechanical gate possible instead of a broad audit.
#
# # What it checks
#
# For the resolved archive (and, with --libbox, the shipped iOS Libbox slice):
#
#   unresolved_base = { s in undefined(s) : s starts with __ZN4base, s not in defined(s) }
#
# and fails if that set is non-empty, printing every symbol demangled. `__ZN3net` is
# reported alongside it for context but is expected to be empty too.
#
# # THIS GATE IS RED TODAY, ON PURPOSE
#
# The defect is real and tracked (see docs/../reports/S03-apple-abi-cronet.md, item 4).
# The gate fails until the dependency build is fixed; that is the point of adding it -
# a green run here means the archive is self-contained, not that nobody looked.
# CRONET_IOS_ARCHIVE_TRACKED_DEFECT=1 downgrades the failure to a loud "KNOWN DEFECT
# (tracked)" record while STILL printing the full symbol list and still exiting through
# the same code path, so it cannot be confused with a clean archive in a log.
#
# Usage:
#   verify-cronet-ios-archive.sh [--core DIR] [--archive PATH] [--libbox XCFRAMEWORK]
#
# Environment:
#   CRONET_IOS_ARCHIVE_TRACKED_DEFECT=1   record the known defect instead of failing
set -euo pipefail

core="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
archive=""
libbox=""
tracked="${CRONET_IOS_ARCHIVE_TRACKED_DEFECT:-0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --core) core="${2:?}"; shift 2 ;;
    --archive) archive="${2:?}"; shift 2 ;;
    --libbox) libbox="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: $1 is required" >&2; exit 2; }; }
need nm
need ar
need c++filt

# --- resolving the pinned archive ---------------------------------------------
# The pin is read out of go.mod rather than hardcoded, so a re-pin silently changes
# what this gate inspects instead of leaving it pointing at a stale version.
#
#   replace <module> => <fork-module> <version>
#
# The REPLACEMENT path is what the module cache is keyed by, not the original.
module_path="github.com/sagernet/cronet-go/lib/ios_arm64"
resolve_pin() { # -> "<fork-module> <version>", or empty when not pinned
  awk -v want="$1" '
    $1 == "replace" && $2 == want && $3 == "=>" { print $4, $5; exit }
  ' "$core/go.mod"
}
escaped_module_path() {
  printf '%s' "$1" | awk '{ out = ""
    for (i = 1; i <= length($0); i++) {
      c = substr($0, i, 1)
      out = out (c ~ /[A-Z]/ ? "!" tolower(c) : c)
    }
    print out }'
}

if [ -z "$archive" ]; then
  pin="$(resolve_pin "$module_path")"
  if [ -z "$pin" ]; then
    echo "NOTE: go.mod does not pin $module_path; the iOS archive is not part of this build." >&2
    echo "verify-cronet-ios-archive: SKIP (not pinned)"
    exit 0
  fi
  fork_path="${pin% *}"
  version="${pin##* }"
  modcache="$(go env GOMODCACHE)"
  escaped="$(escaped_module_path "$fork_path")"
  extracted="$modcache/$escaped@$version/libcronet.a"
  zip="$modcache/cache/download/$escaped/@v/$version.zip"
  echo "module:  $module_path"
  echo "replace: $fork_path"
  echo "pin:     $version"
  if [ -f "$extracted" ]; then
    archive="$extracted"
  elif [ -f "$zip" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    unzip -o -j "$zip" '*/libcronet.a' -d "$tmp" >/dev/null
    archive="$tmp/libcronet.a"
    echo "source:  extracted from $zip"
  else
    echo "FAIL: neither $extracted nor $zip exists; run 'go mod download $module_path' first." >&2
    exit 2
  fi
fi

echo "archive: $archive"
echo "sha256:  $(shasum -a 256 "$archive" | awk '{print $1}')"
echo "size:    $(stat -f %z "$archive") bytes, $(ar t "$archive" 2>/dev/null | wc -l | tr -d ' ') members"
echo

# The intra-namespace hole, computed on the archive as the static linker will see it.
ALL_HOLES=""
check_archive() { # <archive> <label>
  local a="$1" label="$2"
  local defined undefined
  defined="$(mktemp)"; undefined="$(mktemp)"
  nm --defined-only -A "$a" 2>/dev/null | awk '{print $NF}' | sort -u >"$defined"
  nm --undefined-only -A "$a" 2>/dev/null | awk '{print $NF}' | sort -u >"$undefined"

  echo "== $label"
  for ns in '__ZN4base' '__ZN3net'; do
    local holes n
    holes="$(comm -23 "$undefined" "$defined" | grep "^$ns" || true)"
    n=0
    [ -n "$holes" ] && n="$(printf '%s\n' "$holes" | wc -l | tr -d ' ')"
    if [ "$n" = "0" ]; then
      echo "   $ns  undefined-and-nowhere-defined: 0"
    else
      echo "   $ns  undefined-and-nowhere-defined: $n"
      while IFS= read -r sym; do
        [ -n "$sym" ] || continue
        printf '        %s\n' "$sym"
        printf '          = %s\n' "$(printf '%s' "$sym" | c++filt)"
        # Name the member that wants it, so the fix has an address.
        nm -A --undefined-only "$a" 2>/dev/null | grep -F " $sym" | sed 's/^/          from /'
      done <<<"$holes"
      [ "$ns" = "__ZN4base" ] && ALL_HOLES="$ALL_HOLES$holes"$'\n'
    fi
  done
  rm -f "$defined" "$undefined"
}
check_archive "$archive" "cronet-go $(basename "$(dirname "$archive")") archive"

if [ -n "$libbox" ]; then
  echo
  slice="$libbox/ios-arm64/Libbox.framework/Versions/A/Libbox"
  [ -f "$slice" ] || slice="$libbox/ios-arm64/Libbox.framework/Libbox"
  if [ ! -f "$slice" ]; then
    echo "FAIL: no ios-arm64 Libbox binary under $libbox" >&2
    exit 2
  fi
  # A fat wrapper confuses nm; thin it first.
  if file "$slice" | grep -q 'universal binary'; then
    thinned="$(mktemp -d)/Libbox-ios-arm64.a"
    lipo -thin arm64 "$slice" -output "$thinned"
    slice="$thinned"
  fi
  echo "libbox:  $libbox (ios-arm64)"
  check_archive "$slice" "shipped Libbox ios-arm64 slice"
fi

echo
if [ -z "$ALL_HOLES" ]; then
  echo "verify-cronet-ios-archive: PASS (the archive is self-contained for base:: symbols)"
  exit 0
fi

cat <<'EOF'
--------------------------------------------------------------
KNOWN DEFECT (tracked): cronet-go iOS archive is not self-contained
--------------------------------------------------------------
Cause:   features.o is compiled with an Apple-wide guard that still names
         base::MessagePumpKqueue, while message_pump_kqueue.cc - the only
         definition - is compiled for macOS only, so the member is absent from
         the iOS archive. The reference therefore reaches the shipped iOS
         Libbox static archive as an unresolved `U`.
Verdict: DEAD_CODE_ONLY - the real client links because DEAD_CODE_STRIPPING=YES
         drops features.o entirely (verified: the linked sing-box.debug.dylib
         has 0 MessagePumpKqueue symbols). The green build is an accident of
         dead stripping, and it is load-bearing: it breaks as soon as anything
         makes base::features::Init() live, or a consumer links without
         -dead_strip.
Fix:     guard the MessagePumpKqueue::InitializeFeatures() call to the same
         macOS-only condition, rebuild the iOS archives, re-pin. Runbook:
         reports/S03-apple-abi-cronet.md, item 5.
Status:  BLOCKED_TOOLCHAIN - the archive rebuild needs the Chromium/cronet
         build pipeline, which is not available in this environment.
Do NOT:  adopt -dead_strip as the fix. It hides the symbol per consumer while
         the framework still ships the dangling reference; the archive must be
         rebuilt self-contained instead.
EOF

if [ "$tracked" = "1" ]; then
  echo
  echo "verify-cronet-ios-archive: KNOWN DEFECT (tracked) - recorded, not resolved"
  exit 0
fi
echo
echo "verify-cronet-ios-archive: FAIL ($(printf '%s\n' "$ALL_HOLES" | grep -c .) unresolved base:: symbol hit(s); see the symbol list above)"
exit 1
