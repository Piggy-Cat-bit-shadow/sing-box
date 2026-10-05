#!/usr/bin/env bash
# Proves which cronet native archive a release build actually links.
#
# # Why this is a release gate and not a formality
#
# cronet-go is not one module. The repository root, `all`, and every `lib/<os>_<arch>` are separate
# Go modules, and a `replace` written for one of them is not inherited by the others. A fork can
# therefore be pinned in the root - source says fork - while a nested module still resolves to
# upstream, and the link quietly puts a fork wrapper on a native archive it was never tested with.
#
# The construction this repository uses is deliberate and is what this gate checks: the module
# PATHS stay upstream (`github.com/sagernet/cronet-go/...`) so imports need no rewriting, and every
# one of them carries its own `replace` to the fork. A module path alone therefore proves nothing -
# the resolved replacement is the fact.
#
# # What it checks
#
#   1. every cronet-go module in the resolved graph has a replace, and the replace is the fork;
#   2. the native archive each replaced module provides, by path, size and SHA256;
#   3. against `release/cronet-provenance.txt` (recorded, checked into the repository), so an
#      archive that changed under a fixed version cannot pass unnoticed.
#
# Usage:
#   scripts/ci/verify-cronet-provenance.sh apple|linux|windows [arch]
#   scripts/ci/verify-cronet-provenance.sh --record apple|linux|windows [arch]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

fork="github.com/Piggy-Cat-bit-shadow/cronet-go"
tags="$(cat release/DEFAULT_BUILD_TAGS_OTHERS)"

record=0
if [ "${1:-}" = "--record" ]; then
    record=1
    shift
fi

platform="${1:-apple}"
arch="${2:-}"
manifest="release/cronet-provenance.txt"

# The slices each product links. Apple links four: the two darwin slices and the two device/simulator
# iOS slices, which is what build-apple-libbox.sh asks the toolchain for.
case "$platform" in
    apple)   globs=('lib/darwin_*' 'lib/ios_*'); goos="darwin" ;;
    linux)   globs=('lib/linux_*');             goos="linux" ;;
    windows) globs=('lib/windows_*');           goos="windows" ;;
    *) echo "unknown platform '$platform' (apple|linux|windows)" >&2; exit 2 ;;
esac

echo "cronet provenance: platform=${platform} arch=${arch:-all} goos=${goos}"
echo "  profile tags: ${tags}"

# 1. The resolved graph, as the module system sees it, with each replacement.
unreplaced=0
not_fork=0
module_lines=()
archive_lines=()
while IFS= read -r path; do
    [ -n "$path" ] || continue
    resolved="$(GOOS="$goos" go list -tags "$tags" -m -f '{{.Path}}{{if .Replace}} => {{.Replace.Path}}@{{.Replace.Version}}{{else}} => NONE{{end}}' "$path" 2>/dev/null || true)"
    [ -n "$resolved" ] || continue
    module_lines+=("$resolved")
    case "$resolved" in
        *"=> NONE"*) unreplaced=$((unreplaced + 1)); continue ;;
    esac
    case "$resolved" in
        *"=> ${fork}"*) ;;
        *) not_fork=$((not_fork + 1)) ;;
    esac

    # 2. Only the slices this platform links, and only through the replaced module directory.
    for glob in "${globs[@]}"; do
        case "$path" in
            */$glob) ;;
            *) continue ;;
        esac
        dir="$(GOOS="$goos" go list -tags "$tags" -m -f '{{.Dir}}' "$path" 2>/dev/null || true)"
        [ -n "$dir" ] && [ -d "$dir" ] || continue
        while IFS= read -r archive; do
            [ -n "$archive" ] || continue
            size="$(wc -c < "$archive" | tr -d ' ')"
            hash="$(shasum -a 256 "$archive" | awk '{print $1}')"
            relative="$(basename "$archive")"
            archive_lines+=("$path $relative $size $hash")
        done < <(find "$dir" -maxdepth 1 \( -name 'libcronet.a' -o -name 'libcronet.dll' \) 2>/dev/null | sort)
    done
done < <(GOOS="$goos" go list -tags "$tags" -m -f '{{.Path}}' all 2>/dev/null | grep 'cronet-go' || true)

if [ "${#module_lines[@]}" -eq 0 ]; then
    echo "FAIL: no cronet-go module resolved for this profile, so nothing can be proven." >&2
    exit 1
fi

printf '  modules (%d):\n' "${#module_lines[@]}"
printf '    %s\n' "${module_lines[@]}"

if [ "$unreplaced" -ne 0 ]; then
    echo "FAIL: $unreplaced cronet-go module(s) have no replace directive." >&2
    echo "      A nested module does not inherit the root module's replace, so this links upstream" >&2
    echo "      while the source says fork." >&2
    exit 1
fi
if [ "$not_fork" -ne 0 ]; then
    echo "FAIL: $not_fork cronet-go module(s) replace to something other than the fork." >&2
    exit 1
fi
echo "  every resolved cronet module replaces to the fork"

if [ "${#archive_lines[@]}" -eq 0 ]; then
    echo "FAIL: no native cronet archive found for the slices this platform links." >&2
    exit 1
fi
printf '  native archives linked by this platform (%d):\n' "${#archive_lines[@]}"
printf '    %s\n' "${archive_lines[@]}"

# 3. Record, or compare.
if [ "$record" -eq 1 ]; then
    {
        echo "# Native cronet archives a release build links, by module path and content."
        echo "#"
        echo "# The module paths are upstream by design; every one of them is replaced with the fork"
        echo "# in go.mod, and this file records WHICH BYTES that resolved to. Regenerate only when"
        echo "# the cronet pin changes:"
        echo "#"
        echo "#   scripts/ci/verify-cronet-provenance.sh --record ${platform}${arch:+ $arch}"
        echo "#"
        echo "# Format: <module-path> <archive> <size-bytes> <sha256>"
        printf '%s\n' "${archive_lines[@]}"
    } > "$manifest"
    echo "  recorded ${#archive_lines[@]} archive(s) in $manifest"
    exit 0
fi

if [ ! -f "$manifest" ]; then
    echo "FAIL: $manifest is missing; record it with --record" >&2
    exit 1
fi

status=0
checked=0
while IFS= read -r expected; do
    case "$expected" in ''|'#'*) continue ;; esac
    checked=$((checked + 1))
    matched=0
    for actual in "${archive_lines[@]}"; do
        if [ "$actual" = "$expected" ]; then
            matched=1
            break
        fi
    done
    if [ "$matched" -eq 1 ]; then
        echo "  ok   $expected"
    else
        echo "  FAIL expected: $expected" >&2
        status=1
    fi
done < "$manifest"

if [ "$checked" -eq 0 ]; then
    echo "FAIL: $manifest records nothing" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "cronet provenance: PASS - the linked archives are the ones the release recorded"
else
    echo "cronet provenance: FAIL - resolved instead:" >&2
    printf '  %s\n' "${archive_lines[@]}" >&2
fi
exit "$status"
