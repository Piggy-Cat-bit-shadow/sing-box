#!/usr/bin/env bash
#
# Nested Go module integrity guard.
#
# # The failure this exists to prevent
#
# This repository has more than one Go module. A nested module does NOT inherit the
# root module's replace directives or its go.sum, so a change to the root dependency
# graph can leave a nested module's go.mod/go.sum stale while every root-level check
# still passes. The breakage then surfaces only when something finally compiles the
# nested module -- which is late, intermittent, and not where the mistake was made.
#
# That has happened here at least three times. It is not something to keep watching for
# by hand, so this script checks every module.
#
# # What it checks
#
# For each module:
#
#   go mod tidy -diff                 go.mod/go.sum are complete and canonical
#   go list -mod=readonly -m all      the whole module graph resolves without modifying go.mod/go.sum
#   go mod verify                     (--verify) downloaded cache content matches go.sum
#
# `-diff` is used instead of plain `tidy` on purpose: this script must never modify the
# working tree and must never "fix" drift by rewriting files. Drift is a FAILURE, and the
# fix belongs in a commit.
#
# # Why `go mod verify` is opt-in
#
# The default run discovers every module and checks its metadata with `tidy -diff` and
# read-only graph resolution. `--verify` additionally checks downloaded module cache
# content against go.sum for every checked module; it is left to the deep run.
#
# Measured warm on this repository:
#
#   default run (tidy -diff + list, all modules)   ~0.5s
#   bare `go mod verify`, all modules summed        ~9s   (4.0 + 4.6 + 0.4)
#   full run with --verify                          ~11s
#
# `go mod verify` re-hashes every module in the cache, which is where essentially all of the
# time goes; the surrounding checks are cheap.
#
# Note the distinction when quoting timings: ~11s is the cost of a full --verify RUN
# (tidy + verify + list + parity), not the cost of `go mod verify` in isolation (~9s here).
# Measure the bare command separately if that is the number wanted.
#
# # Fork replace parity
#
# The modules that depend on the production dependency graph must pin the same fork
# revisions for the packages the fork actually patches. A silent divergence there is the
# specific bug this guard was written for, so it is checked explicitly rather than being
# left to `tidy` (which does not police replace target SHAs across modules).
#
# The reference isolation module is deliberately exempt: its whole purpose is to build a
# reference implementation against its OWN dependency graph, so forcing it to match
# production would destroy the comparison it exists to provide.
#
# Usage:
#   scripts/ci/check-go-module-integrity.sh              # every module, cheap checks
#   scripts/ci/check-go-module-integrity.sh --verify     # add `go mod verify`
#   scripts/ci/check-go-module-integrity.sh --exclude DIR
#   scripts/ci/check-go-module-integrity.sh --require-checked DIR
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Modules whose fork replaces must agree with the root module. These are the modules
# that build the shipped product or test it against the production dependency graph.
PARITY_MODULES=(test)
# Fork modules that must be pinned identically wherever they are replaced.
PARITY_REPLACES=(
    github.com/sagernet/sing
    github.com/sagernet/cronet-go
    github.com/sagernet/quic-go
)
EXCLUDES=()
REQUIRE_CHECKED=()
RUN_VERIFY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --verify) RUN_VERIFY=1; shift ;;
        --exclude) EXCLUDES+=("${2#./}"); shift 2 ;;
        --require-checked) REQUIRE_CHECKED+=("${2#./}"); shift 2 ;;
        -h|--help) sed -n '2,62p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

failures=0
fail() { echo "  FAIL: $*" >&2; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# Discover modules dynamically.
#
# This is the core of the guard: the module list is DERIVED, never hardcoded. A new
# nested go.mod is picked up automatically, so "nobody is checking the new module"
# cannot happen silently.
# ---------------------------------------------------------------------------
discover_modules() {
    find . -name go.mod \
        -not -path './.git/*' \
        -not -path '*/vendor/*' \
        -print | sed 's|/go.mod$||; s|^\./||; s|^$|.|' | sort
}

is_excluded() {
    local module="$1" excluded
    for excluded in "${EXCLUDES[@]:-}"; do
        [ -n "$excluded" ] && [ "$module" = "$excluded" ] && return 0
    done
    return 1
}

# Reads a `replace <module> => <target> <version>` line from a go.mod and prints the FULL
# target: "<path> <version>".
#
# The version must be part of the comparison. Comparing only the path would accept a fork
# pinned to a DIFFERENT revision in one module, which is exactly the silent drift this
# guard exists to catch -- the path stays identical while the code being built differs.
replace_target() {
    local gomod="$1" module="$2"
    [ -f "$gomod" ] || return 1
    awk -v want="$module" '
        $1 == "replace" && $2 == want && $3 == "=>" {
            # A filesystem replace (=> ../x) has no version field; report the path alone.
            if (NF >= 5) { print $4 " " $5 } else { print $4 }
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$gomod"
}

# ---------------------------------------------------------------------------
# 1. Discover
# ---------------------------------------------------------------------------
ALL_MODULES=()
while IFS= read -r module; do
    ALL_MODULES+=("$module")
done < <(discover_modules)

if [ "${#ALL_MODULES[@]}" -eq 0 ]; then
    echo "FAIL: no go.mod found; the discovery itself is broken" >&2
    exit 1
fi

CHECKED_MODULES=()
for module in "${ALL_MODULES[@]}"; do
    if is_excluded "$module"; then
        continue
    fi
    CHECKED_MODULES+=("$module")
done

echo "Go module integrity"
echo "==================="
echo "discovered ${#ALL_MODULES[@]} module(s):"
for module in "${ALL_MODULES[@]}"; do
    marker="checked"
    is_excluded "$module" && marker="excluded"
    echo "  MODULE: ${module}  [${marker}]"
done
echo

# A nested module must never disappear from the checked set by accident. If a caller declares
# a module required, it must actually have been CHECKED -- not merely discovered.
#
# Testing membership in ALL_MODULES is not enough and produced a false green:
#
#   --exclude test --require-checked test
#
# found `test` among the discovered modules, reported success, and never ran a single
# integrity check against it. The requirement is about what was checked, so it is evaluated
# against CHECKED_MODULES, and the two failure modes are reported distinctly:
#
#   not discovered at all  -> the module was renamed or removed
#   discovered but excluded -> the exclusion and the requirement contradict each other
for required in "${REQUIRE_CHECKED[@]:-}"; do
    [ -n "$required" ] || continue

    required_discovered=0
    for module in "${ALL_MODULES[@]}"; do
        [ "$module" = "$required" ] && required_discovered=1
    done

    if [ "$required_discovered" -eq 0 ]; then
        fail "required module '$required' was not discovered; it may have been renamed or removed"
        continue
    fi

    required_checked=0
    for module in "${CHECKED_MODULES[@]}"; do
        [ "$module" = "$required" ] && required_checked=1
    done

    if [ "$required_checked" -eq 0 ]; then
        fail "required module '$required' was discovered but excluded, so it was NOT checked;"$'\n'"        remove it from --exclude or drop the --require-checked requirement"
        continue
    fi

    echo "required module '${required}': checked"
done
echo

# ---------------------------------------------------------------------------
# 2. Per-module integrity
# ---------------------------------------------------------------------------
for module in "${CHECKED_MODULES[@]}"; do
    if [ "$module" = "." ]; then
        dir="$REPO_ROOT"
        label="."
    else
        dir="$REPO_ROOT/$module"
        label="./$module"
    fi

    echo "--- ${label} ---"

    # EVERY command below must run INSIDE the module directory. Running them from the
    # repository root would silently check the ROOT module once per discovered module --
    # a guard that reports "3 modules checked" while only ever inspecting one. That bug is
    # why the module directory is derived here and used for each invocation.

    # go.mod / go.sum must already be canonical. -diff never writes to the tree.
    #
    # Two things make the naive version of this check wrong, and both were hit for real:
    #
    #   1. `go mod tidy -diff` can print the required changes and still exit 0, so the exit
    #      status alone is not a verdict.
    #   2. It writes the ACTUAL DIFF to stdout, but progress noise -- "go: downloading ..."
    #      on a cold module cache -- goes to stderr. Merging the two with 2>&1 makes any
    #      download look like drift, so a clean tree fails on the first CI run.
    #
    # So: capture stdout ONLY, and treat a non-empty result as drift. Stderr is preserved
    # and shown when the command itself fails, which is where genuine errors appear.
    tidy_stderr="$(mktemp)"
    tidy_rc=0
    tidy_diff="$(cd "$dir" && GOWORK=off go mod tidy -diff 2>"$tidy_stderr")" || tidy_rc=$?

    if [ "$tidy_rc" -ne 0 ]; then
        fail "${label}: go mod tidy -diff failed to run (exit ${tidy_rc})"
        sed 's/^/      /' "$tidy_stderr" >&2
    elif [ -n "$tidy_diff" ]; then
        fail "${label}: go mod tidy -diff reports drift; go.mod/go.sum are not canonical"
        printf '%s\n' "$tidy_diff" | sed 's/^/      /' >&2
    else
        echo "  ok: go mod tidy -diff is clean"
    fi
    rm -f "$tidy_stderr"

    # Downloaded module content must match go.sum. Opt-in: see the note at the top.
    if [ "$RUN_VERIFY" -eq 1 ]; then
        if ! (cd "$dir" && GOWORK=off go mod verify >/dev/null 2>&1); then
            fail "${label}: go mod verify failed; module cache content does not match go.sum"
        else
            echo "  ok: go mod verify"
        fi
    fi

    # The entire module graph must resolve without modifying go.mod or go.sum.
    #
    # This is NOT an offline check. -mod=readonly guarantees the module files are left
    # untouched, but on a cold cache it may still download modules to satisfy the graph.
    # Nothing here forces offline resolution (no GOPROXY=off), so do not describe it as
    # network-free.
    if ! (cd "$dir" && GOWORK=off go list -mod=readonly -m all >/dev/null 2>&1); then
        fail "${label}: go list -mod=readonly -m all failed; module graph does not resolve read-only"
    else
        echo "  ok: go list -mod=readonly -m all"
    fi
    echo
done

# ---------------------------------------------------------------------------
# 3. Fork replace parity across production modules
# ---------------------------------------------------------------------------
echo "Fork replace parity"
echo "==================="
for module in "${PARITY_MODULES[@]}"; do
    is_excluded "$module" && continue
    if [ ! -f "$REPO_ROOT/$module/go.mod" ]; then
        fail "parity module '$module' has no go.mod"
        continue
    fi
    for replaced in "${PARITY_REPLACES[@]}"; do
        root_target="$(replace_target "$REPO_ROOT/go.mod" "$replaced" || true)"
        sub_target="$(replace_target "$REPO_ROOT/$module/go.mod" "$replaced" || true)"

        if [ -z "$root_target" ]; then
            # Root does not replace it; nothing to keep in sync.
            continue
        fi
        if [ -z "$sub_target" ]; then
            fail "$module/go.mod does not replace $replaced, but the root module does ($root_target)."$'\n'"        A nested module does NOT inherit root replaces; add the same replace."
            continue
        fi
        if [ "$root_target" != "$sub_target" ]; then
            fail "$replaced fork pin differs between root and $module:"$'\n'"        root: $root_target"$'\n'"        $module: $sub_target"
            continue
        fi
        echo "  ok: $replaced"
        echo "        root:   $root_target"
        echo "        $module: $sub_target"
    done
done
echo

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
if [ "$failures" -gt 0 ]; then
    echo "FAILED: ${failures} module integrity problem(s)." >&2
    exit 1
fi

# Prove the guard actually inspected something. A guard that silently checks zero
# modules is worse than no guard, because it reports success.
if [ "${#CHECKED_MODULES[@]}" -eq 0 ]; then
    echo "FAILED: zero modules were checked." >&2
    exit 1
fi

echo "PASSED: ${#CHECKED_MODULES[@]} module(s) verified."
