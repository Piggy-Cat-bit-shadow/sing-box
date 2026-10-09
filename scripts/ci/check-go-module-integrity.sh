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
# ## Why the parity set is DERIVED and why there is a second list anyway
#
# The set of modules to compare used to be the hand-written PARITY_REPLACES=(sing, quic-go)
# plus a prefix rule for cronet-go. That list was wrong in exactly the way a hand-written
# list goes wrong: `github.com/sagernet/sing-tun` was replaced by the fork in the root
# module and NOT replaced at all in `test`, and because sing-tun was not in the list the
# guard reported success. The test module therefore linked upstream sing-tun, and the TUN
# Start/Close race fix whose regression the tests exist to catch was not the code under
# test. The old code could not fail on it, by construction.
#
# So the set is now DERIVED from the toolchain's own view: every module the ROOT module
# replaces, intersected with the modules the nested module actually resolves. For each
# such path the nested module must replace it with the identical target.
#
# That fixes the omission, but a derived set alone still has a hole: it is derived FROM the
# root go.mod, so a change that drops a load-bearing replace on BOTH sides (reverting the
# fork pin in the root and never adding it to the nested module) would leave nothing to
# compare and the derived check would pass vacuously.
#
# REQUIRED_FORK_REPLACES below is the independent expectation that closes it. It is
# deliberately NOT derived from anything: it is the engineering statement "the shipped
# product is built on these forks", and it fails when the root stops replacing one of
# them, when a parity module stops replacing one of them, or when the expectation itself
# rots because a module left the graph. Nothing in this file removes an entry from it
# automatically - that has to be a deliberate edit.
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

# Fork module paths that MUST be replaced, by the root module AND by every parity module.
#
# This list is the independent expectation described in the header. It is not derived from a
# go.mod on purpose: it is the only thing that can fail when a load-bearing replace is dropped
# on BOTH sides at once. Keep it to the modules the shipped product is genuinely built on, and
# change it only together with the fork pin it names.
REQUIRED_FORK_REPLACES=(
    github.com/sagernet/sing
    github.com/sagernet/sing-tun
    github.com/sagernet/quic-go
)
# Module path PREFIXES with the same requirement, for forks that publish a TREE of modules.
#
# cronet-go publishes `all` and each `lib/<os>_<arch>` as its own module. A list would have to
# name thirty-one paths and would drift the first time upstream adds a platform, so a prefix
# stands for "every path the root replaces under here must also be replaced by every parity
# module, and at least one such path must exist".
REQUIRED_FORK_REPLACE_PREFIXES=(
    github.com/sagernet/cronet-go
)
EXCLUDES=()
REQUIRE_CHECKED=()
RUN_VERIFY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --verify) RUN_VERIFY=1; shift ;;
        --exclude) EXCLUDES+=("${2#./}"); shift 2 ;;
        --require-checked) REQUIRE_CHECKED+=("${2#./}"); shift 2 ;;
        -h|--help) sed -n '2,72p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

failures=0
fail() { echo "  FAIL: $*" >&2; failures=$((failures + 1)); }

# Resolved module graphs are recorded here, one file per module, and read back by the parity
# section. A directory rather than an associative array because macOS still ships bash 3.2,
# where `declare -A` does not exist -- and this guard has to run on a developer's Mac as well as
# on a Linux runner, or the drift it exists to catch is found in CI instead of before the push.
MODULE_VIEW_DIR="$(mktemp -d)"
cleanup_module_views() { rm -rf "$MODULE_VIEW_DIR"; }
trap cleanup_module_views EXIT

# ---------------------------------------------------------------------------
# Toolchain selection, per module.
#
# A module declares the toolchain it needs with its `go` directive. The root and `test`
# modules declare go 1.25.5, the same as the toolchain the repository pins; the reference
# isolation module declares a NEWER one (1.26.0), because it pins upstream quic-go and is
# deliberately on its own dependency graph.
#
# With GOTOOLCHAIN=auto -- what `actions/setup-go` leaves behind -- `go` switches to the
# declared toolchain by itself and every module is checkable. With GOTOOLCHAIN pinned to a
# specific version, as the release verification environment does, the reference module cannot
# be evaluated at all and `go` says so:
#
#   go: go.mod requires go >= 1.26.0 (running go 1.25.5; GOTOOLCHAIN=go1.25.5)
#
# Reporting that as module DRIFT would be wrong: nothing in the module is stale, the running
# toolchain is simply older than the module declares. Reporting it as a silent SKIP would be
# worse -- this guard exists because a check that verifies nothing while printing success is
# the bug. So a module whose `go` directive is newer than the running toolchain is evaluated
# with GOTOOLCHAIN=auto (the toolchain IT declares), the substitution is printed, and the
# checks still run. The pin is left alone for every module the pin can handle.
#
# `local` and a toolchain PATH are explicit operator constraints ("do not download a
# toolchain"), so they are honoured rather than overridden: a module that cannot be evaluated
# under them is reported as a failure with the reason, never skipped.
# ---------------------------------------------------------------------------
RUNNING_GO_VERSION="$(go env GOVERSION | sed 's/^go//')"
RUNNING_GOTOOLCHAIN="$(go env GOTOOLCHAIN)"
if [ -z "$RUNNING_GO_VERSION" ]; then
    echo "FAIL: could not determine the running Go version; the guard cannot evaluate toolchain requirements" >&2
    exit 1
fi

# module_go_directive <dir> prints the module's `go` directive, or nothing when it has none.
module_go_directive() {
    [ -f "$1/go.mod" ] || return 0
    awk '$1 == "go" && NF >= 2 { print $2; exit }' "$1/go.mod"
}

# version_lt <a> <b> is true when dotted version a is strictly older than b.
version_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, pa, "."); nb = split(b, pb, ".")
        for (i = 1; i <= 3; i++) {
            x = (i <= na) ? pa[i] + 0 : 0
            y = (i <= nb) ? pb[i] + 0 : 0
            if (x != y) { exit(x < y ? 0 : 1) }
        }
        exit 1
    }'
}

# module_gotoolchain <dir> prints the GOTOOLCHAIN value to evaluate the module with, and
# whether the substitution is a failure. Prints "<value> <ok|needs-newer|cannot-switch>".
module_gotoolchain() {
    local dir="$1" declared
    declared="$(module_go_directive "$dir")"
    if [ -z "$declared" ] || ! version_lt "$RUNNING_GO_VERSION" "$declared"; then
        printf '%s ok' "$RUNNING_GOTOOLCHAIN"
        return
    fi
    case "$RUNNING_GOTOOLCHAIN" in
        auto)
            # `go` will switch by itself; nothing to substitute.
            printf '%s ok' "$RUNNING_GOTOOLCHAIN"
            ;;
        local|/*|.*)
            printf '%s cannot-switch' "$RUNNING_GOTOOLCHAIN"
            ;;
        *)
            printf 'auto needs-newer'
            ;;
    esac
}

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

# ---------------------------------------------------------------------------
# Effective replaces, read from the TOOLCHAIN instead of parsed out of go.mod.
#
# `go list -m all` reports the replacement actually in effect for every module in the
# resolved graph. That is strictly better than an awk over go.mod text:
#
#   - it covers every directive FORM -- a single-line `replace X => Y v`, a `replace (...)`
#     block, and a filesystem replace such as `=> ../` -- where a text parser has to be
#     taught each one and silently sees nothing in the forms it does not know;
#   - it reports nothing for a module the graph does not resolve, so a replace that no
#     longer applies cannot be mistaken for one that does;
#   - it is the same view the compiler uses, so this guard cannot disagree with the build.
#
# The `replaced` sentinel is what separates "not replaced" (one field) from "replaced by a
# directory" (three fields, with an empty version), which would otherwise be ambiguous.
#
# The output is recorded once per module and reused by the parity section, so a module is
# resolved exactly once no matter how many checks read its graph.
# ---------------------------------------------------------------------------
module_view_format='{{.Path}} {{if .Replace}}replaced {{.Replace.Path}} {{.Replace.Version}}{{end}}'

record_module_view() {
    # $1 module dir, $2 view output file, $3 stderr file, $4 GOTOOLCHAIN to evaluate it with
    local dir="$1" view="$2" errfile="$3" gotoolchain="$4" status=0
    (cd "$dir" && GOWORK=off GOTOOLCHAIN="$gotoolchain" go list -mod=readonly -m -f "$module_view_format" all) \
        >"$view" 2>"$errfile" || status=$?
    return "$status"
}

module_view_path() {
    local slug
    slug="$(printf '%s' "$1" | tr '/.' '__')"
    printf '%s' "$MODULE_VIEW_DIR/${slug}.view"
}

# effective_replace <view> <module> prints "<target path> <version>", or the path alone for a
# filesystem replace. Exits 1 when the module is not replaced.
#
# The version must be part of the comparison. Comparing only the path would accept a fork pinned
# to a DIFFERENT revision in one module, which is exactly the silent drift this guard exists to
# catch -- the path stays identical while the code being built differs.
effective_replace() {
    local view="$1" module="$2"
    [ -f "$view" ] || return 1
    awk -v want="$module" '
        $1 == want && $2 == "replaced" {
            if (NF >= 4 && $4 != "") { print $3 " " $4 } else { print $3 }
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$view"
}

# module_in_view <view> <module> reports whether the module is in the resolved graph at all.
module_in_view() {
    local view="$1" module="$2"
    [ -f "$view" ] || return 1
    awk -v want="$module" '$1 == want { found = 1 } END { exit(found ? 0 : 1) }' "$view"
}

# replaced_paths <view> prints every module path that has an effective replacement.
replaced_paths() {
    local view="$1"
    [ -f "$view" ] || return 1
    awk '$2 == "replaced" { print $1 }' "$view"
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

    # Which toolchain evaluates THIS module. See the toolchain note above: a module whose `go`
    # directive is newer than the running toolchain is evaluated with the toolchain it declares,
    # announced here, and never skipped.
    gotoolchain_line="$(module_gotoolchain "$dir")"
    module_gotoolchain_value="${gotoolchain_line%% *}"
    module_gotoolchain_state="${gotoolchain_line##* }"
    case "$module_gotoolchain_state" in
        ok)
            ;;
        needs-newer)
            echo "  note: ${label} declares go $(module_go_directive "$dir") and this toolchain is go ${RUNNING_GO_VERSION};"
            echo "        evaluating it with GOTOOLCHAIN=auto (the toolchain the module declares)."
            ;;
        cannot-switch)
            fail "${label}: declares go $(module_go_directive "$dir") but this environment is go ${RUNNING_GO_VERSION}"$'\n'"        with GOTOOLCHAIN=${RUNNING_GOTOOLCHAIN}, which forbids switching toolchains. The module"$'\n'"        cannot be evaluated here, and this guard does not report an unevaluated module as clean."
            echo
            continue
            ;;
    esac

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
    tidy_diff="$(cd "$dir" && GOWORK=off GOTOOLCHAIN="$module_gotoolchain_value" go mod tidy -diff 2>"$tidy_stderr")" || tidy_rc=$?

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
        if ! (cd "$dir" && GOWORK=off GOTOOLCHAIN="$module_gotoolchain_value" go mod verify >/dev/null 2>&1); then
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
    #
    # The resolution is RECORDED: the parity section compares the replacements that are
    # actually in effect, from this same view, rather than re-parsing go.mod.
    module_view="$(module_view_path "$module")"
    list_stderr="$(mktemp)"
    list_rc=0
    record_module_view "$dir" "$module_view" "$list_stderr" "$module_gotoolchain_value" || list_rc=$?
    if [ "$list_rc" -ne 0 ]; then
        fail "${label}: go list -mod=readonly -m all failed; module graph does not resolve read-only"
        sed 's/^/      /' "$list_stderr" >&2
    else
        echo "  ok: go list -mod=readonly -m all"
    fi
    rm -f "$list_stderr"
    echo
done

# ---------------------------------------------------------------------------
# 3. Fork replace parity across production modules
# ---------------------------------------------------------------------------
echo "Fork replace parity"
echo "==================="

root_view="$(module_view_path ".")"
root_stderr="$(mktemp)"
root_view_rc=0
record_module_view "$REPO_ROOT" "$root_view" "$root_stderr" "$RUNNING_GOTOOLCHAIN" || root_view_rc=$?
if [ "$root_view_rc" -ne 0 ]; then
    fail "cannot read the root module's effective replace set; the parity check cannot be evaluated"
    sed 's/^/      /' "$root_stderr" >&2
fi
rm -f "$root_stderr"

# ---------------------------------------------------------------------------
# 3a. The independent expectation.
#
# Checked FIRST and separately from the derived rule, because it is the only check that can
# fail when a load-bearing replace is dropped from the root module and from every parity
# module at the same time. Everything below this block is derived from the root go.mod and
# therefore cannot see that case at all.
# ---------------------------------------------------------------------------
echo "-- required fork replaces (independent of any go.mod)"
for required in "${REQUIRED_FORK_REPLACES[@]}"; do
    if [ "$root_view_rc" -ne 0 ]; then
        fail "cannot verify required fork replace '$required': the root module graph did not resolve"
        continue
    fi
    root_target="$(effective_replace "$root_view" "$required" || true)"
    if [ -z "$root_target" ]; then
        fail "the root module no longer replaces $required."$'\n'"        This list is the statement that the shipped product is built on that fork. Dropping"$'\n'"        the replace silently reverts the product to upstream code; if that is intended, the"$'\n'"        fork pin, this expectation and the fork's own documentation must change together."
        continue
    fi
    if ! module_in_view "$root_view" "$required"; then
        fail "required fork replace '$required' is replaced by the root but absent from its resolved graph;"$'\n'"        the expectation has rotted and must be updated deliberately"
        continue
    fi
    echo "  root: $required => $root_target"
done

for prefix in "${REQUIRED_FORK_REPLACE_PREFIXES[@]}"; do
    # The enumeration comes from the root module's resolved graph. When that did not resolve there
    # is nothing to enumerate, and saying "the prefix matches nothing" would blame the fork for a
    # failure that was already reported above.
    if [ "$root_view_rc" -ne 0 ]; then
        break
    fi
    prefix_count=0
    while read -r replaced; do
        [ -n "$replaced" ] || continue
        prefix_count=$((prefix_count + 1))
        root_target="$(effective_replace "$root_view" "$replaced" || true)"
        echo "  root: $replaced => $root_target"
    done < <(replaced_paths "$root_view" | awk -v prefix="$prefix" 'index($1, prefix) == 1' || true)
    if [ "$prefix_count" -eq 0 ]; then
        fail "no replace under the required fork prefix '$prefix' is in effect in the root module."$'\n'"        Every module path the fork publishes must be pinned; a prefix that matches nothing means"$'\n'"        the fork left the graph or the prefix is stale."
    fi
done
echo

# ---------------------------------------------------------------------------
# 3b. The derived rule: every module the ROOT replaces, that the parity module also
# resolves, must be replaced identically by the parity module.
#
# This is what closes the original hole. The hand-written list this replaces named
# sing and quic-go and missed sing-tun, so a nested module that did not replace sing-tun --
# and therefore linked upstream sing-tun while the tests claimed to test the fork -- passed.
# ---------------------------------------------------------------------------
for module in "${PARITY_MODULES[@]}"; do
    is_excluded "$module" && continue
    if [ ! -f "$REPO_ROOT/$module/go.mod" ]; then
        fail "parity module '$module' has no go.mod"
        continue
    fi

    sub_view="$(module_view_path "$module")"
    if [ ! -s "$sub_view" ]; then
        fail "$module: no resolved module graph was recorded, so parity cannot be checked;"$'\n'"        the per-module check above must have failed as well"
        continue
    fi

    derived_count=0
    compared_count=0
    while read -r replaced; do
        [ -n "$replaced" ] || continue
        # Only a module the parity module actually resolves can be built from it. A replace in
        # the root for something the nested module never links is not a parity question.
        if ! module_in_view "$sub_view" "$replaced"; then
            continue
        fi
        derived_count=$((derived_count + 1))
        root_target="$(effective_replace "$root_view" "$replaced" || true)"
        sub_target="$(effective_replace "$sub_view" "$replaced" || true)"
        if [ -z "$sub_target" ]; then
            fail "$module/go.mod does not replace $replaced, but the root module does ($root_target)."$'\n'"        A nested module does NOT inherit root replaces; add the same replace."$'\n'"        Without it $module builds UPSTREAM $replaced, so anything it verifies about the fork"$'\n'"        is a statement about code that is not in the product."
            continue
        fi
        if [ "$root_target" != "$sub_target" ]; then
            fail "$replaced fork pin differs between root and $module:"$'\n'"        root: $root_target"$'\n'"        $module: $sub_target"
            continue
        fi
        compared_count=$((compared_count + 1))
        echo "  ok: $replaced"
        echo "        root:   $root_target"
        echo "        $module: $sub_target"
    done < <(replaced_paths "$root_view" || true)

    # A derivation that silently produces an empty comparison is the failure mode this whole
    # section exists to remove, so an empty result is itself a failure.
    if [ "$derived_count" -eq 0 ]; then
        fail "no root replace is present in $module's resolved graph; the derivation produced nothing"$'\n'"        to compare, which is a broken guard rather than a passing one"
    fi
    echo "  ($module: $compared_count of $derived_count root replace(s) present in its graph verified)"
done
echo

# ---------------------------------------------------------------------------
# 3c. The independent expectation, applied to every parity module.
#
# Runs AFTER the derived rule so a drifted pin is reported once by 3b and once here; the
# duplication is deliberate: 3b cannot fail when the replace is missing from both sides, and
# this cannot be trusted to enumerate the full set.
# ---------------------------------------------------------------------------
echo "-- required fork replaces in parity modules"
for module in "${PARITY_MODULES[@]}"; do
    is_excluded "$module" && continue
    sub_view="$(module_view_path "$module")"
    required_synced=0
    for required in "${REQUIRED_FORK_REPLACES[@]}"; do
        root_target="$(effective_replace "$root_view" "$required" || true)"
        sub_target="$(effective_replace "$sub_view" "$required" || true)"
        if [ -z "$root_target" ]; then
            # Already reported by 3a; do not double-report.
            continue
        fi
        if ! module_in_view "$sub_view" "$required"; then
            # Not in the graph: nothing is built from it, so there is nothing to keep in sync.
            # Reported rather than skipped, because the expectation says this module is
            # load-bearing for the product.
            fail "required fork '$required' is not in $module's resolved graph."$'\n'"        The expectation in REQUIRED_FORK_REPLACES says the product is built on it; if that is no"$'\n'"        longer true, remove the entry deliberately instead of leaving a check that verifies nothing."
            continue
        fi
        if [ -z "$sub_target" ]; then
            fail "$module does not replace the required fork $required (root: $root_target)"
            continue
        fi
        if [ "$root_target" != "$sub_target" ]; then
            fail "the required fork $required is pinned differently in $module than in the root:"$'\n'"        root: $root_target"$'\n'"        $module: $sub_target"
            continue
        fi
        required_synced=$((required_synced + 1))
    done
    if [ "$required_synced" -gt 0 ]; then
        echo "  ok: $module: $required_synced required fork(s) pinned identically"
    fi
done

# Same, for the prefixes: at least one replaced path per prefix must reach the parity module.
for module in "${PARITY_MODULES[@]}"; do
    is_excluded "$module" && continue
    sub_view="$(module_view_path "$module")"
    for prefix in "${REQUIRED_FORK_REPLACE_PREFIXES[@]}"; do
        if [ ! -s "$sub_view" ]; then
            # The module graph did not resolve; already reported per module.
            break
        fi
        prefix_total=0
        prefix_synced=0
        while read -r replaced; do
            [ -n "$replaced" ] || continue
            prefix_total=$((prefix_total + 1))
            if module_in_view "$sub_view" "$replaced"; then
                root_target="$(effective_replace "$root_view" "$replaced" || true)"
                sub_target="$(effective_replace "$sub_view" "$replaced" || true)"
                if [ -z "$sub_target" ] || [ "$root_target" != "$sub_target" ]; then
                    fail "$replaced is not pinned identically in $module:"$'\n'"        root: $root_target"$'\n'"        $module: ${sub_target:-<absent>}"
                    continue
                fi
                prefix_synced=$((prefix_synced + 1))
            fi
        done < <(replaced_paths "$root_view" | awk -v prefix="$prefix" 'index($1, prefix) == 1' || true)
        if [ "$prefix_total" -eq 0 ]; then
            fail "the required fork prefix '$prefix' matches nothing the root replaces"
            continue
        fi
        if [ "$prefix_synced" -eq 0 ]; then
            fail "$module replaces no path under the required fork prefix '$prefix'; the fork is not in"$'\n'"        the code it builds"
            continue
        fi
        echo "  ok: $module: $prefix_synced/$prefix_total path(s) under $prefix pinned identically"
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
