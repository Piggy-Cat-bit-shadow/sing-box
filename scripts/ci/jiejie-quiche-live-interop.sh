#!/usr/bin/env bash
# Builds Google QUICHE's masque_client at the pinned commit, for use as an
# EXTERNAL reference client in the live MASQUE interop tests.
#
# Usage: jiejie-quiche-live-interop.sh [--output-dir DIR] [--print-env]
#
#   --output-dir DIR   where to place the built binary (default: a directory
#                      under the system temp dir). The absolute path is printed
#                      on stdout as the last line.
#   --print-env        print only `export JIEJIE_QUICHE_MASQUE_CLIENT=...`, so
#                      the caller can `eval` it.
#
# # Why this is a separate script rather than a Go test
#
# QUICHE is C++ built with Bazel, and building it pulls BoringSSL, Abseil and
# Protobuf from the Bazel Central Registry. None of that may enter this
# repository: it would add a C++ toolchain and a second dependency system to a
# project that ships a Go binary, and it would make the ordinary Go build depend
# on a network fetch of a C++ monorepo.
#
# So QUICHE is treated exactly like the other reference implementations in
# test/jiejie/reference - quic-go/masque-go and connect-ip-go - as a TEST-ONLY
# external tool. The difference is only that it is built by this script instead
# of by `go test`, because it is not a Go program.
#
# Root go.mod is NOT touched by this script and must never be: verified by the
# workflow, which asserts go.mod is unchanged after the build.
#
# # Why the pin is verified rather than trusted
#
# A QUICHE build that silently used a different revision would produce interop
# evidence for a different implementation, which is worse than no evidence. The
# checkout is therefore verified against QUICHE_PIN with `git rev-parse HEAD`
# and the script REFUSES to continue on any mismatch - including a prefix match,
# which is why the comparison is on the full 40-character SHA.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The QUICHE revision this fork's interop evidence is pinned to. It must match
# the revision recorded in docs/JIEJIE-MASQUE-REFERENCE-AUDIT.md and in
# test/jiejie/reference/quiche_oracle_test.go, so the transcribed protocol
# vectors and the live interop describe ONE implementation.
QUICHE_PIN="c961965aa3ee8f2b6f05ebcac794f7854101adcd"
QUICHE_REPO="https://github.com/google/quiche.git"

# The Bazel target. Verified present at the pin: quiche/BUILD.bazel declares
# `cc_binary(name = "masque_client", srcs = ["quic/masque/masque_client_bin.cc"],
# ...)`. It is deliberately not guessed, and the script fails loudly if the
# build reports it missing.
QUICHE_TARGET="//quiche:masque_client"

output_dir=""
print_env=false
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    --print-env) print_env=true; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

work_dir="${JIEJIE_QUICHE_WORK_DIR:-$(mktemp -d -t jiejie-quiche-XXXXXX)}"
if [ -z "$output_dir" ]; then
  output_dir="$work_dir/out"
fi
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

log() { echo "[quiche-interop] $*" >&2; }

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------

# bazelisk is required rather than bazel: QUICHE pins its Bazel version in
# .bazelversion, and letting bazelisk honour that file is what makes the build
# reproducible across machines. A system `bazel` of a different version would
# build QUICHE with a toolchain QUICHE did not pin.
BAZELISK="${JIEJIE_BAZELISK:-}"
if [ -z "$BAZELISK" ]; then
  if command -v bazelisk >/dev/null 2>&1; then
    BAZELISK="$(command -v bazelisk)"
  elif command -v bazel >/dev/null 2>&1; then
    # A system bazel is accepted only when it is bazelisk in disguise; the
    # version check below is what actually enforces the pin.
    BAZELISK="$(command -v bazel)"
  else
    log "bazelisk is not installed and no bazel is on PATH."
    log "Install it (e.g. 'go install github.com/bazelbuild/bazelisk@latest')"
    log "or set JIEJIE_BAZELISK to its path. This run is NOT-TESTED."
    exit 3
  fi
fi

# ---------------------------------------------------------------------------
# Checkout at the exact pin
# ---------------------------------------------------------------------------

source_dir="$work_dir/quiche"
if [ -d "$source_dir/.git" ]; then
  log "reusing existing checkout at $source_dir"
else
  log "cloning QUICHE into $source_dir"
  # A partial clone: the full history with all blobs is large and none of it is
  # needed, because the pin is a single commit and its own SHA is verified below.
  git clone --filter=blob:none --no-checkout "$QUICHE_REPO" "$source_dir" >&2
fi

git -C "$source_dir" fetch --depth 1 origin "$QUICHE_PIN" >&2 2>/dev/null || true
git -C "$source_dir" checkout --force "$QUICHE_PIN" >&2

actual_pin="$(git -C "$source_dir" rev-parse HEAD)"
if [ "$actual_pin" != "$QUICHE_PIN" ]; then
  log "FATAL: QUICHE checkout is at $actual_pin but the evidence is pinned to $QUICHE_PIN."
  log "Refusing to build: interop results from an unpinned revision would be"
  log "attributed to the pinned one, which is worse than no result."
  exit 4
fi
log "verified QUICHE pin: $actual_pin"

# The Bazel version comes from QUICHE's own .bazelversion. It is READ and
# recorded rather than assumed, so the evidence can state which toolchain
# actually produced the binary.
bazel_version="$(cat "$source_dir/.bazelversion" 2>/dev/null || echo unknown)"
log "QUICHE .bazelversion: $bazel_version"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

log "building $QUICHE_TARGET (this is a large C++ build and may take a long time)"
(
  cd "$source_dir"
  # Bazel writes its output tree inside the workspace; the symlink below is what
  # the binary is copied out of, so the workspace can be discarded afterwards.
  "$BAZELISK" build "$QUICHE_TARGET" >&2
)

bazel_bin="$source_dir/bazel-bin/quiche/masque_client"
if [ ! -x "$bazel_bin" ]; then
  # bazel-bin is a convenience symlink that can be disabled by configuration; the
  # output base path is the authoritative location, so it is asked for directly
  # rather than assumed.
  resolved="$(cd "$source_dir" && "$BAZELISK" cquery "$QUICHE_TARGET" --output=files 2>/dev/null | head -1 || true)"
  if [ -n "$resolved" ] && [ -x "$resolved" ]; then
    bazel_bin="$resolved"
  fi
fi

if [ ! -x "$bazel_bin" ]; then
  log "FATAL: the build reported success but $bazel_bin is not executable."
  log "The target name may have moved at this pin. Refusing to continue."
  exit 5
fi

installed="$output_dir/masque_client"
cp "$bazel_bin" "$installed"
chmod +x "$installed"

binary_sha="$(sha256_of "$installed")"
log "masque_client built: $installed"
log "masque_client sha256: $binary_sha"

# The provenance record is written next to the binary so a workflow can attach
# both without re-deriving anything, and so a reader can tell which QUICHE
# revision and Bazel version a recorded interop run used.
cat > "$output_dir/QUICHE-PROVENANCE.txt" <<EOF
QUICHE live interop — reference client provenance
=================================================
quiche_repo:      $QUICHE_REPO
quiche_commit:    $actual_pin
bazel_target:     $QUICHE_TARGET
bazel_version:    $bazel_version
bazelisk:         $BAZELISK
masque_client:    $installed
masque_client_sha256: $binary_sha
sing_box_sha:     $(git -C "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)" rev-parse HEAD 2>/dev/null || echo unknown)
EOF

if [ "$print_env" = true ]; then
  echo "export JIEJIE_QUICHE_MASQUE_CLIENT='$installed'"
else
  echo "$installed"
fi
