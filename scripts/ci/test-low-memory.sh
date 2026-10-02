#!/usr/bin/env bash
# Runs the data-path test suites under the buffer size the iOS client actually uses.
#
# Usage: test-low-memory.sh
#
# # Why this exists
#
# The iOS client is not built with the default buf.BufferSize. libbox passes
# -tags-not-macos=with_low_memory, which halves it:
#
#   default            BufferSize 32 KiB   UDPBufferSize 16 KiB
#   with_low_memory    BufferSize 16 KiB   UDPBufferSize  8 KiB
#
# That is not a cosmetic difference. It changes where in-place framing stops and
# copying begins, so tests that derive a payload from the buffer size bound a
# different boundary in each build. A production crash came out of exactly this gap:
#
#   panic: buffer overflow: capacity 16384, start 0, need 9
#
# 16384 is BufferSize under with_low_memory, and the Shadowsocks MTU wrapper had
# advertised headroom for only part of its writer chain. The ordinary test run used
# 32 KiB and could not reach the combination that failed. A separate test in this very
# repository also hard-coded a 16 KiB payload, which is exactly BufferSize in
# low-memory mode, so it failed there - and had been failing unnoticed because nothing
# ran these packages with the tag.
#
# So the tag is part of the contract, and it needs its own gate.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# --- fail closed if the Apple contract changes --------------------------------
# This gate is only meaningful while the iOS build really does use with_low_memory.
# If that ever changes, running these tests with the tag would be checking a
# configuration nothing ships - worse than no gate, because it looks like coverage.
if ! grep -q 'tags-not-macos=with_low_memory' cmd/internal/build_libbox/main.go; then
  echo "FAIL: the Apple libbox build no longer passes with_low_memory." >&2
  echo "  iOS would be built with the default 32 KiB buffers, so this gate would test" >&2
  echo "  a configuration that is not shipped." >&2
  echo "  Apple iOS low-memory contract changed; review required." >&2
  exit 1
fi
echo "low-memory contract: with_low_memory is still passed to the Apple libbox build"

# --- production tags, derived not invented ------------------------------------
#
# The data-path packages are not buildable with a bare tag set: transport/http needs
# with_quic for client_h3.go, and the production tag files list everything the shipped
# binaries use. The set is read from the repository rather than restated here, so it
# cannot drift from what is actually built.
#
# DEFAULT_BUILD_TAGS_OTHERS is the non-Windows, non-Apple client set, which is what the
# Apple libbox build itself extends with with_low_memory.
tags_file="release/DEFAULT_BUILD_TAGS_OTHERS"
if [ ! -f "$tags_file" ]; then
  echo "FAIL: $tags_file is missing; cannot derive the production tag set." >&2
  exit 1
fi
production_tags="$(tr -d '[:space:]' < "$tags_file")"
if [ -z "$production_tags" ]; then
  echo "FAIL: $tags_file is empty." >&2
  exit 1
fi
test_tags="$production_tags,with_low_memory"

# libbox references runtime internals that the linker rejects unless the linkname
# escape hatch is enabled, so its tests need the same two tags and linker flag the
# libbox build itself uses. Both are read from that build rather than restated.
if ! grep -q 'badlinkname' cmd/internal/build_libbox/main.go; then
  echo "FAIL: the libbox build no longer passes badlinkname." >&2
  echo "  Apple iOS low-memory contract changed; review required." >&2
  exit 1
fi
libbox_tags="$test_tags,badlinkname,tfogo_checklinkname0"
echo "low-memory tags: with_low_memory appended to $tags_file"

# --- the packages that depend on buffer geometry ------------------------------
#
# Derived from what actually reads buffer size, headroom or MTU rather than from a
# guess: the two sizes themselves, everything that computes or propagates headroom and
# MTU, and the copy paths that size buffers from them. Each entry appears because it
# references one of those concepts.
packages=(
  ./protocol/shadowsocks   # WriterMTU, in-place framing boundary, the crash site
  ./protocol/shadowtls     # prepends its own header, the layer that overflowed
  ./protocol/naive         # its own copy buffers
  ./protocol/anytls        # frame sizing
  ./protocol/shadowsocks   # (kept explicit: MTU wrapper)
  ./transport/http         # ExtendedWriter over HTTP/2 and HTTP/3
  ./transport/masque       # datagram sizing
  ./route                  # splice eligibility and the UDP copy path
  ./dns/...                # response sizing

  # Only the common packages that actually touch buffer geometry, not ./common/... .
  # The wildcard pulled in common/netns, whose TestUnshareNamespace needs CAP_SYS_ADMIN
  # and fails in a CI container for reasons unrelated to buffer sizes - it has nothing
  # to do with buf.BufferSize in the first place. Discovered by the gate failing in CI
  # on exactly that package.
  ./common/badtls
  ./common/ktls
  ./common/listener
  ./common/tls

  ./service/oomkiller      # the Apple memory policy itself
  ./experimental/libbox    # applies that policy
)

# Deduplicate while preserving order.
declare -a unique=()
for pkg in "${packages[@]}"; do
  skip=0
  for seen in "${unique[@]:-}"; do
    [ "$seen" = "$pkg" ] && skip=1 && break
  done
  [ "$skip" -eq 0 ] && unique+=("$pkg")
done

fail=0
ran=0
for pkg in "${unique[@]}"; do
  # A package that has no test files is not a failure; a package that fails to build
  # or fails a test is. `go test` distinguishes them in its output.
  # libbox needs the linker flag; every other package is unaffected by it.
  pkg_tags="$test_tags"
  extra_flags=()
  if [ "$pkg" = "./experimental/libbox" ]; then
    pkg_tags="$libbox_tags"
    extra_flags=(-ldflags=-checklinkname=0)
  fi
  # An empty array must contribute NO argument. "${extra_flags[@]:-}" expands to a
  # single empty string, which go test treats as the package argument and silently
  # tests the ROOT package instead - so every package "passed" while the gate never
  # ran the one it claimed to. Verified by the run reporting one package tested
  # instead of eleven.
  go_args=(-tags "$pkg_tags" -count=1 -timeout 10m)
  if [ "${#extra_flags[@]}" -gt 0 ]; then
    go_args+=("${extra_flags[@]}")
  fi
  if output="$(go test "${go_args[@]}" "$pkg" 2>&1)"; then
    if printf '%s' "$output" | grep -q "no test files"; then
      continue
    fi
    ran=$((ran + 1))
    echo "  ok   $pkg"
  else
    # A package that does not exist is a mistake in this list, not a product failure,
    # so report it distinctly rather than as a test failure.
    if printf '%s' "$output" | grep -q "no packages to test\|directory not found"; then
      echo "  MISS $pkg (listed here but does not exist)" >&2
      fail=1
      continue
    fi
    echo "  FAIL $pkg" >&2
    printf '%s\n' "$output" | tail -25 | sed 's/^/      /' >&2
    fail=1
  fi
done

echo "low-memory gate: $ran package(s) tested with with_low_memory"
[ "$fail" -eq 0 ] || {
  echo "FAIL: the low-memory data paths do not pass." >&2
  exit 1
}
echo "test-low-memory: PASS"
