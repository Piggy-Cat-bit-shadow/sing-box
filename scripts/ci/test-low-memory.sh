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
if ! grep -q 'appleLowMemoryTag' cmd/internal/build_libbox/tags.go; then
  echo "FAIL: the Apple libbox build no longer declares a low-memory tag." >&2
  echo "  iOS would be built with the default 32 KiB buffers, so this gate would test" >&2
  echo "  a configuration that is not shipped." >&2
  echo "  Apple iOS low-memory contract changed; review required." >&2
  exit 1
fi
echo "low-memory contract: with_low_memory is still passed to the Apple libbox build"

# --- Apple tags, from the one definition the builder uses ---------------------
#
# The data-path packages are not buildable with a bare tag set, and they must be tested
# with the tags the APPLE CLIENT SHIPS, not a desktop set that happens to compile.
#
# This previously read release/DEFAULT_BUILD_TAGS_OTHERS, which is the non-Windows DESKTOP
# client set. That set differs from what libbox builds, so the gate was checking a
# configuration no Apple binary uses - coverage that reads as coverage while testing
# something else.
#
# cmd/internal/appletags prints the canonical set from the same source build_libbox uses.
# A contract test in that package fails if the two ever diverge.
apple_tags="$(go run ./cmd/internal/appletags -low-memory=true 2>&1)"
if [ -z "$apple_tags" ]; then
  echo "FAIL: could not read the canonical Apple tag set from cmd/internal/appletags." >&2
  echo "  Refusing to fall back to a guess: a gate testing unknown tags is worse than none." >&2
  exit 1
fi
case "$apple_tags" in
  *with_low_memory*)
    ;;
  *)
    echo "FAIL: the Apple iOS/tvOS tag set does not contain with_low_memory." >&2
    echo "  Apple iOS low-memory contract changed; review required." >&2
    exit 1
    ;;
esac
test_tags="$apple_tags"

# libbox references runtime internals the linker rejects unless the linkname escape hatch
# is enabled. Those tags now arrive with the canonical set, so this asserts they are
# present rather than re-adding them.
case "$test_tags" in
  *badlinkname*)
    ;;
  *)
    echo "FAIL: the canonical Apple tag set is missing badlinkname." >&2
    echo "  Apple iOS low-memory contract changed; review required." >&2
    exit 1
    ;;
esac
libbox_tags="$test_tags"
echo "low-memory tags: canonical Apple set from cmd/internal/appletags (with_low_memory present)"

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
