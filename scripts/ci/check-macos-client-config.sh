#!/usr/bin/env bash
# Renders the macOS client fixture into a real config and runs `sing-box check`.
#
# Usage: check-macos-client-config.sh [binary] [output-dir]
#
# The fixture is a .tmpl because every listener needs a free port, and because
# the cache_file path has to live inside the caller's temp directory rather than
# in the repository. This script owns that substitution so local runs and CI
# cannot disagree about what "the fixture" is.
#
# Ports are fixed rather than probed. A probe would make the check non-
# deterministic and could still race between the probe and the bind; the check
# only parses and validates, it does not bind, so a fixed high port range is
# correct here. The runtime smoke test (check-macos-client-runtime.sh) is the
# script that actually binds, and it uses its own port range.
set -euo pipefail

binary="${1:-dist/sing-box-darwin-arm64}"
outdir="${2:-$(mktemp -d)}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tmpl="test/jiejie/macos-client/jiejie-macos-client-fixture.json.tmpl"
if [ ! -f "$tmpl" ]; then
  echo "missing fixture: $tmpl" >&2
  exit 2
fi
if [ ! -x "$binary" ]; then
  echo "missing or non-executable binary: $binary" >&2
  exit 2
fi

mkdir -p "$outdir"
config="$outdir/jiejie-macos-client.json"

sed \
  -e "s|__CACHE_FILE__|$outdir/cache.db|g" \
  -e "s/__CLASH_PORT__/19090/g" \
  -e "s/__MIXED_PORT__/19080/g" \
  -e "s/__SOCKS_IN_PORT__/19081/g" \
  -e "s/__HTTP_IN_PORT__/19082/g" \
  -e "s/__DIRECT_IN_PORT__/19083/g" \
  -e "s/__ECHO_PORT__/19084/g" \
  -e "s/__SOCKS_UPSTREAM_PORT__/19085/g" \
  -e "s/__HTTP_UPSTREAM_PORT__/19086/g" \
  -e "s/__VLESS_PORT__/19087/g" \
  -e "s/__VMESS_PORT__/19088/g" \
  -e "s/__TROJAN_PORT__/19089/g" \
  -e "s/__SS_PORT__/19091/g" \
  -e "s/__SHADOWTLS_PORT__/19092/g" \
  -e "s/__SNELL_PORT__/19093/g" \
  -e "s/__ANYTLS_PORT__/19094/g" \
  -e "s/__HYSTERIA2_PORT__/19095/g" \
  -e "s/__TUIC_PORT__/19096/g" \
  "$tmpl" > "$config"

# A placeholder left behind means the fixture grew a token this script does not
# know about. Failing here is the point: sed would otherwise leave "__FOO__" in
# the file, and the resulting error from sing-box would name a JSON string
# rather than the real mistake.
if grep -q '__[A-Z_]*__' "$config"; then
  echo "unsubstituted placeholder remains in $config:" >&2
  grep -o '__[A-Z_]*__' "$config" | sort -u >&2
  exit 2
fi

echo "checking $config"
"$binary" check -c "$config"
echo "PASS: $config"

# The example config is what a GUI operator actually copies, so it is checked
# too. A stale example is worse than no example: the first thing a new user does
# is run it, and a failure there reads as "this build is broken" rather than
# "this file is out of date".
example="test/jiejie/macos-client/example-config.json"
if [ -f "$example" ]; then
  echo "checking $example"
  "$binary" check -c "$example"
  echo "PASS: $example"
fi
