#!/usr/bin/env bash
# Runs the Jiejie macOS client core from a configuration file.
#
# Usage: run-headless.sh <config.json> [extra sing-box args...]
#        run-headless.sh config.json
#        run-headless.sh config.json --directory /path/to/workdir
#
# This is a thin, predictable wrapper. It deliberately does almost nothing:
#
#   - it does NOT modify your configuration,
#   - it does NOT use sudo, and it does not need to for mixed/proxy mode,
#   - it does NOT redirect or swallow stdout/stderr,
#   - it does NOT daemonize or background the process,
#   - it does NOT trap and swallow signals.
#
# It resolves the binary next to the repository, validates the config once before
# starting so a typo fails fast instead of half-starting, and then replaces itself
# with sing-box via exec. Because of exec, sing-box is the foreground process:
# Ctrl-C delivers SIGINT straight to it and it shuts down cleanly, with no
# intermediate shell to leak or mis-forward signals.
#
# For TUN mode you must run this with sudo; see docs/JIEJIE-MACOS-CLIENT.md.
# For a supervised background service, use scripts/macos/install-launchd.sh
# instead of backgrounding this script by hand.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: run-headless.sh <config.json> [extra sing-box args...]

Runs the Jiejie macOS client core in the foreground.

Examples:
  ./scripts/macos/run-headless.sh test/jiejie/macos-client/example-config.json
  ./scripts/macos/run-headless.sh my-config.json --directory ~/.jiejie
  sudo ./scripts/macos/run-headless.sh tun-config.json

Environment:
  JIEJIE_BIN   path to the sing-box binary (default: dist/sing-box-darwin-<arch>)
EOF
  exit 2
}

if [ "$#" -lt 1 ]; then
  usage
fi
case "${1:-}" in
  -h|--help) usage ;;
esac

config="$1"; shift

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Default to the binary for this machine's architecture, so the script works on
# both Apple Silicon and Intel without an argument.
if [ -n "${JIEJIE_BIN:-}" ]; then
  binary="$JIEJIE_BIN"
else
  case "$(uname -m)" in
    arm64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
  esac
  binary="$root/dist/sing-box-darwin-$arch"
fi

if [ ! -f "$config" ]; then
  echo "config not found: $config" >&2
  exit 2
fi

if [ ! -x "$binary" ]; then
  cat >&2 <<EOF
sing-box binary not found or not executable: $binary

Build it first:
  ./scripts/ci/build-macos-client.sh $arch lite "$binary"

Or point JIEJIE_BIN at an existing binary.
EOF
  exit 2
fi

# An absolute path, because the validation below and the final exec can otherwise
# disagree about the working directory.
config="$(cd "$(dirname "$config")" && pwd)/$(basename "$config")"

# Validate before starting. `sing-box check` parses and constructs the whole
# configuration without binding listeners, so a bad config fails here with a
# clear message instead of after partially starting.
echo "checking $config"
if ! "$binary" check -c "$config"; then
  echo "configuration check failed; not starting" >&2
  exit 1
fi

# A TUN inbound needs root, and the failure without it is a bare
# "operation not permitted" from deep inside the utun setup. Warning here is
# cheap and explains the real cause.
if [ "$(id -u)" -ne 0 ] && grep -q '"tun"' "$config"; then
  cat >&2 <<'EOF'
warning: this configuration contains a tun inbound, but you are not root.
         macOS requires root to create a utun device; without it sing-box will
         fail with "configure tun interface: Connect: operation not permitted".
         Re-run with sudo for TUN mode. Mixed/proxy mode does not need root.
EOF
fi

echo "starting: $binary run -c $config $*"
# exec, not a subprocess: no wrapper shell survives to mis-handle signals.
exec "$binary" run -c "$config" "$@"
