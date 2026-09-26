#!/usr/bin/env bash
# Installs the Jiejie macOS client core as a per-user LaunchAgent.
#
# Usage: install-launchd.sh [config.json]
#
# This is a thin, discoverable wrapper for the requested command name. All the
# logic lives in launchd.sh, which also provides start/stop/restart/status/logs
# and uninstall; keeping one implementation means the subcommands cannot drift
# apart. Run `launchd.sh` with no arguments for the full command list.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/launchd.sh" install "$@"
