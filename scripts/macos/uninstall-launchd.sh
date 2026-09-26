#!/usr/bin/env bash
# Removes the Jiejie macOS client LaunchAgent.
#
# Usage: uninstall-launchd.sh
#
# Thin wrapper for the requested command name; the implementation is in
# launchd.sh so install and uninstall cannot drift. Logs under
# ~/Library/Logs/jiejie-sing-box are deliberately kept, so a failure can still be
# diagnosed after removal.
set -euo pipefail
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/launchd.sh" uninstall "$@"
