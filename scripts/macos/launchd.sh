#!/usr/bin/env bash
# Manages the Jiejie macOS client core as a per-user LaunchAgent.
#
# Usage: launchd.sh <command> [config.json]
#
# Commands:
#   install [config]   install the LaunchAgent and start it (config defaults to
#                      the headless example shipped in the repository)
#   start              start (or resume) the agent
#   stop               stop the agent without removing it
#   restart            stop then start
#   status             report whether the agent is loaded and running
#   logs               tail the agent's stdout/stderr logs
#   uninstall          stop and remove the agent
#
# # Why a per-user LaunchAgent and not a root LaunchDaemon
#
# This installs to ~/Library/LaunchAgents and runs as YOU. That is deliberate and
# it is sufficient for mixed/proxy mode, which needs no privileges at all.
#
# TUN mode is the exception: macOS requires root to create a utun device through
# the AF_SYSTEM/SYSPROTO_CONTROL "utun" kernel control, so a TUN configuration
# can NOT be run from a per-user agent. That case needs a root LaunchDaemon in
# /Library/LaunchDaemons, which this script deliberately does not install by
# default. Installing a root daemon is a security-relevant, system-wide change
# and should be a conscious decision, not a side effect of "set up the client".
# Run TUN mode with `sudo ./scripts/macos/run-headless.sh tun-config.json`
# instead, or write your own daemon plist following the model this script emits
# (see the header of the emitted plist).
#
# # Why bootstrap/bootout/kickstart and not load/unload
#
# `launchctl load`/`unload` are the legacy interface; on modern macOS they are
# deprecated in favour of the domain-based `bootstrap`/`bootout`/`kickstart`
# verbs, which report real errors instead of silently doing nothing. This script
# uses the modern verbs exclusively and targets the user's GUI domain
# (gui/<uid>), which is the correct domain for a LaunchAgent.
#
# # Idempotency
#
# install and uninstall are safe to run repeatedly. install boots out any
# existing instance first so a config change is actually picked up rather than
# silently ignored.
set -euo pipefail

label="org.jiejie.sing-box.client"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
agent_dir="$HOME/Library/LaunchAgents"
plist="$agent_dir/$label.plist"
log_dir="$HOME/Library/Logs/jiejie-sing-box"
out_log="$log_dir/sing-box.out.log"
err_log="$log_dir/sing-box.err.log"

# The LaunchAgent domain for this user. Required for LaunchAgents: the
# system/ domain is for daemons and would reject a user agent.
domain="gui/$(id -u)"
service="$domain/$label"

default_config="$root/test/jiejie/macos-client/example-config.json"

die() { echo "error: $*" >&2; exit 1; }

resolve_binary() {
  # JIEJIE_BIN overrides the default, matching run-headless.sh. Building a fresh
  # binary is not always what you want, and the override is what makes this
  # script testable against a binary in a different location.
  if [ -n "${JIEJIE_BIN:-}" ]; then
    binary="$JIEJIE_BIN"
  else
    case "$(uname -m)" in
      arm64) arch=arm64 ;;
      x86_64) arch=amd64 ;;
      *) die "unsupported architecture: $(uname -m)" ;;
    esac
    binary="$root/dist/sing-box-darwin-$arch"
  fi
  [ -x "$binary" ] || die "sing-box binary not found: $binary
build it first:
  ./scripts/ci/build-macos-client.sh $arch lite \"$binary\"
or set JIEJIE_BIN to an existing binary"
}

is_loaded() {
  launchctl print "$service" >/dev/null 2>&1
}

cmd_install() {
  local config="${1:-$default_config}"
  [ -f "$config" ] || die "config not found: $config"
  resolve_binary

  # Absolute paths in the plist: launchd does not inherit your shell's cwd, and a
  # relative path would resolve against / which silently breaks both the config
  # and the log files.
  config="$(cd "$(dirname "$config")" && pwd)/$(basename "$config")"
  local workdir
  workdir="$(dirname "$config")"

  "$binary" check -c "$config" >/dev/null || die "configuration check failed: $config"

  mkdir -p "$agent_dir" "$log_dir"

  # A TUN config cannot work in a user agent. Refusing here is much kinder than
  # letting launchd restart-loop on "operation not permitted" forever.
  if [ "$(id -u)" -ne 0 ] && grep -q '"tun"' "$config"; then
    die "this config contains a tun inbound, which needs root.
A per-user LaunchAgent runs as uid $(id -u) and cannot create a utun device.
Use mixed/proxy mode with launchd, or run TUN mode in the foreground:
  sudo $root/scripts/macos/run-headless.sh \"$config\""
  fi

  local stdout_path="$out_log" stderr_path="$err_log"

  # macOS TCC protects ~/Desktop, ~/Documents and ~/Downloads. A LaunchAgent has
  # no TCC grant for those directories, and the failure mode is nasty: the
  # process launches, launchd reports "state = running" with a real pid, but dyld
  # blocks in open() while mapping the binary. It never execs, never logs and
  # never binds a port, so it looks like a hang with an empty log. Warn loudly.
  case "$binary$config" in
    "$HOME/Desktop"*|"$HOME/Documents"*|"$HOME/Downloads"*)
      cat >&2 <<EOF
warning: the binary or config lives under a TCC-protected directory
         (~/Desktop, ~/Documents or ~/Downloads).

         launchd has no privacy grant for those paths. The agent will appear to
         start (launchd shows "running" with a pid) but block in dyld before it
         ever execs, producing no output and no listening port.

         Fix: move the binary and config somewhere unprotected, for example
           ~/.local/share/jiejie/
         Then re-run this command. Granting Full Disk Access to
         /bin/launchd is possible but is a system-wide privacy change.
EOF
      ;;
  esac

  # Boot out an existing instance so a changed config/binary is actually used.
  if is_loaded; then
    echo "booting out existing agent"
    launchctl bootout "$service" 2>/dev/null || true
  fi

  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  Jiejie Client Edition - per-user LaunchAgent.

  Runs as the logged-in user in the gui/$(id -u) domain. This is correct for
  mixed/proxy mode, which needs no privileges.

  It is NOT suitable for TUN mode: creating a utun device requires root, so a
  TUN configuration needs a LaunchDaemon in /Library/LaunchDaemons running as
  root. To model that, copy this file, change Label, move it to
  /Library/LaunchDaemons, set UserName to root (or omit it), and install with:
      sudo launchctl bootstrap system /Library/LaunchDaemons/<label>.plist

  KeepAlive restarts the core if it exits. SuccessfulExit is false so a clean
  stop is not immediately restarted - without it, the stop command would be
  undone by launchd within seconds.

  NOTE: this heredoc is unquoted so the paths above are expanded. Never use
  backticks or dollar-parentheses in this comment block - they are executed as
  commands. That mistake happened once here and ran a stray "stop".
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$label</string>

  <key>ProgramArguments</key>
  <array>
    <string>$binary</string>
    <string>run</string>
    <string>-c</string>
    <string>$config</string>
    <string>--directory</string>
    <string>$workdir</string>
  </array>

  <key>WorkingDirectory</key>
  <string>$workdir</string>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>

  <key>ProcessType</key>
  <string>Interactive</string>

  <key>StandardOutPath</key>
  <string>$stdout_path</string>
  <key>StandardErrorPath</key>
  <string>$stderr_path</string>

  <key>EnvironmentVariables</key>
  <dict>
    <!-- No secrets belong here: this file is world-readable. -->
    <key>HOME</key>
    <string>$HOME</string>
  </dict>
</dict>
</plist>
PLIST

  chmod 0644 "$plist"

  # bootstrap loads AND honours RunAtLoad. kickstart is used afterwards so the
  # agent is definitely running even if RunAtLoad raced.
  launchctl bootstrap "$domain" "$plist"
  launchctl kickstart "$service" 2>/dev/null || true

  echo "installed: $plist"
  echo "config:    $config"
  echo "binary:    $binary"
  echo "logs:      $out_log"
  echo "           $err_log"
  echo ""
  echo "check status with: $0 status"
}

cmd_start() {
  is_loaded || die "agent is not installed (run: $0 install)"
  launchctl kickstart "$service"
  echo "started"
}

cmd_stop() {
  is_loaded || die "agent is not installed (run: $0 install)"
  # kill SIGTERM asks sing-box to shut down cleanly. bootout would also unload
  # the definition, which stop should not do.
  launchctl kill SIGTERM "$service" 2>/dev/null || launchctl stop "$service" 2>/dev/null || true
  echo "stopped"
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  if ! is_loaded; then
    echo "status: NOT INSTALLED"
    [ -f "$plist" ] && echo "note: $plist exists but the agent is not loaded"
    return 1
  fi
  echo "status: loaded"
  launchctl print "$service" 2>/dev/null | grep -E "^\s*(state|pid|last exit code|program) = " || true
  echo ""
  echo "plist: $plist"
  if [ -f "$err_log" ]; then
    echo "recent stderr:"
    tail -n 5 "$err_log" | sed 's/^/  /'
  fi
}

cmd_logs() {
  [ -d "$log_dir" ] || die "no log directory: $log_dir"
  tail -n 50 -f "$out_log" "$err_log"
}

cmd_uninstall() {
  if is_loaded; then
    launchctl bootout "$service" 2>/dev/null || true
    echo "booted out"
  fi
  if [ -f "$plist" ]; then
    rm -f "$plist"
    echo "removed: $plist"
  else
    echo "no plist to remove"
  fi
  echo "logs kept at: $log_dir"
}

case "${1:-}" in
  install)   shift; cmd_install "${1:-}" ;;
  start)     cmd_start ;;
  stop)      cmd_stop ;;
  restart)   cmd_restart ;;
  status)    cmd_status ;;
  logs)      cmd_logs ;;
  uninstall) cmd_uninstall ;;
  *)
    cat >&2 <<EOF
usage: $(basename "$0") <command> [config.json]

commands:
  install [config]  install and start the LaunchAgent
                    (config defaults to test/jiejie/macos-client/example-config.json)
  start             start the agent
  stop              stop the agent (keeps the definition)
  restart           stop then start
  status            report load state, pid and recent errors
  logs              tail the agent logs
  uninstall         stop and remove the agent

The agent is a PER-USER LaunchAgent in ~/Library/LaunchAgents and runs as you.
It cannot run TUN mode, which needs root; see the header of this script.
EOF
    exit 2
    ;;
esac
