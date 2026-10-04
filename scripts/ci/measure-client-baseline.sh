#!/usr/bin/env bash
# Measures what a running client core retains, on the machine that runs it.
#
# Usage: measure-client-baseline.sh [binary]
#
# # Why a script and not a Go benchmark
#
# The Go benchmarks in this repository measure functions. Steady-state memory is a property of the
# process: the registries, the DNS cache, the rule sets, the connection manager, the trackers, the
# scheduler and whatever the runtime has not returned. A benchmark cannot see any of it, and a number
# taken from one is not the number that decides whether the client fits on a phone.
#
# So this starts the real binary with a real configuration and samples its resident set at four
# points: after startup, at idle, with a hundred connections held open, and again after they close.
# The last two are the pair that matters. Retained memory rather than allocation count is what the low
# memory work is about, and a per-connection leak is invisible without the before-and-after.
#
# # What it does not do
#
# No TUN, no root and no routes: the inbound is a SOCKS5 listener, which exercises the router, the
# direct outbound, the connection manager and the copy loops without needing privileges. Traffic
# stays on loopback, so the throughput figures elsewhere in this repository are the ones to use for
# throughput; this is about memory.
#
# It is intentionally small. A baseline that needs a lab is a baseline nobody re-measures.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

binary="${1:-}"
if [ -z "$binary" ]; then
  binary="$(mktemp -t sing-box-baseline)"
  echo "building the production binary..."
  CGO_ENABLED=1 go build -tags "$(cat release/DEFAULT_BUILD_TAGS)" -o "$binary" ./cmd/sing-box
  cleanup_binary=1
else
  cleanup_binary=0
fi

workdir="$(mktemp -d -t sing-box-baseline)"
cleanup() {
  if [ -n "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "${box_pid:-}" ]; then kill "$box_pid" 2>/dev/null || true; fi
  rm -rf "$workdir"
  if [ "$cleanup_binary" = 1 ]; then rm -f "$binary"; fi
}
trap cleanup EXIT

proxy_port=18080
echo_port=18081
api_port=19090

cat >"$workdir/config.json" <<JSON
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "listen_port": ${proxy_port}
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:${api_port}" }
  }
}
JSON

echo "checking the configuration..."
"$binary" check -c "$workdir/config.json"

# The sink the proxied connections talk to.
#
# It holds each connection open until its peer closes, and THEN closes its own side. That detail is the
# difference between measuring a lifecycle and measuring a half-close: with a sink that never closes,
# the connection object legitimately stays alive after the client goes away - the target side is still
# open - and the active-connection list keeps its row. That is correct behaviour and it is not what
# this script is asserting; the assertion below is about a connection whose both ends are done.
python3 - "$echo_port" <<'PY' &
import socket, sys, threading

def serve(conn):
    try:
        while conn.recv(65536):
            pass
    except OSError:
        pass
    conn.close()


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen(512)
while True:
    accepted, _ = listener.accept()
    threading.Thread(target=serve, args=(accepted,), daemon=True).start()
PY
server_pid=$!

"$binary" run -c "$workdir/config.json" >"$workdir/box.log" 2>&1 &
box_pid=$!

resident_kb() {
  # ps reports kilobytes on both Linux and macOS for -o rss.
  ps -o rss= -p "$1" | tr -d ' '
}

# active_connections asks the running core how many connections it believes are open.
#
# This is the behavioural half of the memory question, and the more useful half: resident bytes move
# with the allocator, but a counter that does not come back to zero is a stale tracker, and a stale
# tracker is a dashboard row that never disappears.
active_connections() {
  python3 - "$api_port" <<'PY'
import json, sys, urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:%s/connections" % sys.argv[1], timeout=5) as response:
        print(len(json.load(response).get("connections") or []))
except Exception:
    print(-1)
PY
}

sample() {
  local label="$1"
  local value
  value="$(resident_kb "$box_pid")"
  printf '%-34s %8s KB\n' "$label" "$value"
  if [ -n "${baseline_idle:-}" ] && [ "$label" = "100 connections closed" ]; then
    printf '%-34s %8s KB\n' "per-connection cost while held" \
      "$(( (held_kb - baseline_idle) / 100 ))"
    printf '%-34s %8s KB\n' "retained after close" "$(( value - baseline_idle ))"
  fi
}

# Startup: the process is running, nothing has been proxied.
for _ in $(seq 1 100); do
  if resident_kb "$box_pid" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
sleep 1
sample "after startup"

# Idle: the configuration is loaded, the DNS cache is empty, no connections exist.
sleep 2
sample "at idle"
baseline_idle="$(resident_kb "$box_pid")"

# run_cycle opens a hundred connections, samples the held state, closes every one of them, and waits
# for the core to agree that none are left.
#
# The wait is the assertion, and it is about the tracker rather than about bytes: a connection the core
# still lists after both ends are done is a stale row, which is what a dashboard would show a user.
run_cycle() {
  local cycle="$1"
  local ready_file="$workdir/ready-${cycle}"
  local stop_file="$workdir/stop-${cycle}"
  rm -f "$ready_file" "$stop_file"

  echo "=== cycle ${cycle}: opening 100 connections ==="
  python3 - "$proxy_port" "$echo_port" "$ready_file" "$stop_file" <<'PY' &
import os, socket, sys, time

proxy_port, echo_port, ready_file, stop_file = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]


def handshake(proxy_port, target_port):
    conn = socket.create_connection(("127.0.0.1", proxy_port))
    conn.sendall(b"\x05\x01\x00")
    if conn.recv(2) != b"\x05\x00":
        raise SystemExit("socks5 greeting failed")
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + target_port.to_bytes(2, "big"))
    reply = conn.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        raise SystemExit("socks5 connect failed: %r" % reply)
    return conn


connections = [handshake(proxy_port, echo_port) for _ in range(100)]
with open(ready_file, "w") as handle:
    handle.write("ready\n")

deadline = time.time() + 60
while time.time() < deadline and not os.path.exists(stop_file):
    time.sleep(0.05)

# Close them explicitly rather than letting the interpreter exit. An exit closes the same sockets, but
# it also ends the process the readiness handshake depends on, which makes the two states harder to
# tell apart than they need to be.
for conn in connections:
    conn.close()
PY
  local driver_pid=$!

  for _ in $(seq 1 300); do
    if [ -f "$ready_file" ]; then break; fi
    sleep 0.1
  done
  if [ ! -f "$ready_file" ]; then
    echo "FAIL: the connection driver never reported readiness" >&2
    exit 1
  fi

  local held_active
  held_active="$(active_connections)"
  if [ "$held_active" != "100" ]; then
    echo "FAIL: ${held_active} connections listed while 100 were open" >&2
    exit 1
  fi
  sample "cycle ${cycle}: 100 held"
  local held
  held="$(resident_kb "$box_pid")"

  touch "$stop_file"
  wait "$driver_pid" 2>/dev/null || true

  for _ in $(seq 1 300); do
    if [ "$(active_connections)" = "0" ]; then break; fi
    sleep 0.1
  done
  local active_after
  active_after="$(active_connections)"
  if [ "$active_after" != "0" ]; then
    echo "FAIL: ${active_after} connections still listed after every client closed." >&2
    echo "A connection whose target side is still open keeps its row, which is correct; this counts" >&2
    echo "rows that remain after BOTH ends are done, and those are stale." >&2
    exit 1
  fi

  sleep 3
  sample "cycle ${cycle}: closed"
  closed_kb="$(resident_kb "$box_pid")"

  printf '%-34s %8s KB\n' "cycle ${cycle}: per-connection cost" "$(( (held - baseline_idle) / 100 ))"
  printf '%-34s %8s KB\n' "cycle ${cycle}: retained after close" "$(( closed_kb - baseline_idle ))"
}

# Two cycles, because the leak signal is the COMPARISON.
#
# Resident bytes do not fall back to their pre-work value when the work ends: the Go allocator keeps
# spans for reuse and the scavenger returns them over minutes, so an absolute threshold measures the
# allocator rather than the code and would fail on a busy machine. A leak grows with every cycle;
# allocation retention plateaus. The script therefore checks that the second cycle closed no higher
# than the first, which is a property of the program rather than of the runtime.
run_cycle 1
first_closed="$closed_kb"
run_cycle 2
second_closed="$closed_kb"

printf '%-34s %8s KB\n' "growth between cycles" "$(( second_closed - first_closed ))"
if [ "$(( second_closed - first_closed ))" -gt 2048 ]; then
  echo "FAIL: the second cycle retained more than 2 MiB more than the first, which is the shape of a" >&2
  echo "per-flow leak rather than allocator retention." >&2
  exit 1
fi

echo
echo "Sampled on $(uname -s)/$(uname -m). Method: scripts/ci/measure-client-baseline.sh"
echo "A TUN client additionally retains the stack, the route table mirror and the flow table; those"
echo "need a real device and are measured by the manual validation package, not here."
