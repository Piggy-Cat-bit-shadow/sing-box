#!/usr/bin/env bash
# Runtime smoke test for the Jiejie macOS client core.
#
# Usage: check-macos-client-runtime.sh [binary] [workdir]
#
# This is the test that proves the binary is usable as an external GUI core. It
# starts a real `sing-box run`, then talks to the real Clash API over TCP and
# asserts on real responses. Nothing here is a compile-time or source-grep check.
#
# What it covers:
#
#   - the process starts and stays up (no panic, no immediate exit)
#   - the Clash API listener accepts connections
#   - GET /version, /proxies, /connections, /traffic, /configs all answer
#   - the selector and urltest groups are present and readable
#   - the mixed inbound accepts a real TCP connection
#   - SIGTERM shuts the process down cleanly
#
# What it deliberately does NOT cover, and why:
#
#   - a real TUN device. Creating one needs root and would reconfigure the host's
#     routing table; a CI runner must not do that. TUN registration and config
#     parsing ARE covered, by check-macos-client-config.sh. The runtime TUN path
#     is reported NOT-TESTED rather than faked.
#   - real proxy connectivity. The fixture's servers are 127.0.0.1 placeholders
#     on purpose: a smoke test must not depend on a live remote endpoint.
#
# The config used here is derived from the same fixture template, so the smoke
# test cannot drift from the config check.
set -euo pipefail

binary="${1:-dist/sing-box-darwin-arm64}"
workdir="${2:-$(mktemp -d)}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

if [ ! -x "$binary" ]; then
  echo "missing or non-executable binary: $binary" >&2
  exit 2
fi

mkdir -p "$workdir"
config="$workdir/runtime.json"

# The runtime config is the check fixture with the listener set reduced to what a
# smoke test can actually bind, and with the TUN inbound removed. Removing TUN is
# not a workaround for a bug: binding a utun device requires root, and the point
# of this script is the API and process lifecycle. TUN coverage lives in the
# config check and is reported separately.
python3 - "$workdir" <<'PY'
import json, re, sys, pathlib

workdir = sys.argv[1]
root = pathlib.Path(__file__).resolve().parent if False else pathlib.Path.cwd()

tmpl = (root / "test/jiejie/macos-client/jiejie-macos-client-fixture.json.tmpl").read_text()
subs = {
    "__CACHE_FILE__": f"{workdir}/cache.db",
    "__CLASH_PORT__": "19190",
    "__MIXED_PORT__": "19180",
    "__SOCKS_IN_PORT__": "19181",
    "__HTTP_IN_PORT__": "19182",
    "__DIRECT_IN_PORT__": "19183",
    "__ECHO_PORT__": "19184",
    "__SOCKS_UPSTREAM_PORT__": "19185",
    "__HTTP_UPSTREAM_PORT__": "19186",
    "__VLESS_PORT__": "19187",
    "__VMESS_PORT__": "19188",
    "__TROJAN_PORT__": "19189",
    "__SS_PORT__": "19191",
    "__SHADOWTLS_PORT__": "19192",
    "__SNELL_PORT__": "19193",
    "__ANYTLS_PORT__": "19194",
    "__HYSTERIA2_PORT__": "19195",
    "__TUIC_PORT__": "19196",
}
for k, v in subs.items():
    tmpl = tmpl.replace(k, v)

leftover = re.findall(r"__[A-Z_]+__", tmpl)
if leftover:
    sys.exit(f"unsubstituted placeholders: {sorted(set(leftover))}")

cfg = json.loads(tmpl)
cfg["inbounds"] = [i for i in cfg["inbounds"] if i["type"] != "tun"]
cfg["log"]["level"] = "info"

pathlib.Path(workdir, "runtime.json").write_text(json.dumps(cfg, indent=2))
PY

echo "starting: $binary run -c $config"
"$binary" run -c "$config" > "$workdir/sing-box.log" 2>&1 &
pid=$!

cleanup() {
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

api="http://127.0.0.1:19190"

# Wait for the controller to answer. 15s is generous for a cold start on a
# loaded CI runner; polling is what makes this robust rather than a sleep.
ready=0
for _ in $(seq 1 150); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: sing-box exited during startup" >&2
    cat "$workdir/sing-box.log" >&2
    exit 1
  fi
  if curl -sS -m 2 "$api/version" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  echo "FAIL: Clash API did not become reachable at $api" >&2
  cat "$workdir/sing-box.log" >&2
  exit 1
fi

fail=0
assert_json() {
  local path="$1" desc="$2" filter="${3:-}"
  local body
  if ! body="$(curl -sS -m 5 "$api$path")"; then
    echo "FAIL: GET $path ($desc): request failed" >&2
    fail=1
    return
  fi
  if [ -n "$filter" ]; then
    if ! python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if ($filter) else 1)" <<<"$body"; then
      echo "FAIL: GET $path ($desc): assertion [$filter] did not hold; body: $body" >&2
      fail=1
      return
    fi
  fi
  echo "PASS: GET $path ($desc)"
}

# The Clash API surface a third-party GUI uses to drive an external core.
assert_json "/version" "reports a version" \
  "isinstance(d.get('version'), str) and d['version'] != ''"
assert_json "/proxies" "exposes proxies and groups" \
  "isinstance(d.get('proxies'), dict) and 'select' in d['proxies'] and 'urltest' in d['proxies']"
assert_json "/proxies/select" "the selector is readable" \
  "d.get('type') == 'Selector' and isinstance(d.get('all'), list) and len(d['all']) > 0"
assert_json "/proxies/urltest" "the urltest group is readable" \
  "d.get('type') == 'URLTest' and isinstance(d.get('all'), list) and len(d['all']) > 0"
assert_json "/proxies/direct" "a protocol outbound is registered and visible" \
  "d.get('type') == 'Direct'"
assert_json "/connections" "connections endpoint answers" \
  "isinstance(d.get('connections'), list)"
assert_json "/configs" "configs endpoint answers" \
  "isinstance(d.get('port'), int)"

# /traffic is a streaming endpoint. curl with a short timeout is the right tool:
# it must produce at least one JSON object and must not hang forever.
traffic="$(curl -sS -m 3 "$api/traffic" 2>/dev/null | head -c 400 || true)"
if [ -n "$traffic" ]; then
  echo "PASS: GET /traffic (streaming traffic endpoint produced data: ${traffic:0:80}...)"
else
  echo "FAIL: GET /traffic produced no data" >&2
  fail=1
fi

# A real TCP connection to the mixed inbound. 127.0.0.1 through a mixed port
# without credentials is fine for a liveness check: the listener existing and
# answering is the assertion, not a successful proxy.
if python3 -c "
import socket,sys
s=socket.create_connection(('127.0.0.1',19180),timeout=5)
s.close()
" 2>/dev/null; then
  echo "PASS: mixed inbound accepts a real TCP connection on 127.0.0.1:19180"
else
  echo "FAIL: mixed inbound did not accept a TCP connection" >&2
  fail=1
fi

# SIGTERM must produce a clean exit. `sing-box run` installs a handler and exits
# 0; anything else means a shutdown path is broken.
if kill -0 "$pid" 2>/dev/null; then
  kill -TERM "$pid"
  exited=0
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then exited=1; break; fi
    sleep 0.1
  done
  if [ "$exited" -ne 1 ]; then
    echo "FAIL: SIGTERM did not stop the process within 10s" >&2
    kill -KILL "$pid" 2>/dev/null || true
    fail=1
  else
    set +e
    wait "$pid"
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      echo "PASS: SIGTERM shut the process down cleanly (exit 0)"
    else
      echo "FAIL: SIGTERM exit status was $status, expected 0" >&2
      fail=1
    fi
  fi
fi

if grep -qE "panic:|fatal error:" "$workdir/sing-box.log"; then
  echo "FAIL: the log contains a panic or fatal error" >&2
  grep -nE "panic:|fatal error:" "$workdir/sing-box.log" >&2
  fail=1
else
  echo "PASS: no panic or fatal error in the log"
fi

if [ "$fail" -ne 0 ]; then
  echo "--- sing-box log ---" >&2
  cat "$workdir/sing-box.log" >&2
  echo "RUNTIME SMOKE TEST: FAIL" >&2
  exit 1
fi

echo "RUNTIME SMOKE TEST: PASS"
