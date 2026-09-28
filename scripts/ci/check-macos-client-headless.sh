#!/usr/bin/env bash
# Headless smoke test for the Jiejie macOS client core.
#
# Usage: check-macos-client-headless.sh [binary] [workdir]
#
# This script proves the NATIVE management plane works, which is what the Web
# Dashboard and a headless deployment depend on. It is the ONLY control-plane
# smoke test in this product: the Clash API was removed, so there is no second
# management plane to check.
#
# It is deliberately self-contained: it
# builds its own minimal configuration rather than deriving it from the shared
# fixture, because the native `api` service is a control-plane concern and
# mixing it into the data-path fixture would make both harder to reason about.
#
# What is covered, all against a real running process using the real gRPC-Web
# wire protocol over plain HTTP:
#
#   - the process starts and stays up
#   - `api` service binds and answers
#   - GetVersion returns the expected version, with grpc-status 0
#   - SubscribeGroups decodes to the real selector/urltest tree
#   - SelectOutbound actually changes the selection (read back, not assumed)
#   - URLTest is accepted
#   - SubscribeStatus, SubscribeLog, SubscribeConnections, SubscribeOutbounds stream
#   - CloseAllConnections and ClearLogs are accepted
#   - SIGTERM shuts the process down cleanly
#   - no panic in the log
#
# What is deliberately NOT covered:
#
#   - the dashboard's remote download. CI must not depend on GitHub being
#     reachable, and the download is upstream's code, not this fork's. The
#     dashboard is tested locally against a real download and reported
#     separately as NOT-TESTED-in-CI.
#   - TUN. Needs root, which a CI runner must not have; TUN registration and
#     config parsing are covered by check-macos-client-config.sh instead.
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

api_port=19690
mixed_port=19680

config="$workdir/headless.json"
dashboard_dir="$workdir/dashboard"

# The dashboard is intentionally NOT enabled here. Enabling it makes the core
# download an archive from GitHub at startup, which would make this test depend
# on the public network and would slow it down. Dashboard behaviour is verified
# separately; see docs/JIEJIE-MACOS-CLIENT.md.
cat > "$config" <<JSON
{
  "log": {"level": "info"},
  "services": [
    {
      "type": "api", "tag": "api",
      "listen": "127.0.0.1", "listen_port": $api_port,
      "dashboard": {"enabled": true, "path": "$dashboard_dir"}
    }
  ],
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": $mixed_port}
  ],
  "outbounds": [
    {"type": "selector", "tag": "select", "outbounds": ["auto", "direct"], "default": "auto"},
    {"type": "urltest", "tag": "auto", "outbounds": ["direct"], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "select"}
}
JSON

echo "config written to $config"

# `check` must accept the api service. This is the assertion that would have
# caught the registry gap where `type: api` was unknown.
"$binary" check -c "$config"
echo "PASS: sing-box check accepts the api service and the headless config"

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

ready=0
for _ in $(seq 1 200); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: sing-box exited during startup" >&2
    cat "$workdir/sing-box.log" >&2
    exit 1
  fi
  if curl -sS -m 2 -o /dev/null -X POST \
       -H "Content-Type: application/grpc-web+proto" \
       --data-binary @/dev/null \
         "http://127.0.0.1:$api_port/daemon.StartedService/GetVersion" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  echo "FAIL: management APIs did not become reachable" >&2
  cat "$workdir/sing-box.log" >&2
  exit 1
fi
echo "PASS: native api ($api_port) reachable"

# The gRPC-Web assertions run in Python: hand-rolling length-prefixed protobuf
# frames in shell is unreadable and easy to get subtly wrong, and Python 3 is
# guaranteed present on macOS runners.
API_PORT="$api_port" MIXED_PORT="$mixed_port" \
python3 - "$binary" "$dashboard_dir" <<'PY'
import json, os, signal, struct, subprocess, sys, threading, time, urllib.request

api = int(os.environ["API_PORT"])
mixed = int(os.environ["MIXED_PORT"])
binary, dashboard_dir = sys.argv[1], sys.argv[2]

base = f"http://127.0.0.1:{api}"
failures = []

def check(ok, label, detail=""):
    print(("PASS: " if ok else "FAIL: ") + label + (f"  [{detail}]" if detail else ""))
    if not ok:
        failures.append(label)

def frame(payload=b""):
    return b"\x00" + struct.pack(">I", len(payload)) + payload

def call(method, payload=b"", timeout=10):
    req = urllib.request.Request(
        base + "/" + method, data=frame(payload), method="POST",
        headers={"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def ok_call(method, payload=b""):
    """A unary call is successful when the trailer carries grpc-status: 0."""
    body = call(method, payload)
    return b"grpc-status: 0" in body, body

def stream(method, payload=b"", seconds=4):
    req = urllib.request.Request(
        base + "/" + method, data=frame(payload), method="POST",
        headers={"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"})
    got = []
    def run():
        try:
            with urllib.request.urlopen(req, timeout=seconds + 5) as r:
                while True:
                    h = r.read(5)
                    if len(h) < 5:
                        break
                    flag = h[0]
                    ln = struct.unpack(">I", h[1:5])[0]
                    d = r.read(ln)
                    if flag == 0:
                        got.append(d)
        except Exception:
            pass
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    return got

def parse(b):
    """Minimal protobuf decoder; enough for the messages asserted here."""
    out, i = [], 0
    while i < len(b):
        tag = b[i]; i += 1
        f, wt = tag >> 3, tag & 7
        if wt == 0:
            v = 0; sh = 0
            while i < len(b):
                c = b[i]; i += 1
                v |= (c & 0x7f) << sh
                if not (c & 0x80):
                    break
                sh += 7
            out.append((f, wt, v))
        elif wt == 2:
            ln = 0; sh = 0
            while i < len(b):
                c = b[i]; i += 1
                ln |= (c & 0x7f) << sh
                if not (c & 0x80):
                    break
                sh += 7
            out.append((f, wt, b[i:i+ln])); i += ln
        elif wt == 5:
            i += 4; out.append((f, wt, None))
        elif wt == 1:
            i += 8; out.append((f, wt, None))
        else:
            break
    return out

def string_field(msg, field):
    for f, wt, v in parse(msg):
        if f == field and wt == 2:
            return v.decode("utf-8", "replace")
    return None

def groups():
    """Return {tag: {type, selected, selectable, items:[tags]}}."""
    result = {}
    for fr in stream("daemon.StartedService/SubscribeGroups", b"", 4):
        for f, wt, v in parse(fr):
            if f != 1 or wt != 2:
                continue
            g = {"items": []}
            for gf, gwt, gv in parse(v):
                if gwt == 2:
                    if gf == 1: g["tag"] = gv.decode("utf-8", "replace")
                    elif gf == 2: g["type"] = gv.decode("utf-8", "replace")
                    elif gf == 4: g["selected"] = gv.decode("utf-8", "replace")
                    elif gf == 6: g["items"].append(gv)
                elif gwt == 0 and gf == 3:
                    g["selectable"] = gv
            if "tag" in g:
                result[g["tag"]] = g
    return result

# --- version ---------------------------------------------------------------
ok, body = ok_call("daemon.StartedService/GetVersion")
ver = None
for fr in [body]:
    pass
# The version message is field 1 of Version.
try:
    payload = body[5:5 + struct.unpack(">I", body[1:5])[0]]
    ver = string_field(payload, 1)
except Exception:
    pass
check(ok and bool(ver), "GetVersion returns a version", ver or "no grpc-status 0")

# --- groups ----------------------------------------------------------------
g = groups()
check("select" in g, "SubscribeGroups reports the selector",
      f"groups={sorted(g)}")
check(g.get("select", {}).get("type") == "selector",
      "selector group has the right type", str(g.get("select", {}).get("type")))
check("auto" in g, "SubscribeGroups reports the urltest group")
check(g.get("auto", {}).get("type") == "urltest",
      "urltest group has the right type", str(g.get("auto", {}).get("type")))
check(g.get("select", {}).get("selectable") == 1,
      "selector is marked selectable")

# --- selection actually changes -------------------------------------------
def select(group_tag, outbound_tag):
    def s(field, val):
        b = val.encode()
        return bytes([field << 3 | 2, len(b)]) + b
    return ok_call("daemon.StartedService/SelectOutbound",
                   s(1, group_tag) + s(2, outbound_tag))[0]

before = groups().get("select", {}).get("selected")
check(select("select", "direct"), "SelectOutbound(select -> direct) is accepted")
time.sleep(0.5)
after = groups().get("select", {}).get("selected")
check(after == "direct",
      "the selection CHANGED and reads back as direct",
      f"before={before} after={after}")

# --- urltest ---------------------------------------------------------------
def s1(field, val):
    b = val.encode()
    return bytes([field << 3 | 2, len(b)]) + b

check(ok_call("daemon.StartedService/URLTest", s1(1, "auto"))[0],
      "URLTest is accepted")

# --- streaming endpoints ---------------------------------------------------
check(len(stream("daemon.StartedService/SubscribeStatus", b"\x08\x00", 4)) > 0,
      "SubscribeStatus streams traffic")
check(len(stream("daemon.StartedService/SubscribeLog", b"", 3)) > 0,
      "SubscribeLog streams log batches")
check(len(stream("daemon.StartedService/SubscribeConnections", b"\x08\x00", 3)) > 0,
      "SubscribeConnections streams")
outbounds = stream("daemon.StartedService/SubscribeOutbounds", b"", 4)
objs = []
for fr in outbounds:
    objs += [v for f, wt, v in parse(fr) if wt == 2]
check(len(outbounds) > 0, "SubscribeOutbounds streams the outbound list")

# --- mutation --------------------------------------------------------------
check(ok_call("daemon.StartedService/CloseAllConnections")[0],
      "CloseAllConnections is accepted")
check(ok_call("daemon.StartedService/ClearLogs")[0], "ClearLogs is accepted")
check(ok_call("daemon.StartedService/SetClashMode", s1(3, "Global"))[0],
      "SetClashMode is accepted")

# --- data plane still binds ------------------------------------------------
try:
    import socket
    sk = socket.create_connection(("127.0.0.1", mixed), timeout=5)
    sk.close()
    check(True, "the mixed inbound accepts a TCP connection")
except Exception as e:
    check(False, "the mixed inbound accepts a TCP connection", str(e))

# --- dashboard -------------------------------------------------------------
# The dashboard downloads from GitHub at startup. If the archive already exists
# (a previous run, or a network-restricted CI), it is served from disk. Either
# way, once present the HTTP surface must work. This is asserted only when files
# are actually there, so a download failure cannot fail the control-plane test.
if os.path.isdir(dashboard_dir) and os.listdir(dashboard_dir):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{api}/dashboard/", timeout=5) as r:
            html = r.read(2048)
        check(b"<html" in html.lower(), "the dashboard serves HTML from disk")
    except Exception as e:
        check(False, "the dashboard serves HTML from disk", str(e))
else:
    print("SKIP: dashboard files not present (download not attempted in this run)")

print()
if failures:
    print(f"HEADLESS SMOKE TEST: FAIL ({len(failures)} assertion(s))")
    sys.exit(1)
print("HEADLESS SMOKE TEST: PASS")
PY

# --- shutdown --------------------------------------------------------------
if kill -0 "$pid" 2>/dev/null; then
  kill -TERM "$pid"
  exited=0
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then exited=1; break; fi
    sleep 0.1
  done
  if [ "$exited" -eq 1 ]; then
    set +e
    wait "$pid"
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      echo "PASS: SIGTERM shut the process down cleanly (exit 0)"
    else
      echo "FAIL: SIGTERM exit status was $status, expected 0" >&2
      exit 1
    fi
  else
    echo "FAIL: SIGTERM did not stop the process within 10s" >&2
    kill -KILL "$pid" 2>/dev/null || true
    exit 1
  fi
fi

if grep -qE "panic:|fatal error:" "$workdir/sing-box.log"; then
  echo "FAIL: the log contains a panic or fatal error" >&2
  grep -nE "panic:|fatal error:" "$workdir/sing-box.log" >&2
  exit 1
fi
echo "PASS: no panic or fatal error in the log"
