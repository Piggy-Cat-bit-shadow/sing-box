#!/usr/bin/env bash
# Real-client compatibility test: the OFFICIAL klzgrad/naiveproxy client against
# this fork's Native Naive inbound.
#
# This exists because a test suite that only uses sing-box's own outbound, or a
# hand-written client, cannot prove compatibility with the ORIGINAL NaiveProxy
# implementation. This script runs the official released binary.
#
# It is intentionally NOT part of `go test`: it needs a downloaded third-party
# binary and a TLS certificate the client will trust, neither of which belongs in
# CI by default. Run it manually.
#
# Requirements:
#   - the official naiveproxy binary (see CLIENT SOURCE below)
#   - a certificate the client trusts. The client uses the platform trust store
#     (CFNetwork/Security on macOS) and has NO "ignore certificate" option, so a
#     self-signed certificate must be trusted first (see TRUST below).
#
# Usage:
#   ./run.sh /path/to/naive /path/to/sing-box /path/to/cert.pem /path/to/key.pem
set -euo pipefail

NAIVE_BIN="${1:?path to the official naive binary}"
SING_BOX_BIN="${2:?path to a sing-box binary with the naive inbound}"
CERT="${3:?path to the TLS certificate (chain)}"
KEY="${4:?path to the TLS private key}"

WORKDIR="$(mktemp -d)"
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
SOCKS_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
ORIGIN_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  [[ -n "${ORIGIN_PID:-}" ]] && kill "$ORIGIN_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

cat > "$WORKDIR/origin.py" <<PY
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'NAIVE-ORIGIN-OK'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', $ORIGIN_PORT), H).serve_forever()
PY
python3 "$WORKDIR/origin.py" & ORIGIN_PID=$!

cat > "$WORKDIR/server.json" <<JSON
{
  "log": {"level": "debug", "output": "$WORKDIR/server.log"},
  "inbounds": [{
    "type": "naive", "tag": "naive-in",
    "listen": "127.0.0.1", "listen_port": $PORT,
    "network": "tcp",
    "users": [{"username":"testuser","password":"testpassword"}],
    "tls": {"enabled":true,"server_name":"naive.test",
            "certificate_path":"$CERT","key_path":"$KEY"}
  }],
  "outbounds": [{"type":"direct","tag":"direct"}],
  "route": {"final":"direct"}
}
JSON

"$SING_BOX_BIN" run -c "$WORKDIR/server.json" > "$WORKDIR/server-stdout.log" 2>&1 & SERVER_PID=$!
sleep 3

"$NAIVE_BIN" --listen="socks://127.0.0.1:$SOCKS_PORT" \
  --proxy="https://testuser:testpassword@naive.test:$PORT" \
  --host-resolver-rules="MAP naive.test 127.0.0.1" \
  --log > "$WORKDIR/client.log" 2>&1 & CLIENT_PID=$!
sleep 5

fail=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "PASS  $label"
  else
    echo "FAIL  $label (expected '$expected', got '$actual')"
    fail=1
  fi
}

echo "=== official NaiveProxy client: $("$NAIVE_BIN" --version) ==="
echo "=== server: naive.test:$PORT, origin: 127.0.0.1:$ORIGIN_PORT ==="
echo

body="$(curl -sS --max-time 25 --socks5-hostname "127.0.0.1:$SOCKS_PORT" "http://127.0.0.1:$ORIGIN_PORT/" || true)"
check "TCP CONNECT through the official client" "NAIVE-ORIGIN-OK" "$body"

padding="$(grep -c 'negotiated padding type: Variant' "$WORKDIR/client.log" || true)"
if [[ "$padding" -gt 0 ]]; then echo "PASS  Naive Padding negotiated"; else echo "FAIL  Naive Padding not negotiated"; fail=1; fi

# Wait ONLY for these curl jobs. A bare `wait` would also block on the server and
# client processes, which never exit. Each job writes its own file so the count
# cannot be corrupted by concurrent appends to one file.
curl_pids=()
for n in $(seq 1 8); do
  curl -sS --max-time 30 --socks5-hostname "127.0.0.1:$SOCKS_PORT" "http://127.0.0.1:$ORIGIN_PORT/" -o "$WORKDIR/conc-$n.out" 2>/dev/null &
  curl_pids+=($!)
done
for pid in "${curl_pids[@]}"; do wait "$pid" || true; done
concurrent=0
for n in $(seq 1 8); do
  [[ "$(cat "$WORKDIR/conc-$n.out" 2>/dev/null)" == "NAIVE-ORIGIN-OK" ]] && concurrent=$((concurrent + 1))
done
check "8 concurrent connections" "8" "$concurrent"

echo
if [[ "$fail" -eq 0 ]]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
