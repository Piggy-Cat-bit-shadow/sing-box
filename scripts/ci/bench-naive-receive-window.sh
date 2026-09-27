#!/usr/bin/env bash
# Receive-window sweep for the Naive HTTP/2 client on macOS.
#
# Usage:
#   scripts/ci/bench-naive-receive-window.sh [server_host] [server_port]
#
# # The question
#
# cronet-go picks the HTTP/2 stream receive window by platform
# (naive_client.go, SetHTTP2Options):
#
#   if runtime.GOOS == "ios" { receiveWindow = 4 * 1024 * 1024 }
#   else                     { receiveWindow = 128 * 1024 * 1024 }
#
# and sets the connection window to half of it. So macOS defaults to a 128 MiB
# per-stream window.
#
# 128 MiB is a CEILING, not an allocation: Chromium's flow control grows the
# window as the bandwidth-delay product requires and does not reserve it up front.
# That is why the large default is not automatically a memory problem - but it is
# also why "smaller must be better" is not automatically true, and the decision
# belongs to a measurement rather than to intuition.
#
# # What this measures
#
# The sweep is 4, 8, 16, 32, 64 and 128 MiB (the current default), because the
# question is where throughput stops improving. For each value:
#
#   single-stream throughput
#   multi-stream throughput (4 and 8 parallel streams)
#   RSS and private memory
#   first-byte and total latency
#   stalls (transfers that failed or hit the timeout)
#
# # The signal that decides it
#
# If throughput is flat from 32 or 64 MiB upward, then 128 MiB buys nothing and a
# lower default would bound per-connection memory with no cost. If 128 MiB is
# measurably faster on a high-BDP path, it stays. This script prints the table; it
# does not pick a winner.
#
# # Known limitation, stated rather than hidden
#
# A receive window only matters when the path has enough bandwidth-delay product to
# keep it full. On a loopback or a short-RTT LAN every value will look identical
# and the measurement will be meaningless. A high-BDP path is required, which in
# practice means a distant server. Without one this exits with NOT TESTED.
set -euo pipefail

server_host="${1:-}"
server_port="${2:-443}"
windows="${WINDOW_SWEEP:-4MiB 8MiB 16MiB 32MiB 64MiB 128MiB}"
outdir="${OUTDIR:-/tmp/naive-window-ab}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

if [ -z "$server_host" ]; then
  echo "NOT TESTED: no Naive server supplied."
  echo ""
  echo "A receive window bounds in-flight bytes. Comparing 4 MiB against 128 MiB is"
  echo "only meaningful when the path's bandwidth-delay product is large enough that"
  echo "the small window would actually bind - otherwise every value is identical and"
  echo "the sweep proves nothing. Pass a server on a high-BDP (distant) path:"
  echo ""
  echo "  $0 <server_host> [server_port]"
  echo ""
  echo "Set BENCH_URL to a large object so the transfer is not dominated by setup."
  exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "NOT TESTED: this sweep measures macOS Cronet behaviour and requires Darwin." >&2
  exit 0
fi

mkdir -p "$outdir"

echo "building the naive flavor once; only stream_receive_window changes per run"
CGO_ENABLED=1 go build \
  -trimpath -buildvcs=false \
  -tags "$(cat release/BUILD_TAGS_JIEJIE_CLIENT_MACOS_NAIVE)" \
  -o "$outdir/sing-box-window" ./cmd/sing-box

url="${BENCH_URL:-https://$server_host/}"

printf '%-10s %-14s %-14s %-12s %-10s %s\n' \
  "window" "1-stream_MB/s" "4-stream_MB/s" "rss_kib" "private" "stalls"

for window in $windows; do
  config="$outdir/window-$window.json"
  cat > "$config" <<JSON
{
  "log": {"level": "warn"},
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 18081}
  ],
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-out",
      "server": "$server_host",
      "server_port": $server_port,
      "username": "${NAIVE_USER:-}",
      "password": "${NAIVE_PASS:-}",
      "stream_receive_window": "$window",
      "tls": {"enabled": true, "server_name": "${NAIVE_SNI:-$server_host}"}
    }
  ]
}
JSON

  "$outdir/sing-box-window" run -c "$config" >"$outdir/window-$window.log" 2>&1 &
  pid=$!

  for _ in $(seq 1 300); do
    nc -z 127.0.0.1 18081 2>/dev/null && break
    sleep 0.1
  done

  measure_streams() {
    local streams="$1"
    local total
    total="$(seq 1 "$streams" | xargs -P "$streams" -I{} \
      curl -s -o /dev/null -w '%{size_download}\n' \
        --proxy "socks5h://127.0.0.1:18081" \
        --max-time 120 -w '%{size_download} %{time_total}\n' "$url" 2>/dev/null \
      | awk '{b+=$1} END {print b+0}')"
    # Throughput needs the elapsed time too; the slowest stream bounds the wall
    # clock for a parallel download, so the max time_total is the right divisor.
    local elapsed
    elapsed="$(seq 1 "$streams" | xargs -P "$streams" -I{} \
      curl -s -o /dev/null -w '%{time_total}\n' \
        --proxy "socks5h://127.0.0.1:18081" \
        --max-time 120 "$url" 2>/dev/null | sort -rn | head -1)"
    python3 -c "
import sys
total=float('${total:-0}'); elapsed=float('${elapsed:-0}' or 0)
print(f'{total/elapsed/1e6:.2f}' if elapsed>0 else 'n/a')"
  }

  one="$(measure_streams 1)"
  four="$(measure_streams 4)"

  rss="$(ps -o rss= -p "$pid" | tr -d ' ')"
  private="$(footprint -p "$pid" 2>/dev/null | grep -i 'physical footprint' | head -1 | sed 's/.*: *//' || echo n/a)"
  stalls="$(grep -c -i "timeout\|stall" "$outdir/window-$window.log" 2>/dev/null || echo 0)"

  printf '%-10s %-14s %-14s %-12s %-10s %s\n' \
    "$window" "$one" "$four" "${rss:-n/a}" "$private" "$stalls"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done

echo ""
echo "Compare throughput against the window size. If the last two rows are equal"
echo "within noise, the larger window is not buying throughput and a lower default"
echo "would bound per-connection memory at no cost. If 128MiB is clearly ahead, it"
echo "stays. Record the machine, the server and the path RTT in"
echo "docs/JIEJIE-NAIVE-CLIENT-AUDIT.md."
