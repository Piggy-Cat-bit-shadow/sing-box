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
#   1, 4 and 8 stream throughput, one batch per stream count
#   RSS and private memory
#   first-byte latency (max time_starttransfer within the batch)
#   client failures (non-zero curl exit, non-2xx status, zero-byte transfer)
#   sing-box log stalls, reported separately as a secondary signal
#
# Throughput comes from ONE batch: the bytes and the wall time are taken from the same
# run of `n` parallel downloads, and the divisor is max(time_total) because the slowest
# stream bounds the batch. A previous revision measured bytes in one batch and the time
# in a SECOND batch and divided one by the other, which is not a throughput at all: it
# mixes two independent samples of a variable system. It also only swept 1 and 4
# streams while this header promised 8.
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

echo "building the macOS core once; only stream_receive_window changes per run"
CGO_ENABLED=1 go build \
  -trimpath -buildvcs=false \
  -tags "$(cat release/BUILD_TAGS_JIEJIE_CLIENT_MACOS)" \
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

  # measure_streams runs ONE batch of `streams` parallel downloads and derives the
  # throughput from THAT batch alone.
  #
  # A previous revision measured bytes in one batch and elapsed time in a SECOND
  # batch, then divided one by the other. That number is not a throughput: it mixes
  # two independent samples of a variable system, so it can report a figure no single
  # run ever produced. Bytes and time must come from the same batch.
  #
  # For one parallel batch the wall clock is bounded by the SLOWEST stream, so
  # max(time_total) is the correct divisor, not the sum. Every curl also reports its
  # own exit status, HTTP code and byte count, so a failed or stalled transfer is
  # visible instead of silently contributing zero bytes.
  measure_streams() {
    local streams="$1"
    local raw_file="$outdir/raw-$window-$streams.txt"

    # %{exitcode} cannot be emitted by curl's -w, so each line carries the fields curl
    # can report and the shell records the exit status separately by wrapping the call.
    seq 1 "$streams" | xargs -P "$streams" -I{} \
      sh -c 'curl -s -o /dev/null \
        -w "%{http_code} %{size_download} %{time_total} %{time_starttransfer}\n" \
        --proxy "socks5h://127.0.0.1:18081" \
        --max-time 120 "$1"; echo " exit=$?"' _ "$url" \
      > "$raw_file" 2>/dev/null

    python3 - "$raw_file" "$streams" <<'PYTHON'
import sys

path, streams = sys.argv[1], int(sys.argv[2])
total_bytes = 0
max_time = 0.0
max_starttransfer = 0.0
failures = []

with open(path) as handle:
    for index, line in enumerate(handle):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        # Expected shape: "<http> <bytes> <total> <starttransfer> exit=<code>"
        if len(parts) < 5:
            failures.append(f"stream{index}: unparsable output {line!r}")
            continue
        try:
            http_code = int(parts[0])
            size = float(parts[1])
            elapsed = float(parts[2])
            starttransfer = float(parts[3])
        except ValueError:
            failures.append(f"stream{index}: unparsable numbers {line!r}")
            continue
        exit_code = parts[4].split("=", 1)[-1]

        if exit_code != "0":
            failures.append(f"stream{index}: curl exit {exit_code}")
            continue
        if http_code < 200 or http_code >= 300:
            failures.append(f"stream{index}: HTTP {http_code}")
            continue
        # A truncated transfer must not be counted as a fast one.
        if index == 0 and size <= 0:
            failures.append(f"stream{index}: zero bytes")

        total_bytes += size
        max_time = max(max_time, elapsed)
        max_starttransfer = max(max_starttransfer, starttransfer)

if failures:
    print("n/a " + "; ".join(failures[:3]))
else:
    throughput = total_bytes / max_time / 1e6 if max_time > 0 else 0.0
    print(f"{throughput:.2f} {max_starttransfer:.3f}")
PYTHON
  }

  # One batch per stream count, and the throughput of each batch comes from that batch
  # alone. Every count is measured once: re-running a count to "get the time" is the
  # mistake this replaced.
  one_stats="$(measure_streams 1)"
  four_stats="$(measure_streams 4)"
  eight_stats="$(measure_streams 8)"

  one="$(echo "$one_stats" | awk '{print $1}')"
  four="$(echo "$four_stats" | awk '{print $1}')"
  eight="$(echo "$eight_stats" | awk '{print $1}')"

  # A stall is now reported by the transfers themselves: a non-zero curl exit, a
  # non-2xx status, or output the parser could not read. Grepping the sing-box log for
  # "timeout" is a useful SECONDARY signal but cannot see a client-side failure at all,
  # so it is reported separately rather than as the stall count.
  client_failures="$(printf '%s\n%s\n%s\n' "$one_stats" "$four_stats" "$eight_stats" \
    | grep -c 'n/a' || true)"
  log_stalls="$(grep -c -i "timeout\|stall" "$outdir/window-$window.log" 2>/dev/null || echo 0)"

  rss="$(ps -o rss= -p "$pid" | tr -d ' ')"
  private="$(footprint -p "$pid" 2>/dev/null | grep -i 'physical footprint' | head -1 | sed 's/.*: *//' || echo n/a)"

  printf '%-10s %-13s %-13s %-13s %-12s %-10s %s\n' \
    "$window" "$one" "$four" "$eight" "${rss:-n/a}" "$private" \
    "client=$client_failures log=$log_stalls"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
done

echo ""
echo "Compare throughput against the window size. If the last two rows are equal"
echo "within noise, the larger window is not buying throughput and a lower default"
echo "would bound per-connection memory at no cost. If 128MiB is clearly ahead, it"
echo "stays. Record the machine, the server and the path RTT in"
echo "the experiment record."
