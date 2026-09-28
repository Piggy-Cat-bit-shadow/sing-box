#!/usr/bin/env bash
# A/B measurement harness for the Cronet engine strategy on macOS.
#
# Usage:
#   scripts/ci/bench-naive-cronet-engine.sh [server_host] [server_port]
#
# # The question
#
# cronet-go's NaiveClient starts `insecure_concurrency` Cronet engines unless
# singleEngine is forced (see naive_client.go):
#
#   singleEngine: config.TestForceSingleEngine || runtime.GOOS == "ios"
#   engineCount := 1
#   if c.concurrency > 1 && !c.singleEngine { engineCount = c.concurrency }
#
# On macOS that means `insecure_concurrency: 4` runs four full Chromium network
# stacks. The alternative shape - ONE engine plus N network isolation keys, which
# is what iOS does - may provide the same connection isolation at a fraction of
# the memory and thread cost, or it may not.
#
# # What this script measures
#
#   variant  A  N engines        (insecure_concurrency_single_engine: false)
#   variant  B  1 engine + N keys (insecure_concurrency_single_engine: true)
#
# For each variant, at a fixed insecure_concurrency (default 4):
#
#   RSS (resident)              peak RSS during the run
#   private memory              via footprint, which is what "private" means here
#   thread count                from the process table
#   FD count                    from lsof
#   startup latency             time to the API becoming reachable
#   first request latency       END-TO-END time for the first proxied request,
#                               including target connect and target TLS. It is NOT
#                               CONNECT establishment on its own, and the field name
#                               says so.
#   1/4/8/16 stream throughput  from ONE parallel batch per stream count: bytes and
#                               wall time come from the SAME batch, and wall time is
#                               max(time_total) because the slowest stream bounds it.
#                               A failed stream is reported, not counted as zero bytes.
#   CPU %                       max and median of 10 samples taken WHILE 4 concurrent
#                               downloads run
#   failures                    per-batch count of non-zero curl exits, non-2xx
#                               statuses and zero-byte transfers
#
# # What it deliberately does NOT do
#
# It does not decide anything. It prints a table and the raw samples so a human (or
# a later revision of the audit doc) can judge, because the decision depends on
# whether throughput and isolation survive, and that is not a single number.
#
# # Known limitation, stated rather than hidden
#
# This requires a real Naive server. Without one the script exits with
# "NOT TESTED" rather than producing numbers from a loopback fixture, because a
# loopback has no RTT, no loss and no BDP, which is exactly what a congestion and
# windowing comparison is about.
#
# It also cannot observe Cronet engine count, HTTP/2 session count, network isolation
# keys or connection pool count. The single-engine decision rule requires the session
# count to still reach insecure_concurrency, so that half of the rule is NOT DIRECTLY
# VERIFIED by this harness - see docs/JIEJIE-NAIVE-CLIENT-AUDIT.md. Do not read a
# favourable throughput row as evidence that isolation holds.
set -euo pipefail

server_host="${1:-}"
server_port="${2:-443}"
concurrency="${NAIVE_CONCURRENCY:-4}"
streams_sweep="${STREAMS_SWEEP:-1 4 8 16}"
outdir="${OUTDIR:-/tmp/naive-cronet-ab}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

if [ -z "$server_host" ]; then
  echo "NOT TESTED: no Naive server supplied."
  echo ""
  echo "This harness compares two Cronet engine layouts, which differ in how many"
  echo "independent HTTP/2 sessions they can carry. A loopback or stub server has no"
  echo "RTT, no loss and no bandwidth-delay product, so it cannot distinguish them in"
  echo "any way that would generalise. Pass a real server:"
  echo ""
  echo "  $0 <server_host> [server_port]"
  exit 0
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "NOT TESTED: this harness measures macOS Cronet behaviour and requires Darwin." >&2
  exit 0
fi

mkdir -p "$outdir"

# build_variant NAME SINGLE_ENGINE
#
# Builds the macOS core with the engine switch set as requested. The Go build tags
# are identical between variants on purpose: the ONLY difference is the
# configuration value, so any measured difference is attributable to the engine
# layout rather than to the build.
build_variant() {
  local name="$1"
  local single="$2"
  echo "building variant $name (single_engine=$single)"
  CGO_ENABLED=1 go build \
    -trimpath -buildvcs=false \
    -tags "$(cat release/BUILD_TAGS_JIEJIE_CLIENT_MACOS)" \
    -o "$outdir/sing-box-$name" ./cmd/sing-box
}

config_for() {
  local single="$1"
  local path="$2"
  cat > "$path" <<JSON
{
  "log": {"level": "warn"},
  "inbounds": [
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 18080}
  ],
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-out",
      "server": "$server_host",
      "server_port": $server_port,
      "username": "${NAIVE_USER:-}",
      "password": "${NAIVE_PASS:-}",
      "insecure_concurrency": $concurrency,
      "insecure_concurrency_single_engine": $single,
      "tls": {"enabled": true, "server_name": "${NAIVE_SNI:-$server_host}"}
    }
  ]
}
JSON
}

# sample_process PID LABEL
#
# Emits the resource figures for a running process. `footprint` is used for private
# memory because ps' RSS on Darwin does not separate shared framework pages, and
# Cronet maps a large shared library that would otherwise dominate the number and
# hide the per-engine cost this comparison is about.
sample_process() {
  local pid="$1"
  local label="$2"
  local rss threads fds footprint
  rss="$(ps -o rss= -p "$pid" | tr -d ' ')"
  threads="$(ps -M -p "$pid" 2>/dev/null | wc -l | tr -d ' ')"
  fds="$(lsof -p "$pid" 2>/dev/null | wc -l | tr -d ' ')"
  footprint="$(footprint -p "$pid" 2>/dev/null | grep -i "physical footprint" | head -1 | sed 's/.*: *//' || echo "n/a")"
  printf '%s\trss_kib=%s\tthreads=%s\tfds=%s\tprivate=%s\n' "$label" "$rss" "$threads" "$fds" "$footprint"
}

run_variant() {
  local name="$1"
  local single="$2"
  local binary="$outdir/sing-box-$name"
  local config="$outdir/$name.json"
  local log="$outdir/$name.log"

  config_for "$single" "$config"

  # Startup latency: time until the mixed inbound accepts a connection.
  local started_at ready
  started_at="$(python3 -c 'import time;print(time.time())')"
  "$binary" run -c "$config" >"$log" 2>&1 &
  local pid=$!

  ready=""
  for _ in $(seq 1 300); do
    if nc -z 127.0.0.1 18080 2>/dev/null; then
      ready="$(python3 -c "import time;print(f'{time.time()-$started_at:.3f}')")"
      break
    fi
    sleep 0.1
  done

  if [ -z "$ready" ]; then
    echo "FAIL: variant $name never became ready; see $log" >&2
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi

  echo "--- variant $name ---"
  printf 'startup_seconds=%s\n' "$ready"
  sample_process "$pid" "idle"

    # First request latency through the proxy, END TO END.
    #
    # This is curl's total time for one request, which includes the local proxy, the
    # Naive connection, the target connect, the target TLS handshake, the request and
    # the response. It is NOT the CONNECT establishment time on its own, and a previous
    # revision labelled it "first_connect_seconds", claiming a precision it did not
    # have. The field is renamed to say what is actually measured.
    local first_request_latency
    first_request_latency="$(curl -s -o /dev/null -w '%{time_total}' \
      --proxy "socks5h://127.0.0.1:18080" \
      --max-time 30 "https://$server_host/" 2>/dev/null || echo "n/a")"
    printf 'first_request_seconds=%s\n' "$first_request_latency"

    # Throughput at each stream count.
    #
    # ONE batch of `streams` parallel downloads produces BOTH the bytes and the time,
    # so the result is a real throughput. A previous revision summed size_download but
    # never measured elapsed time at all, and printed the byte count under a name that
    # implied throughput: for a fixed payload at streams=8 that was simply
    # 8 x object_size, unchanged by any performance work.
    #
    # For one parallel batch the wall clock is bounded by the SLOWEST stream, so
    # max(time_total) is the divisor, not the sum. Each transfer also reports its own
    # exit status and HTTP code, so a failed or stalled stream is reported instead of
    # contributing zero bytes to a total that still looks plausible.
    local url="${BENCH_URL:-https://$server_host/}"
    for streams in $streams_sweep; do
      local raw_file="$outdir/cronet-raw-$name-$streams.txt"

      seq 1 "$streams" | xargs -P "$streams" -I{} \
        sh -c 'curl -s -o /dev/null \
          -w "%{http_code} %{size_download} %{time_total} %{time_starttransfer}\n" \
          --proxy "socks5h://127.0.0.1:18080" \
          --max-time 60 "$1"; echo " exit=$?"' _ "$url" \
        > "$raw_file" 2>/dev/null || true

      local parsed mbps starttransfer bytes_total failures
      parsed="$(python3 - "$raw_file" <<'PYTHON'
import sys

path = sys.argv[1]
total_bytes = 0.0
max_time = 0.0
max_starttransfer = 0.0
failures = []

with open(path) as handle:
    for index, line in enumerate(handle):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            failures.append("stream%d: unparsable %r" % (index, line))
            continue
        try:
            http_code = int(parts[0])
            size = float(parts[1])
            elapsed = float(parts[2])
            starttransfer = float(parts[3])
        except ValueError:
            failures.append("stream%d: unparsable numbers %r" % (index, line))
            continue
        exit_code = parts[4].split("=", 1)[-1]

        if exit_code != "0":
            failures.append("stream%d: curl exit %s" % (index, exit_code))
            continue
        if not 200 <= http_code < 300:
            failures.append("stream%d: HTTP %d" % (index, http_code))
            continue
        if size <= 0:
            failures.append("stream%d: zero bytes" % index)
            continue

        total_bytes += size
        max_time = max(max_time, elapsed)
        max_starttransfer = max(max_starttransfer, starttransfer)

if failures:
    print("n/a 0.000 0 %d failure(s): %s" % (len(failures), "; ".join(failures[:3])))
elif max_time <= 0:
    print("n/a 0.000 0 no timing recorded")
else:
    print("%.2f %.3f %d" % (total_bytes / max_time / 1e6, max_starttransfer,
                            int(total_bytes)))
PYTHON
)"
      mbps="$(echo "$parsed" | awk '{print $1}')"
      starttransfer="$(echo "$parsed" | awk '{print $2}')"
      bytes_total="$(echo "$parsed" | awk '{print $3}')"
      failures="$(echo "$parsed" | cut -d' ' -f4-)"

      # Bytes, wall time and throughput all come from the SAME batch.
      printf 'streams=%s throughput_MBps=%s bytes_downloaded=%s first_byte_seconds=%s failures=%s\n' \
        "$streams" "$mbps" "${bytes_total:-0}" "$starttransfer" "$failures"
      sample_process "$pid" "streams=$streams"
    done


  # CPU during a SUSTAINED transfer.
  #
  # The previous revision sampled once, AFTER every transfer had finished, and labelled
  # the result "cpu during a sustained transfer". An idle process reports a lifetime
  # average, not transfer CPU, so that number described the setup phase.
  #
  # Here a background download runs for the sampling window and ps is polled while it
  # is in flight. `ps -o %cpu` is a decaying average, so the samples are taken during
  # real work and the maximum is reported; the median is reported too, because a single
  # max is easy to over-read.
  local cpu_samples cpu_max cpu_median
  cpu_samples="$(mktemp)"
  ( seq 1 4 | xargs -P 4 -I{} curl -s -o /dev/null \
      --proxy "socks5h://127.0.0.1:18080" --max-time 25 "$url" ) &
  local load_pid=$!
  for _ in $(seq 1 10); do
    ps -o %cpu= -p "$pid" 2>/dev/null | tr -d ' ' >> "$cpu_samples" || true
    sleep 0.4
  done
  wait "$load_pid" 2>/dev/null || true

  cpu_max="$(sort -rn "$cpu_samples" 2>/dev/null | head -1)"
  cpu_median="$(sort -n "$cpu_samples" 2>/dev/null | awk '{v[NR]=$1} END {if(NR==0) print "n/a"; else print v[int((NR+1)/2)]}')"
  rm -f "$cpu_samples"
  printf 'cpu_percent_max=%s cpu_percent_median=%s cpu_samples=%s\n' \
    "${cpu_max:-n/a}" "${cpu_median:-n/a}" "10x400ms during 4 concurrent downloads"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  echo ""
}

echo "Cronet engine A/B on $(uname -m), concurrency=$concurrency"
echo "server=$server_host:$server_port"
echo ""

build_variant a-engines false
build_variant b-single true

run_variant a-engines false
run_variant b-single true

echo "Raw output retained in $outdir."
echo ""
echo "Compare the two blocks above. Single-engine is worth adopting as the macOS"
echo "default only if throughput and first-CONNECT latency show no meaningful"
echo "regression AND the session count still reaches insecure_concurrency; the"
echo "resource figures alone are not sufficient. Record the result in"
echo "docs/JIEJIE-NAIVE-CLIENT-AUDIT.md, including the machine and server used."
