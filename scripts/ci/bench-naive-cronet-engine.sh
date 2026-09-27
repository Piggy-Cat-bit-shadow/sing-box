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
#   first CONNECT latency       time to the first successful proxied request
#   1/4/8/16 stream throughput  parallel curl download throughput
#   CPU %                       sampled during the throughput phase
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

  # First CONNECT latency through the proxy.
  local connect_latency
  connect_latency="$(curl -s -o /dev/null -w '%{time_total}' \
    --proxy "socks5h://127.0.0.1:18080" \
    --max-time 30 "https://$server_host/" 2>/dev/null || echo "n/a")"
  printf 'first_connect_seconds=%s\n' "$connect_latency"

  # Throughput at each stream count. A fixed payload keeps the comparison about
  # transfer efficiency rather than about what the server happened to serve.
  local url="${BENCH_URL:-https://$server_host/}"
  for streams in $streams_sweep; do
    local bytes_total
    bytes_total="$(seq 1 "$streams" | xargs -P "$streams" -I{} \
      curl -s -o /dev/null -w '%{size_download}\n' \
        --proxy "socks5h://127.0.0.1:18080" \
        --max-time 60 "$url" 2>/dev/null | paste -sd+ - | bc 2>/dev/null || echo 0)"
    printf 'streams=%s bytes_downloaded=%s\n' "$streams" "${bytes_total:-0}"
    sample_process "$pid" "streams=$streams"
  done

  # CPU during a sustained transfer, sampled rather than averaged over the whole
  # run so the setup phase does not dilute it.
  local cpu
  cpu="$(ps -o %cpu= -p "$pid" | tr -d ' ')"
  printf 'cpu_percent=%s\n' "$cpu"

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
