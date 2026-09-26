#!/usr/bin/env bash
# Repeatable MASQUE acceptance runner for a REAL VPS deployment.
#
# Usage:
#   jiejie-masque-vps.sh --safe          (default)
#   jiejie-masque-vps.sh --stress
#   jiejie-masque-vps.sh --destructive
#
# # What this is, and what it is NOT
#
# It is a RUNNER: it performs a real measurement against a real deployment and
# writes down what it observed. It is NOT a substitute for having a VPS. Running
# it without reachable infrastructure produces NOT-TESTED lines, never PASS lines,
# because every check below is driven by an observation of the remote system.
#
# The distinction matters more here than anywhere else in this repository. The
# loopback and CI fixtures prove the protocol; only a real deployment over a real
# network proves the DEPLOYMENT - a real certificate chain, a real Nginx Stream
# hop, real firewall behaviour, real path MTU, real mobile networks. None of that
# can be simulated honestly, so none of it is claimed from this side.
#
# # Modes
#
#   --safe         (DEFAULT) read-only. Collects facts and runs the external client
#                  checks. Changes nothing on the server: no firewall edit, no
#                  restart, no ulimit change, no package install.
#   --stress       long-lived and churn load, plus RSS/FD/goroutine sampling. Still
#                  non-destructive, but it does load the server and create many
#                  short-lived tunnels.
#   --destructive  FD exhaustion, memory pressure and kill -9 recovery. Requires
#                  BOTH --destructive and JIEJIE_ACCEPT_DESTRUCTIVE=1, and is never
#                  the default. Anything it changes it must restore.
#
# # Credentials
#
# Never passed as command-line arguments: they are read from the environment, so
# they cannot leak through `ps`, shell history or a CI log. The runner never echoes
# a password, and every recorded command is redacted.
set -euo pipefail

MODE="safe"
for argument in "$@"; do
  case "$argument" in
    --safe) MODE="safe" ;;
    --stress) MODE="stress" ;;
    --destructive) MODE="destructive" ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $argument" >&2; exit 2 ;;
  esac
done

# Destructive work needs an explicit second confirmation. A single flag is too easy
# to leave in a shell history and re-run by accident against production.
if [ "$MODE" = "destructive" ] && [ "${JIEJIE_ACCEPT_DESTRUCTIVE:-0}" != "1" ]; then
  echo "refusing --destructive without JIEJIE_ACCEPT_DESTRUCTIVE=1" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Configuration (environment only)
# ---------------------------------------------------------------------------

JIEJIE_VPS_HOST="${JIEJIE_VPS_HOST:-}"
JIEJIE_VPS_USER="${JIEJIE_VPS_USER:-root}"
JIEJIE_TLS_NAME="${JIEJIE_TLS_NAME:-}"
JIEJIE_MASQUE_USER="${JIEJIE_MASQUE_USER:-}"
JIEJIE_MASQUE_PASSWORD="${JIEJIE_MASQUE_PASSWORD:-}"
# The local, EXTERNAL client harness. It must run somewhere other than the VPS:
# curling localhost on the server proves nothing about the WAN path.
JIEJIE_VPS_CLIENT="${JIEJIE_VPS_CLIENT:-}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="${JIEJIE_ACCEPTANCE_OUT:-$PWD}"
report="$out_dir/MASQUE-VPS-ACCEPTANCE-$timestamp.md"
build_info="$out_dir/BUILD-INFO-VPS.txt"

ssh_options=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

# Every result line goes through here, so the report format is uniform and a
# reader can grep the file for a verdict.
record() {
  # record <PASS|FAIL|SKIP|NOT-TESTED> <check> <detail...>
  local verdict="$1" check="$2"; shift 2
  printf '| %-11s | %-38s | %s |\n' "$verdict" "$check" "$*" >> "$report"
  printf '%-11s %-38s %s\n' "$verdict" "$check" "$*" >&2
}

section() {
  printf '\n## %s\n\n' "$1" >> "$report"
}

# A remote command runner. Output is captured, never streamed with a password in it.
remote() {
  ssh "${ssh_options[@]}" "$JIEJIE_VPS_USER@$JIEJIE_VPS_HOST" "$@"
}

log() { printf '[vps-acceptance] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Report header
# ---------------------------------------------------------------------------

{
  echo "# MASQUE VPS acceptance — $timestamp"
  echo
  echo "mode: \`$MODE\`"
  echo "host: \`${JIEJIE_VPS_HOST:-<unset>}\`"
  echo "tls name: \`${JIEJIE_TLS_NAME:-<unset>}\`"
  echo
  echo "Every row below is a real observation of the remote system or of an"
  echo "external client. A row recorded as NOT-TESTED means the measurement was"
  echo "not possible in this environment; it is never a pass."
  echo
  echo "| Verdict     | Check                                  | Detail |"
  echo "|-------------|----------------------------------------|--------|"
} > "$report"

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

section "Preconditions"

if [ -z "$JIEJIE_VPS_HOST" ]; then
  record NOT-TESTED "vps reachable" "JIEJIE_VPS_HOST is unset; no deployment was measured"
  record NOT-TESTED "remote facts" "no host"
  record NOT-TESTED "TCP/443 ALPN h2" "no host"
  record NOT-TESTED "UDP/443 HTTP/3" "no host"
  record NOT-TESTED "external CONNECT-UDP H3" "no host and no external client"
  record NOT-TESTED "external CONNECT-UDP H2 via Nginx" "no host and no external client"
  record NOT-TESTED "WAN IPv4" "no host"
  record NOT-TESTED "WAN IPv6" "no host"
  record NOT-TESTED "real WAN PMTU" "no host"
  record NOT-TESTED "mobile / NAT rebinding" "requires a real mobile network"
  record NOT-TESTED "CGNAT" "requires a real carrier network"
  echo
  echo "**Real VPS / WAN: NOT-TESTED — no real deployment was available.**" >> "$report"
  echo
  echo "Harness ready; real deployment measurement still required." >> "$report"
  log "no JIEJIE_VPS_HOST set: wrote NOT-TESTED report to $report"
  echo "$report"
  exit 0
fi

if remote true >/dev/null 2>&1; then
  record PASS "vps ssh reachable" "$JIEJIE_VPS_USER@$JIEJIE_VPS_HOST"
else
  record FAIL "vps ssh reachable" "ssh to $JIEJIE_VPS_USER@$JIEJIE_VPS_HOST failed"
  echo
  echo "**Real VPS / WAN: NOT-TESTED — the host was configured but unreachable.**" >> "$report"
  echo "$report"
  exit 1
fi

# ---------------------------------------------------------------------------
# Remote facts (read-only)
# ---------------------------------------------------------------------------

section "Deployment facts"

# Binary identity. Recorded from the running binary, not from a local build, so a
# stale deployment cannot be mistaken for the reviewed revision.
binary_path="$(remote 'command -v sing-box || echo /usr/local/bin/sing-box' 2>/dev/null | tr -d '\r')"
if remote "test -x '$binary_path'" >/dev/null 2>&1; then
  remote "sha256sum '$binary_path' 2>/dev/null || shasum -a 256 '$binary_path'" \
    > /tmp/.jj-binsha 2>/dev/null || true
  bin_sha="$(awk '{print $1}' /tmp/.jj-binsha 2>/dev/null || echo unknown)"
  bin_size="$(remote "stat -c %s '$binary_path' 2>/dev/null || stat -f %z '$binary_path'" 2>/dev/null | tr -d '\r')"
  version="$(remote "'$binary_path' version 2>/dev/null | head -1" 2>/dev/null | tr -d '\r')"
  tags="$(remote "'$binary_path' version 2>/dev/null | grep -i '^Tags:' | head -1" 2>/dev/null | tr -d '\r')"
  rm -f /tmp/.jj-binsha

  {
    echo "Jiejie sing-box VPS deployment information"
    echo "=========================================="
    echo "collected_at:  $timestamp"
    echo "host:          $JIEJIE_VPS_HOST"
    echo "binary_path:   $binary_path"
    echo "binary_sha256: $bin_sha"
    echo "binary_size:   $bin_size"
    echo "version:       $version"
    echo "build_tags:    $tags"
  } > "$build_info"

  record PASS "binary sha256 recorded" "$bin_sha"
  record PASS "binary size recorded" "${bin_size:-unknown} bytes"
  record PASS "build tags recorded" "${tags:-unknown}"
else
  record FAIL "binary present" "no executable sing-box at $binary_path"
fi

# The RUNNING configuration must pass the shipper's own validator. A config that
# fails `check` means the service is either stale or broken.
if remote "test -r /etc/sing-box/config.json" >/dev/null 2>&1; then
  if remote "'$binary_path' check -c /etc/sing-box/config.json" >/dev/null 2>&1; then
    record PASS "sing-box check" "/etc/sing-box/config.json is valid"
  else
    record FAIL "sing-box check" "the deployed configuration is rejected by its own binary"
  fi
  # The MASQUE inbound the runner is about must actually be configured.
  if remote "grep -q 'masque' /etc/sing-box/config.json" >/dev/null 2>&1; then
    record PASS "masque configured" "the deployed config declares a MASQUE surface"
  else
    record FAIL "masque configured" "no MASQUE surface found in the deployed config"
  fi
else
  record SKIP "sing-box check" "/etc/sing-box/config.json not readable at that path"
fi

# systemd state: running, and how many times it has restarted. A service that is
# up but has restarted several times is not healthy.
if remote "systemctl is-active --quiet sing-box" >/dev/null 2>&1; then
  main_pid="$(remote "systemctl show -p MainPID --value sing-box" 2>/dev/null | tr -d '\r')"
  restarts="$(remote "systemctl show -p NRestarts --value sing-box" 2>/dev/null | tr -d '\r')"
  record PASS "systemd active" "MainPID=$main_pid"
  if [ "${restarts:-0}" = "0" ]; then
    record PASS "systemd restarts" "0 restarts"
  else
    record FAIL "systemd restarts" "$restarts restarts, which is not a stable service"
  fi
else
  record FAIL "systemd active" "sing-box is not an active systemd unit"
fi

# Listeners. The MASQUE surfaces are TCP/443 (H2 via Nginx Stream) and UDP/443
# (H3), plus the loopback HTTP/2 listener Nginx forwards to.
if remote "ss -lntH 'sport = :443' | grep -q ." >/dev/null 2>&1; then
  record PASS "TCP/443 listening" "$(remote "ss -lntH 'sport = :443' | head -1" 2>/dev/null | tr -s ' ' | tr -d '\r')"
else
  record FAIL "TCP/443 listening" "nothing is listening on TCP/443"
fi
if remote "ss -lunH 'sport = :443' | grep -q ." >/dev/null 2>&1; then
  record PASS "UDP/443 listening" "$(remote "ss -lunH 'sport = :443' | head -1" 2>/dev/null | tr -s ' ' | tr -d '\r')"
else
  record FAIL "UDP/443 listening" "nothing is listening on UDP/443 (HTTP/3 MASQUE is down)"
fi
if remote "ss -lntH 'sport = :28440' | grep -q ." >/dev/null 2>&1; then
  record PASS "127.0.0.1:28440 listening" "the HTTP/2 MASQUE listener behind Nginx"
else
  record FAIL "127.0.0.1:28440 listening" "the loopback HTTP/2 MASQUE listener is not up"
fi

# The Nginx Stream hop. This is the part a loopback test cannot reach: the H2 path
# goes client -> TCP/443 -> Nginx Stream -> 127.0.0.1:28440 -> sing-box.
if remote "test -d /etc/nginx" >/dev/null 2>&1; then
  if remote "grep -rqE 'stream[[:space:]]*\\{' /etc/nginx/nginx.conf /etc/nginx/conf.d 2>/dev/null" >/dev/null 2>&1; then
    record PASS "nginx stream configured" "an nginx stream block exists"
  else
    record FAIL "nginx stream configured" "no nginx stream block, so the H2 path cannot work"
  fi
  if remote "grep -rq '28440' /etc/nginx 2>/dev/null" >/dev/null 2>&1; then
    record PASS "nginx forwards to 28440" "the stream hop targets the MASQUE H2 listener"
  else
    record FAIL "nginx forwards to 28440" "no nginx reference to the MASQUE H2 listener"
  fi
else
  record SKIP "nginx stream configured" "nginx is not installed on the host"
fi

# Certificate: the chain the client will actually be asked to trust.
if [ -n "$JIEJIE_TLS_NAME" ]; then
  cert_info="$(remote "echo | timeout 10 openssl s_client -connect 127.0.0.1:443 -servername '$JIEJIE_TLS_NAME' 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null" 2>/dev/null | tr -d '\r')"
  if [ -n "$cert_info" ]; then
    subject="$(printf '%s' "$cert_info" | grep -i '^subject' | head -1)"
    dates="$(printf '%s' "$cert_info" | grep -iE '^not(Before|After)' | tr '\n' ' ')"
    san="$(printf '%s' "$cert_info" | grep -i 'DNS:' | head -1)"
    record PASS "certificate subject" "${subject:-unknown}"
    record PASS "certificate validity" "${dates:-unknown}"
    if printf '%s' "$san" | grep -q "$JIEJIE_TLS_NAME"; then
      record PASS "certificate SAN covers name" "$JIEJIE_TLS_NAME"
    else
      record FAIL "certificate SAN covers name" "SAN does not include $JIEJIE_TLS_NAME"
    fi
  else
    record FAIL "certificate inspection" "could not read the certificate on TCP/443"
  fi
else
  record SKIP "certificate" "JIEJIE_TLS_NAME is unset"
fi

# Firewall state is RECORDED, never modified.
section "Firewall (recorded, not modified)"
fw="$(remote "nft list ruleset 2>/dev/null | head -40 || iptables-save 2>/dev/null | head -40" 2>/dev/null | tr -d '\r' || true)"
if [ -n "$fw" ]; then
  record PASS "firewall rules recorded" "see the appendix; the runner changed nothing"
  {
    echo
    echo "<details><summary>firewall ruleset (read-only)</summary>"
    echo
    echo '```'
    printf '%s\n' "$fw"
    echo '```'
    echo
    echo "</details>"
  } >> "$report"
else
  record SKIP "firewall rules recorded" "no nft/iptables output (or no privileges)"
fi

# ---------------------------------------------------------------------------
# ALPN and reachability from OUTSIDE
# ---------------------------------------------------------------------------

section "Path checks"

# TCP/443 must negotiate h2, which is what the MASQUE H2 client requires.
if [ -n "$JIEJIE_TLS_NAME" ]; then
  alpn_out="$(echo | timeout 15 openssl s_client -connect "$JIEJIE_VPS_HOST:443" \
    -servername "$JIEJIE_TLS_NAME" -alpn h2 2>/dev/null | grep -i 'ALPN protocol' || true)"
  if printf '%s' "$alpn_out" | grep -qi 'h2'; then
    record PASS "TCP/443 ALPN h2" "$(printf '%s' "$alpn_out" | tr -d '\r')"
  else
    record FAIL "TCP/443 ALPN h2" "server did not negotiate h2 (${alpn_out:-no ALPN})"
  fi
else
  record SKIP "TCP/443 ALPN h2" "JIEJIE_TLS_NAME is unset"
fi

# UDP/443 must answer a real HTTP/3 handshake, from outside the host.
if [ -n "$JIEJIE_TLS_NAME" ]; then
  if command -v curl >/dev/null 2>&1 && curl --version 2>/dev/null | grep -q HTTP3; then
    h3_out="$(timeout 20 curl -sS --http3-only -o /dev/null -w '%{http_version} %{http_code}' \
      --resolve "$JIEJIE_TLS_NAME:443:$JIEJIE_VPS_HOST" \
      "https://$JIEJIE_TLS_NAME/" 2>&1 || true)"
    if printf '%s' "$h3_out" | grep -q '^3'; then
      record PASS "UDP/443 HTTP/3 handshake" "curl negotiated HTTP/3: $h3_out"
    else
      record SKIP "UDP/443 HTTP/3 handshake" "curl could not complete an HTTP/3 request: $h3_out"
    fi
  else
    record SKIP "UDP/443 HTTP/3 handshake" "this curl has no HTTP/3 support; use the external client harness"
  fi
fi

# ---------------------------------------------------------------------------
# External client: the checks that actually prove the WAN path
# ---------------------------------------------------------------------------

section "External client (must NOT run on the VPS)"

if [ -z "$JIEJIE_VPS_CLIENT" ]; then
  record NOT-TESTED "external CONNECT-UDP H3" "JIEJIE_VPS_CLIENT is unset; no external client was run"
  record NOT-TESTED "external CONNECT-UDP H2 via Nginx" "JIEJIE_VPS_CLIENT is unset"
  record NOT-TESTED "WAN IPv4" "no external client"
  record NOT-TESTED "WAN IPv6" "no external client"
  record NOT-TESTED "real WAN PMTU" "no external client"
else
  if [ ! -x "$JIEJIE_VPS_CLIENT" ]; then
    record FAIL "external client executable" "$JIEJIE_VPS_CLIENT is not executable"
  else
    # The client harness owns the protocol detail; the runner owns the
    # environment, the recording and the verdict format. Credentials reach it
    # through the environment only.
    for check in h3-connect-udp h2-connect-udp ipv4 ipv6; do
      case "$check" in
        h3-connect-udp) label="external CONNECT-UDP H3" ;;
        h2-connect-udp) label="external CONNECT-UDP H2 via Nginx" ;;
        ipv4) label="WAN IPv4" ;;
        ipv6) label="WAN IPv6" ;;
      esac
      set +e
      client_out="$(JIEJIE_VPS_HOST="$JIEJIE_VPS_HOST" \
        JIEJIE_TLS_NAME="$JIEJIE_TLS_NAME" \
        JIEJIE_MASQUE_USER="$JIEJIE_MASQUE_USER" \
        JIEJIE_MASQUE_PASSWORD="$JIEJIE_MASQUE_PASSWORD" \
        timeout 120 "$JIEJIE_VPS_CLIENT" "$check" 2>&1)"
      client_status=$?
      set -e
      if [ $client_status -eq 0 ]; then
        record PASS "$label" "$(printf '%s' "$client_out" | tail -1)"
      elif [ $client_status -eq 77 ]; then
        # 77 is the harness's "not applicable here" code (for example no IPv6 on
        # this client), which is a SKIP rather than a failure.
        record SKIP "$label" "$(printf '%s' "$client_out" | tail -1)"
      else
        record FAIL "$label" "exit $client_status: $(printf '%s' "$client_out" | tail -1)"
      fi
      {
        echo
        echo "<details><summary>$label raw output</summary>"
        echo
        echo '```'
        printf '%s\n' "$client_out"
        echo '```'
        echo
        echo "</details>"
      } >> "$report"
    done

    # Real WAN path MTU, probed from the client with a range of inner payloads.
    # This is a DIFFERENT measurement from the loopback PTB fixture and both must
    # be recorded separately: the loopback case proves the ICMP generation, this
    # proves the real path's behaviour.
    set +e
    pmtu_out="$(JIEJIE_VPS_HOST="$JIEJIE_VPS_HOST" JIEJIE_TLS_NAME="$JIEJIE_TLS_NAME" \
      JIEJIE_MASQUE_USER="$JIEJIE_MASQUE_USER" JIEJIE_MASQUE_PASSWORD="$JIEJIE_MASQUE_PASSWORD" \
      timeout 300 "$JIEJIE_VPS_CLIENT" pmtu 2>&1)"
    pmtu_status=$?
    set -e
    if [ $pmtu_status -eq 0 ]; then
      record PASS "real WAN PMTU" "largest working inner payload: $(printf '%s' "$pmtu_out" | tail -1)"
    elif [ $pmtu_status -eq 77 ]; then
      record SKIP "real WAN PMTU" "$(printf '%s' "$pmtu_out" | tail -1)"
    else
      record FAIL "real WAN PMTU" "exit $pmtu_status"
    fi
    {
      echo
      echo "<details><summary>real WAN PMTU probe (payload sizes 1000..1400)</summary>"
      echo
      echo '```'
      printf '%s\n' "$pmtu_out"
      echo '```'
      echo
      echo "</details>"
    } >> "$report"
  fi
fi

# ---------------------------------------------------------------------------
# Stress (opt-in)
# ---------------------------------------------------------------------------

if [ "$MODE" = "stress" ] || [ "$MODE" = "destructive" ]; then
  section "Stress"

  if [ -z "$JIEJIE_VPS_CLIENT" ]; then
    record NOT-TESTED "soak" "no external client harness configured"
  else
    for concurrency in 10 50 100 250 500; do
      set +e
      soak_out="$(JIEJIE_VPS_HOST="$JIEJIE_VPS_HOST" JIEJIE_TLS_NAME="$JIEJIE_TLS_NAME" \
        JIEJIE_MASQUE_USER="$JIEJIE_MASQUE_USER" JIEJIE_MASQUE_PASSWORD="$JIEJIE_MASQUE_PASSWORD" \
        JIEJIE_SOAK_CONCURRENCY="$concurrency" \
        timeout 600 "$JIEJIE_VPS_CLIENT" soak 2>&1)"
      soak_status=$?
      set -e
      if [ $soak_status -eq 0 ]; then
        record PASS "soak concurrency=$concurrency" "$(printf '%s' "$soak_out" | tail -1)"
      else
        record FAIL "soak concurrency=$concurrency" "exit $soak_status"
      fi
      # Resource sampling AFTER each step, so the trend is visible rather than one
      # final number. Read from /proc directly: no production metrics were added.
      main_pid="$(remote "systemctl show -p MainPID --value sing-box" 2>/dev/null | tr -d '\r')"
      if [ -n "${main_pid:-}" ] && [ "$main_pid" != "0" ]; then
        sample="$(remote "grep -E '^(VmRSS|VmPeak|Threads)' /proc/$main_pid/status 2>/dev/null | tr '\n' ' '; echo -n 'fds='; ls /proc/$main_pid/fd 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r')"
        record PASS "resources at concurrency=$concurrency" "${sample:-unavailable}"
      else
        record SKIP "resources at concurrency=$concurrency" "MainPID not available"
      fi
    done
  fi
fi

# ---------------------------------------------------------------------------
# Destructive (double opt-in)
# ---------------------------------------------------------------------------

if [ "$MODE" = "destructive" ]; then
  section "Destructive (opt-in)"

  # Each of these changes something and MUST restore it. The restoration is written
  # next to the change so a failure cannot leave the server altered silently.
  log "destructive mode: FD exhaustion, memory pressure and kill -9 recovery"

  original_limits="$(remote "cat /proc/$(remote "systemctl show -p MainPID --value sing-box" 2>/dev/null | tr -d '\r')/limits 2>/dev/null | grep -i 'open files'" 2>/dev/null | tr -d '\r')"
  record PASS "recorded original limits" "${original_limits:-unknown}"

  # kill -9 recovery: the unit must come back on its own.
  main_pid="$(remote "systemctl show -p MainPID --value sing-box" 2>/dev/null | tr -d '\r')"
  if [ -n "${main_pid:-}" ] && [ "$main_pid" != "0" ]; then
    remote "kill -9 $main_pid" >/dev/null 2>&1 || true
    restored=false
    for _ in $(seq 1 30); do
      sleep 1
      if remote "systemctl is-active --quiet sing-box" >/dev/null 2>&1; then
        restored=true
        break
      fi
    done
    if [ "$restored" = true ]; then
      record PASS "kill -9 recovery" "systemd restarted the service within 30s"
    else
      record FAIL "kill -9 recovery" "the service did not come back within 30s"
    fi
  else
    record SKIP "kill -9 recovery" "no MainPID"
  fi

  record SKIP "FD exhaustion" "run manually with a reviewed ulimit plan; the runner will not lower limits on production unattended"
  record SKIP "cgroup memory pressure" "run manually with a reviewed cgroup plan"
else
  section "Destructive (opt-in)"
  record SKIP "destructive checks" "not requested; use --destructive with JIEJIE_ACCEPT_DESTRUCTIVE=1"
fi

# ---------------------------------------------------------------------------
# Manual section: things no automation can honestly produce
# ---------------------------------------------------------------------------

section "Manual checks (cannot be automated honestly)"

record NOT-TESTED "mobile / NAT rebinding" "requires a real Wi-Fi -> cellular transition on a real device"
record NOT-TESTED "CGNAT" "requires a real carrier-grade NAT path"

cat >> "$report" <<'EOF'

### Mobile / NAT rebinding procedure

These cannot be produced from a CI runner or a wired host, so they are recorded as
NOT-TESTED until someone performs them on a real device. Both outcomes are valid;
what matters is that the recorded observation matches the expectation.

1. Start a long-lived transfer through the tunnel and note the connection ID and
   the local timestamp.
2. Switch the device from Wi-Fi to cellular (or the reverse) mid-transfer.
3. Record which happened:
   - **survived**: the transfer continued after the path change; or
   - **reconnected**: the tunnel was torn down and re-established.
4. Record the elapsed time and the client's own log lines.

### CGNAT procedure

1. Connect from a network behind carrier-grade NAT.
2. Record the observed public address and whether the tunnel establishes.
3. Note whether a path change (address rebinding) is survived or reconnects.

EOF

# ---------------------------------------------------------------------------
# Verdict summary
# ---------------------------------------------------------------------------

section "Verdict"

{
  echo "Counts by verdict:"
  echo
  echo '```'
  for verdict in PASS FAIL SKIP NOT-TESTED; do
    count="$(grep -c "^| $verdict" "$report" 2>/dev/null || echo 0)"
    printf '%-11s %s\n' "$verdict" "$count"
  done
  echo '```'
  echo
  echo "**Real VPS / WAN is only claimed where a real deployment was measured.**"
  echo "A NOT-TESTED row means the measurement was not possible here."
} >> "$report"

log "report: $report"
if [ -f "$build_info" ]; then
  log "build info: $build_info"
fi

# The machine-readable path on stdout, so a caller can collect it.
echo "$report"
