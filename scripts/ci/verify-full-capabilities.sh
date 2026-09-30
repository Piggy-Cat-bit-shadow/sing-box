#!/usr/bin/env bash
# Verifies that a built binary really carries the full upstream feature profile.
#
# Usage: verify-full-capabilities.sh <binary> [config-dir]
#
# # What this replaces
#
# This fork used to ship a product-specific registry and a matching audit whose job
# was to prove that capabilities were ABSENT: Hysteria2 absent, TUIC absent, the
# Clash API absent, a protocol's server role absent, and so on. Those assertions
# were the contract for a pruning architecture that no longer exists.
#
# The contract is now the opposite one. The binary is expected to carry the complete
# upstream registry, so what needs proving is that capabilities are PRESENT. A
# regression here is silent: a narrower tag set still produces a working binary, and
# nothing would notice that the shipped core had lost part of its protocol surface.
#
# # Why config-level rather than symbol-level
#
# The shipped macOS artifact is stripped (-s -w), so `go tool nm` cannot read it. The
# check therefore goes through the same path an operator uses: build a minimal but
# valid configuration for each capability and let `sing-box check` resolve it through
# the real registry. That exercises the registry, the option schema and each
# constructor's validation, which is exactly what "the capability is present" means.
#
# It deliberately does NOT claim these capabilities interoperate over a live network.
# That requires real peers and is covered by the protocol regression suites.
set -euo pipefail

binary="${1:?usage: verify-full-capabilities.sh <binary> [config-dir]}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$script_dir/../.." && pwd)"
work="${2:-$(mktemp -d)}"

if [ ! -x "$binary" ]; then
  echo "not an executable: $binary" >&2
  exit 2
fi
mkdir -p "$work"

# A certificate the TLS-bearing capabilities can point at. Generated into a
# throwaway directory: nothing here is a real credential.
cert_dir="$work/certs"
mkdir -p "$cert_dir"
if [ ! -f "$cert_dir/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$cert_dir/key.pem" -out "$cert_dir/cert.pem" \
    -subj "/CN=capability-smoke.invalid" >/dev/null 2>&1
fi

pass=0
fail=0
declare -a failures=()

# check_config runs `sing-box check` over a configuration supplied on stdin.
check_config() {
  local name="$1" body="$2"
  local file="$work/$name.json"
  # sing-box 1.12+ refuses to start when DNS servers exist but no dial field names a
  # domain resolver. Inject it centrally so each case below only describes the
  # capability under test.
  if printf '%s' "$body" | grep -q '"dns"'; then
    body="$(python3 -c '
import json,sys
d=json.loads(sys.argv[1])
d.setdefault("route",{}).setdefault("default_domain_resolver",{"server":"fallback"})
d["dns"].setdefault("servers",[])
if not any(s.get("tag")=="fallback" for s in d["dns"]["servers"]):
    d["dns"]["servers"].append({"tag":"fallback","type":"local"})
print(json.dumps(d))
' "$body")"
  fi
  printf '%s' "$body" > "$file"
  if "$binary" check -c "$file" >"$work/$name.log" 2>&1; then
    pass=$((pass + 1))
    echo "  PASS: $name"
  else
    fail=$((fail + 1))
    failures+=("$name")
    echo "  FAIL: $name"
    sed 's/^/        /' "$work/$name.log" | head -5
  fi
}

# A capability counts as present when a minimal valid configuration naming it is
# accepted. Each entry is [name] = config body.
echo "== outbound protocols (full registry) =="
for spec in \
  "outbound-vmess:{\"type\":\"vmess\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\"}" \
  "outbound-trojan:{\"type\":\"trojan\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"password\":\"p\"}" \
  "outbound-vless:{\"type\":\"vless\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\"}" \
  "outbound-shadowsocks:{\"type\":\"shadowsocks\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}" \
  "outbound-socks:{\"type\":\"socks\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1}" \
  "outbound-http:{\"type\":\"http\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1}" \
  "outbound-shadowtls:{\"type\":\"shadowtls\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"version\":3,\"password\":\"p\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\"}}" \
  "outbound-anytls:{\"type\":\"anytls\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"password\":\"p\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\"}}" \
  "outbound-tor:{\"type\":\"tor\",\"tag\":\"o\"}" \
  "outbound-ssh:{\"type\":\"ssh\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"user\":\"u\",\"password\":\"p\"}" \
  "outbound-direct:{\"type\":\"direct\",\"tag\":\"o\"}" \
  "outbound-block:{\"type\":\"block\",\"tag\":\"o\"}" \
  "outbound-selector:{\"type\":\"selector\",\"tag\":\"o\",\"outbounds\":[\"direct\"]}" \
  "outbound-urltest:{\"type\":\"urltest\",\"tag\":\"o\",\"outbounds\":[\"direct\"]}" \
  ; do
  name="${spec%%:*}"; body="${spec#*:}"
  check_config "$name" "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"},$body]}"
done

echo "== inbound protocols (full registry) =="
for spec in \
  "inbound-http:{\"type\":\"http\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1080}" \
  "inbound-socks:{\"type\":\"socks\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1081}" \
  "inbound-mixed:{\"type\":\"mixed\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1082}" \
  "inbound-shadowsocks:{\"type\":\"shadowsocks\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1083,\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}" \
  "inbound-vmess:{\"type\":\"vmess\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1084,\"users\":[{\"uuid\":\"00000000-0000-0000-0000-000000000000\"}]}" \
  "inbound-trojan:{\"type\":\"trojan\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1085,\"users\":[{\"password\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-vless:{\"type\":\"vless\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1086,\"users\":[{\"uuid\":\"00000000-0000-0000-0000-000000000000\"}]}" \
  "inbound-anytls:{\"type\":\"anytls\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1087,\"users\":[{\"password\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-shadowtls:{\"type\":\"shadowtls\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1088,\"version\":3,\"users\":[{\"password\":\"p\"}],\"handshake\":{\"server\":\"127.0.0.1\",\"server_port\":443}}" \
  "inbound-naive:{\"type\":\"naive\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1089,\"users\":[{\"username\":\"u\",\"password\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-hysteria:{\"type\":\"hysteria\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1090,\"up_mbps\":100,\"down_mbps\":100,\"users\":[{\"auth_str\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-hysteria2:{\"type\":\"hysteria2\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1091,\"users\":[{\"password\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-tuic:{\"type\":\"tuic\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1092,\"users\":[{\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"password\":\"p\"}],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}" \
  "inbound-tun:{\"type\":\"tun\",\"tag\":\"i\",\"address\":[\"172.19.0.1/30\"],\"auto_route\":false}" \
  "inbound-tproxy:{\"type\":\"tproxy\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1093}" \
  "inbound-redirect:{\"type\":\"redirect\",\"tag\":\"i\",\"listen\":\"127.0.0.1\",\"listen_port\":1094}" \
  ; do
  name="${spec%%:*}"; body="${spec#*:}"
  check_config "$name" "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"inbounds\":[$body]}"
done

echo "== DNS transports (full registry) =="
for spec in \
  "dns-udp:{\"tag\":\"d\",\"type\":\"udp\",\"server\":\"127.0.0.1\"}" \
  "dns-tcp:{\"tag\":\"d\",\"type\":\"tcp\",\"server\":\"127.0.0.1\"}" \
  "dns-tls:{\"tag\":\"d\",\"type\":\"tls\",\"server\":\"127.0.0.1\"}" \
  "dns-https:{\"tag\":\"d\",\"type\":\"https\",\"server\":\"127.0.0.1\"}" \
  "dns-quic:{\"tag\":\"d\",\"type\":\"quic\",\"server\":\"127.0.0.1\"}" \
  "dns-h3:{\"tag\":\"d\",\"type\":\"h3\",\"server\":\"127.0.0.1\"}" \
  "dns-local:{\"tag\":\"d\",\"type\":\"local\"}" \
  "dns-hosts:{\"tag\":\"d\",\"type\":\"hosts\",\"path\":[\"$work/hosts.txt\"]}" \
  "dns-fakeip:{\"tag\":\"d\",\"type\":\"fakeip\",\"inet4_range\":\"198.18.0.0/15\"}" \
  ; do
  name="${spec%%:*}"; body="${spec#*:}"
  [ -f "$work/hosts.txt" ] || echo "127.0.0.1 localhost" > "$work/hosts.txt"
  # A fakeip server cannot be the default resolver, so pair it with a local server
  # that is the final one. This is upstream's own rule, not a fork restriction.
  check_config "$name" "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"dns\":{\"servers\":[{\"tag\":\"fallback\",\"type\":\"local\"},$body],\"final\":\"fallback\"}}"
done

echo "== endpoints / services =="
check_config "endpoint-wireguard" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"wg\",\"address\":[\"10.0.0.2/32\"],\"private_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"peers\":[{\"address\":\"127.0.0.1\",\"port\":51820,\"public_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"allowed_ips\":[\"0.0.0.0/0\"]}]}]}"
check_config "service-api" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"services\":[{\"type\":\"api\",\"tag\":\"api\",\"listen\":\"127.0.0.1\",\"listen_port\":19090}]}"

echo
echo "== capability smoke: $pass passed, $fail failed =="
if [ "$fail" -ne 0 ]; then
  echo "missing capabilities: ${failures[*]}" >&2
  echo "the binary does not carry the full upstream feature profile" >&2
  exit 1
fi
echo "PASS: full upstream feature profile present"
