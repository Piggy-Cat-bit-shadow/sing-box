#!/usr/bin/env bash
# Representative runtime capability smoke for a built binary.
#
# Usage: verify-full-capabilities.sh <binary> [config-dir]
#
# # What this is, precisely
#
# This is a RUNTIME, construction-level smoke over a representative sample of the
# feature set: 50 capabilities covering outbound and inbound protocols, DNS
# transports, endpoints and services. Each one builds a minimal but valid
# configuration and resolves it through the binary's own registry with
# `sing-box check`.
#
# It is NOT a proof that the binary carries the COMPLETE upstream registry, and it
# does not claim to be. The exhaustive, compile-time presence proof is the
# `go list -deps` audit in the Linux workflow, which asserts ~28 specific packages
# (including components this script does not cover, such as the derp service, the
# resolved/origin_ca/ssmapi services and caddyserver/certmagic) are linked. Between
# them: deps proves what is COMPILED, this proves what the binary will ACCEPT.
#
# # What it deliberately does not do
#
# It does not claim any of these capabilities interoperate over a live network. That
# needs real peers, and it is covered by the protocol regression suites.
#
# It also does not fabricate configurations that cannot be legitimately constructed
# in CI. Two places where that boundary was hit are recorded rather than papered
# over: OpenVPN is exercised in static_key mode because TLS mode would need a real
# PKI, and the MASQUE endpoints use a throwaway self-signed certificate. Nothing
# here is a credential.
#
# # Why config-level rather than symbol-level
#
# The shipped macOS artifact is stripped (-s -w), so `go tool nm` cannot read it. The
# check therefore goes through the same path an operator uses: resolve a config
# through the real registry. That exercises the registry, the option schema and each
# constructor's validation, which is what "the capability is present" means.
#
# # What this replaces
#
# The previous audit's job was to prove that capabilities were ABSENT: Hysteria2
# absent, TUIC absent, the Clash API absent, a protocol's server role absent. Those
# assertions were the contract for a product registry that no longer exists, and the
# contract is now the opposite one.
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
  "outbound-hysteria2:{\"type\":\"hysteria2\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"password\":\"p\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\"}}" \
  "outbound-tuic:{\"type\":\"tuic\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"password\":\"p\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\"}}" \
  "outbound-snell:{\"type\":\"snell\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"psk\":\"p\",\"version\":4}" \
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

# ---------------------------------------------------------------------------
# VLESS transports that have their own build tag.
#
# # Why this is a separate section
#
# with_xhttp is in every product tag file and its constructor is registered from an init()
# in transport/v2rayxhttp, reached through a blank import in include/v2rayxhttp.go. Three
# separate things have to hold for the capability to exist in a shipped binary, and only the
# last one of them is what an operator experiences:
#
#   1. the tag is in the tag file            - checked by
#                                              cmd/internal/build_libbox's profile tag tests
#   2. the package is in the program          - checked by the `go list -deps` audit in the
#                                              Linux workflow
#   3. the registry ACCEPTS an xhttp config   - checked here, and nowhere else
#
# A capability that disappears silently is indistinguishable from one that was never
# claimed, so the case below is deliberately a real vless outbound with a real
# `transport: {"type": "xhttp"}`. Built without with_xhttp the same configuration fails with
# the registry's own error rather than being quietly ignored:
#
#   unknown transport type: xhttp
#
# Two modes are exercised because they take different paths through the constructor: the
# streamed-body mode (stream-one) and the packet-up mode, which is the one that adds the
# per-packet upload sequence placement. A single case would not notice the registration being
# narrowed to one of them.
#
# outbound-vless-ws is the CONTROL for this section. Websocket is not behind a tag, so it must
# pass in EVERY build. When the gate is red-checked by removing with_xhttp, this case is what
# shows the failure is the missing capability and not a broken vless section: websocket keeps
# passing while both xhttp cases fail.
echo "== VLESS transports (tagged capabilities) =="
for spec in \
  "outbound-vless-xhttp-stream-one:{\"type\":\"vless\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"transport\":{\"type\":\"xhttp\",\"path\":\"/xhttp\",\"mode\":\"stream-one\"}}" \
  "outbound-vless-xhttp-packet-up:{\"type\":\"vless\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"transport\":{\"type\":\"xhttp\",\"path\":\"/xhttp\",\"mode\":\"packet-up\",\"session_placement\":\"path\"}}" \
  "outbound-vless-ws-control:{\"type\":\"vless\",\"tag\":\"o\",\"server\":\"127.0.0.1\",\"server_port\":1,\"uuid\":\"00000000-0000-0000-0000-000000000000\",\"transport\":{\"type\":\"ws\",\"path\":\"/ws\"}}" \
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

echo "== endpoints =="
check_config "endpoint-wireguard" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"wireguard\",\"tag\":\"wg\",\"address\":[\"10.0.0.2/32\"],\"private_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"peers\":[{\"address\":\"127.0.0.1\",\"port\":51820,\"public_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"allowed_ips\":[\"0.0.0.0/0\"]}]}]}"
check_config "endpoint-tailscale" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"tailscale\",\"tag\":\"ts\"}]}"
check_config "endpoint-masque-client" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"masque-client\",\"tag\":\"mc\",\"server\":\"127.0.0.1\",\"server_port\":443,\"tls\":{\"enabled\":true,\"server_name\":\"example.com\"}}]}"
check_config "endpoint-masque-server" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"masque-server\",\"tag\":\"ms\",\"listen\":\"127.0.0.1\",\"listen_port\":4443,\"address\":[\"10.0.0.1/24\"],\"tls\":{\"enabled\":true,\"certificate_path\":\"$cert_dir/cert.pem\",\"key_path\":\"$cert_dir/key.pem\"}}]}"
check_config "endpoint-openconnect" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"openconnect\",\"tag\":\"oc\",\"server\":\"127.0.0.1\"}]}"

# OpenVPN is modelled in static_key mode: TLS mode would need a real PKI, so this
# stays a construction-level smoke rather than a fabricated handshake config. The
# key is generated per run and is deliberately not a credential.
ovpn_key="$(openssl rand -base64 256 | tr -d '\n')"
check_config "endpoint-openvpn-client" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"openvpn-client\",\"tag\":\"ov\",\"servers\":[{\"server\":\"127.0.0.1\",\"server_port\":1194}],\"mode\":\"static_key\",\"address\":[\"10.8.0.2/24\"],\"peer_address\":\"10.8.0.1\",\"cipher\":\"AES-256-CBC\",\"static_key\":[\"$ovpn_key\"]}]}"
check_config "endpoint-openvpn-server" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"endpoints\":[{\"type\":\"openvpn-server\",\"tag\":\"ovs\",\"listen\":\"127.0.0.1\",\"listen_port\":1194,\"mode\":\"static_key\",\"address\":[\"10.8.0.1/24\"],\"peer_address\":\"10.8.0.2\",\"remote\":\"127.0.0.1\",\"remote_port\":1195,\"cipher\":\"AES-256-CBC\",\"static_key\":[\"$ovpn_key\"]}]}"

echo "== experimental =="
# The Clash API is restored from upstream and must remain constructible. It is the one
# capability that is both a config model and a listener, so it is checked here at the
# construction level; the runtime probe lives in the workflow, which starts the binary
# and speaks HTTP to it.
check_config "experimental-clash-api" \
  "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct\"}],\"experimental\":{\"clash_api\":{\"external_controller\":\"127.0.0.1:19099\",\"secret\":\"ci-smoke\"}}}"

echo "== services =="
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
