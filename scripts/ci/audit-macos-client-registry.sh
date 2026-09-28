#!/usr/bin/env bash
# Registry and symbol audit for the Jiejie macOS client core.
#
# Usage: audit-macos-client-registry.sh [binary]
#
# This script answers two different questions, because either one alone can lie:
#
#   1. TYPE-LEVEL: is every protocol the client fixture names actually
#      resolvable through the registry? A build can link a protocol package and
#      still fail to REGISTER it, which only shows up at runtime as "unknown
#      outbound type". `sing-box check` answers this, and this script runs it.
#
#   2. LINK-LEVEL: did a package the profile deliberately excludes stay out of
#      the binary? "The source tree contains it" proves nothing, so this reads
#      the real symbol table with `go tool nm`.
#
# The symbol check uses a temporary UNSTRIPPED copy. -s -w removes the symbol
# table, so auditing the shipped artifact directly is impossible by construction;
# the copy is built into a temp directory and never uploaded.
set -euo pipefail

binary="${1:-dist/sing-box-darwin-arm64}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Resolve the binary to an ABSOLUTE path BEFORE changing directory.
#
# The flavor is derived from `basename "$binary"` below, so the NAME must still be
# visible after resolution - which it is, since only the directory part changes.
#
# This matters because the script cd's to the repository root and then invokes
# "$binary" for the type-level checks. A relative path is therefore resolved
# against the root, not against the caller's directory: invoked from CI with
# `dist/sing-box-darwin-arm64` from a different working directory, every
# "$binary" invocation failed with "command not found" while the surrounding
# assertions reported the failure as a fixture problem.
case "$binary" in
  /*) ;;
  *)
    if [ -e "$binary" ]; then
      binary="$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")"
    elif [ -e "$root/$binary" ]; then
      binary="$root/$binary"
    fi
    ;;
esac
if [ ! -x "$binary" ]; then
  echo "binary not found or not executable: $binary" >&2
  exit 2
fi

cd "$root"

# The flavor decides which tag file is used, and therefore whether Cronet is
# There is exactly ONE macOS core, so there is exactly one tag set. The audit does
# not derive anything from the binary NAME any more: a name-based flavor guess was
# only meaningful while a lite/naive pair existed, and keeping it would have meant
# keeping the ability to audit a profile that no longer ships.
tags="$(cat release/BUILD_TAGS_JIEJIE_CLIENT_MACOS)"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# The shipped macOS artifact is now STRIPPED (-s -w), so `go tool nm` on it yields
# no Go symbols -- verified: zero symbols matching sing-box. This audit therefore
# builds its own UNSTRIPPED analysis copy.
#
# That copy exists only to be read by this script. It is written to a temporary
# directory, deleted on exit, and NEVER uploaded: there is exactly one shipped
# macOS artifact, and it is the stripped one.
#
# # Why symbol analysis is still worth doing at all
#
# It is no longer the PRIMARY evidence. The layers that decide whether this product
# works are, in order of strength:
#
#   1. registry unit tests        -- do the required types resolve, and do the
#                                    excluded ones fail to?
#   2. source/build-graph         -- go list -deps, which needs no build at all
#   3. config check               -- the shipped binary validating the real fixture
#   4. RUNTIME smoke             -- the shipped binary actually serving the Native
#                                    API and the Dashboard
#
# This script is layer 5: a static cross-check on the LINKED image, catching the
# case where a package is present in the graph but its code was dropped (or the
# reverse). Layers 3 and 4 run against the STRIPPED artifact and are what actually
# gate the product; this one explains WHY a failure happened.
#
# A symbol name was never strong evidence on its own -- which is why the naive
# outbound check below tests for the real Cronet constructor AND for the absence of
# the not-included stub's message, rather than for the type being registered.
nm_out="$tmpdir/nm.txt"
go tool nm "$binary" > "$nm_out" 2>/dev/null || true

# The test is for GO symbols, not for a non-empty file.
#
# A stripped Go binary still has a symbol table for its C and Objective-C
# dependencies, so `[ -s "$nm_out" ]` is TRUE on the stripped artifact while every
# Go symbol is gone. An earlier version of this script tested exactly that, decided
# the shipped binary was analysable, and then reported every "included package"
# check as FAILING -- 34 false failures, because it was reading the absence of the
# symbols it was looking for as evidence the code was missing. That is the same
# class of error this file has produced before: the check could not distinguish
# "the thing is absent" from "the measurement did not happen".
if ! grep -q "sing-box/" "$nm_out"; then
  echo "note: $binary carries no Go symbols (stripped), so it cannot be audited statically"
  echo "      building an unstripped analysis copy; it is deleted on exit and never uploaded"
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build \
    -trimpath -buildvcs=false -tags "$tags" \
    -o "$tmpdir/audit" ./cmd/sing-box
  go tool nm "$tmpdir/audit" > "$nm_out"
  if ! grep -q "sing-box/" "$nm_out"; then
    echo "FAIL: the analysis copy has no Go symbols either; this audit cannot run" >&2
    exit 1
  fi
  echo "analysing the unstripped analysis copy (the shipped artifact is stripped)"
else
  echo "analysing the shipped binary directly (it carries Go symbols, so it is unstripped)"
fi

# ---------------------------------------------------------------------------
# 1. Excluded packages must have no symbols.
# ---------------------------------------------------------------------------
#
# Each entry is a package the client registry deliberately does not import. A
# nonzero count means something dragged it back into the import graph, which is
# exactly the regression this audit exists to catch.
excluded_packages=(
  "protocol/openvpn"
  "protocol/openconnect"
  "protocol/ssh"
  "protocol/tor"
  "protocol/redirect"
  "service/resolved"
  "service/ssmapi"
  "service/usbip"
  "protocol/wireguard"
  "protocol/hysteria"          # Hysteria v1: superseded by Hysteria2
  "dns/transport/dhcp"
  "protocol/bridge"
)

# protocol/masque is deliberately NOT in the list above.
#
# It used to be, on the reasoning that "the macOS client connects through ordinary
# proxy protocols" and MASQUE was a server concern. That was wrong: MASQUE is a
# first-class Jiejie CLIENT transport, and excluding the whole package meant a
# valid `type: masque-client` configuration failed with "unknown endpoint type"
# even though the implementation was compiled in.
#
# The distinction that actually matters is CLIENT PRESENT / SERVER ABSENT, which
# a package-level check cannot express because both roles live in one package.
# The role split is asserted at symbol level below and at type level in
# test/jiejie/macos_client_registry_audit_test.go.

# The MASQUE role split, asserted at symbol level.
#
# protocol/masque holds BOTH endpoint roles. The macOS client must link the client
# role and must NOT link the server role, and only the symbol table can tell the
# difference. Registering the client role alone in the registry is not sufficient
# evidence on its own: if some other package pulled in the server constructor, the
# server endpoint would be linked as dead weight in the artifact.
#
# The positive evidence is NewClientEndpoint and its METHOD SET, not
# RegisterClientEndpoint: the registrar is a two-line wrapper with a single call
# site, so the linker inlines it away and no symbol survives. Asserting on the
# registrar would produce a permanent false FAIL, which is worse than having no
# check at all -- it trains a reader to ignore the audit. The methods are the
# honest evidence that the client ENDPOINT is really linked, and they are what
# cannot be inlined.
masque_client_symbols=(
  "masque.NewClientEndpoint"
  "masque.(*ClientEndpoint)"
)

# masque.NewServerEndpoint is the server role's constructor, and
# masque.RegisterEndpoint is the COMBINED helper. The client registry must call
# neither: the combined helper registers masque-server too, which is exactly the
# mistake this audit is here to catch.
#
# (*ServerEndpoint) is asserted as well because the TYPE is what would actually
# ship: a build that linked the type but not the registrar would still carry the
# whole server endpoint implementation.
masque_server_symbols=(
  "masque.NewServerEndpoint"
  "masque.RegisterEndpoint"
  "masque.(*ServerEndpoint)"
)

# The Native Naive HTTP/3 listener is a SERVER and must not be linked into the
# macOS client.
#
# include/quic_client_macos.go used to import protocol/naive/quic, whose init()
# installs naive.ConfigureHTTP3ListenerFunc (qtls.ListenEarly + http3.Server) and
# naive.WrapError. Both are consumed only by protocol/naive/inbound.go and
# protocol/naive/inbound_conn.go -- the Naive INBOUND. The macOS client is
# outbound-only and never constructs that inbound, so the import linked an
# unreachable HTTP/3 server listener stack into the artifact.
#
# Naive outbound over HTTP/2 and over QUIC/HTTP3 is unaffected: it goes through
# cronet.NewNaiveClient, which the flavor check further down still requires.
naive_server_h3_symbols=(
  "naive.ConfigureHTTP3ListenerFunc"
  "naive.WrapError"
  "sing-box/protocol/naive/quic."
)

# dns/transport/mdns is deliberately NOT asserted absent, and that is a finding
# rather than an oversight.
#
# The client registry does not register mdns, and cannot avoid linking it:
# dns/transport/local imports dns/transport/mdns UNCONDITIONALLY (local.go and
# local_preferred.go carry no build tag and use mdns for the neighbour /
# preferred-domain resolver), and `local` is a mandatory boot dependency because
# box.go initialises the DNS transport manager with a local fallback. So mdns is
# reachable from a package every profile must register.
#
# Removing it would require editing upstream dns/transport/local, which this
# fork does not do: the trim is registration-level and build-tag-level only, and
# upstream build capability must keep working. The honest response is to record
# the coupling instead of asserting a trim that does not exist. The practical
# consequence is small: mdns is not registered, so no configuration can name it
# as a transport type; what links is IsLocalDomain and two group-address
# variables.
mdns_coupled_via="dns/transport/local"

# The Tailscale endpoint/outbound must be absent, but `protocol/tailscale` as a
# PACKAGE is not fully absent and must not be asserted away: upstream ships
# cmd/sing-box/cmd_generate_tailcat.go, which imports the package for the
# standalone `sing-box generate tailcat-keypair` CLI helper. That is upstream
# command behaviour, unrelated to the registry, and asserting on the whole
# package would make this audit fail on a correct build. The endpoint and
# outbound symbols are what actually matter, so they are asserted directly.
excluded_symbols=(
  "tailscale.NewEndpoint"
  "tailscale.RegisterEndpoint"
  "tailscale.NewOutbound"
  "tailscale.RegisterOutbound"
)

fail=0

echo ""
echo "== excluded packages (must have 0 symbols) =="
for pkg in "${excluded_packages[@]}"; do
  count="$(grep -c "sing-box/$pkg\." "$nm_out" || true)"
  if [ "$count" -eq 0 ]; then
    echo "PASS: $pkg absent"
  else
    echo "FAIL: $pkg has $count linked symbols" >&2
    grep "sing-box/$pkg\." "$nm_out" | head -5 >&2
    fail=1
  fi
done

echo ""
echo "== excluded symbols (must have 0 occurrences) =="
for sym in "${excluded_symbols[@]}"; do
  count="$(grep -cF "$sym" "$nm_out" || true)"
  if [ "$count" -eq 0 ]; then
    echo "PASS: $sym absent"
  else
    echo "FAIL: $sym is linked" >&2
    fail=1
  fi
done

echo ""
echo "== MASQUE role split (client present, server absent) =="
for sym in "${masque_client_symbols[@]}"; do
  count="$(grep -cF "$sym" "$nm_out" || true)"
  if [ "$count" -gt 0 ]; then
    echo "PASS: client role symbol $sym is linked ($count)"
  else
    echo "FAIL: client role symbol $sym is MISSING; masque-client would not resolve" >&2
    fail=1
  fi
done
for sym in "${masque_server_symbols[@]}"; do
  count="$(grep -cF "$sym" "$nm_out" || true)"
  if [ "$count" -eq 0 ]; then
    echo "PASS: server role symbol $sym absent"
  else
    echo "FAIL: server role symbol $sym is linked; masque-server leaked into the client" >&2
    grep -F "$sym" "$nm_out" | head -5 >&2
    fail=1
  fi
done

# The shared data plane must be present for BOTH roles: this is the "one source
# tree" property. If transport/masque were absent the client role could not work.
masque_shared_packages=(
  "transport/masque"
  "transport/http"
)
for pkg in "${masque_shared_packages[@]}"; do
  count="$(grep -c "sing-box/$pkg\." "$nm_out" || true)"
  if [ "$count" -gt 0 ]; then
    echo "PASS: shared MASQUE data plane $pkg is linked ($count symbols)"
  else
    echo "FAIL: shared MASQUE data plane $pkg has no symbols" >&2
    fail=1
  fi
done

echo ""
echo "== Native Naive server HTTP/3 listener (must be absent from the client) =="
for sym in "${naive_server_h3_symbols[@]}"; do
  count="$(grep -cF "$sym" "$nm_out" || true)"
  if [ "$count" -eq 0 ]; then
    echo "PASS: naive server H3 symbol $sym absent"
  else
    echo "FAIL: naive server H3 symbol $sym is linked; the client profile is" \
         "linking a server it cannot run" >&2
    grep -F "$sym" "$nm_out" | head -5 >&2
    fail=1
  fi
done

# ---------------------------------------------------------------------------
# 2. Included protocols must have symbols.
# ---------------------------------------------------------------------------
#
# A registry that names a type whose package the linker dropped would fail at
# runtime, so this is the mirror image of the check above: the client protocols
# must be genuinely present, not merely mentioned in a source file.
included_packages=(
  # The production allowlist. Each entry must have linked symbols, which is what
  # proves the registration is backed by a real implementation rather than a stub.
  #
  # protocols removed from the product (socks, snell, trojan, vmess, hysteria2,
  # tuic) are deliberately ABSENT from this list: asserting their symbols would
  # assert the opposite of the product definition. They are covered instead by the
  # exclusion list below, which fails if they come back.
  "protocol/tun"
  "protocol/mixed"
  "protocol/http"              # the MASQUE client outbound shares this package
  "protocol/block"
  "protocol/group"
  "protocol/shadowsocks"
  "protocol/shadowtls"
  "protocol/vless"
  "protocol/anytls"
  "protocol/masque"            # the CLIENT role; server role asserted absent above
  "dns/transport/fakeip"
  "dns/transport/hosts"
  "dns/transport/local"
  "dns/transport/quic"
)

echo ""
echo "== included packages (must have >0 symbols) =="
for pkg in "${included_packages[@]}"; do
  count="$(grep -c "sing-box/$pkg\." "$nm_out" || true)"
  if [ "$count" -gt 0 ]; then
    echo "PASS: $pkg present ($count symbols)"
  else
    echo "FAIL: $pkg has no linked symbols" >&2
    fail=1
  fi
done

# ---------------------------------------------------------------------------
# 3. Type-level registry audit, driven by the fixture rather than a list.
# ---------------------------------------------------------------------------
#
# This is the check that cannot drift: adding a protocol to the fixture without
# registering it fails here, naming the missing type, instead of surfacing later
# as a runtime "unknown outbound type".
echo ""
echo "== registry resolves every type the fixture names =="
echo "checking fixture config (unknown types fail here)"
if "$root/scripts/ci/check-macos-client-config.sh" "$binary" "$tmpdir/fixture" >/dev/null 2>&1; then
  echo "PASS: every inbound/outbound/DNS type in the client fixture resolves"
else
  echo "FAIL: the client fixture does not pass sing-box check" >&2
  "$root/scripts/ci/check-macos-client-config.sh" "$binary" "$tmpdir/fixture" >&2 || true
  fail=1
fi

# A type the profile excludes must be REJECTED. This proves the trim is real at
# the type level rather than only in the symbol table.
rejected="$tmpdir/rejected.json"
cat > "$rejected" <<'JSON'
{
  "log": {"level": "error"},
  "outbounds": [{"type": "tor", "tag": "tor-out"}]
}
JSON
if "$binary" check -c "$rejected" >/dev/null 2>&1; then
  echo "FAIL: an excluded outbound type (tor) was accepted by the client build" >&2
  fail=1
else
  echo "PASS: an excluded outbound type (tor) is rejected"
fi

# masque-server must be rejected as an endpoint type while masque-client is
# accepted. This is the type-level half of the role split: the symbol audit above
# proves what is LINKED, this proves what the registry RESOLVES, and a profile can
# get either one wrong independently.
masque_server_cfg="$tmpdir/masque-server.json"
cat > "$masque_server_cfg" <<'JSON'
{
  "log": {"level": "error"},
  "endpoints": [{"type": "masque-server", "tag": "ms", "system": false}]
}
JSON
if "$binary" check -c "$masque_server_cfg" >/dev/null 2>&1; then
  echo "FAIL: masque-server is registered in the macOS client build" >&2
  fail=1
else
  echo "PASS: masque-server is rejected as an endpoint type in the client build"
fi

masque_client_cfg="$tmpdir/masque-client.json"
cat > "$masque_client_cfg" <<'JSON'
{
  "log": {"level": "error"},
  "endpoints": [{
    "type": "masque-client",
    "tag": "mc",
    "server": "example.com",
    "server_port": 443,
    "tls": {"enabled": true, "server_name": "example.com"}
  }]
}
JSON
if "$binary" check -c "$masque_client_cfg" >/dev/null 2>&1; then
  echo "PASS: masque-client resolves and validates in the client build"
else
  echo "FAIL: masque-client does not resolve in the macOS client build" >&2
  "$binary" check -c "$masque_client_cfg" >&2 || true
  fail=1
fi

echo ""
echo "== mdns: linked via local, but must NOT be registered =="
# The distinction that matters. mdns being linked is an upstream import
# consequence; mdns being a usable transport type would be a registry leak. The
# check is behavioural, not symbolic: a config naming `type: mdns` must be
# rejected.
mdns_cfg="$tmpdir/mdns.json"
cat > "$mdns_cfg" <<'JSON'
{
  "log": {"level": "error"},
  "dns": {"servers": [{"tag": "m", "type": "mdns", "service": "_http._tcp.local"}]}
}
JSON
if "$binary" check -c "$mdns_cfg" >/dev/null 2>&1; then
  echo "FAIL: the mdns DNS transport is registered in the client build" >&2
  fail=1
else
  echo "PASS: mdns is linked ($mdns_coupled_via) but not registered as a transport type"
fi

# ---------------------------------------------------------------------------
# 4. The product capabilities must genuinely be linked.
# ---------------------------------------------------------------------------
#
# The macOS core is ONE product, so this section asserts what it CONTAINS rather
# than distinguishing it from a sibling profile. The distinction still matters,
# because the `naive` TYPE resolves either way: upstream's
# include/naive_outbound_stub.go registers it behind `!with_naive_outbound` so a
# user gets an actionable error instead of "unknown outbound type". A type-level
# check therefore cannot tell a real NaiveProxy implementation from a stub, which
# is precisely what the symbol table answers.
#
# NaiveProxy and MASQUE are the two transports this core exists for, so their
# absence is a hard failure rather than a note.
echo ""
echo "== product capability: NaiveProxy (Cronet) =="
naive_symbols="$(grep -c "cronet-go" "$nm_out" || true)"
if [ "$naive_symbols" -gt 0 ]; then
  echo "PASS: with_naive_outbound is set and Cronet symbols are linked ($naive_symbols)"
else
  echo "FAIL: with_naive_outbound is set but NO Cronet symbols are linked; the" >&2
  echo "      shipped core cannot speak NaiveProxy" >&2
  fail=1
fi

# A substring count over the whole cronet-go tree is NOT proof that the NaiveProxy
# client itself is present: any shared helper, CGO shim or vendored utility from that
# module would satisfy it. The constructor is the symbol the `naive` outbound actually
# calls, so it is asserted by NAME. This is the assertion the retired
# "product capability verification" workflow step made, folded in here so the binary's
# symbol table is read once.
if grep -qF "cronet-go.NewNaiveClient" "$nm_out"; then
  echo "PASS: cronet-go.NewNaiveClient is linked (the real Naive outbound constructor)"
else
  echo "FAIL: cronet-go.NewNaiveClient is MISSING. cronet-go symbols exist, but not the" >&2
  echo "      constructor the naive outbound calls, so a \`type: naive\` config may still" >&2
  echo "      resolve to a stub. Refusing to accept a substring match as proof." >&2
  fail=1
fi

# The stub must NOT be what is linked. If both the stub and the real
# implementation were present the binary would be larger than needed and the
# resolution order would decide which one a configuration got, which is not a
# property this audit is willing to leave to chance.
if grep -qF "naive outbound is not included in this build" "$nm_out"; then
  echo "FAIL: the naive outbound STUB string is linked, so the real implementation" >&2
  echo "      may not be the one that resolves" >&2
  fail=1
else
  echo "PASS: the naive not-included stub is absent (the real outbound is linked)"
fi

echo ""
echo "== removed dependency: gVisor must be ABSENT =="
#
# with_gvisor was REMOVED from this product. The production configuration declares a
# tun inbound with no `stack` field, and sing-tun resolves unset to "" -> NewGo, the
# Go userspace stack; stack="gvisor"/"mixed" (the only paths that reach gVisor) are
# never configured. Verified against sing-tun's NewStack with the tag absent: <unset>
# and "go" both still work, while "gvisor" and "mixed" return the documented
# "rebuild with -tags with_gvisor" error rather than failing silently.
#
# This is a NEGATIVE assertion, i.e. the mirror of the one it replaced. It fails if
# gVisor comes back, which is what keeps a 3.89 MiB dependency from being
# reintroduced by an upstream sync or a careless tag-file edit.
gvisor_symbols="$(grep -c "sagernet/gvisor" "$nm_out" || true)"
if [ "$gvisor_symbols" -gt 0 ]; then
  echo "FAIL: gVisor is linked ($gvisor_symbols symbols); it was removed from this" >&2
  echo "      product because the tun inbound uses the Go stack" >&2
  fail=1
else
  echo "PASS: gVisor is absent (the tun inbound uses the Go stack)"
fi

echo ""
echo "== product capability: the TUN stack that IS used =="
#
# The positive half. Removing gVisor is only safe if the Go stack is genuinely
# present, so this asserts sing-tun's own symbols rather than trusting the tag.
if grep -q "sing-tun" "$nm_out"; then
  echo "PASS: sing-tun is linked ($(grep -c "sing-tun" "$nm_out") symbols); the tun inbound has a real stack"
else
  echo "FAIL: no sing-tun symbols; the tun inbound could not create any stack" >&2
  fail=1
fi

echo "== removed feature: LXD daemon package must be ABSENT =="
#
# The LXD daemon and the `sing-box lxd` subcommand were removed from this fork, so
# the package must not be linked at all. This is a negative assertion: it fails if
# the package comes back, which is what makes the removal a property of the build
# rather than a one-time edit.
if grep -qF "sing-box/lxd." "$nm_out"; then
  echo "FAIL: sing-box/lxd. is linked; the LXD daemon was removed from this fork" >&2
  fail=1
else
  echo "PASS: the LXD daemon package is absent"
fi

echo ""
echo "== removed feature: Clash API must be ABSENT =="
if grep -qF "sing-box/experimental/clashapi." "$nm_out"; then
  echo "FAIL: experimental/clashapi is linked; the Clash API was removed from this fork" >&2
  fail=1
else
  echo "PASS: the Clash API package is absent"
fi

echo ""
echo "== product capability: MASQUE =="
masque_symbols="$(grep -cF 'sing-box/transport/masque.' "$nm_out" || true)"
if [ "$masque_symbols" -gt 0 ]; then
  echo "PASS: the shared MASQUE data plane is linked ($masque_symbols symbols)"
else
  echo "FAIL: transport/masque has no symbols; the MASQUE transport is unavailable" >&2
  fail=1
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "REGISTRY AUDIT: FAIL" >&2
  exit 1
fi
echo "REGISTRY AUDIT: PASS"
