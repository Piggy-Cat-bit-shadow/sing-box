#!/usr/bin/env bash
# Release mutation sweep.
#
# Every test that a release claim rests on is only worth what it notices. This runs the load
# balance sweep and then breaks the load-bearing lines of everything added since: the TCP splice
# diagnostics, the single action-to-options decision, and the v4-mapped ingress boundary.
#
# A mutation that leaves its named test green is a problem, not a curiosity: it means the test
# would not have caught the bug the mutation represents. Each one is restored immediately, and the
# suite is required to go green again, so a sweep that ends in a failing tree is a failure of the
# sweep rather than of the code.
#
# Usage: scripts/dev/release-mutation-sweep.sh   (from the repository root)
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
TAGS="$(cat release/DEFAULT_BUILD_TAGS)"
failures=0

# Applies a patch with python (multi-line anchors), runs the named test, requires red, restores,
# requires green.
run_case() {
    local name="$1" file="$2" pkg="$3" pattern="$4"
    local from="$5" to="$6"
    cp "$file" "/tmp/release-mutation-backup"

    python3 - "$file" "$from" "$to" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if old not in text:
    print("ANCHOR-MISSING", file=sys.stderr)
    sys.exit(3)
open(path, "w").write(text.replace(old, new, 1))
PY
    if [ $? -ne 0 ]; then
        echo "SKIP  $name (anchor not found)"
        cp /tmp/release-mutation-backup "$file"
        failures=$((failures + 1))
        return
    fi

    if go test -tags "$TAGS" -count=1 -timeout 300s -run "$pattern" "./$pkg/" >/tmp/release-mutation-run.log 2>&1; then
        echo "BAD   $name - the test named for this behaviour stayed GREEN"
        failures=$((failures + 1))
    else
        echo "ok    $name - red as expected"
    fi

    cp /tmp/release-mutation-backup "$file"
    if ! go test -tags "$TAGS" -count=1 -timeout 300s -run "$pattern" "./$pkg/" >/tmp/release-mutation-restore.log 2>&1; then
        echo "BAD   $name - the test did not go green again after restore"
        failures=$((failures + 1))
    fi
}

if [ "${SKIP_LOADBALANCE_SWEEP:-}" != "1" ]; then
    echo "== load balance =="
    bash scripts/dev/loadbalance-mutation-sweep.sh || failures=$((failures + 1))
fi

echo
echo "== TCP splice diagnostics =="

run_case "S1 the stream decision stops recording" route/splice.go route \
    'TestTCPSplice' \
    $'\t\tm.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)\n' \
    ''

run_case "S2 a target rejection recorded as a success" route/splice.go route \
    'TestTCPSplice' \
    'm.tcpSpliceDiagnostics.recordOutcome(tcpSpliceTargetReason(targetReason))' \
    'm.tcpSpliceDiagnostics.recordOutcome(spliceReasonSuccess)'

run_case "S3 a declined handover claims success and skips the copy fallback" route/splice.go route \
    'TestTCPSplice' \
    $'\t\tm.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)\n\t\treturn false, nil' \
    $'\t\tm.tcpSpliceDiagnostics.recordOutcome(spliceReasonSourceNotGoConn)\n\t\treturn true, nil'

echo
echo "== pre-match / full-match equivalence =="

run_case "P1 the pre-match asymmetry restored (bypass applies options with no outbound)" route/route.go route \
    'TestPreMatchAndFullMatchAgreeOnBypass' \
    $'\t\t\tapplyActionRouteOptions(&metadata, action)\n\t\t\tif action.Outbound == "" {' \
    $'\t\t\tapplyRouteOptionsMetadata(&metadata, &action.RuleActionRouteOptions)\n\t\t\tif action.Outbound == "" {'

run_case "P2 one field dropped by the shared applier" route/route.go route \
    'TestPreMatchAndFullMatchAgreeOnEveryOption' \
    '\tif routeOptions.OverridePort > 0 {' \
    '\tif false && routeOptions.OverridePort > 0 {'

run_case "P3 the full match path stops applying options" route/route.go route \
    'TestBothPassesShareTheActionDecision' \
    $'\t\tif applyActionRouteOptions(metadata, currentRule.Action()) {\n\t\t\t// TODO: add nat\n\t\t}' \
    $'\t\tif false {\n\t\t\t// MUTATION\n\t\t}'

echo
echo "== v4-mapped ingress boundary =="

run_case "M1 the NAT64 prefix treated as mapped" protocol/tun/inbound.go protocol/tun \
    'TestOnlyV4Mapped|TestNAT64' \
    $'func canonicalAddrPort(destination netip.AddrPort) netip.AddrPort {\n\taddress := destination.Addr()' \
    $'var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")\n\nfunc canonicalAddrPort(destination netip.AddrPort) netip.AddrPort {\n\taddress := destination.Addr()\n\tif nat64Prefix.Contains(address) {\n\t\tbytes := address.As16()\n\t\treturn netip.AddrPortFrom(netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]}), destination.Port())\n\t}'

run_case "M2 canonicalisation removed" protocol/tun/inbound.go protocol/tun \
    'TestOnlyV4Mapped|TestNAT64|TestMapped' \
    $'\taddress := destination.Addr()\n\tif !address.Is4In6() {\n\t\treturn destination\n\t}\n\treturn netip.AddrPortFrom(address.Unmap(), destination.Port())' \
    '\treturn destination'

echo
if [ "$failures" -eq 0 ]; then
    echo "release mutation sweep: PASS - every named test noticed its mutation"
else
    echo "release mutation sweep: $failures problem(s)"
fi
exit "$failures"
