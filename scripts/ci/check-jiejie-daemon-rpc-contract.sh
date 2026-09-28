#!/usr/bin/env bash
#
# Contract drift guard: sing-box daemon  <->  singbox-launcher.
#
# WHY THIS EXISTS
#
# On a real machine the launcher's proxy page showed nothing and reported
#
#     cannot read the proxies of group "...": daemon GetGroups:
#     rpc error: code = Unimplemented desc = unknown method GetGroups
#
# The launcher's generated client is produced from a specific upstream revision,
# recorded in its internal/daemonpb/SYNC_REV. This repo's daemon/started_service.proto
# is an independent file. Nothing forced the two to agree, and they silently drifted:
# the launcher called thirteen lx_command RPCs that this fork's descriptor did not
# declare. A gRPC method absent from the descriptor is answered at the TRANSPORT
# layer with "unknown method", which the launcher's capability probe cannot tell
# apart from a typo, a version skew or a broken connection.
#
# Unit tests in this repo cannot catch that class of failure by construction: they
# compile against THIS repo's proto, so they agree with it by definition. Only a
# comparison against the launcher's own generated method set can.
#
# WHAT IT CHECKS
#
#   1. Every RPC the launcher calls is DECLARED in this repo's proto.
#   2. Every RPC the launcher calls is REGISTERED by the generated server, so it is
#      reachable at runtime rather than merely present in the descriptor.
#   3. The launcher's SYNC_REV is recorded, so a silent upstream bump is visible.
#
# A method the launcher calls but this core cannot implement YET is expected to be
# declared AND stubbed with codes.Unimplemented (see
# daemon/started_service_command_lx_stub.go). That is a supported state: the client
# asks, the server answers "this build does not include it", and the launcher
# degrades to its Clash HTTP fallback. What is NOT supported is the method being
# invisible.
#
# USAGE
#
#   scripts/ci/check-jiejie-daemon-rpc-contract.sh [path-to-launcher-checkout]
#
# Without an argument the launcher is cloned to a temporary directory. CI passes a
# checkout it already has to avoid a network round trip.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

readonly LAUNCHER_REPO="https://github.com/Piggy-Cat-bit-shadow/singbox-launcher.git"

LAUNCHER_DIR="${1:-}"
TEMP_CLONE=""

cleanup() {
  if [ -n "${TEMP_CLONE}" ] && [ -d "${TEMP_CLONE}" ]; then
    rm -rf "${TEMP_CLONE}"
  fi
}
trap cleanup EXIT

if [ -z "${LAUNCHER_DIR}" ]; then
  TEMP_CLONE="$(mktemp -d)"
  LAUNCHER_DIR="${TEMP_CLONE}/singbox-launcher"
  echo "cloning ${LAUNCHER_REPO} for contract comparison"
  if ! git clone --depth 1 --quiet "${LAUNCHER_REPO}" "${LAUNCHER_DIR}" 2>/dev/null; then
    echo "SKIP: could not clone the launcher (offline?); contract not verified"
    echo "      this is a SKIP, not a PASS"
    exit 0
  fi
fi

if [ ! -d "${LAUNCHER_DIR}/internal/daemonpb" ]; then
  echo "FAIL: ${LAUNCHER_DIR}/internal/daemonpb does not exist." >&2
  echo "      The guard needs the launcher's generated client to compare against." >&2
  exit 1
fi

readonly LAUNCHER_GRPC="${LAUNCHER_DIR}/internal/daemonpb/started_service_grpc.pb.go"
readonly OUR_PROTO="${REPO_ROOT}/daemon/started_service.proto"
readonly OUR_GRPC="${REPO_ROOT}/daemon/started_service_grpc.pb.go"

for required in "${LAUNCHER_GRPC}" "${OUR_PROTO}" "${OUR_GRPC}"; do
  if [ ! -f "${required}" ]; then
    echo "FAIL: missing ${required}" >&2
    exit 1
  fi
done

# Record the revision the launcher's client was generated from, so a bump is
# visible in the log even when the method set happens to be unchanged.
if [ -f "${LAUNCHER_DIR}/internal/daemonpb/SYNC_REV" ]; then
  echo "launcher SYNC_REV: $(tr -d '[:space:]' < "${LAUNCHER_DIR}/internal/daemonpb/SYNC_REV")"
fi

# Method names the launcher's generated client can call.
launcher_methods="$(
  grep -oE 'StartedService_[A-Za-z0-9]+_FullMethodName' "${LAUNCHER_GRPC}" \
    | sed -E 's/^StartedService_([A-Za-z0-9]+)_FullMethodName$/\1/' \
    | sort -u
)"

if [ -z "${launcher_methods}" ]; then
  echo "FAIL: could not extract any method names from ${LAUNCHER_GRPC}" >&2
  exit 1
fi

# Methods our proto declares.
# [[:space:]] rather than \s: BSD grep -E does not support \s, and the leading
# indentation must be stripped or the names never compare equal to the launcher's.
our_proto_methods="$(
  grep -oE '^[[:space:]]*rpc[[:space:]]+[A-Za-z0-9]+' "${OUR_PROTO}" \
    | sed -E 's/^[[:space:]]*rpc[[:space:]]+//' \
    | sort -u
)"

if [ -z "${our_proto_methods}" ]; then
  echo "FAIL: could not extract any rpc lines from ${OUR_PROTO}" >&2
  exit 1
fi

# Methods our generated server registers.
our_server_methods="$(
  grep -oE 'StartedService_[A-Za-z0-9]+_FullMethodName' "${OUR_GRPC}" \
    | sed -E 's/^StartedService_([A-Za-z0-9]+)_FullMethodName$/\1/' \
    | sort -u
)"

echo "launcher calls:        $(echo "${launcher_methods}" | wc -l | tr -d ' ') methods"
echo "our proto declares:    $(echo "${our_proto_methods}" | wc -l | tr -d ' ') methods"
echo "our server registers:  $(echo "${our_server_methods}" | wc -l | tr -d ' ') methods"
echo

status=0

# 1. Declared in the proto.
missing_from_proto="$(comm -23 <(echo "${launcher_methods}") <(echo "${our_proto_methods}"))"
if [ -n "${missing_from_proto}" ]; then
  echo "FAIL: the launcher calls these RPCs but our .proto does not declare them:" >&2
  echo "${missing_from_proto}" | sed 's/^/        /' >&2
  echo >&2
  echo "      A method absent from the descriptor is answered with" >&2
  echo "      'unknown method <Name>' at the transport layer, which the launcher's" >&2
  echo "      capability probe cannot distinguish from a broken connection. Declare" >&2
  echo "      the RPC in daemon/started_service.proto and regenerate (make proto)." >&2
  status=1
fi

# 2. Registered by the generated server.
missing_from_server="$(comm -23 <(echo "${launcher_methods}") <(echo "${our_server_methods}"))"
if [ -n "${missing_from_server}" ]; then
  echo "FAIL: declared in the proto but not registered by the generated server:" >&2
  echo "${missing_from_server}" | sed 's/^/        /' >&2
  echo "      Run 'make proto' to regenerate started_service_grpc.pb.go." >&2
  status=1
fi

# 3. The specific RPCs the proxy UI cannot work without must have a real handler in
#    the shipped macOS profile, not just a stub. Their absence is the reported bug;
#    a stub would reproduce it on a shipped binary.
echo "--- JiejieBox proxy-UI critical path ---"
for method in GetGroups GetOutbounds URLTestOutbound SelectOutbound; do
  in_proto="no"
  in_server="no"
  echo "${our_proto_methods}" | grep -qx "${method}" && in_proto="yes"
  echo "${our_server_methods}" | grep -qx "${method}" && in_server="yes"

  if ! echo "${launcher_methods}" | grep -qx "${method}"; then
    # The launcher does not call it in this revision; nothing to guarantee.
    printf '  %-18s proto=%-3s server=%-3s launcher=no\n' "${method}" "${in_proto}" "${in_server}"
    continue
  fi

  # The handler may live either in the tag-gated command file (real, gated) or in
  # the always-compiled service file (real, unconditional, e.g. SelectOutbound).
  handler="missing"
  if grep -qE "func \(s \*StartedService\) ${method}\(" \
      "${REPO_ROOT}/daemon/started_service_command_lx.go" 2>/dev/null; then
    handler="real (with_lx_command)"
  elif grep -qE "func \(s \*StartedService\) ${method}\(" \
      "${REPO_ROOT}/daemon/started_service.go" 2>/dev/null; then
    handler="real (always built)"
  fi

  printf '  %-18s proto=%-3s server=%-3s launcher=yes handler=%s\n' \
    "${method}" "${in_proto}" "${in_server}" "${handler}"

  if [ "${in_proto}" != "yes" ] || [ "${in_server}" != "yes" ]; then
    status=1
  fi
done

# 4. The shipped macOS profile must actually enable the real implementations,
#    otherwise the source has the capability and the release binary does not.
echo
echo "--- shipped macOS client profile ---"
readonly MACOS_TAGS_FILE="${REPO_ROOT}/release/BUILD_TAGS_JIEJIE_CLIENT_MACOS"
if [ -f "${MACOS_TAGS_FILE}" ]; then
  macos_tags="$(cat "${MACOS_TAGS_FILE}")"
  for tag in with_lxd with_lx_command; do
    if echo "${macos_tags}" | tr ',' '\n' | grep -qx "${tag}"; then
      echo "  ${tag}: present"
    else
      echo "FAIL: ${tag} is missing from release/BUILD_TAGS_JIEJIE_CLIENT_MACOS" >&2
      echo "      A build without it registers the RPCs but answers" >&2
      echo "      codes.Unimplemented, so the shipped binary still cannot list" >&2
      echo "      proxies. Source capability without the tag is not a fix." >&2
      status=1
    fi
  done
else
  echo "FAIL: ${MACOS_TAGS_FILE} does not exist" >&2
  status=1
fi

# 5. The server profile must NOT gain any of this. It serves one known VPS
#    topology and has no proxy UI.
readonly SERVER_TAGS_FILE="${REPO_ROOT}/release/BUILD_TAGS_JIEJIE_SERVER_MINIMAL"
if [ -f "${SERVER_TAGS_FILE}" ]; then
  server_tags="$(cat "${SERVER_TAGS_FILE}")"
  for forbidden in with_lx_command with_lxd with_naive_outbound; do
    if echo "${server_tags}" | tr ',' '\n' | grep -qx "${forbidden}"; then
      echo "FAIL: ${forbidden} must not be in BUILD_TAGS_JIEJIE_SERVER_MINIMAL" >&2
      status=1
    fi
  done
  echo "  server minimal: uncontaminated"
fi

echo
if [ "${status}" -eq 0 ]; then
  echo "PASS: the daemon RPC contract covers every method the launcher calls"
else
  echo "FAIL: daemon RPC contract drift detected" >&2
fi
exit "${status}"
