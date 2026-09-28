#!/usr/bin/env bash
#
# Real-binary gRPC smoke test for the JiejieBox daemon command surface.
#
# WHY A SEPARATE SCRIPT
#
# The Go tests in daemon/ use bufconn: a real gRPC connection, but in-process. They
# prove the descriptor, the method names and the handlers. They CANNOT prove the
# shipped binary was compiled with with_lx_command, because a test binary is built
# from the same source with its own tag set. The reported failure was exactly a
# tag/artifact problem — the source had the capability and the release binary did
# not — so the artifact itself has to be exercised.
#
# USAGE
#
#   scripts/ci/smoke-jiejie-daemon-rpc.sh /path/to/sing-box [control-port]
#
# Exit codes: 0 pass, 1 failure, 2 bad usage.

set -euo pipefail

readonly BINARY="${1:-}"
readonly PORT="${2:-19191}"

if [ -z "${BINARY}" ] || [ ! -x "${BINARY}" ]; then
  echo "usage: $0 /path/to/sing-box [control-port]" >&2
  exit 2
fi

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "--- build tags ---"
version_output="$("${BINARY}" version 2>&1 || true)"
echo "${version_output}" | sed 's/^/  /'

tags="$(echo "${version_output}" | sed -n 's/^Tags: //p')"
if [ -z "${tags}" ]; then
  echo "FAIL: could not read the Tags line from 'sing-box version'" >&2
  exit 1
fi

for required in with_lxd with_lx_command; do
  if echo "${tags}" | tr ',' '\n' | grep -qx "${required}"; then
    echo "  ${required}: present"
  else
    echo "FAIL: ${required} is missing from the binary's build tags." >&2
    echo "      The command RPCs are compiled out, so this binary cannot list" >&2
    echo "      proxies however complete the source is. Rebuild with" >&2
    echo "      release/BUILD_TAGS_JIEJIE_CLIENT_MACOS." >&2
    exit 1
  fi
done

readonly WORKDIR="$(mktemp -d)"
cleanup() {
  if [ -n "${DAEMON_PID:-}" ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

readonly STATE_DIR="${WORKDIR}/state"
mkdir -p "${STATE_DIR}"

# daemon.json is the ONLY source of the daemon's connection settings. TLS is off
# with a Bearer secret, keeping this smoke test to one moving part: the gRPC surface.
printf '{"listen":"127.0.0.1:%s","tls":false,"secret":"smoke-test-secret"}\n' "${PORT}" \
  > "${STATE_DIR}/daemon.json"

readonly CONFIG="${WORKDIR}/config.json"
cat > "${CONFIG}" <<'JSON'
{
  "log": {"level": "error", "output": "stderr"},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "direct", "tag": "node-a"},
    {
      "type": "selector", "tag": "smoke-group",
      "outbounds": ["node-a", "direct"], "default": "node-a"
    }
  ],
  "route": {"final": "direct"}
}
JSON

echo
echo "--- starting the daemon on 127.0.0.1:${PORT} ---"
"${BINARY}" lxd --state-dir "${STATE_DIR}" -c "${CONFIG}" >"${WORKDIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

bound=false
for _ in $(seq 1 60); do
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo "FAIL: the daemon exited during startup" >&2
    sed 's/^/      /' "${WORKDIR}/daemon.log" >&2
    exit 1
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
    exec 3<&- 3>&- 2>/dev/null || true
    bound=true
    break
  fi
  sleep 0.25
done

if [ "${bound}" != "true" ]; then
  echo "FAIL: the daemon never bound 127.0.0.1:${PORT}" >&2
  sed 's/^/      /' "${WORKDIR}/daemon.log" >&2
  exit 1
fi
echo "  control channel is accepting (pid ${DAEMON_PID})"

echo
echo "--- exercising the command RPC surface ---"
probe_dir="${WORKDIR}/probe"
mkdir -p "${probe_dir}"

cat > "${probe_dir}/main.go" <<'GO'
// Command probe_rpc calls the JiejieBox command RPCs against a running sing-box
// daemon over a real socket.
//
// It is a CLIENT of this repo's generated stub rather than a hand-rolled HTTP/2
// request, because the thing under test is the contract a real client sees.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: probe_rpc <address> <secret>")
		os.Exit(2)
	}
	address, secret := os.Args[1], os.Args[2]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+secret)

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("FAIL dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := daemon.NewStartedServiceClient(conn)

	// GetVersion proves the connection, the service name and the auth path.
	version, err := client.GetVersion(ctx, &emptypb.Empty{})
	if err != nil {
		fmt.Printf("FAIL GetVersion (control channel not usable): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  GetVersion                -> ok (api %d)\n", version.ApiVersion)

	failed := false

	type call struct {
		name string
		run  func() error
	}
	calls := []call{
		{"GetGroups", func() error {
			_, err := client.GetGroups(ctx, &emptypb.Empty{})
			return err
		}},
		{"GetOutbounds", func() error {
			_, err := client.GetOutbounds(ctx, &emptypb.Empty{})
			return err
		}},
		{"URLTestOutbound", func() error {
			_, err := client.URLTestOutbound(ctx, &daemon.URLTestOutboundRequest{
				OutboundTag: "node-a", Timeout: 2000,
			})
			return err
		}},
	}

	for _, c := range calls {
		err := c.run()
		message := ""
		if err != nil {
			message = status.Convert(err).Message()
		}
		switch {
		case err == nil:
			fmt.Printf("  %-25s -> ok (handler ran and answered)\n", c.name)

		case status.Code(err) == codes.Unimplemented:
			fmt.Printf("  %-25s -> UNIMPLEMENTED: not in this build\n", c.name)
			fmt.Printf("      %v\n", err)
			failed = true

		case isUnknownMethod(message):
			// The reported bug: the descriptor lacks the method, so the TRANSPORT
			// rejects it before any handler runs.
			fmt.Printf("  %-25s -> UNKNOWN METHOD: absent from the descriptor\n", c.name)
			fmt.Printf("      %v\n", err)
			failed = true

		default:
			// Any other status proves the method EXISTS and rejected this call.
			// FailedPrecondition (no config loaded) is the expected outcome here.
			fmt.Printf("  %-25s -> recognized (refused: %s)\n", c.name, status.Code(err))
		}
	}

	if failed {
		os.Exit(1)
	}
	fmt.Println("  all command RPCs are recognized by the running daemon")
}

// isUnknownMethod reports whether a gRPC message says the METHOD itself is unknown.
func isUnknownMethod(message string) bool {
	for _, marker := range []string{"unknown method", "unknown service"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
GO

if ! (cd "${REPO_ROOT}" && go build -o "${probe_dir}/probe_rpc" "${probe_dir}/main.go" 2>"${probe_dir}/build.log"); then
  echo "FAIL: could not build the RPC probe" >&2
  sed 's/^/      /' "${probe_dir}/build.log" >&2
  exit 1
fi

echo "  dialing 127.0.0.1:${PORT}"
if "${probe_dir}/probe_rpc" "127.0.0.1:${PORT}" "smoke-test-secret"; then
  echo
  echo "PASS: the shipped binary answers the JiejieBox command RPCs"
  echo "      GetGroups is no longer an unknown method on a real daemon."
  exit 0
else
  echo
  echo "FAIL: the shipped binary does not satisfy the command RPC contract" >&2
  sed 's/^/      /' "${WORKDIR}/daemon.log" >&2
  exit 1
fi
