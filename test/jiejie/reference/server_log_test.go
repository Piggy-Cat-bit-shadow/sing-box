package reference_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Reading the SERVER's own recorded source identity.
//
// The migration tests in migration_test.go assert OUTCOMES: an existing tunnel
// keeps working, a new one can be opened. Those are necessary but not sufficient,
// because they cannot see what sing-box RECORDED as the source. The reference
// clients are separate processes on the other end of a socket, so nothing on the
// client side can observe the server's view.
//
// The server already writes that view at INFO level. `protocol/http/inbound.go`
// logs, for every admitted packet connection:
//
//	inbound/http[<tag>]: [<user>] inbound packet connection to <destination>
//
// and the log file the harness already redirects the child process's output into is
// the observation point. It is a TEST-ONLY read of output the production server
// emits anyway: no debug endpoint, no exported API, no build tag, and nothing added
// to the shipped binary.
//
// # Why this is not circular, and what it can and cannot prove
//
// It proves what the server ATTACHED to the request, which is the value that feeds
// metadata.Source, source-based routing and the unauthenticated limiter. It does not
// prove anything about quic-go's internal path-validation state: that the log line
// exists at all means quic-go already accepted the packet on some path.
//
// So the two halves are stated separately everywhere this is used:
//
//   - quic-go owns cryptographic path validation (RFC 9000 section 9), and this
//     suite does not reimplement or fake it;
//   - sing-box owns what identity it attaches to an admitted request, and THAT is
//     what these helpers measure.

// admittedTunnelLogPattern matches the server's per-tunnel admission line.
//
// The tag is captured so a test can attribute a line to the right listener, and the
// destination is captured because it is what varies between fixtures.
var admittedTunnelLogPattern = regexp.MustCompile(
	`inbound/(?:http|masque-server)\[([^\]]+)\]: (?:\[([^\]]+)\] )?inbound packet connection to (\S+)`)

// loggedTunnelAdmission is one admission line decoded.
type loggedTunnelAdmission struct {
	// User is the authenticated user, or "" when the log carried none.
	User string
	// Destination is the packet destination the server logged.
	Destination string
}

// awaitLogLines waits until predicate is satisfied over the server's log, returning
// the decoded admissions seen so far.
//
// It polls rather than reading once because the server writes asynchronously, and it
// is bounded so a missing line fails with a deadline instead of hanging. Reading the
// file with os.ReadFile while the process holds it open is safe on every platform
// this suite runs on: the child writes through its own descriptor and the parent
// opens a second one, which sees everything flushed so far.
func awaitLogLines(t *testing.T, logPath string, predicate func([]loggedTunnelAdmission) bool) []loggedTunnelAdmission {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last []loggedTunnelAdmission
	for {
		admissions, err := readLoggedAdmissions(logPath)
		require.NoError(t, err, "the server log must be readable; the harness "+
			"redirects the child process's output into this file")
		last = admissions
		if predicate(admissions) {
			return admissions
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// readLoggedAdmissions decodes every admission line in the log so far.
func readLoggedAdmissions(logPath string) ([]loggedTunnelAdmission, error) {
	content, err := os.ReadFile(logPath)
	if err != nil {
		return nil, err
	}
	var admissions []loggedTunnelAdmission
	for _, line := range strings.Split(string(content), "\n") {
		match := admittedTunnelLogPattern.FindStringSubmatch(stripANSI(line))
		if match == nil {
			continue
		}
		admissions = append(admissions, loggedTunnelAdmission{
			User:        match[2],
			Destination: match[3],
		})
	}
	return admissions, nil
}

// ansiEscapePattern strips the colour codes sing-box writes when it is not told to
// disable them.
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(line string) string {
	return ansiEscapePattern.ReplaceAllString(line, "")
}

// destinationPortOf extracts the port from a logged destination.
//
// The server logs the destination as host:port, and for these fixtures the
// destination is the UDP origin rather than the client, so the port identifies the
// fixture rather than the source. It is provided because a test that needs the port
// should not re-implement the parsing.
func destinationPortOf(t *testing.T, destination string) int {
	t.Helper()
	index := strings.LastIndexByte(destination, ':')
	require.GreaterOrEqual(t, index, 0, "a logged destination must carry a port: %q", destination)
	port, err := strconv.Atoi(destination[index+1:])
	require.NoError(t, err, "the logged destination port must be numeric: %q", destination)
	return port
}

// countLogLinesMatching counts log lines containing needle, so a test can assert on
// a message without decoding it.
func countLogLinesMatching(t *testing.T, logPath string, needle string) int {
	t.Helper()
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(stripANSI(line), needle) {
			count++
		}
	}
	return count
}

// logContains reports whether the server's log has the given text, after stripping
// colour codes.
func logContains(t *testing.T, logPath string, needle string) bool {
	t.Helper()
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	return strings.Contains(stripANSI(string(content)), needle)
}
