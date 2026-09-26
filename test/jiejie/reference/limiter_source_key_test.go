package reference_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// The unauthenticated limiter must key on the SOURCE IP, not on the source port.
//
// The unit level already pins this: TestUnauthenticatedLimiterIgnoresPort shows that
// three requests from one IP on three different ports share one bucket. What that
// test cannot show is the property on the WIRE, where the port is chosen by the
// network rather than by the test.
//
// That difference matters because a NAT rebind is exactly "same source IP, different
// source port", and the question is whether a client can use it to mint a fresh
// unauthenticated budget. If the limiter keyed on the full address:port, every
// rebind would reset the bucket and the limit would be trivially bypassable by a
// peer that keeps changing its port. This test measures the real thing: a server
// with a limiter configured to admit almost nothing, driven through a UDP relay that
// is rebound between requests.
//
// It is deliberately NOT a test of validated migration. The traffic here is
// UNAUTHENTICATED, so there is no tunnel and no path validation involved: each probe
// is a fresh HTTP/3 request on a fresh connection, and the only thing carried across
// the rebind is the source IP.

// startLimiterServer starts a CONNECT-UDP inbound whose unauthenticated budget is
// exhausted by the very first probe and cannot refill during the test.
//
// # The rates are chosen from the REAL option semantics, not from what "0" looks like
//
// The first version of this fixture set requests_per_second to 0 expecting "no
// refill". Measured, that is wrong, and reading option/http_unauthenticated_limits.go
// shows why: `Build()` treats every non-positive field as UNSET and substitutes the
// default, so 0 became DefaultUnauthenticatedRPS (10/s) and burst 0 would have become
// DefaultUnauthenticatedBurst (20). The budget therefore refilled between probes and
// the second probe was admitted, which looked like a keying defect and was a fixture
// mistake.
//
// The rates below are positive, so they survive Build() as written:
//
//	requests_per_second 0.001  -> one token per 1000 seconds
//	burst               1      -> exactly one request admitted, ever, within the test
//	max_concurrent_per_ip 1    -> and only one at a time
//
// So the first probe consumes the only token and nothing can refill it for the
// lifetime of the test. A second probe being ADMITTED is then unambiguous evidence
// that its budget came from somewhere else - a new bucket, i.e. a port-keyed limiter.
//
// idle_timeout is well above the test's runtime so the entry cannot expire and be
// recreated with a full bucket either.
func startLimiterServer(t *testing.T) *singBoxServer {
	t.Helper()

	origin := startUDPEchoOrigin(t)
	server := startSingBoxMASQUEH3WithConfig(t, map[string]any{
		"inbounds": []any{
			map[string]any{
				"type":    "http",
				"tag":     "masque-in",
				"version": []int{3},
				"users": []any{
					map[string]any{
						"username": referenceTestUser,
						"password": referenceTestPassword,
					},
				},
				"unauthenticated_limits": map[string]any{
					"enabled":               true,
					"requests_per_second":   0.001,
					"burst":                 1,
					"max_concurrent_per_ip": 1,
					"idle_timeout":          "10m",
				},
			},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	server.origin = origin
	return server
}

// unauthenticatedProbe sends one CONNECT-UDP request with NO credentials and reports
// the HTTP status.
//
// A status of 407 or 401 means the probe reached the authentication path; any other
// status means it was answered by the masquerade or the over-limit decoy. Either way
// the request was ADMITTED by the limiter, which is all this test needs to know: it
// is not asserting on the response shape (that is covered by the Probe-Status and
// masquerade suites), only on whether the budget was available.
func unauthenticatedProbe(t *testing.T, dialAddress string, target string) int {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddrEarly(ctx, dialAddress, &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err, "the probe must be able to reach the server; a failure "+
		"here is a transport problem, not a limiter result")
	defer quicConn.CloseWithError(0, "")

	transport := &http3.Transport{EnableDatagrams: true}
	defer transport.Close()
	clientConn := transport.NewClientConn(quicConn)

	stream, err := clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	request := connectUDPRequest(target)
	// Deliberately remove the credential: this is an unauthenticated probe.
	request.Header.Del("Proxy-Authorization")
	require.NoError(t, stream.SendRequestHeader(&request))

	response, err := stream.ReadResponse()
	require.NoError(t, err, "the probe must get SOME response; the question is "+
		"which one")
	return response.StatusCode
}

// TestReferenceUnauthenticatedLimiterSurvivesPortChurnOnTheWire is the live
// regression.
//
// Every probe goes through the SAME relay, so the server sees one source IP. The
// relay is rebound BEFORE the second probe, so the second probe arrives from a
// different source PORT. Both must be accounted to the same per-IP budget, and with
// Burst 1 the second must therefore be treated as over budget.
//
// The relay counters prove the rebind really happened, so a run where the relay
// never rebound cannot report a pass.
func TestReferenceUnauthenticatedLimiterSurvivesPortChurnOnTheWire(t *testing.T) {
	server := startLimiterServer(t)
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPNATRelay(t, server.address())

	// Probe 1: the first unauthenticated request from this IP consumes the burst.
	firstStatus := unauthenticatedProbe(t, dialAddress, server.origin)
	require.NotEqual(t, http.StatusOK, firstStatus,
		"an unauthenticated CONNECT-UDP must never be handed a tunnel, whatever the "+
			"limiter decides")

	// The FIRST probe must be admitted by the limiter and then rejected by
	// authentication, which is the 407 that proves the budget was still available.
	// MEASURED: 407.
	require.Equal(t, http.StatusProxyAuthRequired, firstStatus,
		"the first probe must be admitted by the limiter and refused by "+
			"authentication (407). Anything else means the budget was already gone "+
			"before this test started, so the rebind assertion below would be vacuous")

	require.Empty(t, limiterOverBudgetSources(t, server.logPath),
		"the first probe must not have been reported as over budget, which is what "+
			"makes the second probe's report meaningful")

	portsBefore := relay.upstreamPortsSeen()
	relay.rebind()
	portsAfter := relay.upstreamPortsSeen()
	require.GreaterOrEqual(t, len(portsAfter), len(portsBefore)+1,
		"the relay must have a new upstream socket")
	require.NotEqual(t, portsBefore[len(portsBefore)-1], portsAfter[len(portsAfter)-1],
		"the relay must present a DIFFERENT source port for the second probe, or this "+
			"test measures nothing about port churn")

	// Probe 2: SAME source IP, DIFFERENT source port. The budget must already be
	// exhausted.
	secondStatus := unauthenticatedProbe(t, dialAddress, server.origin)
	require.NotEqual(t, http.StatusOK, secondStatus,
		"an unauthenticated CONNECT-UDP must never be handed a tunnel")

	// The second probe MUST be over budget, and the response code is the direct
	// evidence. MEASURED, deterministically across repeated runs:
	//
	//	probe 1 (port A) -> 407   admitted by the limiter, refused by authentication
	//	probe 2 (port B) -> 429   refused by the limiter
	//	probe 3 (port C) -> 429   refused by the limiter
	//
	// A 429 means the limiter declined to admit the request at all. With
	// requests_per_second 0 and burst 1 the only way that can happen is if the second
	// probe was accounted to the SAME bucket the first one drained. Had the limiter
	// keyed on address:port, the new port would have arrived with a full bucket, the
	// probe would have been admitted, and the answer would have been 407 again.
	require.Equal(t, http.StatusTooManyRequests, secondStatus,
		"the second probe arrived from the same IP on a DIFFERENT port and was NOT "+
			"refused by the limiter (got %d, expected 429). With burst 1 the first "+
			"probe consumed the whole budget, so admission here means the rebind "+
			"minted a fresh bucket: the limiter would be keying on the source port, "+
			"and a peer could bypass the limit by churning its port - which is exactly "+
			"what a NAT rebind does. Measured baseline: probe 1 -> 407, probe 2 -> 429",
		secondStatus)

	// A third probe from yet another port, so the property is not an artefact of a
	// single rebind.
	relay.rebind()
	thirdStatus := unauthenticatedProbe(t, dialAddress, server.origin)
	require.Equal(t, http.StatusTooManyRequests, thirdStatus,
		"a third probe from a THIRD source port must still be over budget (got %d, "+
			"expected 429)", thirdStatus)

	// The server's own over-budget lines are the SECONDARY evidence, and their shape
	// matters: the line prints the full `source` it was handed, which INCLUDES the
	// port. So several probes produce several distinct strings, all sharing one host.
	// The limiter's key is the bare IP; the 429s above are what prove the two ports
	// shared one bucket, and this checks that every refusal was attributed to this
	// fixture's single peer.
	overBudget := awaitOverBudgetSources(t, server.logPath)
	require.NotEmpty(t, overBudget,
		"the server must have reported at least one over-budget source")

	hosts := make(map[string]bool)
	for source := range overBudget {
		host, _, err := net.SplitHostPort(source)
		require.NoError(t, err,
			"the reported source must be host:port, got %q", source)
		hosts[host] = true
	}
	require.Equal(t, map[string]bool{"127.0.0.1": true}, hosts,
		"every refusal must be attributed to this fixture's ONE loopback peer. Distinct "+
			"HOSTS here would mean the probes were seen as different peers; note that "+
			"distinct host:PORT strings are expected and are not evidence of that, "+
			"because the log prints the source it was handed rather than the limiter's "+
			"key. Got sources %v", overBudget)

	t.Logf("limiter across port churn: upstream ports %v -> %v; probes answered "+
		"%d/%d/%d; over-budget sources reported %v", portsBefore, portsAfter,
		firstStatus, secondStatus, thirdStatus, overBudget)
}

// limiterOverBudgetSources returns the distinct source addresses the server reported
// as OVER the unauthenticated budget, read from its own log.
//
// The signal is produced by the production limiter path itself:
// httpHandler.rejectUnauthenticated logs
//
//	unauthenticated request from <source> over the unauthenticated budget
//
// at DEBUG level, and the fixture runs at DEBUG. Nothing was added to the server for
// this test: the line is what an operator already sees when the limiter fires.
//
// The SOURCE in that line is the limiter's own key (source.AddrString(), IP without
// port), which is exactly the value under test. Asserting on the number of DISTINCT
// sources reported as over budget therefore measures the key directly: if the limiter
// keyed on address:port, the second probe from a new port would appear as a different
// source and the count would be 2.
func limiterOverBudgetSources(t *testing.T, logPath string) map[string]bool {
	t.Helper()
	return parseOverBudgetSources(t, logPath)
}

// awaitOverBudgetSources waits for at least one over-budget line to appear.
//
// It is separate from limiterOverBudgetSources because the blocking form is only
// correct when a line is EXPECTED. An earlier version always waited, so an assertion
// that the map was EMPTY still burned the full deadline - which both slowed the test
// and pushed the later probes far enough apart in time that the token bucket's
// (tiny but non-zero) refill became relevant. Blocking is therefore opt-in.
func awaitOverBudgetSources(t *testing.T, logPath string) map[string]bool {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		sources := parseOverBudgetSources(t, logPath)
		if len(sources) > 0 || time.Now().After(deadline) {
			return sources
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// parseOverBudgetSources extracts the source of every over-budget log line.
func parseOverBudgetSources(t *testing.T, logPath string) map[string]bool {
	t.Helper()
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	sources := make(map[string]bool)
	for _, line := range strings.Split(stripANSI(string(content)), "\n") {
		match := overBudgetLogPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		sources[match[1]] = true
	}
	return sources
}

// overBudgetLogPattern matches the limiter's own over-budget line and captures the
// source it keyed on.
var overBudgetLogPattern = regexp.MustCompile(
	`unauthenticated request from (\S+) over the unauthenticated budget`)
