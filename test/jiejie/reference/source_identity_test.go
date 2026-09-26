package reference_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/stretchr/testify/require"
)

// Source identity: what sing-box RECORDS, observed through ROUTING rather than
// through log text or a debug hook.
//
// # Why the previous version of this test was not evidence
//
// TestReferenceSourceIdentityIsStableAcrossMigration carried a comment saying it
// measured "what identity the SERVER layer reports, taken from the server's own
// logs". It never read the log and it never read the source. The body only proved
// that the relay's source port changed and that both tunnels still carried traffic.
// That is a genuine DATA-PATH property and it is worth keeping, but it says nothing
// about the identity sing-box ATTACHED to the request - which is what feeds
// source_ip_cidr rules, the unauthenticated limiter, logging and the audit trail.
// The audit recorded "source identity CLOSED" on that basis, which the test did not
// support.
//
// # How the identity is observed now
//
// The routing table carries a `source_ip_cidr` rule whose ACTION is observable:
// traffic whose recorded source falls inside the probe prefix is REJECTED, and
// traffic outside it is forwarded to a working origin. `source_ip_cidr` is evaluated
// against metadata.Source, so WHICH BRANCH IS TAKEN is the measurement of what the
// server attached. A value the server merely printed could not satisfy it, and a
// server that attached nothing would take the reject branch and fail the test.
//
// # What this proves, and what it deliberately does not
//
// It proves, per request:
//
//	the source sing-box attached to an admitted request;
//	that a client-supplied header cannot change it;
//	that it does not silently change across a validated path change.
//
// It does NOT prove anything about quic-go's cryptographic path-validation state.
// quic-go owns that (RFC 9000 section 9); this suite neither reimplements it nor
// synthesizes PATH_CHALLENGE / PATH_RESPONSE. Only the sing-box-side consequence is
// asserted, which is the part sing-box owns.

// sourceRulePrefix is the prefix the probe routes on. The fixture is loopback, so a
// correct server records a source inside it.
const sourceRulePrefix = "127.0.0.0/8"

// The two outbound tags the fixture routes between. They are named here so a test
// never repeats a string literal and so the log line it looks for is obviously the
// one the fixture configured.
const (
	sourceMatchedOutbound   = "source-matched"
	sourceUnmatchedOutbound = "source-unmatched"
)

// startSourceSensitiveConnectUDPServer starts a CONNECT-UDP server whose routing
// table sends packet connections to one of TWO direct outbounds depending on the
// recorded source.
//
// The choice of observable matters and the first two attempts got it wrong:
//
//   - a `reject` action on the CONNECT itself answered 400, so no tunnel existed;
//   - `network: ["udp"]` fixed that, but the reject still aborted the request
//     STREAM, so the post-rebind tunnel could not be opened and the migration case
//     failed with an H3 stream error rather than a measurement.
//
// Routing to a NAMED outbound keeps the tunnel healthy and still makes the source
// observable, because `protocol/direct/outbound.go` logs the outbound's own tag:
//
//	outbound/direct[<tag>]: outbound packet connection
//
// So the tag that appears in the log IS the routing decision, and the routing
// decision was made from metadata.Source. Nothing depends on log formatting beyond
// a tag the fixture itself chooses.
func startSourceSensitiveConnectUDPServer(t *testing.T) *singBoxServer {
	t.Helper()
	// The echo origin must exist before the server. startSingBoxMASQUEH3WithConfig
	// takes an explicit config and creates no origin; using it alone leaves
	// server.origin empty, the request path becomes "/.well-known/masque/udp//" and
	// the server answers 400, which reads like a routing regression and is actually a
	// fixture mistake.
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
			},
		},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": sourceMatchedOutbound},
			map[string]any{"type": "direct", "tag": sourceUnmatchedOutbound},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{
					"source_ip_cidr": []string{sourceRulePrefix},
					"action":         "route",
					"outbound":       sourceMatchedOutbound,
				},
			},
			"final": sourceUnmatchedOutbound,
		},
	})
	server.origin = origin
	return server
}

// requireSourceMatched asserts that the routing layer selected the outbound that
// only a packet connection with a recorded source inside sourceRulePrefix can reach.
func requireSourceMatched(t *testing.T, server *singBoxServer) {
	t.Helper()
	matched, unmatched := awaitOutboundSelection(t, server.logPath)
	require.Greater(t, matched, 0,
		"the source rule must have selected outbound/%s, which requires metadata.Source "+
			"to be inside %s. It was not selected, so the source the server attached "+
			"did not reach the routing layer", sourceMatchedOutbound, sourceRulePrefix)
	require.Zero(t, unmatched,
		"outbound/%s is the fallback for a source OUTSIDE %s; selecting it means the "+
			"recorded source did not match the rule", sourceUnmatchedOutbound, sourceRulePrefix)
}

// requireSourceUnmatched is the negative control: it asserts the opposite outcome, so
// a fixture that always matched (or never did) cannot pass both tests.
func requireSourceUnmatched(t *testing.T, server *singBoxServer) {
	t.Helper()
	matched, unmatched := awaitOutboundSelection(t, server.logPath)
	require.Greater(t, unmatched, 0,
		"outbound/%s must have been selected, which requires metadata.Source to be "+
			"OUTSIDE %s", sourceUnmatchedOutbound, sourceRulePrefix)
	require.Zero(t, matched,
		"outbound/%s must NOT have been selected when the source is outside the rule",
		sourceMatchedOutbound)
}

// awaitOutboundSelection counts how many times each fixture outbound was selected,
// waiting briefly for the routing layer to record the decision.
func awaitOutboundSelection(t *testing.T, logPath string) (matched int, unmatched int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		matched = countLogLinesMatching(t, logPath, "outbound/direct["+sourceMatchedOutbound+"]")
		unmatched = countLogLinesMatching(t, logPath, "outbound/direct["+sourceUnmatchedOutbound+"]")
		if matched+unmatched > 0 || time.Now().After(deadline) {
			return matched, unmatched
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSourceIdentityIsRecordedAndDrivesRouting is the foundational measurement.
//
// The routing table sends a packet connection to outbound/source-matched when
// metadata.Source is inside 127.0.0.0/8, and to outbound/source-unmatched otherwise.
// The fixture is loopback, so a correct server must select source-matched. Because
// the two branches are mutually exclusive, a server that attached nothing, or that
// attached a client-supplied value, takes the OTHER branch and the assertions below
// fail in a way that names which branch was taken.
func TestSourceIdentityIsRecordedAndDrivesRouting(t *testing.T) {
	server := startSourceSensitiveConnectUDPServer(t)
	t.Cleanup(server.stop)

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnel(t, server.origin)

	// The tunnel must still carry traffic, so this is not measuring a broken tunnel:
	// the echo proves the packet connection was routed and forwarded end to end.
	require.Equal(t, "origin:source-identity", datagramEchoRoundTrip(t, stream, "source-identity"),
		"the tunnel must forward to the origin, so the assertion below is about "+
			"WHICH outbound was chosen rather than about whether the tunnel works")

	requireSourceMatched(t, server)
}

// TestSourceIdentityIgnoresClientSuppliedHeaders is the anti-spoofing half.
//
// X-Forwarded-For and Forwarded are client-controlled. If either decided
// metadata.Source, the client could move itself OUT of the rule prefix by claiming
// another address, the rule would stop matching, and the traffic would be routed to
// outbound/source-unmatched instead. The assertion is that the MATCHED outbound is
// still selected.
func TestSourceIdentityIgnoresClientSuppliedHeaders(t *testing.T) {
	server := startSourceSensitiveConnectUDPServer(t)
	t.Cleanup(server.stop)

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnelWithHeaders(t, server.origin, http.Header{
		"X-Forwarded-For": []string{"203.0.113.9"},
		"Forwarded":       []string{"for=203.0.113.9"},
	})

	require.Equal(t, "origin:spoofed-header", datagramEchoRoundTrip(t, stream, "spoofed-header"),
		"the tunnel must still forward, so the assertion is about the ROUTING DECISION")

	requireSourceMatched(t, server)
}

// TestSourceIdentityIsStableAcrossMigration measures the recorded identity across a
// validated path change.
//
// The relay changes the source port the server sees. The requirement is NOT that the
// recorded source changes - quic-go decides the peer address of a path, and sing-box
// only reports what it is given. The requirement is that the attribution stays
// SELF-CONSISTENT: a tunnel admitted after the rebind must still be routed by the
// same rule, so the source-based decision and the limiter bucket do not silently
// flip.
//
// This is the assertion the previous version of this test could not make, because it
// never looked at the source at all.
func TestSourceIdentityIsStableAcrossMigration(t *testing.T) {
	server := startSourceSensitiveConnectUDPServer(t)
	t.Cleanup(server.stop)

	relay, dialAddress := startUDPNATRelay(t, server.address())
	client := startRelayedConnectUDPClient(t, server, dialAddress)

	first, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:pre-rebind", datagramEchoRoundTrip(t, first, "pre-rebind"))
	requireSourceMatched(t, server)

	portsBefore := relay.upstreamPortsSeen()
	relay.rebind()
	portsAfter := relay.upstreamPortsSeen()
	require.GreaterOrEqual(t, len(portsAfter), len(portsBefore)+1,
		"the rebind must produce a new upstream socket, or nothing was migrated")
	require.NotEqual(t, portsBefore[len(portsBefore)-1], portsAfter[len(portsAfter)-1],
		"the relay must present a DIFFERENT source port after rebinding")

	// A NEW tunnel on the same connection, after the rebind. The recorded source must
	// still satisfy the same rule.
	second, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:post-rebind", datagramEchoRoundTrip(t, second, "post-rebind"),
		"the tunnel must carry traffic after the rebind, so the routing assertion "+
			"below is about the DECISION rather than about the data path")
	requireSourceMatched(t, server)

	// And the pre-rebind tunnel must still be routed the same way, so the two are
	// attributed consistently rather than the first being silently re-keyed.
	require.Equal(t, "origin:pre-rebind-again",
		datagramEchoRoundTrip(t, first, "pre-rebind-again"),
		"the tunnel admitted before the rebind must keep working alongside the new one")
	requireSourceMatched(t, server)

	t.Logf("source identity: upstream ports %v -> %v; every packet connection was "+
		"routed by the %s rule to outbound/%s, so the recorded source stayed inside "+
		"%s across a validated path change",
		portsBefore, portsAfter, sourceRulePrefix, sourceMatchedOutbound, sourceRulePrefix)
}

// TestSourceIdentityRoutingRuleIsLoadBearing is the negative control for the fixture
// itself.
//
// Without it, every assertion above would also pass on a server that routed
// EVERYTHING to source-matched regardless of the source - the tests would be
// tautologies. This case removes the rule match by requiring the source to be
// outside the loopback prefix, so outbound/source-unmatched must be selected. If the
// fixture or the rule were inert, this fails.
func TestSourceIdentityRoutingRuleIsLoadBearing(t *testing.T) {
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
			},
		},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": sourceMatchedOutbound},
			map[string]any{"type": "direct", "tag": sourceUnmatchedOutbound},
		},
		"route": map[string]any{
			"rules": []any{
				// A prefix the loopback fixture can never match, so the rule must
				// NOT fire and the fallback outbound must be selected.
				map[string]any{
					"source_ip_cidr": []string{"203.0.113.0/24"},
					"action":         "route",
					"outbound":       sourceMatchedOutbound,
				},
			},
			"final": sourceUnmatchedOutbound,
		},
	})
	t.Cleanup(server.stop)
	server.origin = origin

	client := startRelayedConnectUDPClient(t, server, server.address())
	stream, _ := client.openTunnel(t, server.origin)
	require.Equal(t, "origin:negative-control",
		datagramEchoRoundTrip(t, stream, "negative-control"))

	requireSourceUnmatched(t, server)
	t.Logf("negative control: a rule that matches nothing routed to outbound/%s, so "+
		"the outbound tag in the log really does reflect the routing decision",
		sourceUnmatchedOutbound)
}

// openTunnelWithHeaders is openTunnel plus extra request headers, so a test can probe
// whether a client-supplied header influences the recorded source.
func (c *relayedConnectUDPClient) openTunnelWithHeaders(t *testing.T, target string, extra http.Header) (*http3.RequestStream, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	stream, err := c.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)

	request := connectUDPRequest(target)
	for name, values := range extra {
		request.Header[name] = values
	}
	require.NoError(t, stream.SendRequestHeader(&request))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the CONNECT-UDP request must be accepted before its source can be measured")
	return stream, ""
}
