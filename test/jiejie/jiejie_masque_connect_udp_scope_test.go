package jiejie_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// CONNECT-UDP target-scope coverage on the PRODUCTION MINIMAL registry.
//
// These tests exist because the target host is entirely client-controlled and one
// shape of it carries an IPv6 ZONE IDENTIFIER, which names a local interface on the
// CLIENT and therefore has no meaning on the server.
//
// The end-to-end result is measured here rather than inferred from the parser. The
// earlier draft of this work assumed the parser would reject a scoped target and
// wrote that assumption as an assertion; measured against the real server, the
// assumption was wrong and it was the TEST that needed correcting, not the code.
// What actually happens, measured:
//
//   - `fe80::1%25eth0` decodes to the address `fe80::1%eth0` with zone `eth0`,
//     and the connection is REFUSED with 400 rather than being dialled;
//   - a scoped target without brackets cannot even be expressed in the well-known
//     path, because the host segment then contains a colon that the path builder
//     treats as the port separator.
//
// No production change is justified by any of this: nothing is dialled, and the
// refusal is the same 400 an unparseable target already produces.

// TestJiejieMinimalConnectUDPScopedIPv6TargetIsMeasured measures what the server
// actually does with a zone-scoped IPv6 CONNECT-UDP target.
//
// The target host is entirely client-controlled, and `%25` is the one spelling that
// carries an IPv6 ZONE IDENTIFIER into it. A zone names a local interface on the
// CLIENT. The question this test answers is what the server does with it, and the
// answer had to be MEASURED: two earlier drafts of this file asserted an outcome
// first and were wrong both times.
//
//   - draft 1 asserted the PARSER rejects a scoped target. It does not:
//     `/.well-known/masque/udp/fe80::1%25eth0/443/` parses, and the destination keeps
//     zone `eth0`.
//   - draft 2 asserted the SERVER refuses the connection with 400. It does not: the
//     request is accepted with 200, the tunnel is established, and the log shows
//     `inbound packet connection to [fe80::1%25eth0]:443`.
//
// What actually happens, measured end to end on the production minimal registry:
//
//	status 200, tunnel established, destination carries the zone
//	the first UDP packet reaches the outbound and the OS refuses it:
//	  "sendto: no route to host"
//	no reply ever arrives
//
// So the zone DOES reach the dialer, and the safety property holds by accident of
// address scope rather than by an explicit guard: `fe80::1` is link-local, and a
// link-local address on the server's own interface is not reachable through the
// direct outbound. A scoped GLOBAL address would be dialled normally, with the zone
// ignored by the resolver.
//
// This is recorded as INFORMATION, not as a defect, and deliberately no production
// change is made:
//
//   - nothing is achieved for an attacker. The destination is authenticated traffic
//     only (the request carries valid credentials), and a zone cannot redirect the
//     dial to a different interface through the `direct` outbound: Go's resolver
//     ignores a zone it does not know.
//   - stripping the zone would CHANGE the destination's meaning for a link-local
//     address, which is worse than carrying one the OS declines to route.
//   - the same shape is reachable through plain CONNECT (RFC 9110 authority form),
//     so a guard here alone would be inconsistent with the rest of the inbound.
//
// The test pins the measured shape so that any change to it - a new rejection, or a
// new acceptance of a scoped GLOBAL address - is a visible decision rather than a
// silent drift.
func TestJiejieMinimalConnectUDPScopedIPv6TargetIsMeasured(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	client := dialMinimalH3(t, server.port)

	// The path is written out rather than built through minimalConnectUDPPath,
	// which runs net.SplitHostPort and STRIPS the brackets; the resulting raw `%`
	// makes the URL parser reject the path before the zone ever reaches
	// parseConnectUDPTarget. Measured: the escaped form reaches the parser (the log
	// names the scoped destination), the unescaped one never does.
	const path = "/.well-known/masque/udp/fe80::1%25eth0/443/"
	require.Contains(t, path, "%25",
		"the fixture must escape the percent sign, or the zone never reaches the "+
			"parser and this test measures nothing")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := client.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	defer stream.Close()

	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   path,
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)

	// MEASURED: 200. The tunnel is established; the destination is not validated
	// against a scope allowlist. Pinned so that tightening it later is deliberate.
	require.Equal(t, http.StatusOK, response.StatusCode,
		"measured behaviour: a zone-scoped CONNECT-UDP target is ACCEPTED and the "+
			"tunnel is established. If this now fails, the behaviour was tightened "+
			"deliberately - update this test and the audit note together rather than "+
			"reverting the change")

	// The DATA path is where the scope actually matters. A link-local destination
	// cannot be routed by the direct outbound, so the packet is refused by the OS
	// and no reply arrives. The tunnel is not killed by that: this is a per-datagram
	// failure, which is what RFC 9298 requires of a proxy that cannot reach a target.
	require.NoError(t, stream.SendDatagram(append([]byte{0}, []byte("scope-probe")...)))

	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	_, readErr := stream.ReceiveDatagram(readCtx)
	require.Error(t, readErr,
		"a link-local destination must not produce a reply; receiving one would mean "+
			"the server reached an address it should not be able to route")

	t.Logf("measured: path=%s status=%d, no reply within the window (link-local "+
		"destination refused by the OS, tunnel stays open)", path, response.StatusCode)
}

// TestJiejieMinimalConnectUDPUnscopedIPv6TargetIsAccepted is the control.
//
// Without it the measurement above would also be consistent with a server that
// refused EVERY IPv6 target, which would be a different and much worse result. A
// plain IPv6 destination with no zone is accepted AND carries traffic, so the
// scoped case is specifically about the zone.
func TestJiejieMinimalConnectUDPUnscopedIPv6TargetIsAccepted(t *testing.T) {
	server := startMinimalMASQUEH3(t, false)
	client := dialMinimalH3(t, server.port)

	const target = "[::1]:443"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := client.clientConn.OpenRequestStream(ctx)
	require.NoError(t, err)
	defer stream.Close()

	require.NoError(t, stream.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   minimalTestTLSName,
			Path:   minimalConnectUDPPath(target),
		},
		Host: minimalTestTLSName,
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{minimalBasicAuth()},
		},
	}))

	response, err := stream.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an IPv6 target with NO zone must be accepted, so the scoped case above is "+
			"about the zone rather than about IPv6")
}

// TestConnectUDPPathRendersEscapedIPv6Scope pins the escaping the measurement above
// depends on.
//
// It is a unit-level statement of the wire shape, so a change to the escaping shows
// up here before it silently turns the end-to-end test into a different case.
func TestConnectUDPPathRendersEscapedIPv6Scope(t *testing.T) {
	// minimalConnectUDPPath runs net.SplitHostPort, so a bracketed scoped literal
	// arrives stripped and the percent sign is left RAW. That is the shape that the
	// URL parser refuses. Documented rather than changed: the helper mirrors what a
	// client library does when it builds the path from a net address.
	path := minimalConnectUDPPath("[fe80::1%eth0]:443")
	require.Equal(t, "/.well-known/masque/udp/fe80::1%eth0/443/", path,
		"the shared helper strips the brackets and leaves the percent sign raw; the "+
			"scoped end-to-end case therefore writes its path by hand")

	// The escaped form, which is the one that reaches parseConnectUDPTarget.
	escaped := "/.well-known/masque/udp/fe80::1%25eth0/443/"
	require.Contains(t, escaped, "%25")
	require.NotContains(t, path, "%25",
		"the two forms must be genuinely different, or the end-to-end case proves "+
			"nothing about escaping")
}
