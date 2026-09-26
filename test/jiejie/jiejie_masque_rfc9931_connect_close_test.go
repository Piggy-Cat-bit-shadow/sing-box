package jiejie_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// RFC 9931 section 8, "Requirements for HTTP CONNECT".
//
// The normative server-side requirement this file tests, quoted from the RFC:
//
//	"As a mitigation, proxy servers MUST close the underlying connection when
//	 rejecting a CONNECT request without processing any further requests on
//	 that connection.  This requirement applies whether or not the request
//	 includes a 'close' connection option."
//
// The reason is request smuggling. A proxy CLIENT that forwards untrusted TCP
// payload optimistically (before seeing the 2xx) can have that payload
// interpreted by the server as a FURTHER HTTP/1.1 request when the CONNECT is
// rejected, because on rejection the server goes back to reading HTTP/1.1 on
// the same connection. The RFC's mitigation puts the burden on the server:
// rejecting a CONNECT must end the connection, no matter what the client asked
// for.
//
// The RFC also notes the mitigation "will frequently cause slower connection
// establishment ... especially when returning a 407". That cost is accepted
// deliberately here; it can be avoided by using HTTP/2 or HTTP/3, which are not
// vulnerable to this attack, and both are supported.
//
// These tests send raw bytes rather than using net/http, because the whole
// point is to observe exactly how many bytes of a SECOND request the server
// processes after rejecting the first. A high-level client would hide that.

// smuggledRequest is the second request an attacker would try to have processed
// as if the client had issued it. It is a plain GET so the test can tell whether
// it was answered.
const smuggledRequest = "GET /smuggled HTTP/1.1\r\nHost: example.org\r\n\r\n"

// rawTLSConn opens a TLS connection to the MASQUE H2/TCP listener and completes
// the handshake, so bytes written afterwards are the HTTP/1.1 layer.
func rawTLSConn(t *testing.T, port uint16) net.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		ServerName:         "example.org",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readWithTimeout reads whatever the server sends within the deadline.
func readWithTimeout(t *testing.T, conn net.Conn, timeout time.Duration) string {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	buffer := make([]byte, 4096)
	var received []byte
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			received = append(received, buffer[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(received)
}

// TestJiejieMASQUERejectedCONNECTClosesTheConnection is the core RFC 9931
// section 8 case over HTTP/1.1.
//
// A CONNECT that is rejected must end the connection. The test sends the
// rejected CONNECT followed immediately by a second, well-formed request, then
// asserts the second request was never answered.
//
// A server that keeps the connection open answers the second request, which is
// precisely the request-smuggling primitive: the attacker's bytes became a
// request the client is deemed to have made.
func TestJiejieMASQUERejectedCONNECTClosesTheConnection(t *testing.T) {
	// Rejection is forced by sending CONNECT with NO credentials. The listener
	// requires authentication, so the proxy answers 407 and the RFC applies.
	//
	// The authority deliberately points at a loopback port nothing listens on,
	// so even a server that tried to honour the CONNECT could not connect. The
	// rejection therefore comes from authentication, which is the case the RFC
	// calls out as especially worth slowing down.
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH1(t, decoyAddr)

	conn := rawTLSConn(t, port)

	// Note the explicit "Connection: keep-alive": the RFC requires the server to
	// close even when the client asks to keep the connection alive. Without this
	// header the test would pass against a server that only honours
	// "Connection: close", which is not what the RFC requires.
	rejected := "CONNECT 127.0.0.1:9 HTTP/1.1\r\n" +
		"Host: 127.0.0.1:9\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"
	_, err := conn.Write([]byte(rejected + smuggledRequest))
	require.NoError(t, err)

	received := readWithTimeout(t, conn, 5*time.Second)

	require.Contains(t, received, "407",
		"the unauthenticated CONNECT must be rejected with 407")
	require.NotContains(t, received, "smuggled",
		"RFC 9931 section 8: a rejected CONNECT MUST close the connection without "+
			"processing any further request on it. The server answered a second "+
			"request sent after the rejection, which is the request-smuggling "+
			"primitive the RFC exists to prevent.")
	// The connection must actually be closed by the server, not merely left
	// silent. The response must advertise the close so a correct client stops
	// reusing it.
	require.Contains(t, received, "Connection: close",
		"the rejection response must announce that the connection is closing")
}

// TestJiejieMASQUERejectedCONNECTClosesEvenWithKeepAliveHTTP10 covers the
// HTTP/1.0 form, where keep-alive is opt-in.
//
// RFC 9931 states the requirement "applies whether or not the request includes a
// 'close' connection option", so the HTTP/1.0 keep-alive spelling must not be a
// way around it either.
func TestJiejieMASQUERejectedCONNECTClosesEvenWithKeepAliveHTTP10(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH1(t, decoyAddr)

	conn := rawTLSConn(t, port)

	rejected := "CONNECT 127.0.0.1:9 HTTP/1.0\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"\r\n"
	_, err := conn.Write([]byte(rejected + smuggledRequest))
	require.NoError(t, err)

	received := readWithTimeout(t, conn, 5*time.Second)

	require.Contains(t, received, "407")
	require.NotContains(t, received, "smuggled",
		"an HTTP/1.0 CONNECT with Proxy-Connection: keep-alive must still close "+
			"on rejection")
}

// TestJiejieMASQUERejectedCONNECTUDPUpgradeClosesTheConnection covers the
// RFC 9298 form.
//
// RFC 9931 section 6.3 specifically updates CONNECT-UDP: optimistic sending is
// now forbidden over HTTP/1.x because the upgrade "is likely to be rejected in
// certain circumstances, such as when the UDP destination address (which is
// attacker-controlled) is invalid". An invalid target is exactly the case here,
// and the rejected upgrade must close the connection for the same reason.
func TestJiejieMASQUERejectedCONNECTUDPUpgradeClosesTheConnection(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH1(t, decoyAddr)

	conn := rawTLSConn(t, port)

	// A syntactically invalid CONNECT-UDP target is rejected before any tunnel
	// exists, which is the rejection case the RFC describes.
	rejected := "GET /.well-known/masque/udp//80/ HTTP/1.1\r\n" +
		"Host: example.org\r\n" +
		"Connection: Upgrade, keep-alive\r\n" +
		"Upgrade: connect-udp\r\n" +
		"Capsule-Protocol: ?1\r\n" +
		"Proxy-Authorization: " + jiejieProxyAuthorization() + "\r\n" +
		"\r\n"
	_, err := conn.Write([]byte(rejected + smuggledRequest))
	require.NoError(t, err)

	received := readWithTimeout(t, conn, 5*time.Second)

	// It must not have been upgraded: no 101, and no smuggled request served.
	require.NotContains(t, received, "101",
		"an invalid CONNECT-UDP target must not be upgraded")
	require.NotContains(t, received, "smuggled",
		"RFC 9931 section 6.3: a rejected HTTP/1.x CONNECT-UDP upgrade must close "+
			"the connection; the attacker-controlled UDP destination is exactly the "+
			"case the RFC names")
}

// TestJiejieMASQUEAcceptedCONNECTStillTunnels is the control.
//
// Closing on rejection must not be implemented by closing on every CONNECT. A
// correctly authenticated CONNECT to a reachable target must still produce a
// working tunnel, so this asserts the fix is scoped to the rejection path.
func TestJiejieMASQUEAcceptedCONNECTStillTunnels(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH1(t, decoyAddr)

	conn := rawTLSConn(t, port)
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	accepted := "CONNECT " + targetAddr + " HTTP/1.1\r\n" +
		"Host: " + targetAddr + "\r\n" +
		"Proxy-Authorization: " + jiejieProxyAuthorization() + "\r\n" +
		"\r\n"
	_, err := conn.Write([]byte(accepted))
	require.NoError(t, err)

	// Read exactly the CONNECT response, then use the tunnel.
	responseBuffer := make([]byte, 4096)
	n, err := conn.Read(responseBuffer)
	require.NoError(t, err)
	response := string(responseBuffer[:n])
	require.Contains(t, response, "200",
		"an authenticated CONNECT must be accepted, so the rejection fix is not "+
			"closing every CONNECT")

	// A tunnel carries raw bytes in both directions.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"))
	require.NoError(t, err)
	tunnelBuffer := make([]byte, 4096)
	n, err = conn.Read(tunnelBuffer)
	require.NoError(t, err)
	require.Contains(t, string(tunnelBuffer[:n]), "proxy-target-ok",
		"the accepted tunnel must carry the origin's response")
}

// TestJiejieMASQUEH2RejectedCONNECTDoesNotKillTheConnection is the HTTP/2
// control, and it exists to prove the RFC 9931 fix is scoped to HTTP/1.1.
//
// RFC 9931 is explicit that the mitigation is needed only for HTTP/1.1, and
// recommends HTTP/2 and HTTP/3 as the way to avoid its cost: a rejected request
// in HTTP/2 has an explicit stream, so it cannot leave a second request
// half-read on a shared byte stream. Applying the close to HTTP/2 would be a
// regression, not extra safety -- it would tear down a multiplexed connection
// carrying other, unrelated requests.
//
// So this asserts the OPPOSITE outcome from the HTTP/1.1 tests: after a rejected
// CONNECT, the HTTP/2 connection stays usable.
func TestJiejieMASQUEH2RejectedCONNECTDoesNotKillTheConnection(t *testing.T) {
	decoyAddr, targetAddr := startDecoyOrigins(t)
	port := startJiejieMASQUEH2(t, decoyAddr)
	clientConn := dialJiejieH2(t, port)

	// An unauthenticated CONNECT with a masquerade configured is answered with
	// the decoy site (200) rather than a 407 -- that is the documented
	// anti-fingerprinting behaviour, so it is the rejection path for this
	// listener and is what the assertion below pins.
	rejected := probeConnectH2(t, clientConn, targetAddr, http.Header{})
	defer rejected.Body.Close()
	body, err := io.ReadAll(rejected.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rejected.StatusCode,
		"an unauthenticated CONNECT is served the masquerade decoy on this listener")
	require.Contains(t, string(body), "jiejie decoy site")
	assertNotAProxyChallenge(t, rejected)

	// The SAME connection must still serve a further request. In HTTP/1.1 that
	// shape is the smuggling primitive; in HTTP/2 it is ordinary multiplexing and
	// must keep working.
	followUp, err := http.NewRequest(http.MethodGet, "https://example.org/", nil)
	require.NoError(t, err)
	response, err := clientConn.RoundTrip(followUp)
	require.NoError(t, err,
		"the HTTP/2 connection must survive a rejected CONNECT: RFC 9931 scopes "+
			"the close requirement to HTTP/1.1, and closing here would tear down a "+
			"multiplexed connection carrying unrelated requests")
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
}

// TestJiejieMASQUERejectedHTTP1CONNECTIPLeavesTheConnectionReusable pins that the
// forced-close rule is NOT applied to CONNECT-IP.
//
// # Why this test exists, and what it is protecting against
//
// The CONNECT and CONNECT-UDP rejection paths force the HTTP/1.1 connection closed.
// CONNECT-IP deliberately does not, because the requirement behind those two does not
// exist for it:
//
//   - RFC 9931 section 8 requires a server to close when it rejects a CONNECT, without
//     processing further requests. That is a SERVER requirement;
//   - RFC 9931 section 6.3 forbids an HTTP/1.x CONNECT-UDP CLIENT from sending UDP
//     payload optimistically. Closing on rejection is defence in depth for a client that
//     ignores it, not compliance;
//   - RFC 9484 already forbids HTTP/1.x optimistic IP packets for CONNECT-IP, so the
//     smuggling shape those two close against is not created here.
//
// Applying the measure anyway would be a behavioural change with no requirement behind
// it, costing every rejected CONNECT-IP client an extra TLS handshake for a shape the
// protocol already rules out.
//
// This test is a GUARD, not a defect regression: it passes today, and its purpose is to
// fail if someone later extends the forced-close rule by symmetry - which is exactly the
// kind of change that looks obviously correct and is not.
//
// # MEASURED: what actually happens to an HTTP/1.1 CONNECT-IP upgrade
//
// The tunnel-handler lookup requires a REGISTERED handler for the named protocol, and
// this fixture registers none (`tunnels` is empty on the http inbound). So
// `Upgrade: connect-ip` is not a tunnel request here: it is an ordinary forward request,
// which is answered 400 because the upgrade token is not a CONNECT.
//
// The important measurement is that the connection REMAINS USABLE afterwards, and the
// observed log shows exactly that:
//
//	HTTP/1.1 400 Bad Request        <- the connect-ip request, not a tunnel upgrade
//	HTTP/1.1 407 Proxy Authentication Required   <- the NEXT request on the SAME connection
//
// Two responses on one connection is the assertion. It is the exact opposite of the
// CONNECT case above, which is why the two are separate tests with explicit reasoning
// rather than one parameterised loop.
func TestJiejieMASQUERejectedHTTP1CONNECTIPLeavesTheConnectionReusable(t *testing.T) {
	decoyAddr, _ := startDecoyOrigins(t)
	port := startJiejieMASQUEH1(t, decoyAddr)

	conn := rawTLSConn(t, port)

	// An HTTP/1.1 request naming the CONNECT-IP upgrade token, WITH valid credentials.
	//
	// The credential matters and the first version of this test omitted it, which produced
	// a misleading failure: without it the FIRST request is answered 407 with "Connection:
	// close", so the connection closed on the authentication failure and the test saw one
	// response. That is the ordinary unauthenticated path and has nothing to do with
	// CONNECT-IP.
	//
	// With valid credentials the request is authenticated and then handled as an ordinary
	// forward request (no tunnel handler is registered for the token), which is the case
	// whose connection-reuse semantics this test is about.
	rejected := "GET / HTTP/1.1\r\n" +
		"Host: example.org\r\n" +
		"Connection: Upgrade, keep-alive\r\n" +
		"Upgrade: connect-ip\r\n" +
		"Capsule-Protocol: ?1\r\n" +
		"Proxy-Authorization: " + jiejieProxyAuthorization() + "\r\n" +
		"\r\n"

	// The follow-up carries credentials too, so a response to it proves the connection was
	// returned to the HTTP/1.1 loop rather than closed.
	authenticatedFollowUp := "GET /smuggled HTTP/1.1\r\n" +
		"Host: example.org\r\n" +
		"Proxy-Authorization: " + jiejieProxyAuthorization() + "\r\n" +
		"\r\n"

	_, err := conn.Write([]byte(rejected + authenticatedFollowUp))
	require.NoError(t, err)

	received := readWithTimeout(t, conn, 5*time.Second)

	require.NotContains(t, received, "101",
		"a CONNECT-IP upgrade must not be accepted over HTTP/1.1")

	// The SECOND request on the same connection must have been processed. This is the
	// assertion that distinguishes CONNECT-IP from CONNECT: the forced-close rule was
	// not applied, so the connection was returned to the HTTP/1.1 loop.
	//
	// Both requests are unauthenticated, so both are answered 4xx; what matters is that
	// there are TWO responses. A forced close would produce one and then EOF.
	require.Contains(t, received, "HTTP/1.1",
		"the first request must have been answered")
	responseCount := strings.Count(received, "HTTP/1.1")
	require.GreaterOrEqual(t, responseCount, 2,
		"the SECOND request on the same connection must have been processed. Only one "+
			"response means the connection was closed after the first, i.e. the "+
			"forced-close rule was applied to CONNECT-IP. That rule has no RFC basis for "+
			"CONNECT-IP (RFC 9484 already forbids HTTP/1.x optimistic IP packets), so if "+
			"this starts failing, the change should be reverted rather than accommodated "+
			"here. Received %d bytes: %q", len(received), truncateForLog(received, 300))

	t.Logf("rejected HTTP/1.1 CONNECT-IP request left the connection reusable: %d HTTP "+
		"responses on one connection", responseCount)
}

// truncateForLog shortens a byte string for a log line.
func truncateForLog(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}
