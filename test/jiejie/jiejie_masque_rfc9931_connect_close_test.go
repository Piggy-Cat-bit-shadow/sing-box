package jiejie_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
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
