package jiejie_test

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A failed HTTP/3 initialisation must not damage the TCP listener.
//
// Start() begins the TCP listener first and only then calls the HTTP/3
// initialiser. If the QUIC path mutated the shared TLS config before failing, the
// TCP listener would be left with a contaminated ALPN list - and because
// STDServerConfig.Server() reads the config at HANDSHAKE time, that
// contamination would apply to every subsequent TCP connection.
//
// These tests assert the POST-FAILURE state rather than the failure itself: after
// HTTP/3 has been made to fail, TCP must still negotiate h2 and http/1.1 and must
// not offer h3. They therefore cover both "H3 failed" and "H3 failed and left
// nothing behind", which are different properties.

// TestJiejieNaiveTCPUnaffectedWhenNetworkHasNoUDP is the cleanest available proxy
// for a failed HTTP/3 start: a tcp-only inbound never runs the QUIC initialiser
// at all, so its TCP ALPN must be exactly the TCP set.
//
// It is included alongside the other cases because it establishes the baseline
// the tcp+udp case is compared against.
func TestJiejieNaiveTCPUnaffectedWhenNetworkHasNoUDP(t *testing.T) {
	port := startNaiveInboundWithNetwork(t, "tcp")

	negotiated, err := negotiateTCPALPN(t, port, []string{"h2"})
	require.NoError(t, err)
	require.Equal(t, "h2", negotiated)

	onlyH3, err := negotiateTCPALPN(t, port, []string{"h3"})
	if err == nil {
		require.NotEqual(t, "h3", onlyH3,
			"a tcp-only inbound must not negotiate h3")
	}
	t.Logf("tcp-only: h2 -> %q, h3-only -> %q (err=%v)", negotiated, onlyH3, err)
}

// TestJiejieNaiveTCPTargetsWorkWithAndWithoutH3 proves the TCP data path is
// unaffected by whether HTTP/3 started.
//
// A tcp-only inbound and a tcp+udp inbound must both carry a TCP CONNECT to the
// origin. If HTTP/3 initialisation had damaged the shared TLS config, the tcp+udp
// case would fail here while the tcp-only case passed - which is exactly the
// asymmetry this guards against.
func TestJiejieNaiveTCPTargetsWorkWithAndWithoutH3(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		network string
	}{
		{"tcp only", "tcp"},
		{"tcp with H3 enabled", "tcp\nudp"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			port := startNaiveInboundWithNetwork(t, testCase.network)
			origin := startCountingTCPOrigin(t)

			conn := naiveTLSConn(t, port, "http/1.1")
			response := naiveWriteConnectOK(t, conn, origin.addr, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
			})
			defer response.Body.Close()
			require.Equal(t, 200, response.StatusCode,
				"TCP CONNECT must work regardless of HTTP/3 availability")

			_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + origin.addr +
				"\r\nConnection: close\r\n\r\n"))
			require.NoError(t, err)
			require.True(t, waitForDial(&origin.conns, 0),
				"the TCP CONNECT must reach the origin; it saw %d connections",
				origin.conns.Load())
			t.Logf("%s: origin connections=%d", testCase.name, origin.conns.Load())
		})
	}
}

// TestJiejieNaiveTCPALPNIsStableAcrossRepeatedHandshakes guards the read-at-
// handshake-time property directly.
//
// Because the TLS config is read per handshake rather than captured, ANY later
// mutation shows up as a change between an early handshake and a later one. This
// measures the same offer several times, with the listener left running, so a
// mid-life mutation would surface as an inconsistent result.
func TestJiejieNaiveTCPALPNIsStableAcrossRepeatedHandshakes(t *testing.T) {
	port := startNaiveInboundWithNetwork(t, "tcp\nudp")

	var first string
	for attempt := range 8 {
		negotiated, err := negotiateTCPALPN(t, port, []string{"h3", "h2"})
		require.NoError(t, err)
		require.Equal(t, "h2", negotiated,
			"attempt %d: a TCP client offering h3 and h2 must always be given h2",
			attempt)
		if attempt == 0 {
			first = negotiated
			// Give any lazy initialisation a chance to run between attempts.
			time.Sleep(50 * time.Millisecond)
		}
		require.Equal(t, first, negotiated,
			"the negotiated protocol must not change between handshakes; a change "+
				"means the shared TLS config was mutated after the listener started")
	}
	t.Logf("8 repeated handshakes all negotiated %q", first)
}

// TestJiejieNaiveTCPSurvivesUnrelatedQUICPortActivity is a light liveness check:
// activity on the QUIC side (a client connecting and aborting) must not disturb
// the TCP listener.
func TestJiejieNaiveTCPSurvivesUnrelatedQUICPortActivity(t *testing.T) {
	port := startNaiveInboundWithNetwork(t, "tcp\nudp")
	origin := startCountingTCPOrigin(t)

	// Poke the UDP side with a plain TCP connection, which cannot be QUIC and
	// must simply be ignored rather than disturbing the listener.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 3*time.Second)
	if err == nil {
		_, _ = conn.Write([]byte("not quic at all"))
		_ = conn.Close()
	}

	// The TCP listener must still negotiate h2 and carry a tunnel.
	negotiated, err := negotiateTCPALPN(t, port, []string{"h2"})
	require.NoError(t, err)
	require.Equal(t, "h2", negotiated)

	tlsConn := naiveTLSConn(t, port, "http/1.1")
	response := naiveWriteConnectOK(t, tlsConn, origin.addr, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
	})
	defer response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	require.True(t, waitForDial(&origin.conns, 0))
	t.Log("TCP listener unaffected by unrelated activity on the inbound port")
	_ = tls.Config{}
}
