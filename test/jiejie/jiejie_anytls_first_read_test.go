package jiejie_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// These tests exercise the one-shot pre-authentication read timeout on the
// AnyTLS inbound at RUNTIME, through a real TLS handshake and the real
// sing-anytls service.
//
// The bug they guard against: sing-anytls reads the prologue with a single
// ReadOnceFrom that carries no deadline. A peer that completes the TLS handshake
// and then sends nothing -- no AnyTLS password, no HTTP fallback payload --
// therefore held the FD, goroutine, TLS state and buffers open indefinitely.
// Because these tests drive the inbound the same way an attacker would, they
// fail if the wrapper is removed from protocol/anytls/inbound.go.

// startAnyTLSInboundWithFallback starts a plain AnyTLS inbound with a default
// fallback backend and returns the AnyTLS port and the fallback backend port.
func startAnyTLSInboundWithFallback(t *testing.T) (int, int) {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, minimalTestTLSName)
	anytlsPort := reserveTCPPort(t)
	fallbackPort := startALPNLabeledBackend(t, "web-decoy")

	tlsContainer := minimalInboundTLS(certPem, keyPem)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeAnyTLS,
			Tag:  "anytls-in",
			Options: &option.AnyTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     minimalLoopback(),
					ListenPort: anytlsPort,
				},
				Users: []option.AnyTLSUser{{Name: minimalTestUser, Password: minimalTestPassword}},
				Fallback: &option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: uint16(fallbackPort),
				},
				InboundTLSOptionsContainer: tlsContainer,
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return int(anytlsPort), fallbackPort
}

// TestJiejieAnyTLSSilentPeerIsClosedAfterHandshake is case A at runtime: the peer
// completes TLS and then sends nothing at all, so the connection must be closed
// by the pre-authentication read deadline rather than held open forever.
func TestJiejieAnyTLSSilentPeerIsClosedAfterHandshake(t *testing.T) {
	anytlsPort, _ := startAnyTLSInboundWithFallback(t)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.Dial("tcp", "127.0.0.1:"+strconv.Itoa(anytlsPort))
	require.NoError(t, err)
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         minimalTestTLSName,
	})
	require.NoError(t, tlsConn.Handshake(), "the TLS handshake itself must still succeed")

	// From here on: complete silence. The server must give up on us.
	//
	// Production uses C.TCPTimeout (15s); this allows generous headroom on top
	// of that for a slow CI machine while still failing loudly if the deadline
	// is never applied.
	readDeadline := C.TCPTimeout + 45*time.Second
	require.NoError(t, tlsConn.SetReadDeadline(time.Now().Add(readDeadline)))

	buffer := make([]byte, 1)
	start := time.Now()
	_, readErr := tlsConn.Read(buffer)
	elapsed := time.Since(start)

	require.Error(t, readErr,
		"a peer that completes the TLS handshake and then sends nothing must have its "+
			"connection closed by the pre-authentication read timeout, not held open")
	require.Less(t, elapsed, readDeadline,
		"the connection must be closed by the server's own timeout, not by the client deadline")

	// Confirm the closure was a clean EOF/reset from the server rather than a
	// local timeout we imposed.
	if netErr, isNetErr := readErr.(net.Error); isNetErr && netErr.Timeout() {
		t.Fatalf("the read hit the CLIENT deadline (%v) instead of the server closing the "+
			"connection; the pre-auth timeout is not being applied", elapsed)
	}
}

// TestJiejieAnyTLSNonClientFallsBackToWeb is case C at runtime: an ordinary HTTPS
// client (no AnyTLS password) must be served by the fallback and see normal web
// behaviour, with no proxy challenge headers.
func TestJiejieAnyTLSNonClientFallsBackToWeb(t *testing.T) {
	anytlsPort, _ := startAnyTLSInboundWithFallback(t)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         minimalTestTLSName,
				NextProtos:         []string{"http/1.1"},
			},
		},
		Timeout: 20 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(anytlsPort) + "/")
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode,
		"a plain HTTPS client must receive the fallback's normal response")
	require.Contains(t, string(body), "web-decoy", "the fallback must have served the request")

	// No proxy authentication surface must be revealed.
	require.Empty(t, response.Header.Get("Proxy-Authenticate"),
		"a non-AnyTLS client must never be shown a proxy authentication challenge")
	require.Empty(t, response.Header.Get("WWW-Authenticate"),
		"a non-AnyTLS client must never be shown a WWW-Authenticate challenge")
	require.NotEqual(t, http.StatusUnauthorized, response.StatusCode)
	require.NotEqual(t, http.StatusProxyAuthRequired, response.StatusCode)
}

// TestJiejieAnyTLSWrongPasswordFallsBack is case D at runtime: a wrong AnyTLS
// password must be indistinguishable from a non-client and must not produce a
// proxy challenge.
func TestJiejieAnyTLSWrongPasswordFallsBack(t *testing.T) {
	anytlsPort, _ := startAnyTLSInboundWithFallback(t)

	body, header := requestThroughALPN(t, anytlsPort, "http/1.1")
	require.Contains(t, body, "web-decoy", "a wrong-password peer must still reach the fallback")

	require.Empty(t, header.Get("Proxy-Authenticate"),
		"a wrong password must never produce a Proxy-Authenticate header")
	require.Empty(t, header.Get("WWW-Authenticate"),
		"a wrong password must never produce a WWW-Authenticate header")
}
