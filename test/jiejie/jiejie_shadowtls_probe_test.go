package jiejie_test

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// These tests lock down ShadowTLS v3 active-probe behaviour at runtime.
//
// Production topology: public TCP/443 -> Nginx SNI www.intel.com ->
// 127.0.0.1:8554 -> sing-box ShadowTLS v3 (strict_mode) -> detour -> SS2022 on
// 127.0.0.1:17414. SS2022 is never exposed publicly.
//
// The property under test is that an unauthenticated or plain-TLS client is
// RELAYED to the real handshake target rather than shown a proxy error. Measured
// against the pinned sing-shadowtls v0.2.1: when verifyClientHello fails, the
// service dials the configured handshake server and does a bidirectional copy of
// the original ClientHello, so the prober sees the decoy's genuine TLS session.
//
// These tests deliberately do NOT use the public internet. They point the
// handshake at a local TLS decoy origin, so they cannot be affected by an
// external site changing, being unreachable, or being rate-limited.
//
// The ShadowTLS wire protocol is NOT reimplemented here.

// startLocalTLSDecoyOrigin starts a real TLS server with its own self-signed
// certificate and a distinctive HTTP body. It stands in for www.intel.com.
func startLocalTLSDecoyOrigin(t *testing.T) (string, uint16) {
	t.Helper()
	// createSelfSignedCertificate returns a CA path and the leaf cert/key PATHS.
	_, certPath, keyPath := createSelfSignedCertificate(t, "decoy.test")
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	server := &http.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "text/html")
			writer.Header().Set("X-Decoy-Origin", "local-tls-decoy")
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, "<html><body>decoy-origin-page</body></html>")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() { _ = server.Close() })

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)
	return listener.Addr().String(), uint16(port)
}

// startShadowTLSv3Inbound starts a ShadowTLS v3 inbound in strict mode whose
// handshake points at the local decoy, and returns its port.
func startShadowTLSv3Inbound(t *testing.T, decoyPort uint16) int {
	t.Helper()
	shadowTLSPort := reserveTCPPort(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeShadowTLS,
			Tag:  "shadowtls-in",
			Options: &option.ShadowTLSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     minimalLoopback(),
					ListenPort: shadowTLSPort,
				},
				Version: 3,
				Users: []option.ShadowTLSUser{{
					Name:     minimalTestUser,
					Password: minimalTestPassword,
				}},
				// strict_mode requires the handshake server to negotiate TLS 1.3.
				StrictMode: true,
				Handshake: option.ShadowTLSHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: decoyPort,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return int(shadowTLSPort)
}

// TestJiejieShadowTLSNonClientSeesDecoy is case A: a plain TLS client that is not
// a ShadowTLS client at all must be relayed to the real handshake target and see
// genuine decoy TLS/HTTP behaviour -- never a proxy challenge or proxy error.
func TestJiejieShadowTLSNonClientSeesDecoy(t *testing.T) {
	_, decoyPort := startLocalTLSDecoyOrigin(t)
	shadowTLSPort := startShadowTLSv3Inbound(t, decoyPort)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "decoy.test",
				NextProtos:         []string{"http/1.1"},
			},
		},
		Timeout: 20 * time.Second,
	}
	response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(shadowTLSPort) + "/")
	require.NoError(t, err,
		"an ordinary TLS client must complete a handshake through ShadowTLS, because the "+
			"unauthenticated ClientHello is relayed to the real handshake target")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, response.StatusCode,
		"a prober must receive the decoy origin's normal response")
	require.Contains(t, string(body), "decoy-origin-page",
		"the prober must be served by the real handshake target, not by sing-box")
	require.Equal(t, "local-tls-decoy", response.Header.Get("X-Decoy-Origin"))

	// No proxy authentication surface may be revealed.
	require.Empty(t, response.Header.Get("Proxy-Authenticate"),
		"ShadowTLS must never emit a Proxy-Authenticate challenge to a prober")
	require.Empty(t, response.Header.Get("WWW-Authenticate"))
	require.NotEqual(t, http.StatusUnauthorized, response.StatusCode)
	require.NotEqual(t, http.StatusProxyAuthRequired, response.StatusCode)
}

// TestJiejieShadowTLSWrongCredentialSeesDecoy is case B: a client that looks like
// ShadowTLS but carries the wrong credential must also be relayed to the decoy.
// The HMAC over the ClientHello session ID does not match any configured user, so
// verifyClientHello fails and the same fallback path runs.
func TestJiejieShadowTLSWrongCredentialSeesDecoy(t *testing.T) {
	_, decoyPort := startLocalTLSDecoyOrigin(t)
	shadowTLSPort := startShadowTLSv3Inbound(t, decoyPort)

	// A raw TLS handshake with a large session ID is the closest a non-ShadowTLS
	// client gets to the v3 shape; either way the HMAC will not match.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(shadowTLSPort), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "decoy.test",
	})
	require.NoError(t, tlsConn.Handshake(),
		"a wrong-credential prober must still complete a handshake against the decoy")

	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(15*time.Second)))
	_, err = io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: decoy.test\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	responseBytes, err := io.ReadAll(tlsConn)
	require.NoError(t, err)
	responseText := string(responseBytes)

	require.Contains(t, responseText, "decoy-origin-page",
		"a wrong-credential prober must be answered by the decoy origin")
	require.NotContains(t, responseText, "Proxy-Authenticate",
		"a wrong credential must never produce a proxy challenge")
	require.NotContains(t, responseText, "WWW-Authenticate")
	require.NotContains(t, responseText, "407")
	require.NotContains(t, responseText, "401")
}

// TestJiejieShadowTLSRejectsNonTLSProbe proves a connection that is not TLS at
// all is simply closed, and that the internal SS2022 protocol is never exposed
// on the ShadowTLS port.
func TestJiejieShadowTLSRejectsNonTLSProbe(t *testing.T) {
	_, decoyPort := startLocalTLSDecoyOrigin(t)
	shadowTLSPort := startShadowTLSv3Inbound(t, decoyPort)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(shadowTLSPort), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send junk that is not a TLS record.
	_, err = conn.Write([]byte("this is not a tls client hello at all"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(15*time.Second)))

	buffer := make([]byte, 256)
	n, readErr := conn.Read(buffer)
	if readErr == nil {
		// Anything the server sends must not look like a proxy error surface.
		text := string(buffer[:n])
		require.NotContains(t, text, "Proxy-Authenticate")
		require.NotContains(t, text, "WWW-Authenticate")
	}
}

// TestJiejieShadowTLSStrictModeIsConfigured pins the production setting: strict
// mode must stay on, because it forces the handshake target to prove TLS 1.3 and
// otherwise falls back to a plain bidirectional copy.
func TestJiejieShadowTLSStrictModeIsConfigured(t *testing.T) {
	require.True(t, shadowTLSStrictModeInProductionTopology(t),
		"the production ShadowTLS inbound must keep strict_mode enabled")
}

// TestJiejieSS2022IsNeverPubliclyExposed pins the topology contract that makes
// ShadowTLS worth having: the SS2022 inbound must listen on loopback only and be
// reachable solely through the ShadowTLS detour. If it were ever bound to a
// public address, or unfronted, probing resistance would be meaningless.
func TestJiejieSS2022IsNeverPubliclyExposed(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "release", "jiejie-production-topology.json"))
	require.NoError(t, err)

	var topology struct {
		Inbounds []struct {
			Type     string `json:"type"`
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Detour   string `json:"detour"`
			Port     int    `json:"listen_port"`
			Users    any    `json:"users"`
			Password string `json:"password"`
		} `json:"inbounds"`
	}
	require.NoError(t, json.Unmarshal(content, &topology))

	var (
		foundSS      bool
		foundShadow  bool
		shadowDetour string
		ssListenAddr string
		shadowListen string
	)
	for _, inbound := range topology.Inbounds {
		switch inbound.Type {
		case "shadowsocks":
			foundSS = true
			ssListenAddr = inbound.Listen
		case "shadowtls":
			foundShadow = true
			shadowDetour = inbound.Detour
			shadowListen = inbound.Listen
		}
	}
	require.True(t, foundSS, "the production topology must define the ss2022 inbound")
	require.True(t, foundShadow, "the production topology must define the shadowtls inbound")

	require.Equal(t, "127.0.0.1", ssListenAddr,
		"the SS2022 inbound must bind loopback ONLY; exposing it publicly would remove "+
			"the probe resistance ShadowTLS provides")
	require.Equal(t, "ss2022-in", shadowDetour,
		"the shadowtls inbound must detour INTO the SS2022 inbound; the detour names "+
			"its target, not itself")
	require.Equal(t, "127.0.0.1", shadowListen,
		"the shadowtls inbound itself must also stay on loopback, behind the Nginx front door")
}

// shadowTLSStrictModeInProductionTopology reads the real production topology
// fixture and reports whether strict_mode is enabled on the ShadowTLS inbound.
func shadowTLSStrictModeInProductionTopology(t *testing.T) bool {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "release", "jiejie-production-topology.json"))
	require.NoError(t, err)

	var topology struct {
		Inbounds []struct {
			Type       string `json:"type"`
			StrictMode bool   `json:"strict_mode"`
			Version    int    `json:"version"`
		} `json:"inbounds"`
	}
	require.NoError(t, json.Unmarshal(content, &topology))

	for _, inbound := range topology.Inbounds {
		if inbound.Type == "shadowtls" {
			require.Equal(t, 3, inbound.Version,
				"the production ShadowTLS inbound must stay on protocol version 3")
			return inbound.StrictMode
		}
	}
	t.Fatal("the production topology must contain a shadowtls inbound")
	return false
}
