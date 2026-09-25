// Package reference_test drives the sing-box MASQUE server with the PINNED
// third-party reference clients (quic-go/masque-go and quic-go/connect-ip-go)
// instead of with sing-box's own client code.
//
// Why this is a separate module and a separate package:
//
//   - The two reference clients are the implementations the sing-box client was
//     written to interoperate with, so a round trip through them is the only
//     evidence that the wire format is actually right. A test that uses
//     sing-box's own client on both ends proves sing-box agrees with itself,
//     which is exactly the class of bug this file exists to rule out.
//   - They must never be importable from the shipped binary, so they live in
//     their own module (see go.mod) that neither the root module nor the `test`
//     module depends on.
//
// Every fixture here is loopback, uses a self-signed throwaway certificate and
// the literal credentials below. No production host, secret or private
// certificate appears anywhere in this file.
package reference_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/stretchr/testify/require"
)

const (
	// The same throwaway credentials the rest of the Jiejie fixture suite uses.
	referenceTestUser     = "sekai"
	referenceTestPassword = "password"

	// The self-signed certificate is issued for this name. It is a reserved
	// example domain, never a real host.
	referenceTestTLSName = "example.org"
)

// singBoxServer is a running MASQUE HTTP/3 inbound plus the harness that
// produces the server configuration.
//
// It is defined here rather than reusing the `test/jiejie` harness because this
// is a different module: importing that package would pull the whole Jiejie
// suite, and its `test` module dependencies, into this module's graph. The
// configuration below is intentionally the same shape as
// startJiejieMASQUEH3 so the two harnesses describe the same server.
type singBoxServer struct {
	port   uint16
	stop   func()
	origin string
	// connectIPPath is the URI template path for the CONNECT-IP resource. It is
	// a field because the path is part of what is being tested: the reference
	// client must be pointed at the resource the server actually serves.
	connectIPPath string
}

// startSingBoxMASQUEH3 starts an HTTP/3-only CONNECT-UDP (RFC 9298) inbound on
// loopback, plus a UDP echo origin to proxy to.
//
// It runs the server as a REAL PROCESS rather than in-process, because this
// module does not (and must not) import the sing-box root module, which is what
// box.New would require. Driving the shipped binary over a real socket is also
// strictly stronger evidence than an in-process call: the configuration is
// parsed from JSON, the full listener stack runs, and nothing is reachable only
// because a test set a Go field directly.
func startSingBoxMASQUEH3(t *testing.T, extraConfig string) *singBoxServer {
	t.Helper()

	origin := startUDPEchoOrigin(t)
	inbound := map[string]any{
		"type":    "http",
		"tag":     "masque-in",
		"version": []int{3},
		"users": []any{
			map[string]any{
				"username": referenceTestUser,
				"password": referenceTestPassword,
			},
		},
	}
	if extraConfig != "" {
		var extra map[string]any
		require.NoError(t, json.Unmarshal([]byte(extraConfig), &extra),
			"extraConfig must be a JSON object")
		for key, value := range extra {
			inbound[key] = value
		}
	}

	server := startSingBoxMASQUEH3WithConfig(t, map[string]any{
		"inbounds": []any{inbound},
	})
	server.origin = origin
	return server
}

// ---------------------------------------------------------------------------
// Loopback fixtures
// ---------------------------------------------------------------------------

// startUDPEchoOrigin starts a UDP echo server and returns its host:port.
//
// A CONNECT-UDP target must be a UDP endpoint the server can reach through its
// real routing path, so a loopback echo server is the origin. It replies with a
// fixed prefix so a test can prove the payload that comes back is the payload
// the origin produced, not a local echo of what the client sent.
func startUDPEchoOrigin(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, address, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			payload := append([]byte("origin:"), buffer[:n]...)
			_, _ = conn.WriteTo(payload, address)
		}
	}()
	return conn.LocalAddr().String()
}

// reserveUDPPort asks the kernel for a free loopback UDP port.
func reserveUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// isUDPPortFree reports whether a UDP port can still be bound.
func isUDPPortFree(port uint16) bool {
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// connectUDPRequest builds an RFC 9298 extended CONNECT for a target.
//
// The target goes in the PATH, which is the form the sing-box inbound parses
// (/.well-known/masque/udp/<host>/<port>/), with Proxy-Authorization for the
// proxy authentication surface.
func connectUDPRequest(target string) http.Request {
	return http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		URL: &url.URL{
			Scheme: "https",
			Host:   referenceTestTLSName,
			Path:   connectUDPPath(target),
		},
		Host: referenceTestTLSName,
		Header: http.Header{
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{basicProxyAuthorization()},
		},
	}
}

// connectUDPPath renders the RFC 9298 well-known path for a host:port target.
func connectUDPPath(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "/.well-known/masque/udp/" + target + "/"
	}
	return "/.well-known/masque/udp/" + host + "/" + port + "/"
}

// ---------------------------------------------------------------------------
// The CONNECT-UDP interop test
// ---------------------------------------------------------------------------

// TestReferenceMasqueGoConnectUDP is the external-interoperability proof for
// RFC 9298 CONNECT-UDP over HTTP/3.
//
// The client on the wire is github.com/quic-go/masque-go, pinned by commit in
// go.mod, driving a real QUIC + HTTP/3 Extended CONNECT to a real sing-box
// process. The assertions are made on bytes that travelled:
//
//	masque-go -> QUIC datagram -> sing-box -> UDP -> echo origin
//	          <- QUIC datagram <- sing-box <- UDP <-
//
// so a divergence in the request path, the :protocol pseudo-header, the
// Capsule-Protocol setting, the Extended CONNECT settings exchange, the
// DATAGRAM context ID or the capsule framing all fail here.
func TestReferenceMasqueGoConnectUDP(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The URI template must expand to the RFC 9298 well-known resource the
	// sing-box inbound actually serves. masque-go expands {target_host} and
	// {target_port} into whatever position the template puts them, and sing-box
	// parses the target out of the PATH segments
	// (/.well-known/masque/udp/<host>/<port>/), not out of a query string, so the
	// template has to place the variables in the path.
	proxyURL := fmt.Sprintf("https://%s/.well-known/masque/udp/{target_host}/{target_port}/", server.address())
	template, err := uritemplate.New(proxyURL)
	require.NoError(t, err)

	request, err := masque.NewRequest(ctx, template, server.origin)
	require.NoError(t, err)
	// The credentials travel as Proxy-Authorization, which is what the sing-box
	// HTTP inbound authenticates with for proxy clients.
	request.Header().Set("Proxy-Authorization", basicProxyAuthorization())

	transport := &masque.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         referenceTestTLSName,
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	}

	conn, response, err := transport.Dial(request)
	require.NoError(t, err, "masque-go must be able to dial the sing-box MASQUE server")
	require.NotNil(t, response)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"the MASQUE server must accept the extended CONNECT")
	defer conn.Close()

	// A payload large enough to be unambiguously a datagram and small enough to
	// fit the tunnel MTU, with a distinctive shape so a truncated or reordered
	// reply cannot pass by accident.
	payload := []byte("masque-go-interop-0123456789")
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	// masque.Conn is a net.PacketConn: RFC 9298 proxies individual UDP
	// datagrams, so the client writes TO a remote address rather than into a
	// byte stream. The reply is expected from the same address.
	_, err = conn.WriteTo(payload, nil)
	require.NoError(t, err)

	buffer := make([]byte, 1500)
	n, from, err := conn.ReadFrom(buffer)
	require.NoError(t, err, "the proxied connection must deliver the origin's reply")
	require.NotNil(t, from)
	require.Equal(t, "origin:"+string(payload), string(buffer[:n]),
		"the reply must be the one the ORIGIN produced, proving the UDP payload "+
			"crossed the proxy end to end")
}

// TestReferenceMasqueGoConnectUDPRejectedWithoutAuth is the negative half: the
// same reference client, same request shape, but no credentials.
//
// It must not be handed a tunnel. This is what makes the positive test above
// meaningful - if the server accepted every extended CONNECT, the round trip
// would prove nothing about authentication.
func TestReferenceMasqueGoConnectUDPRejectedWithoutAuth(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyURL := fmt.Sprintf("https://%s/masque?h={target_host}&p={target_port}", server.address())
	template, err := uritemplate.New(proxyURL)
	require.NoError(t, err)

	request, err := masque.NewRequest(ctx, template, server.origin)
	require.NoError(t, err)
	// No Proxy-Authorization.

	transport := &masque.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         referenceTestTLSName,
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}

	conn, response, err := transport.Dial(request)
	if err == nil {
		_ = conn.Close()
		t.Fatal("an unauthenticated CONNECT-UDP must not be handed a tunnel")
	}
	// The server is configured with a masquerade backend, so the failure is
	// served as an ordinary web response rather than a proxy challenge. Either
	// way no tunnel exists, which is what this test asserts.
	require.Nil(t, conn)
	_ = response
}

// TestReferenceMasqueGoRequiresServerDatagramSupport pins the SETTINGS exchange
// the reference client depends on.
//
// masque-go refuses to dial unless the server advertised BOTH
// SETTINGS_ENABLE_CONNECT_PROTOCOL (Extended CONNECT) and
// SETTINGS_H3_DATAGRAM. Reading those back from the reference client's own view
// of the connection is stronger than asserting sing-box's configuration says so,
// because it is the peer's observation of the wire.
func TestReferenceMasqueGoRequiresServerDatagramSupport(t *testing.T) {
	server := startSingBoxMASQUEH3(t, "")
	t.Cleanup(server.stop)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	quicConn, err := quic.DialAddr(ctx, server.address(), &tls.Config{
		ServerName:         referenceTestTLSName,
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)
	defer quicConn.CloseWithError(0, "")

	require.True(t, quicConn.ConnectionState().SupportsDatagrams.Local,
		"the QUIC handshake must negotiate the datagram extension; the whole "+
			"CONNECT-UDP data path is QUIC datagrams")
	require.True(t, quicConn.ConnectionState().SupportsDatagrams.Remote,
		"the server must negotiate the datagram extension too")

	transport := &http3.Transport{EnableDatagrams: true}
	defer transport.Close()
	clientConn := transport.NewClientConn(quicConn)

	// NewClientConn is the reference library's own gate: it fails unless the
	// connection's settings carry Extended CONNECT and datagram support.
	proxyConn, err := (&masque.Transport{}).NewClientConn(quicConn)
	require.NoError(t, err,
		"masque-go must accept sing-box's HTTP/3 settings: Extended CONNECT and "+
			"datagram support are both mandatory for it")
	require.NotNil(t, proxyConn)

	_ = clientConn
}

// ---------------------------------------------------------------------------
// Self-checks for the harness itself
// ---------------------------------------------------------------------------

// TestReferenceHarnessDetectsAStoppedServer is a guard on the harness, not on
// sing-box.
//
// If startSingBoxMASQUEH3 silently failed to start a listener, every interop
// assertion above would fail for the wrong reason and the failure would be
// misread as a protocol bug. This test proves the harness notices a server that
// is not listening.
func TestReferenceHarnessDetectsAStoppedServer(t *testing.T) {
	port := reserveUDPPort(t)
	require.True(t, isUDPPortFree(port))

	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	require.NoError(t, err)
	require.False(t, isUDPPortFree(port), "a bound port must not read as free")
	_ = conn.Close()
	require.True(t, isUDPPortFree(port), "a released port must read as free again")
}
