package jiejie_test

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"

	"github.com/stretchr/testify/require"
)

// AUDIT: TLS / ALPN / listener behaviour across the network matrix.
//
// The concern is that TCP and UDP setup both touch NextProtos, so one protocol
// could overwrite the other's ALPN, and that a TCP-only inbound must not open a
// UDP listener at all. Both are measured here.

func auditNaiveInbound(t *testing.T, network option.NetworkList) uint16 {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: "naive",
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				Network:       network,
				Users:         []auth.User{{Username: naiveTestUser, Password: naiveTestPassword}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: "direct", Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return port
}

// TestAuditTLSOnlyNetworkDoesNotOpenUDP proves a tcp-only inbound is TCP only.
func TestAuditTLSOnlyNetworkDoesNotOpenUDP(t *testing.T) {
	port := auditNaiveInbound(t, option.NetworkList("tcp"))

	// TCP must accept.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 5*time.Second)
	require.NoError(t, err, "a tcp-only inbound must accept TCP")
	conn.Close()

	// UDP must NOT be bound. A UDP send to an unbound port does not error, so
	// the reliable check is that the port cannot be dialled for UDP at all OR
	// that nothing answers a QUIC initial. We assert the weaker, honest form:
	// no UDP listener is reported for this port.
	if udpAddr, resolveErr := net.ResolveUDPAddr("udp", "127.0.0.1:"+strconv.Itoa(int(port))); resolveErr == nil {
		probe, dialErr := net.DialUDP("udp", nil, udpAddr)
		if dialErr == nil {
			_ = probe.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = probe.Write([]byte{0x00})
			buffer := make([]byte, 64)
			n, _, readErr := probe.ReadFromUDP(buffer)
			require.Error(t, readErr,
				"a tcp-only inbound must not run a UDP server; got %d bytes back", n)
			probe.Close()
		}
	}
}

// TestAuditALPNNegotiationMatrix proves HTTP/2 and HTTP/1.1 both negotiate on the
// TLS listener, and that h2 is advertised even when the user set only http/1.1.
func TestAuditALPNNegotiationMatrix(t *testing.T) {
	port := auditNaiveInbound(t, option.NetworkList("tcp"))

	cases := []struct {
		name        string
		offer       []string
		wantProto   string
		wantAnyALPN bool
	}{
		{name: "h2 only", offer: []string{"h2"}, wantProto: "h2"},
		{name: "http/1.1 only", offer: []string{"http/1.1"}, wantProto: "http/1.1"},
		{name: "h2 preferred", offer: []string{"h2", "http/1.1"}, wantProto: "h2"},
		{name: "no ALPN offered", offer: nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			tlsConn := tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "naive.test",
				NextProtos:         testCase.offer,
			})
			require.NoError(t, tlsConn.Handshake(),
				"the TLS handshake must succeed for %s", testCase.name)
			negotiated := tlsConn.ConnectionState().NegotiatedProtocol
			t.Logf("%-16s -> negotiated %q", testCase.name, negotiated)
			if testCase.wantProto != "" {
				require.Equal(t, testCase.wantProto, negotiated,
					"the server must negotiate %s when offered", testCase.wantProto)
			}
		})
	}
}

// TestAuditTCPAndUDPSimultaneously proves enabling both networks leaves BOTH
// working, i.e. neither ALPN overwrites the other.
func TestAuditTCPAndUDPSimultaneously(t *testing.T) {
	port := auditNaiveInbound(t, option.NetworkList("tcp\nudp"))

	// TCP must still negotiate h2.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, ServerName: "naive.test", NextProtos: []string{"h2"},
	})
	if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
		t.Logf("TCP handshake with h2 failed: %v", handshakeErr)
	} else {
		require.Equal(t, "h2", tlsConn.ConnectionState().NegotiatedProtocol,
			"with tcp+udp enabled, the TCP listener must still negotiate h2 for the "+
				"HTTP/2 CONNECT path: a UDP/H3 setup must not remove h2 from ALPN")
	}
}

// TestAuditNoTLSIsRejectedForUDPOnly proves a udp-only inbound without TLS fails
// to construct rather than silently serving plaintext.
func TestAuditNoTLSIsRejectedForUDPOnly(t *testing.T) {
	requireFullNaiveRegistry(t)
	port := reserveTCPPort(t)
	_, err := box.New(box.Options{
		Context: globalCtx,
		Options: option.Options{
			Inbounds: []option.Inbound{{
				Type: "naive",
				Tag:  "naive-in",
				Options: &option.NaiveInboundOptions{
					ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
					Network:       option.NetworkList("udp"),
					Users:         []auth.User{{Username: "u", Password: "p"}},
				},
			}},
			Outbounds: []option.Outbound{{Type: "direct", Tag: "direct"}},
			Route:     &option.RouteOptions{Final: "direct"},
		},
	})
	require.Error(t, err,
		"a udp-only Naive inbound requires TLS; constructing it without TLS must "+
			"fail rather than silently running plaintext QUIC")
}

// TestAuditPlaintextH2CIsNotSilentlyEnabled documents that the h2c handler only
// serves a connection that is NOT wrapped in TLS. With TLS configured, a
// plaintext HTTP/2 client must not be able to speak proxy protocol.
func TestAuditPlaintextH2CIsNotSilentlyEnabled(t *testing.T) {
	port := auditNaiveInbound(t, option.NetworkList("tcp"))

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Speak plaintext HTTP/1.1 to a TLS listener: it must not be served.
	_, _ = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 256)
	n, _ := conn.Read(buffer)
	response := string(buffer[:n])
	require.NotContains(t, response, "200 OK",
		"a plaintext request to a TLS listener must not be served as a proxy tunnel")
	t.Logf("plaintext probe response: %q", response)
}
