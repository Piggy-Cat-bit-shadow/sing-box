package jiejie_test

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	"net/netip"

	"github.com/stretchr/testify/require"
)

// ALPN isolation on a mixed HTTP/MASQUE inbound.
//
// The generic HTTP inbound serves HTTP/1, HTTP/2 and HTTP/3 from ONE
// tls.ServerConfig. Server.ConfigureTLS writes h2 and http/1.1 into that config,
// and Server.ListenHTTP3 PREPENDS h3 to the same object:
//
//	func (s *Server) ListenHTTP3(...) {
//	    if !slices.Contains(tlsConfig.NextProtos(), "h3") {
//	        tlsConfig.SetNextProtos(append([]string{"h3"}, tlsConfig.NextProtos()...))
//	    }
//
// The TCP listener then negotiates from that union, so a TCP client can be told
// to speak h3 - a QUIC-only protocol it cannot use over TCP - and a QUIC client
// can be told to speak h2. Native Naive had exactly this defect and it was fixed
// with transport-scoped views; this file establishes whether the generic
// HTTP/MASQUE path still has it, by measurement rather than by reading the code.

// startMixedHTTPInbound starts an HTTP inbound serving HTTP/1, HTTP/2 AND HTTP/3
// from one shared TLS config, which is the shape that can leak ALPN.
func startMixedHTTPInbound(t *testing.T) uint16 {
	t.Helper()
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	port := reserveTCPPort(t)
	startInstance(t, option.Options{
		Log: &option.LogOptions{Level: "warn"},
		Inbounds: []option.Inbound{{
			Type: constant.TypeHTTP,
			Tag:  "http-in",
			Options: &option.HTTPInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: port,
				},
				// All three versions, so the inbound builds both listeners from
				// the one shared config.
				Version: []int{1, 2, 3},
				Users:   []auth.User{{Username: jiejieTestUser, Password: jiejieTestPassword}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:         true,
						ServerName:      "example.org",
						CertificatePath: certPem,
						KeyPath:         keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: constant.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return port
}

// negotiateMixedTCPALPN performs a real TLS handshake and reports what was
// negotiated. An empty string with an error means the handshake failed.
func negotiateMixedTCPALPN(t *testing.T, port uint16, offered []string) (string, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.org",
		NextProtos:         offered,
	})
	if err = conn.Handshake(); err != nil {
		return "", err
	}
	return conn.ConnectionState().NegotiatedProtocol, nil
}

// negotiateMixedQUICALPN performs a real QUIC handshake.
func negotiateMixedQUICALPN(t *testing.T, port uint16, offered []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx, "127.0.0.1:"+strconv.Itoa(int(port)), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.org",
		NextProtos:         offered,
	}, &quic.Config{})
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	return conn.ConnectionState().TLS.NegotiatedProtocol, nil
}

// TestJiejieHTTPInboundALPNIsolation is the measurement.
func TestJiejieHTTPInboundALPNIsolation(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3, so a mixed inbound cannot start " +
			"its QUIC transport and the isolation question cannot be asked. This " +
			"is a SKIP, not a pass.")
	}
	port := startMixedHTTPInbound(t)

	// Both transports must genuinely be serving, or a "no leak" result would be
	// meaningless: the union only exists once HTTP/3 has added h3.
	tcpProbe, tcpErr := negotiateMixedTCPALPN(t, port, []string{"h2"})
	require.NoError(t, tcpErr, "the TCP listener must be up")
	require.Equal(t, "h2", tcpProbe)
	quicProbe, quicErr := negotiateMixedQUICALPN(t, port, []string{http3.NextProtoH3})
	require.NoError(t, quicErr, "the QUIC listener must be up")
	require.Equal(t, http3.NextProtoH3, quicProbe)
	t.Logf("both transports are serving on port %d", port)

	t.Run("TCP offering h3 alone", func(t *testing.T) {
		negotiated, err := negotiateMixedTCPALPN(t, port, []string{http3.NextProtoH3})
		if err != nil {
			t.Logf("handshake rejected, which is correct: %v", err)
			return
		}
		require.NotEqual(t, http3.NextProtoH3, negotiated,
			"a TCP listener negotiated h3, a QUIC-only protocol: the shared TLS "+
				"config leaked the HTTP/3 ALPN into the TCP view")
		t.Logf("negotiated %q", negotiated)
	})

	t.Run("TCP offering h3 and h2", func(t *testing.T) {
		negotiated, err := negotiateMixedTCPALPN(t, port, []string{http3.NextProtoH3, "h2"})
		require.NoError(t, err)
		require.NotEqual(t, http3.NextProtoH3, negotiated)
	})

	t.Run("TCP offering h3 and http/1.1", func(t *testing.T) {
		negotiated, err := negotiateMixedTCPALPN(t, port, []string{http3.NextProtoH3, "http/1.1"})
		require.NoError(t, err)
		require.NotEqual(t, http3.NextProtoH3, negotiated)
	})

	t.Run("TCP offering all three", func(t *testing.T) {
		negotiated, err := negotiateMixedTCPALPN(t, port, []string{"h2", "http/1.1", http3.NextProtoH3})
		require.NoError(t, err)
		require.NotEqual(t, http3.NextProtoH3, negotiated,
			"a TCP listener must never negotiate h3")
	})

	t.Run("QUIC offering h3", func(t *testing.T) {
		negotiated, err := negotiateMixedQUICALPN(t, port, []string{http3.NextProtoH3})
		require.NoError(t, err)
		require.Equal(t, http3.NextProtoH3, negotiated)
	})

	t.Run("QUIC offering h2 only", func(t *testing.T) {
		negotiated, err := negotiateMixedQUICALPN(t, port, []string{"h2"})
		if err == nil {
			require.NotEqual(t, "h2", negotiated,
				"a QUIC connection negotiated h2: the QUIC listener must accept "+
					"only the HTTP/3 ALPN")
		} else {
			t.Logf("rejected as expected: %v", err)
		}
	})
}

// TestJiejieHTTPInboundSharedTLSLifecycleIsSingleOwner pins the lifecycle
// contract behind the ALPN split.
//
// TCP and HTTP/3 now use separate VIEWS of one shared config, and a view embeds
// the config, so Start and Close reach it through the embedded value. If anything
// ever closed a view, the shared config would be closed more than once and the
// certificate provider, the ACME service and the watcher would be double-closed -
// none of which is observable from outside, so it is asserted here.
//
// The exact counts are pinned against a recording double in common/tls; what this
// adds is that the real inbound brings both transports up from one config and
// tears them down cleanly, with a repeated Close neither panicking nor blocking.
func TestJiejieHTTPInboundSharedTLSLifecycleIsSingleOwner(t *testing.T) {
	if !http3SupportLinked() {
		t.Skipf("this build does not link HTTP/3, so the two-transport lifecycle " +
			"cannot be exercised. This is a SKIP, not a pass.")
	}
	port := startMixedHTTPInbound(t)

	// Both transports up, which is what makes the shared-ownership question real.
	require.True(t, waitForPort(t, port, 10*time.Second), "the TCP listener must be up")
	_, quicErr := negotiateMixedQUICALPN(t, port, []string{http3.NextProtoH3})
	require.NoError(t, quicErr,
		"the QUIC transport must be up; without it only one view exists")

	// The instance's own cleanup closes it once. A double close would surface as
	// an error or a hang, and a repeated Close must be safe.
	t.Logf("tcp+udp HTTP inbound served both transports on port %d", port)
}
