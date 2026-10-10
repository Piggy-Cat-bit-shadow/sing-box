//go:build with_quic

package http

// The production WIRING between a network transition and the HTTP/3 connection it must drop.
//
// # Why a wiring test is needed at all
//
// `transport/http`'s own churn stand drives `Client.ResetConnections()` directly, because that is
// the object the connection layer owns. But a stand that calls a method proves nothing about
// whether the PRODUCT calls it, and a matrix row that reads "HTTP/3 churn verified" must not rest
// on a method nothing reaches in production.
//
// The chain is:
//
//	NetworkManager.resetNetworkLocked   route/network.go
//	  -> every outbound's InterfaceUpdated        (pinned by
//	     route/interface_update_deferral_test.go, which counts the callbacks)
//	  -> protocol/http.Outbound.InterfaceUpdated
//	  -> transport/http.Client.ResetConnections
//	  -> a NEW QUIC handshake on the next dial
//
// The first two links are covered in `route`. This file covers the last two on REAL sockets: an
// HTTP/3 outbound against a real loopback HTTP/3 egress, where "the connection was dropped" is
// observed as the egress accepting a SECOND handshake. Counting a call would not distinguish a
// reset that reached the connection from one that only cleared a field.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// h3WiringEgress is a real HTTP/3 egress on loopback that counts the connections it accepted.
type h3WiringEgress struct {
	address  string
	server   *http3.Server
	served   chan struct{}
	access   sync.Mutex
	accepted int
	tunnels  int
}

func startH3WiringEgress(t *testing.T) *h3WiringEgress {
	t.Helper()
	egress := &h3WiringEgress{served: make(chan struct{})}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"example.test"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	egress.address = packetConn.LocalAddr().String()

	egress.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			egress.access.Lock()
			egress.tunnels++
			egress.access.Unlock()
			writer.WriteHeader(http.StatusOK)
			if flusher, isFlusher := writer.(http.Flusher); isFlusher {
				flusher.Flush()
			}
			// A CONNECT is a tunnel: stay open and echo, so the connection is genuinely live
			// rather than half-closed when the reset arrives.
			buffer := make([]byte, 4096)
			for {
				read, readErr := request.Body.Read(buffer)
				if read > 0 {
					if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
						return
					}
					if flusher, isFlusher := writer.(http.Flusher); isFlusher {
						flusher.Flush()
					}
				}
				if readErr != nil {
					return
				}
			}
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			egress.access.Lock()
			egress.accepted++
			egress.access.Unlock()
			return ctx
		},
	}
	go func() {
		_ = egress.server.Serve(packetConn)
		close(egress.served)
	}()
	t.Cleanup(func() {
		_ = egress.server.Close()
		<-egress.served
	})
	return egress
}

func (e *h3WiringEgress) acceptedCount() int {
	e.access.Lock()
	defer e.access.Unlock()
	return e.accepted
}

// TestInterfaceUpdatedDropsTheRealHTTP3Connection is the wiring claim, on real sockets.
func TestInterfaceUpdatedDropsTheRealHTTP3Connection(t *testing.T) {
	t.Parallel()

	egress := startH3WiringEgress(t)
	host, portText, err := net.SplitHostPort(egress.address)
	require.NoError(t, err)
	portValue, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)
	port := uint16(portValue)

	instance, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "h3-out",
		option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{Server: host, ServerPort: port},
			Version:       3,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "example.test",
					Insecure:   true,
					ALPN:       []string{"h3"},
				},
			},
		})
	require.NoError(t, err)
	outbound := instance.(*Outbound)
	t.Cleanup(func() { _ = outbound.client.Close() })

	dial := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, dialErr := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("origin.test:443"))
		require.NoError(t, dialErr, "the tunnel must be established over HTTP/3")
		require.NotNil(t, conn)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, writeErr := conn.Write([]byte("probe"))
		require.NoError(t, writeErr)
		echo := make([]byte, len("probe"))
		_, readErr := io.ReadFull(conn, echo)
		require.NoError(t, readErr, "the tunnel must carry payload, or nothing was established")
		require.Equal(t, "probe", string(echo))
		_ = conn.Close()
	}

	dial()
	require.Equal(t, 1, egress.acceptedCount(), "the first dial performs one QUIC handshake")

	// Control: without a transition the SAME connection is reused. Without this the assertion
	// below would pass against an outbound that re-handshakes on every dial, which would make the
	// reset unobservable.
	dial()
	require.Equal(t, 1, egress.acceptedCount(),
		"a second dial on an unchanged network must REUSE the HTTP/3 connection; if it does not, "+
			"the handshake count below cannot distinguish a reset from ordinary redialing")

	// The production entry route's dispatch reaches: NetworkManager walks every outbound and calls
	// this. It must really drop the connection, not merely clear a field.
	outbound.InterfaceUpdated(context.Background())

	dial()
	require.Equal(t, 2, egress.acceptedCount(),
		"InterfaceUpdated did not drop the HTTP/3 connection: the next dial reused the one the "+
			"transition was supposed to retire, so a QUIC session pinned to the previous network "+
			"would keep carrying traffic on the new one")
}
