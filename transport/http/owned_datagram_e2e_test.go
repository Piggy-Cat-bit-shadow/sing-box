//go:build with_quic

package http

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// End-to-end tests for the zero-copy outbound DATAGRAM path against a REAL quic-go connection.
//
// # Why a real connection is required
//
// The owned path moves buffer ownership across three layers: sing-box hands a pooled buffer to the
// HTTP/3 layer, HTTP/3 writes a prefix into its headroom, and quic-go takes the bytes and releases
// the buffer when the packet is built. A stub stream can confirm the calls happen; only a real
// connection confirms that the bytes arrive, that the release is neither early nor late, and that
// the datagram ceiling the transport reports is respected.
//
// The tests below therefore dial a real HTTP/3 server and compare what the server received against
// what was sent.

// ownedPathServer is a real HTTP/3 server that accepts a CONNECT-IP tunnel and records every
// HTTP Datagram payload it decodes.
type ownedPathServer struct {
	address string
	server  *http3.Server
	access  sync.Mutex
	// received holds the decoded payloads, each starting with the MASQUE context ID.
	received [][]byte
	// loopStarted records whether the server reached its datagram receive loop, so a test can tell
	// "nothing arrived" apart from "the tunnel was never established".
	loopStarted bool
}

func (s *ownedPathServer) payloads() [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	out := make([][]byte, len(s.received))
	for index, payload := range s.received {
		out[index] = append([]byte(nil), payload...)
	}
	return out
}

func (s *ownedPathServer) started() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.loopStarted
}

func startOwnedPathServer(t *testing.T) *ownedPathServer {
	t.Helper()
	server := &ownedPathServer{}

	tlsConfig := testServerTLSConfig(t)
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	server.address = packetConn.LocalAddr().String()

	server.server = &http3.Server{
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			// Both of these must happen, and in this order, before the flush: the peer uses the
			// Capsule-Protocol header to confirm the extended CONNECT, and HTTP Datagrams are only
			// associated with a request that carried it. transport/http/tunnel_server.go does the
			// same in its Accept.
			writer.Header().Set("Capsule-Protocol", "?1")
			writer.WriteHeader(http.StatusOK)
			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			}
			stream, ok := HTTP3StreamFunc(request.Context(), writer)
			if !ok {
				return
			}
			server.access.Lock()
			server.loopStarted = true
			server.access.Unlock()
			for {
				payload, readErr := stream.ReceiveDatagram(request.Context())
				if readErr != nil {
					return
				}
				server.access.Lock()
				server.received = append(server.received, append([]byte(nil), payload...))
				server.access.Unlock()
			}
		}),
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		EnableDatagrams: true,
	}
	go func() { _ = server.server.Serve(packetConn) }()
	t.Cleanup(func() { _ = server.server.Close() })
	return server
}

// ownedPathTunnel opens a real CONNECT-IP tunnel and returns its datagram stream.
func ownedPathTunnel(t *testing.T, address string) DatagramStream {
	t.Helper()
	clientTLS, err := tls.NewSTDClient(t.Context(), logger.NOP(), "example.test",
		option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.test",
			Insecure:   true,
			ALPN:       []string{"h3"},
		})
	require.NoError(t, err)

	impl := &http3ClientImpl{
		dialer:    &connectedUDPDialer{},
		server:    M.ParseSocksaddr(address),
		authority: address,
		tlsConfig: clientTLS,
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			EnableDatagrams:      true,
		},
		transport: &http3.Transport{EnableDatagrams: true, DisableCompression: true},
	}
	impl.connectCandidate = impl.connectCandidateAt

	client := &Client{
		dialer:            &connectedUDPDialer{},
		http1Dialer:       &connectedUDPDialer{},
		authorityOverride: address,
		version:           3,
		server:            M.ParseSocksaddr(address),
		http3:             impl,
		http3Authority:    address,
	}
	tunnel, transport, err := client.OpenTunnelWithInfo(context.Background(), "connect-ip", "/")
	require.NoError(t, err)
	require.Equal(t, TunnelTransportHTTP3, transport)
	stream, ok := tunnel.(DatagramStream)
	require.True(t, ok)
	return stream
}

// TestOwnedDatagramPathIsAvailableOverRealHTTP3 proves the production wiring offers the zero-copy
// capability rather than quietly taking the fallback forever.
func TestOwnedDatagramPathIsAvailableOverRealHTTP3(t *testing.T) {
	server := startOwnedPathServer(t)
	stream := ownedPathTunnel(t, server.address)

	require.NotNil(t, AsOwnedDatagramSender(stream),
		"a real HTTP/3 datagram stream must expose the owned path; nil means the zero-copy path is "+
			"dead code and every packet takes the copying fallback")
}

// TestOwnedDatagramDeliversExactBytes is the payload-integrity proof on a real connection.
//
// # Why the buffers carry a per-packet pattern
//
// Each payload is filled with bytes derived from its index, so a buffer that was released early --
// and therefore recycled before its packet was built -- cannot produce the right bytes by accident.
// The server compares what it decoded against what was sent, byte for byte.
func TestOwnedDatagramDeliversExactBytes(t *testing.T) {
	server := startOwnedPathServer(t)
	stream := ownedPathTunnel(t, server.address)
	sender := AsOwnedDatagramSender(stream)
	require.NotNil(t, sender)
	require.True(t, server.started(), "the server must have reached its datagram loop")

	// 512 bytes plus framing stays under the datagram ceiling a loopback QUIC connection reports.
	const packets = 16
	const payloadSize = 512
	sent := make([][]byte, 0, packets)
	for index := range packets {
		payload := make([]byte, payloadSize)
		for byteIndex := range payload {
			payload[byteIndex] = byte(index*29 + byteIndex)
		}
		buffer := buf.NewSize(CapsuleHeadroom + len(payload))
		buffer.Resize(CapsuleHeadroom, 0)
		_, _ = buffer.Write(payload)
		datagram := PrependContextID(buffer)
		// What the peer should decode: the MASQUE context ID followed by the payload.
		sent = append(sent, append([]byte(nil), datagram.Bytes()...))

		require.NoError(t, sender.SendDatagramOwned(datagram),
			"packet %d must send over the owned path", index)
		// Ownership moved on success, so there is deliberately NO Release here. Calling one would
		// be a double release.
	}

	deadline := time.Now().Add(10 * time.Second)
	for len(server.payloads()) < packets && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	received := server.payloads()
	require.Len(t, received, packets,
		"every datagram must arrive; a short count means a buffer was released before its bytes "+
			"reached a packet")
	for index := range packets {
		require.Equal(t, sent[index], received[index],
			"packet %d arrived corrupted, so the release point is wrong and the payload was "+
				"recycled or overwritten before serialization", index)
	}
}

// TestOwnedDatagramTooLargeRollsBackOnRealConnection covers §29 and §85 on a real transport.
//
// A payload above the connection's datagram ceiling must fail WITHOUT taking ownership, and the
// buffer must come back exactly as it was handed over -- because the caller then trims it and builds
// an ICMP Packet Too Big from it.
func TestOwnedDatagramTooLargeRollsBackOnRealConnection(t *testing.T) {
	server := startOwnedPathServer(t)
	stream := ownedPathTunnel(t, server.address)
	sender := AsOwnedDatagramSender(stream)
	require.NotNil(t, sender)

	// Larger than any loopback QUIC connection will carry in one datagram.
	payload := make([]byte, 4096)
	for index := range payload {
		payload[index] = byte(index)
	}
	buffer := buf.NewSize(CapsuleHeadroom + len(payload))
	buffer.Resize(CapsuleHeadroom, 0)
	_, _ = buffer.Write(payload)
	datagram := PrependContextID(buffer)
	before := append([]byte(nil), datagram.Bytes()...)

	err := sender.SendDatagramOwned(datagram)
	require.Error(t, err, "an oversized datagram must be refused")
	var tooLarge *DatagramTooLargeError
	require.ErrorAs(t, err, &tooLarge,
		"the error must be the typed too-large error so the caller can compute a PTB MTU")
	require.Positive(t, tooLarge.MaxPayloadSize)

	// THE assertion: the HTTP/3 layer's prefix was rolled back, so the caller still sees exactly
	// ContextID + packet and can trim it.
	require.Equal(t, before, datagram.Bytes(),
		"a failed owned send must restore the caller's buffer exactly; a leftover quarter stream ID "+
			"would make the caller's PTB quote the wrong bytes")
	datagram.Release()
}

// TestOwnedPathAndCopyingPathAgree sends the same payload through both APIs and requires the peer to
// decode identical bytes, so the owned path cannot be subtly re-framing what it sends.
func TestOwnedPathAndCopyingPathAgree(t *testing.T) {
	server := startOwnedPathServer(t)
	stream := ownedPathTunnel(t, server.address)
	sender := AsOwnedDatagramSender(stream)
	require.NotNil(t, sender)

	payload := make([]byte, 256)
	for index := range payload {
		payload[index] = byte(index * 7)
	}

	// Owned send.
	ownedBuffer := buf.NewSize(CapsuleHeadroom + len(payload))
	ownedBuffer.Resize(CapsuleHeadroom, 0)
	_, _ = ownedBuffer.Write(payload)
	ownedDatagram := PrependContextID(ownedBuffer)
	ownedExpected := append([]byte(nil), ownedDatagram.Bytes()...)
	require.NoError(t, sender.SendDatagramOwned(ownedDatagram))

	// Copying send, with the context ID prepended by hand to match.
	copiedDatagram := append([]byte{0}, payload...)
	require.NoError(t, stream.SendDatagram(copiedDatagram))

	deadline := time.Now().Add(10 * time.Second)
	for len(server.payloads()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	received := server.payloads()
	require.Len(t, received, 2)
	// Order is preserved over a single stream, so the owned send arrives first.
	require.Equal(t, ownedExpected, received[0], "the owned path must frame the datagram identically")
	require.Equal(t, copiedDatagram, received[1])
	require.Equal(t, received[0], received[1],
		"both APIs must produce the same bytes on the wire")
}
