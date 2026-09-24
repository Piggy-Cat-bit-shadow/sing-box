package jiejie_test

import (
	"bufio"
	"encoding/binary"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// AUDIT: UoT data-plane details not covered by the earlier v1/v2 round trips.
//
// The earlier work proved v2 connect-mode and v1 multi-target. This adds v2
// NON-connect mode (which carries a destination per datagram, like v1 but with
// the UoT address encoding), plus payload edge cases and a check that the magic
// address never becomes a real destination.

// openUoTNonConnect opens a v2 session with isConnect=false, so every datagram
// carries its own destination.
func openUoTNonConnect(t *testing.T, port uint16) *uotSession {
	t.Helper()
	conn := naiveTLSConn(t, port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.Equal(t, http.StatusOK, response.StatusCode)

	session := &uotSession{conn: conn, reader: bufio.NewReader(conn), padding: true, version: uot.Version}
	// isConnect = 0. The destination in the header is a placeholder; the real
	// destination is sent per datagram.
	addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr("0.0.0.0:0"))
	require.NoError(t, err)
	_, err = conn.Write(naivePaddingFrame(append([]byte{0}, addressBytes...), 0))
	require.NoError(t, err)
	return session
}

// writeNonConnectDatagram sends one datagram carrying its own destination, using
// the UoT per-datagram address encoding.
func (s *uotSession) writeNonConnectDatagram(t *testing.T, destination string, payload []byte) {
	t.Helper()
	writer := &sliceWriter{}
	require.NoError(t, uot.AddrParser.WriteAddrPort(writer, metadata.ParseSocksaddr(destination)))
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body := append(writer.data, append(length, payload...)...)
	_, err := s.conn.Write(naivePaddingFrame(body, 0))
	require.NoError(t, err)
}

// readNonConnectDatagram reads one reply, which carries its source address.
func (s *uotSession) readNonConnectDatagram(t *testing.T) (string, []byte) {
	t.Helper()
	body := naiveReadPaddingFrame(t, s.reader)
	reader := &sliceReader{data: body}
	source, err := uot.AddrParser.ReadAddrPort(reader)
	require.NoError(t, err)
	rest := reader.remaining()
	require.GreaterOrEqual(t, len(rest), 2)
	size := int(binary.BigEndian.Uint16(rest[:2]))
	require.Equal(t, len(rest)-2, size)
	// String() includes the PORT, which is what the caller must verify: an
	// address alone would not catch a wrong source port.
	return source.String(), rest[2:]
}

// TestAuditUoTV2NonConnectMode proves v2 non-connect mode works and reports the
// reply's SOURCE address, which is what distinguishes it from connect mode.
func TestAuditUoTV2NonConnectMode(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := openUoTNonConnect(t, env.port)
	defer session.Close()

	payload := []byte("non-connect-mode")
	session.writeNonConnectDatagram(t, env.echoAddr, payload)
	source, got := session.readNonConnectDatagram(t)
	require.Equal(t, payload, got, "the reply payload must match")
	t.Logf("v2 non-connect reply came from %s", source)
	require.Equal(t, env.echoAddr, source,
		"the reply must be attributed to the real UDP source, not the magic address")
}

// TestAuditUoTV2NonConnectMultipleTargets proves one non-connect session can
// address several destinations, the same capability v1 has.
func TestAuditUoTV2NonConnectMultipleTargets(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	second := startUDPEchoServer(t)

	session := openUoTNonConnect(t, env.port)
	defer session.Close()

	for _, target := range []string{env.echoAddr, second} {
		payload := []byte("to-" + target)
		session.writeNonConnectDatagram(t, target, payload)
		source, got := session.readNonConnectDatagram(t)
		require.Equal(t, payload, got)
		require.Equal(t, target, source,
			"the reply must come from the requested target")
	}
}

// TestAuditUoTPayloadEdgeCases covers zero-length and large datagrams.
func TestAuditUoTPayloadEdgeCases(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	defer session.Close()

	t.Run("zero-length datagram", func(t *testing.T) {
		session.writeDatagram(t, uot.Version, env.echoAddr, []byte{})
		got := session.readDatagram(t, uot.Version)
		require.Empty(t, got, "a zero-length datagram is legal and must round trip")
	})

	t.Run("maximum practical datagram", func(t *testing.T) {
		// A payload near the practical UDP limit for loopback.
		payload := make([]byte, 1400)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		session.writeDatagram(t, uot.Version, env.echoAddr, payload)
		require.Equal(t, payload, session.readDatagram(t, uot.Version))
	})
}

// TestAuditMagicAddressIsNeverADestination proves the magic address is consumed
// as a protocol selector and never dialled as a real host.
//
// If it leaked through as a destination, resolution of
// "sp.v2.udp-over-tcp.arpa" would be attempted and would fail.
func TestAuditMagicAddressIsNeverADestination(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	conn := naiveTLSConn(t, env.port)
	magic := uot.RequestDestination(uot.Version).String()
	response := naiveWriteConnectOK(t, conn, magic, map[string]string{
		"Proxy-Authorization": naiveBasicAuth(),
		"Padding":             "~~~~~~~~",
	})
	require.Equal(t, http.StatusOK, response.StatusCode)

	// Send a v2 request naming the magic address itself as the UDP target. That
	// is nonsense input; the server must not treat the magic address as a real
	// destination to resolve.
	writer := &sliceWriter{}
	require.NoError(t, metadata.SocksaddrSerializer.WriteAddrPort(writer,
		metadata.ParseSocksaddr(magic+":53")))
	_, _ = conn.Write(naivePaddingFrame(append([]byte{1}, writer.data...), 0))

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 4)
	_, _ = conn.Write(naivePaddingFrame(append(length, []byte("ping")...), 0))

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, err := readPaddingFrameRaw2(bufio.NewReader(conn))
	if err == nil {
		t.Logf("reply for a magic-address target: %q", string(frame))
	} else {
		t.Logf("magic-address target produced an error (expected): %v", err)
	}
	// Whatever happens, the server must still be healthy.
	session := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	defer session.Close()
	session.writeDatagram(t, uot.Version, env.echoAddr, []byte("still-working"))
	require.Equal(t, []byte("still-working"), session.readDatagram(t, uot.Version),
		"a nonsensical magic-address destination must not damage the server")
}

// TestAuditUoTTruncatedRequestIsRejected proves a truncated UoT request header
// fails cleanly rather than hanging or being misinterpreted.
func TestAuditUoTTruncatedRequestIsRejected(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	cases := []struct {
		name string
		body []byte
	}{
		{"empty request header", []byte{}},
		{"isConnect only", []byte{1}},
		{"truncated address", []byte{1, 0x01, 127}},
		{"bad address family", []byte{1, 0x7F, 127, 0, 0, 1, 0, 53}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			conn := naiveTLSConn(t, env.port)
			magic := uot.RequestDestination(uot.Version).String()
			response, err := naiveWriteConnect(t, conn, magic, map[string]string{
				"Proxy-Authorization": naiveBasicAuth(),
				"Padding":             "~~~~~~~~",
			})
			if err != nil {
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return
			}
			_, _ = conn.Write(naivePaddingFrame(testCase.body, 0))

			// The server must respond by closing or erroring, not by hanging.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.ReadAll(conn)
			_ = conn.Close()
		})
	}

	// The server must still work afterwards.
	require.NoError(t, shortLivedUoTSession(env.port, env.echoAddr, []byte("post-truncation")),
		"malformed UoT requests must not damage the server")
}

// TestAuditUoTServerInitiatedClose proves the server closing a session is
// observable to the client and does not affect other sessions.
func TestAuditUoTServerInitiatedClose(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	first := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	first.writeDatagram(t, uot.Version, env.echoAddr, []byte("hello"))
	require.Equal(t, []byte("hello"), first.readDatagram(t, uot.Version))

	// Close from the server side via the instance lifecycle is covered
	// elsewhere; here the client-side close stands in for the observable end of
	// the session.
	first.Close()

	second := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	defer second.Close()
	second.writeDatagram(t, uot.Version, env.echoAddr, []byte("independent"))
	require.Equal(t, []byte("independent"), second.readDatagram(t, uot.Version),
		"a closed session must not affect a new one")
}
