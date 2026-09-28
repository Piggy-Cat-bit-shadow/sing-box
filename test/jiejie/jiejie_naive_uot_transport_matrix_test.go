package jiejie_test

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// AUDIT: the Naive padding contract is TRANSPORT-DEPENDENT, and the two things
// that vary are independent:
//
//   - the Padding REQUEST HEADER, which any transport may carry and which the
//     response mirrors unconditionally;
//   - the padding PAYLOAD FRAMING, which the server enables only on HTTP/2 and
//     HTTP/3.
//
// This matrix pins all four combinations, because a single boolean cannot express
// them and conflating the two is what produced a false "UoT v2 non-connect is a
// P0 product bug" report. In that report the harness set padding=true on an
// HTTP/1 tunnel, framed a UoT request header HTTP/1 sends raw, and the server
// read the frame's length byte (0x08) as a SOCKS address family:
//
//	"unknown address family: 8"
//
// The product was correct. The test had written the wrong wire format.

// TestAuditUoTPaddingContractIsTransportDependent is the matrix.
func TestAuditUoTPaddingContractIsTransportDependent(t *testing.T) {
	t.Run("HTTP/1 with Padding header is a RAW tunnel", func(t *testing.T) {
		// The Padding header is present, and the payload is STILL raw: this is
		// the exact case that was mis-written before.
		env := startNaiveInboundForUoT(t)
		session := openUoTNonConnectOver(t, env.port, transportHTTP1, true)
		defer session.Close()

		require.False(t, session.padding,
			"HTTP/1 must never frame payloads, even with a Padding header")

		payload := []byte("h1-padded-header-raw-payload")
		session.writeNonConnectDatagram(t, env.echoAddr, payload)
		source, got := session.readNonConnectDatagram(t)
		require.Equal(t, payload, got)
		require.Equal(t, env.echoAddr, source)
	})

	t.Run("HTTP/1 without Padding header is a RAW tunnel", func(t *testing.T) {
		env := startNaiveInboundForUoT(t)
		session := openUoTNonConnectOver(t, env.port, transportHTTP1, false)
		defer session.Close()

		require.False(t, session.padding)

		payload := []byte("h1-unpadded-raw-payload")
		session.writeNonConnectDatagram(t, env.echoAddr, payload)
		source, got := session.readNonConnectDatagram(t)
		require.Equal(t, payload, got)
		require.Equal(t, env.echoAddr, source)
	})

	t.Run("HTTP/2 with Padding header is a FRAMED tunnel", func(t *testing.T) {
		env := startNaiveInboundForUoT(t)
		session := openUoTNonConnectOverH2(t, env.port, true)
		defer session.Close()

		require.True(t, session.padding,
			"HTTP/2 with a Padding header must frame payloads")

		payload := []byte("h2-padded-framed-payload")
		session.writeNonConnectDatagram(t, env.echoAddr, payload)
		source, got := session.readNonConnectDatagram(t)
		require.Equal(t, payload, got)
		require.Equal(t, env.echoAddr, source)
	})

	t.Run("HTTP/2 without Padding header is a RAW tunnel", func(t *testing.T) {
		env := startNaiveInboundForUoT(t)
		session := openUoTNonConnectOverH2(t, env.port, false)
		defer session.Close()

		require.False(t, session.padding,
			"HTTP/2 frames only when the request carried a Padding header")

		payload := []byte("h2-unpadded-raw-payload")
		session.writeNonConnectDatagram(t, env.echoAddr, payload)
		source, got := session.readNonConnectDatagram(t)
		require.Equal(t, payload, got)
		require.Equal(t, env.echoAddr, source)
	})
}

// TestNaiveFrameLengthByteLooksLikeAnAddressFamily pins the EXACT byte sequence
// behind the retracted "P0 product bug", so the diagnosis is asserted rather than
// narrated in a comment.
//
// A UoT v2 non-connect request header is 8 bytes (isConnect plus a 7-byte SOCKS5
// address for 0.0.0.0:0). Wrapping it in a Naive frame puts the frame's length low
// byte, 0x08, at offset 1 -- which is exactly where uot.ReadRequest reads the
// SOCKS address family. That is the whole mechanism of the false report.
func TestNaiveFrameLengthByteLooksLikeAnAddressFamily(t *testing.T) {
	addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr("0.0.0.0:0"))
	require.NoError(t, err)
	payload := append([]byte{0}, addressBytes...)
	require.Len(t, payload, 8, "isConnect(1) + SOCKS5 IPv4 addrport(7)")

	raw := payload
	framed := naivePaddingFrame(payload, 0)

	// Raw: byte 0 is isConnect, byte 1 is the SOCKS5 address type (1 = IPv4).
	require.Equal(t, byte(0), raw[0], "isConnect = 0")
	require.Equal(t, byte(1), raw[1], "ATYP = IPv4")

	// Framed: the frame header shifts everything right, and byte 1 becomes the
	// frame's length low byte.
	require.Equal(t, byte(0), framed[0], "frame length high byte")
	require.Equal(t, byte(8), framed[1], "frame length low byte -- read as the address family")
	require.Equal(t, byte(0), framed[2], "padding size")

	// The server reads raw[0] as isConnect and raw[1] as the family. Feeding it
	// the FRAMED bytes yields family 8, which is why it answered
	// "unknown address family: 8" -- with no product defect involved.
	require.NotEqual(t, raw[1], framed[1],
		"if these matched, the framing mistake would be invisible and this "+
			"retraction would have no mechanism to explain")
}

// TestUoTPaddingFramingIsDerivedNotDeclared pins the rule itself, so the
// derivation cannot be replaced by a caller-supplied boolean without failing.
//
// This is the guard against the class of bug above: it is a unit test of the
// contract, independent of any live tunnel.
func TestUoTPaddingFramingIsDerivedNotDeclared(t *testing.T) {
	cases := []struct {
		transport naiveTransport
		header    bool
		framed    bool
		why       string
	}{
		{transportHTTP1, false, false, "HTTP/1 is raw"},
		{transportHTTP1, true, false, "HTTP/1 is raw even with the Padding header: serveHijack passes a literal false"},
		{transportHTTP2, false, false, "HTTP/2 frames only when Padding was requested"},
		{transportHTTP2, true, true, "HTTP/2 with Padding is the framed case"},
		{transportHTTP3, false, false, "HTTP/3 frames only when Padding was requested"},
		{transportHTTP3, true, true, "HTTP/3 with Padding is the framed case"},
	}
	for _, c := range cases {
		require.Equal(t, c.framed, c.transport.framesPayload(c.header),
			"%s with header=%v: %s", c.transport, c.header, c.why)
	}
}

// openUoTNonConnectOverH2 opens a v2 non-connect session on its own HTTP/2
// stream, where the Padding header DOES enable framing.
func openUoTNonConnectOverH2(t *testing.T, port uint16, requestPaddingHeader bool) *uotSession {
	t.Helper()

	conn := naiveTLSConn(t, port, http2.NextProtoTLS)
	clientConn, err := (&http2.Transport{}).NewClientConn(conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	pipeReader, pipeWriter := io.Pipe()
	magic := uot.RequestDestination(uot.Version).String()
	headers := http.Header{"Proxy-Authorization": []string{naiveBasicAuth()}}
	if requestPaddingHeader {
		headers.Set("Padding", "~~~~~~~~")
	}
	response, err := clientConn.RoundTrip(&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: magic},
		Host:   magic,
		Header: headers,
		Body:   pipeReader,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	require.Equal(t, http.StatusOK, response.StatusCode)

	// One net.Conn-shaped object presents the stream: writes go to the request
	// pipe, reads come from the response body. The session is then built on it
	// with the real transport, so newUoTSession derives the framing exactly as it
	// does for HTTP/1.
	stream := &h2UoTSessionConn{writer: pipeWriter, reader: response.Body}
	session := newUoTSession(stream, naiveTransportForH2(response), requestPaddingHeader, uot.Version)

	addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr("0.0.0.0:0"))
	require.NoError(t, err)
	_, err = session.writeFrame(append([]byte{0}, addressBytes...))
	require.NoError(t, err)
	return session
}

// naiveTransportForH2 reports the transport an extended-CONNECT response was
// served over. It exists so the H2 helper cannot silently disagree with the
// transport it is actually using.
func naiveTransportForH2(response *http.Response) naiveTransport {
	if response.ProtoMajor == 2 {
		return transportHTTP2
	}
	return transportHTTP1
}

// h2UoTSessionConn adapts an HTTP/2 stream's two halves to net.Conn so the UoT
// helpers can drive it. Writes go to the request pipe, reads to the response.
type h2UoTSessionConn struct {
	writer io.Writer
	reader io.Reader
}

func (c *h2UoTSessionConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *h2UoTSessionConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *h2UoTSessionConn) Close() error                { return nil }

func (c *h2UoTSessionConn) LocalAddr() net.Addr              { return nil }
func (c *h2UoTSessionConn) RemoteAddr() net.Addr             { return nil }
func (c *h2UoTSessionConn) SetDeadline(time.Time) error      { return nil }
func (c *h2UoTSessionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *h2UoTSessionConn) SetWriteDeadline(time.Time) error { return nil }
