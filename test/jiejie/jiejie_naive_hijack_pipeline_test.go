package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// DETERMINISTIC REGRESSION TEST for the HTTP/1.1 hijack buffered-reader bug.
//
// net/http hijacks a connection and returns a *bufio.ReadWriter whose Reader may
// already hold bytes the server read past the request headers. A client that
// PIPELINES its prologue -- sends the CONNECT request and the tunnel bytes in one
// write, or fast enough that the server reads them together -- ends up with those
// tunnel bytes sitting in that buffer.
//
// The inbound previously discarded the reader (`conn, _, err := Hijack()`), so
// the tunnel started mid-stream: the UoT request header and the first datagram
// were lost, the server read garbage, and the session failed with a short-buffer
// or EOF error. klzgrad/forwardproxy handles this explicitly.
//
// This test is deterministic rather than probabilistic: the client writes the
// request and the tunnel frames in a SINGLE Write, which guarantees the server's
// bufio.Reader holds them. No sleep, no retry, no tolerance.

// TestJiejieHijackPipelinedUoTRequestIsNotLost is the primary regression test.
func TestJiejieHijackPipelinedUoTRequestIsNotLost(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(20*time.Second)))

	magic := uot.RequestDestination(uot.Version).String()
	addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr(env.echoAddr))
	require.NoError(t, err)

	payload := []byte("pipelined-first-datagram")
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))

	// ONE write: CONNECT + UoT v2 request header + first datagram.
	//
	// The prologue is sent UNFRAMED even though the CONNECT carries a Padding
	// header, because HTTP/1 is a raw tunnel in the reference: serveHijack ends
	// in dualStream(targetConn, clientConn, clientConn, false). What this test
	// checks is the hijack buffered-reader path - net/http reads past the request
	// headers, so these bytes are already sitting in the bufio.Reader when the
	// connection is hijacked, and dropping that reader loses them from the first
	// byte. Framing is irrelevant to that property, so the pipelined bytes are
	// raw and the reply is read raw.
	request := "CONNECT " + magic + " HTTP/1.1\r\n" +
		"Host: " + magic + "\r\n" +
		"Proxy-Authorization: " + naiveBasicAuth() + "\r\n" +
		"Padding: ~~~~~~~~\r\n\r\n"
	pipelined := append([]byte(request), append([]byte{1}, addressBytes...)...)
	pipelined = append(pipelined, append(length, payload...)...)

	_, err = tlsConn.Write(pipelined)
	require.NoError(t, err, "the pipelined write must succeed")

	reader := bufio.NewReader(tlsConn)

	// Read the CONNECT response.
	response, err := readHTTPResponseHead(reader)
	require.NoError(t, err)
	require.Equal(t, 200, response)

	// The datagram must come back. If the buffered bytes were dropped, the
	// server never sees the request header and this read fails or returns junk.
	// The tunnel is raw, so the reply is a UoT datagram: 2-byte length + payload.
	body := make([]byte, 2+len(payload))
	_, err = io.ReadFull(reader, body)
	require.NoError(t, err, "reading the reply failed")
	require.Equal(t, payload, body[2:],
		"the pipelined first datagram must round trip intact, proving the "+
			"buffered bytes were consumed rather than discarded")
}

// TestJiejieHijackPipelinedPlainConnectRequestIsNotLost covers the same bug on a
// plain (unpadded) tunnel: the prologue bytes are pipelined, so they are buffered.
func TestJiejieHijackPipelinedPlainConnectRequestIsNotLost(t *testing.T) {
	env := startNaiveInbound(t, false)
	origin := env.originAddr

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(env.port)), 10*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	require.NoError(t, tlsConn.Handshake())
	require.NoError(t, tlsConn.SetDeadline(time.Now().Add(20*time.Second)))

	// CONNECT and the proxied request in ONE write, unpadded so there is no
	// frame layer to hide the problem.
	request := "CONNECT " + origin + " HTTP/1.1\r\n" + "Host: " + origin + "\r\n" +
		"Proxy-Authorization: " + naiveBasicAuth() + "\r\n\r\n"
	proxied := "GET / HTTP/1.1\r\nHost: " + origin + "\r\nConnection: close\r\n\r\n"
	_, err = tlsConn.Write(append([]byte(request), []byte(proxied)...))
	require.NoError(t, err)

	reader := bufio.NewReader(tlsConn)
	status, err := readHTTPResponseHead(reader)
	require.NoError(t, err)
	require.Equal(t, 200, status)

	// The origin's response proves the pipelined request reached it.
	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Contains(t, string(body), "origin-ok",
		"the pipelined plain request must reach the origin, proving the buffered "+
			"bytes were not discarded")
}

// readHTTPResponseHead reads a status line plus headers and returns the status.
func readHTTPResponseHead(reader *bufio.Reader) (int, error) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	status := 0
	if len(statusLine) >= 12 {
		status, _ = strconv.Atoi(statusLine[9:12])
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return status, err
		}
		if line == "\r\n" {
			return status, nil
		}
	}
}

// readPaddingFrameGuarded decodes one padding frame without failing the test from
// inside a helper, so the caller can report the real error.
func readPaddingFrameGuarded(t *testing.T, reader *bufio.Reader) []byte {
	t.Helper()
	body, err := readPaddingFrameRaw2(reader)
	require.NoError(t, err, "reading the reply frame failed")
	return body
}
