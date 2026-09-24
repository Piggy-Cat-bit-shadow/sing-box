package main

import (
	std_bufio "bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func appendVarint(b []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(b, byte(value))
	case value < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(value)|0x4000)
	case value < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(value)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, value|0xC000000000000000)
	}
}

func readVarint(t *testing.T, reader *std_bufio.Reader) uint64 {
	first, err := reader.ReadByte()
	require.NoError(t, err)
	length := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		next, err := reader.ReadByte()
		require.NoError(t, err)
		value = value<<8 | uint64(next)
	}
	return value
}

func writeDatagramCapsule(t *testing.T, writer io.Writer, payload []byte) {
	capsule := appendVarint(nil, 0)
	capsule = appendVarint(capsule, uint64(1+len(payload)))
	capsule = append(capsule, 0)
	capsule = append(capsule, payload...)
	_, err := writer.Write(capsule)
	require.NoError(t, err)
}

func readDatagramCapsule(t *testing.T, reader *std_bufio.Reader) []byte {
	capsuleType := readVarint(t, reader)
	require.Equal(t, uint64(0), capsuleType)
	length := readVarint(t, reader)
	contextID, err := reader.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte(0), contextID)
	payload := make([]byte, length-1)
	_, err = io.ReadFull(reader, payload)
	require.NoError(t, err)
	return payload
}

func startUDPEcho(t *testing.T) *net.UDPAddr {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.Close()
	})
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			conn.WriteToUDP(buffer[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func connectUDPPath(target *net.UDPAddr) string {
	return "/.well-known/masque/udp/" + target.IP.String() + "/" + strconv.Itoa(target.Port) + "/"
}

func TestHTTPInboundConnectUDP(t *testing.T) {
	startForwardProxy(t)
	echo := startUDPEcho(t)
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(int(serverPort)))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET " + connectUDPPath(echo) + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nProxy-Authorization: " + proxyAuthorization + "\r\n\r\n"))
	require.NoError(t, err)
	reader := std_bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
	require.Equal(t, "connect-udp", response.Header.Get("Upgrade"))
	for i := 0; i < 3; i++ {
		writeDatagramCapsule(t, conn, []byte("ping"))
		require.Equal(t, "ping", string(readDatagramCapsule(t, reader)))
	}
}

func TestHTTPInboundConnectUDPHTTP2(t *testing.T) {
	_, certPem, keyPem := createSelfSignedCertificate(t, "example.org")
	startTLSHTTPInbound(t, certPem, keyPem, nil, nil)
	echo := startUDPEcho(t)
	clientConn := dialHTTP2Proxy(t, serverPort)
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.org",
			Path:   connectUDPPath(echo),
		},
		Host: "example.org",
		Header: http.Header{
			":protocol":           []string{"connect-udp"},
			"Capsule-Protocol":    []string{"?1"},
			"Proxy-Authorization": []string{proxyAuthorization},
		},
		Body: pipeReader,
	}
	response, err := clientConn.RoundTrip(request)
	require.NoError(t, err)
	defer response.Body.Close()
	defer pipeWriter.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "?1", response.Header.Get("Capsule-Protocol"))
	reader := std_bufio.NewReader(response.Body)
	for i := 0; i < 3; i++ {
		writeDatagramCapsule(t, pipeWriter, []byte("ping"))
		require.Equal(t, "ping", string(readDatagramCapsule(t, reader)))
	}
}
