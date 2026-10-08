package sniff

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	"github.com/stretchr/testify/require"
)

// tlsGateCaptureClientHello builds a real ClientHello for the cases below, so the accept corpus is
// the bytes a browser sends rather than a hand-written approximation.
func tlsGateCaptureClientHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	conn := &tlsGateCaptureConn{}
	client := tls.Client(conn, config)
	_ = client.Handshake()
	hello := conn.written.Bytes()
	if len(hello) == 0 || hello[0] != 0x16 {
		t.Fatal("failed to capture a TLS ClientHello")
	}
	return hello
}

type tlsGateCaptureConn struct {
	written bytes.Buffer
}

func (c *tlsGateCaptureConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *tlsGateCaptureConn) Write(p []byte) (int, error) { return c.written.Write(p) }
func (c *tlsGateCaptureConn) Close() error                { return nil }
func (c *tlsGateCaptureConn) LocalAddr() net.Addr         { return nil }
func (c *tlsGateCaptureConn) RemoteAddr() net.Addr        { return nil }
func (c *tlsGateCaptureConn) SetDeadline(time.Time) error { return nil }
func (c *tlsGateCaptureConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *tlsGateCaptureConn) SetWriteDeadline(time.Time) error { return nil }

// TestTLSFirstRecordGateRejectsOnlyWhatCryptoTLSRejects is the invariant the gate is allowed to
// exist under: GateRejects(x) => the parser returns a definite rejection for x.
//
// It is stated this way round, and not as "accepted payloads pass the gate", because the dangerous
// mistake is in the other direction. A gate that rejects a payload the parser would have asked for
// more bytes for does not merely cost a parse: it turns ErrNeedMoreData into a verdict, PeekStream
// stops reading, and a fragmented ClientHello is classified as unknown. So every header the gate
// rejects is handed to crypto/tls itself here and must come back rejected rather than incomplete.
func TestTLSFirstRecordGateRejectsOnlyWhatCryptoTLSRejects(t *testing.T) {
	t.Parallel()
	versions := []uint16{
		0x0000, 0x0001, 0x0002, 0x00FF, 0x0100, 0x02FF,
		0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305, 0x03FF,
		0x0400, 0x0FFF, 0x1000, 0x1001, 0x7FFF, 0x8000, 0xFFFF,
	}
	checked := 0
	for typeValue := 0; typeValue < 256; typeValue++ {
		for _, version := range versions {
			header := []byte{byte(typeValue), byte(version >> 8), byte(version), 0x00, 0x04}
			if !tlsFirstRecordRejected(header) {
				continue
			}
			checked++
			payload := append(append([]byte{}, header...), 0x00, 0x00, 0x00, 0x00)
			err := tls.Server(
				bufio.NewReadOnlyConn(bytes.NewReader(payload)),
				&tls.Config{},
			).HandshakeContext(context.Background())
			require.Error(t, err, "header % x", header)
			require.False(t, errors.Is(err, io.ErrUnexpectedEOF),
				"the gate rejected header % x but crypto/tls only wanted more bytes", header)
		}
	}
	// A gate that rejected nothing would pass the loop above vacuously.
	require.Greater(t, checked, 256*10)
}

// TestTLSFirstRecordGateNeverDecidesOnAPartialHeader is the length rule, stated over every prefix
// length rather than over a sample: a header that is not complete proves nothing, because
// crypto/tls would be waiting for the rest of it.
func TestTLSFirstRecordGateNeverDecidesOnAPartialHeader(t *testing.T) {
	t.Parallel()
	headers := [][]byte{
		{0x16, 0x03, 0x01, 0x00, 0x2e},
		{0x00, 0x00, 0x00, 0x00, 0x00},
		{0x47, 0x45, 0x54, 0x20, 0x2f},
		{0x80, 0x2e, 0x01, 0x03, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
	}
	for _, header := range headers {
		for length := 0; length < len(header); length++ {
			require.False(t, tlsFirstRecordRejected(header[:length]),
				"header % x decided on a %d byte prefix", header, length)
		}
	}
	// The same headers, complete, are where a decision becomes possible at all: two of them are
	// rejections and one of them is not.
	require.True(t, tlsFirstRecordRejected(headers[1]))
	require.True(t, tlsFirstRecordRejected(headers[2]))
	require.True(t, tlsFirstRecordRejected(headers[3]))
	require.True(t, tlsFirstRecordRejected(headers[4]))
	require.False(t, tlsFirstRecordRejected(headers[0]))
}

// TestTLSClientHelloStillAsksForMoreDataOnShortPrefixes is ParserNeedsMoreData(x) => GateAllows(x)
// checked through the parser the gate lives in, which is the only place it can be checked for real:
// the prefixes below are the starts of a genuine ClientHello, and every one of them is too short to
// decide anything, so every one of them has to keep asking for more data.
func TestTLSClientHelloStillAsksForMoreDataOnShortPrefixes(t *testing.T) {
	t.Parallel()
	hello := tlsGateCaptureClientHello(t, &tls.Config{ServerName: "www.example.com"})
	for length := 1; length < tlsRecordHeaderSize; length++ {
		var metadata adapter.InboundContext
		err := TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello[:length]))
		require.ErrorIs(t, err, ErrNeedMoreData, "prefix of %d bytes", length)
		require.Empty(t, metadata.Protocol, "prefix of %d bytes", length)
	}
	// A complete header with an incomplete body is the same situation one step later.
	var metadata adapter.InboundContext
	err := TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello[:tlsRecordHeaderSize]))
	require.ErrorIs(t, err, ErrNeedMoreData)
	require.Empty(t, metadata.Protocol)
}

// TestTLSClientHelloGateKeepsTheParsersOwnError pins the diagnostic side of the gate. A payload
// turned away by the gate has to be described the way crypto/tls described it before the gate
// existed, down to the error type and the header bytes it carries, because metadata.SniffError is
// what an operator reads when a flow is classified wrongly.
func TestTLSClientHelloGateKeepsTheParsersOwnError(t *testing.T) {
	t.Parallel()
	payload := []byte("GET / HTTP/1.1\r\nHost: not-tls.example.com\r\n\r\n")
	var metadata adapter.InboundContext
	err := TLSClientHello(context.Background(), &metadata, bytes.NewReader(payload))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNeedMoreData)
	require.Equal(t, "tls: first record does not look like a TLS handshake", err.Error())
	var recordHeaderError tls.RecordHeaderError
	require.ErrorAs(t, err, &recordHeaderError)
	require.Equal(t, [tlsRecordHeaderSize]byte{'G', 'E', 'T', ' ', '/'}, recordHeaderError.RecordHeader)
}

// TestTLSClientHelloGateAllowsEveryAcceptedClientHello is the accept-corpus direction: whatever the
// parser used to recognise, it still recognises. A gate that rejected one of these would show up as
// a missing protocol or a missing domain rather than as an error.
func TestTLSClientHelloGateAllowsEveryAcceptedClientHello(t *testing.T) {
	t.Parallel()
	corpus := map[string]*tls.Config{
		"with-sni":            {ServerName: "www.example.com"},
		"no-sni":              {InsecureSkipVerify: true},
		"tls12-max":           {ServerName: "tls12.example.com", MaxVersion: tls.VersionTLS12},
		"tls13-max":           {ServerName: "tls13.example.com", MaxVersion: tls.VersionTLS13},
		"with-session-ticket": {ServerName: "ticket.example.com", ClientSessionCache: tls.NewLRUClientSessionCache(4)},
		"no-key-share":        {ServerName: "nokey.example.com", CurvePreferences: []tls.CurveID{tls.CurveP384}},
	}
	for name, config := range corpus {
		t.Run(name, func(t *testing.T) {
			hello := tlsGateCaptureClientHello(t, config)
			var metadata adapter.InboundContext
			require.NoError(t, TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello)))
			require.Equal(t, C.ProtocolTLS, metadata.Protocol)
			require.Equal(t, config.ServerName, metadata.Domain)
		})
	}
}
