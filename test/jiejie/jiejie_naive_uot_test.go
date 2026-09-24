package jiejie_test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/stretchr/testify/require"
)

// These tests exercise UoT (UDP over TCP) through the Naive inbound.
//
// The client side is hand-built rather than borrowed from sing-box's Naive
// outbound, so the wire format is asserted directly instead of proving only that
// sing-box can talk to itself. Addresses are serialised with sing's own
// SocksaddrSerializer, so the test speaks the real UoT format and not a private
// one:
//
//	UoT v2 (sp.v2.udp-over-tcp.arpa):
//	    isConnect(1) + addrport, then   len(2) + payload
//	UoT v1 (sp.udp-over-tcp.arpa):
//	    no request header, then         addrport + len(2) + payload
//
// The inbound is started with network=tcp, which is the production setting, to
// prove that a TCP-only listener still carries UoT.

// uotTestEnv is a running Naive inbound plus a reachable UDP echo backend.
type uotTestEnv struct {
	port     uint16
	echoAddr string
}

// startNaiveInboundForUoT starts a TCP-only Naive inbound and a loopback UDP echo
// server, and returns both.
func startNaiveInboundForUoT(t *testing.T) *uotTestEnv {
	t.Helper()
	requireFullNaiveRegistry(t)
	_, certPem, keyPem := createSelfSignedCertificate(t, "naive.test")
	port := reserveTCPPort(t)

	echoAddr := startUDPEchoServer(t)

	startInstance(t, option.Options{
		Inbounds: []option.Inbound{{
			Type: C.TypeNaive,
			Tag:  "naive-in",
			Options: &option.NaiveInboundOptions{
				ListenOptions: option.ListenOptions{Listen: minimalLoopback(), ListenPort: port},
				// TCP only. network controls the LISTENER and is not a UoT
				// switch, so UoT must still work on this inbound.
				Network: option.NetworkList("tcp"),
				Users: []auth.User{{
					Username: naiveTestUser,
					Password: naiveTestPassword,
				}},
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled: true, ServerName: "naive.test",
						CertificatePath: certPem, KeyPath: keyPem,
					},
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct"}},
		Route:     &option.RouteOptions{Final: "direct"},
	})
	return &uotTestEnv{port: port, echoAddr: echoAddr}
}

// startUDPEchoServer starts a UDP echo server on loopback and returns its address.
func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 64*1024)
		for {
			n, addr, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}

// uotSession is one open UoT tunnel.
type uotSession struct {
	conn    net.Conn
	reader  *bufio.Reader
	padding bool
	// version records which UoT protocol version this session speaks, so the
	// unpadded reader knows whether a v1 address prefix precedes the length.
	version uint8
}

// dialUoT opens an authenticated CONNECT to the UoT magic address for the given
// protocol version and writes the version-appropriate request header.
//
// udpTarget is the destination the client intends to reach. For v2 in connect
// mode it is carried in the request header; for v1 it is carried per datagram.
func dialUoT(t *testing.T, port uint16, version uint8, udpTarget string, usePadding bool) *uotSession {
	t.Helper()
	conn := naiveTLSConn(t, port)

	headers := map[string]string{"Proxy-Authorization": naiveBasicAuth()}
	if usePadding {
		headers["Padding"] = "~~~~~~~~"
	}
	magic := uot.RequestDestination(version).String()
	response := naiveWriteConnectOK(t, conn, magic, headers)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"an authenticated UoT CONNECT to %s must be accepted", magic)

	session := &uotSession{conn: conn, reader: bufio.NewReader(conn), padding: usePadding, version: version}

	if version == uot.Version {
		// UoT v2 connect mode: isConnect=1 followed by the destination.
		//
		// The v2 REQUEST header uses the SOCKS5 serializer, while per-datagram
		// addresses use uot.AddrParser. They are genuinely different encodings in
		// the same protocol, which is why they are encoded separately here.
		payload := []byte{1}
		addressBytes, err := encodeV2RequestAddr(t, metadata.ParseSocksaddr(udpTarget))
		require.NoError(t, err)
		payload = append(payload, addressBytes...)
		// The UoT v2 request header travels INSIDE the tunnel, so when padding
		// was negotiated it must itself be wrapped in a padding frame. Writing it
		// raw makes the server read the isConnect byte as a frame length.
		if usePadding {
			payload = naivePaddingFrame(payload, 0)
		}
		_, err = conn.Write(payload)
		require.NoError(t, err)
	}
	return session
}

// encodeSocksaddr serialises an address in the UoT wire format.
//
// UoT uses its OWN address parser (uot.AddrParser: 0x00=IPv4, 0x01=IPv6,
// 0x02=FQDN), NOT the global SOCKS5 serializer (0x01=IPv4, 0x04=IPv6,
// 0x03=FQDN). Using the SOCKS5 one makes the server report
// "unknown address family: 0", because 0x00 is not a SOCKS5 family.
func encodeSocksaddr(t *testing.T, addr metadata.Socksaddr) ([]byte, error) {
	t.Helper()
	return encodeUoTAddr(addr)
}

// encodeV2RequestAddr encodes the address in a UoT v2 REQUEST header, which uses
// the global SOCKS5 serializer (0x01=IPv4, 0x04=IPv6, 0x03=FQDN).
func encodeV2RequestAddr(t *testing.T, addr metadata.Socksaddr) ([]byte, error) {
	t.Helper()
	writer := &sliceWriter{}
	if err := metadata.SocksaddrSerializer.WriteAddrPort(writer, addr); err != nil {
		return nil, err
	}
	return writer.data, nil
}

// encodeUoTAddr encodes one address+port in the UoT per-datagram format.
func encodeUoTAddr(addr metadata.Socksaddr) ([]byte, error) {
	writer := &sliceWriter{}
	if err := uot.AddrParser.WriteAddrPort(writer, addr); err != nil {
		return nil, err
	}
	return writer.data, nil
}

// sliceWriter is a minimal io.Writer collecting into a byte slice.
type sliceWriter struct{ data []byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

// writeDatagram writes one UoT datagram. In v1 the destination is prefixed to
// every datagram; in v2 connect mode it is not.
func (s *uotSession) writeDatagram(t *testing.T, version uint8, destination string, payload []byte) {
	t.Helper()
	var body []byte
	if version == uot.LegacyVersion {
		addressBytes, err := encodeSocksaddr(t, metadata.ParseSocksaddr(destination))
		require.NoError(t, err)
		body = append(body, addressBytes...)
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	body = append(body, length...)
	body = append(body, payload...)

	if s.padding {
		body = naivePaddingFrame(body, 0)
	}
	_, err := s.conn.Write(body)
	require.NoError(t, err)
}

// readDatagram reads one UoT datagram payload, unwrapping the optional padding
// frame and the optional v1 address prefix.
//
// The decoding is done in exactly one place for each shape, because the padding
// frame and the UoT length prefix are two DIFFERENT framings that can both be
// present. Decoding both in two helpers double-strips the length.
func (s *uotSession) readDatagram(t *testing.T, version uint8) []byte {
	t.Helper()

	// Step 1: obtain the UoT body (address for v1, then the length-prefixed
	// payload). When padding is negotiated this arrives inside a padding frame.
	var body []byte
	if s.padding {
		body = naiveReadPaddingFrame(t, s.reader)
	} else {
		body = readRawUoTBody(t, s.reader, version)
	}

	// Step 2: strip the v1 per-datagram address, if present.
	if version == uot.LegacyVersion {
		reader := &sliceReader{data: body}
		_, err := uot.AddrParser.ReadAddrPort(reader)
		require.NoError(t, err)
		body = reader.remaining()
	}

	require.GreaterOrEqual(t, len(body), 2, "a UoT datagram must carry a 2-byte length prefix")
	size := int(binary.BigEndian.Uint16(body[:2]))
	require.Equal(t, len(body)-2, size,
		"the UoT datagram length prefix must match the payload length")
	return body[2:]
}

// readRawUoTBody reads one unpadded UoT body: an optional v1 address, then a
// 2-byte length and the payload, returning them concatenated so the shared
// decoder above sees one consistent shape.
func readRawUoTBody(t *testing.T, reader io.Reader, version uint8) []byte {
	t.Helper()
	var body []byte
	if version == uot.LegacyVersion {
		address, err := uot.AddrParser.ReadAddrPort(reader)
		require.NoError(t, err)
		addressBytes, err := encodeUoTAddr(address)
		require.NoError(t, err)
		body = append(body, addressBytes...)
	}
	length := make([]byte, 2)
	_, err := io.ReadFull(reader, length)
	require.NoError(t, err)
	payload := make([]byte, int(binary.BigEndian.Uint16(length)))
	_, err = io.ReadFull(reader, payload)
	require.NoError(t, err)
	return append(body, append(length, payload...)...)
}

// sliceReader reads from a byte slice.
type sliceReader struct {
	data []byte
	pos  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *sliceReader) remaining() []byte { return r.data[r.pos:] }

func (s *uotSession) Close() { _ = s.conn.Close() }

// ---------------------------------------------------------------------------
// UoT v2
// ---------------------------------------------------------------------------

// TestJiejieNaiveUoTV2RoundTrip proves a v2 session carries a datagram to the
// real UDP target and back.
func TestJiejieNaiveUoTV2RoundTrip(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	defer session.Close()

	payload := []byte("uot-v2-echo")
	session.writeDatagram(t, uot.Version, env.echoAddr, payload)
	require.Equal(t, payload, session.readDatagram(t, uot.Version),
		"the UDP echo must come back through the UoT tunnel")
}

// TestJiejieNaiveUoTV2MultipleDatagrams proves several datagrams flow in order on
// one session, including varied lengths.
func TestJiejieNaiveUoTV2MultipleDatagrams(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.Version, env.echoAddr, true)
	defer session.Close()

	for index, size := range []int{1, 2, 7, 64, 512, 1400} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte('a' + index)
		}
		session.writeDatagram(t, uot.Version, env.echoAddr, payload)
		require.Equal(t, payload, session.readDatagram(t, uot.Version),
			"datagram %d (len %d) must round trip", index, size)
	}
}

// TestJiejieNaiveUoTV2WithoutPadding proves UoT works on a tunnel that did not
// negotiate padding.
func TestJiejieNaiveUoTV2WithoutPadding(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.Version, env.echoAddr, false)
	defer session.Close()

	payload := []byte("uot-v2-unpadded")
	session.writeDatagram(t, uot.Version, env.echoAddr, payload)
	require.Equal(t, payload, session.readDatagram(t, uot.Version),
		"UoT must work without padding negotiation")
}

// ---------------------------------------------------------------------------
// UoT v1
// ---------------------------------------------------------------------------

// TestJiejieNaiveUoTV1RoundTrip proves a v1 session works, with the destination
// carried per datagram rather than in a request header.
func TestJiejieNaiveUoTV1RoundTrip(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.LegacyVersion, env.echoAddr, true)
	defer session.Close()

	payload := []byte("uot-v1-echo")
	session.writeDatagram(t, uot.LegacyVersion, env.echoAddr, payload)
	require.Equal(t, payload, session.readDatagram(t, uot.LegacyVersion),
		"a v1 datagram must round trip with its per-packet address")
}

// TestJiejieNaiveUoTV1MultipleDatagrams proves several v1 datagrams flow.
func TestJiejieNaiveUoTV1MultipleDatagrams(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	session := dialUoT(t, env.port, uot.LegacyVersion, env.echoAddr, true)
	defer session.Close()

	for index := range 5 {
		payload := []byte("v1-packet-" + strconv.Itoa(index))
		session.writeDatagram(t, uot.LegacyVersion, env.echoAddr, payload)
		require.Equal(t, payload, session.readDatagram(t, uot.LegacyVersion))
	}
}

// TestJiejieNaiveUoTVersionsAreDistinct proves the two versions are not
// interchangeable: they use different magic addresses and different framing.
// This is the regression guard against handling v1 with the v2 frame format.
func TestJiejieNaiveUoTVersionsAreDistinct(t *testing.T) {
	require.NotEqual(t, uot.MagicAddress, uot.LegacyMagicAddress)
	require.Equal(t, uot.MagicAddress, uot.RequestDestination(uot.Version).Fqdn)
	require.Equal(t, uot.LegacyMagicAddress, uot.RequestDestination(uot.LegacyVersion).Fqdn)
	require.NotEqual(t, uot.Version, uot.LegacyVersion)
}

// TestJiejieNaiveUoTV1MultipleTargets proves one v1 session can address several
// different UDP targets, which is the point of the per-datagram address.
func TestJiejieNaiveUoTV1MultipleTargets(t *testing.T) {
	env := startNaiveInboundForUoT(t)
	secondEcho := startUDPEchoServer(t)

	session := dialUoT(t, env.port, uot.LegacyVersion, env.echoAddr, true)
	defer session.Close()

	for _, target := range []string{env.echoAddr, secondEcho} {
		payload := []byte("to-" + target)
		session.writeDatagram(t, uot.LegacyVersion, target, payload)
		require.Equal(t, payload, session.readDatagram(t, uot.LegacyVersion),
			"a v1 session must reach %s", target)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestJiejieNaiveUoTV2ConcurrentSessions proves several UoT tunnels run at once.
func TestJiejieNaiveUoTV2ConcurrentSessions(t *testing.T) {
	env := startNaiveInboundForUoT(t)

	const concurrency = 6
	errs := make(chan error, concurrency)
	for index := range concurrency {
		go func() {
			errs <- runConcurrentUoTSession(env.port, env.echoAddr, index)
		}()
	}
	for range concurrency {
		require.NoError(t, <-errs, "each concurrent UoT session must complete")
	}
}

// runConcurrentUoTSession performs one full v2 UoT round trip without using
// testing.T, so it is safe to run in a goroutine.
func runConcurrentUoTSession(port uint16, echoAddr string, index int) error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "naive.test"})
	if err = tlsConn.Handshake(); err != nil {
		return err
	}
	if err = tlsConn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}

	magic := uot.RequestDestination(uot.Version).String()
	// The reader returned here MUST be reused for every subsequent read: it may
	// already hold tunnel bytes that arrived with or after the response headers,
	// and discarding it loses them.
	tunnelReader, err := writeConnectWithoutT(tlsConn, magic)
	if err != nil {
		return err
	}

	addressBytes, err := encodeV2RequestAddrForGoroutine(metadata.ParseSocksaddr(echoAddr))
	if err != nil {
		return err
	}
	// The v2 request header is sent inside the tunnel, so it needs a padding
	// frame when padding is negotiated.
	if _, err = tlsConn.Write(naivePaddingFrame(append([]byte{1}, addressBytes...), 0)); err != nil {
		return err
	}

	want := []byte("session-" + strconv.Itoa(index))
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(want)))
	frame := append(length, want...)
	if _, err = tlsConn.Write(naivePaddingFrame(frame, 0)); err != nil {
		return err
	}

	// The response arrives inside a padding frame. Its body is the UoT
	// datagram: a 2-byte length followed by the payload. (This session used
	// UoT v2 in connect mode, so there is no per-datagram address.)
	frameHeader := make([]byte, 3)
	if _, err = io.ReadFull(tunnelReader, frameHeader); err != nil {
		return err
	}
	frameDataSize := int(frameHeader[0])<<8 | int(frameHeader[1])
	framePaddingSize := int(frameHeader[2])
	frameData := make([]byte, frameDataSize)
	if _, err = io.ReadFull(tunnelReader, frameData); err != nil {
		return err
	}
	if framePaddingSize > 0 {
		if _, err = io.ReadFull(tunnelReader, make([]byte, framePaddingSize)); err != nil {
			return err
		}
	}
	if len(frameData) < 2 {
		return errors.New("short UoT datagram")
	}
	payloadSize := int(binary.BigEndian.Uint16(frameData[:2]))
	if payloadSize != len(frameData)-2 {
		return errors.New("UoT length prefix does not match the payload")
	}
	if got := frameData[2:]; string(got) != string(want) {
		return errors.New("payload mismatch: got " + string(got))
	}
	return nil
}

// writeConnectWithoutT sends an authenticated padded CONNECT without testing.T
// and returns the buffered reader that must be used for the tunnel.
//
// Returning the reader is not a convenience: http.ReadResponse reads through a
// bufio.Reader, which may buffer tunnel bytes beyond the response headers. If
// that reader were discarded, those bytes would be lost and every later read
// would stall until the deadline.
func writeConnectWithoutT(conn net.Conn, authority string) (*bufio.Reader, error) {
	request := "CONNECT " + authority + " HTTP/1.1\r\n" +
		"Host: " + authority + "\r\n" +
		"Proxy-Authorization: " + naiveBasicAuth() + "\r\n" +
		"Padding: ~~~~~~~~\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, errors.New("CONNECT refused with status " + strconv.Itoa(response.StatusCode))
	}
	// The response body of a CONNECT is the tunnel itself; do NOT close it here.
	return reader, nil
}

// encodeV2RequestAddrForGoroutine is encodeV2RequestAddr without testing.T.
func encodeV2RequestAddrForGoroutine(addr metadata.Socksaddr) ([]byte, error) {
	writer := &sliceWriter{}
	if err := metadata.SocksaddrSerializer.WriteAddrPort(writer, addr); err != nil {
		return nil, err
	}
	return writer.data, nil
}
