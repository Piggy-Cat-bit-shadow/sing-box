package tf_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"

	"github.com/stretchr/testify/require"
)

// The fragmentation tests.
//
// # Why these no longer dial 1.1.1.1
//
// The three tests that used to live here opened a TCP connection to 1.1.1.1:443 and asserted only
// that the handshake completed. That made the default suite red on every machine without outbound
// network - every build sandbox and every air-gapped CI runner - for a reason that has nothing to do
// with the code under test, and it made the result depend on a third party this repository does not
// control. More quietly, it also proved less than it looked like it did: a completed handshake shows
// that SOMETHING arrived that a TLS server could parse, but not that the ServerName was actually
// fragmented, because the unfragmented ClientHello handshakes just as well.
//
// These tests replace it with a real crypto/tls server and an observation point on the client's
// write path, so the DEFAULT suite proves the fragmentation structure itself: how many pieces the
// ClientHello leaves in, where the pieces are cut, that every piece is an independently well-formed
// TLS record, and that the pieces concatenate back to the exact ClientHello bytes - all of it
// checked by a cryptographic state machine rather than by a fixture. The internet check is kept,
// unweakened, in integration_test.go behind the `tlsfragment_integration` build tag.
//
// # What the deterministic half proves, precisely
//
// For each switch combination:
//
//   - the wrapper's Write calls on the connection below it are exactly the expected number, so
//     "splitPacket did something" is a count and not an inference from a completed handshake;
//   - record mode emits MORE THAN ONE independently framed record, each with a self-consistent
//     5-byte header, so the record layer really was rewritten rather than copied;
//   - the pieces, with the record headers removed where record mode added them, reconstruct the
//     ClientHello byte for byte - no byte dropped, duplicated or reordered;
//   - the reassembled ClientHello still parses, still names the SNI under test, and the cut falls
//     inside the FIRST label of that name, which is where the implementation chooses it;
//   - a real crypto/tls server completes a handshake over the pieces, so the rewrite is
//     interoperable and not merely self-consistent.

// testServerName is the SNI the fragmented ClientHello carries.
//
// It is deliberately a multi-label name under a known public suffix. The wrapper strips the public
// suffix and then picks one cut position per label that remains; under a known suffix only the
// leading label remains, so "www" is the entire range the cut can land in, which is what the
// boundary assertions below range over.
const testServerName = "www.cloudflare.com"

// The record layer's own constants, repeated here rather than imported so that a change to the
// implementation's constants cannot silently change what the test considers a well-formed record.
const (
	recordHeaderLen       = 5
	handshakeContentType  = 0x16
	recordVersionMajor    = 0x03
	recordVersionMinorMin = 0x01
	recordVersionMinorMax = 0x03
)

// fragmentMode is one configuration of the wrapper's two switches, together with the shape the
// ClientHello must leave in for it.
type fragmentMode struct {
	name        string
	splitPacket bool
	splitRecord bool

	// writes is how many times the wrapper may call Write on the connection below it.
	//
	// splitRecord alone rewrites the record layer in place and can hand the whole flight over in a
	// single call; splitPacket is what forces the pieces out separately, because each piece has to
	// reach the wire before the next one is written.
	writes int
	// pieces is how many independently framed records the ClientHello must be split into.
	//
	// In record mode that count is visible in the record layer of a single write; otherwise each
	// piece is its own write.
	pieces int
	// fragments reports whether this mode is expected to fragment at all. It exists so the control
	// can share the analysis code while being asserted in the opposite direction.
	fragments bool
}

var allFragmentModes = []fragmentMode{
	{name: "off", splitPacket: false, splitRecord: false, writes: 1, pieces: 1, fragments: false},
	{name: "packet", splitPacket: true, splitRecord: false, writes: 2, pieces: 2, fragments: true},
	{name: "record", splitPacket: false, splitRecord: true, writes: 1, pieces: 2, fragments: true},
	{name: "packet+record", splitPacket: true, splitRecord: true, writes: 2, pieces: 2, fragments: true},
}

// observation is what one handshake left behind: the raw writes the wrapper issued, and the logical
// pieces those writes encode. The logical view strips the record layer when record mode rewrote it,
// so the same concatenation assertion holds for every mode.
type observation struct {
	writes  [][]byte
	pieces  [][]byte
	headers [][]byte
}

// recordingConn is the observation point on the write path.
//
// It must NOT be a type that N.UnwrapReader can walk to a *net.TCPConn, or the wrapper would take
// its acknowledgement-waiting branch and the write boundaries would stop being something this test
// can name. It deliberately implements only net.Conn, so conn.go finds no TCP connection and takes
// its documented fallback: one Write per fragment, separated by the fallback delay. That write
// boundary is exactly the boundary being asserted.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) recorded() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

// localTLSConfig generates a throwaway ECDSA certificate for the loopback server and a client that
// accepts it.
//
// The server needs a certificate or it cannot complete a handshake, and generating one here keeps
// the test independent of the network and of a checked-in key that would expire. The client skips
// verification because the certificate's only job is to let crypto/tls run its state machine: what
// is being tested is whether the pieces reassemble into a ClientHello the SERVER accepts, and that
// verdict does not depend on the client's opinion of the certificate.
func localTLSConfig(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testServerName},
		DNSNames:     []string{testServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	// The minimum version is pinned so the record header's legacy version is stable across Go
	// releases: the fragmentation only ever runs on the first flight, and a ClientHello whose shape
	// changed with the toolchain would turn these assertions into a Go-version test.
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		&tls.Config{ServerName: testServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

// fragmentedClientHello performs one TLS handshake with the given switches against a real crypto/tls
// server over net.Pipe, and returns the writes and the logical pieces the wrapper produced.
//
// It returns only after the server has completed its half, so the bytes the analysis sees are
// exactly the bytes a real TLS server accepted. The fallback delay is deliberately small: it is the
// pause the wrapper inserts between pieces when it cannot wait for a TCP acknowledgement, and the
// test only needs it to exist, not to be long.
func fragmentedClientHello(t *testing.T, mode fragmentMode) observation {
	t.Helper()
	serverConfig, clientConfig := localTLSConfig(t)

	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})
	recorder := &recordingConn{Conn: clientSide}

	serverDone := make(chan error, 1)
	go func() {
		// The raw sides are closed by the cleanup rather than through tls.Conn.Close: net.Pipe is
		// synchronous, so two peers each sending close_notify would block on each other's write and
		// deadlock the test. The handshake is what is being asserted; the alert exchange is not.
		serverDone <- tls.Server(serverSide, serverConfig).Handshake()
	}()

	clientConn := tls.Client(
		tf.NewConn(recorder, context.Background(), mode.splitPacket, mode.splitRecord, time.Millisecond),
		clientConfig,
	)
	require.NoError(t, clientConn.Handshake())
	require.NoError(t, <-serverDone, "the local TLS server must accept the fragmented ClientHello")
	return observe(t, mode, recorder.recorded())
}

// prefixWrites returns the leading writes that together carry the first n bytes, truncating the last
// one when n ends inside it, and reports whether n landed exactly on a write boundary.
//
// The boundary matters: the first flight is a whole number of records, so an implementation that cut
// the ClientHello in the middle of a write it had already decided to make would be leaving the
// remainder of that write to be written later, which is not fragmentation of the flight but a
// stall. Every mode here ends the flight on a boundary, and this is what says so.
func prefixWrites(writes [][]byte, n int) (prefix [][]byte, exact bool) {
	consumed := 0
	for _, write := range writes {
		if consumed >= n {
			break
		}
		take := len(write)
		if take > n-consumed {
			take = n - consumed
		}
		prefix = append(prefix, write[:take])
		consumed += take
	}
	return prefix, consumed == n
}

// observe turns the raw writes into the logical pieces the fragmentation was meant to produce.
//
// It must first find the end of the ClientHello, because the recorder sees the whole connection, not
// just the first flight: crypto/tls writes ChangeCipherSpec and its Finished through the same wrapper
// once the handshake proceeds, and those writes must not be counted as fragments of a ClientHello
// they have nothing to do with. The first flight ends where the implementation's own framing says it
// does. Without record mode the first write starts with the record header, whose declared length is
// the length of the one ClientHello record. With record mode the flight is the run of handshake
// records at the head of the stream, and the first record of the next flight has a different content
// type.
//
// Then: without record mode a piece is a write. With record mode the pieces are the RECORDS inside the
// stream - one write may carry several - and each record must be independently well formed before it
// is accepted as a piece. That parse is where "the record header was rewritten, not copied" becomes a
// check rather than a claim.
func observe(t *testing.T, mode fragmentMode, writes [][]byte) observation {
	t.Helper()
	require.NotEmpty(t, writes, "the handshake must have written the ClientHello")
	if !mode.splitRecord {
		require.GreaterOrEqual(t, len(writes[0]), recordHeaderLen, "the first write must carry a record header")
		require.Equal(t, byte(handshakeContentType), writes[0][0], "the first flight must start with a handshake record")
		flightLen := recordHeaderLen + int(binary.BigEndian.Uint16(writes[0][3:5]))
		pieces, exact := prefixWrites(writes, flightLen)
		require.True(t, exact, "the ClientHello must end on a write boundary")
		return observation{writes: pieces, pieces: pieces}
	}

	stream := bytes.Join(writes, nil)
	var pieces, headers [][]byte
	offset := 0
	for offset < len(stream) {
		require.GreaterOrEqual(t, len(stream)-offset, recordHeaderLen,
			"a record header must be fully present at offset %d", offset)
		header := stream[offset : offset+recordHeaderLen]
		if header[0] != handshakeContentType {
			// The first flight is over; what follows is the post-handshake flight the wrapper does
			// not touch.
			break
		}
		require.Equal(t, byte(recordVersionMajor), header[1],
			"the record version must be preserved at offset %d", offset)
		require.GreaterOrEqual(t, header[2], byte(recordVersionMinorMin),
			"the record version must be preserved at offset %d", offset)
		require.LessOrEqual(t, header[2], byte(recordVersionMinorMax),
			"the record version must be preserved at offset %d", offset)
		payloadLen := int(binary.BigEndian.Uint16(header[3:5]))
		require.LessOrEqual(t, offset+recordHeaderLen+payloadLen, len(stream),
			"the declared record length must fit the stream at offset %d", offset)
		pieces = append(pieces, stream[offset+recordHeaderLen:offset+recordHeaderLen+payloadLen])
		headers = append(headers, header)
		offset += recordHeaderLen + payloadLen
	}
	flightWrites, exact := prefixWrites(writes, offset)
	require.True(t, exact, "the ClientHello must end on a write boundary")
	return observation{writes: flightWrites, pieces: pieces, headers: headers}
}

// reassembled reconstructs the single ClientHello the pieces encode, so the SNI index can be read in
// the coordinate system the pieces were cut in.
//
// In record mode the pieces are handshake bodies and the original record header has to be rebuilt
// around them: its content type and version are the ones the wrapper preserved, and its length is
// the length of the concatenated bodies. Without record mode the pieces already are the ClientHello.
func reassembled(mode fragmentMode, seen observation) []byte {
	stream := bytes.Join(seen.pieces, nil)
	if !mode.splitRecord {
		return stream
	}
	header := append([]byte(nil), seen.headers[0]...)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(stream)))
	return append(header, stream...)
}

// assertFragmentBoundary is the structural verdict for a mode that is supposed to fragment.
func assertFragmentBoundary(t *testing.T, mode fragmentMode, seen observation) {
	t.Helper()
	require.True(t, mode.fragments)

	require.Len(t, seen.writes, mode.writes,
		"the wrapper must issue exactly this many writes: splitPacket separates the pieces on the wire, "+
			"splitRecord alone rewrites the record layer in place and may hand the flight over in one")
	require.Len(t, seen.pieces, mode.pieces,
		"the ClientHello must arrive in this many independently framed pieces")
	for index, piece := range seen.pieces {
		require.NotEmpty(t, piece, "piece %d must not be empty", index)
	}

	whole := reassembled(mode, seen)
	serverName := tf.IndexTLSServerName(whole)
	require.NotNil(t, serverName, "the reassembled ClientHello must still parse as one handshake message")
	require.Equal(t, testServerName, serverName.ServerName)
	require.Equal(t, len(testServerName), serverName.Length)
	require.Equal(t, testServerName, string(whole[serverName.Index:serverName.Index+serverName.Length]))

	// The cut is chosen inside the FIRST label of the name the SNI carries. The wrapper strips the
	// public suffix and then takes one cut per remaining label, so for a name under a known suffix
	// only "www" is left and the cut lands somewhere in [start, start+len("www")]. The upper end is
	// what the assertion has to allow: rand.Intn can return 0, which cuts immediately BEFORE the
	// name, and demanding a strictly interior cut would assert a property the implementation does
	// not provide. What it does provide - and what this asserts - is that the name never survives
	// whole inside the leading piece, which is the entire point of the fragmentation.
	firstLabel := testServerName
	if dot := strings.Index(testServerName, "."); dot >= 0 {
		firstLabel = testServerName[:dot]
	}
	offset := serverName.Index
	if mode.splitRecord {
		// Piece positions are handshake-body positions; the SNI index is a ClientHello position.
		offset -= recordHeaderLen
	}
	boundary := len(seen.pieces[0])
	require.GreaterOrEqual(t, boundary, offset,
		"the cut must not land ahead of the name it is meant to break up")
	require.LessOrEqual(t, boundary, offset+len(firstLabel),
		"the cut must stay within the leading label, which is where the implementation chooses it")
	require.Less(t, boundary, offset+serverName.Length,
		"the ServerName must not fit inside the first piece")
	require.Less(t, boundary, len(bytes.Join(seen.pieces, nil)),
		"the trailing piece must not be empty")
}

// TestTLSFragmentStructure is the deterministic half for the three fragmenting modes.
func TestTLSFragmentStructure(t *testing.T) {
	t.Parallel()
	for _, mode := range allFragmentModes {
		if !mode.fragments {
			continue
		}
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			assertFragmentBoundary(t, mode, fragmentedClientHello(t, mode))
		})
	}
}

// TestTLSFragmentPassThroughWhenDisabled is the control.
//
// It exists because the assertions above are all of the form "more than one piece", and a wrapper
// that fragmented a ClientHello even when both switches are off would satisfy none of them but would
// also not be caught by a test that only ever looks at the fragmenting modes. The pass-through case
// has to be pinned in the opposite direction: one write, one record, the name entirely inside it.
func TestTLSFragmentPassThroughWhenDisabled(t *testing.T) {
	t.Parallel()
	mode := allFragmentModes[0]
	require.False(t, mode.fragments)

	seen := fragmentedClientHello(t, mode)
	require.Len(t, seen.writes, 1, "with both switches off the ClientHello must go out in one write")
	require.Len(t, seen.pieces, 1, "with both switches off the ClientHello must stay one record")

	whole := reassembled(mode, seen)
	serverName := tf.IndexTLSServerName(whole)
	require.NotNil(t, serverName)
	require.Equal(t, testServerName, serverName.ServerName)
	require.LessOrEqual(t, serverName.Index+serverName.Length, len(whole),
		"with both switches off the whole ServerName must sit inside the single record")
}

// TestTLSFragmentHandshakeOverLoopbackTCP runs every mode over a real loopback socket rather than a
// pipe.
//
// This is not redundant with the pipe test. Over a pipe the wrapper cannot resolve a *net.TCPConn,
// so splitPacket takes its fallback branch (write, sleep, write). Over a real TCP connection it
// resolves one and takes the production branch instead - writeAndWaitAck, the SO_NWRITE / TCP_INFO
// acknowledgement wait in wait_darwin.go and wait_linux.go - whose platform code the default suite
// would otherwise never exercise at all. Segmentation cannot be observed through a byte stream, so
// this test asserts the one thing it can: both branches carry a real handshake to completion.
func TestTLSFragmentHandshakeOverLoopbackTCP(t *testing.T) {
	t.Parallel()
	for _, mode := range allFragmentModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			handshakeOverLoopbackTCP(t, mode)
		})
	}
}

func handshakeOverLoopbackTCP(t *testing.T, mode fragmentMode) {
	t.Helper()
	serverConfig, clientConfig := localTLSConfig(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer raw.Close()
		// A deadline rather than a plain wait: if the acknowledgement wait ever stops making
		// progress, the test has to report that as a failure instead of hanging the package.
		_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
		serverDone <- tls.Server(raw, serverConfig).Handshake()
	}()

	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	tcpConn, isTCP := raw.(*net.TCPConn)
	require.True(t, isTCP, "the loopback dial must hand back a *net.TCPConn for the production branch")
	require.NoError(t, tcpConn.SetDeadline(time.Now().Add(30*time.Second)))

	clientConn := tls.Client(
		tf.NewConn(tcpConn, context.Background(), mode.splitPacket, mode.splitRecord, 10*time.Millisecond),
		clientConfig,
	)
	require.NoError(t, clientConn.Handshake())
	require.NoError(t, <-serverDone, "the loopback TLS server must accept the fragmented ClientHello")
}
