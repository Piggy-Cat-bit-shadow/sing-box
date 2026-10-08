package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests drive the two conn wrappers over an in-memory duplex pair, so
// both directions are exercised without a socket and without a server. They are
// the closest thing to a handshake round trip the client half can have on its
// own: the record framing, the rekey path, the `input`/`rawInput` buffers Vision
// reads (the ABI pinned in common.go), and the XOR header mask.

// fakeDuplex is an unbounded, non-blocking duplex conn.
type fakeDuplex struct {
	net.Conn
	readBuf  bytes.Buffer
	writeBuf *bytes.Buffer
}

func newDuplexPair() (*fakeDuplex, *fakeDuplex) {
	a := &fakeDuplex{}
	b := &fakeDuplex{}
	a.writeBuf = &b.readBuf
	b.writeBuf = &a.readBuf
	return a, b
}

func (c *fakeDuplex) Read(p []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuf.Read(p)
}

func (c *fakeDuplex) Write(p []byte) (int, error) { return c.writeBuf.Write(p) }

func (c *fakeDuplex) Close() error         { return nil }
func (c *fakeDuplex) LocalAddr() net.Addr  { return nil }
func (c *fakeDuplex) RemoteAddr() net.Addr { return nil }

// TestCommonConnFramingRoundTrip pins the native appearance framing: a payload
// larger than one record is split into TLSv1.3-shaped chunks, sealed with the
// united key, and reassembled on the peer. The larger-than-8192 case also
// exercises the `input`/`rawInput` buffers Vision reflects on, including the
// partial-record path where a sealed record is longer than the caller's read
// buffer.
func TestCommonConnFramingRoundTrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	iv := []byte("0123456789abcdef")

	clientInner, serverInner := newDuplexPair()
	client := NewCommonConn(clientInner, false)
	client.UnitedKey = key
	client.AEAD = NewAEAD(iv, key, false)
	server := NewCommonConn(serverInner, false)
	server.UnitedKey = key
	server.PeerAEAD = NewAEAD(iv, key, false)

	payload := make([]byte, 20000)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	written, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)

	// The wire starts with an application-data record header whose length is
	// the first 8192-byte chunk plus the tag.
	wire := serverInner.readBuf.Bytes()
	require.Greater(t, len(wire), 5)
	require.Equal(t, byte(23), wire[0])
	require.Equal(t, byte(3), wire[1])
	require.Equal(t, byte(3), wire[2])
	length, err := DecodeHeader(wire[:5])
	require.NoError(t, err)
	require.Equal(t, 8192+16, length)

	// Read back through a buffer smaller than a record, so the leftover path
	// through CommonConn.input is taken.
	var got []byte
	buf := make([]byte, 4096)
	for len(got) < len(payload) {
		n, err := server.Read(buf)
		require.NoError(t, err)
		require.NotZero(t, n)
		got = append(got, buf[:n]...)
	}
	require.Equal(t, payload, got)
}

// TestXorConnMasksOnlyHeaders pins the xorpub/random appearance: the five-byte
// record header is XOR-ed with the keystream and the ciphertext body is left
// alone, in both directions and across arbitrary Write chunking.
func TestXorConnMasksOnlyHeaders(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	iv := []byte("0123456789abcdef")

	body := make([]byte, 100)
	_, err = rand.Read(body)
	require.NoError(t, err)
	payload := make([]byte, 5)
	EncodeHeader(payload, len(body)+16)
	payload = append(payload, body...)
	plain := append([]byte(nil), payload...)

	maskedHeader := make([]byte, 5)
	NewCTR(key, iv).XORKeyStream(maskedHeader, plain[:5])

	// Write the record in one call: exactly the header changes.
	writerInner, readerInner := newDuplexPair()
	writer := NewXorConn(writerInner, NewCTR(key, iv), NewCTR(key, iv), 0, 0)
	reader := NewXorConn(readerInner, NewCTR(key, iv), NewCTR(key, iv), 0, 0)

	written, err := writer.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(plain), written)
	require.Equal(t, maskedHeader, payload[:5], "the header must be masked")
	require.Equal(t, plain[5:], payload[5:], "the body must be untouched")

	readBuf := make([]byte, len(plain))
	read, err := reader.Read(readBuf)
	require.NoError(t, err)
	require.Equal(t, len(plain), read)
	require.Equal(t, plain, readBuf, "the peer must recover the record exactly")

	// The same record split into three-byte writes must produce identical wire
	// bytes: the skip counters cannot depend on chunking.
	chunkedInner, chunkedPeerInner := newDuplexPair()
	chunked := NewXorConn(chunkedInner, NewCTR(key, iv), NewCTR(key, iv), 0, 0)
	chunkedReader := NewXorConn(chunkedPeerInner, NewCTR(key, iv), NewCTR(key, iv), 0, 0)
	chunk := append([]byte(nil), plain...)
	for offset := 0; offset < len(chunk); offset += 3 {
		end := min(offset+3, len(chunk))
		n, err := chunked.Write(chunk[offset:end])
		require.NoError(t, err)
		require.Equal(t, end-offset, n)
	}
	require.Equal(t, maskedHeader, chunkedInner.writeBuf.Bytes()[:5])

	chunkedRead := make([]byte, len(plain))
	read, err = chunkedReader.Read(chunkedRead)
	require.NoError(t, err)
	require.Equal(t, len(plain), read)
	require.Equal(t, plain, chunkedRead)
}

// The XOR layer must advertise the conn beneath it so Vision can reach the TLS
// layer directly.
func TestXorConnUpstreamIsInnerConn(t *testing.T) {
	t.Parallel()

	inner, _ := newDuplexPair()
	conn := NewXorConn(inner, NewCTR(make([]byte, 32), make([]byte, 16)), nil, 0, 0)
	require.Same(t, inner, conn.Upstream())
}

// CommonConn advertises the conn beneath it for the same reason.
func TestCommonConnUpstreamIsInnerConn(t *testing.T) {
	t.Parallel()

	inner, _ := newDuplexPair()
	conn := NewCommonConn(inner, false)
	require.Same(t, inner, conn.Upstream())
}
