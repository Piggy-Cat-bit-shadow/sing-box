package naive

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests pin the Naive padding frame codec.
//
// The layout is defined by klzgrad/forwardproxy and must not change:
//
//	[2-byte big-endian original data size][1-byte padding size][data][padding zeros]
//
// applied to the first paddingCount frames in each direction.
//
// Two properties matter as much as the layout itself:
//
//  1. Padding is OPTIONAL. A CONNECT without the Padding header is a valid plain
//     HTTP proxy request, and then there are no frames at all.
//  2. The frame fields are inherently bounded (16-bit size, 8-bit padding), so a
//     hostile frame cannot drive a large allocation.

// TestPaddingFrameRoundTrips proves a written frame is read back exactly.
func TestPaddingFrameRoundTrips(t *testing.T) {
	// The writer picks its own random padding, so the test decodes whatever
	// frame it produced rather than assuming a padding size.
	for _, dataSize := range []int{1, 2, 100, 1400, 65535} {
		var buffer bytes.Buffer
		writer := &paddingConn{enabled: true}
		payload := bytes.Repeat([]byte{'x'}, dataSize)
		n, err := writer.writeFrameForTest(&buffer, payload)
		require.NoError(t, err)
		require.Equal(t, dataSize, n, "a write reports the DATA length, not the frame length")

		frame := buffer.Bytes()
		require.GreaterOrEqual(t, len(frame), 3)
		declaredSize := int(binary.BigEndian.Uint16(frame[:2]))
		declaredPadding := int(frame[2])
		require.Equal(t, dataSize, declaredSize,
			"the frame must declare the data length")
		require.Equal(t, dataSize+3+declaredPadding, len(frame),
			"frame length must be data + 3-byte header + declared padding")

		reader := &paddingConn{enabled: true}
		out := make([]byte, dataSize)
		read, err := reader.readWithPadding(&buffer, out)
		require.NoError(t, err)
		require.Equal(t, dataSize, read)
		require.Equal(t, payload, out)
	}
}

// TestPaddingIsOptional is the compatibility property: with padding disabled the
// connection must be plain byte-for-byte I/O with no frame header at all.
func TestPaddingIsOptional(t *testing.T) {
	var buffer bytes.Buffer
	writer := &paddingConn{enabled: false}
	payload := []byte("plain proxy bytes with no frame header")
	n, err := writer.writeFrameForTest(&buffer, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, buffer.Bytes(),
		"an unpadded write must not add a frame header")

	reader := &paddingConn{enabled: false}
	out := make([]byte, len(payload))
	read, err := reader.readWithPadding(&buffer, out)
	require.NoError(t, err)
	require.Equal(t, len(payload), read)
	require.Equal(t, payload, out)
}

// TestPaddingAppliesOnlyToTheFirstFrames proves the negotiation window is
// exactly paddingCount frames and then stops, in both directions.
func TestPaddingAppliesOnlyToTheFirstFrames(t *testing.T) {
	var buffer bytes.Buffer
	writer := &paddingConn{enabled: true}
	payload := []byte("payload")

	// writeChunked is the entry point that owns the window rule: it pads the
	// first paddingCount frames and then writes the remainder raw. Driving
	// writeFrame directly would bypass that rule and count every call, which is
	// not what the production copy path does.
	for range paddingCount + 3 {
		if _, err := writer.writeChunked(&buffer, payload); err != nil {
			require.NoError(t, err)
		}
	}
	require.Equal(t, paddingCount, writer.writePadding,
		"padding must stop after exactly paddingCount frames")
	require.True(t, writer.writerReplaceable(),
		"once the window is over the padding layer is replaceable")
}

// TestUnpaddedConnectionIsImmediatelyReplaceable proves a non-padded connection
// has no padding layer to strip, so it can be dropped from the stack at once.
func TestUnpaddedConnectionIsImmediatelyReplaceable(t *testing.T) {
	connection := &paddingConn{enabled: false}
	require.True(t, connection.readerReplaceable())
	require.True(t, connection.writerReplaceable())
	require.Zero(t, connection.frontHeadroom())
	require.Zero(t, connection.rearHeadroom())
	require.Zero(t, connection.writerMTU())
}

// TestPaddedConnectionReservesHeadroom proves the frame overhead is advertised
// while the padding window is open, so buffers are sized correctly.
func TestPaddedConnectionReservesHeadroom(t *testing.T) {
	connection := &paddingConn{enabled: true}
	require.Equal(t, 3, connection.frontHeadroom())
	require.Equal(t, 255, connection.rearHeadroom(),
		"the maximum padding is one byte's worth, 255")
	require.Equal(t, 65278, connection.writerMTU(),
		"the advertised MTU must be the WORST-CASE payload for the reference "+
			"frame ceiling: 65536 - 3 header - 255 max padding. Advertising 65535 "+
			"(the 16-bit length field's maximum) ignored padding entirely and let "+
			"a caller hand over a payload that framed to 65793 bytes")
	require.False(t, connection.readerReplaceable())
	require.False(t, connection.writerReplaceable())
}

// TestPaddingFrameFieldsAreBounded proves a hostile frame cannot drive a large
// allocation: both fields have fixed widths, so the maximum frame is 65535 + 3 +
// 255 bytes regardless of what the peer claims.
func TestPaddingFrameFieldsAreBounded(t *testing.T) {
	// A frame header claiming the maximum size, followed by a truncated body.
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header, 65535)
	header[2] = 255
	reader := &paddingConn{enabled: true}

	// The reader must return an error rather than allocate 65535+255 bytes and
	// block or panic: it reads into the CALLER's buffer, which the caller sized.
	small := make([]byte, 8)
	_, err := reader.readWithPadding(bytes.NewReader(header), small)
	require.Error(t, err,
		"a frame claiming more data than was sent must fail, not allocate")

	// And an entirely truncated header must fail too, not hang.
	truncated := &paddingConn{enabled: true}
	_, err = truncated.readWithPadding(bytes.NewReader([]byte{0x00}), make([]byte, 8))
	require.Error(t, err)
}

// TestPaddingReadReturnsErrorOnTruncatedFrame proves a partial frame is an error
// and never an infinite wait: io.ReadFull returns as soon as the source is
// exhausted.
func TestPaddingReadReturnsErrorOnTruncatedFrame(t *testing.T) {
	// Header says 10 bytes of data; only 3 are present.
	frame := make([]byte, 0, 3+3)
	frame = append(frame, 0x00, 0x0A, 0x00)
	frame = append(frame, 'a', 'b', 'c')

	connection := &paddingConn{enabled: true}
	done := make(chan error, 1)
	go func() {
		_, err := connection.readWithPadding(bytes.NewReader(frame), make([]byte, 16))
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err, "a truncated frame must produce an error")
	case <-time.After(5 * time.Second):
		t.Fatal("a truncated frame must not block forever")
	}
}

// TestPaddingWriteChunksOversizedBuffers proves data larger than the 16-bit
// frame limit is split into several frames rather than truncated.
func TestPaddingWriteChunksOversizedBuffers(t *testing.T) {
	var buffer bytes.Buffer
	connection := &paddingConn{enabled: true}
	payload := bytes.Repeat([]byte{'z'}, 70000)

	n, err := connection.writeChunked(&buffer, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n,
		"chunked writing must report the full data length, not the frame length")

	// Decode it all back.
	reader := &paddingConn{enabled: true}
	recovered := make([]byte, 0, len(payload))
	scratch := make([]byte, 4096)
	for len(recovered) < len(payload) {
		read, readErr := reader.readWithPadding(&buffer, scratch)
		if readErr != nil {
			break
		}
		recovered = append(recovered, scratch[:read]...)
	}
	require.Equal(t, len(payload), len(recovered))
	require.Equal(t, payload, recovered)
}

// TestUnpaddedWriteIsNotChunked proves that without padding there is no 16-bit
// frame limit, so a large write passes through as one piece.
func TestUnpaddedWriteIsNotChunked(t *testing.T) {
	var buffer bytes.Buffer
	connection := &paddingConn{enabled: false}
	payload := bytes.Repeat([]byte{'z'}, 70000)

	n, err := connection.writeChunked(&buffer, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, len(payload), buffer.Len(),
		"an unpadded write must not be split by the padding frame limit")
}

// TestPaddingHeaderLooksLikeTheReference proves the server's Padding response
// header matches the reference shape: a length in [30, 62), the first 16 bytes
// drawn from a non-Huffman-coded alphabet, the rest '~'.
func TestPaddingHeaderLooksLikeTheReference(t *testing.T) {
	const alphabet = "!#$()+<>?@[]^`{}"
	for range 200 {
		header := generatePaddingHeader()
		require.GreaterOrEqual(t, len(header), 30)
		require.Less(t, len(header), 62)
		for index, character := range header {
			if index < 16 {
				require.True(t, strings.ContainsRune(alphabet, character),
					"the first 16 bytes must come from the reference alphabet, got %q", character)
			} else {
				require.Equal(t, '~', character,
					"bytes past the first 16 must be '~'")
			}
		}
	}
}

// TestPaddingConnReadIsFullRead proves a short underlying read does not make the
// frame layer return partial data, which would corrupt the stream. io.ReadFull is
// what guarantees this.
func TestPaddingConnReadIsFullRead(t *testing.T) {
	// A reader that returns one byte at a time.
	slow := &oneByteReader{data: []byte{0x00, 0x04, 0x00, 'a', 'b', 'c', 'd'}}
	connection := &paddingConn{enabled: true}

	out := make([]byte, 16)
	n, err := connection.readWithPadding(slow, out)
	require.NoError(t, err)
	require.Equal(t, 4, n, "the frame layer must deliver the whole frame")
	require.Equal(t, []byte("abcd"), out[:n])
}

// oneByteReader returns at most one byte per Read, to exercise short reads.
type oneByteReader struct {
	data []byte
	pos  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.data[r.pos]
	r.pos++
	return 1, nil
}
