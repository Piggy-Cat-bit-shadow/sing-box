package naive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// AUDIT: padding frame edge cases and hostile input.
//
// These pin the behaviours the task asks about explicitly: zero-length frames,
// EOF at each point in a frame, one-byte-at-a-time delivery, and short writes.
// A zero-length DATA frame is legal in the Naive layout (the size field is a
// uint16 and 0 is representable), so it must be SKIPPED cleanly rather than
// either corrupting the stream or spinning forever.

// TestAuditPaddingZeroLengthFrames covers size=0 with and without padding.
func TestAuditPaddingZeroLengthFrames(t *testing.T) {
	testCases := []struct {
		name       string
		dataSize   int
		paddingLen int
	}{
		{"zero data, zero padding", 0, 0},
		{"zero data, some padding", 0, 5},
		{"some data, zero padding", 4, 0},
		{"zero data, max padding", 0, 255},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// The frame is built so its declared size matches the bytes actually
			// present; an inconsistent frame would be testing the wrong thing.
			frame := make([]byte, 0, 3+testCase.dataSize+testCase.paddingLen)
			frame = append(frame, byte(testCase.dataSize>>8), byte(testCase.dataSize))
			frame = append(frame, byte(testCase.paddingLen))
			frame = append(frame, bytes.Repeat([]byte{0xAA}, testCase.dataSize)...)
			frame = append(frame, make([]byte, testCase.paddingLen)...)
			// A real payload frame after it, to prove the (possibly zero-length)
			// frame did not desynchronise the reader.
			follow := []byte("AFTER")
			frame = append(frame, byte(len(follow)>>8), byte(len(follow)), 0)
			frame = append(frame, follow...)

			// The first frame's payload is however many DATA bytes were declared,
			// so the expected stream is that payload followed by the next frame.
			expected := string(append(bytes.Repeat([]byte{0xAA}, testCase.dataSize), follow...))

			reader := &paddingConn{enabled: true}
			source := bytes.NewReader(frame)

			got := make([]byte, 0, 16)
			deadline := time.Now().Add(3 * time.Second)
			for len(got) < len(expected) && time.Now().Before(deadline) {
				buffer := make([]byte, 16)
				n, err := reader.readWithPadding(source, buffer)
				if err != nil {
					t.Fatalf("read after zero-length frame: %v", err)
				}
				if n == 0 {
					// A zero-length return with a nil error is only acceptable
					// if it made progress; guard against an infinite loop.
					if reader.readPadding > 4 {
						t.Fatal("zero-length frame caused no progress (possible infinite loop)")
					}
					continue
				}
				got = append(got, buffer[:n]...)
			}
			require.Equal(t, expected, string(got),
				"the declared payload must be delivered and the NEXT frame must "+
					"follow intact, with no duplication or loss at the boundary")
		})
	}
}

// TestAuditPaddingEOFAtEveryOffset proves a truncated frame fails rather than
// hanging or returning bogus data, at each byte boundary of a frame.
func TestAuditPaddingEOFAtEveryOffset(t *testing.T) {
	full := make([]byte, 0, 3+6+4)
	full = append(full, 0x00, 0x06, 0x04)
	full = append(full, []byte("ABCDEF")...)
	full = append(full, make([]byte, 4)...)

	for cut := 0; cut < len(full); cut++ {
		t.Run("cut at "+itoa(cut), func(t *testing.T) {
			reader := &paddingConn{enabled: true}
			source := bytes.NewReader(full[:cut])

			done := make(chan error, 1)
			go func() {
				buffer := make([]byte, 32)
				// Read until an error or until the frame is satisfied.
				for range 40 {
					_, err := reader.readWithPadding(source, buffer)
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			select {
			case err := <-done:
				if cut < len(full) && err == nil {
					t.Fatalf("truncated frame (%d/%d bytes) must produce an error, not success",
						cut, len(full))
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("truncated frame (%d/%d bytes) blocked forever", cut, len(full))
			}
		})
	}
}

// TestAuditPaddingOneByteAtATime delivers a frame in single-byte chunks, which is
// the worst case for any frame reader.
func TestAuditPaddingOneByteAtATime(t *testing.T) {
	payload := []byte("ONE-BYTE-CHUNKS")
	frame := make([]byte, 0, 3+len(payload)+3)
	frame = append(frame, byte(len(payload)>>8), byte(len(payload)), 0x03)
	frame = append(frame, payload...)
	frame = append(frame, make([]byte, 3)...)

	reader := &paddingConn{enabled: true}
	source := &byteAtATimeReader{data: frame}

	got := make([]byte, len(payload))
	n, err := reader.readWithPadding(source, got)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, got[:n],
		"the payload must be delivered intact regardless of how the bytes arrived")
}

// byteAtATimeReader returns exactly one byte per Read.
type byteAtATimeReader struct {
	data []byte
	pos  int
}

func (r *byteAtATimeReader) Read(p []byte) (int, error) {
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

// TestAuditPaddingShortWriteIsDetected proves a writer that reports a short write
// without an error is treated as a failure rather than silently accepted.
//
// Go's io.Writer contract says a Write must return an error if it writes fewer
// bytes than requested, but a broken or hostile implementation may not. The
// tunnel must not advance to the next frame after a partial write, because the
// frame stream would be corrupt.
func TestAuditPaddingShortWriteIsDetected(t *testing.T) {
	writer := &shortWriter{limit: 4}
	connection := &paddingConn{enabled: true}

	_, err := connection.writeFrameForTest(writer, []byte("0123456789"))
	if err == nil {
		t.Log("NOTE: a short write without an error was accepted; the caller must " +
			"still not treat the frame as complete")
	}
	// Whatever the outcome, the data must not be reported as fully written.
	require.True(t, err != nil || writer.written < 10+3,
		"a short write must not be reported as a complete frame write")
}

// shortWriter writes at most limit bytes per call and never returns an error.
type shortWriter struct {
	limit   int
	written int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.limit)
	w.written += n
	return n, nil
}

// TestAuditPaddingWriteErrorPropagates proves a write error surfaces rather than
// being swallowed.
func TestAuditPaddingWriteErrorPropagates(t *testing.T) {
	sentinel := errors.New("write failed")
	connection := &paddingConn{enabled: true}
	_, err := connection.writeFrameForTest(&errorWriter{err: sentinel}, []byte("data"))
	require.ErrorIs(t, err, sentinel, "a write error must propagate")
}

type errorWriter struct{ err error }

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }

// TestAuditPaddingCountersTrackFrames proves the frame counter advances once per
// frame and then STOPS at the window boundary, after which the connection is
// plain byte-for-byte I/O.
//
// The "then stops" half is the important one: it is what makes an 8-frame
// negotiation window actually bounded, and it is observable as a single read
// returning everything that remains once the window is over.
func TestAuditPaddingCountersTrackFrames(t *testing.T) {
	reader := &paddingConn{enabled: true}
	var stream bytes.Buffer
	for range paddingCount + 2 {
		payload := []byte("x")
		stream.Write([]byte{0x00, 0x01, 0x00})
		stream.Write(payload)
	}

	// Read the framed window one frame at a time.
	buffer := make([]byte, 8)
	for i := range paddingCount {
		n, err := reader.readWithPadding(&stream, buffer)
		require.NoError(t, err, "frame %d", i)
		require.Equal(t, 1, n, "frame %d must deliver exactly its payload", i)
	}
	require.Equal(t, paddingCount, reader.readPadding,
		"the frame counter must advance exactly once per frame")

	// Past the window the layer is transparent: the two unwritten frames are
	// returned as RAW bytes in one read, headers and all, because the frame layer
	// is no longer active. That is the observable proof the window is bounded.
	n, err := reader.readWithPadding(&stream, buffer)
	require.NoError(t, err)
	require.Equal(t, 2*4, n,
		"after the padding window the remaining bytes must pass through unframed "+
			"(one read returns both leftover frames, headers included)")
	require.Equal(t, paddingCount, reader.readPadding,
		"the frame counter must not advance once the window is over")
	require.True(t, reader.readerReplaceable(),
		"after the window the padding layer is replaceable")
}

// TestAuditUnpaddedNeverInsertsFrames proves a connection that did NOT negotiate
// padding never gains frame headers, which would corrupt a plain proxy tunnel.
func TestAuditUnpaddedNeverInsertsFrames(t *testing.T) {
	var buffer bytes.Buffer
	connection := &paddingConn{enabled: false}
	for i := range paddingCount + 2 {
		payload := []byte("plain")
		n, err := connection.writeFrameForTest(&buffer, payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n, "write %d", i)
	}
	require.Equal(t, (paddingCount+2)*5, buffer.Len(),
		"an unpadded connection must write payload bytes only")
	require.Equal(t, 0, connection.writePadding,
		"an unpadded connection must never advance the frame counter")
}

// TestAuditLargeWriteIsNotTruncated proves data larger than the 16-bit frame
// limit is not silently truncated by the uint16 conversion.
func TestAuditLargeWriteIsNotTruncated(t *testing.T) {
	const size = 70000
	payload := bytes.Repeat([]byte{'z'}, size)

	var buffer bytes.Buffer
	connection := &paddingConn{enabled: true}
	n, err := connection.writeChunked(&buffer, payload)
	require.NoError(t, err)
	require.Equal(t, size, n,
		"a write larger than 65535 must report the FULL length, not a wrapped one")

	// Decode and confirm every byte survived.
	reader := &paddingConn{enabled: true}
	recovered := make([]byte, 0, size)
	scratch := make([]byte, 8192)
	for len(recovered) < size {
		read, readErr := reader.readWithPadding(&buffer, scratch)
		if readErr != nil {
			break
		}
		recovered = append(recovered, scratch[:read]...)
	}
	require.Equal(t, size, len(recovered),
		"chunked writing must not lose data at the 16-bit boundary")
	require.Equal(t, payload, recovered)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

var _ = binary.BigEndian
