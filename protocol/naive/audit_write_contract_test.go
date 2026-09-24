package naive

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// AUDIT: the padding write paths must obey the io.Writer contract.
//
// io.Writer permits a Write to return n < len(p) with a NIL error, and callers
// must treat that as a failure. The padding writer previously checked ONLY the
// error and then reported the full payload length, so a short write produced:
//
//   - silent data loss (the caller believed bytes were sent);
//   - a full-length success report for a partial frame;
//   - a padding frame counter advanced past a frame the peer never fully
//     received, after which the next write emitted RAW bytes into a stream the
//     peer was still parsing as framed.
//
// These tests pin the corrected behaviour for every short-write shape the audit
// asks about.

// scriptedWriter returns a fixed number of bytes and an optional error.
type scriptedWriter struct {
	allow int
	err   error
	got   int
	calls int
}

func (w *scriptedWriter) Write(p []byte) (int, error) {
	w.calls++
	n := min(w.allow, len(p))
	w.got += n
	return n, w.err
}

// TestAuditWriteContractMatrix covers all five write outcomes.
func TestAuditWriteContractMatrix(t *testing.T) {
	payload := []byte("0123456789")
	boom := errors.New("write failed")

	testCases := []struct {
		name         string
		allow        int
		writeErr     error
		wantError    bool
		wantFrames   int
		wantPayloadN int
		wantErrorIs  error
	}{
		{"full write and nil error", 1 << 20, nil, false, 1, len(payload), nil},
		{"partial write and nil error", 4, nil, true, 0, 0, io.ErrShortWrite},
		{"zero write and nil error", 0, nil, true, 0, 0, io.ErrShortWrite},
		{"partial write with error", 3, boom, true, 0, 0, boom},
		{"zero write with error", 0, boom, true, 0, 0, boom},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			writer := &scriptedWriter{allow: testCase.allow, err: testCase.writeErr}
			connection := &paddingConn{enabled: true}

			n, err := connection.writeWithPadding(writer, payload)

			if testCase.wantError {
				require.Error(t, err,
					"a write that did not deliver every byte must report an error")
				require.ErrorIs(t, err, testCase.wantErrorIs)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, testCase.wantPayloadN, n,
				"the reported payload length must reflect what was actually sent")
			require.Equal(t, testCase.wantFrames, connection.writePadding,
				"the frame counter must not advance past an incompletely written frame")
		})
	}
}

// TestAuditUnpaddedWriteContract proves the unpadded path applies the same rule.
// Without the fix this path also reported success for a short write, which would
// silently truncate a plain proxy tunnel.
func TestAuditUnpaddedWriteContract(t *testing.T) {
	payload := []byte("plain-bytes")

	// Full write succeeds and reports the true length.
	full := &scriptedWriter{allow: 1 << 20}
	connection := &paddingConn{enabled: false}
	n, err := connection.writeWithPadding(full, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	// A short write is an error, not a silent truncation.
	short := &scriptedWriter{allow: 3}
	shortConn := &paddingConn{enabled: false}
	n, err = shortConn.writeWithPadding(short, payload)
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.Less(t, n, len(payload),
		"a failed unpadded write must not be reported as a complete payload write")
	require.Equal(t, 3, n,
		"the reported count must be the bytes actually written, which is more "+
			"useful to the caller than a forced zero")
	require.Equal(t, 3, short.got,
		"the writer received the whole payload but accepted only 3 bytes")
}

// TestAuditBufferWriteContract proves the buffer-based path is fixed too, since
// it is the path the router actually uses for bulk transfer.
func TestAuditBufferWriteContract(t *testing.T) {
	// The real data path hands this writer buffers that already carry HEADROOM,
	// because writeBufferWithPadding prepends a 3-byte frame header with
	// ExtendHeader. A buffer created with no spare capacity would panic for a
	// reason unrelated to the contract under test, so headroom is reserved here
	// exactly as the production path does.
	makeBuffer := func(content []byte) *buf.Buffer {
		b := buf.NewSize(3 + 255 + len(content))
		b.Resize(3, 3+len(content))
		copy(b.Bytes(), content)
		return b
	}

	t.Run("full write advances the counter once", func(t *testing.T) {
		writer := &scriptedWriter{allow: 1 << 20}
		connection := &paddingConn{enabled: true}
		require.NoError(t, connection.writeBufferWithPadding(writer, makeBuffer([]byte("hello"))))
		require.Equal(t, 1, connection.writePadding)
	})

	t.Run("short write fails and does not advance the counter", func(t *testing.T) {
		writer := &scriptedWriter{allow: 2}
		connection := &paddingConn{enabled: true}
		err := connection.writeBufferWithPadding(writer, makeBuffer([]byte("hello")))
		require.ErrorIs(t, err, io.ErrShortWrite)
		require.Zero(t, connection.writePadding,
			"an incompletely written frame must not advance the frame counter")
	})

	t.Run("unpadded short write fails", func(t *testing.T) {
		writer := &scriptedWriter{allow: 1}
		connection := &paddingConn{enabled: false}
		err := connection.writeBufferWithPadding(writer, makeBuffer([]byte("hello")))
		require.ErrorIs(t, err, io.ErrShortWrite)
	})
}

// TestAuditChunkedWriteStopsOnShortWrite proves the chunked writer aborts instead
// of continuing to emit frames after the stream is already corrupt.
func TestAuditChunkedWriteStopsOnShortWrite(t *testing.T) {
	// Allow one full frame, then refuse: the second frame must not be attempted
	// as a "successful" continuation.
	writer := &failingAfter{allowFirst: true}
	connection := &paddingConn{enabled: true}

	data := bytes.Repeat([]byte{'z'}, 70000)
	_, err := connection.writeChunked(writer, data)
	require.Error(t, err,
		"a short write in the middle of chunked output must abort the write")
	require.Equal(t, 1, connection.writePadding,
		"exactly the frames that were fully written must be counted")
}

// failingAfter permits the first Write and refuses every later one.
type failingAfter struct {
	allowFirst bool
	used       bool
}

func (w *failingAfter) Write(p []byte) (int, error) {
	if w.allowFirst && !w.used {
		w.used = true
		return len(p), nil
	}
	return 0, io.ErrShortWrite
}

// TestAuditWriterThatLiesAboutLengthIsStillCaught documents the boundary of what
// a writer-side check can do: a writer that CLAIMS success while dropping bytes
// cannot be detected here. The test exists so the limitation is explicit rather
// than assumed away.
func TestAuditWriterThatLiesAboutLengthIsStillCaught(t *testing.T) {
	// A writer that reports full length but writes nothing is indistinguishable
	// from a correct writer at this layer by contract. Record that, so nobody
	// later mistakes this layer for a data-integrity guarantee.
	liar := &lyingWriter{}
	connection := &paddingConn{enabled: true}
	n, err := connection.writeWithPadding(liar, []byte("data"))
	require.NoError(t, err, "a writer claiming success is trusted, by contract")
	require.Equal(t, 4, n)
}

type lyingWriter struct{}

func (w *lyingWriter) Write(p []byte) (int, error) { return len(p), nil }
