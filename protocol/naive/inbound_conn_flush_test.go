package naive

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

// errFlush reports a flush that reached the transport but did not succeed.
var errFlush = errors.New("flush failed")

// flushFailingWriter is an http.ResponseWriter whose Write succeeds and whose Flush fails.
//
// That combination is the point: the tunnel's payload reaches the transport buffer, so the
// write itself reports success, and only the flush reveals that the stream is gone. A
// caller that cannot see the flush error treats a dead tunnel as healthy and keeps writing.
type flushFailingWriter struct {
	header http.Header

	writeErr error
	flushErr error

	flushes   int
	written   int
	lastWrite []byte
}

func (w *flushFailingWriter) Header() http.Header { return w.header }

func (w *flushFailingWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	w.written += len(p)
	w.lastWrite = append([]byte(nil), p...)
	return len(p), nil
}

func (w *flushFailingWriter) WriteHeader(int) {}

// FlushError is how http.ResponseController reports a flush error. It is the interface the
// controller prefers over http.Flusher, which returns nothing and therefore cannot report
// anything.
func (w *flushFailingWriter) FlushError() error {
	w.flushes++
	return w.flushErr
}

func newFlushTestConn(t *testing.T, writer *flushFailingWriter) *naiveH2Conn {
	t.Helper()
	return &naiveH2Conn{
		reader:  strings.NewReader(""),
		writer:  writer,
		flusher: http.NewResponseController(writer),
	}
}

// TestH2ConnWriteReportsFlushFailure pins that a failed flush fails the write.
func TestH2ConnWriteReportsFlushFailure(t *testing.T) {
	t.Parallel()

	writer := &flushFailingWriter{header: make(http.Header), flushErr: errFlush}
	conn := newFlushTestConn(t, writer)

	_, err := conn.Write([]byte("payload"))

	require.ErrorIs(t, err, errFlush,
		"Write must report a failed flush: the payload reached the transport buffer but "+
			"was not delivered, so a success here marks a dead tunnel as usable")
	require.Equal(t, 1, writer.flushes, "the flush must have been attempted")
}

// TestH2ConnWriteBufferReportsFlushFailure is the same contract on the buffer path, which
// is the one bulk traffic uses.
func TestH2ConnWriteBufferReportsFlushFailure(t *testing.T) {
	t.Parallel()

	writer := &flushFailingWriter{header: make(http.Header), flushErr: errFlush}
	conn := newFlushTestConn(t, writer)

	// The buffer carries the headroom the padding codec needs: 3 bytes in front for the
	// frame header and up to 255 bytes behind for the padding, which is what the copy
	// path guarantees for this connection.
	const (
		frameHeaderSize = 3
		maxPaddingSize  = 255
	)
	// WriteZeroN appends into the buffer's remaining capacity, so the rear space is
	// included in the allocation and left usable rather than reserved.
	buffer := buf.NewSize(frameHeaderSize + len("payload") + maxPaddingSize)
	buffer.Resize(frameHeaderSize, len("payload"))
	copy(buffer.Bytes(), "payload")
	buffer.Write([]byte("payload"))
	err := conn.WriteBuffer(buffer)

	require.ErrorIs(t, err, errFlush,
		"WriteBuffer must report a failed flush, or bulk traffic keeps feeding a stream "+
			"that is already gone")
	require.Equal(t, 1, writer.flushes)
}

// TestH2ConnWriteSucceedsWhenFlushSucceeds is the control: a healthy flush must not turn a
// successful write into an error.
func TestH2ConnWriteSucceedsWhenFlushSucceeds(t *testing.T) {
	t.Parallel()

	writer := &flushFailingWriter{header: make(http.Header)}
	conn := newFlushTestConn(t, writer)

	_, err := conn.Write([]byte("payload"))
	require.NoError(t, err, "a successful flush must not be reported as a failure")
	require.Equal(t, 1, writer.flushes)
	// The frame carries a 3-byte header and 0..255 bytes of padding around the payload,
	// so the exact write size varies; what matters is that the payload was written.
	require.GreaterOrEqual(t, writer.written, len("payload"),
		"the payload must have been written")
	require.Contains(t, string(writer.lastWrite), "payload")
}

// TestH2ConnWriteReportsTheWriteErrorFirst keeps the existing behaviour: a failing write is
// reported as the write error, not as a flush error.
func TestH2ConnWriteReportsTheWriteErrorFirst(t *testing.T) {
	t.Parallel()

	writer := &flushFailingWriter{header: make(http.Header), writeErr: errFlush}
	conn := newFlushTestConn(t, writer)

	_, err := conn.Write([]byte("payload"))
	require.ErrorIs(t, err, errFlush)
	require.Zero(t, writer.flushes,
		"a write that failed must not flush: there is nothing to deliver")
}
