package naive

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

// These tests pin the HTTP/2/3 tunnel write contract: a failed flush must
// surface as an error on the write that needed it.
//
// Why this matters rather than being a formality: http.Flusher.Flush() returns
// nothing, so the previous implementation could not distinguish a delivered
// write from one that failed. A stream reset, a closed connection or a rejected
// write all looked identical to success, and the tunnel kept producing frames
// into a stream that was already dead. The reference uses
// http.NewResponseController(w).Flush() and checks the error, which is the only
// way to observe it.

// failingFlushResponseWriter is an http.ResponseWriter whose Flush always fails.
//
// http.NewResponseController reaches Flush through the http.Flusher interface, so
// implementing it here is enough to drive the failure path without needing a real
// HTTP/2 stream. The write itself succeeds, which is exactly the case that used
// to be misreported: the payload reaches the transport buffer, and only the flush
// reveals that the stream is gone.
type failingFlushResponseWriter struct {
	header http.Header

	// flushErr is what Flush reports. Set to a non-nil error to drive the
	// failure path.
	flushErr error

	// flushed counts Flush calls, so the test can assert the flush was actually
	// attempted rather than skipped.
	flushed int

	// written records what reached the writer.
	written []byte
}

func newFailingFlushWriter(flushErr error) *failingFlushResponseWriter {
	return &failingFlushResponseWriter{header: make(http.Header), flushErr: flushErr}
}

func (w *failingFlushResponseWriter) Header() http.Header { return w.header }

func (w *failingFlushResponseWriter) Write(p []byte) (int, error) {
	w.written = append(w.written, p...)
	return len(p), nil
}

func (w *failingFlushResponseWriter) WriteHeader(int) {}

// Flush satisfies http.Flusher, which is how ResponseController finds it. The
// error it returns is the whole point of the test.
func (w *failingFlushResponseWriter) Flush() {
	w.flushed++
}

// FlushError mirrors what controllers do for writers that can report a flush
// error: a writer implementing this interface takes precedence.
func (w *failingFlushResponseWriter) FlushError() error {
	w.flushed++
	return w.flushErr
}

var errFlushFailed = errors.New("simulated flush failure")

// newFlushTestConn builds a naiveH2Conn around a writer whose flush behaviour the
// caller controls.
func newFlushTestConn(t *testing.T, writer http.ResponseWriter, padding bool) *naiveH2Conn {
	t.Helper()
	return &naiveH2Conn{
		reader:        strings.NewReader(""),
		writer:        writer,
		flusher:       http.NewResponseController(writer),
		remoteAddress: nil,
		paddingConn:   paddingConn{enabled: padding},
	}
}

// TestNaiveH2ConnWritePropagatesFlushFailure is the core fault injection: the
// payload write succeeds and the flush fails, so Write must report an error.
func TestNaiveH2ConnWritePropagatesFlushFailure(t *testing.T) {
	for _, padding := range []bool{false, true} {
		name := "raw"
		if padding {
			name = "padded"
		}
		t.Run(name, func(t *testing.T) {
			writer := newFailingFlushWriter(errFlushFailed)
			conn := newFlushTestConn(t, writer, padding)

			_, err := conn.Write([]byte("tunnel payload"))
			if err == nil {
				t.Fatal("a write whose flush failed must return an error; reporting " +
					"success here is what let the tunnel keep writing into a dead stream")
			}
			if !errors.Is(err, errFlushFailed) {
				t.Fatalf("the flush error must be the reported cause, got %v", err)
			}
			// The byte count is NOT asserted to be zero. io.Writer permits
			// returning n > 0 together with an error, and that is the honest
			// report here: the payload did reach the transport buffer, and only
			// the flush revealed that the stream was gone. What must not happen
			// is the error being swallowed.
			if writer.flushed == 0 {
				t.Fatal("the flush must actually be attempted")
			}
		})
	}
}

// TestNaiveH2ConnWriteBufferPropagatesFlushFailure covers the buffer path, which
// is the one the data plane actually uses for tunnelled traffic.
func TestNaiveH2ConnWriteBufferPropagatesFlushFailure(t *testing.T) {
	for _, padding := range []bool{false, true} {
		name := "raw"
		if padding {
			name = "padded"
		}
		t.Run(name, func(t *testing.T) {
			writer := newFailingFlushWriter(errFlushFailed)
			conn := newFlushTestConn(t, writer, padding)

			// The padded path emits a frame header via ExtendHeader, which needs
			// spare front capacity: a zero-headroom buffer fails for that reason
			// rather than for the flush, which would make this test pass while
			// proving nothing. Resize reserves the header, matching the existing
			// writer-contract tests.
			payload := []byte("tunnel payload")
			buffer := buf.NewSize(3 + 255 + len(payload))
			buffer.Resize(3, len(payload))
			copy(buffer.Bytes(), payload)

			err := conn.WriteBuffer(buffer)
			if err == nil {
				t.Fatal("WriteBuffer must report a flush failure")
			}
			if !errors.Is(err, errFlushFailed) {
				t.Fatalf("the flush error must be the reported cause, got %v", err)
			}
			// The buffer must have been released even on the failure path;
			// WriteBuffer owns it via defer.
			if !buffer.IsEmpty() {
				t.Fatal("the buffer must be released on the failure path")
			}
		})
	}
}

// TestNaiveH2ConnWriteSucceedsWhenFlushSucceeds is the control.
//
// Without it, the failure tests above would also pass against an implementation
// that simply returned an error for every write.
func TestNaiveH2ConnWriteSucceedsWhenFlushSucceeds(t *testing.T) {
	for _, padding := range []bool{false, true} {
		name := "raw"
		if padding {
			name = "padded"
		}
		t.Run(name, func(t *testing.T) {
			writer := newFailingFlushWriter(nil)
			conn := newFlushTestConn(t, writer, padding)

			payload := []byte("tunnel payload")
			n, err := conn.Write(payload)
			if err != nil {
				t.Fatalf("a successful flush must not produce an error: %v", err)
			}
			if n != len(payload) {
				t.Fatalf("expected %d bytes written, got %d", len(payload), n)
			}
			if writer.flushed == 0 {
				t.Fatal("the flush must be attempted on the success path too")
			}
			// The payload must actually reach the writer. For a padded
			// connection the bytes on the wire are a Naive frame, so the check
			// is that SOMETHING was written and that it is longer than the
			// payload by the frame header.
			if len(writer.written) == 0 {
				t.Fatal("the payload must reach the writer")
			}
			if padding && len(writer.written) <= len(payload) {
				t.Fatalf("a padded write must emit a frame header in addition to "+
					"the payload: wrote %d bytes for a %d byte payload",
					len(writer.written), len(payload))
			}

			buffer := buf.NewSize(3 + 255 + len(payload))
			buffer.Resize(3, len(payload))
			copy(buffer.Bytes(), payload)
			if err = conn.WriteBuffer(buffer); err != nil {
				t.Fatalf("a successful buffer flush must not produce an error: %v", err)
			}
		})
	}
}

// TestNaiveH2ConnWriteStopsAfterFlushFailure asserts the write-side contract the
// tunnel teardown depends on: once a flush has failed, the caller is told, so it
// does not go on to emit further frames.
//
// The connection does not memoise the failure; it reports it on the write that
// observed it. That is deliberate and matches how the reference propagates the
// error up to its handler, which then tears the tunnel down. The assertion here
// is that the error is reported per-write rather than swallowed, which is what
// makes "stop sending subsequent frames" possible at all.
func TestNaiveH2ConnWriteStopsAfterFlushFailure(t *testing.T) {
	writer := newFailingFlushWriter(errFlushFailed)
	conn := newFlushTestConn(t, writer, true)

	for i := range 3 {
		if _, err := conn.Write([]byte("frame")); err == nil {
			t.Fatalf("write %d must report the flush failure", i)
		}
	}

	// The reader side must remain usable: a failed write does not have to close
	// the tunnel by itself, the caller decides that.
	if _, err := conn.Read(make([]byte, 4)); err != nil && err != io.EOF {
		t.Fatalf("the read side must not be broken by a write-side flush failure: %v", err)
	}
}
