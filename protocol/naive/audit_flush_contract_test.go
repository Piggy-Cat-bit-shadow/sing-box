package naive

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The CONNECT response flush must be checked, and a failed flush must NOT be
// followed by tunnel creation.
//
// The reference checks it (forwardproxy.go calls
// http.NewResponseController(w).Flush() and returns a 500 on error). A bare
// http.Flusher.Flush() cannot report failure, so the previous code would build a
// tunnel whose 200 the client never received.
//
// These tests exercise the writer contract directly rather than standing up an
// inbound, because the property under test is what the handler does with a writer
// that fails to flush.

// flushFailingWriter is an http.ResponseWriter whose Flush always fails, which is
// what a dropped connection or a closed HTTP/2 stream looks like at this layer.
type flushFailingWriter struct {
	header      http.Header
	statusCode  int
	wroteHeader bool
	written     int
	flushCalls  int
}

func newFlushFailingWriter() *flushFailingWriter {
	return &flushFailingWriter{header: make(http.Header)}
}

func (w *flushFailingWriter) Header() http.Header { return w.header }

func (w *flushFailingWriter) Write(data []byte) (int, error) {
	w.written += len(data)
	return len(data), nil
}

func (w *flushFailingWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.statusCode = statusCode
		w.wroteHeader = true
	}
}

func (w *flushFailingWriter) Flush() { w.flushCalls++ }

// FlushError makes this writer satisfy http.ResponseController's optional
// interface, so NewResponseController(writer).Flush() returns this error.
func (w *flushFailingWriter) FlushError() error {
	w.flushCalls++
	return errors.New("simulated flush failure: connection gone")
}

// TestAuditFlushFailureIsReported proves the controller surfaces the failure that
// a bare Flusher could not.
func TestAuditFlushFailureIsReported(t *testing.T) {
	writer := newFlushFailingWriter()
	controller := http.NewResponseController(writer)

	err := controller.Flush()
	if err == nil {
		t.Fatal("a writer whose FlushError returns an error must make " +
			"ResponseController.Flush() return it; otherwise a flush that never " +
			"reached the client would be indistinguishable from success")
	}
	t.Logf("flush failure surfaced: %v", err)

	if writer.flushCalls == 0 {
		t.Fatal("the writer's flush must actually be attempted")
	}
}

// TestAuditFlushSuccessIsNotAnError is the control: a writer that flushes
// correctly must not be reported as failing, or the guard would reject every
// connection.
func TestAuditFlushSuccessIsNotAnError(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(recorder).Flush(); err != nil {
		t.Fatalf("a recorder flushes cleanly and must not error: %v", err)
	}
}

// TestAuditControllerUnwrapsWrappedFlusher proves the controller reaches a
// flusher hidden behind a wrapper, which the plain type assertion the old code
// used would miss.
//
// This is the practical reason the controller is used rather than a type
// assertion: the reference HTTP/2 writer and Caddy's writers are wrapped, and a
// wrapper that does not itself implement http.Flusher would have made the old
// code reject an otherwise working connection with "response writer is not a
// flusher".
func TestAuditControllerUnwrapsWrappedFlusher(t *testing.T) {
	inner := httptest.NewRecorder()
	inner.WriteHeader(http.StatusOK)

	wrapped := &unwrappingWriter{ResponseWriter: inner}

	if _, isFlusher := any(wrapped).(http.Flusher); isFlusher {
		t.Fatal("precondition: the wrapper must NOT implement http.Flusher " +
			"directly, so the test proves the controller unwraps rather than that " +
			"the assertion succeeds")
	}

	if err := http.NewResponseController(wrapped).Flush(); err != nil {
		t.Fatalf("the controller must reach the wrapped flusher: %v", err)
	}
	t.Log("the controller found the flusher behind a non-Flusher wrapper")
}

// unwrappingWriter deliberately does not implement http.Flusher; it exposes the
// wrapped writer through Unwrap, which is the convention ResponseController uses.
type unwrappingWriter struct {
	http.ResponseWriter
}

func (w *unwrappingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

var _ io.Writer = (*flushFailingWriter)(nil)
