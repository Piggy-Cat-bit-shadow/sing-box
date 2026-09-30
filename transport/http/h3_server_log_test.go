//go:build with_quic

package http

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

// Tests for connection-level HTTP/3 fault visibility.
//
// # The gap
//
// http3.Server handles each connection on its own goroutine and logs handleConn's error through
// s.Logger, then discards it. ServeListener returns ONLY http.ErrServerClosed on graceful
// shutdown or the listener's own Accept error. So a connection-level fault:
//
//   - never reaches the `ServeListener` return value that sing-box classifies, and
//   - with Logger unset, was discarded inside quic-go with no operator-visible signal at all.
//
// These tests drive the handler directly, because that is the only place the fault is ever
// visible -- which is precisely why an integration path through ServeListener cannot observe it.

// recordingSlogLogger captures what the adapter emits.
type recordingSlogLogger struct {
	access   sync.Mutex
	errors   []string
	debugs   []string
	warnings []string
}

func (l *recordingSlogLogger) Trace(args ...any) { l.record(&l.debugs, args...) }
func (l *recordingSlogLogger) Debug(args ...any) { l.record(&l.debugs, args...) }
func (l *recordingSlogLogger) Info(args ...any)  { l.record(&l.debugs, args...) }
func (l *recordingSlogLogger) Warn(args ...any)  { l.record(&l.warnings, args...) }
func (l *recordingSlogLogger) Error(args ...any) { l.record(&l.errors, args...) }
func (l *recordingSlogLogger) Fatal(args ...any) { l.record(&l.errors, args...) }
func (l *recordingSlogLogger) Panic(args ...any) { l.record(&l.errors, args...) }

func (l *recordingSlogLogger) record(into *[]string, args ...any) {
	l.access.Lock()
	defer l.access.Unlock()
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		switch typed := arg.(type) {
		case string:
			parts = append(parts, typed)
		case error:
			if typed != nil {
				parts = append(parts, typed.Error())
			}
		}
	}
	*into = append(*into, strings.Join(parts, " "))
}

func (l *recordingSlogLogger) snapshot() (errs, warns, debugs []string) {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.errors...),
		append([]string(nil), l.warnings...),
		append([]string(nil), l.debugs...)
}

// handleConnectionFailure feeds the handler the exact record http3.Server produces for a failed
// connection, so the test exercises the real adapter input shape.
// zeroTime avoids importing time for a value the handler ignores.
func zeroTime() (zero time.Time) { return }

func handleConnectionFailure(t *testing.T, handler slog.Handler, failure error) {
	t.Helper()
	record := slog.NewRecord(
		// The handler ignores the timestamp; a zero value keeps the test deterministic.
		zeroTime(),
		slog.LevelDebug,
		"handling connection failed",
		0,
	)
	record.AddAttrs(slog.Any("error", failure))
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("handler returned an error: %v", err)
	}
}

// TestH3ServerConnectionFaultIsVisible is the regression for the observability gap.
//
// A connection-level HTTP/3 fault must produce an operator-visible ERROR. Before the adapter
// existed this was impossible: http3.Server.Logger was nil, so the error was discarded and
// ServeListener never returned it.
func TestH3ServerConnectionFaultIsVisible(t *testing.T) {
	t.Parallel()

	faults := []struct {
		name string
		err  error
	}{
		{"transport protocol violation", &quic.TransportError{ErrorCode: 0xa, ErrorMessage: "PROTOCOL_VIOLATION"}},
		{"transport frame encoding error", &quic.TransportError{ErrorCode: 0x7}},
		{"http3 internal error", &http3.Error{ErrorCode: http3.ErrCodeInternalError}},
		{"http3 message error", &http3.Error{ErrorCode: http3.ErrCodeMessageError}},
		{"stateless reset", &quic.StatelessResetError{}},
		{"version negotiation failure", &quic.VersionNegotiationError{}},
		{"application error with a fault code", &quic.ApplicationError{ErrorCode: 0x102}},
	}

	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			recorder := &recordingSlogLogger{}
			handler := h3ServerLogHandler{logger: recorder, component: "http3 server"}

			handleConnectionFailure(t, handler, fault.err)

			errorsLogged, warnings, _ := recorder.snapshot()
			if len(errorsLogged) == 0 {
				t.Fatalf("a connection-level fault must be operator-visible; %s produced no "+
					"ERROR, so it is still swallowed exactly as it was before the adapter",
					fault.name)
			}
			if len(warnings) != 0 {
				t.Fatalf("a fault must not be emitted as a warning: %v", warnings)
			}
			// The message must identify what failed.
			if !strings.Contains(strings.Join(errorsLogged, " "), fault.err.Error()) {
				t.Fatalf("the logged message must carry the underlying error: %v", errorsLogged)
			}
		})
	}
}

// TestH3ServerExpectedClosureStaysQuiet pins the other half: an ordinary connection teardown must
// not become ERROR noise on a listener that serves many connections.
func TestH3ServerExpectedClosureStaysQuiet(t *testing.T) {
	t.Parallel()

	expected := []struct {
		name string
		err  error
	}{
		{"idle timeout", &quic.IdleTimeoutError{}},
		{"handshake timeout", &quic.HandshakeTimeoutError{}},
		{"orderly transport close", &quic.TransportError{ErrorCode: quic.NoError}},
		{"orderly application close", &quic.ApplicationError{ErrorCode: 0}},
		{"http3 no error", &http3.Error{ErrorCode: http3.ErrCodeNoError}},
		{"http3 request cancelled", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}},
		{"context canceled", context.Canceled},
	}

	for _, testCase := range expected {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &recordingSlogLogger{}
			handler := h3ServerLogHandler{logger: recorder, component: "http3 server"}

			handleConnectionFailure(t, handler, testCase.err)

			errorsLogged, warnings, _ := recorder.snapshot()
			if len(errorsLogged) != 0 {
				t.Fatalf("an expected closure must not be logged as a fault: %v", errorsLogged)
			}
			if len(warnings) != 0 {
				t.Fatalf("an expected closure must not be logged as a warning: %v", warnings)
			}
		})
	}
}

// TestH3ServerAdapterIgnoresUnrelatedRecords proves the adapter does not mirror the library's
// internal logging. It exists to surface connection faults, not to relay debug output.
func TestH3ServerAdapterIgnoresUnrelatedRecords(t *testing.T) {
	t.Parallel()

	recorder := &recordingSlogLogger{}
	handler := h3ServerLogHandler{logger: recorder, component: "http3 server"}

	for _, message := range []string{
		"some internal detail",
		"another message",
		"handling connection failed but no error attr",
	} {
		record := slog.NewRecord(zeroTime(), slog.LevelDebug, message, 0)
		if err := handler.Handle(context.Background(), record); err != nil {
			t.Fatalf("handler returned an error: %v", err)
		}
	}

	errorsLogged, warnings, debugs := recorder.snapshot()
	if len(errorsLogged) != 0 || len(warnings) != 0 || len(debugs) != 0 {
		t.Fatalf("unrelated records must not be mirrored: errors=%v warnings=%v debugs=%v",
			errorsLogged, warnings, debugs)
	}
}

// TestH3ServerLoggerIsNilWithoutALogger proves the adapter is optional.
func TestH3ServerLoggerIsNilWithoutALogger(t *testing.T) {
	t.Parallel()

	if got := newH3ServerLogger(nil, "http3 server"); got != nil {
		t.Fatalf("a nil logger must yield a nil slog.Logger so http3.Server keeps its default "+
			"behaviour, got %v", got)
	}

	recorder := &recordingSlogLogger{}
	if got := newH3ServerLogger(recorder, "http3 server"); got == nil {
		t.Fatal("a real logger must produce a usable slog.Logger")
	}
}

// TestH3ServerAdapterClassifiesLikeTheRestOfThePackage is the drift guard.
//
// The adapter must not grow its own opinion about what is expected: it delegates to
// isExpectedH3Closure, the same predicate the server exit path uses. This asserts the two agree
// across the error surface, so a future edit to one cannot silently diverge from the other.
func TestH3ServerAdapterClassifiesLikeTheRestOfThePackage(t *testing.T) {
	t.Parallel()

	surface := []error{
		&quic.TransportError{ErrorCode: quic.NoError},
		&quic.TransportError{ErrorCode: 0xa},
		&quic.ApplicationError{ErrorCode: 0},
		&quic.ApplicationError{ErrorCode: 0x102},
		&quic.StreamError{ErrorCode: 0},
		&quic.StreamError{ErrorCode: 268},
		&quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)},
		&quic.StatelessResetError{},
		&quic.VersionNegotiationError{},
		&quic.IdleTimeoutError{},
		&quic.HandshakeTimeoutError{},
		&http3.Error{ErrorCode: http3.ErrCodeNoError},
		&http3.Error{ErrorCode: http3.ErrCodeInternalError},
		errors.New("unknown"),
	}

	for _, testErr := range surface {
		recorder := &recordingSlogLogger{}
		handler := h3ServerLogHandler{logger: recorder, component: "http3 server"}
		handleConnectionFailure(t, handler, testErr)

		errorsLogged, _, _ := recorder.snapshot()
		adapterSaysFault := len(errorsLogged) > 0
		classifierSaysFault := !isExpectedH3Closure(testErr)
		if adapterSaysFault != classifierSaysFault {
			t.Fatalf("%T (%v): the adapter says fault=%v but isExpectedH3Closure says fault=%v; "+
				"the adapter must delegate rather than form its own opinion",
				testErr, testErr, adapterSaysFault, classifierSaysFault)
		}
	}
}
