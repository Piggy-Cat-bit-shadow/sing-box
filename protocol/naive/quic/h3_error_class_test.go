//go:build with_quic

package quic

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
)

// recordingLogger captures classified output for assertions.
type recordingLogger struct {
	access   sync.Mutex
	errors   []string
	debugs   []string
	warnings []string
}

func (l *recordingLogger) Trace(args ...any) { l.record(&l.debugs, args...) }
func (l *recordingLogger) Debug(args ...any) { l.record(&l.debugs, args...) }
func (l *recordingLogger) Info(args ...any)  { l.record(&l.debugs, args...) }
func (l *recordingLogger) Warn(args ...any)  { l.record(&l.warnings, args...) }
func (l *recordingLogger) Error(args ...any) { l.record(&l.errors, args...) }
func (l *recordingLogger) Fatal(args ...any) { l.record(&l.errors, args...) }
func (l *recordingLogger) Panic(args ...any) { l.record(&l.errors, args...) }

func (l *recordingLogger) record(into *[]string, args ...any) {
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

func (l *recordingLogger) snapshot() (errs, warns, debugs []string) {
	l.access.Lock()
	defer l.access.Unlock()
	return append([]string(nil), l.errors...),
		append([]string(nil), l.warnings...),
		append([]string(nil), l.debugs...)
}

// TestNaiveExpectedClosuresStayQuiet pins the events that must not become ERROR noise.
func TestNaiveExpectedClosuresStayQuiet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
	}{
		{"peer cancels a request stream", &quic.StreamError{ErrorCode: 268, Remote: true}},
		{"local stream reset with no error", &quic.StreamError{ErrorCode: 0, Remote: false}},
		{"orderly transport close", &quic.TransportError{ErrorCode: quic.NoError}},
		{"orderly application close", &quic.ApplicationError{ErrorCode: 0}},
		{"idle timeout", &quic.IdleTimeoutError{}},
		{"handshake timeout", &quic.HandshakeTimeoutError{}},
		{"http3 no error", &http3.Error{ErrorCode: http3.ErrCodeNoError}},
		{"http3 request cancelled", &http3.Error{ErrorCode: http3.ErrCodeRequestCanceled}},
		{"context canceled", context.Canceled},
		{"context deadline", context.DeadlineExceeded},
		{"io.EOF", io.EOF},
		{"net.ErrClosed", net.ErrClosed},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !classifyNaiveH3Error(testCase.err) {
				t.Fatalf("must be classified as an expected closure: %v", testCase.err)
			}
		})
	}
}

// TestNaiveRealFaultsStayVisible is the half that was broken.
//
// Each of these unwraps to net.ErrClosed, so a generic closed test alone -- which is what the
// server exit path used before -- would have silenced it.
func TestNaiveRealFaultsStayVisible(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
	}{
		{"transport protocol violation", &quic.TransportError{ErrorCode: 0xa}},
		{"transport frame encoding error", &quic.TransportError{ErrorCode: 0x7}},
		{"application error with a fault code", &quic.ApplicationError{ErrorCode: 0x102}},
		{"stream internal error", &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)}},
		{"stateless reset", &quic.StatelessResetError{}},
		{"version negotiation failure", &quic.VersionNegotiationError{}},
		{"http3 internal error", &http3.Error{ErrorCode: http3.ErrCodeInternalError}},
		{"unknown error", errors.New("boom")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if classifyNaiveH3Error(testCase.err) {
				t.Fatalf("a real fault must not be classified as an expected closure: %v", testCase.err)
			}
			// And the generic test must NOT already agree, or this case is not exercising the
			// typed-first requirement at all.
			if !errors.Is(testCase.err, net.ErrClosed) &&
				!errors.Is(testCase.err, io.EOF) &&
				!errors.Is(testCase.err, context.Canceled) {
				t.Logf("%s does not unwrap to a closed sentinel; it was already visible and is "+
					"pinned here only for completeness", testCase.name)
			}
		})
	}
}

// TestNaiveWrapErrorBoundaryClassification drives the tunnel error boundary directly.
func TestNaiveWrapErrorBoundaryClassification(t *testing.T) {
	t.Parallel()

	// An expected closure must not be reported as a fault at the routing layer.
	for _, expected := range []error{
		&quic.StreamError{ErrorCode: 268, Remote: true},
		&quic.TransportError{ErrorCode: quic.NoError},
		&quic.IdleTimeoutError{},
	} {
		got := normalizeNaiveStreamError(expected)
		if !E.IsClosedOrCanceled(got) {
			t.Fatalf("an expected closure must satisfy the routing layer's closed test: %v", expected)
		}
	}

	// A real fault must remain visible even wrapped by the shared quic wrapper.
	for _, fault := range []error{
		&quic.TransportError{ErrorCode: 0xa},
		&quic.StatelessResetError{},
		&quic.VersionNegotiationError{},
		&quic.ApplicationError{ErrorCode: 0x102},
	} {
		wrapped := qtls.WrapError(fault)
		if !errors.Is(wrapped, net.ErrClosed) {
			t.Fatalf("premise: %T is expected to leak net.ErrClosed through qtls.WrapError", fault)
		}
		got := normalizeNaiveStreamError(wrapped)
		if E.IsClosedOrCanceled(got) {
			t.Fatalf("the Naive error boundary silenced a real fault (%T): %v", fault, got)
		}
	}

	// A visible fault must not let errors.As reach the misleading quic-go type.
	got := normalizeNaiveStreamError(qtls.WrapError(&quic.TransportError{ErrorCode: 0xa}))
	var back *quic.TransportError
	if errors.As(got, &back) {
		t.Fatal("a visible fault must not expose the quic-go type, because that traversal is " +
			"one of the paths by which net.ErrClosed leaked in")
	}
	var fault *naiveVisibleFault
	if !errors.As(got, &fault) || fault.Cause() == nil {
		t.Fatal("the original error must remain reachable through Cause()")
	}
}

// TestNaiveServerConnectionFaultIsVisible covers the connection-level observability gap.
func TestNaiveServerConnectionFaultIsVisible(t *testing.T) {
	t.Parallel()

	recorder := &recordingLogger{}
	handler := naiveH3ServerLogHandler{logger: recorder}

	record := slog.NewRecord(zeroTime(), slog.LevelDebug, "handling connection failed", 0)
	record.AddAttrs(slog.Any("error", &quic.TransportError{ErrorCode: 0xa}))
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	errorsLogged, warnings, _ := recorder.snapshot()
	if len(errorsLogged) == 0 {
		t.Fatal("a connection-level fault must be operator-visible; otherwise it is discarded " +
			"inside quic-go exactly as it was before")
	}
	if len(warnings) != 0 {
		t.Fatalf("a fault must not be a warning: %v", warnings)
	}
}

// TestNaiveServerExpectedClosureStaysQuiet is the noise-control half.
func TestNaiveServerExpectedClosureStaysQuiet(t *testing.T) {
	t.Parallel()

	for _, expected := range []error{
		&quic.IdleTimeoutError{},
		&quic.TransportError{ErrorCode: quic.NoError},
		&http3.Error{ErrorCode: http3.ErrCodeNoError},
	} {
		recorder := &recordingLogger{}
		handler := naiveH3ServerLogHandler{logger: recorder}
		record := slog.NewRecord(zeroTime(), slog.LevelDebug, "handling connection failed", 0)
		record.AddAttrs(slog.Any("error", expected))
		if err := handler.Handle(context.Background(), record); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		errorsLogged, warnings, _ := recorder.snapshot()
		if len(errorsLogged) != 0 || len(warnings) != 0 {
			t.Fatalf("an expected closure must stay quiet: errors=%v warnings=%v",
				errorsLogged, warnings)
		}
	}
}

// TestNaiveServerLoggerOptional proves the logger is optional.
func TestNaiveServerLoggerOptional(t *testing.T) {
	t.Parallel()

	if got := newNaiveH3ServerLogger(nil); got != nil {
		t.Fatalf("a nil logger must yield a nil slog.Logger, got %v", got)
	}
	if got := newNaiveH3ServerLogger(&recordingLogger{}); got == nil {
		t.Fatal("a real logger must produce a usable slog.Logger")
	}
}

func zeroTime() (zero time.Time) { return }
