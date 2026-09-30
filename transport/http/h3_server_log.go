//go:build with_quic

package http

import (
	"context"
	"log/slog"

	"github.com/sagernet/sing/common/logger"
)

// h3ServerLogHandler surfaces connection-level HTTP/3 and QUIC faults that would otherwise be
// swallowed inside quic-go.
//
// # The observability gap this closes
//
// http3.Server handles each connection on its own goroutine:
//
//	go func() {
//	    if err := s.handleConn(conn); err != nil {
//	        if s.Logger != nil {
//	            s.Logger.Debug("handling connection failed", "error", err)
//	        }
//	    }
//	}()
//
// and http3.Server.ServeListener returns ONLY http.ErrServerClosed on graceful shutdown or the
// listener's own Accept error. A connection-level fault therefore never reaches the
// `ServeListener` return value that sing-box classifies, and with Logger unset it is discarded
// entirely: an operator sees nothing at any level.
//
// # Why an adapter rather than redirecting debug output
//
// quic-go's messages are structured records, not a decision. Piping all of them through as
// sing-box ERROR would trade a silent gap for log flooding, and piping them as DEBUG would leave
// real faults invisible again. So the adapter re-applies the SAME typed classification the rest
// of this package uses: an error that carries quic-go or HTTP/3 semantics is decided by its type
// and code, and only a genuine fault is raised.
//
// # Noise control
//
// Only records at DEBUG level or above are considered, and only the connection-failure message
// carries an error to classify. Everything else is dropped: this exists to make faults visible,
// not to mirror the library's internal logging.
type h3ServerLogHandler struct {
	logger logger.Logger
	// component names the listener in the emitted message, so an operator can tell which
	// service produced it when several share a process.
	component string
}

func (h h3ServerLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Accept everything slog offers; the filtering that matters happens in Handle, which can see
	// the error value and the message.
	return level >= slog.LevelDebug
}

func (h h3ServerLogHandler) Handle(_ context.Context, record slog.Record) error {
	if h.logger == nil {
		return nil
	}
	// Only the connection-failure record carries a classifiable error. Other records are
	// library-internal detail and are deliberately not mirrored.
	const connectionFailure = "handling connection failed"
	if record.Message != connectionFailure {
		return nil
	}

	var failure error
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "error" && attr.Value.Any() != nil {
			if asError, isError := attr.Value.Any().(error); isError {
				failure = asError
			}
			return false
		}
		return true
	})
	if failure == nil {
		return nil
	}

	// The SAME classification the rest of the package uses. typed semantics first, then the
	// generic closed/canceled tests, then fault.
	if isExpectedH3Closure(failure) {
		h.logger.Debug(h.component+" connection closed: ", failure)
		return nil
	}

	h.logger.Error(h.component+" connection failed: ", failure)
	return nil
}

func (h h3ServerLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h h3ServerLogHandler) WithGroup(_ string) slog.Handler      { return h }

// newH3ServerLogger builds the slog.Logger handed to http3.Server so connection-level faults
// reach the operator.
//
// A nil logger returns nil, which leaves http3.Server with its default of no logging: an
// unconfigured caller keeps the previous behaviour rather than acquiring a logger it did not ask
// for.
func newH3ServerLogger(lifecycleLogger logger.Logger, component string) *slog.Logger {
	if lifecycleLogger == nil {
		return nil
	}
	return slog.New(h3ServerLogHandler{logger: lifecycleLogger, component: component})
}
