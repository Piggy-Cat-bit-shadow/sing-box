package urltest

import (
	"time"

	"github.com/sagernet/sing/common/logger"
)

// urlTestDebugLogger is set once by the box, when debug logging is enabled.
//
// A package-level variable is acceptable here because there is exactly one logger per process
// and it is write-once during startup; the alternative - threading a logger through every
// caller - would change signatures for a diagnostic that is not part of the measurement.
var (
	urlTestDebugLogger logger.Logger
	commonLogDebug     bool
)

// SetDebugLogger enables the per-measurement diagnostic line.
//
// It is deliberately NOT wired into the hot path of connection handling: it affects only
// URLTest, which runs once per measurement.
func SetDebugLogger(logger logger.Logger, enabled bool) {
	urlTestDebugLogger = logger
	commonLogDebug = enabled
}

// debugURLTest records the two phases of a measurement.
//
// It does not claim the connection was reused: that cannot be observed from here without
// instrumenting the transport, and reporting an unverified `reused=true` would be worse than
// reporting nothing.
func debugURLTest(first time.Duration, warm time.Duration, warmSucceeded bool) {
	if urlTestDebugLogger == nil {
		return
	}
	if warmSucceeded {
		urlTestDebugLogger.Debug("urltest first_request=", first,
			" warm_request=", warm, " warm_reused=assumed")
		return
	}
	urlTestDebugLogger.Debug("urltest first_request=", first,
		" warm_request=failed", " fallback=first_path")
}
