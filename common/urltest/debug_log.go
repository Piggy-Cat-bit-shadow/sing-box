package urltest

import (
	"sync/atomic"

	"github.com/sagernet/sing/common/logger"
)

// debugConfig is the URLTest diagnostic configuration.
//
// It is stored behind a single atomic pointer rather than as separate flag and logger variables
// because the two are read together: a measurement that observed the new enabled flag alongside
// the old logger would log through a logger the operator had just replaced. One pointer means one
// generation, so a reader can never see half of an update.
type debugConfig struct {
	logger  logger.Logger
	enabled bool
}

// currentDebugConfig holds the active configuration. It is written once during box setup and read
// once per measurement, never on a packet path.
var currentDebugConfig atomic.Pointer[debugConfig]

// SetDebugLogger installs the diagnostic logger.
//
// Passing a nil logger, or enabled false, disables the diagnostic line.
func SetDebugLogger(log logger.Logger, enabled bool) {
	currentDebugConfig.Store(&debugConfig{logger: log, enabled: enabled})
}
