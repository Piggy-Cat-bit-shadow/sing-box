package oomkiller

import (
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/log"
)

// Test fixtures for the adaptive timer, on every platform.
//
// # Why this is not in a darwin-only file
//
// newPressureTestTimer was defined in timer_darwin_test.go, which is built only for darwin
// with cgo. The interval ladder it exercises is not platform-specific, so a cross-platform
// test that used it failed to COMPILE on Linux - which is exactly what the low-memory gate
// caught. A test helper should live with the code it supports, not with the platform whose
// other tests happen to need it.

func newPressureTestTimer(pressure *atomic.Uint32) *adaptiveTimer {
	// network and connections are nil, which poll() already handles: it guards both with a
	// nil check before use. That keeps tests about timing rather than about faking a network
	// stack.
	return newAdaptiveTimer(
		log.NewNOPFactory().Logger(),
		nil,
		nil,
		nil,
		nil,
		pressure,
		timerConfig{
			policyMode:   policyModeNetworkExtension,
			minInterval:  10 * time.Millisecond,
			maxInterval:  time.Second,
			memoryLimit:  50 * 1024 * 1024,
			safetyMargin: 5 * 1024 * 1024,
		},
	)
}
