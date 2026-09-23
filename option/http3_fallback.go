package option

import (
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

// HTTP3FallbackOptions overrides the HTTP/3 -> earlier-version fallback backoff
// schedule. Every field is optional; when the whole object is absent the
// upstream behaviour (5m initial, doubling, 48h cap) is preserved verbatim.
//
// The schedule is applied per request authority, so one unreachable server does
// not push other servers off HTTP/3.
type HTTP3FallbackOptions struct {
	InitialBackoff badoption.Duration `json:"initial_backoff,omitempty"`
	MaxBackoff     badoption.Duration `json:"max_backoff,omitempty"`
	Multiplier     float64            `json:"multiplier,omitempty"`
	// ResetOnSuccess is a pointer so that "absent" (default true) is
	// distinguishable from an explicit false.
	ResetOnSuccess *bool `json:"reset_on_success,omitempty"`
}

const (
	upstreamH3InitialBackoff = 5 * time.Minute
	upstreamH3MaxBackoff     = 48 * time.Hour
	upstreamH3Multiplier     = 2.0
)

// Build resolves the option into a concrete schedule. A nil receiver yields the
// upstream schedule so that callers never need to branch on presence.
func (o *HTTP3FallbackOptions) Build() HTTP3FallbackSchedule {
	if o == nil {
		return HTTP3FallbackSchedule{
			InitialBackoff: upstreamH3InitialBackoff,
			MaxBackoff:     upstreamH3MaxBackoff,
			Multiplier:     upstreamH3Multiplier,
			ResetOnSuccess: true,
		}
	}
	schedule := HTTP3FallbackSchedule{
		InitialBackoff: time.Duration(o.InitialBackoff),
		MaxBackoff:     time.Duration(o.MaxBackoff),
		Multiplier:     o.Multiplier,
		ResetOnSuccess: true,
	}
	if o.ResetOnSuccess != nil {
		schedule.ResetOnSuccess = *o.ResetOnSuccess
	}
	if schedule.InitialBackoff <= 0 {
		schedule.InitialBackoff = upstreamH3InitialBackoff
	}
	if schedule.MaxBackoff <= 0 {
		schedule.MaxBackoff = upstreamH3MaxBackoff
	}
	// The multiplier must be >= 1. Exactly 1 means a fixed backoff; anything
	// below 1 would make the backoff shrink on every failure, which is not a
	// schedule, so it falls back to the default.
	if schedule.Multiplier < 1 {
		schedule.Multiplier = upstreamH3Multiplier
	}
	if schedule.MaxBackoff < schedule.InitialBackoff {
		schedule.MaxBackoff = schedule.InitialBackoff
	}
	return schedule
}

// HTTP3FallbackSchedule is the resolved form of HTTP3FallbackOptions.
type HTTP3FallbackSchedule struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
	ResetOnSuccess bool
}

// Next returns the backoff that follows the given one, clamped to MaxBackoff.
func (s HTTP3FallbackSchedule) Next(current time.Duration) time.Duration {
	if current <= 0 {
		return s.InitialBackoff
	}
	// multiplier == 1 means a FIXED backoff: the schedule stays at
	// initial_backoff and never escalates. This must be handled explicitly,
	// because a "next <= current implies overflow" guard would treat the
	// unchanged value as an error and jump straight to max_backoff.
	if s.Multiplier <= 1 {
		return s.InitialBackoff
	}
	next := time.Duration(float64(current) * s.Multiplier)
	// Guard against duration overflow or a multiplier that does not actually
	// grow the value. Both are treated as "already at the ceiling".
	if next <= current {
		return s.MaxBackoff
	}
	if next > s.MaxBackoff {
		return s.MaxBackoff
	}
	return next
}
