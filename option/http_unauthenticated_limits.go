package option

import (
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

// UnauthenticatedLimitsOptions bounds what an unauthenticated peer can consume
// on a publicly exposed inbound. It applies only before authentication
// succeeds, and only on the masquerade / auth-failure paths: authenticated
// proxy traffic is never limited by this.
type UnauthenticatedLimitsOptions struct {
	Enabled            bool               `json:"enabled,omitempty"`
	MaxConcurrentPerIP int                `json:"max_concurrent_per_ip,omitempty"`
	RequestsPerSecond  float64            `json:"requests_per_second,omitempty"`
	Burst              int                `json:"burst,omitempty"`
	IdleTimeout        badoption.Duration `json:"idle_timeout,omitempty"`
	// MaxTrackedIPs caps how many distinct source IPs are remembered. It is
	// the defence against an attacker filling the limiter map itself with
	// random addresses.
	MaxTrackedIPs int `json:"max_tracked_ips,omitempty"`
}

const (
	// DefaultUnauthenticatedMaxTrackedIPs bounds limiter memory when the user
	// enables the limiter without choosing a cap.
	DefaultUnauthenticatedMaxTrackedIPs = 4096
	DefaultUnauthenticatedIdleTimeout   = 10 * time.Second
	DefaultUnauthenticatedMaxConcurrent = 8
	DefaultUnauthenticatedRPS           = 10.0
	DefaultUnauthenticatedBurst         = 20
)

// UnauthenticatedLimits is the resolved form of the option.
type UnauthenticatedLimits struct {
	Enabled            bool
	MaxConcurrentPerIP int
	RequestsPerSecond  float64
	Burst              int
	IdleTimeout        time.Duration
	MaxTrackedIPs      int
}

// Build resolves the option, filling documented defaults. A nil receiver or a
// disabled limiter yields Enabled=false, which callers treat as "no limiter".
func (o *UnauthenticatedLimitsOptions) Build() UnauthenticatedLimits {
	if o == nil || !o.Enabled {
		return UnauthenticatedLimits{}
	}
	limits := UnauthenticatedLimits{
		Enabled:            true,
		MaxConcurrentPerIP: o.MaxConcurrentPerIP,
		RequestsPerSecond:  o.RequestsPerSecond,
		Burst:              o.Burst,
		IdleTimeout:        time.Duration(o.IdleTimeout),
		MaxTrackedIPs:      o.MaxTrackedIPs,
	}
	if limits.MaxConcurrentPerIP <= 0 {
		limits.MaxConcurrentPerIP = DefaultUnauthenticatedMaxConcurrent
	}
	if limits.RequestsPerSecond <= 0 {
		limits.RequestsPerSecond = DefaultUnauthenticatedRPS
	}
	if limits.Burst <= 0 {
		limits.Burst = DefaultUnauthenticatedBurst
	}
	if limits.IdleTimeout <= 0 {
		limits.IdleTimeout = DefaultUnauthenticatedIdleTimeout
	}
	if limits.MaxTrackedIPs <= 0 {
		limits.MaxTrackedIPs = DefaultUnauthenticatedMaxTrackedIPs
	}
	return limits
}
