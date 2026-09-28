package option

import (
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// NaiveServerLimitsOptions bounds the resources a peer can hold on a Native Naive
// inbound BEFORE it has authenticated.
//
// # Why this is a separate option from unauthenticated_limits
//
// unauthenticated_limits already exists on the HTTP inbound and bounds
// pre-authentication REQUESTS. Naive needs the same protection, but it cannot
// simply reuse that field for two reasons:
//
//  1. The Naive path has no request-per-connection relationship to rate limit.
//     A Naive client opens ONE connection and keeps it for the life of a tunnel,
//     so a per-request token bucket is the wrong instrument. What matters here is
//     how many connections a peer may hold open at once.
//
//  2. The measured exposure is different. See the lifecycle audit: the unbounded
//     stages are "TLS completed then silence", "headers that never finish" and
//     "an HTTP/2 connection that never opens a stream". None of those is a
//     request-rate problem; all of them are a connection-lifetime problem.
//
// The semantics deliberately mirror unauthenticated_limits where they overlap
// (per-IP keying on the real transport peer, bounded map, idle expiry) so an
// operator has one mental model rather than two.
//
// # Everything here defaults to disabled
//
// A zero or omitted value means "preserve the existing behaviour exactly", which
// for this inbound is unlimited. No default limit is applied: the production
// topology serves long-lived tunnels from real users, and a limit chosen without
// measuring that deployment's concurrency would be a guess that silently breaks
// traffic. See docs/JIEJIE-NAIVE-RESOURCE-CONTROLS.md.
type NaiveServerLimitsOptions struct {
	// MaxConnections caps total concurrent connections on this inbound,
	// authenticated or not.
	//
	// This is the only bound that covers the whole listener. It is deliberately
	// separate from the per-IP limit because they defend different things: this
	// one bounds the host's total exposure, the per-IP one bounds a single
	// offender.
	MaxConnections int `json:"max_connections,omitempty"`
	// MaxConnectionsPerIP caps concurrent connections from one source address.
	//
	// The key is the REAL transport peer (request.RemoteAddr), never a forwarded
	// header: a client that can name its own source address can trivially evade a
	// per-IP limit, so honouring X-Forwarded-For here would make the limit
	// decorative.
	MaxConnectionsPerIP int `json:"max_connections_per_ip,omitempty"`
	// NOTE: there is deliberately no handshake_timeout here.
	//
	// The TLS options already provide one (tls.handshake_timeout), and the
	// lifecycle audit verified it works: with handshake_timeout=3s a peer that
	// opens TCP and never sends a ClientHello is disconnected. Adding a second
	// field for the same phase would give an operator two controls that overlap
	// and can disagree, so this struct does not duplicate it.
	//
	// Its scope is worth stating because it is narrower than it appears: it covers
	// a peer that stalls DURING the handshake, and does NOT cover a peer that
	// finishes the handshake and then goes silent. HeaderTimeout below is the
	// control for that second case.
	// HeaderTimeout bounds how long a connection may take to deliver a COMPLETE
	// request once the handshake is done. This is the control for the measured
	// "TLS completes, then silence" and "headers never finish" stages.
	//
	// It applies to the request phase only. An established tunnel is never
	// subject to it: a tunnel that is legitimately idle for longer than this --
	// which long-lived connections routinely are -- must not be torn down.
	HeaderTimeout badoption.Duration `json:"header_timeout,omitempty"`
	// IdleTimeout closes a connection that has carried no traffic for this long.
	//
	// This one DOES apply to established tunnels, so it is the setting most
	// likely to break working traffic if chosen carelessly: an idle-timeout
	// shorter than the quiet periods of a normal session will disconnect healthy
	// clients. It is therefore off unless explicitly set, and the zero value must
	// be understood as "never".
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`
	// MaxTrackedIPs caps how many distinct source addresses the per-IP limiter
	// remembers. It is the defence against an attacker filling the limiter's own
	// map with random addresses, which is why it exists even though the map is
	// otherwise bounded by idle expiry.
	MaxTrackedIPs int `json:"max_tracked_ips,omitempty"`
}

// NaiveServerLimits is the resolved form of the option.
type NaiveServerLimits struct {
	MaxConnections      int
	MaxConnectionsPerIP int
	HeaderTimeout       time.Duration
	IdleTimeout         time.Duration
	MaxTrackedIPs       int
}

const (
	// DefaultNaiveMaxTrackedIPs bounds limiter memory when a per-IP limit is
	// configured without choosing a cap. It matches the HTTP inbound's default so
	// the two limiters cannot disagree about what "bounded" means.
	DefaultNaiveMaxTrackedIPs = 4096
	// DefaultNaiveLimiterIdleTimeout is how long an idle limiter ENTRY (not a
	// connection) is remembered. Short, because the entry only needs to outlive
	// the connection that created it.
	DefaultNaiveLimiterIdleTimeout = 10 * time.Second
)

// Enabled reports whether any limit is configured. A disabled limiter must
// behave exactly as if it were absent, including allocating no map.
func (o *NaiveServerLimitsOptions) Enabled() bool {
	if o == nil {
		return false
	}
	return o.MaxConnections > 0 ||
		o.MaxConnectionsPerIP > 0 ||
		o.HeaderTimeout > 0 ||
		o.IdleTimeout > 0
}

// Build resolves the option. A nil or all-zero receiver yields the zero value,
// which callers read as "no limits", so an unconfigured inbound is unchanged.
func (o *NaiveServerLimitsOptions) Build() NaiveServerLimits {
	if o == nil {
		return NaiveServerLimits{}
	}
	limits := NaiveServerLimits{
		MaxConnections:      o.MaxConnections,
		MaxConnectionsPerIP: o.MaxConnectionsPerIP,
		HeaderTimeout:       o.HeaderTimeout.Build(),
		IdleTimeout:         o.IdleTimeout.Build(),
		MaxTrackedIPs:       o.MaxTrackedIPs,
	}
	if limits.MaxConnectionsPerIP > 0 && limits.MaxTrackedIPs <= 0 {
		limits.MaxTrackedIPs = DefaultNaiveMaxTrackedIPs
	}
	return limits
}

// Validate rejects values that cannot be honoured, so a mistyped limit fails at
// configuration time rather than silently doing something else.
func (o *NaiveServerLimitsOptions) Validate() error {
	if o == nil {
		return nil
	}
	if o.MaxConnections < 0 {
		return E.New("max_connections must not be negative")
	}
	if o.MaxConnectionsPerIP < 0 {
		return E.New("max_connections_per_ip must not be negative")
	}
	if o.MaxTrackedIPs < 0 {
		return E.New("max_tracked_ips must not be negative")
	}
	if o.HeaderTimeout < 0 {
		return E.New("header_timeout must not be negative")
	}
	if o.IdleTimeout < 0 {
		return E.New("idle_timeout must not be negative")
	}
	// A per-IP limit larger than the global one can never be reached, which
	// almost always means one of the two was mistyped. It is rejected rather than
	// silently clamped so the operator learns their configuration does not mean
	// what they think.
	if o.MaxConnections > 0 && o.MaxConnectionsPerIP > o.MaxConnections {
		return E.New("max_connections_per_ip (", o.MaxConnectionsPerIP,
			") exceeds max_connections (", o.MaxConnections,
			"), so it could never take effect")
	}
	return nil
}
