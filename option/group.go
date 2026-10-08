package option

import "github.com/sagernet/sing/common/json/badoption"

type SelectorOutboundOptions struct {
	Outbounds                 []string `json:"outbounds" reference:"outbound"`
	Default                   string   `json:"default,omitempty" reference:"outbound"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type URLTestOutboundOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
	URL       string   `json:"url,omitempty"`
	// ExpectedStatus restricts which HTTP statuses count as reachable.
	//
	// Empty means no constraint, which is the historical behaviour: any response counts. A
	// configuration that needs a strict 204 says so explicitly, so an existing config is never
	// silently tightened.
	ExpectedStatus            string             `json:"expected_status,omitempty"`
	Interval                  badoption.Duration `json:"interval,omitempty"`
	Tolerance                 uint16             `json:"tolerance,omitempty"`
	IdleTimeout               badoption.Duration `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

// LoadBalanceOutboundOptions configures the loadbalance outbound group.
//
// # What this group is
//
// It distributes NEW flows over its members and keeps each flow on the member it was
// given. It does not bond, stripe or reassemble anything: one flow is one member for
// the flow's whole life, which is what keeps NAT, TLS and application state intact.
//
// # Strategy
//
// The default is round_robin, not the consistent-hashing default that Clash-derived
// clients use. Hashing on the destination sends every flow to the same site to the same
// member, which for a client whose traffic is concentrated on a few sites is the
// opposite of what the group is for. A configuration that wants the hashing behaviour
// states it.
type LoadBalanceOutboundOptions struct {
	Outbounds []string `json:"outbounds" reference:"outbound"`
	// Strategy selects how a member is chosen for a new flow:
	//
	//	round_robin        successive flows go to successive members (default)
	//	consistent_hashing flows to the same destination key keep the same member
	//	sticky_sessions    flows from the same source to the same destination keep the
	//	                   same member for a bounded time
	Strategy string `json:"strategy,omitempty"`
	// URL enables health-aware candidate filtering, using the same measurement the
	// urltest group uses. Empty disables it: with nothing measuring the members,
	// "no health entry" cannot mean "dead", so every member stays a candidate.
	URL string `json:"url,omitempty"`
	// ExpectedStatus restricts which HTTP statuses count as reachable, as in urltest.
	ExpectedStatus string `json:"expected_status,omitempty"`
	// Interval is the health re-check interval. Defaults to three minutes.
	Interval badoption.Duration `json:"interval,omitempty"`
	// Tolerance is accepted but unused for selection: it is a urltest notion of how much
	// slower a node may be and still be preferred, and a balancing group does not rank.
	Tolerance uint16 `json:"tolerance,omitempty"`
	// IdleTimeout stops the health checker after the group has been idle this long.
	IdleTimeout badoption.Duration `json:"idle_timeout,omitempty"`
	//
	// There is deliberately no failover option, and the always-on policy is narrow enough
	// not to need one: a failed attempt is replaced only when the failure proves the PATH to
	// the member is dead - a timeout or an unreachable network - which is exactly the case
	// in which no application byte can have reached the destination and a second member is
	// safe to try. A refusal, a reset or the caller's own cancellation is reported
	// unchanged. Bounding the retry to one alternate and reusing the caller's remaining
	// deadline is what keeps it a replacement for a dead path rather than a second attempt
	// at a live one.
	//
	// There is no knob because there is nothing to tune that a configuration could express
	// better than the code: the threshold, the alternate bound and the evidence that clears
	// a penalty are properties of the failure, not preferences.
}
