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
	// Failover enables the bounded retry and the live-dial failure ledger.
	//
	// # Why this is opt-in and not always-on
	//
	// Before this option existed the group made exactly one dial attempt per flow and never
	// recorded a failure, and an upgrade must not silently change which member carries a
	// flow. Turning the option on adds two observable behaviours: a second dial attempt
	// against one alternate when the first member's own path is provably broken, and the
	// penalty records that retry can accumulate until a member is demoted out of the primary
	// rotation. Both are visible to an operator, so neither may happen unless the
	// configuration asks for them.
	//
	// # What enabling it does not change
	//
	// The chosen member, the strategy and the health filter are untouched in the normal
	// case. A flow whose first dial succeeds makes exactly one attempt, and a success is
	// never second-guessed. round_robin still rotates, consistent_hashing still keeps the
	// bucket space fixed, and sticky_sessions still honours a pin; the retry is a
	// replacement for a dead path, not a second selection policy.
	//
	// # One budget for the whole flow
	//
	// The retry is bounded to ONE alternate for the entire flow, including a nested group's
	// own retry: a flow through two balancing groups makes at most two dial attempts in
	// total, not two per level. The budget is per-flow state created by the outermost
	// capability dial and consumed by every nested one, so nesting depth cannot multiply
	// the cost of one outage.
	Failover bool `json:"failover,omitempty"`
}
