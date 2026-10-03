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
