package box_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Rules that do NOT constrain the network must not become a requirement that every network is
// delivered (P4).
//
// # Why this is the dangerous direction
//
// `deliveredNetworksFromRoutes` (box.go) proves delivery only from a rule with an EXPLICIT network
// condition. Every other shape - a plain rule with no `network:`, `route.final`, a logical rule, an
// inverted rule - proves nothing, and "nothing proven" has to stay "nothing proven". Reading it as
// "both networks" is the mistake that once made one unrelated TCP+UDP outbound responsible for UDP
// everywhere else and refused configurations that had always started.
//
// The other half matters equally: where the configuration DOES prove a network reaches an object
// that cannot carry it, the answer must be a definite refusal naming the object - not an "unknown"
// that reads as "not checked". A verdict that can be neither confirmed nor denied is not a pass.

// TestFinalProvesNothingAboutDelivery covers `route.final`.
//
// `final` receives everything no rule matched, which is every network, so it is left unproven rather
// than read as both. A TCP-only outbound set as `final` must therefore start.
func TestFinalProvesNothingAboutDelivery(t *testing.T) {
	t.Parallel()

	instance, err := newBoxFromConfig(t, `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ],
  "route": {"final": "tcp-only"}
}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	require.NoError(t, instance.Start(),
		"`route.final` proves nothing about which networks arrive, so it must not make a TCP-only "+
			"outbound responsible for UDP")
}

// TestALogicalRuleProvesNothingAboutDelivery covers a logical rule.
//
// A logical rule's conditions are a tree whose network constraints are an intersection the helper
// deliberately does not evaluate - summarising it would be a second routing engine. Its outbound is
// therefore unproven, and an unproven outbound must not be failed for a network nothing proved.
func TestALogicalRuleProvesNothingAboutDelivery(t *testing.T) {
	t.Parallel()

	instance, err := newBoxFromConfig(t, `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"type": "logical", "mode": "and", "rules": [{"domain": ["example.com"]}],
       "outbound": "tcp-only"}
    ]
  }
}`)
	require.NoError(t, err)
	require.NoError(t, instance.Start(),
		"a logical rule's network constraints are not evaluated, so they prove nothing, and "+
			"nothing proven must not become a both-networks requirement")
	t.Cleanup(func() { _ = instance.Close() })
}

// TestAnInvertedRuleProvesNothingAboutDelivery covers an inverted rule, which matches the complement
// of its conditions and can therefore match any network.
func TestAnInvertedRuleProvesNothingAboutDelivery(t *testing.T) {
	t.Parallel()

	instance, err := newBoxFromConfig(t, `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"invert": true, "domain": ["example.com"], "outbound": "tcp-only"}
    ]
  }
}`)
	require.NoError(t, err)
	require.NoError(t, instance.Start(),
		"an inverted rule matches the complement of its conditions, so it constrains nothing "+
			"about the network and must not become a requirement")
	t.Cleanup(func() { _ = instance.Close() })
}

// TestAProvenNetworkIsRefusedDefinitelyAndNotLeftUnverified is the other half.
//
// The rule proves TCP reaches a network-blind selector, and one of that selector's members declares
// udp-only. The verdict must be a definite refusal that names the member - never an "unknown", which
// a reader can only interpret as "not checked".
func TestAProvenNetworkIsRefusedDefinitelyAndNotLeftUnverified(t *testing.T) {
	t.Parallel()

	instance, err := newBoxFromConfig(t, `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "dual", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "udp-only", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "udp"},
    {"type": "selector", "tag": "sel", "outbounds": ["dual", "udp-only"], "default": "dual"}
  ],
  "route": {
    "rules": [
      {"network": "tcp", "outbound": "sel"}
    ]
  }
}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	err = instance.Start()
	require.Error(t, err,
		"the route proves TCP reaches a selector that does not filter, so its udp-only member is "+
			"reachable by a TCP flow and the configuration cannot work")
	require.Contains(t, err.Error(), "udp-only",
		"the refusal must name the member that cannot carry the flow")
	require.Contains(t, err.Error(), "cannot serve the tcp flow",
		"and it must state the definite reason rather than leaving the member unverified")
	require.NotContains(t, err.Error(), "unknown",
		"a proven defect must not be reported as an unknown")
}

// TestAProvenNetworkLeavesTheCapableMemberAlone is the positive control: proving TCP reaches a
// selector must not fail the member that CAN carry TCP.
func TestAProvenNetworkLeavesTheCapableMemberAlone(t *testing.T) {
	t.Parallel()

	instance, err := newBoxFromConfig(t, `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"},
    {"type": "selector", "tag": "sel", "outbounds": ["tcp-only"], "default": "tcp-only"}
  ],
  "route": {
    "rules": [
      {"network": "tcp", "outbound": "sel"}
    ]
  }
}`)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	require.NoError(t, instance.Start(),
		"TCP is the only network the route proves, and every member carries it, so this must start")
}
