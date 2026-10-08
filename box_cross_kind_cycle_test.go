package box_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	json "github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// Real-config regression tests for the DNS-transport <-> outbound cross-kind cycle.
//
// # Why these run through box.New/Start rather than a manager fixture
//
// The defect is a gap BETWEEN two managers, so a test that builds one of them cannot show it: each
// manager is correct about its own namespace. These tests take the configuration text a user would
// write, load it through the production registry (include.Context), and assert on what
// box.Start() reports - which is the only place the two graphs meet.
//
// # What was measured before the fix
//
// The cycle configurations below both returned START: <nil> on the unfixed tree, and the first dial
// through the SOCKS outbound then never returned: the outbound resolves its server through the DNS
// transport, whose detour dials the outbound again, and the DNS transport's connection pool blocks
// the re-entry on the slot the outer exchange holds. A hang, not a startup error. See
// adapter/outbound/cross_kind_cycle.go for the full analysis.
//
// # Why the acyclic case is the control that matters most
//
// Refusing this cycle is only an improvement if the configurations around it still start. The
// acyclic case has the same three edge kinds - a DNS transport with a detour, a proxy whose server
// is a domain, and a resolver tag - but the resolver points at a transport that does not detour
// back, so it is legal and must start.

// crossKindCycleConfig is the smallest configuration that closes the cycle:
//
//	dns/udp[remote] --detour--> outbound/socks[proxy]
//	outbound/socks[proxy] --domain_resolver--> dns/udp[remote]
const crossKindCycleConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "remote", "server": "1.1.1.1", "server_port": 53, "detour": "proxy"}
    ]
  },
  "outbounds": [
    {"type": "socks", "tag": "proxy", "server": "proxy.invalid", "server_port": 1080,
     "version": "5", "domain_resolver": "remote"}
  ]
}`

// crossKindSelectorCycleConfig closes the same cycle through a selector member, which is the shape
// neither per-kind sort can complete on its own: the DNS detour names the selector, and the closing
// edge belongs to the member the selector names.
const crossKindSelectorCycleConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "remote", "server": "1.1.1.1", "server_port": 53, "detour": "sel"}
    ]
  },
  "outbounds": [
    {"type": "selector", "tag": "sel", "outbounds": ["proxy"]},
    {"type": "socks", "tag": "proxy", "server": "proxy.invalid", "server_port": 1080,
     "version": "5", "domain_resolver": "remote"}
  ]
}`

// crossKindAcyclicConfig has every edge kind of the cycle and no cycle: the proxy's server is
// resolved by a second transport, and that transport has no detour.
const crossKindAcyclicConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "remote", "server": "1.1.1.1", "server_port": 53, "detour": "proxy"},
      {"type": "local", "tag": "bootstrap"}
    ]
  },
  "outbounds": [
    {"type": "socks", "tag": "proxy", "server": "proxy.invalid", "server_port": 1080,
     "version": "5", "domain_resolver": "bootstrap"}
  ]
}`

// newBoxFromConfig parses and constructs the instance, exactly as the CLI's config load and
// `sing-box check` do.
func newBoxFromConfig(t *testing.T, configContent string) (*box.Box, error) {
	t.Helper()
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(configContent))
	require.NoError(t, err, "the configuration must decode; a parse failure would make the start assertion meaningless")
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// TestCrossKindDNSCycleIsRefusedAtStartup is the contract: the configuration is rejected by
// box.Start(), naming the cycle, rather than being accepted and then hanging on the first dial.
func TestCrossKindDNSCycleIsRefusedAtStartup(t *testing.T) {
	for name, configContent := range map[string]string{
		"dns-through-outbound-back-to-dns": crossKindCycleConfig,
		"cycle-through-a-selector-member":  crossKindSelectorCycleConfig,
	} {
		t.Run(name, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, configContent)
			require.NoError(t, err, "construction alone cannot see the cycle; it is a start-order decision")
			t.Cleanup(func() { _ = instance.Close() })

			err = instance.Start()
			require.Error(t, err, "a cross-kind cycle must be refused at startup, not at the first dial")
			require.Contains(t, err.Error(), "circular dependency between DNS server and outbound",
				"the failure must name the cycle so an operator can find it; anything else leaves a "+
					"configuration that starts and then never returns a connection")
		})
	}
}

// TestCrossKindAcyclicConfigStillStarts is the negative control.
func TestCrossKindAcyclicConfigStillStarts(t *testing.T) {
	instance, err := newBoxFromConfig(t, crossKindAcyclicConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	require.NoError(t, instance.Start(),
		"a legal configuration with a DNS detour, a domain server and an explicit resolver must start")
}
