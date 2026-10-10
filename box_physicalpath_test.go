package box_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Box-level tests for the start-time reachable-leaf dry run and the destination-DNS-ownership
// coherence check.
//
// # Why these run through the real configuration loader
//
// The dry run reads three facts that exist only in the CONFIGURATION TEXT - which tags declared
// `destination_dns_ownership`, which member lists a group has, and how a domain resolver is derived
// for an outbound - and it is installed by box.New. A unit test cannot show that the facts reach it:
// it would have to construct the same wiring the Box does, which is the thing under test. These
// tests therefore load the JSON a user would write through the production registry and assert on
// what box.Start() reports.
//
// The existing cross-kind cycle tests in box_cross_kind_cycle_test.go are the model, and this file
// deliberately reuses their helper: the two checks are neighbours in the start sequence and a
// second loader would be a second thing to keep in step.

// physicalPathSelectorConfig is the smallest configuration with a group whose SECOND member cannot
// carry the flow the first member carries. The selector's current default is the healthy member, so
// every flow works until the group switches - which is exactly the failure the dry run exists to
// move to Start.
//
// `"network": "udp"` on the second SOCKS outbound is what makes it UDP-only: NetworkList.Build
// returns exactly the listed networks, and the default is both.
const physicalPathSelectorConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "healthy", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "udp-only", "server": "127.0.0.1", "server_port": 1081, "version": "5",
     "network": "udp"},
    {"type": "selector", "tag": "sel", "outbounds": ["healthy", "udp-only"], "default": "healthy"}
  ]
}`

// physicalPathLegalConfig is the negative control: the same shape with every member usable.
const physicalPathLegalConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["a", "b"], "default": "a"}
  ]
}`

// physicalPathOwnershipOnCapableTypeConfig declares destination_dns_ownership on a SOCKS outbound,
// which implements it, and gives it a resolver. This is the coherent configuration.
const physicalPathOwnershipOnCapableTypeConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "local", "tag": "local"}
    ]
  },
  "outbounds": [
    {"type": "socks", "tag": "owned", "server": "127.0.0.1", "server_port": 1080, "version": "5",
     "destination_dns_ownership": true, "domain_resolver": "local"}
  ]
}`

// physicalPathOwnershipOnIncapableTypeConfig declares the same thing on an outbound type that does
// not read the field. At run time the destination domain would travel to the peer while the
// configuration says it must not - silently, which is the failure the check exists to convert into
// a start error.
const physicalPathOwnershipOnIncapableTypeConfig = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "local", "tag": "local"}
    ]
  },
  "outbounds": [
    {"type": "trojan", "tag": "owned", "server": "127.0.0.1", "server_port": 443,
     "password": "password", "destination_dns_ownership": true, "domain_resolver": "local"}
  ]
}`

// TestPhysicalPathDryRunRefusesAnUnusableUnselectedMember is the property the dry run adds,
// asserted through Start.
//
// The selector's default is the healthy member, so the group is usable RIGHT NOW and every flow
// succeeds until the group switches - which a health check or a user action decides, with no
// configuration change. Start therefore has to refuse it, and the message has to name the route.
func TestPhysicalPathDryRunRefusesAnUnusableUnselectedMember(t *testing.T) {
	instance, err := newBoxFromConfig(t, physicalPathSelectorConfig)
	require.NoError(t, err, "construction cannot see this: it is a start-time decision")
	t.Cleanup(func() { _ = instance.Close() })

	err = instance.Start()
	require.Error(t, err,
		"an unselected member that cannot carry the flow must fail Start, not the first switch to it")
	require.Contains(t, err.Error(), "udp-only", "the failure must name the member")
	require.Contains(t, err.Error(), "sel", "and the group that would switch to it")
	require.Contains(t, err.Error(), "cannot serve the tcp flow",
		"and must say what is wrong with it rather than only that it is unsupported")
	require.Contains(t, err.Error(), "outbound/sel",
		"and must name the root whose flow it would carry")
}

// TestLegalPhysicalPathConfigurationStillStarts is the compatibility control.
//
// The dry run adds a start-time rejection, so the property that matters most about it is that it
// does not reject what already worked. This configuration has a group, a two-member leaf list, and
// no declaration the objects cannot honour.
func TestLegalPhysicalPathConfigurationStillStarts(t *testing.T) {
	instance, err := newBoxFromConfig(t, physicalPathLegalConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	require.NoError(t, instance.Start(),
		"a selector whose every member can carry the flow must keep starting: the dry run must not "+
			"become a compatibility regression")
}

// TestDestinationDNSOwnershipOnACapableTypeStarts pins that the coherence check accepts the
// configuration it was written for.
func TestDestinationDNSOwnershipOnACapableTypeStarts(t *testing.T) {
	instance, err := newBoxFromConfig(t, physicalPathOwnershipOnCapableTypeConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	require.NoError(t, instance.Start(),
		"a SOCKS outbound declares destination_dns_ownership and has a resolver: the declaration and "+
			"the object agree, so start must succeed")
}

// TestDestinationDNSOwnershipOnAnIncapableTypeIsRefusedAtStart is the new rejection.
//
// The declaration is a promise about what the peer receives. An outbound type that never reads the
// field breaks that promise silently, so the configuration is refused where an operator can see it
// rather than at the first connection to a name.
func TestDestinationDNSOwnershipOnAnIncapableTypeIsRefusedAtStart(t *testing.T) {
	instance, err := newBoxFromConfig(t, physicalPathOwnershipOnIncapableTypeConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	err = instance.Start()
	require.Error(t, err,
		"declaring destination_dns_ownership on a type that does not implement it must be refused "+
			"at start, not discovered as a leaked destination name")
	require.Contains(t, err.Error(), "destination_dns_ownership")
	require.Contains(t, err.Error(), "does not implement it")
	require.Contains(t, err.Error(), "outbound/owned",
		"the failure must name the offending route")
}
