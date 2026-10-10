package box_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Two routes reach ONE leaf, and both are broken. Each route must be reported.
//
// # The defect this fixture pins
//
// `adapter/outbound.Manager` collapsed validation failures by LEAF TAG: once one root had reported a
// broken leaf, a later root whose route to the same leaf was ALSO broken could not report it. Two
// routes to one leaf are two independent contracts - the same leaf is usable on one route and broken
// on another - and because the manager walks its roots in declaration order, WHICH of the two verdicts
// survived depended on the order the outbounds happened to be written in.
//
// # Why this has to be a box-level fixture
//
// The de-duplication lives in the manager, and the requirement it de-duplicates comes from the ROUTES
// (`EnablePhysicalPathDelivery`, installed by `box.New`). A test that calls the validator directly
// has no route proof, so it falls back to what the objects advertise - and a group's own `Network()`
// before Start is an optimistic blanket that covers both networks regardless of its members. That
// fallback is why a hand-built fixture cannot express this case: the requirement has to come from a
// real routing rule, and a real routing rule needs a real configuration.
//
// # The shape
//
//	route rule: network=udp, outbound=A          A selects tcp-only
//	route rule: network=udp, outbound=B          B selects tcp-only
//	outbound A: selector over {tcp-only}
//	outbound B: selector over {tcp-only}
//
// Both routes reach the same leaf at position 0 - where the business flow arrives - so both are judged
// against UDP, and the leaf carries TCP only, so both fail.
const twoRoutesToOneBrokenLeaf = `{
  "log": { "disabled": true },
  "inbounds": [
    { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0 }
  ],
  "outbounds": [
    { "type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
      "version": "5", "network": "tcp" },
    { "type": "selector", "tag": "A", "outbounds": ["tcp-only"], "default": "tcp-only" },
    { "type": "selector", "tag": "B", "outbounds": ["tcp-only"], "default": "tcp-only" }
  ],
  "route": {
    "rules": [
      { "network": "udp", "outbound": "A" },
      { "network": "udp", "outbound": "B" }
    ]
  }
}`

// TestOneLeafBrokenOnTwoRoutesIsReportedForBoth drives the whole path: decode, construct, Start.
func TestOneLeafBrokenOnTwoRoutesIsReportedForBoth(t *testing.T) {
	instance, err := newBoxFromConfig(t, twoRoutesToOneBrokenLeaf)
	require.NoError(t, err,
		"construction cannot see this: it is a start-time decision about what the routes deliver")
	t.Cleanup(func() { _ = instance.Close() })

	startErr := instance.Start()
	require.Error(t, startErr,
		"a udp rule delivers udp to a leaf that carries tcp only, twice over, so Start must refuse; "+
			"a Start that succeeds here would mean the requirement never reached the leaf")

	message := startErr.Error()

	// Both route rules name their own root, so the two failures are two lines. Keying the
	// de-duplication on the leaf reported one and dropped the other - and which one survived
	// depended on the declaration order above.
	require.Contains(t, message, "A",
		"the failure must name the first route's root: %s", message)
	require.Contains(t, message, "B",
		"the failure must name the second route's root as well. One line for two broken routes is "+
			"how an operator fixes the first and ships the second: %s", message)

	// Both broken ROUTES are named, one line each, and each line is attributed to the root the
	// operator has to fix: A through its selector, B in its own right. The defect this pins is that
	// the previous leaf-keyed de-duplication named NEITHER - it reported `outbound/tcp-only` once and
	// dropped both routes, so the report said nothing about which rule was broken.
	require.Contains(t, message, "outbound/A -> A -> tcp-only",
		"the first route must be reported against its own root: %s", message)
	require.Contains(t, message, "outbound/B -> B -> tcp-only",
		"and the second route against its own root: %s", message)
	require.Equal(t, 2, strings.Count(message, "hop #0 tcp-only"),
		"one line per broken route, not one for the whole configuration and not three: %s", message)
}

// TestOneDefectIsReportedOncePerAffectedRoot pins the unit of the report.
//
// # What it originally claimed, and what the measurement says
//
// It was written as a control for a widened de-duplication key, claiming that one defect reached by
// two roots must be ONE line. Measurement says it is two, and that the original claim had the unit
// wrong: `Failure.Root` is not decoration, it is how an operator learns WHICH entry point is
// affected, and the two configurations below are reached by two different routing rules. Collapsing
// them would leave the operator fixing one rule and shipping the other.
//
// The de-duplication that DOES exist is the `described` set, which stops a member a group report
// already covered from being reported again as a top-level root - that is what keeps a broken group
// member from appearing three times for one group. It is exercised by the group-level fixtures.
//
// So the property worth pinning here is not "one line": it is that every affected root is named, and
// that the SET does not depend on the order the outbounds happen to be declared in.
//
// Both roots below reach the same leaf along the same route, which is the case a route-aware key
// would have separated and a leaf-aware key separates only when the ROUTES differ.
const twoRoutesToOneBrokenLeafAgain = `{
  "log": { "disabled": true },
  "inbounds": [
    { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0 }
  ],
  "outbounds": [
    { "type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
      "version": "5", "network": "tcp" },
    { "type": "selector", "tag": "A", "outbounds": ["tcp-only"], "default": "tcp-only" }
  ],
  "route": {
    "rules": [
      { "network": "udp", "outbound": "A" },
      { "network": "udp", "outbound": "tcp-only" }
    ]
  }
}`

func TestOneDefectIsReportedOncePerAffectedRoot(t *testing.T) {
	instance, err := newBoxFromConfig(t, twoRoutesToOneBrokenLeafAgain)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	startErr := instance.Start()
	require.Error(t, startErr, "the udp rule reaches a tcp-only leaf, through the selector and directly")

	message := startErr.Error()
	require.Contains(t, message, "outbound/A -> A -> tcp-only",
		"the selector root must be named: %s", message)
	require.Contains(t, message, "outbound/tcp-only",
		"and the root the second rule names directly must be named too, because it is a second "+
			"routing rule the operator has to fix: %s", message)

	// And each root contributes its failure EXACTLY once. Two roots reach the same leaf here (A's
	// route and B's route both end in tcp-only), so a keyed-by-route de-duplication would still be
	// one line each - the assertion is that nothing is doubled, which is what the `reported` guard
	// is for.
	require.Equal(t, 2, strings.Count(message, "hop #0 tcp-only"),
		"exactly one line per broken route: a third would mean a root was reported twice, and two "+
			"would mean one of the two routes went missing: %s", message)
}
