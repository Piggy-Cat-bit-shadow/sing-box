package box_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// START-01: the start-time dry run's network requirement, decided through the REAL loader.
//
// # Why the fixtures are configuration text and the assertion is Start()
//
// The claim under test is not "the helper returns this set" but "a configuration a user can write
// does or does not start". `validatePhysicalPaths` is installed by box.New and fed by box.go, so a
// unit test on the helper would have to rebuild that wiring - which is the thing being decided.
// These fixtures therefore go through the production registry exactly as the CLI does.
//
// # The two independent ways the requirement was inflated
//
//  1. `requiredNetworksFor` unioned the `Network()` of EVERY outbound in the file, and handed the
//     union to every root. One TCP+UDP outbound anywhere in the file therefore made every other
//     root - and every hop of every chain under it - responsible for UDP.
//  2. The union also read GROUPS, whose `Network()` before Start is an optimistic blanket:
//     Selector.Network() returns {tcp,udp} while nothing is selected (protocol/group/selector.go),
//     so a selector over two TCP-only nodes claimed UDP and then failed its own members for it.
//
// The fixtures below are legal, were legal before the dry run existed, and the ones marked
// wantStart must start.

// Case A: a TCP+UDP `direct` outbound beside a TCP-only outbound that no UDP flow reaches.
const networkRequirementDirectBesideTCPOnly = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ]
}`

// Case A2: the second, independent inflation - a selector whose every member is TCP-only, refused
// because Selector.Network() reports both networks before anything is selected.
const networkRequirementSelectorOfTCPOnlyMembers = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-a", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"},
    {"type": "socks", "tag": "tcp-b", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "tcp"},
    {"type": "selector", "tag": "sel", "outbounds": ["tcp-a", "tcp-b"], "default": "tcp-a"}
  ]
}`

// Case B: a selector holding a TCP-only member and a TCP+UDP member. TCP is routed through the
// selector and the UDP flow is routed straight to the member that can carry it, so the TCP-only
// member is never asked for UDP. The `network` conditions are what make that a PROOF rather than
// an assumption.
const networkRequirementSelectorWithMixedMembers = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"},
    {"type": "socks", "tag": "dual", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["tcp-only", "dual"], "default": "dual"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "dual"},
      {"network": "tcp", "outbound": "sel"}
    ]
  }
}`

// Case B2: a load-balancing group holding the same two members with NO route narrowing. This one is
// legal by construction rather than by declaration: LoadBalance filters a member by Network() before
// choosing it, so a UDP flow is never handed to the TCP-only member - see the loadBalanceSnapshot
// comment in protocol/group/loadbalance.go, which names exactly this shape as the reason the union
// is advertised.
const networkRequirementLoadBalanceWithMixedMembers = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"},
    {"type": "socks", "tag": "dual", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "loadbalance", "tag": "lb", "outbounds": ["tcp-only", "dual"]}
  ]
}`

// Case C: a TCP-only exit that only TCP routes reach, beside a UDP-carrying outbound.
const networkRequirementTCPOnlyExitWithTCPRoute = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "udp-hop", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "udp"},
    {"type": "socks", "tag": "tcp-exit", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"network": "tcp", "outbound": "tcp-exit"},
      {"network": "udp", "outbound": "udp-hop"}
    ]
  }
}`

// Case D: business UDP handed to a UoT outbound, whose own transport is TCP, carried through a
// TCP-only middle hop, ending at a UDP-capable exit. Every hop's requirement is a TRANSPORT
// requirement, not the business network: the UDP datagram travels inside the UoT session's TCP
// connection, so a TCP-only middle hop is exactly right rather than a defect.
const networkRequirementUoTOverTCPOnlyMiddleHop = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": 1082, "version": "5"},
    {"type": "socks", "tag": "middle", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "tcp", "detour": "exit"},
    {"type": "socks", "tag": "uot", "server": "127.0.0.1", "server_port": 1080, "version": "5",
     "udp_over_tcp": {"enabled": true}, "detour": "middle"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "uot"},
      {"network": "tcp", "outbound": "uot"}
    ]
  }
}`

// Case A3: the rule that reaches the TCP-only outbound does NOT constrain the network. Nothing is
// proven about delivery, and "nothing proven" must not be read as "both networks": the route model
// explains what MAY arrive, it does not invent a requirement the configuration never stated.
const networkRequirementUnconstrainedRoute = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"outbound": "tcp-only"}
    ]
  }
}`

// Case E: business UDP explicitly delivered to a leaf that declares it cannot carry UDP. This is
// the rejection that must SURVIVE: the route says udp, the object says tcp.
const networkRequirementUDPRouteToTCPOnlyLeaf = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-only", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "tcp-only"}
    ]
  }
}`

// Case G: a selector whose current member is legal but whose other declared member is genuinely
// illegal FOR THE NETWORK THE ROUTES DELIVER. A TCP flow can be handed to the UDP-only member, so
// this must stay refused - and the refusal must be scoped to the selector, naming the member.
const networkRequirementGroupWithIllegalReachableMember = `{
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
}`

// Case G2: a loadbalance whose members are ALL TCP-only, reached by a UDP route. The group filters
// by network, so no individual member is at fault - and the group still cannot serve the flow the
// route delivers to it, which is the same defect as E one level up.
const networkRequirementGroupNoMemberCanCarry = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "tcp-a", "server": "127.0.0.1", "server_port": 1080,
     "version": "5", "network": "tcp"},
    {"type": "socks", "tag": "tcp-b", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "tcp"},
    {"type": "loadbalance", "tag": "lb", "outbounds": ["tcp-a", "tcp-b"]}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "lb"}
    ]
  }
}`

// Case D2: case D with the outbounds declared in the OPPOSITE order.
//
// # Why the declaration order must not be a verdict
//
// The dry run validates each root on its own, and the same tag can be a root AND a dependency of
// another root. If a tag that merely APPEARED in an earlier root's route could suppress a later
// root's failure at it, then this fixture and case D would disagree while describing the same
// graph - the verdict would be a property of the file's line order rather than of the
// configuration.
const networkRequirementUoTReversedOrder = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "uot", "server": "127.0.0.1", "server_port": 1080, "version": "5",
     "udp_over_tcp": {"enabled": true}, "detour": "middle"},
    {"type": "socks", "tag": "middle", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "tcp", "detour": "exit"},
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": 1082, "version": "5"}
  ],
  "route": {
    "rules": [
      {"network": "udp", "outbound": "uot"},
      {"network": "tcp", "outbound": "uot"}
    ]
  }
}`

// Case G3: case G with the group declared LAST, so the broken member's own root entry is validated
// first.
const networkRequirementGroupMemberFirst = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "udp-only", "server": "127.0.0.1", "server_port": 1081,
     "version": "5", "network": "udp"},
    {"type": "socks", "tag": "dual", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["dual", "udp-only"], "default": "dual"}
  ],
  "route": {
    "rules": [
      {"network": "tcp", "outbound": "sel"}
    ]
  }
}`

// Case F1: a declared member that does not exist. The start-order sort owns this message and it
// must keep owning it.
const networkRequirementMissingMember = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "selector", "tag": "sel", "outbounds": ["ghost"], "default": "ghost"}
  ]
}`

// Case F2: a declared cycle. The sort owns this message too.
const networkRequirementCycle = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5",
     "detour": "b"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5",
     "detour": "a"}
  ]
}`

type networkRequirementCase struct {
	id        string
	why       string
	config    string
	wantStart bool
	// wantErr are the substrings a refusal must contain, so a refusal for the WRONG reason is a
	// failure rather than a pass.
	wantErr []string
}

var networkRequirementMatrix = []networkRequirementCase{
	{
		id:        "START-01-A-direct-beside-tcp-only",
		why:       "a TCP+UDP direct outbound must not make an unrelated TCP-only outbound responsible for UDP",
		config:    networkRequirementDirectBesideTCPOnly,
		wantStart: true,
	},
	{
		id:        "START-01-A2-selector-over-tcp-only-members",
		why:       "a selector whose every member is TCP-only serves TCP, and its members must not be failed for the optimistic pre-Start Network()",
		config:    networkRequirementSelectorOfTCPOnlyMembers,
		wantStart: true,
	},
	{
		id:        "START-01-B-selector-mixed-members-udp-routed-elsewhere",
		why:       "the routes prove only TCP reaches this selector, so its TCP+UDP member does not make the TCP-only member unusable",
		config:    networkRequirementSelectorWithMixedMembers,
		wantStart: true,
	},
	{
		id:        "START-01-B2-loadbalance-mixed-members",
		why:       "a network-aware group filters a member by Network() before choosing it, so mixed membership is legal",
		config:    networkRequirementLoadBalanceWithMixedMembers,
		wantStart: true,
	},
	{
		id:        "START-01-C-tcp-only-exit-used-by-tcp-routes",
		why:       "a TCP-only exit reached only by TCP routes must start and keep TCP usable",
		config:    networkRequirementTCPOnlyExitWithTCPRoute,
		wantStart: true,
	},
	{
		id:        "START-01-D-uot-over-tcp-only-middle-hop",
		why:       "UDP-over-TCP is a legal conversion, so a TCP-only middle hop under a UoT outbound is correct",
		config:    networkRequirementUoTOverTCPOnlyMiddleHop,
		wantStart: true,
	},
	{
		id:        "START-01-A3-unconstrained-route-is-unproven",
		why:       "a rule that does not constrain the network proves nothing, and 'nothing proven' must not become 'every network'",
		config:    networkRequirementUnconstrainedRoute,
		wantStart: true,
	},
	{
		id:        "START-01-D2-uot-reversed-declaration-order",
		why:       "the same graph declared in the other order must reach the same verdict: order is not a configuration property",
		config:    networkRequirementUoTReversedOrder,
		wantStart: true,
	},
	{
		id:        "START-01-E-udp-route-to-tcp-only-leaf",
		why:       "a route that explicitly delivers UDP to a leaf that declares tcp-only is a real defect and must stay refused",
		config:    networkRequirementUDPRouteToTCPOnlyLeaf,
		wantStart: false,
		wantErr:   []string{"cannot serve the udp flow", "tcp-only"},
	},
	{
		id:        "START-01-G-group-with-illegal-reachable-member",
		why:       "the routes deliver TCP to a network-blind selector, so its UDP-only member is genuinely illegal",
		config:    networkRequirementGroupWithIllegalReachableMember,
		wantStart: false,
		wantErr:   []string{"cannot serve the tcp flow", "udp-only", "outbound/sel"},
	},
	{
		id:        "START-01-G3-group-declared-last",
		why:       "the group's illegal member must be refused whichever root is validated first",
		config:    networkRequirementGroupMemberFirst,
		wantStart: false,
		wantErr:   []string{"cannot serve the tcp flow", "udp-only", "outbound/sel"},
	},
	{
		id:        "START-01-G2-no-member-can-carry-the-delivered-network",
		why:       "a group that filters by network is unusable when NO member can carry the network the routes deliver to it",
		config:    networkRequirementGroupNoMemberCanCarry,
		wantStart: false,
		wantErr:   []string{"no reachable member carries udp", "outbound/lb"},
	},
	{
		id:        "START-01-F1-missing-member",
		why:       "a declared member that does not exist keeps the start-order sort's message",
		config:    networkRequirementMissingMember,
		wantStart: false,
		wantErr:   []string{"dependency[ghost] not found for outbound[sel]"},
	},
	{
		id:        "START-01-F2-declared-cycle",
		why:       "a declared cycle keeps the start-order sort's message",
		config:    networkRequirementCycle,
		wantStart: false,
		wantErr:   []string{"circular outbound dependency"},
	},
}

// TestNetworkRequirementMatrix is the START-01 decision table, asserted through box.Start().
func TestNetworkRequirementMatrix(t *testing.T) {
	for _, testCase := range networkRequirementMatrix {
		t.Run(testCase.id, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, testCase.config)
			require.NoError(t, err, "construction cannot see this: it is a start-time decision")
			t.Cleanup(func() { _ = instance.Close() })

			err = instance.Start()
			if testCase.wantStart {
				require.NoError(t, err, testCase.why)
				return
			}
			require.Error(t, err, testCase.why)
			for _, expected := range testCase.wantErr {
				require.Contains(t, err.Error(), expected,
					"the refusal must be reported for the right reason; got: "+err.Error())
			}
		})
	}
}

// TestRepeatedStartAndCloseOnARefusedBox is the START-02 re-entrancy fixture at the Box level.
//
// # What a refused Start leaves behind, and what a retry actually is
//
// `Box.Start` closes the Box when `start()` returns an error, and it did so before the dry run
// existed (the same call is in the tree at 8e6c0a96): the refusal releases everything construction
// created - the scope teardown, the power governor, the URL-test storage this Box owns - through
// `Close`, not through the GC. A refused Box is therefore TERMINAL, and a second Start on it is not
// a retry of the configuration: the daemon's own recovery is to build a new Box
// (experimental/boxdd/desktop_service.go, cleanFailedStartLocked). This fixture pins exactly that,
// so nobody reads a "context canceled" as a second verdict on the configuration.
func TestRepeatedStartAndCloseOnARefusedBox(t *testing.T) {
	instance, err := newBoxFromConfig(t, networkRequirementUDPRouteToTCPOnlyLeaf)
	require.NoError(t, err)

	firstErr := instance.Start()
	require.Error(t, firstErr)
	require.Contains(t, firstErr.Error(), "cannot serve the udp flow",
		"the refusal must be the dry run's verdict, not a lifecycle error")

	secondErr := instance.Start()
	require.Error(t, secondErr,
		"a refused Box is closed by Start's own error path, so a second Start cannot succeed: the "+
			"state that would have to be re-entered has already been torn down")
	require.NotEqual(t, firstErr.Error(), secondErr.Error(),
		"and it is a DIFFERENT error: the refusal is not re-evaluated, the Box is gone")

	require.NoError(t, instance.Close())
	require.NoError(t, instance.Close(), "Close must stay idempotent after a refused Start")

	// The defect itself is stable: the daemon's recovery is a new Box from the same configuration,
	// and that one must be refused identically.
	rebuilt, err := newBoxFromConfig(t, networkRequirementUDPRouteToTCPOnlyLeaf)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rebuilt.Close() })
	rebuiltErr := rebuilt.Start()
	require.Error(t, rebuiltErr)
	require.Equal(t, firstErr.Error(), rebuiltErr.Error(),
		"the same configuration must be refused with the same report on every construction")
}

// TestRefusedNetworkRequirementBoxesLeaveNoGoroutines is the other half of the leak contract: the
// instances that are REFUSED must release what they created too.
//
// The refusal happens before any socket is opened, but construction has already created services -
// the URL-test history, the network manager, the power governor - and the Box's own error path is
// what releases them. This asserts that path rather than trusting it.
func TestRefusedNetworkRequirementBoxesLeaveNoGoroutines(t *testing.T) {
	settle := func() int {
		var count int
		for attempt := 0; attempt < 40; attempt++ {
			count = runtime.NumGoroutine()
			time.Sleep(25 * time.Millisecond)
			if runtime.NumGoroutine() <= count {
				return count
			}
		}
		return count
	}
	before := settle()
	for _, testCase := range networkRequirementMatrix {
		if testCase.wantStart {
			continue
		}
		t.Run(testCase.id, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, testCase.config)
			require.NoError(t, err)
			require.Error(t, instance.Start())
			require.NoError(t, instance.Close())
		})
	}
	after := settle()
	require.LessOrEqual(t, after, before+2,
		"a refused instance must release what construction created, not leave it to the GC")
}

// TestStartedNetworkRequirementBoxesLeaveNoGoroutines is the leak half of the START-01 contract.
//
// The dry run walks the object graph before anything is started. A walk that armed a timer, started
// a recheck or cloned a group would leave something behind on the instances that DO start - which
// is the case a "refused configurations do not leak" assertion would never see.
func TestStartedNetworkRequirementBoxesLeaveNoGoroutines(t *testing.T) {
	settle := func() int {
		var count int
		for attempt := 0; attempt < 40; attempt++ {
			count = runtime.NumGoroutine()
			time.Sleep(25 * time.Millisecond)
			if runtime.NumGoroutine() <= count {
				return count
			}
		}
		return count
	}
	before := settle()
	for _, testCase := range networkRequirementMatrix {
		if !testCase.wantStart {
			continue
		}
		t.Run(testCase.id, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, testCase.config)
			require.NoError(t, err)
			require.NoError(t, instance.Start())
			require.NoError(t, instance.Close())
		})
	}
	after := settle()
	require.LessOrEqual(t, after, before+2,
		"an instance that started and closed must not leave goroutines behind")
}
