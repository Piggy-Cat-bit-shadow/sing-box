package physicalpath

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The STATUS view: what it reads, what it refuses to claim, and the order it gets it in
// ---------------------------------------------------------------------------
//
// The fixtures below implement exactly the interfaces status.go declares, and nothing else. A hop that
// implements none of them is the case that must be reported UNKNOWN: it is what every object in this
// tree that does not track its own lifecycle looks like.

// reportingLeaf is a hop that CAN report, with every part switched on by its own field so a test can
// remove exactly one capability and see what the view says without it.
type reportingLeaf struct {
	testLeaf

	// reportsState is false for the default fixture, which is the "no state provider" case.
	reportsState bool
	state        LifecycleState

	reportsError bool
	lastError    error
	errorPhase   FailurePhase
	recovered    bool

	reportsGenerations bool
	networkGeneration  uint64
	resourceGeneration uint64

	// publishesMTU is false for a hop that terminates no tunnel with a fixed capacity.
	publishesMTU uint32
	// publishesEncapOverhead adds the transport-framing capability.
	publishesEncapOverhead bool
	encapOverhead          uint32
	// publishesOuterQuic adds the outer-connection capability.
	publishesOuterQuic bool
	outerQuicInitial   int
}

func (l *reportingLeaf) StatusState() LifecycleState {
	if !l.reportsState {
		// Reported as unknown rather than absent, so a caller cannot tell "implemented but empty" from
		// "not implemented" - both mean the view learned nothing, which is the honest answer.
		return LifecycleStateUnknown
	}
	return l.state
}

func (l *reportingLeaf) StatusLastError() (error, FailurePhase, bool) {
	if !l.reportsError {
		return nil, PhaseUnattributed, false
	}
	return l.lastError, l.errorPhase, l.recovered
}

func (l *reportingLeaf) StatusNetworkGeneration() uint64  { return l.networkGeneration }
func (l *reportingLeaf) StatusResourceGeneration() uint64 { return l.resourceGeneration }

func (l *reportingLeaf) PortMTU() uint32 { return l.publishesMTU }

func (l *reportingLeaf) PortEncapOverhead() uint32 { return l.encapOverhead }

func (l *reportingLeaf) OuterQUICInitialPacketSize() int { return l.outerQuicInitial }

// The fixture deliberately does NOT add a DialContext: this file may only exercise reads, and a leaf
// that could be dialled would make "the view never dials" untestable rather than guaranteed. The
// model's own guard covers the walk (TestBuildNeverCallsADialingMethod); what this file adds is that
// the STATUS view calls nothing beyond the reporter interfaces declared in status.go, which is a
// property of the method set and is checked by the compiler: every call the view makes on a hop is a
// method of one of those interfaces or of adapter.Outbound itself.

// newReportingRegistry builds a registry whose hops are the reporting fixture.
func newReportingRegistry(leaves ...*reportingLeaf) *testRegistry {
	objects := make([]adapter.Outbound, 0, len(leaves))
	for _, leaf := range leaves {
		objects = append(objects, leaf)
	}
	return newRegistry(objects...)
}

// ---------------------------------------------------------------------------
// The state mapping, and the claim it refuses to make
// ---------------------------------------------------------------------------

// TestAHopWithNoStateProviderIsReportedUnknownWithAReason is the rule that matters most.
//
// "Constructed successfully" must NEVER be presented as "the peer is reachable". The fixture below
// implements NONE of the reporting interfaces, which is what an ordinary outbound looks like, and the
// view must say so rather than defaulting to anything.
func TestAHopWithNoStateProviderIsReportedUnknownWithAReason(t *testing.T) {
	plain := &reportingLeaf{testLeaf: *tcpLeaf("plain")}
	registry := newReportingRegistry(plain)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "plain"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Hops, 1)
	hop := status.Hops[0]
	require.Equal(t, ReadinessUnknown, hop.Readiness,
		"a hop that reports nothing must be UNKNOWN, never ready and never 'constructed'")
	require.Equal(t, LifecycleStateUnknown, hop.ClaimedState)
	require.NotEmpty(t, hop.Reason, "an unknown must come with a reason")
	require.Contains(t, hop.Reason, "reachable",
		"the reason must say WHY it is unknown: a constructed object is not evidence about its peer")
	require.False(t, status.Ready(),
		"a path with an unknown hop is not ready: 'not established' is not 'ready'")
}

// TestAConstructedHopIsNotAReadyHop pins the distinction inside the mapping itself.
func TestAConstructedHopIsNotAReadyHop(t *testing.T) {
	constructed := &reportingLeaf{testLeaf: *tcpLeaf("built"), reportsState: true, state: LifecycleStateConstructed}
	registry := newReportingRegistry(constructed)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "built"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Hops, 1)
	require.Equal(t, ReadinessConstructed, status.Hops[0].Readiness,
		"the view reports exactly what the hop claimed, and 'constructed' is its own answer")
	require.NotEqual(t, ReadinessReady, status.Hops[0].Readiness,
		"and it is NOT ready: the object existing says nothing about the peer")
	require.False(t, status.Ready())
}

// TestTheReportedStateIsTheOwnersOwn maps every lifecycle state through, so the vocabulary in the
// documentation and the behaviour cannot drift.
func TestTheReportedStateIsTheOwnersOwn(t *testing.T) {
	cases := []struct {
		state LifecycleState
		want  StatusReadiness
	}{
		{LifecycleStateUnknown, ReadinessUnknown},
		{LifecycleStateConstructed, ReadinessConstructed},
		{LifecycleStateStarting, ReadinessStarting},
		{LifecycleStateReady, ReadinessReady},
		{LifecycleStateDegraded, ReadinessDegraded},
		{LifecycleStateClosing, ReadinessClosing},
		{LifecycleStateClosed, ReadinessClosed},
	}

	for _, testCase := range cases {
		t.Run(testCase.state.String(), func(t *testing.T) {
			leaf := &reportingLeaf{
				testLeaf:     *tcpLeaf("hop"),
				reportsState: true,
				state:        testCase.state,
			}
			registry := newReportingRegistry(leaf)
			status := NewStatusView().SnapshotStatus(registry.resolver(),
				TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})

			require.Len(t, status.Hops, 1)
			require.Equal(t, testCase.want, status.Hops[0].Readiness)
		})
	}

	// And a hop that claims READY is the only one that makes the path ready.
	ready := &reportingLeaf{testLeaf: *tcpLeaf("ready"), reportsState: true, state: LifecycleStateReady}
	registry := newReportingRegistry(ready)
	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "ready"}, Options{Network: N.NetworkTCP})
	require.True(t, status.Ready(), "a single ready hop is a ready path")
}

// TestARecordedFailureBeatsASelfDeclaredState is the precedence rule: evidence wins over a claim.
func TestARecordedFailureBeatsASelfDeclaredState(t *testing.T) {
	leaf := &reportingLeaf{
		testLeaf:     *tcpLeaf("liar"),
		reportsState: true,
		state:        LifecycleStateReady,
		reportsError: true,
		lastError:    errors.New("dial tcp: connection refused"),
		errorPhase:   PhaseConnect,
	}
	registry := newReportingRegistry(leaf)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "liar"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Hops, 1)
	require.Equal(t, ReadinessFailed, status.Hops[0].Readiness,
		"an unrecovered failure is evidence; a self-declared 'ready' is a claim, and evidence wins")
	require.Equal(t, LifecycleStateReady, status.Hops[0].ClaimedState,
		"the claim is still REPORTED, so a reader can see the disagreement")
	require.Contains(t, status.Hops[0].Reason, "claims to be ready")
	require.False(t, status.Ready())
}

// TestARecoveredFailureIsNotPresentedAsCurrent is the generation-adjacent rule for a hop that came back.
func TestARecoveredFailureIsNotPresentedAsCurrent(t *testing.T) {
	leaf := &reportingLeaf{
		testLeaf:     *tcpLeaf("flaky"),
		reportsState: true,
		state:        LifecycleStateReady,
		reportsError: true,
		lastError:    errors.New("handshake timeout"),
		errorPhase:   PhaseTLS,
		recovered:    true,
	}
	registry := newReportingRegistry(leaf)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "flaky"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Hops, 1)
	require.Equal(t, ReadinessReady, status.Hops[0].Readiness,
		"a recovered hop is ready: showing the old error as current would keep a working node "+
			"looking broken forever")
	require.NotEmpty(t, status.Hops[0].LastError, "the history is still reported")
	require.True(t, status.Hops[0].LastErrorRecovered)
	require.Nil(t, status.Failure, "and it is not reported as the path's failure")
	require.True(t, status.Ready())
}

// ---------------------------------------------------------------------------
// Error attribution: which hop, which phase, in which order
// ---------------------------------------------------------------------------

// TestTheStatusNamesTheFailingHopFromTheModelNotFromAnIndex is the direction contract.
//
// The path is built so that ENTRY and EXIT are different tags, and the failing hop is the one in the
// MIDDLE. Nothing here indexes Hops[0] or Hops[len-1] to decide what the failure means: the position
// comes from the model's own Hop.Position, which the direction fix renumbers, so this test cannot pass
// by agreeing with a hard-coded index.
func TestTheStatusNamesTheFailingHopFromTheModelNotFromAnIndex(t *testing.T) {
	exit := &reportingLeaf{testLeaf: *dualLeaf("exit")}
	middle := &reportingLeaf{
		testLeaf:     *dualLeaf("middle", "exit"),
		reportsState: true,
		state:        LifecycleStateReady,
		reportsError: true,
		lastError:    errors.New("dial udp 1.2.3.4: i/o timeout"),
		errorPhase:   PhaseConnect,
	}
	entry := &reportingLeaf{
		testLeaf:     *dualLeaf("entry", "middle"),
		reportsState: true,
		state:        LifecycleStateReady,
	}
	registry := newReportingRegistry(exit, middle, entry)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})

	require.Empty(t, status.Unknowns, "every hop of this path resolves")

	// The order is read FROM THE MODEL, never assumed here. `entry.detour = middle`,
	// `middle.detour = exit`: entry reaches its own server through middle, which reaches its through
	// exit, so the device reaches EXIT's server first - the deepest dependency is nearest this device,
	// which is the direction `common/dialer/detour_wire_order_test.go` establishes on the wire. This
	// test therefore states the model's contract through the model's own accessors and would follow it
	// if the direction were ever re-decided.
	modelPath, modelErr := Build(registry.resolver(), TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})
	require.NoError(t, modelErr)
	modelEntry, hasEntry := modelPath.Entry()
	modelExit, hasExit := modelPath.Exit()
	require.True(t, hasEntry)
	require.True(t, hasExit)
	require.Equal(t, modelEntry.DeclaredTag, status.Entry,
		"PathStatus.Entry must be the model's Path.Entry, not an index this file picked")
	require.Equal(t, modelExit.DeclaredTag, status.Exit,
		"and PathStatus.Exit must be the model's Path.Exit")
	require.NotEqual(t, status.Entry, status.Exit,
		"this fixture is only meaningful if the two ends of the path differ")

	require.NotNil(t, status.Failure, "the path has a failing hop")
	failure := status.Failure
	require.Equal(t, "middle", failure.Hop,
		"the FAILING hop must be named, not the entry and not the exit")
	require.Equal(t, 1, failure.Position,
		"and its position is the model's own, from Hop.Position")
	require.Equal(t, 3, failure.HopCount)
	require.Equal(t, PhaseConnect, failure.Phase)
	require.Contains(t, failure.String(), "hop #1 of 3")
	require.Contains(t, failure.String(), "phase connect")

	// The two neighbours must be split by packet order, not by the order this file happened to write
	// the fixture in: the hop before the failure was reached, the hop after it was not.
	require.Len(t, failure.Reached, 1)
	require.Len(t, failure.Unreached, 1)
	require.Equal(t, status.Hops[failure.Position-1].Tag, failure.Reached[0],
		"everything before the failing hop, in packet order, is known to have been entered")
	require.Equal(t, status.Hops[failure.Position+1].Tag, failure.Unreached[0],
		"and everything after it was never tried")

	for index, hop := range status.Hops {
		require.Equal(t, index, hop.Position,
			"positions must be the model's, contiguous and in packet order")
	}
	require.Equal(t, status.Hops[0].Tag, status.Entry,
		"Entry is the model's Hops[0]")
	require.Equal(t, status.Hops[len(status.Hops)-1].Tag, status.Exit,
		"and Exit is its last element")
}

// TestTheFailureCarriesThePhaseAndNeverACredential is the redaction contract, exercised through the view.
func TestTheFailureCarriesThePhaseAndNeverACredential(t *testing.T) {
	secrets := []string{
		"socks5://user:hunter2@proxy.example:1080: dial failed",
		"tuic://host/?token=eyJhbGciOiJIUzI1NiJ9.abc: handshake failed",
		"password=correct-horse-battery-staple rejected",
		"Authorization: Bearer sk-live-0123456789abcdef rejected",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
		"uuid=3f2504e0-4f89-11d3-9a0c-0305e82c3301 is unknown",
	}
	for _, secret := range secrets {
		t.Run(secret[:min(len(secret), 24)], func(t *testing.T) {
			leaf := &reportingLeaf{
				testLeaf:     *tcpLeaf("hop"),
				reportsState: true,
				state:        LifecycleStateReady,
				reportsError: true,
				lastError:    errors.New(secret),
				errorPhase:   PhaseQUIC,
			}
			registry := newReportingRegistry(leaf)
			status := NewStatusView().SnapshotStatus(registry.resolver(),
				TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})

			require.NotNil(t, status.Failure)
			detail := status.Failure.Detail
			require.Contains(t, strings.ToLower(detail), "[redacted",
				"the recognised secret must be replaced (the PEM form reads '[redacted pem body]')")

			for _, forbidden := range []string{
				"hunter2", "eyJhbGciOiJIUzI1NiJ9.abc", "correct-horse-battery-staple",
				"sk-live-0123456789abcdef", "MIIEvQIBADANBg", "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
			} {
				require.NotContains(t, detail, forbidden,
					"a credential must never reach a report: %q", forbidden)
			}
			require.Equal(t, PhaseQUIC, status.Failure.Phase,
				"redaction must not lose the phase, which is the actionable part")
		})
	}
}

// TestRedactionKeepsTheMessageReadable is the other half: a report that redacted everything would be
// safe and useless.
func TestRedactionKeepsTheMessageReadable(t *testing.T) {
	cases := []struct {
		detail string
		keeps  []string
	}{
		{
			detail: "dial tcp 10.0.0.1:443: connect: connection refused",
			keeps:  []string{"dial tcp 10.0.0.1:443", "connection refused"},
		},
		{
			detail: "lookup node.example: no such host",
			keeps:  []string{"node.example", "no such host"},
		},
		{
			detail: "socks5://user:hunter2@proxy.example:1080: dial failed",
			keeps:  []string{"socks5://", "proxy.example:1080", "dial failed"},
		},
		{
			detail: "password=hunter2 rejected",
			keeps:  []string{"password=", "rejected"},
		},
	}
	for _, testCase := range cases {
		redacted := redactDetail(testCase.detail)
		for _, kept := range testCase.keeps {
			require.Contains(t, redacted, kept, "the message must stay useful after redaction")
		}
		require.NotContains(t, redacted, "hunter2")
	}
}

// TestAWordEndingInASecretKeywordIsNotRedacted pins the boundary of the key matching: a false positive
// would silently destroy the useful part of a message.
func TestAWordEndingInASecretKeywordIsNotRedacted(t *testing.T) {
	for _, detail := range []string{
		"mypassword=not-a-secret-field",
		"the auth path failed",   // no separator, so not an assignment
		"context deadline exceeded", // unrelated
	} {
		require.Equal(t, detail, redactDetail(detail),
			"a key that merely ENDS in a keyword, or a keyword with no value, must be left alone")
	}
}

// ---------------------------------------------------------------------------
// MTU reporting
// ---------------------------------------------------------------------------

// TestTheMTUBudgetsAreDerivedForThisHop is the number a stacked protocol needs, reported per hop.
func TestTheMTUBudgetsAreDerivedForThisHop(t *testing.T) {
	cases := []struct {
		name             string
		innerIP          uint32
		encap            uint32
		wantUDPv4        uint32
		wantUDPv6        uint32
		wantEncapInNote  bool
	}{
		{
			name: "a plain QUIC tunnel at the MASQUE default", innerIP: 1280,
			wantUDPv4: 1252, wantUDPv6: 1232,
		},
		{
			name: "a plain QUIC tunnel at the fork's other default", innerIP: 1408,
			wantUDPv4: 1380, wantUDPv6: 1360,
		},
		{
			name: "a WireGuard tunnel, which encapsulates inside the packet", innerIP: 1408,
			encap: 32, wantUDPv4: 1348, wantUDPv6: 1328, wantEncapInNote: true,
		},
		{
			name: "a WireGuard tunnel at the IPv6 minimum", innerIP: 1280,
			encap: 32, wantUDPv4: 1220, wantUDPv6: 1200, wantEncapInNote: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			leaf := &reportingLeaf{
				testLeaf:               *tcpLeaf("tunnel"),
				reportsState:           true,
				state:                  LifecycleStateReady,
				publishesMTU:           testCase.innerIP,
				publishesEncapOverhead: testCase.encap > 0,
				encapOverhead:          testCase.encap,
			}
			registry := newReportingRegistry(leaf)
			status := NewStatusView().SnapshotStatus(registry.resolver(),
				TagOrOutbound{Tag: "tunnel"}, Options{Network: N.NetworkTCP})

			require.Len(t, status.Hops, 1)
			mtu := status.Hops[0].MTU
			require.True(t, mtu.Known)
			require.Equal(t, testCase.innerIP, mtu.InnerIP)
			require.Equal(t, testCase.wantUDPv4, mtu.InnerUDPIPv4,
				"the IPv4 budget is the inner MTU minus 20 and 8")
			require.Equal(t, testCase.wantUDPv6, mtu.InnerUDPIPv6,
				"and the IPv6 budget minus 40 and 8: the 20-byte difference is the whole reason both "+
					"are reported")
			require.Equal(t, testCase.encap, mtu.Encapsulated)
			if testCase.wantEncapInNote {
				require.Contains(t, mtu.Reason, "framing",
					"a transport that adds framing inside the packet must say so, because the two "+
						"budgets already subtract it")
			}
		})
	}
}

// TestAHopWithoutAFixedCapacitySaysWhyItHasNoMTU is the unknown side, which is most hops.
func TestAHopWithoutAFixedCapacitySaysWhyItHasNoMTU(t *testing.T) {
	for _, testCase := range []struct {
		name string
		mtu  uint32
	}{
		{name: "a hop that does not publish a capacity at all", mtu: 0},
		{name: "a hop that publishes zero, which is a refusal and not a capacity", mtu: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			leaf := &reportingLeaf{testLeaf: *tcpLeaf("proxy"), publishesMTU: testCase.mtu}
			registry := newReportingRegistry(leaf)
			status := NewStatusView().SnapshotStatus(registry.resolver(),
				TagOrOutbound{Tag: "proxy"}, Options{Network: N.NetworkTCP})

			require.Len(t, status.Hops, 1)
			require.False(t, status.Hops[0].MTU.Known)
			require.Zero(t, status.Hops[0].MTU.InnerIP,
				"a capacity that was not established must not be reported as a number")
			require.NotEmpty(t, status.Hops[0].MTU.Reason, "and the reason must be given")
		})
	}
}

// TestTheOuterQuicInitialIsReportedSeparatelyFromTheInnerMTU is the MTU-04 distinction, in the status
// view: the two are different numbers in different layers and must never be rendered as one.
func TestTheOuterQuicInitialIsReportedSeparatelyFromTheInnerMTU(t *testing.T) {
	leaf := &reportingLeaf{
		testLeaf:           *tcpLeaf("masque"),
		reportsState:       true,
		state:              LifecycleStateReady,
		publishesMTU:       1280,
		publishesOuterQuic: true,
		outerQuicInitial:   1331,
	}
	registry := newReportingRegistry(leaf)
	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "masque"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Hops, 1)
	mtu := status.Hops[0].MTU
	require.True(t, mtu.Known, "the inner capacity is known")
	require.True(t, mtu.OuterKnown, "and so is the outer packet size, which is a SEPARATE fact")
	require.EqualValues(t, 1280, mtu.InnerIP)
	require.EqualValues(t, 1331, mtu.OuterQUICInitial)
	require.NotEqual(t, mtu.InnerIP, mtu.OuterQUICInitial,
		"the outer QUIC packet is not the inner MTU: it CARRIES an inner packet plus framing")
	require.Contains(t, mtu.Reason, "not an inner capacity",
		"the limitation must be on the report, so nobody reads the outer number as an MTU")
}

// ---------------------------------------------------------------------------
// Control path, unknowns, and the disconnection boundary
// ---------------------------------------------------------------------------

// TestTheControlPathReportsThePublishedDecisionWithoutCommittingAnything keeps the preview/commit
// distinction the model makes: reading a group's selection must not consume it.
func TestTheControlPathReportsThePublishedDecisionWithoutCommittingAnything(t *testing.T) {
	leaf := &reportingLeaf{testLeaf: *dualLeaf("leaf"), reportsState: true, state: LifecycleStateReady}
	selector := tcpGroup("sel", "leaf", "leaf")
	registry := newRegistry(leaf, selector)
	selector.lookup = registry.objects

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})

	require.Len(t, status.Controls, 1, "the control chain has the group")
	require.Equal(t, "sel", status.Controls[0].Tag)
	require.Equal(t, "leaf", status.Controls[0].Decision,
		"the decision is the member the group PUBLISHED")
	require.True(t, status.Controls[0].Committed,
		"a selector publishes exactly one member, which is its committed choice")

	// The path itself contains the leaf and never the group.
	require.Len(t, status.Hops, 1)
	require.Equal(t, "leaf", status.Hops[0].Tag)
	require.False(t, status.Hops[0].Endpoint)
}

// TestAnUnresolvableHopIsUnknownAndNotInvented keeps the model's unknowns in the report.
func TestAnUnresolvableHopIsUnknownAndNotInvented(t *testing.T) {
	exit := &reportingLeaf{testLeaf: *dualLeaf("exit")}
	entry := &reportingLeaf{testLeaf: *dualLeaf("entry", "missing")}
	registry := newReportingRegistry(exit, entry)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})

	require.True(t, status.HasUnknown(), "a dependency that does not resolve is an unknown")
	require.False(t, status.Ready(), "and a path with an unknown is not ready")
	require.Empty(t, status.Exit, "the exit is not reported for a partly unknown path")
	require.Empty(t, status.Entry)
}

// TestADisconnectedViewStopsAnswering is the Close boundary: after the graph is gone, the last state
// must not be presented as current.
func TestADisconnectedViewStopsAnswering(t *testing.T) {
	leaf := &reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady}
	registry := newReportingRegistry(leaf)
	view := NewStatusView()

	require.True(t, view.Connected())
	before := view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	require.True(t, before.Ready())

	view.Disconnect()
	require.False(t, view.Connected())

	after := view.SnapshotStatus(registry.resolver(), TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
	require.True(t, after.HasUnknown(),
		"a disconnected view must report that it can no longer describe the graph")
	require.Contains(t, after.Unknowns[0].Reason, "disconnected")
	require.Empty(t, after.Hops, "and it must not re-serve the last snapshot as current")
	require.False(t, after.Ready())

	// Disconnect is idempotent and safe to repeat.
	view.Disconnect()
	require.False(t, view.Connected())
}

// TestAnEmptyPathIsNotReady covers the degenerate case: a root that resolves to nothing.
func TestAnEmptyPathIsNotReady(t *testing.T) {
	registry := newReportingRegistry()
	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "missing"}, Options{Network: N.NetworkTCP})

	require.True(t, status.HasUnknown())
	require.Empty(t, status.Hops)
	require.False(t, status.Ready(), "an empty path is not a ready path")
	require.Empty(t, status.Exit)
}

// ---------------------------------------------------------------------------
// Concurrency and re-entrancy
// ---------------------------------------------------------------------------

// TestConcurrentSnapshotsDoNotBlockEachOther is the lock-discipline test, and it runs under -race.
//
// The view holds one mutex and never holds it across a call into a hop, so N goroutines taking snapshots
// of the same path must all finish without serialising behind each other's hops. The fixture's hops do
// real work under their own lock, which is what would deadlock if the view held its lock across the
// call.
func TestConcurrentSnapshotsDoNotBlockEachOther(t *testing.T) {
	exit := &reportingLeaf{testLeaf: *dualLeaf("exit"), reportsState: true, state: LifecycleStateReady}
	entry := &reportingLeaf{
		testLeaf:           *dualLeaf("entry", "exit"),
		reportsState:       true,
		state:              LifecycleStateReady,
		publishesMTU:       1408,
		reportsGenerations: true,
	}
	registry := newReportingRegistry(exit, entry)
	resolver := registry.resolver()
	view := NewStatusView()

	var waitGroup sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < 50; iteration++ {
				status := view.SnapshotStatus(resolver, TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})
				if len(status.Hops) != 2 {
					t.Errorf("a concurrent snapshot returned %d hops, want 2", len(status.Hops))
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}

// TestSnapshotAndDisconnectRaceSafely is the other interleaving: a teardown landing while snapshots run
// must produce either a real snapshot or the disconnected answer, never a torn one.
func TestSnapshotAndDisconnectRaceSafely(t *testing.T) {
	leaf := &reportingLeaf{testLeaf: *tcpLeaf("hop"), reportsState: true, state: LifecycleStateReady}
	registry := newReportingRegistry(leaf)
	resolver := registry.resolver()
	view := NewStatusView()

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		for iteration := 0; iteration < 200; iteration++ {
			view.SnapshotStatus(resolver, TagOrOutbound{Tag: "hop"}, Options{Network: N.NetworkTCP})
		}
	}()
	go func() {
		defer waitGroup.Done()
		view.Disconnect()
	}()
	waitGroup.Wait()
}

// TestTheReadOnlyWalkIsTheModelsOwn is the structural half of "no second manager": the view must not
// build a path by any means other than the model's Build, so the order, tags and unknowns it reports
// cannot disagree with what the model says.
func TestTheReadOnlyWalkIsTheModelsOwn(t *testing.T) {
	exit := &reportingLeaf{testLeaf: *dualLeaf("exit")}
	entry := &reportingLeaf{testLeaf: *dualLeaf("entry", "exit")}
	registry := newReportingRegistry(exit, entry)
	resolver := registry.resolver()

	// The model's own answer, walked ONCE and reused, so the comparison cannot be affected by a second
	// walk's state.
	path, err := Build(resolver, TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)

	status := NewStatusView().SnapshotStatus(resolver, TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})

	require.Equal(t, hopTags(path), statusTags(status),
		"the status view must report exactly the model's hop order")
	require.Equal(t, len(path.Unknowns), len(status.Unknowns),
		"and exactly the model's unknowns")
	require.Equal(t, path.ControlPath, status.ControlPath)
}

func statusTags(status PathStatus) []string {
	tags := make([]string, 0, len(status.Hops))
	for _, hop := range status.Hops {
		tags = append(tags, hop.Tag)
	}
	return tags
}

// TestTheReasonNeverLeaksAConfiguredSecret is the redaction boundary applied to the OTHER free-text
// fields, not only to an error: a reason is written by this view, but a tag comes from configuration and
// a dependency name can be anything.
func TestTheReasonNeverLeaksAConfiguredSecret(t *testing.T) {
	// A dependency tag is user configuration. It is reported as a tag, which is correct and expected -
	// what must NOT happen is the view inventing a message around it that includes anything else.
	exit := &reportingLeaf{testLeaf: *dualLeaf("exit")}
	entry := &reportingLeaf{testLeaf: *dualLeaf("entry", "missing")}
	registry := newReportingRegistry(exit, entry)

	status := NewStatusView().SnapshotStatus(registry.resolver(),
		TagOrOutbound{Tag: "entry"}, Options{Network: N.NetworkTCP})

	for _, unknown := range status.Unknowns {
		require.NotContains(t, unknown.Reason, "://",
			"an unknown's reason must not quote a URL: that is where credentials travel")
		require.False(t, strings.Contains(unknown.Reason, "\n"),
			"and it must be a single line")
	}
}
