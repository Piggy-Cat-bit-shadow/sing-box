package box_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/physicalpath"

	"github.com/stretchr/testify/require"
)

// The Box-level contract for the read-only status surface.
//
// # Why these run through the real configuration loader
//
// The property under test is that a Box built the ordinary way OWNS a status view and disconnects it
// at the right moment. A unit test cannot show that: it would have to construct the object graph the
// Box constructs, which is the thing under test. These tests therefore load the JSON a user would
// write and read `Box.Status` - the same shape box_physicalpath_test.go uses, and the same helper.
//
// # What is deliberately NOT started
//
// A urltest and a health-aware loadbalance start a measurement that dials. Nothing here starts one.
// The walk a status answer performs does not depend on whether a measurement is running, and the
// state that matters for these shapes - a group that has committed nothing - is the state a group is
// in before Start.

// statusSingleHopConfig is the smallest path: one hop, no control plane.
const statusSingleHopConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "only", "server": "127.0.0.1", "server_port": 1080, "version": "5"}
  ]
}`

// statusTwoHopConfig is a detour: `exit` reaches its OWN SERVER through `entry`, so the device
// enters `entry` first and `Hops[0]` is `entry`.
const statusTwoHopConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "entry", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": 1081, "version": "5",
     "detour": "entry"}
  ]
}`

// statusSelectorConfig names the SECOND declared member as the default, so a mistake that reads the
// first member of the declaration instead of the selection is visible in the answer rather than
// hidden by a coincidence.
const statusSelectorConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["a", "b"], "default": "b"}
  ]
}`

// statusSelectorNoPreferenceConfig is the same group with nothing configured and nothing stored, so
// the group is in SelectionUnknown rather than SelectionConfigured.
const statusSelectorNoPreferenceConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "selector", "tag": "sel", "outbounds": ["a", "b"]}
  ]
}`

const statusURLTestConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "urltest", "tag": "ut", "outbounds": ["a", "b"], "url": "http://127.0.0.1:1/generate_204"}
  ]
}`

const statusLoadBalanceConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "a", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "socks", "tag": "b", "server": "127.0.0.1", "server_port": 1081, "version": "5"},
    {"type": "loadbalance", "tag": "lb", "outbounds": ["a", "b"]}
  ]
}`

// statusDanglingDependencyConfig declares a detour that does not exist. Construction cannot see it -
// the dependency graph is a start-time check - so the walk reports it as an UNKNOWN, which is
// exactly the answer a truncated graph must produce.
const statusDanglingDependencyConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "socks", "tag": "exit", "server": "127.0.0.1", "server_port": 1081, "version": "5",
     "detour": "ghost"}
  ]
}`

// requireStatusAgreesWithTheModelWalk reconstructs the path through the SAME read-only lookup the
// Box's own resolver uses, so a disagreement between the two is a disagreement about the object
// graph rather than about two different registries.
//
// # The refused question
//
// A root tag that is the empty string is a question `Build` REFUSES rather than answers, and the two
// surfaces report that differently by design: the model returns an error, and a status answer must
// convert it into an UNKNOWN naming it. Nothing was walked, so an empty PathStatus - no hops and no
// unknowns - would read as a path that was walked and found clean. That case is asserted here rather
// than skipped, because "the question was refused" is exactly the answer a caller must be able to
// tell apart from "the path was fine".
func requireStatusAgreesWithTheModelWalk(t *testing.T, instance *box.Box, root string, network string) {
	t.Helper()
	status := instance.Status(root, network)
	resolver := physicalpath.NewResolver(instance.Outbound().Outbound, physicalpath.Snapshot{})
	path, err := physicalpath.Build(
		resolver,
		physicalpath.TagOrOutbound{Tag: root},
		physicalpath.Options{Network: network},
	)
	if err != nil {
		require.True(t, status.HasUnknown(), "a refused walk must be reported, not left blank")
		require.Contains(t, status.Unknowns[0].Reason, "the path could not be walked")
		require.Contains(t, status.Unknowns[0].Reason, err.Error(),
			"the answer must carry the model's own refusal, so the two cannot disagree about it")
		require.Empty(t, status.Hops)
		return
	}
	requireStatusAgreesWithBuild(t, status, path)
}

// requireStatusAgreesWithBuild pins that the status answer is the model's walk and nothing else: the
// same hops, in the same packet order, with the same unknowns and the same two ends.
func requireStatusAgreesWithBuild(t *testing.T, status physicalpath.PathStatus, path physicalpath.Path) {
	t.Helper()
	require.Equal(t, path.Root, status.Root)
	require.Equal(t, path.ControlPath, status.ControlPath, "the control chain is the model's")
	require.Len(t, status.Hops, len(path.Hops))
	for index := range path.Hops {
		require.Equal(t, path.Hops[index].Position, status.Hops[index].Position)
		require.Equal(t, path.Hops[index].DeclaredTag, status.Hops[index].Tag)
		require.Equal(t, path.Hops[index].ResolvedLeafTag, status.Hops[index].LeafTag)
		require.Equal(t, path.Hops[index].Type, status.Hops[index].Type)
		require.Equal(t, path.Hops[index].IsEndpoint, status.Hops[index].Endpoint)
		require.Equal(t, path.Hops[index].ControlOwner, status.Hops[index].SelectedBy)
	}
	require.Len(t, status.Unknowns, len(path.Unknowns))
	for index := range path.Unknowns {
		require.Equal(t, path.Unknowns[index], status.Unknowns[index])
	}
	entry, hasEntry := path.Entry()
	if hasEntry {
		require.Equal(t, entry.DeclaredTag, status.Entry)
	} else {
		require.Empty(t, status.Entry)
	}
	exit, hasExit := path.Exit()
	if hasExit {
		require.Equal(t, exit.DeclaredTag, status.Exit)
	} else {
		require.Empty(t, status.Exit)
	}
}

// TestStatusBeforeStartDoesNotClaimLiveReady is the first requirement: a Box that was constructed and
// never started answers, and answers without claiming anything is live.
func TestStatusBeforeStartDoesNotClaimLiveReady(t *testing.T) {
	for name, testCase := range map[string]struct {
		config string
		root   string
	}{
		"single hop":            {statusSingleHopConfig, "only"},
		"two-hop detour":        {statusTwoHopConfig, "exit"},
		"selector":              {statusSelectorConfig, "sel"},
		"urltest":               {statusURLTestConfig, "ut"},
		"loadbalance":           {statusLoadBalanceConfig, "lb"},
		"dangling dependency":   {statusDanglingDependencyConfig, "exit"},
		"nothing named at all":  {statusSingleHopConfig, "ghost"},
		"an empty root tag":     {statusSingleHopConfig, ""},
		"group with no default": {statusSelectorNoPreferenceConfig, "sel"},
	} {
		t.Run(name, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, testCase.config)
			require.NoError(t, err)
			t.Cleanup(func() { _ = instance.Close() })

			// The whole call must be safe before Start: no panic, from any goroutine.
			status := instance.Status(testCase.root, "tcp")
			require.False(t, status.Ready(),
				"a Box that has not started must never report a READY path: every hop here is "+
					"constructed and none of them has shown its peer answers")
			for index, hop := range status.Hops {
				require.NotEqual(t, physicalpath.ReadinessReady, hop.Readiness,
					"hop %d claims READY before Start", index)
			}
			for index, control := range status.Controls {
				require.False(t, control.Committed,
					"control node %d claims a committed selection before Start", index)
				require.Empty(t, control.Decision)
			}
			require.True(t, status.HasUnknown() || len(status.Hops) > 0,
				"the answer must explain itself: either a walked path or an UNKNOWN with a reason")
			if testCase.root != "" {
				require.Equal(t, testCase.root, status.Root,
					"the answer must name the root it was asked about, even when nothing resolved")
			}
		})
	}
}

// TestStatusAgreesWithTheModelWalk is the "must not contradict Build/Hops" contract, over every
// shape this configuration language can produce and over the networks a caller can ask about.
func TestStatusAgreesWithTheModelWalk(t *testing.T) {
	configs := map[string]string{
		"single hop":            statusSingleHopConfig,
		"two-hop detour":        statusTwoHopConfig,
		"selector":              statusSelectorConfig,
		"group with no default": statusSelectorNoPreferenceConfig,
		"urltest":               statusURLTestConfig,
		"loadbalance":           statusLoadBalanceConfig,
		"dangling dependency":   statusDanglingDependencyConfig,
	}
	roots := map[string][]string{
		"single hop":            {"only", "ghost", ""},
		"two-hop detour":        {"exit", "entry"},
		"selector":              {"sel", "a"},
		"group with no default": {"sel"},
		"urltest":               {"ut"},
		"loadbalance":           {"lb"},
		"dangling dependency":   {"exit"},
	}

	// The networks a caller can name, including two this tree has no protocol for: the walk must
	// answer for whatever it is asked rather than only for the two it prefers.
	networks := []string{"", "tcp", "udp", "icmp", "sctp"}

	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			instance, err := newBoxFromConfig(t, config)
			require.NoError(t, err)
			t.Cleanup(func() { _ = instance.Close() })

			for _, root := range roots[name] {
				for _, network := range networks {
					requireStatusAgreesWithTheModelWalk(t, instance, root, network)
				}
			}
		})
	}
}

// TestStatusSelectionIsCommittedOnlyAfterTheGroupActuallyCommits is the requirement stated as an
// experiment: the SAME configuration, read either side of the only event that commits a member.
//
// # Why the pair is the whole point
//
// Before Start the selector's state is SelectionConfigured: the configuration names `b`, and `b` is
// a PREFERENCE - what a start would install, not what any flow takes. After Start the live slot
// holds `b`, and only then is `b` a decision. An answer that reads the preference as the decision is
// right for exactly one of the two reads, which is how such a defect survives a single-sided test.
func TestStatusSelectionIsCommittedOnlyAfterTheGroupActuallyCommits(t *testing.T) {
	instance, err := newBoxFromConfig(t, statusSelectorConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	before := instance.Status("sel", "tcp")
	require.Len(t, before.Controls, 1)
	require.Equal(t, "sel", before.Controls[0].Tag)
	require.False(t, before.Controls[0].Committed,
		"a configured default is a preference, not a commitment")
	require.Empty(t, before.Controls[0].Decision,
		"the decision field describes what the traffic takes, and before Start nothing does")
	require.Contains(t, before.Controls[0].Reason, "configured",
		"the reason must name WHICH not-committed state this is, so an operator can tell a "+
			"configuration preference from a stored one")
	require.Contains(t, before.Controls[0].Reason, `"b"`,
		"and it must name the preference it is refusing to call live")
	require.Empty(t, before.Hops,
		"the walk must not reach a member the group has not committed to")
	require.False(t, before.Ready())

	require.NoError(t, instance.Start())

	after := instance.Status("sel", "tcp")
	require.Len(t, after.Controls, 1)
	require.True(t, after.Controls[0].Committed,
		"Start installs the default into the live slot, so it IS committed now")
	require.Equal(t, "b", after.Controls[0].Decision)
	require.Empty(t, after.Controls[0].Reason)
	require.Len(t, after.Hops, 1)
	require.Equal(t, "b", after.Hops[0].Tag,
		"and the path is the member the group committed to, in packet order")
	require.False(t, after.Ready(),
		"committed is not the same fact as ready: no hop here reports that its peer answers")
}

// TestStatusSelectionWithNoPreferenceIsUnknownNotConfigured is the third of the four states: a group
// with neither a configured default nor a stored selection must not be reported as having one.
func TestStatusSelectionWithNoPreferenceIsUnknownNotConfigured(t *testing.T) {
	instance, err := newBoxFromConfig(t, statusSelectorNoPreferenceConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	status := instance.Status("sel", "tcp")
	require.Len(t, status.Controls, 1)
	require.False(t, status.Controls[0].Committed)
	require.Empty(t, status.Controls[0].Decision,
		"the group falls back to its first declared member, and a fallback is not a preference "+
			"either, so it must not be reported as the current value")
	require.Contains(t, status.Controls[0].Reason, "unknown")
	require.Empty(t, status.Hops)
}

// TestStatusAfterCloseAnswersDisconnected is the lifecycle requirement end to end: Start, read,
// Close, read again. The second answer must describe the teardown rather than the last thing the
// view saw, and the value the caller already holds must be unaffected by it.
func TestStatusAfterCloseAnswersDisconnected(t *testing.T) {
	instance, err := newBoxFromConfig(t, statusTwoHopConfig)
	require.NoError(t, err)

	require.NoError(t, instance.Start())
	live := instance.Status("exit", "tcp")
	require.Len(t, live.Hops, 2, "the control: this path is readable while the Box is up")
	require.Equal(t, "entry", live.Hops[0].Tag, "Hops[0] is nearest this device")
	require.Equal(t, "exit", live.Exit)

	require.NoError(t, instance.Close())

	after := instance.Status("exit", "tcp")
	require.Empty(t, after.Hops,
		"a stale view must not describe a torn-down object graph as the current path")
	require.True(t, after.HasUnknown())
	require.Contains(t, after.Unknowns[0].Reason, "disconnected")
	require.False(t, after.Ready())

	// A value a caller already holds is a value: a later teardown cannot rewrite it.
	require.Len(t, live.Hops, 2)
	require.Equal(t, "entry", live.Hops[0].Tag)

	// And a repeated Close changes nothing about the answer.
	require.NoError(t, instance.Close())
	require.Empty(t, instance.Status("exit", "tcp").Hops)
}

// TestStatusAfterAStartErrorIsDisconnected pins the cleanup a failed Start performs. A Box whose
// Start refused the configuration is closed by Start itself, so the status surface must be detached
// by that path too - otherwise a caller could keep reading a graph that was never fully brought up.
func TestStatusAfterAStartErrorIsDisconnected(t *testing.T) {
	// This configuration is refused by the reachable-leaf dry run; see box_physicalpath_test.go.
	instance, err := newBoxFromConfig(t, physicalPathSelectorConfig)
	require.NoError(t, err, "construction cannot see this: it is a start-time decision")

	require.Error(t, instance.Start())

	after := instance.Status("sel", "tcp")
	require.Empty(t, after.Hops)
	require.True(t, after.HasUnknown())
	require.Contains(t, after.Unknowns[0].Reason, "disconnected",
		"a Start that failed must leave the status surface detached, not reporting the state of a "+
			"graph it abandoned halfway through starting")
	require.False(t, after.Ready())

	// A repeated Start is a repeated failure, and it must not resurrect the answer.
	require.Error(t, instance.Start())
	require.Empty(t, instance.Status("sel", "tcp").Hops)
}

// TestStatusAnswersAreValuesOwnedByTheCaller pins that no read-only API here hands out internal
// mutable state: a caller that writes through what it was given changes nothing.
//
// It matters more than it looks. The obvious "optimisation" for a status surface is to cache the
// last PathStatus and hand the same slices back, at which point one caller's slice mutation becomes
// every later caller's answer.
func TestStatusAnswersAreValuesOwnedByTheCaller(t *testing.T) {
	instance, err := newBoxFromConfig(t, statusTwoHopConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })
	require.NoError(t, instance.Start())

	first := instance.Status("exit", "tcp")
	require.Len(t, first.Hops, 2)

	// Clobber every part of the value the caller can reach.
	for index := range first.Hops {
		first.Hops[index].Tag = "clobbered"
		first.Hops[index].LeafTag = "clobbered"
		first.Hops[index].Reason = "clobbered"
		first.Hops[index].Type = "clobbered"
	}
	first.ControlPath = append(first.ControlPath, "clobbered")
	first.Unknowns = append(first.Unknowns, physicalpath.Unknown{Node: "clobbered", Reason: "clobbered"})
	first.Root = "clobbered"
	first.Entry = "clobbered"
	first.Exit = "clobbered"

	second := instance.Status("exit", "tcp")
	require.Equal(t, "exit", second.Root)
	require.Equal(t, "entry", second.Entry)
	require.Equal(t, "exit", second.Exit)
	require.Empty(t, second.ControlPath)
	require.Empty(t, second.Unknowns)
	require.Len(t, second.Hops, 2)
	require.Equal(t, []string{"entry", "exit"}, []string{second.Hops[0].Tag, second.Hops[1].Tag})
	for _, hop := range second.Hops {
		require.NotEqual(t, "clobbered", hop.Tag)
		require.NotContains(t, hop.Reason, "clobbered")
	}
	require.NotSame(t, &first.Hops[0], &second.Hops[0],
		"two reads must not share a backing array: one caller's write would otherwise be the "+
			"next caller's answer")
}

// TestStatusAnswersNeverContainSecrets is the redaction backstop at the Box level, because this is
// where a hop's own error text first reaches an embedder.
func TestStatusAnswersNeverContainSecrets(t *testing.T) {
	instance, err := newBoxFromConfig(t, statusSingleHopConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Close() })

	status := instance.Status("only", "tcp")
	for index, hop := range status.Hops {
		require.NotContains(t, strings.ToLower(hop.LastError), "password", "hop %d", index)
		require.NotContains(t, hop.LastError, "://", "a URL with userinfo must never survive")
	}
}
