package physicalpath

// PATH-02: the state a WALK needs is not the state a RESOLVER owns.
//
// # The two kinds of state, and why conflating them is a defect rather than a style choice
//
// A Resolver is the immutable view a walk is allowed to use: a lookup, a Snapshot and a pinned
// network. The walk itself needs two things that belong to ONE call and to nothing else:
//
//   - the network that call is answering for, because a group with a per-network answer must be
//     asked with the right one; and
//   - the answer each group gave DURING that call, because one walk must not ask the same group
//     twice and get two answers.
//
// When those two live on the Resolver, two walks through one Resolver cross-contaminate: a walk
// asks a group with the other walk's network, and a decision cache cleared by one walk answers a
// question belonging to the other. The tests below pin both, in three separate ways:
//
//  1. concurrently, where the Go race detector also has something to say (TestConcurrentBuild...,
//     TestConcurrentCrossNetworkAB...);
//  2. interleaved but globally ORDERED by channel handoffs, where the race detector has nothing to
//     say and only the assertions can catch the contamination
//     (TestInterleavedWalksOnOneResolverKeepTheirOwnNetwork); and
//  3. through the configuration entry points that made the Resolver mutable in the first place
//     (TestWithNetworkPinsACopy..., TestSnapshotIsFrozenAtConstruction).
//
// # A diagnostic race is not a route-selection race
//
// The state under test is the DIAGNOSTIC's: Build is read-only, it dials nothing, it commits no
// selection and it does not move a group's cursor. Corrupting it makes the REPORT wrong - the
// cached member of another walk, or a member chosen for the wrong network - it does not make the
// route path select differently. These tests therefore assert on what the walk REPORTS, and never
// claim that the route layer is broken.

import (
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// perNetworkGroup answers Selected from a per-network member table, and records every network it
// was asked with.
//
// testGroup cannot express this: it returns one member whatever the network, which is exactly the
// question a shared-network defect needs to distinguish. The recording is mutex-protected because
// the concurrent tests below ask this group from several goroutines at once; a fixture that raced
// on its own bookkeeping would make the race detector report the TEST rather than the Resolver.
type perNetworkGroup struct {
	testGroup
	byNetwork map[string]adapter.Outbound

	mu    sync.Mutex
	asked []string
	// gate runs inside Selected, after the network was recorded and before the answer is produced.
	// It is how a test takes control of the interleaving without relying on the scheduler.
	gate func(network string)
}

func newPerNetworkGroup(tag string, members []string, networks []string, byNetwork map[string]adapter.Outbound) *perNetworkGroup {
	return &perNetworkGroup{
		testGroup: testGroup{
			tag:       tag,
			groupType: "test-group",
			members:   members,
			networks:  networks,
		},
		byNetwork: byNetwork,
	}
}

func (g *perNetworkGroup) Selected(network string) adapter.Outbound {
	g.mu.Lock()
	g.asked = append(g.asked, network)
	g.mu.Unlock()
	if g.gate != nil {
		g.gate(network)
	}
	return g.byNetwork[network]
}

// askedNetworks returns the networks this group was asked with, in order.
func (g *perNetworkGroup) askedNetworks() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.asked...)
}

// twoNetworkFixture is the smallest graph that can answer "which network was this walk for": one
// group whose member depends on the network.
type twoNetworkFixture struct {
	group      *perNetworkGroup
	tcpMember  *testLeaf
	udpMember  *testLeaf
	registry   *testRegistry
	wantMember map[string]string
}

func newTwoNetworkFixture() *twoNetworkFixture {
	tcpMember := tcpLeaf("tcp-member")
	udpMember := &testLeaf{tag: "udp-member", leafType: "test", networks: []string{N.NetworkUDP}}
	group := newPerNetworkGroup("sel", []string{"tcp-member", "udp-member"},
		[]string{N.NetworkTCP, N.NetworkUDP},
		map[string]adapter.Outbound{N.NetworkTCP: tcpMember, N.NetworkUDP: udpMember})
	registry := newRegistry(tcpMember, udpMember, group)
	return &twoNetworkFixture{
		group:      group,
		tcpMember:  tcpMember,
		udpMember:  udpMember,
		registry:   registry,
		wantMember: map[string]string{N.NetworkTCP: "tcp-member", N.NetworkUDP: "udp-member"},
	}
}

// collectFailures drains a channel of assertion messages the worker goroutines could not raise
// themselves: require.FailNow must be called from the goroutine running the test.
func collectFailures(failures chan string) []string {
	var collected []string
	for message := range failures {
		collected = append(collected, message)
	}
	return collected
}

// TestConcurrentBuildOnSharedResolver is PATH-02's headline: the SAME Resolver, driven by two
// concurrent walks.
//
// It is written as the RED test on purpose. The Resolver's own documentation says "One Resolver
// answers consistently for its whole lifetime", and that is a promise about CONCURRENCY as much as
// about time: a caller that keeps one Resolver and validates two flows in parallel must get two
// consistent answers. Two things break it when the walk state lives on the Resolver - the network
// field is written by both walks and read by both walks, and the decision map is cleared and
// written by both walks.
//
// Every walk here asserts its OWN answer, so the test is meaningful after the fix as well: it is
// the regression guard for the shared state, not merely a race-detector tripwire.
func TestConcurrentBuildOnSharedResolver(t *testing.T) {
	fixture := newTwoNetworkFixture()
	shared := fixture.registry.resolver()

	const workers = 8
	const rounds = 300
	failures := make(chan string, workers*rounds)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		network := N.NetworkTCP
		if worker%2 == 1 {
			network = N.NetworkUDP
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := 0; round < rounds; round++ {
				path, err := Build(shared, TagOrOutbound{Outbound: fixture.group}, Options{Network: network})
				if err != nil {
					failures <- "network " + network + ": build failed: " + err.Error()
					return
				}
				exit, ok := path.Exit()
				if !ok {
					failures <- "network " + network + ": no verified exit; unknowns: " + path.Unknowns[0].Reason
					return
				}
				if exit.DeclaredTag != fixture.wantMember[network] {
					failures <- "network " + network + ": reported " + exit.DeclaredTag +
						" instead of " + fixture.wantMember[network]
					return
				}
			}
		}()
	}
	wait.Wait()
	close(failures)
	require.Empty(t, collectFailures(failures),
		"two walks through ONE Resolver must each report the member their own network selects")
}

// networkChain is one walk's own two-group chain: root -> mid (leaf) -> second group -> exit. The
// second group is what makes a contaminated walk network observable, because it is asked after the
// other walk has already run.
//
// The expected hops are compared as a SET, never as an ordered list: which end of a packet-order
// path is nearest this device is a separate question (answered by Path.Entry/Path.Exit and decided
// by the dial path, not by this test), and an ordering assertion here would silently re-decide it.
type networkChain struct {
	first   *perNetworkGroup
	second  *perNetworkGroup
	tags    []string
	objects []adapter.Outbound
}

func newNetworkChain(network string, prefix string) *networkChain {
	exit := &testLeaf{tag: prefix + "-exit", leafType: "test", networks: []string{network}}
	mid := &testLeaf{tag: prefix + "-mid", leafType: "test", networks: []string{network}, dependsOn: []string{prefix + "2"}}
	second := newPerNetworkGroup(prefix+"2", []string{prefix + "-exit"}, []string{network},
		map[string]adapter.Outbound{network: exit})
	first := newPerNetworkGroup(prefix+"1", []string{prefix + "-mid"}, []string{network},
		map[string]adapter.Outbound{network: mid})
	return &networkChain{
		first:   first,
		second:  second,
		tags:    []string{prefix + "-mid", prefix + "-exit"},
		objects: []adapter.Outbound{exit, mid, second, first},
	}
}

// sameTagSet compares two hop tag lists as sets, so a worker goroutine can decide without testify.
func sameTagSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, tag := range left {
		counts[tag]++
	}
	for _, tag := range right {
		counts[tag]--
		if counts[tag] < 0 {
			return false
		}
	}
	return true
}

// TestConcurrentCrossNetworkABOnSharedResolver is the A/B the walk network is about: one walk over
// TCP and one over UDP, through the SAME Resolver, each with its own groups as witnesses.
//
// The exit tag alone would not say whether the TCP walk was answered by the UDP member or by a
// member that happened to be cached; the per-group witness says it directly, because a group is
// asked with exactly one network and returns the member for that network only.
func TestConcurrentCrossNetworkABOnSharedResolver(t *testing.T) {
	tcp := newNetworkChain(N.NetworkTCP, "t")
	udp := newNetworkChain(N.NetworkUDP, "u")
	registry := newRegistry(append(append([]adapter.Outbound{}, tcp.objects...), udp.objects...)...)
	shared := registry.resolver()

	const rounds = 200
	failures := make(chan string, 2*rounds)
	var wait sync.WaitGroup
	walk := func(network string, chain *networkChain) {
		defer wait.Done()
		for round := 0; round < rounds; round++ {
			path, err := Build(shared, TagOrOutbound{Outbound: chain.first}, Options{Network: network})
			if err != nil {
				failures <- network + ": build failed: " + err.Error()
				return
			}
			if path.HasUnknown() {
				failures <- network + ": unknown hop: " + path.Unknowns[0].Reason
				return
			}
			hops := hopTagsAnyOrder(path)
			if !sameTagSet(hops, chain.tags) {
				failures <- network + ": resolved " + strings.Join(hops, ",") + " instead of " +
					strings.Join(chain.tags, ",")
				return
			}
		}
	}
	wait.Add(2)
	go walk(N.NetworkTCP, tcp)
	go walk(N.NetworkUDP, udp)
	wait.Wait()
	close(failures)
	require.Empty(t, collectFailures(failures))

	// The witness: every question each group was asked carried ITS walk's network, and nothing else.
	for _, chain := range []*networkChain{tcp, udp} {
		network := N.NetworkTCP
		if chain == udp {
			network = N.NetworkUDP
		}
		for _, group := range []*perNetworkGroup{chain.first, chain.second} {
			asked := group.askedNetworks()
			require.Len(t, asked, rounds, "each walk asks each of its groups exactly once per walk")
			for _, question := range asked {
				require.Equal(t, network, question,
					"group "+group.Tag()+" belongs to one walk's chain and must only ever be asked for "+
						"that walk's network")
			}
		}
	}

	// And a SEQUENTIAL A/B afterwards, on the same Resolver: the concurrent walks must have left no
	// network pinned behind them.
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		chain := tcp
		if network == N.NetworkUDP {
			chain = udp
		}
		path, err := Build(shared, TagOrOutbound{Outbound: chain.first}, Options{Network: network})
		require.NoError(t, err)
		require.False(t, path.HasUnknown(), "a sequential walk after concurrent use must still resolve")
		require.ElementsMatch(t, chain.tags, hopTagsAnyOrder(path),
			"the network a finished walk pinned must not survive into the next walk")
	}
}

// TestInterleavedWalksOnOneResolverKeepTheirOwnNetwork is the contamination that is NOT a data
// race.
//
// The two walks below are interleaved by explicit channel handoffs, so every access to the
// Resolver's state is ordered by happens-before and the race detector has nothing to report. The
// defect the test is aimed at survives that ordering, which is the point: a shared mutable field is
// wrong even when the accesses are serialised, because the value belongs to the WRONG WALK.
//
// The interleaving, step by step:
//
//	TCP walk: Build sets the walk network, enters group t1, t1 hands control over   <- paused
//	UDP walk: Build sets the walk network, enters group u1, u1 hands control back   <- paused
//	TCP walk: resumes and reaches group t2. The network it is answering for is the
//	          UDP walk's, because the UDP walk is still inside its own Build.
//	TCP walk: finishes, restoring the network to whatever it saw on entry.
//	UDP walk: resumes and reaches group u2, answering for an empty network - the
//	          value the TCP walk restored.
//
// Each walk's own chain has two groups for exactly this reason: the first is read before the
// handoff, the second after it.
func TestInterleavedWalksOnOneResolverKeepTheirOwnNetwork(t *testing.T) {
	tcp := newNetworkChain(N.NetworkTCP, "t")
	udp := newNetworkChain(N.NetworkUDP, "u")
	registry := newRegistry(append(append([]adapter.Outbound{}, tcp.objects...), udp.objects...)...)
	shared := registry.resolver()

	tcpFirst, udpFirst := tcp.first, udp.first
	tcpEntered := make(chan struct{})
	udpEntered := make(chan struct{})
	tcpFinished := make(chan struct{})

	tcpFirst.gate = func(string) {
		close(tcpEntered)
		<-udpEntered
	}
	udpFirst.gate = func(string) {
		close(udpEntered)
		<-tcpFinished
	}

	var tcpPath, udpPath Path
	var tcpErr, udpErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		tcpPath, tcpErr = Build(shared, TagOrOutbound{Outbound: tcpFirst}, Options{Network: N.NetworkTCP})
		close(tcpFinished)
	}()
	go func() {
		defer wait.Done()
		// The UDP walk starts only once the TCP walk is inside its first group, so the order of the
		// two Build calls is fixed rather than left to the scheduler.
		<-tcpEntered
		udpPath, udpErr = Build(shared, TagOrOutbound{Outbound: udpFirst}, Options{Network: N.NetworkUDP})
	}()
	wait.Wait()

	require.NoError(t, tcpErr)
	require.NoError(t, udpErr)

	require.False(t, tcpPath.HasUnknown(),
		"the TCP walk must resolve its whole chain; unknown: %s", tcpPath.Unknowns)
	require.ElementsMatch(t, tcp.tags, hopTagsAnyOrder(tcpPath),
		"the TCP walk must be answered by the TCP chain's members, not by the members the UDP walk's network selects")

	require.False(t, udpPath.HasUnknown(),
		"the UDP walk must resolve its whole chain; unknown: %s", udpPath.Unknowns)
	require.ElementsMatch(t, udp.tags, hopTagsAnyOrder(udpPath),
		"and the UDP walk must be answered by the UDP chain's members")

	// The witnesses. Each group was asked exactly once, by its own walk, with its own network.
	require.Equal(t, []string{N.NetworkTCP}, tcpFirst.askedNetworks(),
		"the TCP walk's entry group was asked for TCP")
	require.Equal(t, []string{N.NetworkTCP}, tcp.second.askedNetworks(),
		"and so was the second group on the TCP walk's chain")
	require.Equal(t, []string{N.NetworkUDP}, udpFirst.askedNetworks())
	require.Equal(t, []string{N.NetworkUDP}, udp.second.askedNetworks())
}

// TestOneWalkTakesOneAnswerPerGroup pins the other half of a walk's internal consistency: a group
// is asked ONCE per walk, and the path the walk reports is derived from that single answer.
//
// A fixture whose answer changes on every call makes the property observable: a walk that asked
// twice - or that re-read a decision another walk wrote - would report a different member than the
// one its single question produced.
func TestOneWalkTakesOneAnswerPerGroup(t *testing.T) {
	first := tcpLeaf("first")
	second := tcpLeaf("second")
	var questions int
	group := newPerNetworkGroup("sel", []string{"first", "second"}, []string{N.NetworkTCP}, nil)
	group.gate = func(string) {
		questions++
		if questions == 1 {
			group.byNetwork = map[string]adapter.Outbound{N.NetworkTCP: first}
			return
		}
		group.byNetwork = map[string]adapter.Outbound{N.NetworkTCP: second}
	}
	group.byNetwork = map[string]adapter.Outbound{N.NetworkTCP: first}
	registry := newRegistry(first, second, group)

	path, err := Build(registry.resolver(), TagOrOutbound{Outbound: group}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Unknowns)
	require.Equal(t, 1, questions, "one walk asks one group once")
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "first", exit.DeclaredTag,
		"the reported path must be the member the walk's single answer named")
}

// TestTwoGroupObjectsSharingATagAreTwoDecisionsNotOne pins the KEY of the per-walk decision record.
//
// The package closes loops by IDENTITY and says so: "a tag is configuration and two objects may
// share one, so a tag comparison could report a cycle that does not exist - or miss one that
// does". A decision record keyed by TAG contradicts that: the second group is never asked, the
// first group's answer is used for it, and the walk either reports a member the second group cannot
// reach or - as here - reports a cycle that does not exist.
func TestTwoGroupObjectsSharingATagAreTwoDecisionsNotOne(t *testing.T) {
	other := tcpLeaf("other")
	// Two DIFFERENT objects, one configured tag: the outer group hands the flow to the inner one.
	inner := newPerNetworkGroup("dup", []string{"other"}, []string{N.NetworkTCP},
		map[string]adapter.Outbound{N.NetworkTCP: other})
	outer := newPerNetworkGroup("dup", []string{"dup"}, []string{N.NetworkTCP},
		map[string]adapter.Outbound{N.NetworkTCP: inner})
	// The registry answers the shared tag with the inner object, which is what a tag lookup can do.
	registry := newRegistry(outer, inner, other)

	path, err := Build(registry.resolver(), TagOrOutbound{Outbound: outer}, Options{Network: N.NetworkTCP})
	require.NoError(t, err, "two objects that share a configured tag are two groups, not a cycle")
	require.Empty(t, path.Unknowns)
	require.Equal(t, []string{"other"}, hopTagsAnyOrder(path))
	require.Equal(t, []string{N.NetworkTCP}, inner.askedNetworks(),
		"the second group must be ASKED rather than answered from the first group's decision")
}

// TestWithNetworkPinsACopyAndLeavesTheReceiverUnchanged pins the immutability contract of the
// configurable part of a Resolver.
//
// A Resolver that can be reconfigured in place cannot be shared: WithNetwork would have to race
// every walk that is already running, and the caller has no way to say which view a walk should
// use. The pin therefore returns a resolver that carries the network and leaves the receiver as it
// was - which is also what makes the fluent form
// `NewResolver(..).WithNetwork(..).WithDomainResolvers(..)` mean what it reads as.
func TestWithNetworkPinsACopyAndLeavesTheReceiverUnchanged(t *testing.T) {
	fixture := newTwoNetworkFixture()
	base := fixture.registry.resolver()

	pinned := base.WithNetwork(N.NetworkUDP)

	udpPath, err := Build(pinned, TagOrOutbound{Outbound: fixture.group}, Options{})
	require.NoError(t, err)
	udpExit, ok := udpPath.Exit()
	require.True(t, ok)
	require.Equal(t, "udp-member", udpExit.DeclaredTag, "the pinned copy answers for its own network")

	tcpPath, err := Build(base, TagOrOutbound{Outbound: fixture.group}, Options{})
	require.NoError(t, err)
	tcpExit, ok := tcpPath.Exit()
	require.True(t, ok)
	require.Equal(t, "tcp-member", tcpExit.DeclaredTag,
		"the receiver must NOT have been reconfigured by the pin: it still answers for the default network")

	// And the per-walk override still wins over the pinned value, without changing the pin.
	overridePath, err := Build(pinned, TagOrOutbound{Outbound: fixture.group}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	overrideExit, ok := overridePath.Exit()
	require.True(t, ok)
	require.Equal(t, "tcp-member", overrideExit.DeclaredTag,
		"Options.Network is the walk's own network and overrides the pinned one")

	stillPinnedPath, err := Build(pinned, TagOrOutbound{Outbound: fixture.group}, Options{})
	require.NoError(t, err)
	stillPinnedExit, ok := stillPinnedPath.Exit()
	require.True(t, ok)
	require.Equal(t, "udp-member", stillPinnedExit.DeclaredTag,
		"and a walk that overrode the pin for itself must not have changed the pinned resolver")

	// The witness: the pinned resolver decided for UDP both times it decided by itself, the unpinned
	// receiver fell back to the default network, and the walk that overrode the pin used TCP for
	// itself only.
	require.Equal(t, []string{N.NetworkUDP, N.NetworkTCP, N.NetworkTCP, N.NetworkUDP}, fixture.group.askedNetworks(),
		"the pin is a property of the resolver it was asked of, and the override is a property of one walk")
}

// TestSnapshotIsFrozenAtConstruction pins the contract of the caller-supplied Snapshot.
//
// The Snapshot is read by the walk without synchronization, so "the caller must not modify it
// while a walk is running" would be a requirement the type cannot express and cannot check. The
// resolver therefore takes a frozen copy: mutating the caller's map afterwards neither changes an
// answer nor races a walk, and a caller that wants different answers builds a different Resolver.
func TestSnapshotIsFrozenAtConstruction(t *testing.T) {
	first := tcpLeaf("first")
	second := tcpLeaf("second")
	group := tcpGroup("sel", "first", "first", "second")
	registry := newRegistry(first, second, group)

	selections := map[string]string{"sel": "first"}
	candidates := map[string][]string{"sel": {"first", "second"}}
	resolver := NewResolver(registry.lookup, Snapshot{Selections: selections, Candidates: candidates})

	// The caller keeps using its own maps, which is what a caller does.
	selections["sel"] = "second"
	candidates["sel"][0] = "second"
	candidates["sel"] = []string{"second"}

	path, err := Build(resolver, TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "first", exit.DeclaredTag,
		"the snapshot the resolver was built with is the one it answers from")
	require.Equal(t, int64(0), group.selectionCount(),
		"a pinned snapshot asks the live group nothing")

	nodes, err := resolver.Hops(group)
	require.NoError(t, err)
	require.Len(t, nodes, 2,
		"the frozen CANDIDATE list is the one the enumeration reads, so both members are still reachable")
}

// TestConcurrentSnapshotMutationByTheCallerDoesNotRaceTheWalk is the same contract under load: the
// caller mutates the map it supplied, a walk runs against the resolver, and the resolver must
// neither observe the change nor race it.
//
// This is what "is concurrent modification by the caller supported" has to be answered with. It is
// NOT supported as a way to change an answer, and it does not have to be forbidden either: the
// resolver owns a copy, so the caller's map is none of its business.
func TestConcurrentSnapshotMutationByTheCallerDoesNotRaceTheWalk(t *testing.T) {
	first := tcpLeaf("first")
	second := tcpLeaf("second")
	group := tcpGroup("sel", "first", "first", "second")
	registry := newRegistry(first, second, group)

	selections := map[string]string{"sel": "first"}
	candidates := map[string][]string{"sel": {"first", "second"}}
	resolver := NewResolver(registry.lookup, Snapshot{Selections: selections, Candidates: candidates})

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			selections["sel"] = "second"
			candidates["sel"] = []string{"second", "first"}
			candidates["other"] = []string{"first"}
		}
	}()

	for round := 0; round < 200; round++ {
		path, err := Build(resolver, TagOrOutbound{Tag: "sel"}, Options{Network: N.NetworkTCP})
		require.NoError(t, err)
		exit, ok := path.Exit()
		require.True(t, ok)
		require.Equal(t, "first", exit.DeclaredTag)
	}
	close(stop)
	writer.Wait()
}

// hopTagsAnyOrder renders a built path's hop tags without depending on the packet-order direction,
// which is a separate question from the one these tests ask.
func hopTagsAnyOrder(path Path) []string {
	tags := make([]string, 0, len(path.Hops))
	for _, hop := range path.Hops {
		tags = append(tags, hop.DeclaredTag)
	}
	return tags
}
