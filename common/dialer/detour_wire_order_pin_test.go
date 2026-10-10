package dialer

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/physicalpath"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// The direction the wire observation settled, PINNED TO THE MODEL
// ---------------------------------------------------------------------------
//
// TestTheDetourServerIsReachedFirst observes the real `NewDetour` plumbing and concludes that the hop
// nearest this device is the DEEPEST DEPENDENCY. That observation is independent of
// common/physicalpath and is the right way to establish the direction.
//
// What it does NOT do is connect the conclusion to common/physicalpath. It is a test in package
// dialer: it builds fake outbounds, dials through NewDetour, and asserts on the log those outbounds
// produced. It never calls physicalpath.Build, so it cannot fail when Build's ordering is wrong - and
// its sibling TestThePacketOrderContractIsTheReverseOfTheDependencyWalk reverses a hard-coded literal
// `[]string{"exit", "middle", "entry"}` with its own loop, which is a tautology about a slice literal
// rather than an observation of anything.
//
// MEASURED, and this is why the file below exists: with `reversePacketOrder(&path)` deleted from
// Build (the single call that establishes packet order), ALL FOUR tests in detour_wire_order_test.go
// still pass, while nine tests in the physicalpath package go red. The direction test is green for
// the wrong reason.
//
// This file closes the loop: it takes the hop the wire test's own plumbing reaches LAST (the
// innermost dependency, which is the hop nearest the device) and asserts that
// common/physicalpath reports it FIRST. Every expected value here is read out of the wire log, not
// written next to the code it is checking.

// wireOrderLeaf is a hop shaped like a proxy outbound: it reaches ITS OWN SERVER through a `detour`,
// which is the edge `physicalpath.Build` and `NewDetour` both read.
type wireOrderLeaf struct {
	tag      string
	server   M.Socksaddr
	detour   string
	networks []string
}

func (l *wireOrderLeaf) Type() string      { return "wire-order-leaf" }
func (l *wireOrderLeaf) Tag() string       { return l.tag }
func (l *wireOrderLeaf) Network() []string { return l.networks }
func (l *wireOrderLeaf) Dependencies() []string {
	if l.detour == "" {
		return nil
	}
	return []string{l.detour}
}
func (l *wireOrderLeaf) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, N.ErrUnknownNetwork
}
func (l *wireOrderLeaf) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, N.ErrUnknownNetwork
}

// TestTheModelAgreesWithTheWireAboutWhichHopIsNearest is the connection the existing test omits.
//
// The topology is the exact one TestTheThreeHopDetourReachesTheInnermostServerFirst measures:
//
//	c.detour = b ; b.detour = a
//
// The wire observation is `log.tags() == ["b", "a"]`: the chain is entered at b and then at a, so the
// hop nearest this device is `a`, the DEEPEST dependency - which is the last tag the observation
// names. `Hops[0]` must therefore be `a`. Removing the reversal in `reversePacketOrder` makes it `c`,
// and this test fails; that is the property the existing tests lack.
func TestTheModelAgreesWithTheWireAboutWhichHopIsNearest(t *testing.T) {
	a := &wireOrderLeaf{tag: "a", server: M.ParseSocksaddr("192.0.2.1:1080"), networks: []string{N.NetworkTCP, N.NetworkUDP}}
	b := &wireOrderLeaf{tag: "b", server: M.ParseSocksaddr("192.0.2.2:1080"), detour: "a", networks: []string{N.NetworkTCP, N.NetworkUDP}}
	c := &wireOrderLeaf{tag: "c", server: M.ParseSocksaddr("192.0.2.3:1080"), detour: "b", networks: []string{N.NetworkTCP, N.NetworkUDP}}

	// The chain driven through the REAL detour constructor, recording which hop is entered first.
	// The assertion below reads its expected values out of this log.
	log := &reachLog{}
	innermost := &recordingServerLeaf{tag: "a", leafType: "socks", log: log}
	bToA := NewDetour(&detourManager{byTag: map[string]adapter.Outbound{"a": innermost}}, "a", false)
	hopB := &hopLeaf{tag: "b", server: b.server, inner: bToA, leafType: "socks", log: log}
	cToB := NewDetour(&detourManager{byTag: map[string]adapter.Outbound{"b": hopB}}, "b", false)

	conn, err := cToB.DialContext(context.Background(), N.NetworkTCP, c.server)
	require.NoError(t, err)
	defer conn.Close()

	entered := log.tags()
	require.Equal(t, []string{"b", "a"}, entered,
		"the premise: the wire observation must enter b and then a, or the assertion below is anchored "+
			"to nothing")
	// The hop nearest this device is the one the traversal reaches LAST, because each hop is entered
	// only to carry the next one's server dial.
	nearestThisDevice := entered[len(entered)-1]
	require.Equal(t, "a", nearestThisDevice, "the deepest dependency is the innermost hop")

	objects := map[string]adapter.Outbound{"a": a, "b": b, "c": c}
	resolver := physicalpath.NewResolver(func(tag string) (adapter.Outbound, bool) {
		object, loaded := objects[tag]
		return object, loaded
	}, physicalpath.Snapshot{})

	path, err := physicalpath.Build(resolver,
		physicalpath.TagOrOutbound{Outbound: c}, physicalpath.Options{Network: N.NetworkTCP})
	require.NoError(t, err)
	require.Empty(t, path.Unknowns)
	require.Len(t, path.Hops, 3)

	// THE ASSERTION. `Hops[0]` is documented as the hop nearest this device; the wire says that hop
	// is the last tag the traversal entered.
	require.Equal(t, nearestThisDevice, path.Hops[0].DeclaredTag,
		"common/physicalpath reports %q as the hop nearest this device, and the real detour plumbing "+
			"reaches %q last (%v). Hops is documented as PACKET order with Hops[0] nearest the device, "+
			"so the two must name the same hop. Model order: %v",
		path.Hops[0].DeclaredTag, nearestThisDevice, entered, hopTagsOf(path))

	// And the exit is the far end, so the two APIs cannot mean opposite things by "exit".
	exit, ok := path.Exit()
	require.True(t, ok)
	require.Equal(t, "c", exit.DeclaredTag,
		"the routing selected c, and c is the hop the flow LEAVES from")
	entry, ok := path.Entry()
	require.True(t, ok)
	require.Equal(t, nearestThisDevice, entry.DeclaredTag)

	// Position 0 must be the same hop Hops[0] is, or a consumer indexing by Position names a
	// different hop from a consumer indexing by slice order.
	require.Equal(t, 0, path.Hops[0].Position)
	for index, hop := range path.Hops {
		require.Equal(t, index, hop.Position,
			"positions are contiguous and agree with packet order")
	}
}

// hopTagsOf renders a built path so a failure message names the whole order.
func hopTagsOf(path physicalpath.Path) []string {
	tags := make([]string, 0, len(path.Hops))
	for _, hop := range path.Hops {
		tags = append(tags, hop.DeclaredTag)
	}
	return tags
}
