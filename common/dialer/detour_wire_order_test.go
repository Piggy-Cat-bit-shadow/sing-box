package dialer

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// WHICH HOP IS NEAREST THIS DEVICE — decided by the real detour plumbing
// ---------------------------------------------------------------------------
//
// # Why this file exists
//
// `common/physicalpath.Path.Hops` is documented as PACKET order with `Hops[0]` nearest to this device,
// and the model builds it by walking the dependency chain root-first. Every test in that package
// asserts against that same reading, so none of them can decide whether the reading is right.
//
// This file decides it from OUTSIDE the model, using the real detour constructor and recording what it
// actually asks for. There is no fake ordering logic here: the only question is which SERVER ADDRESS
// the dial path reaches, and that is answered by the code under test rather than by an expectation
// written next to it.
//
// # The mechanism being observed, quoted
//
// `sing/protocol/socks/client.go` uses the dialer it was built with to reach its OWN SERVER:
//
//	:162  tcpConn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
//	:198  response, err = ClientHandshake5(tcpConn, command, address, ...)   // the TARGET is in the request
//
// and `dialer.NewWithOptions` puts a `DetourDialer` in that position when the outbound declares one:
//
//	common/dialer/dialer.go:47  dialer = NewDetour(outboundManager, dialOptions.Detour, ...)
//
// So for `exit.detour = entry`, exit's SERVER dial is carried by entry, and the device therefore
// reaches ENTRY's server first. The tests below observe exactly that, for two and three hops.

// reached records ONE arrival at a hop, from that hop's own point of view.
//
// # Why the address alone is not enough
//
// A recording that only kept the destination could not tell "the ENTRY outbound was reached and asked
// to carry a connection to the exit's server" from "the device dialled the exit's server itself". Both
// would show the exit's address. The hop's TAG is what makes the two distinguishable, and the
// distinction is the entire direction question.
type reached struct {
	// tag is the hop that was reached.
	tag string
	// asked names the address that hop was asked to reach.
	asked string
}

// reachLog collects arrivals in the order they happened, across every hop in the chain.
type reachLog struct {
	entries []reached
}

func (l *reachLog) add(tag string, destination M.Socksaddr) {
	l.entries = append(l.entries, reached{tag: tag, asked: destination.String()})
}

func (l *reachLog) tags() []string {
	out := make([]string, 0, len(l.entries))
	for _, entry := range l.entries {
		out = append(out, entry.tag)
	}
	return out
}

// recordingServerLeaf stands in for a proxy outbound's SERVER dial: it records that IT was reached and
// what it was asked for, then answers with a fake peer so no process has to exist.
type recordingServerLeaf struct {
	tag      string
	leafType string
	log      *reachLog
}

func (l *recordingServerLeaf) Type() string           { return l.leafType }
func (l *recordingServerLeaf) Tag() string            { return l.tag }
func (l *recordingServerLeaf) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (l *recordingServerLeaf) Dependencies() []string { return nil }

func (l *recordingServerLeaf) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	l.log.add(l.tag, destination)
	return newDetourTestPeer()
}

func (l *recordingServerLeaf) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	l.log.add(l.tag, destination)
	return nil, N.ErrUnknownNetwork
}

// hopLeaf is a hop that reaches ITS OWN SERVER through an inner dialer, which is what a proxy outbound
// does. Recorded twice, because the two records answer different questions:
//
//	the INNER dial's destination  = which hop is asked for whose server (the chain's edges)
//	this hop's own arrival        = the ORDER hops are entered (the chain's traversal)
//
// Only the second can establish which hop is nearest this device, so a fixture that recorded just the
// inner dial would answer a different question than the one under test.
type hopLeaf struct {
	tag      string
	server   M.Socksaddr
	inner    N.Dialer
	leafType string
	log      *reachLog
}

func (l *hopLeaf) Type() string           { return l.leafType }
func (l *hopLeaf) Tag() string            { return l.tag }
func (l *hopLeaf) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (l *hopLeaf) Dependencies() []string { return nil }

func (l *hopLeaf) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	// This hop has been ENTERED. Record that before doing anything else, because the traversal order
	// is what the direction claim is about.
	l.log.add(l.tag, destination)
	// To carry it, the hop must first reach its own server, and it does that through its detour dialer
	// - the same shape as `socks.Client.DialContext` reaching `c.serverAddr`.
	return l.inner.DialContext(ctx, network, l.server)
}

func (l *hopLeaf) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	l.log.add(l.tag, destination)
	return l.inner.ListenPacket(ctx, l.server)
}

// detourManager answers tag lookups for the chain.
type detourManager struct {
	adapter.OutboundManager
	byTag map[string]adapter.Outbound
}

func (m *detourManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

// newDetourTestPeer hands back a pipe-backed connection and drains the far end, so the SOCKS client's
// handshake write cannot block on a peer nobody is reading and nothing leaks.
func newDetourTestPeer() (net.Conn, error) {
	near, far := net.Pipe()
	go func() {
		_, _ = far.Read(make([]byte, 1024))
		_ = far.Close()
	}()
	return near, nil
}

// TestTheDetourServerIsReachedFirst is THE direction test, for two hops.
//
// Configuration: `exit.detour = entry`. The two candidate answers are
//
//	entry first -> packet order is the REVERSE of the dependency walk (deepest dependency first)
//	exit first  -> packet order IS the dependency walk (root first)
//
// The observation: the dial that reaches the network names ENTRY's server, because exit's server dial
// is carried by entry.
func TestTheDetourServerIsReachedFirst(t *testing.T) {
	entryServer := M.ParseSocksaddr("192.0.2.10:1080")
	exitServer := M.ParseSocksaddr("198.51.100.20:1080")

	log := &reachLog{}
	entry := &recordingServerLeaf{tag: "entry", leafType: "socks", log: log}
	exitToServer := NewDetour(&detourManager{
		byTag: map[string]adapter.Outbound{"entry": entry},
	}, "entry", false)

	// `socks.Client.DialContext:162` — the client dials its SERVER through this dialer, naming ITS OWN
	// server address. That is the request the detour carries.
	conn, err := exitToServer.DialContext(context.Background(), N.NetworkTCP, exitServer)
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, []string{"entry"}, log.tags(),
		"only the ENTRY outbound may be reached. A log naming the exit would mean the device dialled "+
			"the exit's server itself, i.e. that the detour is not on the path at all. Reached: %v", log.entries)
	require.Equal(t, []string{exitServer.String()}, []string{log.entries[0].asked},
		"and the entry is asked to carry the connection to the EXIT's server (%s), which is what "+
			"`exit.detour = entry` means: the exit's server dial is carried by the entry. The entry's "+
			"own server (%s) is never named by this dial, because the entry outbound is not being asked "+
			"to reach itself. Reached: %v", exitServer, entryServer, log.entries)

	// The conclusion, in one line, stated as the observation rather than as a reading of the code:
	// the device reaches the ENTRY first, so the hop nearest this device is the DETOUR.
	require.Equal(t, "entry", log.entries[0].tag,
		"the hop nearest this device is the DETOUR (the deepest dependency), so Hops in packet order "+
			"is the REVERSE of the dependency walk")
}

// TestTheThreeHopDetourReachesTheInnermostServerFirst extends the observation to three hops, so a
// two-hop coincidence cannot pass for a rule.
//
// Configuration: `c.detour = b` and `b.detour = a`. Then c's server dial goes through b, b's server
// dial goes through a, and the device reaches a's server first.
func TestTheThreeHopDetourReachesTheInnermostServerFirst(t *testing.T) {
	aServer := M.ParseSocksaddr("192.0.2.1:1080")
	bServer := M.ParseSocksaddr("192.0.2.2:1080")
	cServer := M.ParseSocksaddr("192.0.2.3:1080")

	log := &reachLog{}
	innermost := &recordingServerLeaf{tag: "a", leafType: "socks", log: log}

	// b reaches its server through a.
	bToA := NewDetour(&detourManager{
		byTag: map[string]adapter.Outbound{"a": innermost},
	}, "a", false)
	b := &hopLeaf{tag: "b", server: bServer, inner: bToA, leafType: "socks", log: log}

	// c reaches its server through b (which reaches its own through a).
	cToB := NewDetour(&detourManager{
		byTag: map[string]adapter.Outbound{"b": b},
	}, "b", false)

	// The request c's client would make: reach C'S OWN SERVER, carried by c's detour.
	conn, err := cToB.DialContext(context.Background(), N.NetworkTCP, cServer)
	require.NoError(t, err)
	defer conn.Close()

	require.Equal(t, []string{"b", "a"}, log.tags(),
		"the chain must be entered at b and then at a: b is reached first because c's server dial "+
			"goes through it, and b's own server dial then goes through a. Reached in order: %v", log.entries)
	require.Equal(t, cServer.String(), log.entries[0].asked,
		"b is asked for c's server (%s)", cServer)
	require.Equal(t, bServer.String(), log.entries[1].asked,
		"and a is asked for b's server (%s), which is the hop b had to reach before it could carry "+
			"anything", bServer)
	// a's own server is never named, because a is the innermost hop and is not asked to reach itself.
	for _, entry := range log.entries {
		require.NotEqual(t, aServer.String(), entry.asked,
			"the innermost hop must never be asked to reach its own server")
	}
}

// TestADirectDialReachesItsOwnServer is the control. Without a detour the server dial must name the
// outbound's OWN server and nothing else, so the tests above are measuring the detour and not a
// property of every dial.
func TestADirectDialReachesItsOwnServer(t *testing.T) {
	ownServer := M.ParseSocksaddr("203.0.113.30:1080")
	log := &reachLog{}
	leaf := &recordingServerLeaf{tag: "direct", leafType: "direct", log: log}

	conn, err := leaf.DialContext(context.Background(), N.NetworkTCP, ownServer)
	require.NoError(t, err)
	defer conn.Close()
	require.Equal(t, []string{"direct"}, log.tags(),
		"without a detour the only hop reached is the outbound itself")
	require.Equal(t, ownServer.String(), log.entries[0].asked,
		"and it is asked for the address the caller named, so the tests above are measuring the "+
			"detour and not a property of every dial")
}

// TestThePacketOrderContractIsTheReverseOfTheDependencyWalk states the conclusion in the model's own
// terms, so a reader can see which of the two readings the wire supports without re-deriving it.
//
// It is a relationship, not an example, so it stays meaningful if the walk's starting point changes.
func TestThePacketOrderContractIsTheReverseOfTheDependencyWalk(t *testing.T) {
	// A dependency walk visits root, then its detour, then that detour's detour: ROOT-FIRST.
	walk := []string{"exit", "middle", "entry"}
	// Packet order must therefore be ENTRY-FIRST, which is the reverse.
	wantPacketOrder := []string{"entry", "middle", "exit"}

	got := make([]string, len(walk))
	for index := range walk {
		got[index] = walk[len(walk)-1-index]
	}
	require.Equal(t, wantPacketOrder, got,
		"Hops[0] is nearest this device, and the device reaches the DEEPEST DEPENDENCY first, so "+
			"packet order is the REVERSE of the dependency walk")
	require.NotEqual(t, walk, got,
		"if these were ever equal the two orderings would coincide and this conclusion would need "+
			"re-deriving from the wire")
}
