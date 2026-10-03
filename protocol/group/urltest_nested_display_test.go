package group

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Tests for how a nested group's result is assembled in a DISPLAY-ONLY round.
//
// # The defect these pin
//
// A round recurses into a nested group and measures its leaves, then reports ONE delay for the
// nested group - the delay of whichever leaf it currently selects. That figure was read from the
// HEALTH layer unconditionally:
//
//	groupHistory := history.LoadURLTestHistoryFor(RealTag(nested, tcp), scope)
//
// A display-only round writes DISPLAY history, never health. So for a manual diagnostic the nested
// group's figure came from a layer the round had not written: either nothing, or a stale health
// value left by an earlier automatic check. The client was then shown a number that did not come
// from the measurement it asked for.

// countingLeaf is a leaf whose probe always succeeds, so a round completes normally.
type countingLeaf struct {
	adapter.Outbound
	tag   string
	dials atomic.Int32
}

func (o *countingLeaf) Type() string      { return "leaf" }
func (o *countingLeaf) Tag() string       { return o.tag }
func (o *countingLeaf) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *countingLeaf) DialContext(ctx context.Context, network string, destination metadata.Socksaddr) (net.Conn, error) {
	o.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *countingLeaf) ListenPacket(ctx context.Context, destination metadata.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

// selectingGroup is a nested group whose selection is fixed.
type selectingGroup struct {
	adapter.Outbound
	tag      string
	member   adapter.Outbound
	selected adapter.Outbound
}

func (g *selectingGroup) Type() string                             { return "selector" }
func (g *selectingGroup) Tag() string                              { return g.tag }
func (g *selectingGroup) Network() []string                        { return []string{N.NetworkTCP, N.NetworkUDP} }
func (g *selectingGroup) All() []string                            { return []string{g.member.Tag()} }
func (g *selectingGroup) Selected(string) adapter.Outbound         { return g.selected }
func (g *selectingGroup) AttachConnection(closer io.Closer) func() { return func() {} }

// TestDisplayOnlyNestedResultComesFromThisRound is §35.
//
// A stale health value for the leaf must not appear as the nested group's manual result, and the
// manual round must not disturb that health value.
func TestDisplayOnlyNestedResultComesFromThisRound(t *testing.T) {
	target := newRecordingServer(t)
	link := "http://127.0.0.1:" + portOf(t, target.address) + "/a"

	leaf := &countingLeaf{tag: "leaf-a"}
	nested := &selectingGroup{tag: "nested", member: leaf, selected: leaf}

	// The group's own measurement set, so the nested group is a member of it.
	group, storage := newGroupFixture(t, link, nested, leaf)

	// A STALE health value for the leaf, as an earlier automatic check would have left.
	const staleDelay = 999
	storage.StoreHealthHistory("leaf-a", group.scope,
		&adapter.URLTestHistory{Time: time.Now(), Delay: staleDelay})

	require.EqualValues(t, staleDelay,
		storage.LoadURLTestHistoryFor("leaf-a", group.scope).Delay,
		"the fixture must actually hold a stale health value")

	// A manual, display-only round - exactly what the Clash group delay endpoint runs.
	result := URLTestOutboundsWithTarget(context.Background(), &stubOutboundManager{}, storage,
		group.logger, group.outbounds, link, group.expected, 0, true, TestHistoryDisplayOnly)

	require.Contains(t, result, "nested",
		"a nested group must appear in a display-only result: it was measured through its leaves")

	require.NotEqualValues(t, uint16(staleDelay), result["nested"],
		"the nested group's manual result was read from the HEALTH layer, which a display-only "+
			"round never writes. The client was shown a stale value from an earlier automatic "+
			"check instead of the delay this round actually measured")

	require.Contains(t, result, "leaf-a",
		"the leaf itself is measured and reported")
	require.NotEqualValues(t, uint16(staleDelay), result["leaf-a"],
		"and its value likewise comes from this round")

	// The manual round must not have disturbed the automatic evidence.
	require.EqualValues(t, staleDelay,
		storage.LoadURLTestHistoryFor("leaf-a", group.scope).Delay,
		"a manual measurement overwrote health evidence; that makes a diagnostic into selection input")
}
