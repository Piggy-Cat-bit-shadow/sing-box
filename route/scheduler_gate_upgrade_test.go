package route

import (
	"io"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Phase 2B.0, post-handshake capability fork. Answered with the live production object.
//
// # Why this is the architecture fork
//
// A Go method set is static, so a gate cannot gain an interface merely because its upstream gained
// one. If the engine's post-handshake capabilities were exposed by a REPLACEMENT object becoming
// visible behind the gate, no static route-only wrapper could reflect them and the route-only design
// would be dead.
//
// The live VLESS conn shows the benign case instead: the same object changes the VALUES its methods
// return, on an unchanged method set.
//
//	NeedHandshakeForWrite()  !requestWritten     true  -> false
//	WriterReplaceable()      requestWritten      false -> true
//	FrontHeadroom()          RequestLen|0        >0    -> 0
//
// A gate that delegates these calls reflects both phases for free, which is what this pins.
//
// # Why FrontHeadroom specifically matters
//
// WriteOwnedBuffer resolves headroom from N.UnwrapWriter(destination) - the GATE - and uses it to
// decide whether to hand the buffer straight to ExtendedWriter.WriteBuffer or fall back to a raw
// copy. VLESS relies on that headroom for its first write: WriteBuffer does
// `buf.With(buffer.ExtendHeader(RequestLen(c.request)))`. A gate that fails to forward FrontHeadroom
// changes that decision, so this is a correctness-adjacent capability, not a cosmetic one.

// liveVLESSConn builds the same production object the VLESS outbound hands to the connection
// manager, over a local discard listener.
func liveVLESSConn(t *testing.T) *vless.Conn {
	t.Helper()
	rawConn := dialDiscardListener(t)
	client, err := vless.NewClient("2f0e6a1c-9f4b-4c1e-9b1a-7d3e5f8a0c22", "", log.NewNOPFactory().Logger())
	require.NoError(t, err)
	finalConn, err := client.DialEarlyConn(rawConn, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = finalConn.Close() })
	concrete, isConcrete := finalConn.(*vless.Conn)
	require.True(t, isConcrete, "the VLESS conn is the object under test")
	return concrete
}

// TestLiveVLESSUpgradesCapabilitiesInPlace pins the mechanism the route-only gate depends on.
func TestLiveVLESSUpgradesCapabilitiesInPlace(t *testing.T) {
	conn := liveVLESSConn(t)

	headroom, hasHeadroom := any(conn).(N.FrontHeadroom)
	require.True(t, hasHeadroom, "VLESS advertises front headroom")
	upstream, isReplaceable := any(conn).(N.WriterWithUpstream)
	require.True(t, isReplaceable, "VLESS advertises replaceability")

	// Pre-handshake.
	require.True(t, N.NeedHandshakeForWriteAny(conn), "the handshake is pending")
	require.False(t, upstream.WriterReplaceable(), "pre-handshake the conn is NOT replaceable")
	preHeadroom := headroom.FrontHeadroom()
	require.Positive(t, preHeadroom, "pre-handshake the request header needs front headroom")

	// Complete the handshake with one write.
	written, err := conn.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, len("hello"), written)

	// Post-handshake: SAME object, SAME method set, different values.
	require.False(t, N.NeedHandshakeForWriteAny(conn), "the handshake is done")
	require.True(t, upstream.WriterReplaceable(),
		"post-handshake the conn becomes replaceable - a behavioural change, not a new object")
	require.Zero(t, headroom.FrontHeadroom(),
		"and headroom drops to zero once the header has been written")

	require.NotEqual(t, preHeadroom, headroom.FrontHeadroom(),
		"the fixture is only meaningful if something actually changed")
}

// delegatingGate is the production gate shape: non-replaceable (so it is never unwrapped away and
// the scheduler stays in the path) but delegating the capability calls LIVE, so upstream behaviour
// changes are reflected.
type delegatingGate struct {
	upstream N.ExtendedWriter
}

func (g *delegatingGate) Write(p []byte) (int, error) { return g.upstream.Write(p) }

func (g *delegatingGate) WriteBuffer(buffer *buf.Buffer) error {
	return g.upstream.WriteBuffer(buffer)
}

func (g *delegatingGate) WriterReplaceable() bool { return false }

func (g *delegatingGate) UpstreamWriter() any { return g.upstream }

// Upstream() any is the probe channel common.Cast uses for handshake visibility.
func (g *delegatingGate) Upstream() any { return g.upstream }

// FrontHeadroom delegates live. A cached value captured at construction would be wrong after the
// handshake, because the same object changes its answer.
func (g *delegatingGate) FrontHeadroom() int {
	if headroom, ok := any(g.upstream).(N.FrontHeadroom); ok {
		return headroom.FrontHeadroom()
	}
	return 0
}

var (
	_ N.ExtendedWriter     = (*delegatingGate)(nil)
	_ N.WriterWithUpstream = (*delegatingGate)(nil)
	_ N.FrontHeadroom      = (*delegatingGate)(nil)
	_ N.WithUpstreamWriter = (*delegatingGate)(nil)
)

// TestGateReflectsUpstreamCapabilityChange proves the fork resolves in favour of route-only.
func TestGateReflectsUpstreamCapabilityChange(t *testing.T) {
	conn := liveVLESSConn(t)
	gate := &delegatingGate{upstream: conn}

	// The session can still see the pending handshake THROUGH the gate.
	require.True(t, N.NeedHandshakeForWriteAny(gate),
		"the gate must not hide the pending handshake, or refresh never runs")
	require.Positive(t, gate.FrontHeadroom(), "the gate reports the pre-handshake headroom")

	// The engine must NOT be able to unwrap past the gate.
	require.Same(t, io.Writer(gate), N.UnwrapWriter(gate),
		"the gate stays in the write path; otherwise the scheduler is bypassed")
	require.False(t, gate.WriterReplaceable())

	// Complete the handshake through the gate.
	written, err := gate.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, len("hello"), written)

	// Post-handshake the gate reflects the change without any reconstruction.
	require.False(t, N.NeedHandshakeForWriteAny(gate),
		"completion is visible through the gate, so ErrHandshakeCompleted can still fire")
	require.Zero(t, gate.FrontHeadroom(),
		"and the gate reports the NEW headroom, because it delegates live rather than caching")
}

// TestCachingHeadroomWouldBreakTheUpgrade is the discriminating control for the delegation rule: a
// gate that captured headroom once would report a stale value after the handshake. Documented as a
// type rather than asserted against production code so the contrast is explicit.
type cachingGate struct {
	upstream      N.ExtendedWriter
	frontHeadroom int
}

func newCachingGate(upstream N.ExtendedWriter) *cachingGate {
	gate := &cachingGate{upstream: upstream}
	if headroom, ok := any(upstream).(N.FrontHeadroom); ok {
		gate.frontHeadroom = headroom.FrontHeadroom()
	}
	return gate
}

func (g *cachingGate) Write(p []byte) (int, error) { return g.upstream.Write(p) }
func (g *cachingGate) WriteBuffer(buffer *buf.Buffer) error {
	return g.upstream.WriteBuffer(buffer)
}
func (g *cachingGate) WriterReplaceable() bool { return false }
func (g *cachingGate) UpstreamWriter() any     { return g.upstream }
func (g *cachingGate) FrontHeadroom() int      { return g.frontHeadroom }

func TestCachingHeadroomWouldBreakTheUpgrade(t *testing.T) {
	conn := liveVLESSConn(t)
	stale := newCachingGate(conn)
	live := &delegatingGate{upstream: conn}

	require.Equal(t, stale.FrontHeadroom(), live.FrontHeadroom(), "same before the handshake")

	_, err := stale.Write([]byte("hello"))
	require.NoError(t, err)

	require.NotEqual(t, live.FrontHeadroom(), stale.FrontHeadroom(),
		"after the handshake the caching gate reports a stale headroom while the delegating gate "+
			"reports the live value - this is why the gate must delegate rather than snapshot")
	require.Zero(t, live.FrontHeadroom())
	require.Positive(t, stale.FrontHeadroom())
}
