package route

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Phase 2B.0, handshake hazard.
//
// # The mechanism
//
// The copy session detects a completed handshake through N.HandshakeState, which holds the
// POST-UNWRAP destination - i.e. the gate:
//
//	destination: the writer the session actually writes to
//	writePending: NeedHandshakeForWriteAny(destination)
//	Check():      writePending && !NeedHandshakeForWriteAny(destination) -> ErrHandshakeCompleted
//
// and NeedHandshakeForWriteAny probes with common.Cast, which unwraps through common.WithUpstream
// (the `Upstream() any` method) - a DIFFERENT interface from N.WriterWithUpstream:
//
//	common.Cast       unwraps via  Upstream() any            (common.WithUpstream)
//	UnwrapWriter      unwraps via  WriterReplaceable() bool  (N.WriterWithUpstream)
//	CastWriter[T]     unwraps via  WriterReplaceable() bool
//	SyscallConnForWrite unwraps via WriterReplaceable() bool
//
// So the two are orthogonal, and that is what makes a route-only gate possible:
//
//	WriterReplaceable() == false   keeps the scheduler in the write path and disables copyDirect
//	Upstream() any                 lets capability PROBING still see through the gate
//
// A gate that omits Upstream() hides the handshake from the session entirely: writePending reads
// false, HandshakeState.Upgradable() is false, and refreshUnwrap never runs - so any capability or
// counter the post-handshake writer would have exposed is silently never rediscovered. Data still
// flows, which is what makes it a §47-style silent degradation rather than a failure.

// handshakeUpgradable reports that it needs a handshake until its first write, then stops.
type handshakeUpgradable struct {
	upstream N.ExtendedWriter
	done     atomic.Bool
	writes   atomic.Int64
}

func (w *handshakeUpgradable) NeedHandshakeForWrite() bool { return !w.done.Load() }

func (w *handshakeUpgradable) Write(p []byte) (int, error) {
	w.writes.Add(1)
	w.done.Store(true)
	return w.upstream.Write(p)
}

func (w *handshakeUpgradable) WriteBuffer(buffer *buf.Buffer) error {
	w.writes.Add(1)
	w.done.Store(true)
	return w.upstream.WriteBuffer(buffer)
}

// gateWithUpstream is the gate shape that preserves handshake probing.
type gateWithUpstream struct {
	upstream N.ExtendedWriter
	writes   atomic.Int64
}

func (g *gateWithUpstream) Write(p []byte) (int, error) {
	g.writes.Add(1)
	return g.upstream.Write(p)
}

func (g *gateWithUpstream) WriteBuffer(buffer *buf.Buffer) error {
	g.writes.Add(1)
	return g.upstream.WriteBuffer(buffer)
}

func (g *gateWithUpstream) WriterReplaceable() bool { return false }

func (g *gateWithUpstream) UpstreamWriter() io.Writer { return g.upstream }

// Upstream() any is the probe channel. It does NOT re-enable unwrapping for the write path.
func (g *gateWithUpstream) Upstream() any { return g.upstream }

// gateWithoutUpstream is the same gate minus the probe channel: the hazard.
type gateWithoutUpstream struct {
	upstream N.ExtendedWriter
}

func (g *gateWithoutUpstream) Write(p []byte) (int, error) { return g.upstream.Write(p) }

func (g *gateWithoutUpstream) WriteBuffer(buffer *buf.Buffer) error {
	return g.upstream.WriteBuffer(buffer)
}

func (g *gateWithoutUpstream) WriterReplaceable() bool { return false }

func (g *gateWithoutUpstream) UpstreamWriter() io.Writer { return g.upstream }

var (
	_ N.EarlyWriter        = (*handshakeUpgradable)(nil)
	_ N.ExtendedWriter     = (*handshakeUpgradable)(nil)
	_ N.WriterWithUpstream = (*gateWithUpstream)(nil)
	_ N.WriterWithUpstream = (*gateWithoutUpstream)(nil)
)

func newUpgradable(t *testing.T) (*countingSink, *handshakeUpgradable) {
	t.Helper()
	sink := &countingSink{}
	return sink, &handshakeUpgradable{upstream: sink}
}

// TestHandshakeIsVisibleThroughAProbingGate is the fix: a gate that exposes Upstream() keeps the
// handshake visible, so the session still detects completion and still refreshes.
func TestHandshakeIsVisibleThroughAProbingGate(t *testing.T) {
	_, upgradable := newUpgradable(t)
	gate := &gateWithUpstream{upstream: upgradable}

	require.True(t, N.NeedHandshakeForWriteAny(upgradable), "precondition: the writer starts needing a handshake")
	require.True(t, N.NeedHandshakeForWriteAny(gate),
		"the session must still see the pending handshake through the gate, or refreshUnwrap "+
			"never runs and post-handshake capabilities are silently never rediscovered")

	state := N.NewHandshakeState(strings.NewReader(""), gate)
	require.True(t, state.Upgradable(),
		"the session must consider this direction upgradable, or it will not check for completion")

	// Complete the handshake by writing.
	_, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("hello"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)

	require.False(t, N.NeedHandshakeForWriteAny(gate), "after the first write the handshake is done")
	require.ErrorIs(t, state.Check(), N.ErrHandshakeCompleted,
		"the session must observe completion so it can refresh")
	require.Positive(t, gate.writes.Load(), "and the gate stayed in the write path")
}

// TestHandshakeIsHiddenByAGateWithoutProbeChannel is the hazard, demonstrated.
//
// Without Upstream(), the session cannot see the pending handshake at all: it concludes there is
// nothing to upgrade rather than reporting an error. No data is lost, which is exactly why this
// failure is easy to ship.
func TestHandshakeIsHiddenByAGateWithoutProbeChannel(t *testing.T) {
	sink, upgradable := newUpgradable(t)
	gate := &gateWithoutUpstream{upstream: upgradable}

	require.True(t, N.NeedHandshakeForWriteAny(upgradable))

	require.False(t, N.NeedHandshakeForWriteAny(gate),
		"a gate without a probe channel hides the pending handshake from the session")

	state := N.NewHandshakeState(strings.NewReader(""), gate)
	require.False(t, state.Upgradable(),
		"so the session never treats this direction as upgradable")

	require.NoError(t, state.Check(),
		"and Check never reports completion - refreshUnwrap is unreachable, silently")

	// Data still flows correctly, which is the point: nothing looks broken.
	_, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("hello"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, 1, upgradable.writes.Load(), "one write call reached the writer")
	require.EqualValues(t, len("hello"), sink.received,
		"and every byte was delivered, which is why this failure ships unnoticed: the data path "+
			"is correct and only the upgrade is lost")
}
