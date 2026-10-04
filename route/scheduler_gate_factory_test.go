package route

import (
	"io"
	"math"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// Phase 2B.0: the production-shaped gate factory.
//
// This replaces the per-test gate types that earlier commits introduced (countWriter,
// nonReplaceableGate, counterPreservingAdapter, delegatingGate, cachingGate) with one model the
// integrity tests and the future production scheduler share, so the shape cannot drift between them.
//
// # The contract
//
//	WriterReplaceable() == false   never unwrapped -> scheduler stays in the write PATH
//	Upstream() any                 common.Cast probe channel -> handshake stays VISIBLE
//	capability methods             delegate LIVE, never snapshot
//	optional capabilities          only the shapes the upstream actually supports
//
// # Why two concrete shapes rather than one mega-wrapper
//
// The engine discovers capabilities by direct type assertion (CreateVectorisedWriter) as well as
// through common.Cast. A single wrapper that unconditionally implemented every optional interface
// would advertise capabilities the upstream does not have and change path selection. The factory
// therefore picks the smallest truthful shape.

// schedulerGateCore is shared by every gate shape.
type schedulerGateCore struct {
	upstream io.Writer
	admitted atomic.Int64
}

// admits records one admission and is the single place the future scheduler hook attaches.
func (c *schedulerGateCore) admits() { c.admitted.Add(1) }

// gatePlain is used when the upstream is NOT an ExtendedWriter: it must not claim WriteBuffer.
type gatePlain struct {
	schedulerGateCore
}

func (g *gatePlain) Write(p []byte) (int, error) {
	g.admits()
	return g.upstream.Write(p)
}

func (g *gatePlain) WriterReplaceable() bool { return false }

func (g *gatePlain) UpstreamWriter() any { return g.upstream }

func (g *gatePlain) Upstream() any { return g.upstream }

// gateExtended is used when the upstream IS an ExtendedWriter, so WriteBuffer is preserved.
type gateExtended struct {
	schedulerGateCore
	extended N.ExtendedWriter
}

func (g *gateExtended) Write(p []byte) (int, error) {
	g.admits()
	return g.upstream.Write(p)
}

// WriteBuffer forwards ownership: the upstream releases the buffer, so the gate must not.
func (g *gateExtended) WriteBuffer(buffer *buf.Buffer) error {
	g.admits()
	return g.extended.WriteBuffer(buffer)
}

func (g *gateExtended) WriterReplaceable() bool { return false }

func (g *gateExtended) UpstreamWriter() any { return g.upstream }

func (g *gateExtended) Upstream() any { return g.upstream }

// Geometry delegates LIVE. A snapshot goes stale exactly the way the live VLESS conn showed:
// FrontHeadroom goes from RequestLen(request) to 0 across the handshake on the same object.
//
// When the upstream does not expose a geometry, the gate reports the value that makes
// WriteOwnedBuffer's check vacuous - and the test below proves that is behaviourally identical to
// not implementing the interface at all, rather than assuming it.
func (g *gateExtended) FrontHeadroom() int {
	if headroom, ok := g.upstream.(N.FrontHeadroom); ok {
		return headroom.FrontHeadroom()
	}
	return 0
}

func (g *gateExtended) RearHeadroom() int {
	if headroom, ok := g.upstream.(N.RearHeadroom); ok {
		return headroom.RearHeadroom()
	}
	return 0
}

func (g *gateExtended) WriterMTU() int {
	if withMTU, ok := g.upstream.(N.WriterWithMTU); ok {
		return withMTU.WriterMTU()
	}
	return math.MaxInt
}

var (
	_ N.ExtendedWriter     = (*gateExtended)(nil)
	_ N.WriterWithUpstream = (*gatePlain)(nil)
	_ N.WriterWithUpstream = (*gateExtended)(nil)
	_ N.WithUpstreamWriter = (*gateExtended)(nil)
	_ N.FrontHeadroom      = (*gateExtended)(nil)
	_ N.RearHeadroom       = (*gateExtended)(nil)
	_ N.WriterWithMTU      = (*gateExtended)(nil)
)

// newSchedulerGate is the factory: one decision at flow setup, no per-write discovery.
func newSchedulerGate(upstream io.Writer) io.Writer {
	if extended, isExtended := upstream.(N.ExtendedWriter); isExtended {
		return &gateExtended{schedulerGateCore{upstream: upstream}, extended}
	}
	return &gatePlain{schedulerGateCore{upstream: upstream}}
}

// --- fixtures -------------------------------------------------------------------------------

// plainSink is deliberately NOT an ExtendedWriter.
type plainSink struct {
	received int64
}

func (s *plainSink) Write(p []byte) (int, error) {
	s.received += int64(len(p))
	return len(p), nil
}

// geometrySink exposes live-changeable geometry.
type geometrySink struct {
	received int64
	content  []byte
	mtu      int
	front    int
	rear     int
}

func (s *geometrySink) Write(p []byte) (int, error) {
	s.received += int64(len(p))
	s.content = append(s.content, p...)
	return len(p), nil
}

func (s *geometrySink) WriteBuffer(buffer *buf.Buffer) error {
	s.received += int64(buffer.Len())
	s.content = append(s.content, buffer.Bytes()...)
	buffer.Release()
	return nil
}

func (s *geometrySink) WriterMTU() int     { return s.mtu }
func (s *geometrySink) FrontHeadroom() int { return s.front }
func (s *geometrySink) RearHeadroom() int  { return s.rear }

// TestGateFactoryPicksTheShapeTheUpstreamSupports pins the factory's one decision.
func TestGateFactoryPicksTheShapeTheUpstreamSupports(t *testing.T) {
	plain := newSchedulerGate(&plainSink{})
	_, plainIsExtended := plain.(N.ExtendedWriter)
	require.False(t, plainIsExtended,
		"an upstream without WriteBuffer must not be given a shape that advertises it")

	_, plainIsReplaceable := plain.(N.WriterWithUpstream)
	require.True(t, plainIsReplaceable, "but every shape stays non-replaceable")

	extended := newSchedulerGate(&geometrySink{})
	_, extendedIsExtended := extended.(N.ExtendedWriter)
	require.True(t, extendedIsExtended, "an ExtendedWriter upstream keeps its WriteBuffer path")
}

// TestGateWorksOverAPlainWriter is the production-safe case the earlier prototype could not handle:
// 4346021b0 asserted base.(N.ExtendedWriter), which is not a safe assumption.
func TestGateWorksOverAPlainWriter(t *testing.T) {
	sink := &plainSink{}
	gate := newSchedulerGate(sink)

	require.NotPanics(t, func() {
		written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
		require.NoError(t, err)
		require.EqualValues(t, len("payload"), written)
	}, "a plain writer must not panic the factory")

	require.EqualValues(t, len("payload"), sink.received, "payload correct")
	require.Positive(t, gate.(*gatePlain).admitted.Load(),
		"and the gate observed the write, so the scheduler would be in the path")
	require.False(t, gate.(N.WriterWithUpstream).WriterReplaceable())
}

// TestGatePreservesExtendedWriterPath proves WriteBuffer is used rather than degraded to raw Write.
func TestGatePreservesExtendedWriterPath(t *testing.T) {
	sink := &geometrySink{mtu: 1400, front: 8, rear: 16}
	gate := newSchedulerGate(sink)

	written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.EqualValues(t, len("payload"), sink.received)
	require.Positive(t, gate.(*gateExtended).admitted.Load(), "the gate saw the write")
}

// TestGateGeometryDelegatesLive is the rule established by the VLESS finding: geometry must be read
// through, never snapshotted.
func TestGateGeometryDelegatesLive(t *testing.T) {
	sink := &geometrySink{mtu: 1200, front: 32, rear: 64}
	gate := newSchedulerGate(sink).(*gateExtended)

	require.Equal(t, 1200, gate.WriterMTU())
	require.Equal(t, 32, gate.FrontHeadroom())
	require.Equal(t, 64, gate.RearHeadroom())

	// The upstream changes underneath the gate, exactly as the VLESS conn does on handshake.
	sink.mtu, sink.front, sink.rear = 1400, 0, 8

	require.Equal(t, 1400, gate.WriterMTU(), "MTU must be read live")
	require.Equal(t, 0, gate.FrontHeadroom(), "front headroom must be read live")
	require.Equal(t, 8, gate.RearHeadroom(), "rear headroom must be read live")
}

// TestGateGeometryNeutralDefaultsMatchAbsence proves the neutral-default choice for an upstream that
// exposes no geometry is behaviourally identical to not implementing the interfaces, rather than
// merely asserted to be.
func TestGateGeometryNeutralDefaultsMatchAbsence(t *testing.T) {
	// geometryLess is an ExtendedWriter with NO geometry interfaces.
	sink := &geometryLessSink{}
	gate := newSchedulerGate(sink).(*gateExtended)

	require.Equal(t, math.MaxInt, gate.WriterMTU(),
		"an absent MTU must read as unconstrained, making the length check vacuous")
	require.Zero(t, gate.FrontHeadroom())
	require.Zero(t, gate.RearHeadroom())

	// And WriteOwnedBuffer reaches the same decision through the gate as it would with no geometry.
	buffer := buf.NewSize(8)
	buffer.WriteString("payload")
	err, handedOver := bufio.WriteOwnedBuffer(gate, buffer)
	require.NoError(t, err)
	require.True(t, handedOver, "the WriteBuffer path must still be taken")
	require.EqualValues(t, len("payload"), sink.received)
}

type geometryLessSink struct {
	received int64
}

func (s *geometryLessSink) Write(p []byte) (int, error) {
	s.received += int64(len(p))
	return len(p), nil
}

func (s *geometryLessSink) WriteBuffer(buffer *buf.Buffer) error {
	s.received += int64(buffer.Len())
	buffer.Release()
	return nil
}

// TestGateSeesCachedFirstPayload closes the cached-payload item: the engine writes the cached buffer
// through WriteOwnedBuffer(destination) where destination is the post-unwrap writer, i.e. the gate.
func TestGateSeesCachedFirstPayload(t *testing.T) {
	sink := &geometrySink{mtu: 1400}
	cached := buf.NewSize(64)
	cached.WriteString("cached")
	source := bufio.NewCachedReader(strings.NewReader("stream"), cached)
	gate := newSchedulerGate(sink).(*gateExtended)

	written, err := bufio.CopyWithIncreateBuffer(gate, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	// The engine counts the cached payload through the counters but does NOT add it to the returned
	// n, so the returned count covers the stream only. Asserting equality with the combined length
	// here would have been a test bug that looked correct.
	require.EqualValues(t, len("stream"), written, "the returned count covers the stream body")

	require.Positive(t, gate.admitted.Load(), "the gate saw the cached write and the stream")
	require.EqualValues(t, len("cachedstream"), sink.received,
		"every byte reached the sink: no loss, no duplication")
	require.Equal(t, "cachedstream", string(sink.content),
		"and in order: cached first, then the stream")
}
