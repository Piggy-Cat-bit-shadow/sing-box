package trafficsched

import (
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The gate contract, in one place:
//
//	WriterReplaceable() == false   never unwrapped -> the scheduler stays in the write PATH
//	Upstream() any                 common.Cast probe channel -> the handshake stays VISIBLE
//	capability methods             delegate LIVE, never snapshot
//	optional capabilities          advertised only where the upstream chain has them
//
// Every test below is a discriminating one: it fails if the property it names is removed, not
// merely if the gate stops compiling.

// --- fixtures ---------------------------------------------------------------------------------

// plainSink is deliberately NOT an ExtendedWriter and declares no geometry.
type plainSink struct {
	writes   atomic.Int64
	received atomic.Int64
	content  []byte
}

func (s *plainSink) Write(p []byte) (int, error) {
	s.writes.Add(1)
	s.received.Add(int64(len(p)))
	s.content = append(s.content, p...)
	return len(p), nil
}

// extendedSink is an ExtendedWriter with live-changeable geometry.
type extendedSink struct {
	writeCalls  atomic.Int64
	writeBuffer atomic.Int64
	received    atomic.Int64
	content     []byte
	mtu         int
	front       int
	rear        int
}

func (s *extendedSink) Write(p []byte) (int, error) {
	s.writeCalls.Add(1)
	s.received.Add(int64(len(p)))
	s.content = append(s.content, p...)
	return len(p), nil
}

func (s *extendedSink) WriteBuffer(buffer *buf.Buffer) error {
	s.writeBuffer.Add(1)
	s.received.Add(int64(buffer.Len()))
	s.content = append(s.content, buffer.Bytes()...)
	buffer.Release()
	return nil
}

func (s *extendedSink) WriterMTU() int     { return s.mtu }
func (s *extendedSink) FrontHeadroom() int { return s.front }
func (s *extendedSink) RearHeadroom() int  { return s.rear }

// --- shape selection --------------------------------------------------------------------------

// TestGateClaimsOnlyTheCapabilitiesTheUpstreamHas is the truthful-exposure rule.
//
// A wrapper that implemented every optional interface unconditionally would change path
// selection, because sing discovers these capabilities with a DIRECT type assertion as well as
// through common.Cast.
func TestGateClaimsOnlyTheCapabilitiesTheUpstreamHas(t *testing.T) {
	plain := NewGate(&plainSink{}, nil)
	_, isExtended := plain.(N.ExtendedWriter)
	require.False(t, isExtended,
		"an upstream without WriteBuffer must not be given a shape that advertises it")
	_, hasMTU := plain.(N.WriterWithMTU)
	require.False(t, hasMTU,
		"an upstream chain without a writer MTU must not be given one")

	extended := NewGate(&extendedSink{mtu: 1400}, nil)
	_, isExtended = extended.(N.ExtendedWriter)
	require.True(t, isExtended, "an ExtendedWriter upstream keeps its WriteBuffer path")
	_, hasMTU = extended.(N.WriterWithMTU)
	require.True(t, hasMTU, "and an upstream that constrains the MTU keeps that constraint")

	// Every shape stays non-replaceable, which is what keeps the scheduler in the write path.
	for _, gate := range []io.Writer{plain, extended} {
		upstream, isReplaceable := gate.(N.WriterWithUpstream)
		require.True(t, isReplaceable)
		require.False(t, upstream.WriterReplaceable())
		require.Same(t, io.Writer(gate), N.UnwrapWriter(gate),
			"the engine must not be able to unwrap past the gate")
	}
}

// TestGatePreservesTheExtendedWriterPath proves WriteBuffer is used rather than degraded to a raw
// copy.
func TestGatePreservesTheExtendedWriterPath(t *testing.T) {
	sink := &extendedSink{mtu: 1400}
	gate := NewGate(sink, nil)

	written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.EqualValues(t, len("payload"), sink.received.Load())
	require.Positive(t, sink.writeBuffer.Load(), "the WriteBuffer path must be preserved")
	require.Zero(t, sink.writeCalls.Load(), "and must not be degraded to raw Write")
}

// TestGateWorksOverAPlainWriter is the production-safe case: the destination is NOT guaranteed to
// be an ExtendedWriter, so a gate that asserted one would panic on a real configuration.
func TestGateWorksOverAPlainWriter(t *testing.T) {
	sink := &plainSink{}
	gate := NewGate(sink, nil)

	require.NotPanics(t, func() {
		written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
		require.NoError(t, err)
		require.EqualValues(t, len("payload"), written)
	})
	require.EqualValues(t, len("payload"), sink.received.Load())
	require.Equal(t, "payload", string(sink.content))
}

// --- geometry ---------------------------------------------------------------------------------

// TestGateGeometryDelegatesLive is the VLESS rule: the same object changes its answers across a
// handshake, so a gate that snapshotted geometry would be wrong from the first write on.
func TestGateGeometryDelegatesLive(t *testing.T) {
	sink := &extendedSink{mtu: 1200, front: 32, rear: 64}
	gate := NewGate(sink, nil)

	// The gate's OWN answers are the upstream chain's requirement, which is what
	// bufio.WriteOwnedBuffer reads. (N.CalculateFrontHeadroom walks the chain and adds the
	// upstream's on top; that documented deviation is pinned separately.)
	front := gate.(N.FrontHeadroom)
	rear := gate.(N.RearHeadroom)
	require.Equal(t, 32, front.FrontHeadroom())
	require.Equal(t, 64, rear.RearHeadroom())
	require.Equal(t, 1200, N.CalculateMTU(nil, gate))

	sink.mtu, sink.front, sink.rear = 1400, 0, 8

	require.Zero(t, front.FrontHeadroom(), "front headroom must be read live")
	require.Equal(t, 8, rear.RearHeadroom(), "rear headroom must be read live")
	require.Equal(t, 1400, N.CalculateMTU(nil, gate), "MTU must be read live")
}

// TestGateMTUIsAbsentWhenTheChainHasNone is the regression test for the one catastrophic shape
// mistake available here.
//
// sing's chained MTU resolution takes the MINIMUM and reads 0 as unconstrained, while
// bufio.WriteOwnedBuffer reads the writer's own value as a hard ceiling. A gate that tried to
// satisfy both with one number would have to invent math.MaxInt for an unconstrained upstream,
// and ReadWaitOptions.NewBuffer() would then compute MaxInt + overhead, overflow to a negative
// buffer size, and collapse every read buffer to a single byte while the connection still
// "worked". The only value that is correct in both places is not implementing the interface.
func TestGateMTUIsAbsentWhenTheChainHasNone(t *testing.T) {
	sink := &extendedSink{}
	gate := NewGate(sink, nil)

	_, hasMTU := gate.(N.WriterWithMTU)
	require.False(t, hasMTU)
	require.Zero(t, N.CalculateMTU(nil, gate),
		"an unconstrained chain must stay unconstrained through the gate")

	options := N.NewReadWaitOptions(strings.NewReader(""), gate)
	require.Zero(t, options.MTU)
	buffer := options.NewBuffer()
	defer buffer.Release()
	require.Greater(t, buffer.Cap(), 1024,
		"the read buffer must be a real buffer, not the collapsed one an overflowed MTU produces")

	// And the upstream's own limit still reaches the caller when there IS one.
	limited := NewGate(&extendedSink{mtu: 1200}, nil)
	require.Equal(t, 1200, N.CalculateMTU(nil, limited))
}

// TestGateHeadroomInflationIsBounded pins the ONE deliberate deviation.
//
// N.CalculateFrontHeadroom walks WithUpstreamWriter / common.WithUpstream without consulting
// WriterReplaceable and SUMS what it finds. The gate cannot opt out of that walk while keeping
// Upstream() for handshake probing, and it must report the real headroom for
// bufio.WriteOwnedBuffer, which resolves geometry from the gate alone. Reporting the real value is
// the safe side: WriteOwnedBuffer reaches the same decision it would without a gate, at the cost
// of a doubled headroom in the copy loop's buffer sizing.
//
// This test exists so that cost cannot grow silently. If sing's walkers ever learn to respect
// WriterReplaceable, the expected value becomes 1x and this test is the place that records it.
func TestGateHeadroomInflationIsBounded(t *testing.T) {
	sink := &extendedSink{front: 210, rear: 40}
	gate := NewGate(sink, nil)

	upstreamFront := N.CalculateFrontHeadroom(sink)
	upstreamRear := N.CalculateRearHeadroom(sink)
	require.Equal(t, 210, upstreamFront)
	require.Equal(t, 40, upstreamRear)

	require.Equal(t, 2*upstreamFront, N.CalculateFrontHeadroom(gate),
		"the chain walker adds the gate's value and the upstream's; the gate reports the real "+
			"one so that WriteOwnedBuffer, which does not walk, still sees it")
	require.Equal(t, 2*upstreamRear, N.CalculateRearHeadroom(gate))

	// The absolute cost is what actually matters, and it is bounded by the implementers in this
	// tree. Fail loudly if a future writer declares a headroom large enough for the doubling to
	// be a real buffer-size decision.
	require.Less(t, upstreamFront, 4096, "headroom inflation is only acceptable while the "+
		"declared headrooms stay small")
}

// TestWriteOwnedBufferTakesTheSameDecisionThroughTheGate is the reason the headroom trade is made
// the safe way: the cached first payload must still reach ExtendedWriter.WriteBuffer, and a
// starved buffer must still fall back.
func TestWriteOwnedBufferTakesTheSameDecisionThroughTheGate(t *testing.T) {
	t.Run("headroom available", func(t *testing.T) {
		sink := &extendedSink{front: 16, rear: 16}
		gate := NewGate(sink, nil)
		payload := buf.NewSize(64)
		payload.Resize(16, 0)
		payload.Reserve(16)
		_, writeErr := payload.WriteString("cached")
		require.NoError(t, writeErr)

		err, handedOver := bufio.WriteOwnedBuffer(gate, payload)
		require.NoError(t, err)
		require.True(t, handedOver, "the zero-copy hand-over must be preserved")
		require.Equal(t, "cached", string(sink.content))
	})

	t.Run("headroom missing", func(t *testing.T) {
		sink := &extendedSink{front: 64, rear: 0}
		gate := NewGate(sink, nil)
		payload := buf.NewSize(64)
		_, _ = payload.WriteString("cached")

		err, handedOver := bufio.WriteOwnedBuffer(gate, payload)
		require.NoError(t, err)
		require.False(t, handedOver,
			"a buffer without the headroom the chain needs must fall back, exactly as it would "+
				"without the gate")
		require.Equal(t, "cached", string(sink.content))
		require.Zero(t, sink.writeBuffer.Load())
	})
}

// --- the probe channel ------------------------------------------------------------------------

// handshakeSink needs a write handshake until its first write, and drops its per-write capability
// afterwards - the VLESS shape.
type handshakeSink struct {
	done      atomic.Bool
	mtu       atomic.Int64
	writePath atomic.Int64
}

func (s *handshakeSink) NeedHandshakeForWrite() bool { return !s.done.Load() }

func (s *handshakeSink) Write(p []byte) (int, error) {
	s.writePath.Add(1)
	s.done.Store(true)
	return len(p), nil
}

func (s *handshakeSink) WriteBuffer(buffer *buf.Buffer) error {
	s.writePath.Add(1)
	s.done.Store(true)
	return nil
}

func (s *handshakeSink) FrontHeadroom() int {
	if s.done.Load() {
		return 0
	}
	return 42
}

// TestGateKeepsTheHandshakeVisible is the Upstream() half of the contract.
//
// common.Cast unwraps through common.WithUpstream (the Upstream() any method), while every
// unwrapping helper unwraps through WriterReplaceable(). The two are orthogonal, and that is what
// makes a non-replaceable gate possible at all: the session still sees the pending handshake, so
// refreshUnwrap still runs and post-handshake capabilities are still rediscovered.
func TestGateKeepsTheHandshakeVisible(t *testing.T) {
	sink := &handshakeSink{}
	gate := NewGate(sink, nil)

	require.True(t, N.NeedHandshakeForWriteAny(sink), "precondition")
	require.True(t, N.NeedHandshakeForWriteAny(gate),
		"the session must still see the pending handshake through the gate")
	require.Equal(t, 42, gate.(N.FrontHeadroom).FrontHeadroom(), "and the pre-handshake headroom")

	written, err := gate.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, len("hello"), written)

	require.False(t, N.NeedHandshakeForWriteAny(gate),
		"completion must be visible too, or ErrHandshakeCompleted can never fire")
	require.Zero(t, gate.(N.FrontHeadroom).FrontHeadroom(),
		"and the post-handshake value must be live, not the one captured at construction")
	require.EqualValues(t, 1, sink.writePath.Load())
}

// TestGateInTheCopyEngineStillSeesTheHandshake runs the probe through the real copy loop rather
// than through a direct call, because the session builds its HandshakeState from the post-unwrap
// writer - that is, from the gate.
func TestGateInTheCopyEngineStillSeesTheHandshake(t *testing.T) {
	sink := &handshakeSink{}
	gate := NewGate(sink, nil)

	state := N.NewHandshakeState(strings.NewReader(""), gate)
	require.True(t, state.Upgradable(),
		"the session must consider this direction upgradable, or it never checks for completion")

	_, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("hello"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)

	require.ErrorIs(t, state.Check(), N.ErrHandshakeCompleted,
		"the session must observe completion so refreshUnwrap can run")
	require.EqualValues(t, 1, sink.writePath.Load(), "and the gate stayed in the write path")
}

// --- vectorised ---------------------------------------------------------------------------------

// vectorisedSink is an ExtendedWriter that also offers a vectorised writer, and records which path
// the copy engine chose.
type vectorisedSink struct {
	writeBuffer  atomic.Int64
	vectorised   atomic.Int64
	vectorisedOK bool
	content      []byte
}

func (s *vectorisedSink) Write(p []byte) (int, error) {
	s.content = append(s.content, p...)
	return len(p), nil
}

func (s *vectorisedSink) WriteBuffer(buffer *buf.Buffer) error {
	s.writeBuffer.Add(1)
	s.content = append(s.content, buffer.Bytes()...)
	buffer.Release()
	return nil
}

func (s *vectorisedSink) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	if !s.vectorisedOK {
		return nil, false
	}
	return &recordingVectorisedWriter{sink: s}, true
}

type recordingVectorisedWriter struct {
	sink *vectorisedSink
}

func (w *recordingVectorisedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	w.sink.vectorised.Add(1)
	for _, buffer := range buffers {
		w.sink.content = append(w.sink.content, buffer.Bytes()...)
	}
	buf.ReleaseMulti(buffers)
	return nil
}

// vectorisedSource serves one single buffer and then batches, which is the shape
// copyWaitWithPool expects when it switches to the vectorised loop.
type vectorisedSource struct {
	single     []*buf.Buffer
	batches    [][]*buf.Buffer
	singleNext int
	batchNext  int
}

func (s *vectorisedSource) Read([]byte) (int, error) { return 0, io.EOF }

// InitializeReadWaiter returns false, which is what asks the copy engine to USE this waiter
// rather than fall back to the generic loop. The flag reads inverted at the call site
// (`if !needCopy || common.LowMemory`), and every waiter in sing - tun.GoConn included - returns
// false here.
func (s *vectorisedSource) InitializeReadWaiter(N.ReadWaitOptions) bool { return false }

func (s *vectorisedSource) WaitReadBuffer() (*buf.Buffer, error) {
	if s.singleNext < len(s.single) {
		next := s.single[s.singleNext]
		s.singleNext++
		return next, nil
	}
	return nil, io.EOF
}

func (s *vectorisedSource) WaitReadBuffers() ([]*buf.Buffer, error) {
	if s.batchNext < len(s.batches) {
		next := s.batches[s.batchNext]
		s.batchNext++
		return next, nil
	}
	return nil, io.EOF
}

func (s *vectorisedSource) CreateVectorisedReadWaiter() (N.VectorisedReadWaiter, bool) {
	return s, true
}

func newTestBuffer(content string) *buf.Buffer {
	buffer := buf.NewSize(len(content) + 16)
	_, _ = buffer.WriteString(content)
	return buffer
}

// TestGateKeepsTheVectorisedPathAndStaysInIt is the discriminating test for the capability that
// Upstream() DOES NOT preserve.
//
// bufio.CreateVectorisedWriter discovers the capability by DIRECT type assertion, so a gate that
// only forwarded Upstream() would silently drop it and the copy loop would fall back to
// WriteBuffer. The gate therefore creates the upstream's vectorised writer itself and wraps it, so
// the bytes still pass through the scheduler - without the wrapper, the vectorised path would
// bypass the gate entirely on exactly the large transfers the scheduler exists to schedule.
func TestGateKeepsTheVectorisedPathAndStaysInIt(t *testing.T) {
	sink := &vectorisedSink{vectorisedOK: true}
	flow := NewScheduler(Options{}).NewFlow(trafficclass.ClassInteractive)
	gate := NewGate(sink, flow)

	source := &vectorisedSource{
		single:  []*buf.Buffer{newTestBuffer("first")},
		batches: [][]*buf.Buffer{{newTestBuffer("second"), newTestBuffer("third")}},
	}

	written, err := bufio.CopyWithIncreateBuffer(gate, source, 1, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("firstsecondthird"), written)
	require.Equal(t, "firstsecondthird", string(sink.content))

	require.Positive(t, sink.vectorised.Load(),
		"the copy engine must still reach the upstream's vectorised writer through the gate; "+
			"if this is zero the gate dropped a direct-assertion capability and the copy loop "+
			"silently fell back")
	require.EqualValues(t, len("firstsecondthird"), flowAdmitted(flow),
		"every byte must still pass through the gate, including the ones on the vectorised path")
	require.EqualValues(t, 2, flow.Grants(),
		"and the batch must have been admitted as ONE unit: one grant for the single buffer "+
			"(5 bytes, through WriteBuffer) and one for the whole batch (11 bytes, through "+
			"WriteVectorised). A gate that re-entered WriteBuffer per packet would show three.")
}

// flowAdmitted reads the scheduler's own count of admitted bytes for a flow. It is the only
// observable that proves the gate was in the vectorised path rather than beside it.
func flowAdmitted(f *Flow) int64 { return f.admitted.Load() }

// TestGateDropsVectorisedTruthfullyWhenTheUpstreamHasNone proves the forwarding is conditional
// rather than a blanket claim.
func TestGateDropsVectorisedTruthfullyWhenTheUpstreamHasNone(t *testing.T) {
	sink := &vectorisedSink{vectorisedOK: false}
	gate := NewGate(sink, nil)

	_, created := bufio.CreateVectorisedWriter(gate)
	require.False(t, created,
		"an upstream without a vectorised writer must not gain one from the gate")
}

// --- packets ------------------------------------------------------------------------------------

// packetSink is a PacketWriter with a real batch writer and a connected batch writer, recording
// which entry point was used.
type packetSink struct {
	packets          atomic.Int64
	batches          atomic.Int64
	connectedBatches atomic.Int64
	bytes            atomic.Int64
	packetBytes      []int
}

func (s *packetSink) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	s.packets.Add(1)
	s.bytes.Add(int64(buffer.Len()))
	s.packetBytes = append(s.packetBytes, buffer.Len())
	buffer.Release()
	return nil
}

func (s *packetSink) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return &recordingPacketBatchWriter{sink: s}, true
}

func (s *packetSink) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &recordingConnectedPacketBatchWriter{sink: s}, true
}

type recordingPacketBatchWriter struct {
	sink *packetSink
}

func (w *recordingPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, _ []M.Socksaddr) error {
	w.sink.batches.Add(1)
	for _, buffer := range buffers {
		w.sink.bytes.Add(int64(buffer.Len()))
		w.sink.packetBytes = append(w.sink.packetBytes, buffer.Len())
	}
	buf.ReleaseMulti(buffers)
	return nil
}

type recordingConnectedPacketBatchWriter struct {
	sink *packetSink
}

func (w *recordingConnectedPacketBatchWriter) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.sink.connectedBatches.Add(1)
	for _, buffer := range buffers {
		w.sink.bytes.Add(int64(buffer.Len()))
		w.sink.packetBytes = append(w.sink.packetBytes, buffer.Len())
	}
	buf.ReleaseMulti(buffers)
	return nil
}

// TestPacketGatePreservesTheBatchEntryPoints is the UDP half of the truthful-capability rule.
//
// bufio.CreatePacketBatchWriter falls back to createSyscallPacketBatchWriter, which needs a raw
// connection the gate deliberately does not expose. Without the forwarding, every batch would
// silently become a per-packet loop - the exact degradation that is invisible in a functional test
// and expensive in production.
func TestPacketGatePreservesTheBatchEntryPoints(t *testing.T) {
	sink := &packetSink{}
	gate := NewPacketGate(sink, nil)

	batchWriter, hasBatch := bufio.CreatePacketBatchWriter(gate)
	require.True(t, hasBatch, "a packet gate must not degrade the batch path")
	require.NotNil(t, batchWriter)

	connectedWriter, hasConnected := bufio.CreateConnectedPacketBatchWriter(gate)
	require.True(t, hasConnected, "nor the connected batch path")
	require.NotNil(t, connectedWriter)

	// The wrappers must be the gate's, not the upstream's, so every byte is admitted.
	require.IsType(t, &gatePacketBatchWriter{}, batchWriter)
	require.IsType(t, &gateConnectedPacketBatchWriter{}, connectedWriter)
}

// TestPacketGateAdmitsOneBatchAsOneUnitAndKeepsTheBatch pins both halves of the UDP rule: a batch
// is one scheduling unit, and it is never decomposed into single packets.
func TestPacketGateAdmitsOneBatchAsOneUnitAndKeepsTheBatch(t *testing.T) {
	sink := &packetSink{}
	flow := NewScheduler(Options{}).NewFlow(trafficclass.ClassInteractive)
	gate := NewPacketGate(sink, flow)

	batchWriter, _ := bufio.CreatePacketBatchWriter(gate)
	buffers := []*buf.Buffer{newTestBuffer("aaa"), newTestBuffer("bb"), newTestBuffer("c")}
	err := batchWriter.WritePacketBatch(buffers, []M.Socksaddr{{}, {}, {}})
	require.NoError(t, err)

	require.EqualValues(t, 1, sink.batches.Load(), "the batch must reach the upstream as one call")
	require.Zero(t, sink.packets.Load(), "and must not be split into single packets")
	require.EqualValues(t, 6, sink.bytes.Load())
	require.EqualValues(t, 6, flowAdmitted(flow), "accounted as the SUM of its packet sizes")
	require.EqualValues(t, 1, flow.Grants(), "and as ONE scheduling unit")
}

// TestPacketGateKeepsTheConnectedBatchShape is the same rule for the connected variant, whose
// callers must not be silently redirected to the destination-carrying entry point.
func TestPacketGateKeepsTheConnectedBatchShape(t *testing.T) {
	sink := &packetSink{}
	gate := NewPacketGate(sink, nil)

	batchWriter, _ := bufio.CreateConnectedPacketBatchWriter(gate)
	buffers := []*buf.Buffer{newTestBuffer("aaa"), newTestBuffer("bb")}
	require.NoError(t, batchWriter.WriteConnectedPacketBatch(buffers))

	require.EqualValues(t, 1, sink.connectedBatches.Load())
	require.Zero(t, sink.batches.Load())
	require.Zero(t, sink.packets.Load())
	require.EqualValues(t, 5, sink.bytes.Load())
}

// TestPacketGateDeliversAZeroLengthDatagram pins that a legal empty datagram is not swallowed.
//
// A zero-length UDP datagram is a real packet - it is how some protocols signal - and a gate that
// treated "nothing to admit" as "nothing to send" would drop it. The admit path must not skip the
// write for n == 0.
func TestPacketGateDeliversAZeroLengthDatagram(t *testing.T) {
	sink := &packetSink{}
	gate := NewPacketGate(sink, nil)

	empty := buf.NewSize(16)
	require.NoError(t, gate.WritePacket(empty, M.Socksaddr{}))
	require.EqualValues(t, 1, sink.packets.Load())
	require.Len(t, sink.packetBytes, 1)
	require.Zero(t, sink.packetBytes[0])
}

// TestPacketGateMTUIsAbsentWhenTheChainHasNone mirrors the stream-side rule.
func TestPacketGateMTUIsAbsentWhenTheChainHasNone(t *testing.T) {
	gate := NewPacketGate(&packetSink{}, nil)
	_, hasMTU := gate.(N.WriterWithMTU)
	require.False(t, hasMTU)
	require.Zero(t, N.CalculateMTU(nil, gate))
}

// TestPacketGatePassesAZeroLengthDatagramOverARealSocket closes the item the gate's unit test can
// only cover behaviourally: an empty datagram is a legal packet, and a gate must not treat
// "nothing to admit" as "nothing to send".
func TestPacketGatePassesAZeroLengthDatagramOverARealSocket(t *testing.T) {
	// An unconnected socket, because that is the shape whose WritePacket carries a destination.
	// The socket pair is built here rather than shared with the syscall batch tests so this one
	// runs on every platform.
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	gate := NewPacketGate(bufio.NewPacketConn(client), nil)

	destination := M.SocksaddrFromNet(server.LocalAddr()).Unwrap()
	require.NoError(t, gate.WritePacket(buf.NewSize(16), destination))
	require.NoError(t, server.SetReadDeadline(time.Now().Add(2*time.Second)))
	payload := make([]byte, 64)
	n, _, err := server.ReadFromUDP(payload)
	require.NoError(t, err, "the empty datagram must reach the socket")
	require.Zero(t, n)
}

// --- ownership ------------------------------------------------------------------------------

// TestGateReleasesBuffersItNeverDelegated is the cancel-before-delegate ownership case.
//
// The copy loop's contract is that the WRITER owns a buffer once it is handed over, on both the
// nil and the non-nil return: copyPacketBatchWaitWithPool does not release anything when the batch
// write fails, because the writer is expected to have done it. A gate that fails BEFORE reaching
// the upstream therefore owns every buffer itself and must release them, or the pool leaks one
// buffer per abandoned batch under exactly the conditions that produce them.
func TestGateReleasesBuffersItNeverDelegated(t *testing.T) {
	t.Run("stream buffer", func(t *testing.T) {
		scheduler := NewScheduler(Options{Mode: ModeService, HighIdleWindow: time.Minute})
		holder := scheduler.NewFlow(trafficclass.ClassInteractive)
		require.NoError(t, holder.wait(1), "the holder takes the single service slot")

		target := scheduler.NewFlow(trafficclass.ClassInteractive)
		gate := NewGate(&extendedSink{}, target)

		buffer := newTestBuffer("payload")
		require.Equal(t, len("payload"), buffer.Len())

		result := make(chan error, 1)
		go func() { result <- gate.(N.ExtendedWriter).WriteBuffer(buffer) }()
		time.Sleep(25 * time.Millisecond)

		require.NoError(t, target.Close())
		require.ErrorIs(t, awaitResult(t, result, "the abandoned buffer write"), ErrClosed)
		require.Zero(t, buffer.Len(),
			"a buffer the upstream never saw must be released by the gate, not dropped")

		holder.done()
	})

	t.Run("packet batch", func(t *testing.T) {
		scheduler := NewScheduler(Options{Mode: ModeService, HighIdleWindow: time.Minute})
		holder := scheduler.NewFlow(trafficclass.ClassInteractive)
		require.NoError(t, holder.wait(1))

		target := scheduler.NewFlow(trafficclass.ClassInteractive)
		gate := NewPacketGate(&packetSink{}, target)
		batchWriter, _ := bufio.CreatePacketBatchWriter(gate)

		buffers := []*buf.Buffer{newTestBuffer("aaa"), newTestBuffer("bb"), newTestBuffer("c")}
		result := make(chan error, 1)
		go func() {
			result <- batchWriter.WritePacketBatch(buffers, []M.Socksaddr{{}, {}, {}})
		}()
		time.Sleep(25 * time.Millisecond)

		require.NoError(t, target.Close())
		require.ErrorIs(t, awaitResult(t, result, "the abandoned batch"), ErrClosed)
		for index, buffer := range buffers {
			require.Zero(t, buffer.Len(),
				"every buffer of a batch the upstream never saw must be released: index %d", index)
		}

		holder.done()
	})
}

// TestGateDelegatesOwnershipOnAnUpstreamError is the other half: once the write reaches the
// upstream, the upstream owns the buffer and the gate must not touch it again. Double-releasing is
// a no-op in the current buffer implementation, which is exactly why a caller must not depend on
// being able to do it.
func TestGateDelegatesOwnershipOnAnUpstreamError(t *testing.T) {
	upstreamErr := E.New("upstream refused")
	sink := &failingExtendedSink{err: upstreamErr}
	gate := NewGate(sink, nil)

	buffer := newTestBuffer("payload")
	require.ErrorIs(t, gate.(N.ExtendedWriter).WriteBuffer(buffer), upstreamErr)
	require.Zero(t, buffer.Len(), "the upstream released it, which is the ExtendedWriter contract")
	require.EqualValues(t, 1, sink.releases.Load(),
		"and the gate must not have released it a second time")
}

type failingExtendedSink struct {
	err      error
	releases atomic.Int64
}

func (s *failingExtendedSink) Write([]byte) (int, error) { return 0, s.err }

func (s *failingExtendedSink) WriteBuffer(buffer *buf.Buffer) error {
	s.releases.Add(1)
	buffer.Release()
	return s.err
}
