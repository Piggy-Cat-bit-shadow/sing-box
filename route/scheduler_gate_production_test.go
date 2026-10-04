package route

import (
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/common/trafficsched"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// dialRecordingListener returns a connection to a peer that records everything it receives, so a
// framing path can be asserted on the bytes that actually left, not on the bytes the local code
// intended.
func dialRecordingListener(t *testing.T) (net.Conn, func() []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	var (
		mu       sync.Mutex
		recorded []byte
		received = make(chan struct{})
		once     sync.Once
	)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buffer)
			if n > 0 {
				mu.Lock()
				recorded = append(recorded, buffer[:n]...)
				mu.Unlock()
			}
			if readErr != nil {
				once.Do(func() { close(received) })
				return
			}
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn, func() []byte {
		deadline := time.After(2 * time.Second)
		for {
			mu.Lock()
			if len(recorded) >= len("hello") {
				out := append([]byte(nil), recorded...)
				mu.Unlock()
				return out
			}
			mu.Unlock()
			select {
			case <-received:
			case <-deadline:
				mu.Lock()
				out := append([]byte(nil), recorded...)
				mu.Unlock()
				return out
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
}

// Phase 2B.1: the PRODUCTION gate, driven through the route layer.
//
// The earlier commits in this line each invented a gate type inside a test file, which meant the
// tests proved things about a model of the design rather than about the code that ships. These
// run against trafficsched.NewGate, the factory route actually installs, so the shape cannot drift
// away from what is measured.

// trackingSink is a plain io.Writer that is deliberately not an ExtendedWriter.
type trackingSink struct {
	writes int64
	bytes  int64
	seen   []byte
}

func (s *trackingSink) Write(p []byte) (int, error) {
	s.writes++
	s.bytes += int64(len(p))
	s.seen = append(s.seen, p...)
	return len(p), nil
}

// framingSink is an ExtendedWriter with live-changeable geometry, standing in for a proxy writer.
type framingSink struct {
	writeCalls  int64
	writeBuffer int64
	seen        []byte
	mtu         int
	front       int
	rear        int
}

func (s *framingSink) Write(p []byte) (int, error) {
	s.writeCalls++
	s.seen = append(s.seen, p...)
	return len(p), nil
}

func (s *framingSink) WriteBuffer(buffer *buf.Buffer) error {
	s.writeBuffer++
	s.seen = append(s.seen, buffer.Bytes()...)
	buffer.Release()
	return nil
}

func (s *framingSink) WriterMTU() int     { return s.mtu }
func (s *framingSink) FrontHeadroom() int { return s.front }
func (s *framingSink) RearHeadroom() int  { return s.rear }

// TestProductionGateOverAPlainWriter is the production-safe case: nothing guarantees the outbound
// writer is an ExtendedWriter.
func TestProductionGateOverAPlainWriter(t *testing.T) {
	sink := &trackingSink{}
	scheduler := trafficsched.NewScheduler(trafficsched.Options{})
	flow := scheduler.NewFlow(trafficclass.ClassDefault)
	gate := trafficsched.NewGate(sink, flow)
	defer flow.Close()

	written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.Equal(t, "payload", string(sink.seen))
	require.Positive(t, sink.writes, "the bytes must reach the writer")
	require.Same(t, io.Writer(gate), N.UnwrapWriter(gate),
		"and the gate must still be the writer the engine sees")
}

// TestProductionGatePreservesTheExtendedWriterPath proves WriteBuffer is used rather than degraded
// to a raw copy.
func TestProductionGatePreservesTheExtendedWriterPath(t *testing.T) {
	sink := &framingSink{mtu: 1400}
	gate := trafficsched.NewGate(sink, nil)

	written, err := bufio.CopyWithIncreateBuffer(gate, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.Equal(t, "payload", string(sink.seen))
	require.Positive(t, sink.writeBuffer, "the WriteBuffer path must be preserved")
	require.Zero(t, sink.writeCalls, "and must not be degraded to raw Write")
}

// TestProductionGateSeesTheCachedFirstPayload closes the cached-payload item against the shipping
// factory: the engine writes the sniffed first buffer with WriteOwnedBuffer(destination), where
// destination is the gate.
//
// The returned count covers the stream only. CopyWithIncreateBuffer counts the cached payload
// through the counters but does NOT add it to the value it returns, so asserting the combined
// length here would be a test bug that looks correct.
func TestProductionGateSeesTheCachedFirstPayload(t *testing.T) {
	sink := &framingSink{mtu: 1400}
	cached := buf.NewSize(64)
	_, _ = cached.WriteString("cached")
	source := bufio.NewCachedReader(strings.NewReader("stream"), cached)

	scheduler := trafficsched.NewScheduler(trafficsched.Options{})
	flow := scheduler.NewFlow(trafficclass.ClassDefault)
	gate := trafficsched.NewGate(sink, flow)
	defer flow.Close()

	written, err := bufio.CopyWithIncreateBuffer(gate, source, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("stream"), written, "the returned count covers the stream body")
	require.Equal(t, "cachedstream", string(sink.seen), "no loss, no duplication, in order")
	require.Positive(t, flow.AdmittedBytes(), "the gate saw both writes")
}

// TestProductionGateGeometryDelegatesLive is the VLESS rule applied to the shipping factory.
func TestProductionGateGeometryDelegatesLive(t *testing.T) {
	sink := &framingSink{mtu: 1200, front: 32, rear: 64}
	gate := trafficsched.NewGate(sink, nil)

	front := gate.(N.FrontHeadroom)
	require.Equal(t, 32, front.FrontHeadroom())
	require.Equal(t, 1200, N.CalculateMTU(nil, gate))

	sink.mtu, sink.front, sink.rear = 1400, 0, 8

	require.Zero(t, front.FrontHeadroom(), "front headroom must be read live, never snapshotted")
	require.Equal(t, 1400, N.CalculateMTU(nil, gate), "and so must the MTU")
}

// TestProductionGateOverTheLiveVLESSConn runs the real outbound object through the real factory.
//
// This is the item the earlier phase left open. The properties that matter are all behavioural:
// the handshake must still be visible through the gate, the framing write must still reach the
// peer, and the geometry the engine reads must be the conn's live answer rather than a snapshot.
func TestProductionGateOverTheLiveVLESSConn(t *testing.T) {
	scheduler := trafficsched.NewScheduler(trafficsched.Options{})
	flow := scheduler.NewFlow(trafficclass.ClassInteractive)
	defer flow.Close()

	rawConn, received := dialRecordingListener(t)
	client, err := vless.NewClient("2f0e6a1c-9f4b-4c1e-9b1a-7d3e5f8a0c22", "", log.NewNOPFactory().Logger())
	require.NoError(t, err)
	finalConn, err := client.DialEarlyConn(rawConn, M.ParseSocksaddrHostPort("example.com", 443))
	require.NoError(t, err)
	t.Cleanup(func() { _ = finalConn.Close() })

	gate := trafficsched.NewGate(finalConn, flow)

	// The session must still see the pending handshake through the gate, or refreshUnwrap never
	// runs and post-handshake capabilities are silently never rediscovered.
	require.True(t, N.NeedHandshakeForWriteAny(gate),
		"the gate must not hide the pending handshake")
	require.Positive(t, gate.(N.FrontHeadroom).FrontHeadroom(),
		"the pre-handshake request header needs front headroom")

	// The engine must NOT be able to unwrap past the gate.
	require.Same(t, io.Writer(gate), N.UnwrapWriter(gate))
	require.False(t, gate.(N.WriterWithUpstream).WriterReplaceable())

	written, err := gate.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, len("hello"), written)

	require.False(t, N.NeedHandshakeForWriteAny(gate),
		"completion must be observable through the gate, or ErrHandshakeCompleted can never fire")
	require.Zero(t, gate.(N.FrontHeadroom).FrontHeadroom(),
		"and the geometry must reflect the new phase, because the gate delegates rather than caches")
	require.Positive(t, flow.AdmittedBytes(),
		"and the byte must have been admitted by the scheduler, so the gate is really in the path")

	// The payload must have been written with the VLESS request header, i.e. the framing survived
	// the wrapper. The request length is deterministic, so the recorded bytes must be longer than
	// the payload alone.
	recorded := received()
	require.Greater(t, len(recorded), len("hello"),
		"the request header must still be written ahead of the payload")
	require.Equal(t, "hello", string(recorded[len(recorded)-len("hello"):]),
		"and the payload must be intact at the end of the frame")
}

// TestGatedUploadKeepsTheInboundTrackerCountExact is the accounting correction made executable.
//
// # Why the source side is the one that matters for upload
//
// The traffic tracker wraps the INBOUND connection, and the upload copy's source is exactly that
// connection. UnwrapCountReader therefore finds the counter on the source, where the gate is not
// and cannot be - the gate sits on the destination. This test proves that shape end to end, with
// the counter wrapped exactly the way common/trafficcontrol.RoutedConnection wraps it.
func TestGatedUploadKeepsTheInboundTrackerCountExact(t *testing.T) {
	var uploadBytes atomic.Int64

	sourceConn, peer := net.Pipe()
	t.Cleanup(func() { _ = sourceConn.Close(); _ = peer.Close() })
	trackerConn := bufio.NewInt64CounterConn(sourceConn, []*atomic.Int64{&uploadBytes}, nil)

	sink := &framingSink{}
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	copyWriter, flow := manager.gateWriter(sink, trafficclass.ClassDefault)
	require.NotNil(t, copyWriter)
	defer flow.Close()

	const payload = "tracked-upload-payload"
	go func() {
		_, _ = peer.Write([]byte(payload))
		_ = peer.Close()
	}()

	written, err := bufio.CopyWithIncreateBuffer(copyWriter, trackerConn, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len(payload), written)
	require.Equal(t, payload, string(sink.seen))
	require.EqualValues(t, len(payload), uploadBytes.Load(),
		"the upload counter must be exact with the gate installed: not skipped, not doubled")
	require.Positive(t, flow.AdmittedBytes(),
		"and every byte must still have passed through the gate")
}

// TestUploadGateKeepsDestinationCountersVisible is the historical hazard, closed rather than
// argued away.
//
// N.UnwrapCountWriter stops at a non-replaceable wrapper, so a gate placed OUTSIDE a destination
// counter would make that counter read zero while the data still flowed - an accounting loss that
// looks exactly like a working connection. gateWriter extracts the counters first and carries them
// across the gate, so the walk terminates at the gate with the counters already in hand.
func TestUploadGateKeepsDestinationCountersVisible(t *testing.T) {
	var destinationBytes atomic.Int64

	destinationConn, peer := net.Pipe()
	t.Cleanup(func() { _ = destinationConn.Close(); _ = peer.Close() })
	counted := bufio.NewInt64CounterConn(destinationConn, nil, []*atomic.Int64{&destinationBytes})

	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	copyWriter, flow := manager.gateWriter(counted, trafficclass.ClassDefault)
	defer flow.Close()

	destination, counters := N.UnwrapCountWriter(copyWriter, nil)
	require.Len(t, counters, 1,
		"the destination's counters must be discoverable across the gate, or the accounting "+
			"silently reads zero while the bytes flow")
	require.NotSame(t, io.Writer(counted), destination,
		"and the engine must write THROUGH the gate, or the scheduler is bypassed")

	go func() {
		_, _ = io.Copy(io.Discard, peer)
	}()

	written, err := bufio.CopyWithIncreateBuffer(copyWriter, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len("payload"), written)
	require.EqualValues(t, len("payload"), flow.AdmittedBytes())
	require.Eventually(t, func() bool { return destinationBytes.Load() == int64(len("payload")) },
		time.Second, time.Millisecond,
		"counted exactly once: not skipped, not doubled")
}

// TestUploadStreamGateLeavesSpliceEligibleFlowsAlone pins the scope rule: a flow whose two ends are
// both syscall-capable would be served by the kernel splice path inside the copy engine, and
// wrapping it would only take that fast path away without gaining any scheduling.
func TestUploadStreamGateLeavesSpliceEligibleFlowsAlone(t *testing.T) {
	client, server := tcpPair(t)
	manager := NewConnectionManager(log.NewNOPFactory().Logger())

	writer, flow := manager.uploadStreamGate(client, server, trafficclass.ClassDefault)
	require.Nil(t, writer,
		"a splice-eligible flow must not be gated: the gate cannot delay it and would only "+
			"remove the kernel fast path")
	require.Nil(t, flow)

	// A flow that could NOT have used splice is gated, which is the managed domain.
	pipeSource, pipePeer := net.Pipe()
	t.Cleanup(func() { _ = pipeSource.Close(); _ = pipePeer.Close() })
	writer, flow = manager.uploadStreamGate(pipeSource, server, trafficclass.ClassDefault)
	require.NotNil(t, writer, "a userspace-only flow is exactly what the scheduler manages")
	require.NotNil(t, flow)
	require.NoError(t, flow.Close())
}

var (
	_ io.Writer        = (*trackingSink)(nil)
	_ N.ExtendedWriter = (*framingSink)(nil)
	_ N.FrontHeadroom  = (*framingSink)(nil)
	_ N.RearHeadroom   = (*framingSink)(nil)
	_ N.WriterWithMTU  = (*framingSink)(nil)
)

// replaceableRewriter is a destination-side wrapper that is replaceable for unwrapping purposes
// AND rewrites every write. It is the shape a NAT packet connection has, and the reason the gate
// must not be placed below an unexamined unwrap.
type replaceableRewriter struct {
	upstream io.Writer
	marker   string
}

func (w *replaceableRewriter) Write(p []byte) (int, error) {
	_, _ = w.upstream.Write([]byte(w.marker))
	return w.upstream.Write(p)
}

func (w *replaceableRewriter) WriteBuffer(buffer *buf.Buffer) error {
	_, _ = w.upstream.Write([]byte(w.marker))
	_, err := w.upstream.Write(buffer.Bytes())
	buffer.Release()
	return err
}

func (w *replaceableRewriter) WriterReplaceable() bool { return true }

func (w *replaceableRewriter) UpstreamWriter() any { return w.upstream }

func (w *replaceableRewriter) Upstream() any { return w.upstream }

var _ N.WriterWithUpstream = (*replaceableRewriter)(nil)

// TestUploadGateNeverSkipsADestinationSideRewrite pins that the gate wraps the DESTINATION when
// there is no counter to carry.
//
// N.UnwrapCountWriter unwraps through every replaceable wrapper, not only counters, so a gate
// installed on the unwrapped base would sit BELOW a wrapper that remaps each write - and that
// wrapper's behaviour would silently disappear. bufio's NAT packet connections are exactly this
// shape for UDP.
func TestUploadGateNeverSkipsADestinationSideRewrite(t *testing.T) {
	sink := &trackingSink{}
	rewriter := &replaceableRewriter{upstream: sink, marker: "marker:"}

	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	copyWriter, flow := manager.gateWriter(rewriter, trafficclass.ClassDefault)
	defer flow.Close()

	_, err := bufio.CopyWithIncreateBuffer(copyWriter, strings.NewReader("payload"), bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.Equal(t, "marker:payload", string(sink.seen),
		"the destination-side rewrite must still happen; a gate placed below the rewriter would "+
			"have dropped it")
	require.Positive(t, flow.AdmittedBytes())
}
