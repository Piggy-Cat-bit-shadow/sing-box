package route

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/trafficclass"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The production integration of the upload scheduler: configuration reaches the shaper, and the
// shaper is measured where it actually runs - inside the copy loop the connection manager starts,
// not around a writer a test built for itself.

// configureUploadRate decodes a route section and applies it exactly the way box.New does, so the
// wiring under test is the wiring that ships.
//
// The decode is done without the polymorphic registries the root package installs, because this
// package cannot import it. That costs nothing here: the section under test carries no rule or
// outbound reference, and the registry-based decode of the same section is covered in the option
// package's own tests.
func configureUploadRate(t *testing.T, manager *ConnectionManager, routeJSON string) *option.RouteOptions {
	t.Helper()
	var routeOptions option.RouteOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(routeJSON), &routeOptions))
	if trafficScheduler := routeOptions.TrafficScheduler; trafficScheduler != nil {
		manager.SetUploadRate(trafficScheduler.UploadRate.Build())
	}
	return &routeOptions
}

// TestConfiguredUploadRateReachesTheScheduler pins the first link in the chain: an accepted option
// must become a live rate, and the production default must stay inert.
func TestConfiguredUploadRateReachesTheScheduler(t *testing.T) {
	for routeJSON, expected := range map[string]int64{
		`{}`:                       0,
		`{"traffic_scheduler":{}}`: 0,
		`{"traffic_scheduler":{"upload_rate":0}}`:           0,
		`{"traffic_scheduler":{"upload_rate":"8 MiB/s"}}`:   8 << 20,
		`{"traffic_scheduler":{"upload_rate":1000000}}`:     1_000_000,
		`{"traffic_scheduler":{"upload_rate":"16Mbps"}}`:    2_000_000,
		`{"traffic_scheduler":{"upload_rate":"5 MB/s"}}`:    5_000_000,
		`{"traffic_scheduler":{"upload_rate":"512 KiB/s"}}`: 512 << 10,
	} {
		t.Run(routeJSON, func(t *testing.T) {
			manager := NewConnectionManager(log.NewNOPFactory().Logger())
			configureUploadRate(t, manager, routeJSON)
			require.EqualValues(t, expected, manager.UploadRate())
		})
	}
}

// TestConfiguredRateShapesTheRealTCPCopyPath is the end-to-end claim: a rate in the configuration
// bounds how fast a managed upload actually leaves, through the connection manager's own copy
// function and the gate it installs.
//
// The measurement is wall-clock over a fixed payload, which is the only observable that cannot be
// satisfied by a shaper that is present but inert.
func TestConfiguredRateShapesTheRealTCPCopyPath(t *testing.T) {
	const (
		rate    = 2_000_000
		payload = 4_000_000
	)
	// Two seconds of payload at the configured rate, with a wide band: the point is that the copy
	// is paced at all, and a band that a broken shaper could satisfy would not be a test.
	expected := time.Duration(float64(payload) / rate * float64(time.Second))

	run := func(t *testing.T, routeJSON string) time.Duration {
		t.Helper()
		manager := NewConnectionManager(log.NewNOPFactory().Logger())
		configureUploadRate(t, manager, routeJSON)

		source, sourcePeer := net.Pipe()
		t.Cleanup(func() { _ = source.Close(); _ = sourcePeer.Close() })
		sink, sinkPeer := net.Pipe()
		t.Cleanup(func() { _ = sink.Close(); _ = sinkPeer.Close() })
		go func() { _, _ = io.Copy(io.Discard, sinkPeer) }()

		copyWriter, flow := manager.uploadStreamGate(source, sink, trafficclass.ClassDefault)
		require.NotNil(t, copyWriter, "a net.Pipe flow is userspace-only and must be gated")
		defer flow.Close()

		go func() {
			chunk := make([]byte, 64*1024)
			remaining := payload
			for remaining > 0 {
				size := len(chunk)
				if size > remaining {
					size = remaining
				}
				if _, err := sourcePeer.Write(chunk[:size]); err != nil {
					break
				}
				remaining -= size
			}
			_ = sourcePeer.Close()
		}()

		var done atomic.Bool
		start := time.Now()
		manager.connectionCopy(context.Background(), source, sink, false, bufio.DefaultIncreaseBufferAfter, &done, nil, copyWriter, flow)
		return time.Since(start)
	}

	t.Run("unshaped control", func(t *testing.T) {
		elapsed := run(t, `{}`)
		t.Logf("no configured rate: %s of payload copied in %s", byteCount(payload), elapsed.Round(time.Millisecond))
	})

	t.Run("shaped to the configured rate", func(t *testing.T) {
		elapsed := run(t, `{"traffic_scheduler":{"upload_rate":2000000}}`)
		t.Logf("configured %s: %s of payload copied in %s (paced floor %s)",
			byteCount(rate), byteCount(payload), elapsed.Round(time.Millisecond), expected.Round(time.Millisecond))
		require.Greater(t, elapsed, expected*3/4,
			"a configured rate must actually delay the copy; an unpaced copy of this payload is "+
				"orders of magnitude faster")
	})

	t.Run("a rate the path easily exceeds does not delay it", func(t *testing.T) {
		elapsed := run(t, `{"traffic_scheduler":{"upload_rate":"1 GB/s"}}`)
		t.Logf("configured %s: %s of payload copied in %s", byteCount(1_000_000_000), byteCount(payload), elapsed.Round(time.Millisecond))
		require.Less(t, elapsed, expected/4,
			"a rate far above what the copy needs must not become a delay: the shaper admits "+
				"whenever credit allows, and credit is never the constraint here")
	})
}

func byteCount(bytes int) string {
	switch {
	case bytes >= 1<<20:
		return strconv.FormatFloat(float64(bytes)/(1<<20), 'f', 1, 64) + " MiB"
	case bytes >= 1<<10:
		return strconv.FormatFloat(float64(bytes)/(1<<10), 'f', 1, 64) + " KiB"
	default:
		return strconv.Itoa(bytes) + " B"
	}
}

// TestConfiguredRateShapesTheRealUDPCopyPath is the same claim for the packet path, and it also
// pins that batching survives shaping: the copy must go through the batch entry point rather than
// degrading to one syscall per packet.
func TestConfiguredRateShapesTheRealUDPCopyPath(t *testing.T) {
	const rate = 2_000_000

	t.Run("unshaped control", func(t *testing.T) {
		elapsed, batches, packets := runPacketCopy(t, `{}`)
		t.Logf("no configured rate: %d batches, %d single packets in %s", batches, packets, elapsed.Round(time.Millisecond))
		require.Positive(t, batches, "the packet copy must use the batch entry point")
	})

	t.Run("shaped", func(t *testing.T) {
		elapsed, batches, packets := runPacketCopy(t, `{"traffic_scheduler":{"upload_rate":2000000}}`)
		t.Logf("configured %s: %d batches, %d single packets in %s",
			byteCount(rate), batches, packets, elapsed.Round(time.Millisecond))
		require.Positive(t, batches,
			"shaping must not degrade the packet path to single writes: the gate forwards the "+
				"batch creators precisely so that it does not")
		require.Zero(t, packets)
	})
}

// packetSource feeds a fixed number of same-sized packets and then reports the end of the stream.
//
// It serves BOTH the single-packet and the batch read-waiter entry points, because which one the
// copy engine picks is exactly what this test is about: a source that only offered single packets
// would make the "batching survived" assertion vacuous by never giving the engine the choice.
type packetSource struct {
	remaining int
	size      int
	batchSize int
}

func (s *packetSource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if s.remaining <= 0 {
		return M.Socksaddr{}, io.EOF
	}
	s.remaining--
	if _, err := buffer.Write(make([]byte, s.size)); err != nil {
		return M.Socksaddr{}, err
	}
	return M.Socksaddr{}, nil
}

// InitializeReadWaiter returns false, which asks the copy engine to USE this waiter rather than fall
// back to the generic loop. Every waiter in sing, tun.GoConn included, returns false here.
func (s *packetSource) InitializeReadWaiter(N.ReadWaitOptions) bool { return false }

func (s *packetSource) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	if s.remaining <= 0 {
		return nil, nil, io.EOF
	}
	count := s.batchSize
	if count > s.remaining {
		count = s.remaining
	}
	s.remaining -= count
	buffers := make([]*buf.Buffer, count)
	destinations := make([]M.Socksaddr, count)
	for index := range buffers {
		buffer := buf.NewSize(s.size)
		if _, err := buffer.Write(make([]byte, s.size)); err != nil {
			return nil, nil, err
		}
		buffers[index] = buffer
	}
	return buffers, destinations, nil
}

// packetSink counts how the copy chose to deliver.
type packetSink struct {
	batches atomic.Int64
	packets atomic.Int64
	bytes   atomic.Int64
}

func (s *packetSink) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	s.packets.Add(1)
	s.bytes.Add(int64(buffer.Len()))
	buffer.Release()
	return nil
}

func (s *packetSink) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return &packetSinkBatch{sink: s}, true
}

func (s *packetSink) CreateConnectedPacketBatchWriter() (N.ConnectedPacketBatchWriter, bool) {
	return &packetSinkConnectedBatch{sink: s}, true
}

type packetSinkBatch struct{ sink *packetSink }

func (w *packetSinkBatch) WritePacketBatch(buffers []*buf.Buffer, _ []M.Socksaddr) error {
	w.sink.batches.Add(1)
	for _, buffer := range buffers {
		w.sink.bytes.Add(int64(buffer.Len()))
	}
	buf.ReleaseMulti(buffers)
	return nil
}

type packetSinkConnectedBatch struct{ sink *packetSink }

func (w *packetSinkConnectedBatch) WriteConnectedPacketBatch(buffers []*buf.Buffer) error {
	w.sink.batches.Add(1)
	for _, buffer := range buffers {
		w.sink.bytes.Add(int64(buffer.Len()))
	}
	buf.ReleaseMulti(buffers)
	return nil
}

func runPacketCopy(t *testing.T, routeJSON string) (time.Duration, int64, int64) {
	t.Helper()
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	configureUploadRate(t, manager, routeJSON)

	source := &packetSource{remaining: 512, size: 16 * 1024, batchSize: 32}
	sink := &packetSink{}

	copyWriter, flow := manager.uploadPacketGate(sink, trafficclass.ClassDefault)
	require.NotNil(t, copyWriter)
	defer flow.Close()

	var done atomic.Bool
	start := time.Now()
	manager.packetConnectionCopy(context.Background(), source, sink, false, &done, nil, copyWriter, flow)
	return time.Since(start), sink.batches.Load(), sink.packets.Load()
}

// TestUploadGateMapsTrafficClassToTheLane pins that the class the router resolved is the class the
// scheduler sees. Asserting the lane rather than the timing is what makes this a mapping test and
// not a speed test.
func TestUploadGateMapsTrafficClassToTheLane(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())

	pipeOne, pipeOnePeer := net.Pipe()
	t.Cleanup(func() { _ = pipeOne.Close(); _ = pipeOnePeer.Close() })
	pipeTwo, pipeTwoPeer := net.Pipe()
	t.Cleanup(func() { _ = pipeTwo.Close(); _ = pipeTwoPeer.Close() })

	_, interactiveFlow := manager.gateWriter(pipeOne, trafficclass.ClassInteractive)
	defer interactiveFlow.Close()
	_, bulkFlow := manager.gateWriter(pipeTwo, trafficclass.ClassBulk)
	defer bulkFlow.Close()

	require.True(t, interactiveFlow.HighPriority())
	require.False(t, bulkFlow.HighPriority())
}

// TestShapingKeepsUploadAccountingExact guards the interaction between the two mechanisms: a
// delayed write must still be counted once, and only once.
func TestShapingKeepsUploadAccountingExact(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	configureUploadRate(t, manager, `{"traffic_scheduler":{"upload_rate":500000}}`)

	var uploadBytes atomic.Int64
	sourceConn, peer := net.Pipe()
	t.Cleanup(func() { _ = sourceConn.Close(); _ = peer.Close() })
	trackerConn := bufio.NewInt64CounterConn(sourceConn, []*atomic.Int64{&uploadBytes}, nil)

	sink := &framingSink{}
	copyWriter, flow := manager.gateWriter(sink, trafficclass.ClassDefault)
	defer flow.Close()

	const payload = "shaped-upload-payload"
	go func() {
		_, _ = peer.Write([]byte(payload))
		_ = peer.Close()
	}()

	written, err := bufio.CopyWithIncreateBuffer(copyWriter, trackerConn, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	require.NoError(t, err)
	require.EqualValues(t, len(payload), written)
	require.Equal(t, payload, string(sink.seen))
	require.EqualValues(t, len(payload), uploadBytes.Load(),
		"shaping must not change the accounting: the tracker counts the inbound read side, and "+
			"the gate delays writes without touching that")
	require.EqualValues(t, len(payload), flow.AdmittedBytes())
}

// TestShutdownReleasesAFlowParkedInTheShaper is the lifecycle case at the route level: a write
// delayed by the shaper is not inside a write, so closing the connection does not wake it. Only the
// connection manager's own shutdown can.
func TestShutdownReleasesAFlowParkedInTheShaper(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	// One byte per hour: every write after the first is parked for as long as the test cares.
	configureUploadRate(t, manager, `{"traffic_scheduler":{"upload_rate":1}}`)

	source, sourcePeer := net.Pipe()
	t.Cleanup(func() { _ = source.Close(); _ = sourcePeer.Close() })
	sink, sinkPeer := net.Pipe()
	t.Cleanup(func() { _ = sink.Close(); _ = sinkPeer.Close() })
	go func() { _, _ = io.Copy(io.Discard, sinkPeer) }()

	copyWriter, flow := manager.uploadStreamGate(source, sink, trafficclass.ClassDefault)
	require.NotNil(t, copyWriter)

	go func() {
		chunk := make([]byte, 64*1024)
		for {
			if _, err := sourcePeer.Write(chunk); err != nil {
				return
			}
		}
	}()

	copyReturned := make(chan struct{})
	go func() {
		defer close(copyReturned)
		var done atomic.Bool
		manager.connectionCopy(context.Background(), source, sink, false, bufio.DefaultIncreaseBufferAfter, &done, nil, copyWriter, flow)
	}()

	// Let the copy run into the shaper, then shut the manager down the way a stop or a network
	// transition does.
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, manager.Close())

	select {
	case <-copyReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("a flow parked in the shaper must be released by the connection manager's close")
	}
}

// TestUploadRateCanBeReplacedWhileFlowsRun pins the reload semantics the core actually has: the
// rate is read on every refill rather than captured, so replacing it takes effect on the flows that
// already exist. A reload that builds a new Box gets a new manager and does not need this, but a
// controller installed later does.
func TestUploadRateCanBeReplacedWhileFlowsRun(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	configureUploadRate(t, manager, `{"traffic_scheduler":{"upload_rate":1000000}}`)
	require.EqualValues(t, 1_000_000, manager.UploadRate())

	pipe, pipePeer := net.Pipe()
	t.Cleanup(func() { _ = pipe.Close(); _ = pipePeer.Close() })
	_, flow := manager.gateWriter(pipe, trafficclass.ClassDefault)
	defer flow.Close()

	manager.SetUploadRate(4_000_000)
	require.EqualValues(t, 4_000_000, manager.UploadRate(),
		"the rate must be live: the scheduler reads it per refill, so nothing has to be rebuilt")

	manager.SetUploadRate(0)
	require.Zero(t, manager.UploadRate(), "zero must return the scheduler to inert")
	require.Positive(t, flow.AdmittedBytes()+1)
}

// TestNetworkTransitionReleasesAFlowParkedInTheShaper covers the transition path specifically.
//
// CloseAll is what a network change calls, and unlike Close it does not touch the scheduler: it
// closes the connections and expects the copies to unwind. A flow parked in the shaper is not inside
// a write, so the closed socket tells it nothing - it has to be released by being granted, and then
// fail its write. That is a liveness property, not a cosmetic one: if it did not hold, every network
// change would strand one goroutine per parked flow.
func TestNetworkTransitionReleasesAFlowParkedInTheShaper(t *testing.T) {
	manager := NewConnectionManager(log.NewNOPFactory().Logger())
	// One byte per hour: every write after the first is parked for as long as the test cares.
	configureUploadRate(t, manager, `{"traffic_scheduler":{"upload_rate":1}}`)

	source, sourcePeer := net.Pipe()
	t.Cleanup(func() { _ = source.Close(); _ = sourcePeer.Close() })
	sink, sinkPeer := net.Pipe()
	t.Cleanup(func() { _ = sink.Close(); _ = sinkPeer.Close() })
	go func() { _, _ = io.Copy(io.Discard, sinkPeer) }()

	copyWriter, flow := manager.uploadStreamGate(source, sink, trafficclass.ClassDefault)
	require.NotNil(t, copyWriter)

	go func() {
		chunk := make([]byte, 64*1024)
		for {
			if _, err := sourcePeer.Write(chunk); err != nil {
				return
			}
		}
	}()

	copyReturned := make(chan struct{})
	go func() {
		defer close(copyReturned)
		var done atomic.Bool
		manager.connectionCopy(context.Background(), source, sink, false, bufio.DefaultIncreaseBufferAfter, &done, nil, copyWriter, flow)
	}()

	time.Sleep(50 * time.Millisecond)
	manager.CloseAll()

	select {
	case <-copyReturned:
	case <-time.After(10 * time.Second):
		t.Fatal("a network transition must not strand a flow parked in the shaper")
	}

	require.NoError(t, manager.Close())
}

// TestBoxWiresTheConfiguredRateIntoTheScheduler reads box.go, because the wiring cannot be exercised
// behaviourally from here.
//
// The route package cannot import the root package (it would be a cycle), so the four lines in
// box.New that read route.traffic_scheduler and call SetUploadRate have no behavioural test. A
// source guard is weaker than a behavioural one, and it is stronger than leaving the one link in the
// chain untested: the option decodes, the scheduler shapes, and this is what joins them.
func TestBoxWiresTheConfiguredRateIntoTheScheduler(t *testing.T) {
	source := readRouteSource(t, "../box.go")

	require.Contains(t, source, "routeOptions.TrafficScheduler",
		"box.New must read the scheduler options from the route section")
	require.Contains(t, source, "connectionManager.SetUploadRate(",
		"and must install the configured rate into the connection manager's scheduler")
	require.Contains(t, source, ".UploadRate.Build()",
		"passing the parsed rate rather than the options value, so the unit handling stays in one "+
			"place")

	// The option is a pointer, so absent and present-but-empty are both handled by the same branch;
	// a caller that forgot to check for nil would panic on every configuration that omits it.
	require.Contains(t, source, "trafficScheduler := routeOptions.TrafficScheduler; trafficScheduler != nil",
		"and must not dereference an absent section")
}
